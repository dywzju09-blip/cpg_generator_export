from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from tools.ffi_semantics.registry import (
    DEFAULT_REGISTRY,
    load_semantic_registry,
    save_semantic_registry,
)
from tools.ffi_semantics.binding import bind_call_summaries


_STRUCT_RE = re.compile(r"struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{(.*?)\}", re.S)
_FIELD_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([^,\n]+)")
_EXTERN_BLOCK_RE = re.compile(r'extern\s+"C"\s*\{(.*?)\}', re.S)
_FN_RE = re.compile(r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)\s*(?:->\s*([^;]+))?;", re.S)
_C_STRUCT_TYPEDEF_RE = re.compile(
    r"typedef\s+struct\s+([A-Za-z_][A-Za-z0-9_]*)?\s*\{(.*?)\}\s*([A-Za-z_][A-Za-z0-9_]*)\s*;",
    re.S,
)
_C_STRUCT_RE = re.compile(r"struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{(.*?)\}\s*;", re.S)
_C_FIELD_RE = re.compile(r"(.+?)(\*+)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(\[[^\]]+\])?\s*$", re.S)
_C_TYPEDEF_PTR_RE = re.compile(
    r"typedef\s+(.+?)\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*;",
    re.S,
)
_C_TYPEDEF_ALIAS_RE = re.compile(r"typedef\s+(.+?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", re.S)
_C_FN_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_\s\*]*?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)\s*;",
    re.S,
)


def _split_args(arg_str: str) -> List[str]:
    args = []
    current = []
    depth = 0
    for ch in arg_str:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            token = "".join(current).strip()
            if token:
                args.append(token)
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        args.append(tail)
    return args


def _parse_structs(text: str) -> Dict[str, dict]:
    structs = {}
    for match in _STRUCT_RE.finditer(text):
        struct_name = match.group(1)
        body = match.group(2)
        fields = {}
        for field_match in _FIELD_RE.finditer(body):
            field_name = field_match.group(1)
            field_type = field_match.group(2).strip()
            fields[field_name] = {
                "kind": "unknown",
                "state": "unknown",
                "declared_type": field_type,
            }
        structs[struct_name] = {"name": struct_name, "fields": fields}
    return structs


def _normalize_type(type_name: str) -> str:
    return re.sub(r"\s+", " ", (type_name or "").strip())


def _pointer_info(type_name: str) -> dict:
    normalized = _normalize_type(type_name)
    pointer_info = {
        "arg_shape": "value",
        "abi_kind": "value",
        "type": normalized,
        "pointee_type": None,
    }
    if "*mut " in normalized:
        pointer_info["arg_shape"] = "rust_mut_ref_or_c_mut_ptr"
        pointer_info["abi_kind"] = "mut_ptr"
        pointer_info["pointee_type"] = normalized.split("*mut ", 1)[1].strip()
    elif "*const " in normalized:
        pointer_info["arg_shape"] = "rust_ref_or_c_const_ptr"
        pointer_info["abi_kind"] = "const_ptr"
        pointer_info["pointee_type"] = normalized.split("*const ", 1)[1].strip()
    elif normalized.endswith("*"):
        pointer_info["arg_shape"] = "c_ptr"
        pointer_info["abi_kind"] = "mut_ptr"
        pointer_info["pointee_type"] = normalized[:-1].strip()
    return pointer_info


def _strip_c_comments(text: str) -> str:
    without_block = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//.*?$", "", without_block, flags=re.M)


def _split_c_statements(body: str) -> List[str]:
    parts = []
    current = []
    depth = 0
    for ch in body:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        if ch == ";" and depth == 0:
            token = "".join(current).strip()
            if token:
                parts.append(token)
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _parse_c_field(statement: str) -> Optional[Tuple[str, str]]:
    token = _normalize_type(statement.rstrip(";"))
    if not token:
        return None
    token = re.sub(r"\s+", " ", token)
    match = _C_FIELD_RE.match(token)
    if not match:
        return None
    type_part = match.group(1).strip()
    pointer_suffix = (match.group(2) or "").strip()
    field_name = match.group(3).strip()
    array_suffix = (match.group(4) or "").strip()
    if array_suffix:
        type_part = f"{type_part} {array_suffix}".strip()
    while type_part.endswith("*"):
        pointer_suffix += "*"
        type_part = type_part[:-1].rstrip()
    while field_name.startswith("*"):
        pointer_suffix += "*"
        field_name = field_name[1:]
    declared_type = f"{type_part}{pointer_suffix}".strip()
    return field_name, declared_type


def _pointer_info_from_c_decl(type_name: str, pointer_aliases: Optional[Dict[str, str]] = None) -> dict:
    normalized = _normalize_type(type_name)
    pointer_aliases = pointer_aliases or {}
    if normalized in pointer_aliases:
        pointee = _normalize_type(pointer_aliases[normalized])
        return {
            "arg_shape": "c_ptr_alias",
            "abi_kind": "mut_ptr",
            "type": normalized,
            "pointee_type": pointee,
        }
    pointer_info = _pointer_info(normalized)
    pointee = pointer_info.get("pointee_type")
    if pointee:
        alias_pointee = pointer_aliases.get(pointee)
        if alias_pointee:
            pointer_info["pointee_type"] = _normalize_type(alias_pointee)
    return pointer_info


def _resolve_struct_name(type_name: str, aliases: Optional[Dict[str, str]] = None) -> str:
    normalized = _normalize_type(type_name)
    aliases = aliases or {}
    if normalized in aliases:
        return _normalize_type(aliases[normalized])
    if normalized.startswith("struct "):
        return normalized.split("struct ", 1)[1].strip()
    return normalized


def _parse_c_structs(text: str) -> Tuple[Dict[str, dict], Dict[str, str], Dict[str, str]]:
    text = _strip_c_comments(text)
    structs: Dict[str, dict] = {}
    pointer_aliases: Dict[str, str] = {}
    type_aliases: Dict[str, str] = {}
    consumed_ranges = []

    for match in _C_STRUCT_TYPEDEF_RE.finditer(text):
        tag_name = (match.group(1) or "").strip()
        body = match.group(2)
        alias_name = match.group(3).strip()
        struct_name = alias_name or tag_name
        fields = {}
        for stmt in _split_c_statements(body):
            parsed = _parse_c_field(stmt)
            if not parsed:
                continue
            field_name, field_type = parsed
            fields[field_name] = {
                "kind": "unknown",
                "state": "unknown",
                "declared_type": _normalize_type(field_type),
            }
        structs[struct_name] = {"name": struct_name, "fields": fields}
        if tag_name:
            type_aliases[f"struct {tag_name}"] = struct_name
        type_aliases[alias_name] = struct_name
        consumed_ranges.append(match.span())

    for match in _C_STRUCT_RE.finditer(text):
        start, end = match.span()
        if any(start >= left and end <= right for left, right in consumed_ranges):
            continue
        struct_name = match.group(1).strip()
        body = match.group(2)
        fields = {}
        for stmt in _split_c_statements(body):
            parsed = _parse_c_field(stmt)
            if not parsed:
                continue
            field_name, field_type = parsed
            fields[field_name] = {
                "kind": "unknown",
                "state": "unknown",
                "declared_type": _normalize_type(field_type),
            }
        structs[struct_name] = {"name": struct_name, "fields": fields}
        type_aliases[f"struct {struct_name}"] = struct_name

    for match in _C_TYPEDEF_PTR_RE.finditer(text):
        base_type = _normalize_type(match.group(1))
        alias_name = match.group(2).strip()
        pointer_aliases[alias_name] = _resolve_struct_name(base_type, type_aliases)

    for match in _C_TYPEDEF_ALIAS_RE.finditer(text):
        alias_name = match.group(2).strip()
        if alias_name in pointer_aliases or alias_name in type_aliases:
            continue
        base_type = _normalize_type(match.group(1))
        resolved = _resolve_struct_name(base_type, type_aliases)
        if resolved != alias_name:
            type_aliases[alias_name] = resolved

    return structs, pointer_aliases, type_aliases


def _parse_c_param(param: str) -> Optional[Tuple[str, str]]:
    token = _normalize_type(param)
    if not token or token == "void":
        return None
    token = token.replace(" *", "*").replace("* ", "*")
    match = re.match(r"(.+?)\s+([A-Za-z_][A-Za-z0-9_]*)$", token)
    if match:
        type_part = match.group(1).strip()
        arg_name = match.group(2).strip()
    else:
        match = re.match(r"(.+?)(\*+)([A-Za-z_][A-Za-z0-9_]*)$", token)
        if not match:
            return None
        type_part = f"{match.group(1).strip()}{match.group(2)}"
        arg_name = match.group(3).strip()
    return arg_name, _normalize_type(type_part)


def generate_candidate_summaries_from_rust_ffi(text: str) -> Dict[str, dict]:
    structs = _parse_structs(text)
    summaries = {}
    extern_blocks = list(_EXTERN_BLOCK_RE.finditer(text))
    for block in extern_blocks:
        body = block.group(1)
        for fn_match in _FN_RE.finditer(body):
            fn_name = fn_match.group(1)
            raw_args = fn_match.group(2)
            params = {}
            for idx, raw_arg in enumerate(_split_args(raw_args), start=1):
                parts = raw_arg.split(":", 1)
                if len(parts) != 2:
                    continue
                arg_name = parts[0].strip()
                arg_type = _normalize_type(parts[1])
                pointer_meta = _pointer_info(arg_type)
                param_desc = {
                    "role": arg_name,
                    "confidence": "generated_candidate",
                    "declared_type": arg_type,
                    **pointer_meta,
                }
                pointee = pointer_meta.get("pointee_type")
                if pointee and pointee in structs:
                    param_desc["fields"] = structs[pointee]["fields"]
                params[str(idx)] = param_desc
            summaries[fn_name] = {
                "lang": "Rust",
                "abi_name": fn_name,
                "summary_source": "generated_from_rust_ffi",
                "params": params,
            }
    return summaries


def generate_candidate_summaries_from_c_header(text: str) -> Dict[str, dict]:
    text = _strip_c_comments(text)
    structs, pointer_aliases, type_aliases = _parse_c_structs(text)
    summaries = {}
    for fn_match in _C_FN_RE.finditer(text):
        fn_name = fn_match.group(2)
        raw_args = fn_match.group(3)
        if not fn_name or raw_args is None:
            continue
        params = {}
        for idx, raw_arg in enumerate(_split_args(raw_args), start=1):
            parsed = _parse_c_param(raw_arg)
            if not parsed:
                continue
            arg_name, arg_type = parsed
            pointer_meta = _pointer_info_from_c_decl(arg_type, pointer_aliases)
            param_desc = {
                "role": arg_name,
                "confidence": "generated_candidate",
                "declared_type": arg_type,
                **pointer_meta,
            }
            pointee = pointer_meta.get("pointee_type")
            struct_name = _resolve_struct_name(pointee or "", type_aliases)
            if struct_name in structs:
                param_desc["fields"] = structs[struct_name]["fields"]
            params[str(idx)] = param_desc
        if params:
            summaries[fn_name] = {
                "lang": "C",
                "abi_name": fn_name,
                "summary_source": "generated_from_c_header",
                "params": params,
            }
    return summaries


def upsert_component_entry(registry: dict, component_entry: dict) -> dict:
    components = list(registry.get("components") or [])
    target_name = component_entry.get("name")
    target_version = component_entry.get("version")
    updated = False
    for idx, item in enumerate(components):
        if not isinstance(item, dict):
            continue
        if item.get("name") == target_name and item.get("version") == target_version:
            merged = dict(item)
            merged.update({k: v for k, v in component_entry.items() if k != "summaries"})
            merged_summaries = dict(item.get("summaries") or {})
            for call_name, summary in (component_entry.get("summaries") or {}).items():
                merged_summaries[call_name] = bind_call_summaries(merged_summaries.get(call_name, {}), summary or {})
            merged["summaries"] = merged_summaries
            components[idx] = merged
            updated = True
            break
    if not updated:
        components.append(component_entry)
    registry["components"] = components
    registry.setdefault("schema_version", 1)
    return registry


def cmd_scan(args):
    with open(args.input, "r", encoding="utf-8") as handle:
        text = handle.read()
    if args.scan_mode == "rust":
        summaries = generate_candidate_summaries_from_rust_ffi(text)
        summary_source = "generated_from_rust_ffi"
    else:
        summaries = generate_candidate_summaries_from_c_header(text)
        summary_source = "generated_from_c_header"
    component_entry = {
        "name": args.component,
        "ecosystem": args.ecosystem,
        "language": args.language,
        "version": args.version,
        "version_range": args.version_range,
        "summary_source": "generated_candidate",
        "generated_from": os.path.abspath(args.input),
        "generated_by": summary_source,
        "notes": args.notes,
        "summaries": summaries,
    }
    if args.write_registry:
        registry = load_semantic_registry(args.registry)
        registry = upsert_component_entry(registry, component_entry)
        save_semantic_registry(registry, args.registry)
        print(f"[+] Updated registry: {args.registry}")
    else:
        print(json.dumps(component_entry, indent=2, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description="Generate reusable FFI parameter semantics candidates")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan-rust-ffi", help="Scan Rust extern bindings and emit candidate parameter semantics")
    scan.set_defaults(scan_mode="rust")
    scan.add_argument("--input", required=True, help="Rust source/binding file containing extern declarations")
    scan.add_argument("--component", required=True, help="Component/package name")
    scan.add_argument("--version", required=True, help="Component version")
    scan.add_argument("--version-range", default="", help="Optional component version range")
    scan.add_argument("--ecosystem", default="C", help="Component ecosystem/lang owner")
    scan.add_argument("--language", default="C", help="Component implementation language")
    scan.add_argument("--notes", default="", help="Extra notes saved into the component entry")
    scan.add_argument("--registry", default=DEFAULT_REGISTRY, help="Registry JSON path")
    scan.add_argument("--write-registry", action="store_true", help="Write/merge candidate entry into the registry JSON")
    scan.set_defaults(func=cmd_scan)

    scan_c = sub.add_parser("scan-c-header", help="Scan C headers and emit candidate parameter semantics")
    scan_c.set_defaults(scan_mode="c")
    scan_c.add_argument("--input", required=True, help="C header file containing declarations")
    scan_c.add_argument("--component", required=True, help="Component/package name")
    scan_c.add_argument("--version", required=True, help="Component version")
    scan_c.add_argument("--version-range", default="", help="Optional component version range")
    scan_c.add_argument("--ecosystem", default="C", help="Component ecosystem/lang owner")
    scan_c.add_argument("--language", default="C", help="Component implementation language")
    scan_c.add_argument("--notes", default="", help="Extra notes saved into the component entry")
    scan_c.add_argument("--registry", default=DEFAULT_REGISTRY, help="Registry JSON path")
    scan_c.add_argument("--write-registry", action="store_true", help="Write/merge candidate entry into the registry JSON")
    scan_c.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
