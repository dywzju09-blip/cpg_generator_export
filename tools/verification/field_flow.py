from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Set


_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_CALL_RE_TEMPLATE = r"\b{func}\s*\(([^;]*)\)"


def _split_args(arg_str: str) -> List[str]:
    args: List[str] = []
    current: List[str] = []
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


def _extract_args_from_call_expr(code: str) -> List[str]:
    if not code:
        return []
    left = code.find("(")
    right = code.rfind(")")
    if left == -1 or right == -1 or right <= left:
        return []
    return _split_args(code[left + 1 : right])


def _normalize_alias_expr(expr: str) -> str:
    text = str(expr or "").strip()
    if not text:
        return text
    prefixes = ("move ", "copy ", "const ", "&mut ", "&raw mut ", "&raw const ", "&", "*")
    changed = True
    while changed and text:
        changed = False
        for prefix in prefixes:
            if text.startswith(prefix):
                text = text[len(prefix) :].strip()
                changed = True
    text = re.sub(r"\s+as\s+[A-Za-z_][A-Za-z0-9_:<>]*", "", text).strip()
    text = text.strip("()")
    if text.startswith("*"):
        text = text[1:].strip()
    if text.startswith("(*") and text.endswith(")"):
        text = text[2:-1].strip()
    return text.strip(",;")


def _resolve_numeric_expr(expr: str, value_env: Dict[str, int], const_map: Dict[str, int]) -> Optional[int]:
    text = _normalize_alias_expr(expr)
    if not text:
        return None
    lowered = text.lower()
    if lowered in ("true", "false"):
        return 1 if lowered == "true" else 0
    try:
        return int(text, 16 if lowered.startswith("0x") or lowered.startswith("-0x") else 10)
    except Exception:
        pass
    for candidate in (text, text.split("::")[-1], text.split(".")[-1]):
        if candidate in value_env:
            try:
                return int(value_env[candidate])
            except Exception:
                pass
        if candidate in const_map:
            try:
                return int(const_map[candidate])
            except Exception:
                pass
    return None


def _collect_code_blobs(chain_nodes: Iterable[dict], evidence_calls: Iterable[dict]) -> List[dict]:
    blobs: List[dict] = []
    for node in chain_nodes or []:
        if not isinstance(node, dict):
            continue
        code = node.get("code")
        if isinstance(code, str) and code.strip():
            blobs.append({"kind": "chain_node", "id": node.get("id"), "code": code, "name": node.get("name")})
    for call in evidence_calls or []:
        if not isinstance(call, dict):
            continue
        code = call.get("code")
        if isinstance(code, str) and code.strip():
            blobs.append({"kind": "call", "id": call.get("id"), "code": code, "name": call.get("name"), "method": call.get("method")})
    return blobs


def _build_alias_edges(code_blobs: Iterable[dict]) -> List[dict]:
    patterns = [
        re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b\s*=\s*&mut\s+([A-Za-z_][A-Za-z0-9_]*)"),
        re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b\s*=\s*&raw mut \(\*([A-Za-z_][A-Za-z0-9_]*)\)"),
        re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b\s*=\s*move\s+([A-Za-z_][A-Za-z0-9_]*)"),
        re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b\s*=\s*copy\s+([A-Za-z_][A-Za-z0-9_]*)"),
    ]
    edges = []
    seen = set()
    for blob in code_blobs:
        code = blob.get("code") or ""
        for regex in patterns:
            for match in regex.finditer(code):
                dst, src = match.groups()
                key = (dst, src, blob.get("id"))
                if key in seen:
                    continue
                seen.add(key)
                edges.append(
                    {
                        "from": _normalize_alias_expr(src),
                        "to": _normalize_alias_expr(dst),
                        "source_id": blob.get("id"),
                        "source_kind": blob.get("kind"),
                        "raw": match.group(0),
                    }
                )
    return edges


def _expand_aliases(seed: str, alias_edges: Iterable[dict]) -> Set[str]:
    root = _normalize_alias_expr(seed)
    if not root:
        return set()
    aliases = {root}
    changed = True
    while changed:
        changed = False
        for edge in alias_edges or []:
            src = edge.get("from")
            dst = edge.get("to")
            if src in aliases and dst not in aliases:
                aliases.add(dst)
                changed = True
            if dst in aliases and src not in aliases:
                aliases.add(src)
                changed = True
    return aliases


def _extract_call_args_from_blobs(call_name: str, code_blobs: Iterable[dict]) -> List[dict]:
    rows = []
    regex = re.compile(_CALL_RE_TEMPLATE.format(func=re.escape(call_name)))
    for blob in code_blobs:
        code = blob.get("code") or ""
        for match in regex.finditer(code):
            args = _split_args(match.group(1))
            rows.append(
                {
                    "source_id": blob.get("id"),
                    "source_kind": blob.get("kind"),
                    "args": args,
                    "raw": match.group(0),
                }
            )
    return rows


def _select_arg_expr(call: dict, arg_index: int, code_blobs: Iterable[dict]) -> Optional[dict]:
    direct_args = _extract_args_from_call_expr(call.get("code") or "")
    if len(direct_args) >= arg_index:
        return {
            "expr": direct_args[arg_index - 1],
            "source_id": call.get("id"),
            "source_kind": "call",
            "raw": call.get("code"),
        }
    fallback = _extract_call_args_from_blobs(call.get("name") or "", code_blobs)
    for item in fallback:
        if len(item.get("args") or []) >= arg_index:
            return {
                "expr": item["args"][arg_index - 1],
                "source_id": item.get("source_id"),
                "source_kind": item.get("source_kind"),
                "raw": item.get("raw"),
            }
    return None


def _extract_field_facts(
    object_id: str,
    aliases: Set[str],
    field_descs: Dict[str, dict],
    code_blobs: Iterable[dict],
    value_env: Dict[str, int],
    const_map: Dict[str, int],
) -> List[dict]:
    facts = []
    seen = set()
    for blob in code_blobs:
        code = blob.get("code") or ""
        for field_name, desc in (field_descs or {}).items():
            field_token = re.escape(field_name)
            regexes = [
                re.compile(rf"\b{field_token}\b\s*:\s*([^,\n}};]+)"),
                re.compile(rf"\b([A-Za-z_][A-Za-z0-9_]*)\.{field_token}\b\s*=\s*([^,\n}};]+)"),
                re.compile(rf"\(\*([A-Za-z_][A-Za-z0-9_]*)\)\.{field_token}\b\s*=\s*([^,\n}};]+)"),
            ]
            for index, regex in enumerate(regexes):
                for match in regex.finditer(code):
                    owner = None
                    expr = None
                    confidence = "medium"
                    if index == 0:
                        owner = next(iter(aliases), "")
                        expr = match.group(1).strip()
                    elif index == 1:
                        owner = _normalize_alias_expr(match.group(1))
                        expr = match.group(2).strip()
                        confidence = "high" if owner in aliases else "low"
                    else:
                        owner = _normalize_alias_expr(match.group(1))
                        expr = match.group(2).strip()
                        confidence = "high" if owner in aliases else "low"
                    if index > 0 and owner not in aliases:
                        continue
                    key = (field_name, expr, blob.get("id"))
                    if key in seen:
                        continue
                    seen.add(key)
                    facts.append(
                        {
                            "object_id": object_id,
                            "owner_alias": owner,
                            "field": field_name,
                            "expr": expr,
                            "resolved_value": _resolve_numeric_expr(expr, value_env, const_map),
                            "confidence": confidence,
                            "declared_state": (desc or {}).get("state"),
                            "field_kind": (desc or {}).get("kind"),
                            "source_id": blob.get("id"),
                            "source_kind": blob.get("kind"),
                        }
                    )
    return facts


def build_field_flow(
    chain_nodes: List[dict],
    evidence_calls: List[dict],
    ffi_summaries: Dict[str, dict],
    value_env: Optional[Dict[str, int]] = None,
    const_map: Optional[Dict[str, int]] = None,
) -> dict:
    value_env = dict(value_env or {})
    const_map = dict(const_map or {})
    code_blobs = _collect_code_blobs(chain_nodes, evidence_calls)
    alias_edges = _build_alias_edges(code_blobs)

    objects = []
    field_facts = []
    unresolved = []

    for call in evidence_calls or []:
        if not isinstance(call, dict):
            continue
        summary = ffi_summaries.get(call.get("name"))
        if not summary:
            continue
        for arg_index, param_desc in (summary.get("params") or {}).items():
            arg_info = _select_arg_expr(call, int(arg_index), code_blobs)
            if not arg_info:
                unresolved.append(
                    {
                        "kind": "arg_expr_unresolved",
                        "call_id": call.get("id"),
                        "call_name": call.get("name"),
                        "arg_index": int(arg_index),
                    }
                )
                continue
            root_alias = _normalize_alias_expr(arg_info.get("expr"))
            aliases = _expand_aliases(root_alias, alias_edges)
            if root_alias:
                aliases.add(root_alias)
            object_id = f"{call.get('name')}:{call.get('id')}:arg{arg_index}"
            objects.append(
                {
                    "object_id": object_id,
                    "call_id": call.get("id"),
                    "call_name": call.get("name"),
                    "arg_index": int(arg_index),
                    "role": param_desc.get("role"),
                    "type": param_desc.get("type"),
                    "root_alias": root_alias,
                    "aliases": sorted(a for a in aliases if a),
                    "arg_expr": arg_info.get("expr"),
                    "arg_source_id": arg_info.get("source_id"),
                    "arg_source_kind": arg_info.get("source_kind"),
                }
            )
            field_facts.extend(
                _extract_field_facts(
                    object_id=object_id,
                    aliases=aliases,
                    field_descs=param_desc.get("fields") or {},
                    code_blobs=code_blobs,
                    value_env=value_env,
                    const_map=const_map,
                )
            )

    return {
        "objects": objects,
        "alias_edges": alias_edges,
        "field_facts": field_facts,
        "unresolved": unresolved,
    }
