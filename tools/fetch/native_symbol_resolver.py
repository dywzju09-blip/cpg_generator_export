from __future__ import annotations

import ctypes.util
import glob
import os
import re
import subprocess
from collections import defaultdict

from tools.fetch.native_source_providers import canonical_component_name, get_provider, iter_providers


_LDCONFIG_CACHE: dict[str, list[str]] | None = None
_PKG_CONFIG_CACHE: dict[str, dict] = {}
_BINARY_EXPORT_CACHE: dict[str, set[str]] = {}
_BINARY_IMPORT_CACHE: dict[str, set[str]] = {}

_SYMBOL_SUFFIX_RE = re.compile(r"@{1,2}.+$")
_IGNORED_SYMBOL_PREFIXES = ("GLIBC_", "CXXABI_", "GCC_", "_ITM_", "__gmon_start__", "__cxa_")


def _run_capture(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"command failed: {' '.join(cmd)}")
    return result.stdout


def _normalize_symbol(symbol: str) -> str:
    text = str(symbol or "").strip()
    text = _SYMBOL_SUFFIX_RE.sub("", text)
    return text.strip()


def _binary_basename_tokens(path: str) -> set[str]:
    base = os.path.basename(str(path or "")).lower()
    if not base:
        return set()
    tokens = {base}
    short = base.split(".so", 1)[0]
    tokens.add(short)
    if short.startswith("lib"):
        tokens.add(short[3:])
    return {token for token in tokens if token}


def _binary_name_candidates(component: str) -> list[str]:
    provider = get_provider(component)
    if not provider:
        return []
    names = set()
    raw_names = list(provider.binary_names or ()) + list(provider.pkg_config_names or ()) + [provider.name, *provider.aliases]
    for raw in raw_names:
        value = str(raw or "").strip().lower()
        if not value:
            continue
        value = value.replace("-sys", "")
        if value.startswith("lib") and len(value) > 3:
            names.add(value)
            names.add(value[3:])
        else:
            names.add(value)
            names.add(f"lib{value}")
    return sorted(names)


def _parse_pkg_config_flags(text: str) -> tuple[list[str], list[str]]:
    lib_dirs = []
    libs = []
    for token in str(text or "").split():
        if token.startswith("-L") and len(token) > 2:
            lib_dirs.append(token[2:])
        elif token.startswith("-l") and len(token) > 2:
            libs.append(token[2:])
    return lib_dirs, libs


def _pkg_config_probe(name: str) -> dict:
    if name in _PKG_CONFIG_CACHE:
        return dict(_PKG_CONFIG_CACHE[name])
    probe = {
        "name": name,
        "ok": False,
        "lib_dirs": [],
        "libs": [],
        "version": "",
    }
    try:
        flags = _run_capture(["pkg-config", "--libs-only-L", "--libs-only-l", name])
        version = _run_capture(["pkg-config", "--modversion", name]).strip()
        lib_dirs, libs = _parse_pkg_config_flags(flags)
        probe.update({
            "ok": True,
            "lib_dirs": sorted(set(lib_dirs)),
            "libs": sorted(set(libs)),
            "version": version,
        })
    except Exception as exc:
        probe["error"] = str(exc)
    _PKG_CONFIG_CACHE[name] = dict(probe)
    return dict(probe)


def _load_ldconfig_cache() -> dict[str, list[str]]:
    global _LDCONFIG_CACHE
    if _LDCONFIG_CACHE is not None:
        return _LDCONFIG_CACHE
    index: dict[str, list[str]] = defaultdict(list)
    if os.name != "posix" or not os.path.exists("/sbin/ldconfig") and not os.path.exists("/usr/sbin/ldconfig"):
        _LDCONFIG_CACHE = {}
        return _LDCONFIG_CACHE
    cmd = ["ldconfig", "-p"]
    try:
        output = _run_capture(cmd)
    except Exception:
        _LDCONFIG_CACHE = {}
        return _LDCONFIG_CACHE
    for line in output.splitlines():
        line = line.strip()
        if "=>" not in line or ".so" not in line:
            continue
        left, right = [part.strip() for part in line.split("=>", 1)]
        soname = left.split()[0]
        path = right
        base = soname.lower()
        index[base].append(path)
        if base.startswith("lib"):
            index[base[3:]].append(path)
        short = base.split(".so", 1)[0]
        index[short].append(path)
        if short.startswith("lib"):
            index[short[3:]].append(path)
    _LDCONFIG_CACHE = {key: sorted(set(value)) for key, value in index.items()}
    return _LDCONFIG_CACHE


def find_component_binaries(component: str) -> list[str]:
    provider = get_provider(component)
    if not provider:
        return []
    found = set()
    lib_dirs = set()
    lib_names = set(_binary_name_candidates(component))

    for pkg_name in provider.pkg_config_names or ():
        probe = _pkg_config_probe(pkg_name)
        lib_dirs.update(probe.get("lib_dirs") or [])
        lib_names.update(str(name).lower() for name in (probe.get("libs") or []))

    for lib_dir in sorted(lib_dirs):
        for lib_name in sorted(lib_names):
            patterns = [
                os.path.join(lib_dir, f"lib{lib_name}.so"),
                os.path.join(lib_dir, f"lib{lib_name}.so.*"),
            ]
            for pattern in patterns:
                for path in glob.glob(pattern):
                    if os.path.isfile(path):
                        found.add(os.path.realpath(path))

    ldconfig_index = _load_ldconfig_cache()
    for lib_name in sorted(lib_names):
        for path in ldconfig_index.get(lib_name.lower(), []):
            if os.path.isfile(path):
                found.add(os.path.realpath(path))

    for lib_name in sorted(lib_names):
        ctypes_path = ctypes.util.find_library(lib_name)
        if ctypes_path and os.path.isabs(ctypes_path) and os.path.isfile(ctypes_path):
            found.add(os.path.realpath(ctypes_path))

    return sorted(found)


def _parse_ldd_output(text: str) -> list[dict]:
    rows = []
    for raw in str(text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if "=>" in line:
            left, right = [part.strip() for part in line.split("=>", 1)]
            soname = left.split()[0]
            path = right.split("(")[0].strip()
            if path and path != "not":
                rows.append({"soname": soname, "path": path})
        elif line.startswith("/"):
            path = line.split("(")[0].strip()
            rows.append({"soname": os.path.basename(path), "path": path})
    return rows


def collect_binary_linked_libraries(binary_path: str) -> list[dict]:
    if os.name != "posix":
        return []
    try:
        output = _run_capture(["ldd", binary_path])
    except Exception:
        return []
    return _parse_ldd_output(output)


def collect_component_link_context(component: str, binaries: list[str] | None = None) -> dict:
    provider = get_provider(component)
    if not provider:
        return {"component": canonical_component_name(component), "pkg_config": [], "linked_libs": []}
    binaries = list(binaries or [])
    pkg_rows = []
    linked_libs = []
    linked_tokens = set()
    for pkg_name in provider.pkg_config_names or ():
        probe = _pkg_config_probe(pkg_name)
        pkg_rows.append(probe)
        linked_tokens.update(str(item).lower() for item in (probe.get("libs") or []))
    for binary in binaries:
        rows = collect_binary_linked_libraries(binary)
        linked_libs.extend(rows)
        for row in rows:
            linked_tokens.update(_binary_basename_tokens(row.get("path") or row.get("soname") or ""))
    return {
        "component": provider.name,
        "pkg_config": pkg_rows,
        "linked_libs": linked_libs,
        "linked_tokens": sorted(linked_tokens),
    }


def _provider_matches_link_context(candidate_component: str, provider_row: dict, link_context: dict) -> bool:
    linked_tokens = set(str(item).lower() for item in (link_context or {}).get("linked_tokens") or [])
    if not linked_tokens:
        return True
    provider = get_provider(candidate_component)
    if not provider:
        return True
    candidate_tokens = set()
    for binary in provider_row.get("binaries", []) or []:
        candidate_tokens.update(_binary_basename_tokens(binary))
    for token in provider.binary_names or ():
        candidate_tokens.add(str(token).lower())
    for token in provider.pkg_config_names or ():
        candidate_tokens.add(str(token).lower())
    candidate_tokens.add(provider.name.lower())
    return bool(candidate_tokens & linked_tokens)


def _parse_nm_symbols(text: str) -> set[str]:
    symbols = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        symbol = parts[-1] if parts else ""
        normalized = _normalize_symbol(symbol)
        if normalized:
            symbols.add(normalized)
    return symbols


def collect_binary_exports(binary_path: str) -> set[str]:
    key = os.path.realpath(binary_path)
    if key in _BINARY_EXPORT_CACHE:
        return set(_BINARY_EXPORT_CACHE[key])
    try:
        output = _run_capture(["nm", "-D", "--defined-only", key])
        exports = _parse_nm_symbols(output)
    except Exception:
        exports = set()
    _BINARY_EXPORT_CACHE[key] = set(exports)
    return set(exports)


def collect_binary_imports(binary_path: str) -> set[str]:
    key = os.path.realpath(binary_path)
    if key in _BINARY_IMPORT_CACHE:
        return set(_BINARY_IMPORT_CACHE[key])
    try:
        output = _run_capture(["nm", "-D", "--undefined-only", key])
        imports = _parse_nm_symbols(output)
    except Exception:
        imports = set()
    filtered = {
        symbol
        for symbol in imports
        if symbol and not symbol.startswith(_IGNORED_SYMBOL_PREFIXES)
    }
    _BINARY_IMPORT_CACHE[key] = set(filtered)
    return set(filtered)


def build_symbol_provider_index(candidate_components: list[str] | None = None) -> dict[str, dict]:
    allowed = {canonical_component_name(item) for item in candidate_components or [] if str(item or "").strip()}
    index: dict[str, dict] = {}
    for provider in iter_providers():
        component = provider.name
        if allowed and component not in allowed:
            continue
        binaries = find_component_binaries(component)
        exports = set()
        for binary in binaries:
            exports.update(collect_binary_exports(binary))
        index[component] = {
            "component": component,
            "binaries": binaries,
            "exports": exports,
        }
    return index


def resolve_strict_native_dependencies(component: str, resolved_version: str = "", candidate_components: list[str] | None = None) -> dict:
    provider = get_provider(component)
    if not provider:
        return {"status": "unsupported", "component": canonical_component_name(component), "dependencies": []}
    parent_component = provider.name
    binaries = find_component_binaries(parent_component)
    if not binaries:
        return {
            "status": "unavailable",
            "component": parent_component,
            "resolved_version": resolved_version,
            "reason": "component_binary_not_found",
            "dependencies": [],
            "binaries": [],
        }
    imports_by_binary = {}
    imported_symbols = set()
    for binary in binaries:
        symbols = collect_binary_imports(binary)
        imports_by_binary[binary] = symbols
        imported_symbols.update(symbols)
    link_context = collect_component_link_context(parent_component, binaries)

    provider_index = build_symbol_provider_index(candidate_components)
    resolved: dict[str, dict] = {}
    ambiguous = []
    unresolved_count = 0

    for symbol in sorted(imported_symbols):
        matches = []
        for candidate_component, row in provider_index.items():
            if candidate_component == parent_component:
                continue
            if not _provider_matches_link_context(candidate_component, row, link_context):
                continue
            if symbol in row.get("exports", set()):
                matches.append({
                    "component": candidate_component,
                    "binaries": row.get("binaries", []),
                })
        if not matches:
            unresolved_count += 1
            continue
        if len(matches) > 1:
            ambiguous.append({"symbol": symbol, "matches": [item["component"] for item in matches]})
            continue
        match = matches[0]
        provider_exports = provider_index.get(match["component"], {}).get("exports", set())
        row = resolved.setdefault(
            match["component"],
            {
                "component": match["component"],
                "confidence": "high",
                "evidence_type": "binary-symbol",
                "source": "native-symbol",
                "provider_binaries": match.get("binaries", []),
                "provider_export_sample": sorted(provider_exports)[:64],
                "evidence": [],
            },
        )
        for binary, binary_imports in imports_by_binary.items():
            if symbol not in binary_imports:
                continue
            row["evidence"].append(
                {
                    "binary": binary,
                    "symbol": symbol,
                    "provider_binaries": match.get("binaries", [])[:4],
                }
            )

    dependencies = []
    for child_component, row in sorted(resolved.items()):
        row["evidence"] = row["evidence"][:12]
        dependencies.append(row)
    return {
        "status": "resolved" if dependencies else "no_matches",
        "component": parent_component,
        "resolved_version": resolved_version,
        "binaries": binaries,
        "imports_by_binary": {binary: sorted(symbols)[:256] for binary, symbols in imports_by_binary.items()},
        "imported_symbol_count": len(imported_symbols),
        "link_context": link_context,
        "provider_index_components": sorted(provider_index.keys()),
        "dependencies": dependencies,
        "ambiguous_symbols": ambiguous[:20],
        "unresolved_symbol_count": unresolved_count,
    }
