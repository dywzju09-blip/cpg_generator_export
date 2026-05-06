#!/usr/bin/env python3
"""
Auto-generate family-level vulns/extras inputs when a curated rule mapping is absent.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    from tools.supplychain.vuln_db_seed import COMPONENTS
except ModuleNotFoundError:  # pragma: no cover - direct script execution fallback
    from vuln_db_seed import COMPONENTS


COMPONENT_METADATA = {item["component"]: item for item in COMPONENTS}

FAMILY_COMPONENTS = {item["component"]: item["component"] for item in COMPONENTS}
FAMILY_COMPONENTS["openh264"] = "openh264-sys2"


def _dedupe(items: list[str]) -> list[str]:
    out: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if text and text not in out:
            out.append(text)
    return out


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(text or "").lower()).strip("_")


def _split_tokens(text: str) -> list[str]:
    out: list[str] = []
    for raw in re.split(r"[^A-Za-z0-9]+", str(text or "")):
        token = raw.strip().lower()
        if len(token) >= 3 and token not in out:
            out.append(token)
    return out


def _context_from_item(item: dict[str, Any]) -> list[str]:
    tokens: list[str] = []
    for key in ("project", "family", "code_hit_file", "dependency_chain"):
        for token in _split_tokens(item.get(key) or ""):
            if token not in tokens:
                tokens.append(token)
    hit_file = item.get("code_hit_file")
    if hit_file:
        stem = Path(str(hit_file)).stem
        for token in _split_tokens(stem):
            if token not in tokens:
                tokens.append(token)
    return tokens[:12]


def _match_crates(item: dict[str, Any], defaults: list[str]) -> list[str]:
    crates = list(defaults)
    dep_evidence = item.get("dependency_evidence")
    if isinstance(dep_evidence, dict):
        dep_iter = [dep_evidence]
    elif isinstance(dep_evidence, list):
        dep_iter = dep_evidence
    else:
        dep_iter = []
    for dep in dep_iter:
        if not isinstance(dep, dict):
            continue
        crate = str((dep or {}).get("crate") or "").strip()
        if crate and crate not in crates:
            crates.append(crate)
    return crates


def _lockfile_package_names(project_dir: str | Path | None) -> set[str]:
    root = Path(str(project_dir or "")).resolve() if project_dir else None
    if not root or not root.exists():
        return set()
    cargo_lock = root / "Cargo.lock"
    if not cargo_lock.exists():
        return set()
    try:
        text = cargo_lock.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return set()
    return {
        str(match.group(1) or "").strip()
        for match in re.finditer(r'(?m)^\s*name\s*=\s*"([^"]+)"', text)
        if str(match.group(1) or "").strip()
    }


def _strong_native_dep_crates(component: str, meta: dict[str, Any]) -> set[str]:
    strong = set()
    component_name = str(component or "").strip()
    if component_name:
        strong.add(component_name)
    for crate in meta.get("sys_crates") or []:
        text = str(crate or "").strip()
        if text:
            strong.add(text)
    return strong


def _has_strong_native_dep_evidence(item: dict[str, Any], component: str, meta: dict[str, Any]) -> bool:
    strong_crates = {str(crate or "").strip() for crate in _strong_native_dep_crates(component, meta) if str(crate or "").strip()}
    if not strong_crates:
        return False

    dep_evidence = item.get("dependency_evidence")
    if isinstance(dep_evidence, dict):
        dep_iter = [dep_evidence]
    elif isinstance(dep_evidence, list):
        dep_iter = dep_evidence
    else:
        dep_iter = []
    for dep in dep_iter:
        if not isinstance(dep, dict):
            continue
        crate = str((dep or {}).get("crate") or "").strip()
        if crate and crate in strong_crates:
            return True

    package_names = _lockfile_package_names(item.get("project_dir"))
    return bool(package_names & strong_crates)


def _generic_description(item: dict[str, Any], component: str, detail: str) -> str:
    source = item.get("source_label") or "auto-generated family rule"
    return f"{detail} ({item.get('project') or 'project'}; {component}; {source})."


def _component_meta(family: str) -> dict[str, Any]:
    meta = COMPONENT_METADATA.get(family)
    if not meta:
        raise KeyError(f"No component metadata for family={family!r}")
    return meta


def _component_crates(meta: dict[str, Any]) -> list[str]:
    return _dedupe(
        list(meta.get("package_aliases") or [])
        + list(meta.get("sys_crates") or [])
        + list(meta.get("high_level_crates") or [])
    )


def _generic_component_rule(item: dict[str, Any]) -> dict[str, Any]:
    family = str(item.get("family") or "").strip().lower()
    meta = _component_meta(family)
    package = meta["component"]
    positive_tokens = _dedupe(list(meta.get("input_tokens") or []) + _context_from_item(item) + [family, package])
    rust_entrypoints = _dedupe(list(meta.get("rust_entrypoints") or []))
    native_symbols = _dedupe(list(meta.get("native_symbols") or []))
    trigger_conditions: list[dict[str, Any]] = []
    if rust_entrypoints:
        trigger_conditions.append(
            {
                "id": f"{_slug(family)}_entry_any",
                "type": "any_of",
                "conditions": [
                    {"id": f"{_slug(family)}_rust_sink_{idx}", "type": "call", "name": path, "lang": "Rust"}
                    for idx, path in enumerate(rust_entrypoints[:12])
                ],
            }
        )
    elif native_symbols:
        trigger_conditions.append(
            {
                "id": f"{_slug(family)}_native_entry_any",
                "type": "any_of",
                "conditions": [
                    {"id": f"{_slug(family)}_native_symbol_{idx}", "type": "call", "name": symbol}
                    for idx, symbol in enumerate(native_symbols[:12])
                ],
            }
        )
    trigger_conditions.append(
        {
            "id": f"{_slug(family)}_input",
            "type": "input_class",
            "class": meta.get("input_class") or "crafted_input",
            "positive_tokens": positive_tokens[:12],
            "negative_tokens": [],
            "strategy": "assume_if_not_explicit",
        }
    )
    return {
        "cve": item.get("cve") or f"{package.upper()}-FAMILY",
        "package": package,
        "version_range": item.get("version_range") or ">=0",
        "match": {
            "crates": _match_crates(item, _component_crates(meta)),
        },
        "symbols": native_symbols[:12],
        "source_status": meta.get("default_source") or "system",
        "enforce_rust_sinks": False,
        "rust_sinks": [{"path": path} for path in rust_entrypoints[:12]],
        "input_predicate": {
            "class": meta.get("input_class") or "crafted_input",
            "positive_tokens": positive_tokens[:12],
            "negative_tokens": [],
            "strategy": "assume_if_not_explicit",
        },
        "context_patterns": _dedupe([family, package] + positive_tokens)[:16],
        "trigger_model": {
            "conditions": trigger_conditions,
            "mitigations": [],
        },
        "description": _generic_description(item, package, f"Generic {package} processing path"),
    }


def _build_libxml2_rule(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": item.get("cve", "CVE-2025-6021"),
        "package": "libxml2",
        "version_range": "<2.14.4",
        "match": {
            "crates": _match_crates(item, ["libxml", "libxslt", "xmlsec"]),
        },
        "symbols": [
            "xmlReadMemory",
            "htmlReadMemory",
            "xmlReadDoc",
            "htmlReadDoc",
            "xmlCreatePushParserCtxt",
            "xmlParseChunk",
            "xmlC14NDocDumpMemory",
        ],
        "source_status": "system",
        "enforce_rust_sinks": False,
        "rust_sinks": [
            {"path": "xmlReadMemory"},
            {"path": "htmlReadMemory"},
            {"path": "xmlReadDoc"},
            {"path": "htmlReadDoc"},
            {"path": "xmlCreatePushParserCtxt"},
            {"path": "xmlParseChunk"},
            {"path": "xmlC14NDocDumpMemory"},
            {"path": "Parser::parse_string"},
            {"path": "Parser::parse_file"},
            {"path": "Parser::parse_reader"},
        ],
        "input_predicate": {
            "class": "crafted_xml_or_html_input",
            "strategy": "assume_if_not_explicit",
        },
        "context_patterns": list(dict.fromkeys(["xml", "html", "xpath", "schema", "c14n", "document", "parser", "xslt", "xmlsec"] + _context_from_item(item))),
        "trigger_model": {
            "conditions": [
                {
                    "id": "libxml2_parse_entry",
                    "type": "any_of",
                    "conditions": [
                        {"id": "rust_sink_parse_string", "type": "call", "name": "Parser::parse_string", "lang": "Rust"},
                        {"id": "rust_sink_parse_file", "type": "call", "name": "Parser::parse_file", "lang": "Rust"},
                        {"id": "rust_sink_parse_reader", "type": "call", "name": "Parser::parse_reader", "lang": "Rust"},
                        {"id": "rust_sink_xmlReadMemory", "type": "call", "name": "xmlReadMemory"},
                        {"id": "rust_sink_htmlReadMemory", "type": "call", "name": "htmlReadMemory"},
                        {"id": "rust_sink_xmlReadDoc", "type": "call", "name": "xmlReadDoc"},
                        {"id": "rust_sink_htmlReadDoc", "type": "call", "name": "htmlReadDoc"},
                        {"id": "rust_sink_xmlParseChunk", "type": "call", "name": "xmlParseChunk"},
                    ],
                },
                {
                    "id": "libxml2_input",
                    "type": "input_class",
                    "class": "crafted_xml_or_html_input",
                    "positive_tokens": ["xml", "html", "parser", "document", "xpath", "schema", "c14n"],
                    "negative_tokens": [],
                    "strategy": "assume_if_not_explicit",
                },
            ],
            "mitigations": [],
        },
        "description": _generic_description(item, "libxml2", "Generic libxml2 parse/transform path"),
    }


def _build_zlib_rule(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": item.get("cve", "CVE-2022-37434"),
        "package": "zlib",
        "version_range": "<1.2.13",
        "match": {
            "crates": _match_crates(item, ["libz-sys", "flate2", "zlib", "zlib-rs"]),
        },
        "symbols": [
            "inflateGetHeader",
            "inflate",
        ],
        "source_status": "system",
        "enforce_rust_sinks": False,
        "rust_sinks": [
            {"path": "inflateGetHeader"},
        ],
        "input_predicate": {
            "class": "crafted_gzip_with_large_extra_field",
            "positive_tokens": ["gzip", "zlib", "inflate", "header", "extra", "fextra", "gz"],
            "negative_tokens": ["deflate", "raw"],
            "strategy": "assume_if_not_explicit",
        },
        "trigger_conditions": [
            "Rust code reaches inflateGetHeader on a gzip stream",
            "inflate is subsequently used to process the same stream",
        ],
        "context_patterns": list(
            dict.fromkeys(["zlib", "gzip", "inflate", "header", "extra", "fextra", "libz"] + _context_from_item(item))
        ),
        "trigger_model": {
            "conditions": [
                {
                    "id": "inflate_get_header",
                    "type": "call",
                    "name": "inflateGetHeader",
                    "lang": "Rust",
                },
                {
                    "id": "inflate_followup",
                    "type": "call",
                    "name": "inflate",
                    "lang": "Rust",
                },
                {
                    "id": "gzip_extra_input",
                    "type": "input_class",
                    "class": "crafted_gzip_with_large_extra_field",
                    "positive_tokens": ["gzip", "header", "extra", "fextra", "inflate", "zlib"],
                    "negative_tokens": ["deflate", "raw"],
                    "strategy": "assume_if_not_explicit",
                },
            ],
            "mitigations": [],
        },
        "description": _generic_description(item, "zlib", "Generic inflateGetHeader -> inflate path for gzip extra-field parsing"),
    }


def _build_libheif_rule(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": item.get("cve", "CVE-2025-68431"),
        "package": "libheif",
        "version_range": "<1.21.0",
        "match": {
            "crates": _match_crates(item, ["libheif-rs", "libheif-sys"]),
        },
        "symbols": [
            "heif_context_read_from_file",
            "heif_context_read_from_memory_without_copy",
            "heif_decode_image",
        ],
        "source_status": "system",
        "enforce_rust_sinks": False,
        "rust_sinks": [
            {"path": "HeifContext::read_from_file"},
            {"path": "HeifContext::read_from_bytes"},
            {"path": "ImageHandle::decode"},
            {"path": "decode"},
        ],
        "input_predicate": {
            "class": "crafted_heif_or_heic_file",
            "strategy": "assume_if_not_explicit",
        },
        "context_patterns": list(dict.fromkeys(["heif", "heic", "image", "decode", "metadata"] + _context_from_item(item))),
        "description": _generic_description(item, "libheif", "Generic libheif read/decode path"),
    }


def _build_libwebp_rule(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": item.get("cve", "CVE-2023-4863"),
        "package": "libwebp",
        "version_range": "<1.3.2",
        "match": {
            "crates": _match_crates(item, ["webp", "libwebp-sys"]),
        },
        "symbols": [
            "WebPDecode",
            "VP8LDecodeImage",
            "WebPDecodeRGBA",
            "WebPDecodeBGRA",
        ],
        "enforce_rust_sinks": False,
        "rust_sinks": [
            {"path": "webp::Decoder::new"},
            {"path": "webp::Decoder::decode"},
            {"path": "Decoder::new", "context_tokens": ["webp"], "contains": ["decode"], "contains_all": False},
            {"path": "Decoder::decode", "context_tokens": ["webp"]},
            {"path": "libwebp::WebPDecodeRGBA"},
            {"path": "libwebp::WebPDecodeRGB"},
            {"path": "WebPDecodeRGBA", "context_tokens": ["webp"]},
            {"path": "WebPDecodeRGB", "context_tokens": ["webp"]},
            {"path": "webp_load_rgba_from_memory"},
            {"path": "webp_load_rgb_from_memory"},
        ],
        "input_predicate": {
            "class": "crafted_webp_lossless",
            "strategy": "assume_if_not_explicit",
        },
        "context_patterns": list(dict.fromkeys(["webp", "image", "thumbnail", "decode", "compress"] + _context_from_item(item))),
        "trigger_model": {
            "conditions": [
                {
                    "id": "libwebp_decode_entry",
                    "type": "any_of",
                    "conditions": [
                        {"id": "decoder_new", "type": "call", "name": "webp::Decoder::new", "lang": "Rust"},
                        {"id": "decoder_decode", "type": "call", "name": "webp::Decoder::decode", "lang": "Rust"},
                        {"id": "decode_rgba", "type": "call", "name": "WebPDecodeRGBA", "lang": "Rust"},
                        {"id": "decode_rgb", "type": "call", "name": "WebPDecodeRGB", "lang": "Rust"},
                        {"id": "decode_wrapper_rgba", "type": "call", "name": "webp_load_rgba_from_memory", "lang": "Rust"},
                        {"id": "decode_wrapper_rgb", "type": "call", "name": "webp_load_rgb_from_memory", "lang": "Rust"},
                    ],
                },
                {
                    "id": "libwebp_input",
                    "type": "input_class",
                    "class": "crafted_webp_lossless",
                    "positive_tokens": ["webp", "image", "decode", "thumbnail", "rgba", "rgb"],
                    "negative_tokens": [],
                    "strategy": "assume_if_not_explicit",
                },
            ],
            "mitigations": [],
        },
        "description": _generic_description(item, "libwebp", "Generic WebP decode path"),
    }


def _build_libgit2_rule(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": item.get("cve", "CVE-2024-24575"),
        "package": "libgit2",
        "version_range": "<1.7.2",
        "match": {
            "crates": _match_crates(item, ["git2", "libgit2-sys"]),
        },
        "symbols": [
            "git_revparse_single",
            "git_revparse_ext",
        ],
        "source_status": "bundled",
        "enforce_rust_sinks": False,
        "rust_sinks": [
            {"path": "git2::Repository::revparse_single"},
            {"path": "git2::Repository::revparse_ext"},
            {"path": "Repository::revparse_single"},
            {"path": "Repository::revparse_ext"},
        ],
        "input_predicate": {
            "class": "crafted_revspec",
            "positive_tokens": ["rev", "spec", "tag", "branch", "head", "commit", "range", "git"],
            "negative_tokens": [],
            "strategy": "assume_if_not_explicit",
        },
        "context_patterns": list(dict.fromkeys(["git", "revparse", "revspec", "tag", "branch", "head", "range"] + _context_from_item(item))),
        "description": _generic_description(item, "libgit2", "Generic libgit2 revparse path"),
    }


def _build_pcre2_rule(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": item.get("cve", "CVE-2025-58050"),
        "package": "pcre2-sys",
        "version_range": ">=10.45,<10.46",
        "match": {
            "crates": _match_crates(item, ["pcre2", "pcre2-sys", "grep-pcre2"]),
        },
        "symbols": [
            "pcre2_match_8",
            "pcre2_match",
        ],
        "source_status": "system",
        "enforce_rust_sinks": False,
        "rust_sinks": [
            {"path": "pcre2::bytes::RegexBuilder::build"},
            {"path": "RegexBuilder::build", "context_tokens": ["pcre2"]},
            {"path": "pcre2::bytes::Regex::captures"},
            {"path": "pcre2::bytes::Regex::is_match"},
            {"path": "pcre2::bytes::Regex::find_iter"},
            {"path": "Regex::captures", "context_tokens": ["pcre2"]},
            {"path": "Regex::is_match", "context_tokens": ["pcre2"]},
            {"path": "Regex::find_iter", "context_tokens": ["pcre2"]},
            {"path": "grep_pcre2::RegexMatcherBuilder::build"},
            {"path": "grep_pcre2::RegexMatcher::new"},
            {"path": "RegexMatcherBuilder::build", "context_tokens": ["pcre2", "regex", "matcher"]},
            {"path": "RegexMatcher::new", "context_tokens": ["pcre2", "regex", "matcher"]},
        ],
        "input_predicate": {
            "class": "crafted_pcre2_scan_substring_pattern",
            "positive_tokens": ["regex", "pattern", "pcre2", "scs", "scan", "substring", "accept"],
            "negative_tokens": [],
            "strategy": "assume_if_not_explicit",
        },
        "context_patterns": list(
            dict.fromkeys(["pcre2", "regex", "pattern", "scs", "scan", "substring", "accept", "match"] + _context_from_item(item))
        ),
        "trigger_model": {
            "conditions": [
                {
                    "id": "pcre2_pattern_build",
                    "type": "any_of",
                    "conditions": [
                        {"id": "pcre2_builder_build", "type": "call", "name": "RegexBuilder::build", "lang": "Rust"},
                        {"id": "pcre2_grep_wrapper_build", "type": "call", "name": "RegexMatcherBuilder::build", "lang": "Rust"},
                        {"id": "pcre2_wrapper_new", "type": "call", "name": "RegexMatcher::new", "lang": "Rust"},
                    ],
                },
                {
                    "id": "pcre2_match_use",
                    "type": "any_of",
                    "conditions": [
                        {"id": "pcre2_regex_captures", "type": "call", "name": "Regex::captures", "lang": "Rust"},
                        {"id": "pcre2_regex_is_match", "type": "call", "name": "Regex::is_match", "lang": "Rust"},
                        {"id": "pcre2_regex_find_iter", "type": "call", "name": "Regex::find_iter", "lang": "Rust"},
                    ],
                },
                {
                    "id": "pcre2_scan_substring_pattern",
                    "type": "input_class",
                    "class": "crafted_pcre2_scan_substring_pattern",
                    "positive_tokens": ["regex", "pattern", "pcre2", "scs", "scan", "substring", "accept"],
                    "negative_tokens": [],
                    "strategy": "assume_if_not_explicit",
                },
            ],
            "mitigations": [],
        },
        "description": _generic_description(item, "PCRE2", "Generic PCRE2 scan-substring + ACCEPT match path"),
    }


def _build_sqlite_rule(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": item.get("cve", "CVE-2022-35737"),
        "package": "sqlite",
        "version_range": "<3.39.2",
        "match": {
            "crates": _match_crates(item, ["rusqlite", "libsqlite3-sys"]),
        },
        "symbols": [
            "sqlite3_bind_text64",
            "sqlite3_bind_blob64",
            "sqlite3_exec",
        ],
        "source_status": "system",
        "enforce_rust_sinks": False,
        "rust_sinks": [
            {"path": "rusqlite::Connection::execute"},
            {"path": "rusqlite::Connection::execute_batch"},
            {"path": "rusqlite::Statement::execute"},
            {"path": "Connection::execute"},
            {"path": "rusqlite::Connection::query_row"},
            {"path": "rusqlite::Connection::query_map"},
            {"path": "rusqlite::Statement::query"},
            {"path": "rusqlite::Connection::prepare"},
        ],
        "input_predicate": {
            "class": "extremely_large_string",
            "positive_tokens": ["sql", "sqlite", "query", "insert", "text", "string", "blob"],
            "negative_tokens": [],
            "strategy": "solve_if_length_explicit_else_assume",
        },
        "context_patterns": list(dict.fromkeys(["sqlite", "sql", "query", "execute", "blob", "text", "string"] + _context_from_item(item))),
        "trigger_model": {
            "conditions": [
                {
                    "id": "sqlite_exec_any",
                    "type": "any_of",
                    "conditions": [
                        {"id": "sqlite_execute", "type": "call", "name": "execute", "lang": "Rust"},
                        {"id": "sqlite_execute_batch", "type": "call", "name": "execute_batch", "lang": "Rust"},
                        {"id": "sqlite_query_row", "type": "call", "name": "query_row", "lang": "Rust"},
                        {"id": "sqlite_query_map", "type": "call", "name": "query_map", "lang": "Rust"},
                        {"id": "sqlite_statement_query", "type": "call", "name": "Statement::query", "lang": "Rust"},
                        {"id": "sqlite_prepare", "type": "call", "name": "prepare", "lang": "Rust"},
                    ],
                },
                {
                    "id": "sqlite_large_string",
                    "type": "input_class",
                    "class": "extremely_large_string",
                    "positive_tokens": ["sql", "sqlite", "query", "insert", "text", "string", "blob"],
                    "negative_tokens": [],
                    "strategy": "solve_if_length_explicit_else_assume",
                },
            ],
            "mitigations": [],
        },
        "description": _generic_description(item, "SQLite", "Generic SQLite large text/blob bind path"),
    }


def _build_libarchive_rule(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": item.get("cve", "LIBARCHIVE-2025-FAMILY"),
        "package": "libarchive",
        "version_range": ">=0",
        "match": {
            "crates": _match_crates(item, ["compress-tools", "libarchive", "libarchive3-sys"]),
        },
        "symbols": [
            "archive_read_open_filename",
            "archive_read_open_memory",
            "archive_read_open_fd",
            "archive_read_next_header",
            "archive_read_data",
            "archive_read_data_block",
        ],
        "source_status": "system",
        "enforce_rust_sinks": False,
        "rust_sinks": [
            {"path": "compress_tools::ArchiveIterator::from_read"},
            {"path": "ArchiveIterator::from_read", "context_tokens": ["compress", "archive"]},
            {"path": "compress_tools::ArchiveIterator::from_read_with_encoding"},
            {"path": "ArchiveIterator::from_read_with_encoding", "context_tokens": ["compress", "archive"]},
            {"path": "compress_tools::list_archive_files"},
            {"path": "list_archive_files", "context_tokens": ["compress", "archive"]},
            {"path": "compress_tools::uncompress_archive"},
            {"path": "uncompress_archive", "context_tokens": ["compress", "archive"]},
            {"path": "compress_tools::uncompress_archive_file"},
            {"path": "uncompress_archive_file", "context_tokens": ["compress", "archive"]},
        ],
        "input_predicate": {
            "class": "crafted_archive_file",
            "positive_tokens": ["archive", "tar", "zip", "cpio", "7z", "rar", "extract", "uncompress"],
            "negative_tokens": [],
            "strategy": "assume_if_not_explicit",
        },
        "context_patterns": list(
            dict.fromkeys(["archive", "libarchive", "compress", "extract", "tar", "zip", "cpio", "7z", "rar"] + _context_from_item(item))
        ),
        "trigger_model": {
            "conditions": [
                {
                    "id": "libarchive_entry",
                    "type": "any_of",
                    "conditions": [
                        {"id": "archive_iterator_from_read", "type": "call", "name": "ArchiveIterator::from_read", "lang": "Rust"},
                        {"id": "archive_iterator_from_read_with_encoding", "type": "call", "name": "ArchiveIterator::from_read_with_encoding", "lang": "Rust"},
                        {"id": "list_archive_files", "type": "call", "name": "list_archive_files", "lang": "Rust"},
                        {"id": "uncompress_archive", "type": "call", "name": "uncompress_archive", "lang": "Rust"},
                        {"id": "uncompress_archive_file", "type": "call", "name": "uncompress_archive_file", "lang": "Rust"},
                    ],
                },
                {
                    "id": "libarchive_input",
                    "type": "input_class",
                    "class": "crafted_archive_file",
                    "positive_tokens": ["archive", "tar", "zip", "cpio", "7z", "rar", "extract", "uncompress"],
                    "negative_tokens": [],
                    "strategy": "assume_if_not_explicit",
                },
            ],
            "mitigations": [],
        },
        "description": _generic_description(item, "libarchive", "Generic libarchive open/list/extract path"),
    }


def _build_openssl_rule(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": item.get("cve", "CVE-2022-3602"),
        "package": "openssl",
        "version_range": ">=3.0.0,<3.0.7",
        "match": {
            "crates": _match_crates(
                item,
                [
                    "openssl",
                    "openssl-sys",
                    "native-tls",
                    "tokio-native-tls",
                    "tokio-openssl",
                    "hyper-openssl",
                    "postgres-openssl",
                    "actix-tls",
                ],
            ),
        },
        "symbols": [
            "X509_verify_cert",
            "SSL_connect",
            "SSL_accept",
            "SSL_do_handshake",
        ],
        "source_status": "system",
        "enforce_rust_sinks": False,
        "rust_sinks": [
            {"path": "SslConnector::builder"},
            {"path": "SslConnector::connect"},
            {"path": "SslAcceptor::builder"},
            {"path": "SslAcceptor::accept"},
            {"path": "TlsConnector::builder"},
            {"path": "TlsConnector::connect"},
            {"path": "SslStream::connect"},
            {"path": "SslStream::accept"},
            {"path": "connect_async"},
            {"path": "accept_async"},
        ],
        "input_predicate": {
            "class": "crafted_x509_certificate",
            "positive_tokens": [
                "x509",
                "certificate",
                "cert",
                "ssl",
                "tls",
                "handshake",
                "verify",
            ],
            "negative_tokens": [],
            "strategy": "assume_if_not_explicit",
        },
        "context_patterns": list(dict.fromkeys(["openssl", "ssl", "tls", "x509", "certificate", "handshake", "verify"] + _context_from_item(item))),
        "description": _generic_description(item, "OpenSSL", "Generic OpenSSL certificate verification / handshake path"),
    }


def _build_gstreamer_rule(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": item.get("cve", "CVE-2024-0444"),
        "package": "gstreamer",
        "version_range": "<1.22.9",
        "match": {
            "crates": _match_crates(item, ["gstreamer", "gstreamer-sys", "gstreamer-app", "gstreamer-video"]),
        },
        "symbols": [
            "gst_parse_launch",
            "gst_element_factory_make",
        ],
        "source_status": "system",
        "enforce_rust_sinks": True,
        "rust_sinks": [
            {"path": "gstreamer::parse::launch"},
            {"path": "gst::parse::launch"},
            {"path": "gstreamer::ElementFactory::make"},
            {"path": "gst::ElementFactory::make"},
        ],
        "input_predicate": {
            "class": "crafted_media_stream_or_pipeline",
            "positive_tokens": ["gstreamer", "gst", "pipeline", "rtsp", "rtp", "video", "stream", "av1"],
            "negative_tokens": [],
            "strategy": "assume_if_not_explicit",
        },
        "context_patterns": list(dict.fromkeys(["gstreamer", "gst", "pipeline", "video", "stream", "rtsp", "rtp", "av1"] + _context_from_item(item))),
        "description": _generic_description(item, "GStreamer", "Generic GStreamer pipeline/media parsing path"),
    }


def _build_libjpeg_turbo_rule(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": item.get("cve", "CVE-2023-2804"),
        "package": "libjpeg-turbo",
        "version_range": "<2.1.5.1",
        "match": {
            "crates": _match_crates(item, ["turbojpeg", "turbojpeg-sys"]),
        },
        "symbols": [
            "tjDecompressHeader3",
            "tjDecompress2",
        ],
        "source_status": "system",
        "enforce_rust_sinks": True,
        "rust_sinks": [
            {"path": "turbojpeg::Decompressor::read_header"},
            {"path": "turbojpeg::Decompressor::decompress"},
            {"path": "turbojpeg::decompress_image"},
            {"path": "Decompressor::read_header", "context_tokens": ["turbojpeg"]},
            {"path": "Decompressor::decompress", "context_tokens": ["turbojpeg"]},
            {"path": "decompress_image", "context_tokens": ["turbojpeg"]},
        ],
        "input_predicate": {
            "class": "crafted_jpeg_image",
            "positive_tokens": ["jpeg", "jpg", "mjpeg", "turbojpeg", "frame", "image", "decode"],
            "negative_tokens": [],
            "strategy": "assume_if_not_explicit",
        },
        "context_patterns": list(dict.fromkeys(["jpeg", "jpg", "mjpeg", "turbojpeg", "image", "decode"] + _context_from_item(item))),
        "trigger_model": {
            "conditions": [
                {
                    "id": "jpeg_header_any",
                    "type": "any_of",
                    "conditions": [
                        {"id": "read_header", "type": "call", "name": "Decompressor::read_header", "lang": "Rust"},
                        {"id": "decompress", "type": "call", "name": "Decompressor::decompress", "lang": "Rust"},
                        {"id": "decompress_image", "type": "call", "name": "decompress_image", "lang": "Rust"},
                    ],
                },
                {
                    "id": "jpeg_input",
                    "type": "input_class",
                    "class": "crafted_jpeg_image",
                    "positive_tokens": ["jpeg", "jpg", "mjpeg", "turbojpeg", "image", "decode"],
                    "negative_tokens": [],
                    "strategy": "assume_if_not_explicit",
                },
            ],
            "mitigations": [],
        },
        "description": _generic_description(item, "libjpeg-turbo", "Generic JPEG decode path via turbojpeg"),
    }


def _build_gdal_rule(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": item.get("cve", "CVE-2021-45943"),
        "package": "gdal",
        "version_range": ">=3.3.0,<=3.4.0",
        "match": {
            "crates": _match_crates(item, ["gdal", "gdal-sys"]),
        },
        "symbols": [
            "GDALOpen",
            "GDALOpenEx",
            "GDALDatasetRasterIOEx",
            "GDALRasterIOEx",
        ],
        "source_status": "system",
        "enforce_rust_sinks": False,
        "rust_sinks": [
            {"path": "gdal::Dataset::open"},
            {"path": "gdal::Dataset::open_ex"},
            {"path": "Dataset::open"},
            {"path": "Dataset::open_ex"},
            {"path": "RasterBand::read_as"},
            {"path": "RasterBand::read_into_slice"},
            {"path": "Dataset::rasterband"},
        ],
        "input_predicate": {
            "class": "crafted_gdal_dataset",
            "positive_tokens": [
                "gdal",
                "dataset",
                "raster",
                "open",
                "driver",
                "path",
                "pcidsk",
                "pix",
            ],
            "negative_tokens": [],
            "strategy": "assume_if_not_explicit",
        },
        "context_patterns": list(dict.fromkeys(["gdal", "dataset", "raster", "driver", "pcidsk", "pix", "geospatial"] + _context_from_item(item))),
        "trigger_model": {
            "conditions": [
                {
                    "id": "gdal_dataset_entry",
                    "type": "any_of",
                    "conditions": [
                        {"id": "dataset_open", "type": "call", "name": "Dataset::open", "lang": "Rust"},
                        {"id": "dataset_open_ex", "type": "call", "name": "Dataset::open_ex", "lang": "Rust"},
                        {"id": "raster_read_as", "type": "call", "name": "RasterBand::read_as", "lang": "Rust"},
                        {"id": "raster_read_into_slice", "type": "call", "name": "RasterBand::read_into_slice", "lang": "Rust"},
                    ],
                },
                {
                    "id": "gdal_input",
                    "type": "input_class",
                    "class": "crafted_gdal_dataset",
                    "positive_tokens": ["gdal", "dataset", "raster", "pcidsk", "pix", "path", "driver"],
                    "negative_tokens": [],
                    "strategy": "assume_if_not_explicit",
                },
            ],
            "mitigations": [],
        },
        "description": _generic_description(item, "GDAL", "Generic GDAL dataset open/raster read path for PCIDSK-triggered parsing"),
    }


def _build_openh264_rule(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": item.get("cve", "CVE-2025-27091"),
        "package": "openh264-sys2",
        "version_range": "<0.8.0",
        "match": {
            "crates": _match_crates(item, ["openh264", "openh264-sys2"]),
        },
        "symbols": [
            "WelsDecodeBs",
        ],
        "source_status": "binary-only",
        "enforce_rust_sinks": True,
        "rust_sinks": [
            {"path": "openh264::decoder::Decoder::decode"},
            {
                "path": "Decoder::decode",
                "context_tokens": ["openh264"],
                "contains": ["packet", "buf", "bytes", "nal", "frame", "sample", "as_slice"],
                "contains_all": False,
            },
            {"path": "OpenH264API::from_source", "context_tokens": ["openh264"]},
            {"path": "Decoder::with_api_config", "context_tokens": ["openh264"]},
        ],
        "input_predicate": {
            "class": "crafted_h264_bitstream",
            "positive_tokens": ["openh264", "h264", "nal", "annexb", "annex-b", "decode"],
            "negative_tokens": ["gstreamer", "avdec_h264", "rtph264depay", "webrtc"],
            "strategy": "assume_if_not_explicit",
        },
        "trigger_conditions": [
            "attacker-controlled H.264 bytes reach OpenH264 decoder",
            "Rust code forwards packet or buffer bytes into Decoder::decode",
        ],
        "context_patterns": list(dict.fromkeys(["openh264", "h264", "nal", "video", "packet", "decode"] + _context_from_item(item))),
        "trigger_model": {
            "conditions": [
                {
                    "id": "openh264_input_context",
                    "type": "input_class",
                    "class": "crafted_h264_bitstream",
                    "positive_tokens": ["openh264", "h264", "nal", "annexb", "annex-b", "decode"],
                    "negative_tokens": ["gstreamer", "avdec_h264", "rtph264depay", "webrtc"],
                    "strategy": "assume_if_not_explicit",
                },
            ],
            "mitigations": [],
        },
        "description": _generic_description(item, "OpenH264", "Generic OpenH264 decode path"),
    }


def _build_freetype_rule(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": item.get("cve", "CVE-2025-27363"),
        "package": "freetype",
        "version_range": "<2.13.1",
        "match": {
            "crates": _match_crates(item, ["freetype-rs", "freetype-sys", "servo-freetype-sys", "freetype"]),
        },
        "symbols": [
            "FT_New_Face",
            "FT_Open_Face",
            "FT_Load_Glyph",
            "FT_Load_Char",
            "FT_Render_Glyph",
            "FT_Set_Char_Size",
        ],
        "source_status": "system",
        "enforce_rust_sinks": True,
        "rust_sinks": [
            {"path": "Library::init"},
            {"path": "Library::new_face", "contains": ["font", "face", "path"], "contains_all": False},
            {"path": "Face::load_glyph", "contains": ["glyph", "render", "font"], "contains_all": False},
            {"path": "Face::load_char", "contains": ["char", "glyph", "render", "font"], "contains_all": False},
            {"path": "Face::set_char_size", "contains": ["char_size", "size", "font"], "contains_all": False},
        ],
        "input_predicate": {
            "class": "crafted_font_file",
            "positive_tokens": ["font", "glyph", "ttf", "otf", "woff", "face", "rasterizer", "freetype"],
            "negative_tokens": [],
            "strategy": "assume_if_not_explicit",
        },
        "context_patterns": list(
            dict.fromkeys(
                ["freetype", "font", "glyph", "face", "ttf", "otf", "rasterizer", "render"] + _context_from_item(item)
            )
        ),
        "trigger_model": {
            "conditions": [
                {
                    "id": "freetype_library_init",
                    "type": "call",
                    "name": "Library::init",
                    "lang": "Rust",
                },
                {
                    "id": "freetype_open_face",
                    "type": "any_of",
                    "conditions": [
                        {"type": "call", "name": "new_face", "lang": "Rust"},
                        {"type": "call", "name": "FT_New_Face"},
                        {"type": "call", "name": "FT_Open_Face"},
                    ],
                },
                {
                    "id": "freetype_load_glyph",
                    "type": "any_of",
                    "conditions": [
                        {"type": "call", "name": "load_glyph", "lang": "Rust"},
                        {"type": "call", "name": "load_char", "lang": "Rust"},
                        {"type": "call", "name": "FT_Load_Glyph"},
                        {"type": "call", "name": "FT_Load_Char"},
                        {"type": "call", "name": "FT_Render_Glyph"},
                    ],
                },
                {
                    "id": "freetype_font_input",
                    "type": "input_class",
                    "class": "crafted_font_file",
                    "positive_tokens": ["font", "glyph", "ttf", "otf", "woff", "face", "rasterizer", "freetype"],
                    "strategy": "assume_if_not_explicit",
                },
            ],
            "mitigations": [],
        },
        "description": _generic_description(item, "FreeType", "Generic FreeType font face loading and glyph rendering path"),
    }


RULE_BUILDERS = {
    "zlib": _build_zlib_rule,
    "libarchive": _build_libarchive_rule,
    "libxml2": _build_libxml2_rule,
    "libheif": _build_libheif_rule,
    "libwebp": _build_libwebp_rule,
    "libgit2": _build_libgit2_rule,
    "pcre2": _build_pcre2_rule,
    "sqlite": _build_sqlite_rule,
    "openssl": _build_openssl_rule,
    "gstreamer": _build_gstreamer_rule,
    "libjpeg-turbo": _build_libjpeg_turbo_rule,
    "gdal": _build_gdal_rule,
    "openh264": _build_openh264_rule,
    "freetype": _build_freetype_rule,
}


def can_auto_generate(item: dict[str, Any]) -> bool:
    family = str(item.get("family") or "").strip().lower()
    return family in RULE_BUILDERS or family in COMPONENT_METADATA


def generate_vulns_payload(item: dict[str, Any]) -> list[dict[str, Any]]:
    family = str(item.get("family") or "").strip().lower()
    builder = RULE_BUILDERS.get(family)
    if builder:
        return [builder(item)]
    if family in COMPONENT_METADATA:
        return [_generic_component_rule(item)]
    if not builder:
        raise KeyError(f"No auto rule template for family={family!r}")
    return [builder(item)]


def generate_extras_payload(item: dict[str, Any]) -> dict[str, Any]:
    family = str(item.get("family") or "").strip().lower()
    component = FAMILY_COMPONENTS.get(family)
    if not component:
        raise KeyError(f"No auto extras template for family={family!r}")
    meta = _component_meta(family)
    project_name = item.get("project") or Path(str(item.get("project_dir") or "")).name
    source_label = item.get("source_label") or "auto-generated family rule"
    depends = []
    if _has_strong_native_dep_evidence(item, component, meta):
        depends.append(
            {
                "from": project_name,
                "to": component,
                "evidence_type": "manual",
                "confidence": "medium",
                "source": source_label,
                "evidence": f"root package uses native component {component}",
            }
        )
    return {
        "packages": [
            {
                "name": component,
                "lang": "C",
            }
        ],
        "depends": depends,
    }
