#!/usr/bin/env python3
"""
Auto-generate family-level vulns/extras inputs when a curated rule mapping is absent.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


FAMILY_COMPONENTS = {
    "zlib": "zlib",
    "libxml2": "libxml2",
    "libheif": "libheif",
    "libwebp": "libwebp",
    "libgit2": "libgit2",
    "sqlite": "sqlite",
    "pcre2": "pcre2",
    "openssl": "openssl",
    "gdal": "gdal",
    "openh264": "openh264-sys2",
    "freetype": "freetype",
    "gstreamer": "gstreamer",
    "libjpeg-turbo": "libjpeg-turbo",
}


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
    for dep in item.get("dependency_evidence") or []:
        crate = str((dep or {}).get("crate") or "").strip()
        if crate and crate not in crates:
            crates.append(crate)
    return crates


def _generic_description(item: dict[str, Any], component: str, detail: str) -> str:
    source = item.get("source_label") or "auto-generated family rule"
    return f"{detail} ({item.get('project') or 'project'}; {component}; {source})."


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
        "enforce_rust_sinks": True,
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
        "enforce_rust_sinks": True,
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
        "enforce_rust_sinks": True,
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
        "enforce_rust_sinks": True,
        "rust_sinks": [
            {"path": "webp::Decoder::new"},
            {"path": "webp::Decoder::decode"},
            {"path": "Decoder::new"},
            {"path": "Decoder::decode"},
        ],
        "input_predicate": {
            "class": "crafted_webp_lossless",
            "strategy": "assume_if_not_explicit",
        },
        "context_patterns": list(dict.fromkeys(["webp", "image", "thumbnail", "decode", "compress"] + _context_from_item(item))),
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
        "enforce_rust_sinks": True,
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
        "cve": item.get("cve", "CVE-2022-1586"),
        "package": "pcre2-sys",
        "version_range": "<10.40",
        "match": {
            "crates": _match_crates(item, ["pcre2", "pcre2-sys"]),
        },
        "symbols": [
            "pcre2_jit_compile_8",
        ],
        "source_status": "system",
        "enforce_rust_sinks": True,
        "rust_sinks": [
            {"path": "pcre2::bytes::RegexBuilder::build"},
            {"path": "RegexBuilder::build"},
            {"path": "grep_pcre2::RegexMatcherBuilder::build"},
        ],
        "env_guards": {
            "all": [
                {"type": "feature_enabled", "feature": "jit"},
            ]
        },
        "input_predicate": {
            "class": "crafted_regex_pattern",
            "positive_tokens": ["regex", "pattern", "jit", "pcre2"],
            "negative_tokens": [],
            "strategy": "assume_if_not_explicit",
        },
        "context_patterns": list(dict.fromkeys(["pcre2", "regex", "jit", "pattern", "grep", "match"] + _context_from_item(item))),
        "description": _generic_description(item, "PCRE2", "Generic PCRE2 JIT compile path"),
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
        "enforce_rust_sinks": True,
        "rust_sinks": [
            {"path": "rusqlite::Connection::execute"},
            {"path": "rusqlite::Connection::execute_batch"},
            {"path": "rusqlite::Statement::execute"},
            {"path": "Connection::execute"},
        ],
        "input_predicate": {
            "class": "extremely_large_string",
            "positive_tokens": ["sql", "sqlite", "query", "insert", "text", "string", "blob"],
            "negative_tokens": [],
            "strategy": "solve_if_length_explicit_else_assume",
        },
        "context_patterns": list(dict.fromkeys(["sqlite", "sql", "query", "execute", "blob", "text", "string"] + _context_from_item(item))),
        "description": _generic_description(item, "SQLite", "Generic SQLite large text/blob bind path"),
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
        "enforce_rust_sinks": True,
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
            {"path": "Decompressor::read_header"},
            {"path": "Decompressor::decompress"},
        ],
        "input_predicate": {
            "class": "crafted_jpeg_image",
            "positive_tokens": ["jpeg", "jpg", "mjpeg", "turbojpeg", "frame", "image", "decode"],
            "negative_tokens": [],
            "strategy": "assume_if_not_explicit",
        },
        "context_patterns": list(dict.fromkeys(["jpeg", "jpg", "mjpeg", "turbojpeg", "image", "decode"] + _context_from_item(item))),
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
        "enforce_rust_sinks": True,
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
            {
                "path": "Decoder::decode",
                "contains": ["packet", "buf", "bytes", "nal", "frame", "sample", "as_slice"],
                "contains_all": False,
            },
        ],
        "input_predicate": {
            "class": "crafted_h264_bitstream",
            "positive_tokens": ["h264", "nal", "annexb", "annex-b", "packet", "video", "rtp"],
            "negative_tokens": [],
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
                    "positive_tokens": ["h264", "nal", "video", "packet", "annexb", "annex-b", "rtp"],
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
    return family in RULE_BUILDERS


def generate_vulns_payload(item: dict[str, Any]) -> list[dict[str, Any]]:
    family = str(item.get("family") or "").strip().lower()
    builder = RULE_BUILDERS.get(family)
    if not builder:
        raise KeyError(f"No auto rule template for family={family!r}")
    return [builder(item)]


def generate_extras_payload(item: dict[str, Any]) -> dict[str, Any]:
    family = str(item.get("family") or "").strip().lower()
    component = FAMILY_COMPONENTS.get(family)
    if not component:
        raise KeyError(f"No auto extras template for family={family!r}")
    project_name = item.get("project") or Path(str(item.get("project_dir") or "")).name
    source_label = item.get("source_label") or "auto-generated family rule"
    return {
        "packages": [
            {
                "name": component,
                "lang": "C",
            }
        ],
        "depends": [
            {
                "from": project_name,
                "to": component,
                "evidence_type": "manual",
                "confidence": "medium",
                "source": source_label,
                "evidence": f"root package uses native component {component}",
            }
        ],
    }
