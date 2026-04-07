#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
import tomllib


FAMILY_TO_CVE = {
    "openssl": "CVE-2022-3602",
    "zlib": "CVE-2022-37434",
    "sqlite": "CVE-2022-35737",
    "libgit2": "CVE-2024-24575",
    "pcre2": "CVE-2022-1586",
    "libxml2": "CVE-2025-6021",
    "libwebp": "CVE-2023-4863",
    "libheif": "CVE-2025-68431",
    "gdal": "CVE-2021-45943",
    "openh264": "CVE-2025-27091",
    "freetype": "CVE-2025-27363",
    "gstreamer": "CVE-2024-0444",
}

PRIORITY = [
    "openh264",
    "libheif",
    "libwebp",
    "gdal",
    "gstreamer",
    "pcre2",
    "libxml2",
    "libgit2",
    "sqlite",
    "freetype",
    "openssl",
    "zlib",
]

FAMILY_PATTERNS = {
    "openssl": {"openssl", "native-tls", "tokio-openssl", "openssl-sys"},
    "zlib": {"libz-sys", "zlib", "flate2", "miniz_oxide"},
    "sqlite": {"sqlite", "sqlite3", "libsqlite3-sys", "rusqlite"},
    "libgit2": {"git2", "libgit2-sys", "libgit2"},
    "pcre2": {"pcre2", "pcre2-sys"},
    "libxml2": {"libxml", "libxml2", "libxml-sys"},
    "libwebp": {"webp", "libwebp", "libwebp-sys"},
    "libheif": {"heif", "libheif", "libheif-sys"},
    "gdal": {"gdal", "gdal-sys"},
    "openh264": {"openh264", "openh264-sys"},
    "freetype": {"freetype", "freetype-rs", "freetype-sys"},
    "gstreamer": {"gstreamer", "gstreamer-sys"},
}


def split_feature_token(token: str) -> set[str]:
    parts = re.split(r"[/?:]", token.lower())
    return {part for part in parts if part}


def collect_tokens(table: object, out: set[str]) -> None:
    if not isinstance(table, dict):
        return
    for key, value in table.items():
        if key in {"dependencies", "dev-dependencies", "build-dependencies"} and isinstance(value, dict):
            for dep_name, spec in value.items():
                out.add(dep_name.lower())
                if isinstance(spec, dict):
                    package = spec.get("package")
                    if isinstance(package, str):
                        out.add(package.lower())
                    features = spec.get("features")
                    if isinstance(features, list):
                        for feature in features:
                            if isinstance(feature, str):
                                out.update(split_feature_token(feature))
        elif key == "features" and isinstance(value, dict):
            for _, feature_values in value.items():
                if isinstance(feature_values, list):
                    for feature in feature_values:
                        if isinstance(feature, str):
                            out.update(split_feature_token(feature))
        elif key == "target" and isinstance(value, dict):
            for _, nested in value.items():
                collect_tokens(nested, out)


def detect_families(cargo_toml: Path) -> list[str]:
    data = tomllib.loads(cargo_toml.read_text())
    tokens: set[str] = set()
    collect_tokens(data, tokens)
    matched = []
    for family in PRIORITY:
        if tokens & FAMILY_PATTERNS[family]:
            matched.append(family)
    return matched


def build_outputs(root: Path) -> tuple[list[dict], list[dict]]:
    manifest_items: list[dict] = []
    inventory: list[dict] = []
    for cargo_toml in sorted(root.glob("*/upstream/Cargo.toml")):
        project_dir = cargo_toml.parent
        project_key = project_dir.parent.name
        project_name = project_key.split("__", 1)[1] if "__" in project_key else project_key
        rel = str(project_dir.relative_to(root.parent.parent))
        families = detect_families(cargo_toml)
        if families:
            family = families[0]
            cve = FAMILY_TO_CVE[family]
            cve_dir = f"{cve}__{family}"
            manifest_items.append(
                {
                    "rel": rel,
                    "project_dir": str(project_dir),
                    "project": project_name,
                    "version": "",
                    "source_label": "cargo_toml_scan",
                    "family": family,
                    "component": family,
                    "cve": cve,
                    "cve_dir": cve_dir,
                }
            )
            inventory.append(
                {
                    "project": project_name,
                    "project_key": project_key,
                    "project_dir": str(project_dir),
                    "matched_families": families,
                    "selected_family": family,
                    "selected_cve_dir": cve_dir,
                    "analysis_status": "ready_for_analysis",
                    "note": f"primary family {family} selected from matches {families}",
                }
            )
            continue

        manifest_items.append(
            {
                "rel": rel,
                "project_dir": str(project_dir),
                "project": project_name,
                "version": "",
                "source_label": "cargo_toml_scan",
                "family": "unknown",
                "component": "unknown",
                "cve": "UNKNOWN-CVE",
                "cve_dir": "UNKNOWN-CVE__unknown",
                "skip_reason": "error: could not derive a supported target vulnerability family from Cargo.toml",
            }
        )
        inventory.append(
            {
                "project": project_name,
                "project_key": project_key,
                "project_dir": str(project_dir),
                "matched_families": [],
                "selected_family": "unknown",
                "selected_cve_dir": "UNKNOWN-CVE__unknown",
                "analysis_status": "rule_mapping_missing",
                "note": "no supported family match found in Cargo.toml scan",
            }
        )
    return manifest_items, inventory


def write_summary(summary_path: Path, inventory: list[dict]) -> None:
    family_counts = Counter(item["selected_family"] for item in inventory)
    status_counts = Counter(item["analysis_status"] for item in inventory)
    lines = [
        "# Analysis Batch Summary",
        "",
        f"- total projects: {len(inventory)}",
        f"- ready_for_analysis: {status_counts.get('ready_for_analysis', 0)}",
        f"- rule_mapping_missing: {status_counts.get('rule_mapping_missing', 0)}",
        "",
        "## Family Counts",
        "",
    ]
    for family, count in sorted(family_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"- {family}: {count}")
    summary_path.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, help="Directory containing per-project folders with upstream/Cargo.toml")
    parser.add_argument("--manifest-out", required=True)
    parser.add_argument("--inventory-out", required=True)
    parser.add_argument("--summary-out", required=True)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    manifest_items, inventory = build_outputs(root)

    Path(args.manifest_out).write_text(json.dumps(manifest_items, indent=2, ensure_ascii=False) + "\n")
    Path(args.inventory_out).write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n")
    write_summary(Path(args.summary_out), inventory)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
