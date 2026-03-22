#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.supplychain.vuln_db import (
    DEFAULT_DB_INDEX_DIR,
    default_runtime_rules_path,
    load_json,
    write_json,
)


def _name_variants(text: str) -> set[str]:
    raw = str(text or "").strip()
    if not raw:
        return set()
    items = {raw, raw.lower(), raw.replace("-", "_"), raw.replace("_", "-")}
    lowered = raw.lower()
    if lowered.startswith("lib") and len(lowered) > 3:
        items.add(lowered[3:])
    return {item for item in items if item}


def run_cargo_metadata(cargo_dir: Path, *, cargo_features: str = "", cargo_all_features: bool = False, cargo_no_default_features: bool = False) -> dict:
    cmd = ["cargo", "metadata", "--format-version", "1"]
    if cargo_all_features:
        cmd.append("--all-features")
    elif cargo_features.strip():
        cmd.extend(["--features", cargo_features.strip()])
    if cargo_no_default_features:
        cmd.append("--no-default-features")
    proc = subprocess.run(cmd, cwd=str(cargo_dir), capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "cargo metadata failed")
    return json.loads(proc.stdout)


def crates_from_metadata(meta: dict) -> set[str]:
    crates = set()
    for pkg in meta.get("packages") or []:
        for variant in _name_variants(pkg.get("name") or ""):
            crates.add(variant)
    return crates


def select_rules_from_crates(
    crate_names: set[str],
    rules: list[dict],
    components_by_crate: dict[str, list[str]],
    *,
    curated_only: bool = False,
) -> tuple[list[dict], dict]:
    normalized_crates = set()
    for crate in crate_names:
        normalized_crates.update(_name_variants(crate))

    matched_components = set()
    for crate in normalized_crates:
        for component in components_by_crate.get(crate, []):
            matched_components.add(component)

    selected = []
    for rule in rules:
        if curated_only and rule.get("maturity") != "curated":
            continue
        package = str(rule.get("package") or "")
        rule_crates = set()
        for crate in (rule.get("match") or {}).get("crates") or []:
            rule_crates.update(_name_variants(crate))
        package_keys = _name_variants(package)
        if matched_components and package in matched_components:
            selected.append(rule)
            continue
        if normalized_crates & rule_crates:
            selected.append(rule)
            continue
        if normalized_crates & package_keys:
            selected.append(rule)
            continue

    summary = {
        "project_crates": sorted(crate_names),
        "matched_components": sorted(matched_components),
        "selected_rules": len(selected),
    }
    return selected, summary


def write_selected_rules_for_project(
    project_dir: Path,
    output_path: Path,
    *,
    runtime_rules_path: Path | None = None,
    components_by_crate_path: Path | None = None,
    curated_only: bool = False,
    fallback_to_full_db: bool = True,
    cargo_features: str = "",
    cargo_all_features: bool = False,
    cargo_no_default_features: bool = False,
) -> dict:
    runtime_rules_path = runtime_rules_path or default_runtime_rules_path()
    components_by_crate_path = components_by_crate_path or (DEFAULT_DB_INDEX_DIR / "components_by_crate.json")
    rules = load_json(runtime_rules_path)
    components_by_crate = load_json(components_by_crate_path)
    meta = run_cargo_metadata(
        project_dir,
        cargo_features=cargo_features,
        cargo_all_features=cargo_all_features,
        cargo_no_default_features=cargo_no_default_features,
    )
    crate_names = crates_from_metadata(meta)
    selected, summary = select_rules_from_crates(
        crate_names,
        rules,
        components_by_crate,
        curated_only=curated_only,
    )
    if not selected:
        if fallback_to_full_db:
            selected = rules
            summary["fallback"] = "no_match_use_full_db"
            summary["selected_rules"] = len(selected)
        else:
            summary["fallback"] = "no_match"
            summary["selected_rules"] = 0
    write_json(output_path, selected)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Select project-relevant vulnerability rules from the database")
    parser.add_argument("--cargo-dir", required=True, help="Path to Cargo project")
    parser.add_argument("--out", required=True, help="Output JSON path")
    parser.add_argument("--db-rules", default=str(default_runtime_rules_path()), help="Runtime rules JSON path")
    parser.add_argument(
        "--components-by-crate",
        default=str(DEFAULT_DB_INDEX_DIR / "components_by_crate.json"),
        help="components_by_crate.json path",
    )
    parser.add_argument("--curated-only", action="store_true", help="Keep only curated rules")
    parser.add_argument(
        "--no-fallback-to-full-db",
        action="store_true",
        help="If no relevant rules are matched, write an empty set instead of the full database",
    )
    parser.add_argument("--cargo-features", default="", help="Extra cargo features")
    parser.add_argument("--cargo-all-features", action="store_true", help="Use --all-features")
    parser.add_argument("--cargo-no-default-features", action="store_true", help="Use --no-default-features")
    args = parser.parse_args()

    summary = write_selected_rules_for_project(
        Path(args.cargo_dir).resolve(),
        Path(args.out).resolve(),
        runtime_rules_path=Path(args.db_rules).resolve(),
        components_by_crate_path=Path(args.components_by_crate).resolve(),
        curated_only=args.curated_only,
        fallback_to_full_db=not args.no_fallback_to_full_db,
        cargo_features=args.cargo_features,
        cargo_all_features=args.cargo_all_features,
        cargo_no_default_features=args.cargo_no_default_features,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
