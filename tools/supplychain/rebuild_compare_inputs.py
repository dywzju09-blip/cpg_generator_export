#!/usr/bin/env python3
"""
Rebuild compare baselines and rerun manifests from archived case directories.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
from collections import defaultdict
from pathlib import Path
from typing import Any

from auto_vuln_inputs import FAMILY_COMPONENTS


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def case_json_paths(cases_root: Path) -> list[Path]:
    paths = []
    for path in cases_root.rglob("case.json"):
        parts = path.parts
        if "_runs" in parts:
            continue
        paths.append(path)
    return sorted(paths)


def parse_project_and_version(project_dir: Path) -> tuple[str, str]:
    base = project_dir.parent.name if project_dir.name == "upstream" else project_dir.name
    if "-" in base:
        name, version = base.rsplit("-", 1)
        if version and version[0].isdigit():
            return name, version
    return base, ""


def parse_first_command(run_log_path: Path) -> list[str]:
    if not run_log_path.exists():
        return []
    for line in run_log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("$ "):
            return shlex.split(line[2:].strip())
    return []


def extract_cli_hints(run_log_path: Path) -> dict[str, Any]:
    argv = parse_first_command(run_log_path)
    hints: dict[str, Any] = {
        "root": None,
        "root_method": None,
        "cpg_input": None,
        "cargo_features": "",
        "cargo_all_features": False,
        "cargo_no_default_features": False,
    }
    if not argv:
        return hints

    flag_values = {
        "--root": "root",
        "--root-method": "root_method",
        "--cpg-input": "cpg_input",
        "--cargo-features": "cargo_features",
    }
    i = 0
    while i < len(argv):
        token = argv[i]
        if token in flag_values and i + 1 < len(argv):
            hints[flag_values[token]] = argv[i + 1]
            i += 2
            continue
        if token == "--cargo-all-features":
            hints["cargo_all_features"] = True
        elif token == "--cargo-no-default-features":
            hints["cargo_no_default_features"] = True
        i += 1
    return hints


def relative_code_hit(project_dir: Path, cpg_input: str | None) -> str:
    if not cpg_input:
        return ""
    try:
        return Path(cpg_input).resolve().relative_to(project_dir.resolve()).as_posix()
    except Exception:
        return Path(cpg_input).name


def family_from_vulnerability(vulnerability: str) -> str:
    if "__" not in vulnerability:
        return ""
    return vulnerability.split("__", 1)[1]


def baseline_row(case: dict[str, Any]) -> dict[str, Any]:
    keys = [
        "rel",
        "vulnerability",
        "project_name",
        "status",
        "category",
        "label",
        "reachable",
        "triggerable",
        "result_kind",
        "resolved_version",
        "symbol",
        "project_source",
        "analysis_run",
        "report",
        "log",
        "manual_dir",
        "manual_input",
        "note",
    ]
    return {key: case.get(key) for key in keys}


def manifest_item_from_case(case: dict[str, Any]) -> dict[str, Any]:
    project_dir = Path(str(case["project_source"])).resolve()
    project, version = parse_project_and_version(project_dir)
    vulnerability = str(case.get("vulnerability") or "")
    family = family_from_vulnerability(vulnerability)
    component = FAMILY_COMPONENTS.get(family, family or None)

    analysis_run = Path(str(case.get("analysis_run") or ""))
    log_path = analysis_run / "run.log"
    report_path = analysis_run / "analysis_report.json"
    cli_hints = extract_cli_hints(log_path)
    report = load_json(report_path) if report_path.exists() else {}
    cpg_bootstrap = report.get("cpg_bootstrap") or {}

    cpg_input = cli_hints.get("cpg_input") or cpg_bootstrap.get("input_file")
    root = cli_hints.get("root") or report.get("root")
    root_method = cli_hints.get("root_method") or "main"

    item = {
        "rel": case.get("rel"),
        "project_dir": str(project_dir),
        "project": project,
        "version": version,
        "family": family,
        "component": component,
        "cve": vulnerability.split("__", 1)[0] if "__" in vulnerability else vulnerability,
        "cve_dir": vulnerability,
        "source_label": "reconstructed compare manifest",
        "dependency_evidence": [],
        "code_hit_file": relative_code_hit(project_dir, cpg_input),
        "root_method": root_method,
        "cargo_features": cli_hints.get("cargo_features") or "",
        "cargo_all_features": bool(cli_hints.get("cargo_all_features")),
        "cargo_no_default_features": bool(cli_hints.get("cargo_no_default_features")),
    }
    if root:
        item["root"] = root
    if cpg_input:
        item["cpg_input"] = str(Path(cpg_input).resolve())
    return item


def build_outputs(
    cases_root: Path,
    output_dir: Path,
    *,
    rel_prefix: str = "",
    include_vulnerabilities: set[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    baseline: list[dict[str, Any]] = []
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for case_path in case_json_paths(cases_root):
        case = load_json(case_path)
        rel = str(case.get("rel") or "")
        vulnerability = str(case.get("vulnerability") or "")
        if rel_prefix and not rel.startswith(rel_prefix):
            continue
        if include_vulnerabilities and vulnerability not in include_vulnerabilities:
            continue
        baseline.append(baseline_row(case))
        item = manifest_item_from_case(case)
        grouped[item["family"]].append(item)

    baseline.sort(key=lambda row: (str(row.get("vulnerability") or ""), str(row.get("rel") or "")))
    for items in grouped.values():
        items.sort(key=lambda item: str(item.get("rel") or ""))

    write_json(output_dir / "old_baseline.json", baseline)
    all_items = []
    for family in sorted(grouped):
        items = grouped[family]
        all_items.extend(items)
        write_json(output_dir / "inputs" / f"{family}.manifest.json", items)
    write_json(output_dir / "inputs" / "all.manifest.json", all_items)
    return baseline, grouped


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Rebuild compare baseline/manifests from archived cases.")
    parser.add_argument("--cases-root", required=True, help="Root like .../VUL/cases/by-analysis-status")
    parser.add_argument("--output-dir", required=True, help="Destination directory for baseline and manifests")
    parser.add_argument("--rel-prefix", default="", help="Only include cases whose rel starts with this prefix")
    parser.add_argument(
        "--vulnerability",
        action="append",
        default=[],
        help="Optional vulnerability filter like CVE-2025-27091__openh264 (repeatable)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cases_root = Path(os.path.expanduser(args.cases_root)).resolve()
    output_dir = Path(os.path.expanduser(args.output_dir)).resolve()
    include_vulnerabilities = set(args.vulnerability or [])
    baseline, grouped = build_outputs(
        cases_root,
        output_dir,
        rel_prefix=args.rel_prefix,
        include_vulnerabilities=include_vulnerabilities or None,
    )
    summary = {
        "cases_root": str(cases_root),
        "output_dir": str(output_dir),
        "baseline_count": len(baseline),
        "families": {family: len(items) for family, items in sorted(grouped.items())},
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
