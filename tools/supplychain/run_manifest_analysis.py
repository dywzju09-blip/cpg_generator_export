#!/usr/bin/env python3
"""
Run batch supply-chain analysis from a manifest and optionally archive the run.

Manifest format:
[
  {
    "rel": "NEW/projects/bevy_video-0.9.1/upstream",
    "project_dir": "/abs/path/to/project",
    "cve_dir": "CVE-2025-27091__openh264",
    "vulns": "/abs/path/to/vulns.json",
    "extras": "/abs/path/to/extras.json",
    "root": "bevy_video",
    "root_method": "main",
    "cpg_input": "/abs/path/to/main.rs",
    "cargo_features": "",
    "cargo_all_features": false,
    "cargo_no_default_features": false
  }
]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any


CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent.parent
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "output" / "vulnerability_runs"
DEFAULT_VUL_ROOT = Path(os.environ.get("SUPPLYCHAIN_VUL_ROOT", "/Users/dingyanwen/Desktop/VUL")).resolve()

if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from archive_analysis_run import archive_run
from auto_vuln_inputs import can_auto_generate, generate_extras_payload, generate_vulns_payload


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def infer_project_and_version(project_dir: Path) -> tuple[str, str]:
    base = project_dir.parent.name if project_dir.name == "upstream" else project_dir.name
    if "-" in base:
        name, version = base.rsplit("-", 1)
        if version and version[0].isdigit():
            return name, version
    return base, ""


def run_dir_name(item: dict[str, Any]) -> str:
    rel = item.get("rel") or os.path.relpath(item["project_dir"], start=DEFAULT_VUL_ROOT)
    suffix = "__".join(Path(rel).parts)
    return f"{item['cve_dir']}__{suffix}"


def normalize_item(item: dict[str, Any]) -> dict[str, Any]:
    if "project_dir" not in item:
        raise ValueError("manifest item missing project_dir")
    if "cve_dir" not in item:
        raise ValueError("manifest item missing cve_dir")
    if "vulns" not in item and not item.get("skip_reason") and not can_auto_generate(item):
        raise ValueError("manifest item missing vulns")
    project_dir = Path(item["project_dir"]).resolve()
    project, version = infer_project_and_version(project_dir)
    rel = item.get("rel")
    if not rel:
        try:
            rel = os.path.relpath(project_dir, start=DEFAULT_VUL_ROOT)
        except Exception:
            rel = str(project_dir)
    normalized = dict(item)
    normalized["project_dir"] = str(project_dir)
    normalized["project"] = item.get("project") or project
    normalized["version"] = item.get("version") or version
    normalized["rel"] = rel
    normalized["root_method"] = item.get("root_method") or "main"
    normalized["cargo_features"] = item.get("cargo_features") or ""
    normalized["cargo_all_features"] = bool(item.get("cargo_all_features"))
    normalized["cargo_no_default_features"] = bool(item.get("cargo_no_default_features"))
    normalized["family"] = item.get("family")
    normalized["cve"] = item.get("cve")
    normalized["component"] = item.get("component")
    normalized["code_hit_file"] = item.get("code_hit_file")
    normalized["source_label"] = item.get("source_label")
    normalized["dependency_evidence"] = item.get("dependency_evidence") or []
    return normalized


def copy_or_generate_input_json(
    src: Path | None,
    dest: Path,
    default_payload: Any,
    *,
    generator=None,
) -> None:
    if src and src.exists():
        shutil.copy2(src, dest)
    elif generator is not None:
        write_json(dest, generator())
    else:
        write_json(dest, default_payload)


def build_command(item: dict[str, Any], run_case_dir: Path, *, disable_native_source_supplement: bool = False) -> list[str]:
    inputs_dir = run_case_dir / "analysis_inputs"
    report_path = run_case_dir / "analysis_report.json"
    cmd = [
        sys.executable,
        str(CURRENT_DIR / "supplychain_analyze.py"),
        "--cargo-dir",
        item["project_dir"],
        "--vulns",
        str(inputs_dir / "vulns.json"),
        "--report",
        str(report_path),
        "--root-method",
        item["root_method"],
    ]
    if item.get("root"):
        cmd.extend(["--root", str(item["root"])])
    if item.get("cpg_input"):
        cmd.extend(["--cpg-input", str(item["cpg_input"])])
    if (inputs_dir / "extras.json").exists():
        cmd.extend(["--extras", str(inputs_dir / "extras.json")])
    if item.get("cargo_features"):
        cmd.extend(["--cargo-features", str(item["cargo_features"])])
    if item.get("cargo_all_features"):
        cmd.append("--cargo-all-features")
    if item.get("cargo_no_default_features"):
        cmd.append("--cargo-no-default-features")
    if disable_native_source_supplement:
        cmd.append("--disable-native-source-supplement")
    return cmd


def extract_summary_fields(report_path: Path) -> dict[str, Any]:
    if not report_path.exists():
        return {
            "reachable": False,
            "triggerable": None,
            "result_kind": None,
            "resolved_version": None,
            "symbol": None,
            "component": None,
            "status": "analysis_failed",
        }
    report = load_json(report_path)
    vulns = report.get("vulnerabilities") or []
    if not vulns:
        return {
            "reachable": False,
            "triggerable": None,
            "result_kind": None,
            "resolved_version": None,
            "symbol": None,
            "component": None,
            "status": "analysis_failed",
        }
    vuln = vulns[0]
    reachable = bool(vuln.get("reachable"))
    triggerable = vuln.get("triggerable")
    status = "analysis_failed"
    if triggerable == "confirmed":
        status = "triggerable_confirmed"
    elif triggerable == "possible":
        status = "triggerable_possible"
    elif reachable and triggerable == "false_positive":
        status = "reachable_only"
    elif reachable:
        status = "reachable_only"
    elif triggerable == "unreachable" or reachable is False:
        status = "not_reachable"
    return {
        "reachable": reachable,
        "triggerable": triggerable,
        "result_kind": vuln.get("result_kind"),
        "resolved_version": vuln.get("resolved_version"),
        "symbol": vuln.get("symbol"),
        "component": vuln.get("package"),
        "status": status,
    }


def run_one(
    item: dict[str, Any],
    run_root: Path,
    timeout_seconds: int,
    *,
    disable_native_source_supplement: bool = False,
) -> dict[str, Any]:
    case_dir = run_root / run_dir_name(item)
    ensure_dir(case_dir / "analysis_inputs")

    if item.get("skip_reason"):
        write_json(case_dir / "analysis_inputs" / "vulns.json", [])
        write_json(case_dir / "analysis_inputs" / "extras.json", {"packages": [], "depends": []})
        log_path = case_dir / "run.log"
        log_path.write_text(
            f"Skipped analysis for {item['project_dir']}\nReason: {item['skip_reason']}\n",
            encoding="utf-8",
        )
        return {
            "rel": item["rel"],
            "project": item["project"],
            "version": item["version"],
            "project_dir": item["project_dir"],
            "run_dir": str(case_dir),
            "report": str(case_dir / "analysis_report.json"),
            "log": str(log_path),
            "exit_code": 1,
            "seconds": 0.0,
            "status": "analysis_failed",
            "reachable": False,
            "triggerable": None,
            "result_kind": None,
            "resolved_version": None,
            "symbol": item.get("symbol"),
            "cve_dir": item["cve_dir"],
            "component": item.get("component"),
        }

    vulns_src = Path(item["vulns"]).resolve() if item.get("vulns") else None
    copy_or_generate_input_json(
        vulns_src,
        case_dir / "analysis_inputs" / "vulns.json",
        [],
        generator=(lambda: generate_vulns_payload(item)) if not vulns_src else None,
    )
    extras_src = Path(item["extras"]).resolve() if item.get("extras") else None
    copy_or_generate_input_json(
        extras_src,
        case_dir / "analysis_inputs" / "extras.json",
        {"packages": [], "depends": []},
        generator=(lambda: generate_extras_payload(item)) if not extras_src and can_auto_generate(item) else None,
    )

    cmd = build_command(
        item,
        case_dir,
        disable_native_source_supplement=disable_native_source_supplement,
    )
    start = time.time()
    exit_code = 1
    timed_out = False
    stdout = ""
    stderr = ""
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        exit_code = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = -15
        stdout = exc.stdout or ""
        stderr = (exc.stderr or "") + f"\nTimed out after {timeout_seconds} seconds."
    seconds = round(time.time() - start, 2)

    log_path = case_dir / "run.log"
    log_path.write_text(
        f"$ {' '.join(cmd)}\n\n[stdout]\n{stdout}\n\n[stderr]\n{stderr}\n",
        encoding="utf-8",
    )

    summary = extract_summary_fields(case_dir / "analysis_report.json")
    if timed_out:
        summary["status"] = "analysis_timeout"
        summary["reachable"] = False
        summary["triggerable"] = None
        summary["result_kind"] = None
    elif exit_code != 0 and summary["status"] == "analysis_failed":
        summary["reachable"] = False
        summary["triggerable"] = None
        summary["result_kind"] = None

    return {
        "rel": item["rel"],
        "project": item["project"],
        "version": item["version"],
        "project_dir": item["project_dir"],
        "run_dir": str(case_dir),
        "report": str(case_dir / "analysis_report.json"),
        "log": str(log_path),
        "exit_code": exit_code,
        "seconds": seconds,
        "status": summary["status"],
        "reachable": summary["reachable"],
        "triggerable": summary["triggerable"],
        "result_kind": summary["result_kind"],
        "resolved_version": summary["resolved_version"],
        "symbol": summary["symbol"],
        "cve_dir": item["cve_dir"],
        "component": summary["component"] or item.get("component"),
    }


def build_readme(entries: list[dict[str, Any]], source_manifest: Path) -> str:
    counts = Counter(entry["status"] for entry in entries)
    lines = [
        f"# {source_manifest.stem}",
        "",
        f"本轮对 manifest `{source_manifest}` 中的 {len(entries)} 个项目做了批量检测。",
        "",
        "## 总体结果",
        "",
    ]
    for status in sorted(counts):
        lines.append(f"- `{status}`: {counts[status]}")
    return "\n".join(lines) + "\n"


def write_run_summary(run_root: Path, manifest_path: Path, entries: list[dict[str, Any]]) -> None:
    confirmed = [entry for entry in entries if entry["status"] == "triggerable_confirmed"]
    failed = [entry for entry in entries if entry["status"] == "analysis_failed"]
    timed_out = [entry for entry in entries if entry["status"] == "analysis_timeout"]
    write_json(run_root / "summary.json", entries)
    write_json(run_root / "summary_projects.json", entries)
    write_json(run_root / "confirmed_projects.json", confirmed)
    write_json(run_root / "failed_projects.json", failed)
    write_json(run_root / "timed_out_projects.json", timed_out)
    write_json(run_root / "status_counts.json", dict(Counter(entry["status"] for entry in entries)))
    write_json(
        run_root / "manifest.json",
        [
            {
                "rel": entry["rel"],
                "project_dir": entry["project_dir"],
                "run_dir": entry["run_dir"],
                "report": entry["report"],
                "log": entry["log"],
                "status": entry["status"],
                "cve_dir": entry["cve_dir"],
            }
            for entry in entries
        ],
    )
    write_json(run_root / "summary_seed.json", {"manifest": str(manifest_path), "count": len(entries)})
    write_json(run_root / "summary.partial.json", entries)
    (run_root / "README.md").write_text(build_readme(entries, manifest_path), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="Manifest JSON describing projects and rules")
    parser.add_argument("--run-name", required=True, help="Run name, used under output/vulnerability_runs/<run-name>")
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT), help="Base directory for temporary run output")
    parser.add_argument("--timeout-seconds", type=int, default=900, help="Per-project timeout in seconds")
    parser.add_argument(
        "--archive-dest-root",
        default="",
        help="If set, archive the completed run into VUL/cases/by-analysis-status and remove the source run",
    )
    parser.add_argument(
        "--disable-native-source-supplement",
        action="store_true",
        help="Skip on-demand native source supplementation during batch analysis",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest_path = Path(args.manifest).resolve()
    output_root = Path(args.output_root).resolve()
    run_root = output_root / args.run_name
    if run_root.exists():
        shutil.rmtree(run_root)
    ensure_dir(run_root)

    raw_manifest = load_json(manifest_path)
    items = raw_manifest.get("items", raw_manifest) if isinstance(raw_manifest, dict) else raw_manifest
    normalized = [normalize_item(item) for item in items]
    entries = []
    total = len(normalized)
    for idx, item in enumerate(normalized, start=1):
        print(f"[{idx}/{total}] analyzing {item['project']} ({item['cve_dir']})", flush=True)
        entry = run_one(
            item,
            run_root,
            args.timeout_seconds,
            disable_native_source_supplement=args.disable_native_source_supplement,
        )
        entries.append(entry)
        print(
            f"[{idx}/{total}] status={entry['status']} triggerable={entry['triggerable']} "
            f"reachable={entry['reachable']} seconds={entry['seconds']}",
            flush=True,
        )
        write_json(run_root / "summary.partial.json", entries)
    write_run_summary(run_root, manifest_path, entries)

    if args.archive_dest_root:
        archive_run(run_root, Path(args.archive_dest_root).resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
