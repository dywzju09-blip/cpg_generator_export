#!/usr/bin/env python3
"""
Archive one supply-chain analysis run into VUL/cases/by-analysis-status.

Behavior:
- Move each per-project run directory into the matching case directory under VUL.
- Keep project_source as a symlink into the VUL source tree.
- Generate case.json and README.md for every case.
- Regenerate by-analysis-status/README.md and index.json.
- Store run-level summaries under by-analysis-status/_runs/<run_name>/.

This script is intended to be the final step after a batch detection run completes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from collections import Counter
from pathlib import Path
from typing import Any


CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.common.path_defaults import infer_archive_root


ROOT_DEFAULT = infer_archive_root(REPO_ROOT)


CATEGORY_LABELS = {
    "01_runnable_and_observable_triggered": "runnable_and_observable_triggered",
    "02_runnable_and_path_triggered": "runnable_and_path_triggered",
    "03_runnable_but_not_observed": "runnable_but_not_observed",
    "03_runnable_static_triggerable_confirmed": "runnable_static_triggerable_confirmed",
    "03_runnable_static_triggerable_possible": "runnable_static_triggerable_possible",
    "04_runnable_reachable_only": "runnable_reachable_only",
    "05_runnable_not_reachable": "runnable_not_reachable",
    "06_not_runnable_analysis_failed": "not_runnable_analysis_failed",
    "07_not_runnable_timeout": "not_runnable_timeout",
}


README_CATEGORY_LINES = [
    ("01_runnable_and_observable_triggered", "可运行，且已人工观测到漏洞本体"),
    ("02_runnable_and_path_triggered", "可运行，且已人工确认恶意输入进入真实 native 路径"),
    ("03_runnable_but_not_observed", "可运行，但人工未观测到漏洞本体"),
    ("03_runnable_static_triggerable_confirmed", "可运行，静态为 confirmed，但尚未人工复核"),
    ("03_runnable_static_triggerable_possible", "可运行，静态为 possible，但尚未人工复核"),
    ("04_runnable_reachable_only", "可运行，仅可达"),
    ("05_runnable_not_reachable", "可运行，但不可达"),
    ("06_not_runnable_analysis_failed", "当前不可运行/不可完成分析：失败"),
    ("07_not_runnable_timeout", "当前不可运行/不可完成分析：超时"),
]


TOP_LEVEL_FILES = [
    "README.md",
    "summary.json",
    "summary_projects.json",
    "confirmed_projects.json",
    "failed_projects.json",
    "timed_out_projects.json",
    "status_counts.json",
    "manifest.json",
    "summary_seed.json",
    "summary.partial.json",
]


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def relative_symlink(target: Path, link_path: Path) -> None:
    if link_path.exists() or link_path.is_symlink():
        if link_path.is_dir() and not link_path.is_symlink():
            shutil.rmtree(link_path)
        else:
            link_path.unlink()
    rel = os.path.relpath(target, start=link_path.parent)
    link_path.symlink_to(rel)


def run_name_from_root(run_root: Path) -> str:
    return run_root.name


def project_name_from_rel(rel: str) -> str:
    parts = list(Path(rel).parts)
    markers = {"projects", "pocs", "bindings"}
    start = 0
    for idx, part in enumerate(parts):
        if part in markers:
            start = idx + 1
            break
    relevant = parts[start:] if start < len(parts) else parts
    return "__".join(relevant)


def detect_category(item: dict[str, Any]) -> tuple[str, str, str]:
    status = item.get("status")
    reachable = item.get("reachable")
    triggerable = item.get("triggerable")

    if status == "analysis_failed":
        return (
            "06_not_runnable_analysis_failed",
            CATEGORY_LABELS["06_not_runnable_analysis_failed"],
            "Current workflow could not complete analysis because build, import, or analysis failed.",
        )
    if status == "analysis_timeout":
        return (
            "07_not_runnable_timeout",
            CATEGORY_LABELS["07_not_runnable_timeout"],
            "Current workflow timed out before producing a usable result.",
        )
    if status == "triggerable_confirmed":
        return (
            "03_runnable_static_triggerable_confirmed",
            CATEGORY_LABELS["03_runnable_static_triggerable_confirmed"],
            "Static analysis marked the vulnerable path confirmed, but no manual reproduction has been recorded yet.",
        )
    if status == "triggerable_possible" or triggerable == "possible":
        return (
            "03_runnable_static_triggerable_possible",
            CATEGORY_LABELS["03_runnable_static_triggerable_possible"],
            "Static analysis says the vulnerable path is possible, but no manual reproduction has been recorded yet.",
        )
    if status == "reachable_only" or (reachable and triggerable == "false_positive"):
        return (
            "04_runnable_reachable_only",
            CATEGORY_LABELS["04_runnable_reachable_only"],
            "Analysis completed and the vulnerable path is reachable, but current evidence says not triggerable.",
        )
    if status == "not_reachable" or triggerable == "unreachable" or reachable is False:
        return (
            "05_runnable_not_reachable",
            CATEGORY_LABELS["05_runnable_not_reachable"],
            "Analysis completed and no vulnerable path was found reachable.",
        )
    raise ValueError(f"Unsupported status combination: status={status!r} triggerable={triggerable!r}")


def _extract_skip_reason(lines: list[str]) -> str | None:
    for raw in lines:
        line = raw.strip()
        if line.startswith("Reason:"):
            return line.split("Reason:", 1)[1].strip()
    return None


def _extract_timeout_reason(text: str) -> str | None:
    match = re.search(r"Timed out after (\d+) seconds\.", text)
    if match:
        return f"Current workflow timed out after {match.group(1)} seconds before producing a usable result."
    return None


def _extract_preferred_error_line(text: str) -> str | None:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return None

    skip_reason = _extract_skip_reason(lines)
    if skip_reason:
        return skip_reason

    specialized_checks: list[tuple[str, str]] = [
        ("Failed to get --cflags from xmlsec1-config", "Current workflow failed because xmlsec1-config is missing from the current machine."),
        ("library 'heif' not found", "Current workflow failed because libheif is missing from the current machine."),
        ("libheif.pc", "Current workflow failed because libheif is missing from the current machine."),
        ("could not find system library 'MagickWand'", "Current workflow failed because MagickWand is missing from the current machine."),
        ("No package 'MagickWand' found", "Current workflow failed because MagickWand is missing from the current machine."),
        ("linux/videodev2.h", "Current workflow failed because this project requires Linux V4L2 headers, but the current environment is not Linux."),
    ]
    for needle, note in specialized_checks:
        if needle in text:
            return note

    preferred_patterns = [
        r"^error\[E\d+\]: .+$",
        r"^fatal error: .+$",
        r"^error: could not find system library .+$",
        r"^The system library .+$",
        r"^.+error: .+$",
        r"^error: .+$",
        r"^error: failed to run custom build command .+$",
        r"^Analysis failed with exit code .+$",
        r"^RuntimeError: .+failed \(exit=\d+\).+$",
        r"^RuntimeError: Rust CPG not available in Neo4j.+$",
        r"^thread 'main'.+$",
        r"^No curated .+ sink/rule mapping .+$",
        r"^.+No such file or directory.+$",
        r"^.+not found.+$",
    ]
    for pattern in preferred_patterns:
        for line in lines:
            if "failed to run custom build command" in line and pattern in {r"^.+error: .+$", r"^error: .+$"}:
                continue
            if re.match(pattern, line):
                return line

    return None


def refine_note(item: dict[str, Any], base_note: str) -> str:
    run_dir = Path(item["run_dir"])
    log_path = run_dir / "run.log"
    if not log_path.exists():
        return base_note
    text = log_path.read_text(encoding="utf-8", errors="ignore")
    if item.get("status") == "analysis_timeout":
        timeout_note = _extract_timeout_reason(text)
        if timeout_note:
            return timeout_note
    if "regex" in text and "mismatched types" in text:
        return "Current workflow failed because the project did not compile cleanly under the current dependency resolution."
    if item.get("status") == "analysis_failed":
        msg = _extract_preferred_error_line(text)
        if msg:
            if len(msg) > 220:
                msg = msg[:217] + "..."
            if msg.startswith("Current workflow"):
                return msg
            return f"Current workflow failed: {msg}"
    return base_note


def build_case_readme(case: dict[str, Any]) -> str:
    lines = [
        f"# {case['project_name']}",
        "",
        f"- 漏洞：`{case['vulnerability']}`",
        f"- 分类：`{case['category']}`",
        f"- 静态状态：`{case['status']}`",
        f"- reachable：`{case['reachable']}`",
        f"- triggerable：`{case['triggerable']}`",
        f"- result_kind：`{case['result_kind']}`",
        f"- 关键 sink/symbol：`{case['symbol'] or 'unknown'}`",
        "",
        "## 说明",
        "",
        f"- {case['note']}",
        "",
        "## 路径",
        "",
        "- 原始项目：`project_source/`",
        "- 分析产物：`analysis_run/`",
    ]
    if case.get("manual_dir"):
        lines.append("- 人工复现：`manual_repro/`")
    else:
        lines.append("- 人工复现：无")
    if case.get("manual_input"):
        lines.extend(["", "## 关键输入", "", f"- `{case['manual_input']}`"])
    return "\n".join(lines) + "\n"


def build_root_readme(index: list[dict[str, Any]]) -> str:
    counts = Counter(item["category"] for item in index)
    lines = [
        "# By Analysis Status",
        "",
        "目录结构固定为：`分类 / CVE 编号 / 项目名`。",
        "",
        "每个项目目录下都有：",
        "",
        "- `project_source/`：指向 VUL 原始项目目录的软链接",
        "- `analysis_run/`：该项目的实际分析结果目录",
        "- `manual_repro/`：如果做过人工复现，则放在这里",
        "- `case.json`：结构化元数据",
        "- `README.md`：快速说明",
        "",
        "run 级汇总归档在：`_runs/<run_name>/`。",
        "",
        "## 分类说明",
        "",
    ]
    for category, desc in README_CATEGORY_LINES:
        lines.append(f"- `{category}`：{desc}（{counts.get(category, 0)}）")
    lines.extend(
        [
            "",
            "## 立即优先查看",
            "",
            "- `01_runnable_and_observable_triggered`",
            "- `02_runnable_and_path_triggered`",
            "- `03_runnable_but_not_observed`",
            "- `03_runnable_static_triggerable_confirmed`",
        ]
    )
    return "\n".join(lines) + "\n"


def build_run_readme(run_name: str, entries: list[dict[str, Any]]) -> str:
    counts = Counter(item["status"] for item in entries)
    lines = [
        f"# {run_name}",
        "",
        "该目录保存一次批量检测 run 的汇总文件，路径都已重写到 `VUL/cases/by-analysis-status` 下。",
        "",
        "## 状态统计",
        "",
    ]
    for status in sorted(counts):
        lines.append(f"- `{status}`: {counts[status]}")
    return "\n".join(lines) + "\n"


def _refresh_case_note(case: dict[str, Any]) -> dict[str, Any]:
    _, _, base_note = detect_category(case)
    case["note"] = refine_note({"run_dir": case["analysis_run"], "status": case["status"]}, base_note)
    return case


def _write_case_dir(case: dict[str, Any]) -> None:
    case_dir = Path(case["analysis_run"]).parent
    write_json(case_dir / "case.json", case)
    (case_dir / "README.md").write_text(build_case_readme(case), encoding="utf-8")


def _rewrite_index(dest_root: Path, refreshed_entries: list[dict[str, Any]]) -> None:
    index_path = dest_root / "index.json"
    existing_index = load_json(index_path) if index_path.exists() else []
    refreshed_rels = {entry["rel"] for entry in refreshed_entries}
    merged_index = [entry for entry in existing_index if entry.get("rel") not in refreshed_rels]
    merged_index.extend(refreshed_entries)
    merged_index.sort(key=lambda x: (x["category"], x["vulnerability"], x["project_name"]))
    write_json(index_path, merged_index)
    (dest_root / "README.md").write_text(build_root_readme(merged_index), encoding="utf-8")


def refresh_archived_run(dest_root: Path, run_name: str) -> None:
    run_archive = dest_root / "_runs" / run_name
    summary_path = run_archive / "summary.json"
    if not summary_path.exists():
        raise FileNotFoundError(f"Missing archived run summary: {summary_path}")

    run_entries = load_json(summary_path)
    index_path = dest_root / "index.json"
    existing_index = load_json(index_path) if index_path.exists() else []
    existing_by_rel = {entry.get("rel"): entry for entry in existing_index}
    refreshed_entries: list[dict[str, Any]] = []
    for entry in run_entries:
        case_path = Path(entry["analysis_run"]).parent / "case.json"
        if case_path.exists():
            case = load_json(case_path)
        else:
            case = existing_by_rel.get(entry.get("rel")) or dict(entry)
        refreshed_entries.append(_refresh_case_note(case))
        _write_case_dir(refreshed_entries[-1])

    refreshed_entries.sort(key=lambda x: (x["category"], x["vulnerability"], x["project_name"]))
    _rewrite_index(dest_root, refreshed_entries)

    confirmed = [entry for entry in refreshed_entries if entry["status"] == "triggerable_confirmed"]
    failed = [entry for entry in refreshed_entries if entry["status"] == "analysis_failed"]
    timed_out = [entry for entry in refreshed_entries if entry["status"] == "analysis_timeout"]

    write_json(run_archive / "summary.json", refreshed_entries)
    write_json(run_archive / "summary_projects.json", refreshed_entries)
    write_json(run_archive / "confirmed_projects.json", confirmed)
    write_json(run_archive / "failed_projects.json", failed)
    write_json(run_archive / "timed_out_projects.json", timed_out)
    write_json(run_archive / "status_counts.json", dict(Counter(entry["status"] for entry in refreshed_entries)))
    write_json(
        run_archive / "manifest.json",
        [
            {
                "rel": entry["rel"],
                "category": entry["category"],
                "project_source": entry["project_source"],
                "analysis_run": entry["analysis_run"],
                "report": entry["report"],
                "log": entry["log"],
                "status": entry["status"],
            }
            for entry in refreshed_entries
        ],
    )
    (run_archive / "README.md").write_text(build_run_readme(run_name, refreshed_entries), encoding="utf-8")


def sanitize_existing_case_dir(case_dir: Path) -> None:
    if not case_dir.exists():
        return
    for name in ["analysis_run", "manual_repro", "project_source", "README.md", "case.json"]:
        path = case_dir / name
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)


def archive_run(run_root: Path, dest_root: Path) -> None:
    summary = load_json(run_root / "summary.json")
    index_path = dest_root / "index.json"
    existing_index = load_json(index_path) if index_path.exists() else []
    existing_by_rel = {entry.get("rel"): entry for entry in existing_index}

    new_entries: list[dict[str, Any]] = []
    for item in summary:
        category, label, note = detect_category(item)
        note = refine_note(item, note)
        project_name = project_name_from_rel(item["rel"])
        case_dir = dest_root / category / item["cve_dir"] / project_name
        old_entry = existing_by_rel.get(item["rel"])
        if old_entry:
            old_case_dir = Path(old_entry.get("analysis_run", "")).parent
            if old_case_dir != case_dir and old_case_dir.exists():
                shutil.rmtree(old_case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)
        sanitize_existing_case_dir(case_dir)

        analysis_dest = case_dir / "analysis_run"
        run_dir = Path(item["run_dir"])
        if analysis_dest.exists():
            shutil.rmtree(analysis_dest)
        shutil.move(str(run_dir), str(analysis_dest))

        project_source = Path(item["project_dir"])
        relative_symlink(project_source, case_dir / "project_source")

        case = {
            "rel": item["rel"],
            "vulnerability": item["cve_dir"],
            "project_name": project_name,
            "status": item["status"],
            "category": category,
            "label": label,
            "reachable": item.get("reachable"),
            "triggerable": item.get("triggerable"),
            "result_kind": item.get("result_kind"),
            "resolved_version": item.get("resolved_version"),
            "symbol": item.get("symbol"),
            "project_source": str(project_source),
            "analysis_run": str(analysis_dest),
            "report": str(analysis_dest / "analysis_report.json"),
            "log": str(analysis_dest / "run.log"),
            "manual_dir": None,
            "manual_input": None,
            "note": note,
        }
        write_json(case_dir / "case.json", case)
        (case_dir / "README.md").write_text(build_case_readme(case), encoding="utf-8")
        new_entries.append(case)

    new_rels = {entry["rel"] for entry in new_entries}
    merged_index = [entry for entry in existing_index if entry.get("rel") not in new_rels]
    merged_index.extend(new_entries)
    merged_index.sort(key=lambda x: (x["category"], x["vulnerability"], x["project_name"]))
    write_json(index_path, merged_index)
    (dest_root / "README.md").write_text(build_root_readme(merged_index), encoding="utf-8")

    run_name = run_name_from_root(run_root)
    run_archive = dest_root / "_runs" / run_name
    if run_archive.exists():
        shutil.rmtree(run_archive)
    raw_dir = run_archive / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    for name in TOP_LEVEL_FILES:
        src = run_root / name
        if src.exists():
            shutil.move(str(src), str(raw_dir / name))

    run_entries = [entry for entry in merged_index if entry["rel"] in new_rels]
    run_entries.sort(key=lambda x: (x["category"], x["vulnerability"], x["project_name"]))
    confirmed = [entry for entry in run_entries if entry["status"] == "triggerable_confirmed"]
    failed = [entry for entry in run_entries if entry["status"] == "analysis_failed"]
    timed_out = [entry for entry in run_entries if entry["status"] == "analysis_timeout"]

    write_json(run_archive / "summary.json", run_entries)
    write_json(run_archive / "summary_projects.json", run_entries)
    write_json(run_archive / "confirmed_projects.json", confirmed)
    write_json(run_archive / "failed_projects.json", failed)
    write_json(run_archive / "timed_out_projects.json", timed_out)
    write_json(run_archive / "status_counts.json", dict(Counter(entry["status"] for entry in run_entries)))
    write_json(
        run_archive / "manifest.json",
        [
            {
                "rel": entry["rel"],
                "category": entry["category"],
                "project_source": entry["project_source"],
                "analysis_run": entry["analysis_run"],
                "report": entry["report"],
                "log": entry["log"],
                "status": entry["status"],
            }
            for entry in run_entries
        ],
    )
    (run_archive / "README.md").write_text(build_run_readme(run_name, run_entries), encoding="utf-8")

    if run_root.exists() and not any(run_root.iterdir()):
        run_root.rmdir()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--run-root", help="Source run directory, e.g. output/vulnerability_runs/new_projects_sweep")
    group.add_argument("--refresh-run-name", help="Refresh notes/documents for an already archived run under _runs/<name>")
    parser.add_argument("--dest-root", default=str(ROOT_DEFAULT), help="Destination VUL by-analysis-status root")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dest_root = Path(args.dest_root).resolve()
    if args.run_root:
        run_root = Path(args.run_root).resolve()
        archive_run(run_root, dest_root)
    else:
        refresh_archived_run(dest_root, args.refresh_run_name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
