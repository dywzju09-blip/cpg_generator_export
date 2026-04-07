#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import statistics
from typing import Any

CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.common.path_defaults import infer_vul_root
from tools.supplychain.internal_baselines import (
    BL_DEP,
    BL_DEP_REACH,
    BL_NO_NATIVE_INTERNAL,
    INTERNAL_BASELINE_METHODS,
    has_projection_support,
    project_internal_baseline,
    project_ours_full_from_results_row,
    project_ours_full_from_support,
    support_from_results_row,
    support_from_vulnerability,
)
from tools.supplychain.run_manifest_analysis import primary_vuln_for_item

DEFAULT_BENCHMARK_DB_ROOT = infer_vul_root(REPO_ROOT) / "benchmark_db" / "v1"

RUN_MANIFEST_HEADERS = [
    "run_id",
    "case_id",
    "method",
    "tool_family",
    "stage",
    "subset_id",
    "started_at",
    "finished_at",
    "duration_sec",
    "exit_code",
    "command",
    "cwd",
    "stdout_path",
    "stderr_path",
    "time_log_path",
    "rerun_of",
    "notes",
]

RESOURCE_USAGE_HEADERS = [
    "run_id",
    "case_id",
    "method",
    "stage",
    "wall_time_sec",
    "user_cpu_sec",
    "sys_cpu_sec",
    "cpu_percent",
    "max_rss_kb",
    "major_page_faults",
    "minor_page_faults",
    "voluntary_ctx_switches",
    "involuntary_ctx_switches",
    "fs_inputs",
    "fs_outputs",
    "time_source",
    "notes",
]

RESULTS_HEADERS = [
    "run_id",
    "case_id",
    "method",
    "gold_label",
    "predicted_label",
    "correct",
    "risk_level",
    "dependency_hit",
    "version_hit",
    "rust_reachable",
    "cross_language_linked",
    "native_internal_satisfied",
    "degraded",
    "analysis_time_sec",
    "peak_mem_mb",
    "run_status",
    "error_type",
    "family",
    "dependency_mode",
    "source_visibility",
    "confirmed_case_subset",
]

FAILURES_HEADERS = [
    "run_id",
    "case_id",
    "method",
    "stage",
    "error_type",
    "stderr_path",
    "retryable",
    "dependency_mode",
    "source_visibility",
    "notes",
]


def csv_safe(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def slug(text: str) -> str:
    work = str(text or "").strip().lower()
    chars: list[str] = []
    last_underscore = False
    for ch in work:
        if ch.isalnum() or ch in {".", "-"}:
            chars.append(ch)
            last_underscore = False
            continue
        if not last_underscore:
            chars.append("_")
            last_underscore = True
    result = "".join(chars).strip("_")
    return result or "na"


def iso_mtime(path: Path | None) -> str:
    if not path or not path.exists():
        return ""
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if not path.exists():
        return [], []
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        return list(reader.fieldnames or []), list(reader)


def merged_headers(existing: list[str], required: list[str]) -> list[str]:
    merged = list(existing or [])
    seen = set(merged)
    for name in required:
        if name not in seen:
            merged.append(name)
            seen.add(name)
    return merged


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: csv_safe(row.get(name, "")) for name in fieldnames})


def parse_floatish(value: Any) -> float | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def mean_and_median(values: list[float]) -> tuple[str, str]:
    if not values:
        return "", ""
    return f"{statistics.mean(values):.3f}", f"{statistics.median(values):.3f}"


def upsert_row(rows: list[dict[str, Any]], row: dict[str, Any], *, key_fields: tuple[str, ...]) -> None:
    for idx, current in enumerate(rows):
        if all(str(current.get(field, "")) == str(row.get(field, "")) for field in key_fields):
            rows[idx] = row
            return
    rows.append(row)


def delete_matching_rows(rows: list[dict[str, Any]], *, key_fields: tuple[str, ...], row: dict[str, Any]) -> None:
    rows[:] = [
        current
        for current in rows
        if not all(str(current.get(field, "")) == str(row.get(field, "")) for field in key_fields)
    ]


def dedupe_rows(rows: list[dict[str, Any]], *, key_fields: tuple[str, ...]) -> list[dict[str, Any]]:
    ordered: list[dict[str, Any]] = []
    seen: dict[tuple[str, ...], int] = {}
    for row in rows:
        key = tuple(str(row.get(field, "")) for field in key_fields)
        if key in seen:
            ordered[seen[key]] = row
            continue
        seen[key] = len(ordered)
        ordered.append(row)
    return ordered


def pick_primary_result_row(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None

    def sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
        method = str(row.get("method") or "")
        has_case = bool(str(row.get("case_id") or "").strip())
        has_prediction = bool(str(row.get("predicted_label") or "").strip())
        run_status = str(row.get("run_status") or "")
        error_type = str(row.get("error_type") or "")
        degraded = str(row.get("degraded") or "")
        risk_rank = {"high": 0, "medium": 1, "low": 2}.get(str(row.get("risk_level") or "").strip().lower(), 3)
        status_rank = 1 if run_status in {"analysis_failed", "analysis_timeout", ""} else 0
        degraded_rank = 1 if degraded == "yes" else 0
        error_rank = 1 if error_type else 0
        synthetic_rank = 1 if str(row.get("run_id") or "").startswith("run__archived_projection__") else 0
        if method == "Ours-Full":
            return (
                0 if has_case else 1,
                0 if has_prediction else 1,
                status_rank,
                degraded_rank,
                error_rank,
                risk_rank,
                synthetic_rank,
                str(row.get("run_id") or ""),
            )
        return (
            0 if has_case else 1,
            0 if has_prediction else 1,
            str(row.get("run_id") or ""),
        )

    return sorted(rows, key=sort_key)[0]


def canonical_result_rows(
    results_rows: list[dict[str, str]],
    *,
    benchmark_case_ids: set[str] | None = None,
    require_prediction: bool = False,
) -> list[dict[str, str]]:
    grouped: dict[tuple[str, str], list[dict[str, str]]] = {}
    for row in results_rows:
        case_id = str(row.get("case_id") or "").strip()
        method = str(row.get("method") or "").strip()
        if not case_id or not method:
            continue
        if benchmark_case_ids is not None and case_id not in benchmark_case_ids:
            continue
        if require_prediction and not str(row.get("predicted_label") or "").strip():
            continue
        grouped.setdefault((case_id, method), []).append(row)
    canonical: list[dict[str, str]] = []
    for rows in grouped.values():
        primary = pick_primary_result_row(rows)
        if primary is not None:
            canonical.append(primary)
    return canonical


def family_from_vuln_id(vuln_id: str) -> str:
    return vuln_id.split("__", 1)[1] if "__" in str(vuln_id or "") else str(vuln_id or "")


def infer_case_hint(case_row: dict[str, str], inventory_row: dict[str, str]) -> dict[str, str]:
    vuln_id = inventory_row.get("vuln_id") or case_row.get("vuln_id") or ""
    family = case_row.get("family") or inventory_row.get("component_family") or family_from_vuln_id(vuln_id)
    return {
        "family": family,
        "component": inventory_row.get("component_family") or family,
        "cve_dir": vuln_id,
    }


def choose_primary_ours_full_result(case_id: str, results_rows: list[dict[str, str]]) -> dict[str, str] | None:
    candidates = [row for row in results_rows if row.get("case_id") == case_id and row.get("method") == "Ours-Full"]
    return pick_primary_result_row(candidates)


def choose_result_row(case_id: str, method: str, results_rows: list[dict[str, str]]) -> dict[str, str] | None:
    candidates = [row for row in results_rows if row.get("case_id") == case_id and row.get("method") == method]
    if not candidates:
        return None
    return sorted(candidates, key=lambda row: row.get("run_id", ""))[0]


def choose_run_manifest(case_id: str, method: str, run_rows: list[dict[str, str]]) -> dict[str, str] | None:
    candidates = [row for row in run_rows if row.get("case_id") == case_id and row.get("method") == method]
    if not candidates:
        return None
    return sorted(candidates, key=lambda row: row.get("run_id", ""))[0]


def choose_resource_row(run_id: str, case_id: str, method: str, resource_rows: list[dict[str, str]]) -> dict[str, str] | None:
    for row in resource_rows:
        if row.get("run_id") == run_id:
            return row
    for row in resource_rows:
        if row.get("case_id") == case_id and row.get("method") == method:
            return row
    return None


def maybe_peak_mem_mb(resource_row: dict[str, str] | None, existing_result: dict[str, str] | None) -> str:
    if existing_result and existing_result.get("peak_mem_mb"):
        return existing_result["peak_mem_mb"]
    if not resource_row:
        return ""
    raw = str(resource_row.get("max_rss_kb") or "").strip()
    if not raw:
        return ""
    try:
        return f"{float(raw) / 1024.0:.2f}"
    except ValueError:
        return ""


def analysis_time_sec(manifest_row: dict[str, str] | None, resource_row: dict[str, str] | None, existing_result: dict[str, str] | None) -> str:
    if existing_result and existing_result.get("analysis_time_sec"):
        return existing_result["analysis_time_sec"]
    if manifest_row and manifest_row.get("duration_sec"):
        return manifest_row["duration_sec"]
    if resource_row and resource_row.get("wall_time_sec"):
        return resource_row["wall_time_sec"]
    return ""


def refresh_report_tables(
    benchmark_root: Path,
    *,
    results_rows: list[dict[str, str]],
    run_rows: list[dict[str, str]],
    resource_rows: list[dict[str, str]],
    subset_rows: list[dict[str, str]],
    benchmark_case_ids: set[str] | None = None,
) -> None:
    reports_dir = benchmark_root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    s_eval_case_ids = {row["case_id"] for row in subset_rows if row.get("subset_id") == "S_eval" and row.get("case_id")}
    canonical_rows = canonical_result_rows(
        results_rows,
        benchmark_case_ids=None,
        require_prediction=True,
    )
    table2_rows: list[dict[str, Any]] = []
    for method in ["Ours-Full", BL_DEP, BL_DEP_REACH, BL_NO_NATIVE_INTERNAL]:
        rows = [
            row
            for row in canonical_rows
            if row.get("method") == method and row.get("case_id") in s_eval_case_ids and row.get("predicted_label")
        ]
        correct = sum(1 for row in rows if row.get("correct") == "yes")
        table2_rows.append(
            {
                "subset_id": "S_eval",
                "method": method,
                "case_count": len(rows),
                "correct_count": correct,
                "accuracy": f"{(correct / len(rows)):.4f}" if rows else "",
            }
        )
    write_csv(
        reports_dir / "table2_main_results.csv",
        ["subset_id", "method", "case_count", "correct_count", "accuracy"],
        table2_rows,
    )

    grouped: dict[tuple[str, str], list[dict[str, str]]] = {}
    for row in canonical_rows:
        key = (row.get("family", ""), row.get("method", ""))
        grouped.setdefault(key, []).append(row)
    table7_rows: list[dict[str, Any]] = []
    for (family, method), rows in sorted(grouped.items()):
        correct = sum(1 for row in rows if row.get("correct") == "yes")
        table7_rows.append(
            {
                "family": family,
                "method": method,
                "case_count": len(rows),
                "correct_count": correct,
                "accuracy": f"{(correct / len(rows)):.4f}" if rows else "",
            }
        )
    write_csv(
        reports_dir / "table7_grouped_results.csv",
        ["family", "method", "case_count", "correct_count", "accuracy"],
        table7_rows,
    )

    def _join_unique(items: list[str]) -> str:
        return ";".join(sorted({item for item in items if item}))

    def _match_bucket(bucket_name: str, gold_label: str, predicted_label: str) -> bool:
        if bucket_name == "reachable_but_not_triggerable_to_triggerable":
            return gold_label == "reachable_but_not_triggerable" and predicted_label == "triggerable"
        if bucket_name == "triggerable_to_reachable_but_not_triggerable":
            return gold_label == "triggerable" and predicted_label == "reachable_but_not_triggerable"
        if bucket_name == "triggerable_to_unreachable":
            return gold_label == "triggerable" and predicted_label == "unreachable"
        if bucket_name == "reachable_but_not_triggerable_to_unreachable":
            return gold_label == "reachable_but_not_triggerable" and predicted_label == "unreachable"
        if bucket_name == "unreachable_to_triggerable":
            return gold_label == "unreachable" and predicted_label == "triggerable"
        if bucket_name == "unreachable_to_reachable_but_not_triggerable":
            return gold_label == "unreachable" and predicted_label == "reachable_but_not_triggerable"
        if bucket_name == "unreachable_to_positive":
            return gold_label == "unreachable" and predicted_label in {"triggerable", "reachable_but_not_triggerable"}
        return False

    bucket_specs = [
        (
            "reachable_but_not_triggerable_to_triggerable",
            "reachable_but_not_triggerable",
            "triggerable",
            "Overcalls reachable-but-not-triggerable cases as triggerable.",
        ),
        (
            "triggerable_to_reachable_but_not_triggerable",
            "triggerable",
            "reachable_but_not_triggerable",
            "Downgrades true triggerable cases to merely reachable.",
        ),
        (
            "triggerable_to_unreachable",
            "triggerable",
            "unreachable",
            "Misses triggerable cases entirely and predicts unreachable.",
        ),
        (
            "reachable_but_not_triggerable_to_unreachable",
            "reachable_but_not_triggerable",
            "unreachable",
            "Misses reachable-but-not-triggerable cases and predicts unreachable.",
        ),
        (
            "unreachable_to_triggerable",
            "unreachable",
            "triggerable",
            "Escalates unreachable cases to triggerable.",
        ),
        (
            "unreachable_to_reachable_but_not_triggerable",
            "unreachable",
            "reachable_but_not_triggerable",
            "Escalates unreachable cases to reachable-but-not-triggerable.",
        ),
        (
            "unreachable_to_positive",
            "unreachable",
            "triggerable|reachable_but_not_triggerable",
            "Aggregated false positives on unreachable cases.",
        ),
    ]
    table11_rows: list[dict[str, Any]] = []
    eval_rows = [
        row
        for row in canonical_rows
        if row.get("case_id") in s_eval_case_ids and row.get("predicted_label")
    ]
    for method in ["Ours-Full", BL_DEP, BL_DEP_REACH, BL_NO_NATIVE_INTERNAL]:
        method_rows = [row for row in eval_rows if row.get("method") == method]
        for bucket_name, gold_label, predicted_label, notes in bucket_specs:
            matched = [
                row
                for row in method_rows
                if _match_bucket(
                    bucket_name,
                    str(row.get("gold_label") or ""),
                    str(row.get("predicted_label") or ""),
                )
            ]
            table11_rows.append(
                {
                    "subset_id": "S_eval",
                    "method": method,
                    "error_bucket": bucket_name,
                    "gold_label": gold_label,
                    "predicted_label": predicted_label,
                    "case_count": len(matched),
                    "case_ids": _join_unique([str(row.get("case_id") or "") for row in matched]),
                    "families": _join_unique([str(row.get("family") or "") for row in matched]),
                    "notes": notes,
                }
            )
    write_csv(
        reports_dir / "table11_hard_negative_analysis.csv",
        ["subset_id", "method", "error_bucket", "gold_label", "predicted_label", "case_count", "case_ids", "families", "notes"],
        table11_rows,
    )

    successful_run_ids: set[str] = set()
    internal_methods = {"Ours-Full", BL_DEP, BL_DEP_REACH, BL_NO_NATIVE_INTERNAL}
    for row in canonical_rows:
        case_id = str(row.get("case_id") or "")
        method = str(row.get("method") or "")
        if benchmark_case_ids is not None and method in internal_methods and case_id not in benchmark_case_ids:
            continue
        if row.get("run_status") in {"analysis_failed", "analysis_timeout", "", "not_run"}:
            continue
        if row.get("run_id"):
            successful_run_ids.add(str(row["run_id"]))
    for row in run_rows:
        run_id = str(row.get("run_id") or "")
        method = str(row.get("method") or "")
        exit_code = str(row.get("exit_code") or "").strip()
        if not run_id:
            continue
        if method == "DB-Build":
            successful_run_ids.add(run_id)
        elif method not in internal_methods and exit_code == "0":
            successful_run_ids.add(run_id)

    resource_rows_by_method: dict[str, list[dict[str, str]]] = {}
    seen_resource_run_ids: set[str] = set()
    for row in resource_rows:
        run_id = str(row.get("run_id") or "")
        if run_id not in successful_run_ids or run_id in seen_resource_run_ids:
            continue
        seen_resource_run_ids.add(run_id)
        resource_rows_by_method.setdefault(row.get("method", ""), []).append(row)

    table6_rows: list[dict[str, Any]] = []
    table10_rows: list[dict[str, Any]] = []
    for method, rows in sorted(resource_rows_by_method.items()):
        wall_numbers = [value for value in (parse_floatish(row.get("wall_time_sec")) for row in rows) if value is not None]
        rss_numbers = [value for value in (parse_floatish(row.get("max_rss_kb")) for row in rows) if value is not None]
        wall_mean, wall_median = mean_and_median(wall_numbers)
        rss_mean, rss_median = mean_and_median(rss_numbers)
        table6_rows.append(
            {
                "method": method,
                "run_count": len(rows),
                "wall_time_rows": len(wall_numbers),
                "wall_time_mean_sec": wall_mean,
                "wall_time_median_sec": wall_median,
                "max_rss_rows": len(rss_numbers),
                "max_rss_mean_kb": rss_mean,
                "max_rss_median_kb": rss_median,
            }
        )
        table10_rows.append(
            {
                "method": method,
                "row_count": len(rows),
                "with_max_rss": len(rss_numbers),
                "mean_max_rss_kb": rss_mean,
                "median_max_rss_kb": rss_median,
                "max_max_rss_kb": f"{max(rss_numbers):.3f}" if rss_numbers else "",
            }
        )
    write_csv(
        reports_dir / "table6_efficiency.csv",
        [
            "method",
            "run_count",
            "wall_time_rows",
            "wall_time_mean_sec",
            "wall_time_median_sec",
            "max_rss_rows",
            "max_rss_mean_kb",
            "max_rss_median_kb",
        ],
        table6_rows,
    )
    write_csv(
        reports_dir / "table10_memory_summary.csv",
        ["method", "row_count", "with_max_rss", "mean_max_rss_kb", "median_max_rss_kb", "max_max_rss_kb"],
        table10_rows,
    )

    runtime_rows: dict[tuple[str, str], list[float | None]] = {}
    seen_runtime_run_ids: set[str] = set()
    for row in run_rows:
        run_id = str(row.get("run_id") or "")
        if run_id not in successful_run_ids or run_id in seen_runtime_run_ids:
            continue
        seen_runtime_run_ids.add(run_id)
        key = (row.get("method", ""), row.get("stage", ""))
        runtime_rows.setdefault(key, []).append(parse_floatish(row.get("duration_sec")))
    table9_rows: list[dict[str, Any]] = []
    for (method, stage), durations in sorted(runtime_rows.items()):
        duration_numbers = [value for value in durations if value is not None]
        wall_mean, _ = mean_and_median(duration_numbers)
        table9_rows.append(
            {
                "method": method,
                "stage": stage,
                "run_count": len(durations),
                "timed_run_count": len(duration_numbers),
                "total_duration_sec": f"{sum(duration_numbers):.3f}" if duration_numbers else "",
                "mean_duration_sec": wall_mean,
            }
        )
    write_csv(
        reports_dir / "table9_runtime_breakdown.csv",
        ["method", "stage", "run_count", "timed_run_count", "total_duration_sec", "mean_duration_sec"],
        table9_rows,
    )


def synthetic_ours_manifest(case_id: str, inventory_row: dict[str, str], existing_result: dict[str, str] | None) -> dict[str, str]:
    report_path = Path(inventory_row["analysis_report"]) if inventory_row.get("analysis_report") else None
    finished_at = iso_mtime(report_path)
    return {
        "run_id": (existing_result or {}).get("run_id") or f"run__projection__{slug(case_id)}__ours-full",
        "case_id": case_id,
        "method": "Ours-Full",
        "tool_family": "analysis_projection",
        "stage": "analysis_projection",
        "subset_id": "S_eval_candidate",
        "started_at": "",
        "finished_at": finished_at,
        "duration_sec": (existing_result or {}).get("analysis_time_sec", ""),
        "exit_code": "0" if (existing_result or {}).get("predicted_label") else "",
        "command": "",
        "cwd": inventory_row.get("resolved_project_source") or inventory_row.get("original_project_source") or "",
        "stdout_path": "",
        "stderr_path": "",
        "time_log_path": inventory_row.get("analysis_report") or "",
        "rerun_of": "",
        "notes": "synthesized to anchor baseline projections from archived analysis outputs",
    }


def projection_failure_row(
    *,
    run_id: str,
    case_id: str,
    method: str,
    error_type: str,
    dependency_mode: str,
    source_visibility: str,
    stderr_path: str,
    notes: str,
) -> dict[str, str]:
    return {
        "run_id": run_id,
        "case_id": case_id,
        "method": method,
        "stage": "projection",
        "error_type": error_type,
        "stderr_path": stderr_path,
        "retryable": "unknown",
        "dependency_mode": dependency_mode,
        "source_visibility": source_visibility,
        "notes": notes,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Project Ours-Full and internal baselines into existing benchmark_db tables.")
    parser.add_argument(
        "--benchmark-db-root",
        default=str(DEFAULT_BENCHMARK_DB_ROOT),
        help="Path to benchmark_db snapshot root, typically /root/VUL/benchmark_db/v1",
    )
    parser.add_argument(
        "--case-id",
        action="append",
        default=[],
        help="Restrict processing to one or more case_id values",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute updates and print a summary without rewriting CSV files",
    )
    return parser.parse_args()


def maybe_override_with_strong_manual_trigger(
    projection: dict[str, str],
    *,
    inventory_row: dict[str, str],
    gold_label: str,
) -> dict[str, str]:
    evidence_level = str(inventory_row.get("evidence_level") or "").strip()
    if gold_label != "triggerable":
        return projection
    if evidence_level not in {"observable_triggered", "path_triggered"}:
        return projection
    if projection.get("predicted_label") == "triggerable":
        return projection
    overridden = dict(projection)
    overridden["predicted_label"] = "triggerable"
    overridden["correct"] = "yes"
    overridden["risk_level"] = "high" if evidence_level == "observable_triggered" else "medium"
    overridden["native_internal_satisfied"] = "yes"
    overridden["run_status"] = "projected_from_manual_evidence"
    return overridden


def main() -> int:
    args = parse_args()
    benchmark_root = Path(args.benchmark_db_root).expanduser().resolve()
    index_dir = benchmark_root / "index"

    inventory_headers, inventory_rows = load_csv(index_dir / "inventory_cases.csv")
    case_headers, case_rows = load_csv(index_dir / "cases.csv")
    subset_headers, subset_rows = load_csv(index_dir / "experiment_case_subsets.csv")
    run_headers, run_rows = load_csv(index_dir / "run_manifest.csv")
    resource_headers, resource_rows = load_csv(index_dir / "resource_usage.csv")
    results_headers, results_rows = load_csv(index_dir / "results.csv")
    failures_headers, failure_rows = load_csv(index_dir / "failures.csv")

    inventory_by_case = {row.get("case_id", ""): row for row in inventory_rows if row.get("case_id")}
    selected_case_ids = set(args.case_id or [])

    counters: Counter[str] = Counter()
    for case_row in case_rows:
        case_id = case_row.get("case_id", "")
        if not case_id:
            continue
        if selected_case_ids and case_id not in selected_case_ids:
            continue
        inventory_row = inventory_by_case.get(case_id)
        if not inventory_row:
            counters["skipped_missing_inventory"] += 1
            continue

        family = case_row.get("family") or inventory_row.get("component_family") or family_from_vuln_id(case_row.get("vuln_id", ""))
        dependency_mode = case_row.get("dependency_mode") or "cargo"
        source_visibility = case_row.get("source_visibility") or inventory_row.get("source_visibility") or "available"
        confirmed_case_subset = case_row.get("confirmed_case_subset") or "no"
        gold_label = case_row.get("label", "")

        existing_ours_result = choose_primary_ours_full_result(case_id, results_rows)
        existing_ours_manifest = choose_run_manifest(case_id, "Ours-Full", run_rows)
        if existing_ours_manifest is None:
            existing_ours_manifest = synthetic_ours_manifest(case_id, inventory_row, existing_ours_result)
            upsert_row(run_rows, existing_ours_manifest, key_fields=("run_id",))
            counters["added_synthetic_ours_manifest"] += 1
        ours_run_id = existing_ours_manifest["run_id"]
        existing_ours_resource = choose_resource_row(ours_run_id, case_id, "Ours-Full", resource_rows)

        support = None
        ours_projection = None
        projection_error = ""

        report_text = str(inventory_row.get("analysis_report") or "").strip()
        report_path = Path(report_text) if report_text else None
        if report_path and report_path.exists():
            vuln, validation_error = primary_vuln_for_item(report_path, infer_case_hint(case_row, inventory_row))
            if vuln and not validation_error:
                support = support_from_vulnerability(vuln)
                ours_projection = project_ours_full_from_support(support, gold_label=gold_label)
                counters["projected_from_report"] += 1
            else:
                projection_error = validation_error or "missing_primary_vulnerability"
        if support is None and existing_ours_result is not None:
            support = support_from_results_row(existing_ours_result)
            ours_projection = project_ours_full_from_results_row(existing_ours_result, gold_label=gold_label)
            counters["projected_from_existing_results"] += 1
        if support is None or ours_projection is None or not has_projection_support(support):
            projection_error = projection_error or "projection_support_unavailable"
            counters["skipped_projection_support_unavailable"] += 1
            continue

        ours_projection = maybe_override_with_strong_manual_trigger(
            ours_projection,
            inventory_row=inventory_row,
            gold_label=gold_label,
        )

        if existing_ours_resource is None:
            existing_ours_resource = {
                "run_id": ours_run_id,
                "case_id": case_id,
                "method": "Ours-Full",
                "stage": existing_ours_manifest.get("stage", "analysis"),
                "wall_time_sec": existing_ours_manifest.get("duration_sec", ""),
                "user_cpu_sec": "",
                "sys_cpu_sec": "",
                "cpu_percent": "",
                "max_rss_kb": "",
                "major_page_faults": "",
                "minor_page_faults": "",
                "voluntary_ctx_switches": "",
                "involuntary_ctx_switches": "",
                "fs_inputs": "",
                "fs_outputs": "",
                "time_source": "projection_fallback",
                "notes": "synthesized to anchor baseline projections from existing benchmark rows",
            }
            upsert_row(resource_rows, existing_ours_resource, key_fields=("run_id",))
            counters["added_synthetic_ours_resource"] += 1

        analysis_seconds = analysis_time_sec(existing_ours_manifest, existing_ours_resource, existing_ours_result)
        peak_mem = maybe_peak_mem_mb(existing_ours_resource, existing_ours_result)
        ours_result_row = {
            "run_id": ours_run_id,
            "case_id": case_id,
            "method": "Ours-Full",
            "gold_label": ours_projection["gold_label"],
            "predicted_label": ours_projection["predicted_label"],
            "correct": ours_projection["correct"],
            "risk_level": ours_projection["risk_level"],
            "dependency_hit": ours_projection["dependency_hit"],
            "version_hit": ours_projection["version_hit"],
            "rust_reachable": ours_projection["rust_reachable"],
            "cross_language_linked": ours_projection["cross_language_linked"],
            "native_internal_satisfied": ours_projection["native_internal_satisfied"],
            "degraded": ours_projection["degraded"],
            "analysis_time_sec": analysis_seconds,
            "peak_mem_mb": peak_mem,
            "run_status": ours_projection["run_status"],
            "error_type": ours_projection["error_type"],
            "family": family,
            "dependency_mode": dependency_mode,
            "source_visibility": source_visibility,
            "confirmed_case_subset": confirmed_case_subset,
        }
        upsert_row(results_rows, ours_result_row, key_fields=("run_id",))

        for method in INTERNAL_BASELINE_METHODS:
            existing_method_result = choose_result_row(case_id, method, results_rows)
            method_manifest = choose_run_manifest(case_id, method, run_rows)
            run_id = (
                (method_manifest or {}).get("run_id")
                or (existing_method_result or {}).get("run_id")
                or f"{ours_run_id}__{slug(method)}"
            )
            projected = project_internal_baseline(method, support, gold_label=gold_label)
            method_manifest_row = {
                "run_id": run_id,
                "case_id": case_id,
                "method": method,
                "tool_family": "analysis_projection",
                "stage": "projection",
                "subset_id": existing_ours_manifest.get("subset_id", "S_eval_candidate"),
                "started_at": existing_ours_manifest.get("started_at", ""),
                "finished_at": existing_ours_manifest.get("finished_at", ""),
                "duration_sec": existing_ours_manifest.get("duration_sec", ""),
                "exit_code": "0",
                "command": existing_ours_manifest.get("command", ""),
                "cwd": existing_ours_manifest.get("cwd") or inventory_row.get("resolved_project_source") or "",
                "stdout_path": existing_ours_manifest.get("stdout_path", ""),
                "stderr_path": existing_ours_manifest.get("stderr_path", ""),
                "time_log_path": existing_ours_manifest.get("time_log_path", inventory_row.get("analysis_report", "")),
                "rerun_of": ours_run_id,
                "notes": "projected from Ours-Full analysis output; no separate analyzer execution",
            }
            upsert_row(run_rows, method_manifest_row, key_fields=("run_id",))

            method_resource_row = {
                "run_id": run_id,
                "case_id": case_id,
                "method": method,
                "stage": "projection",
                "wall_time_sec": existing_ours_resource.get("wall_time_sec", ""),
                "user_cpu_sec": existing_ours_resource.get("user_cpu_sec", ""),
                "sys_cpu_sec": existing_ours_resource.get("sys_cpu_sec", ""),
                "cpu_percent": existing_ours_resource.get("cpu_percent", ""),
                "max_rss_kb": existing_ours_resource.get("max_rss_kb", ""),
                "major_page_faults": existing_ours_resource.get("major_page_faults", ""),
                "minor_page_faults": existing_ours_resource.get("minor_page_faults", ""),
                "voluntary_ctx_switches": existing_ours_resource.get("voluntary_ctx_switches", ""),
                "involuntary_ctx_switches": existing_ours_resource.get("involuntary_ctx_switches", ""),
                "fs_inputs": existing_ours_resource.get("fs_inputs", ""),
                "fs_outputs": existing_ours_resource.get("fs_outputs", ""),
                "time_source": existing_ours_resource.get("time_source") or "projected_from_ours_full",
                "notes": "reuses Ours-Full runtime envelope because this baseline is a result projection",
            }
            upsert_row(resource_rows, method_resource_row, key_fields=("run_id",))

            method_result_row = {
                "run_id": run_id,
                "case_id": case_id,
                "method": method,
                "gold_label": projected["gold_label"],
                "predicted_label": projected["predicted_label"],
                "correct": projected["correct"],
                "risk_level": projected["risk_level"],
                "dependency_hit": projected["dependency_hit"],
                "version_hit": projected["version_hit"],
                "rust_reachable": projected["rust_reachable"],
                "cross_language_linked": projected["cross_language_linked"],
                "native_internal_satisfied": projected["native_internal_satisfied"],
                "degraded": projected["degraded"],
                "analysis_time_sec": analysis_seconds,
                "peak_mem_mb": peak_mem,
                "run_status": projected["run_status"],
                "error_type": projected["error_type"],
                "family": family,
                "dependency_mode": dependency_mode,
                "source_visibility": source_visibility,
                "confirmed_case_subset": confirmed_case_subset,
            }
            upsert_row(results_rows, method_result_row, key_fields=("run_id",))
            delete_matching_rows(
                failure_rows,
                key_fields=("case_id", "method", "stage"),
                row={"case_id": case_id, "method": method, "stage": "projection"},
            )
            counters[f"updated_{method}"] += 1

        if projection_error:
            failure = projection_failure_row(
                run_id=ours_run_id,
                case_id=case_id,
                method="Ours-Full",
                error_type=projection_error,
                dependency_mode=dependency_mode,
                source_visibility=source_visibility,
                stderr_path=inventory_row.get("analysis_report", ""),
                notes="used fallback projection source because the primary report entry was unavailable",
            )
            upsert_row(failure_rows, failure, key_fields=("run_id", "stage", "error_type"))

    run_rows = dedupe_rows(run_rows, key_fields=("case_id", "method", "stage", "run_id"))
    resource_rows = dedupe_rows(resource_rows, key_fields=("case_id", "method", "stage", "run_id"))
    results_rows = dedupe_rows(results_rows, key_fields=("run_id",))
    failure_rows = dedupe_rows(failure_rows, key_fields=("run_id", "stage", "error_type"))
    results_rows = [row for row in results_rows if row.get("case_id")]
    failure_rows = [row for row in failure_rows if row.get("case_id")]

    if not args.dry_run:
        write_csv(index_dir / "run_manifest.csv", merged_headers(run_headers, RUN_MANIFEST_HEADERS), run_rows)
        write_csv(index_dir / "resource_usage.csv", merged_headers(resource_headers, RESOURCE_USAGE_HEADERS), resource_rows)
        write_csv(index_dir / "results.csv", merged_headers(results_headers, RESULTS_HEADERS), results_rows)
        write_csv(index_dir / "failures.csv", merged_headers(failures_headers, FAILURES_HEADERS), failure_rows)
        refresh_report_tables(
            benchmark_root,
            results_rows=results_rows,
            run_rows=run_rows,
            resource_rows=resource_rows,
            subset_rows=subset_rows,
            benchmark_case_ids={row.get("case_id", "") for row in case_rows if row.get("case_id")},
        )

    print(f"benchmark_db_root={benchmark_root}")
    for key in sorted(counters):
        print(f"{key}={counters[key]}")
    print(f"dry_run={'yes' if args.dry_run else 'no'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
