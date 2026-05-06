#!/usr/bin/env python3
"""
Export a unified efficiency table for RQ3.

The output table contains exactly four methods:
- Ours-Full (Without Reuse)
- Ours-Full (With Reuse)
- cargo-audit
- OSV-Scanner

All methods must share the same case set and timeout policy.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_csv(path: Path, headers: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in headers})


def parse_float(value: Any) -> float | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def parse_int(value: Any) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(float(text))
    except ValueError:
        return None


def kb_to_gb(kb: int) -> float:
    # /proc and /usr/bin/time report KiB; convert to GiB but label as GB for the paper table.
    return float(kb) / (1024.0 * 1024.0)


@dataclass
class CaseMetric:
    case_id: str
    wall_time_sec: float
    peak_rss_kb: int
    avg_rss_kb: int
    timed_out: bool
    component_cpg_request_count: int = 0
    component_cpg_reused_from_json_count: int = 0


def load_ours_case_metrics(run_root: Path) -> dict[str, CaseMetric]:
    summary_path = run_root / "summary.json"
    if not summary_path.exists():
        raise FileNotFoundError(f"missing summary.json: {summary_path}")
    entries = load_json(summary_path)
    metrics: dict[str, CaseMetric] = {}
    for entry in entries or []:
        case_id = str((entry or {}).get("case_id") or "").strip()
        report_path = Path(str((entry or {}).get("report") or "")).expanduser()
        if not case_id or not report_path.exists():
            continue
        report = load_json(report_path)
        wall_time_sec = parse_float(report.get("wall_time_sec")) or 0.0
        peak_rss_kb = parse_int(report.get("peak_rss_kb")) or 0
        avg_rss_kb = parse_int(report.get("avg_rss_kb")) or 0
        timed_out = bool(report.get("timed_out"))
        metrics[case_id] = CaseMetric(
            case_id=case_id,
            wall_time_sec=float(wall_time_sec),
            peak_rss_kb=int(peak_rss_kb),
            avg_rss_kb=int(avg_rss_kb),
            timed_out=timed_out,
            component_cpg_request_count=int(parse_int(report.get("component_cpg_request_count")) or 0),
            component_cpg_reused_from_json_count=int(parse_int(report.get("component_cpg_reused_from_json_count")) or 0),
        )
    return metrics


def load_external_case_metrics(run_root: Path) -> dict[str, CaseMetric]:
    summary_path = run_root / "summary.json"
    if not summary_path.exists():
        raise FileNotFoundError(f"missing summary.json: {summary_path}")
    entries = load_json(summary_path)
    metrics: dict[str, CaseMetric] = {}
    for entry in entries or []:
        case_id = str((entry or {}).get("case_id") or "").strip()
        if not case_id:
            continue
        wall_time_sec = parse_float((entry or {}).get("wall_time_sec")) or 0.0
        peak_rss_kb = parse_int((entry or {}).get("peak_rss_kb")) or 0
        avg_rss_kb = parse_int((entry or {}).get("avg_rss_kb")) or 0
        timed_out = bool((entry or {}).get("timed_out"))
        metrics[case_id] = CaseMetric(
            case_id=case_id,
            wall_time_sec=float(wall_time_sec),
            peak_rss_kb=int(peak_rss_kb),
            avg_rss_kb=int(avg_rss_kb),
            timed_out=timed_out,
        )
    return metrics


def summarize_method(
    *,
    method_label: str,
    case_ids: list[str],
    case_metrics: dict[str, CaseMetric],
    reuse_applicable: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    missing = [case_id for case_id in case_ids if case_id not in case_metrics]
    if missing:
        raise RuntimeError(f"{method_label} missing {len(missing)} cases, e.g. {missing[:3]}")

    rows = [case_metrics[case_id] for case_id in case_ids]
    wall_times = [row.wall_time_sec for row in rows]
    total_time = sum(wall_times)
    avg_time = statistics.mean(wall_times) if wall_times else 0.0
    median_time = statistics.median(wall_times) if wall_times else 0.0
    timeouts = sum(1 for row in rows if row.timed_out)
    timeout_rate = (timeouts / len(rows)) if rows else 0.0

    peak_mem_gb = kb_to_gb(max(row.peak_rss_kb for row in rows)) if rows else 0.0
    avg_mem_gb = kb_to_gb(int(round(statistics.mean([row.avg_rss_kb for row in rows])))) if rows else 0.0

    reuse_rate: str = "-"
    reuse_meta: dict[str, Any] = {}
    if reuse_applicable:
        requests = sum(row.component_cpg_request_count for row in rows)
        reused = sum(row.component_cpg_reused_from_json_count for row in rows)
        reuse_rate = f"{(reused / requests):.3f}" if requests else "0.000"
        reuse_meta = {"component_cpg_request_count": requests, "component_cpg_reused_from_json_count": reused}

    summary = {
        "Method": method_label,
        "Cases": len(rows),
        "Total Detection Time (s)": f"{total_time:.2f}",
        "Avg. Detection Time (s)": f"{avg_time:.2f}",
        "Median Detection Time (s)": f"{median_time:.2f}",
        "Timeout Rate": f"{(timeout_rate * 100.0):.1f}%",
        "Reuse Rate": reuse_rate,
        "Peak Memory Usage (GB)": f"{peak_mem_gb:.3f}",
        "Average Memory Usage (GB)": f"{avg_mem_gb:.3f}",
    }
    details = {
        "timeouts": timeouts,
        "timeout_rate": timeout_rate,
        "total_time_sec": total_time,
        "avg_time_sec": avg_time,
        "median_time_sec": median_time,
        "peak_mem_gb": peak_mem_gb,
        "avg_mem_gb": avg_mem_gb,
        **reuse_meta,
    }
    return summary, details


def render_markdown(headers: list[str], rows: list[dict[str, Any]]) -> str:
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + "|".join(["---"] * len(headers)) + "|")
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(h, "")) for h in headers) + " |")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="Case manifest with case_id entries")
    parser.add_argument("--ours-without-run-root", required=True, help="run_manifest_analysis output dir for without-reuse")
    parser.add_argument("--ours-with-run-root", required=True, help="run_manifest_analysis output dir for with-reuse")
    parser.add_argument("--cargo-audit-run-root", required=True, help="run_external_baselines output dir for cargo-audit")
    parser.add_argument("--osv-scanner-run-root", required=True, help="run_external_baselines output dir for osv-scanner")
    parser.add_argument("--out-csv", required=True, help="Output CSV path")
    parser.add_argument("--out-md", required=True, help="Output Markdown path")
    parser.add_argument("--out-conclusion", required=True, help="Output conclusion text path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = load_json(Path(args.manifest).resolve())
    items = manifest.get("items", manifest) if isinstance(manifest, dict) else manifest
    if not isinstance(items, list):
        raise ValueError("manifest must be a list or an object with an items array")
    case_ids = [str((item or {}).get("case_id") or "").strip() for item in items if isinstance(item, dict)]
    case_ids = [case_id for case_id in case_ids if case_id]
    if not case_ids:
        raise ValueError("manifest items must include case_id")
    if len(set(case_ids)) != len(case_ids):
        raise ValueError("manifest contains duplicate case_id values")

    ours_without = load_ours_case_metrics(Path(args.ours_without_run_root).resolve())
    ours_with = load_ours_case_metrics(Path(args.ours_with_run_root).resolve())
    cargo_audit = load_external_case_metrics(Path(args.cargo_audit_run_root).resolve())
    osv_scanner = load_external_case_metrics(Path(args.osv_scanner_run_root).resolve())

    headers = [
        "Method",
        "Cases",
        "Total Detection Time (s)",
        "Avg. Detection Time (s)",
        "Median Detection Time (s)",
        "Timeout Rate",
        "Reuse Rate",
        "Peak Memory Usage (GB)",
        "Average Memory Usage (GB)",
    ]

    rows: list[dict[str, Any]] = []
    details: dict[str, dict[str, Any]] = {}

    row, meta = summarize_method(
        method_label="Ours-Full (Without Reuse)",
        case_ids=case_ids,
        case_metrics=ours_without,
        reuse_applicable=True,
    )
    rows.append(row)
    details[row["Method"]] = meta

    row, meta = summarize_method(
        method_label="Ours-Full (With Reuse)",
        case_ids=case_ids,
        case_metrics=ours_with,
        reuse_applicable=True,
    )
    rows.append(row)
    details[row["Method"]] = meta

    row, meta = summarize_method(
        method_label="cargo-audit",
        case_ids=case_ids,
        case_metrics=cargo_audit,
        reuse_applicable=False,
    )
    rows.append(row)
    details[row["Method"]] = meta

    row, meta = summarize_method(
        method_label="OSV-Scanner",
        case_ids=case_ids,
        case_metrics=osv_scanner,
        reuse_applicable=False,
    )
    rows.append(row)
    details[row["Method"]] = meta

    out_csv = Path(args.out_csv).resolve()
    out_md = Path(args.out_md).resolve()
    write_csv(out_csv, headers, rows)
    write_text(out_md, render_markdown(headers, rows))

    without_total = float(details["Ours-Full (Without Reuse)"]["total_time_sec"])
    with_total = float(details["Ours-Full (With Reuse)"]["total_time_sec"])
    speedup = (without_total / with_total) if with_total > 0 else 0.0
    reduction_pct = ((without_total - with_total) / without_total * 100.0) if without_total > 0 else 0.0
    reuse_rate = rows[1]["Reuse Rate"]

    cargo_total = float(details["cargo-audit"]["total_time_sec"])
    osv_total = float(details["OSV-Scanner"]["total_time_sec"])
    ours_peak_with = float(details["Ours-Full (With Reuse)"]["peak_mem_gb"])
    ours_peak_without = float(details["Ours-Full (Without Reuse)"]["peak_mem_gb"])
    cargo_peak = float(details["cargo-audit"]["peak_mem_gb"])
    osv_peak = float(details["OSV-Scanner"]["peak_mem_gb"])
    ours_avg_mem_with = float(details["Ours-Full (With Reuse)"]["avg_mem_gb"])
    ours_avg_mem_without = float(details["Ours-Full (Without Reuse)"]["avg_mem_gb"])
    cargo_avg_mem = float(details["cargo-audit"]["avg_mem_gb"])
    osv_avg_mem = float(details["OSV-Scanner"]["avg_mem_gb"])

    ours_avg_time_with = float(details["Ours-Full (With Reuse)"]["avg_time_sec"])
    cargo_avg_time = float(details["cargo-audit"]["avg_time_sec"])
    osv_avg_time = float(details["OSV-Scanner"]["avg_time_sec"])

    def _ratio(a: float, b: float) -> float:
        return (a / b) if b > 0 else 0.0

    time_vs_cargo = _ratio(ours_avg_time_with, cargo_avg_time)
    time_vs_osv = _ratio(ours_avg_time_with, osv_avg_time)
    peak_vs_cargo = _ratio(ours_peak_with, cargo_peak)
    peak_vs_osv = _ratio(ours_peak_with, osv_peak)

    peak_delta_pct = ((ours_peak_with - ours_peak_without) / ours_peak_without * 100.0) if ours_peak_without > 0 else 0.0
    avg_delta_pct = ((ours_avg_mem_with - ours_avg_mem_without) / ours_avg_mem_without * 100.0) if ours_avg_mem_without > 0 else 0.0
    mem_note = "内存变化不明显" if abs(peak_delta_pct) < 5.0 and abs(avg_delta_pct) < 5.0 else "内存有可见变化"

    conclusion_lines = [
        f"本次统一效率表使用同一批 {len(case_ids)} 个 benchmark case，四个方法采用同一 per-case timeout 策略。",
        f"Ours-Full 开启复用后，总检测时间从 {without_total:.2f}s 降到 {with_total:.2f}s（下降 {reduction_pct:.1f}%，加速 {speedup:.2f}x）。",
        f"Ours-Full (With Reuse) 的 Reuse Rate 为 {reuse_rate}。",
        f"与外部工具相比（按 Avg. Detection Time 口径），Ours-Full(with) 约为 cargo-audit 的 {time_vs_cargo:.1f}x、OSV-Scanner 的 {time_vs_osv:.1f}x。"
        if cargo_avg_time > 0 and osv_avg_time > 0
        else f"外部工具平均时间过小或缺失，无法计算倍数对比（cargo-audit={cargo_avg_time:.3f}s，OSV={osv_avg_time:.3f}s）。",
        f"内存量级（Peak/Avg, GB）：Ours-Full(with)={ours_peak_with:.3f}/{ours_avg_mem_with:.3f}，cargo-audit={cargo_peak:.3f}/{cargo_avg_mem:.3f}，OSV-Scanner={osv_peak:.3f}/{osv_avg_mem:.3f}；相对倍数约为 {peak_vs_cargo:.1f}x（vs cargo-audit peak）、{peak_vs_osv:.1f}x（vs OSV peak）。",
        f"Ours-Full 的 with/without reuse {mem_note}（Peak {ours_peak_without:.3f}->{ours_peak_with:.3f} GB，Avg {ours_avg_mem_without:.3f}->{ours_avg_mem_with:.3f} GB）。",
    ]
    write_text(Path(args.out_conclusion).resolve(), "\n".join(conclusion_lines) + "\n")

    print(f"[+] Efficiency table written to {out_csv}")
    print(f"[+] Efficiency table written to {out_md}")
    print(f"[+] Conclusion written to {Path(args.out_conclusion).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
