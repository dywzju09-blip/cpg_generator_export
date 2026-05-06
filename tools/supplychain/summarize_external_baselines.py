#!/usr/bin/env python3
"""Summarize cargo-audit and OSV-Scanner outputs for Top15 baseline comparison."""

from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
from pathlib import Path
from typing import Any


CVE_RE = re.compile(r"CVE-\d{4}-\d+")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]], headers: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow({header: row.get(header, "") for header in headers})


def kb_to_gb(kb: int | float) -> float:
    return float(kb or 0) / (1024.0 * 1024.0)


def target_cves(row: dict[str, Any]) -> list[str]:
    cves: set[str] = set()
    rule_selection = row.get("rule_selection")
    if isinstance(rule_selection, dict):
        for cve in rule_selection.get("cve_ids") or []:
            if isinstance(cve, str) and CVE_RE.fullmatch(cve):
                cves.add(cve)
    for key in ("best_cve", "cve_dir"):
        for cve in CVE_RE.findall(str(row.get(key) or "")):
            cves.add(cve)
    return sorted(cves)


def extract_cargo_audit_ids(stdout_path: Path) -> tuple[set[str], set[str], int]:
    if not stdout_path.exists() or stdout_path.stat().st_size == 0:
        return set(), set(), 0
    try:
        payload = load_json(stdout_path)
    except Exception:
        return set(), set(), 0
    vulns = ((payload or {}).get("vulnerabilities") or {}).get("list") or []
    ids: set[str] = set()
    packages: set[str] = set()
    for vuln in vulns:
        advisory = (vuln or {}).get("advisory") or {}
        package_name = ((vuln or {}).get("package") or {}).get("name") or advisory.get("package")
        if package_name:
            packages.add(str(package_name))
        for value in [advisory.get("id"), *((advisory.get("aliases") or []))]:
            text = str(value or "").strip()
            if text:
                ids.add(text)
            ids.update(CVE_RE.findall(text))
    return ids, packages, int(((payload or {}).get("vulnerabilities") or {}).get("count") or len(vulns))


def extract_osv_ids(output_path: Path) -> tuple[set[str], set[str], int]:
    if not output_path.exists() or output_path.stat().st_size == 0:
        return set(), set(), 0
    try:
        payload = load_json(output_path)
    except Exception:
        return set(), set(), 0
    ids: set[str] = set()
    packages: set[str] = set()
    count = 0
    for result in (payload or {}).get("results") or []:
        for package in (result or {}).get("packages") or []:
            package_name = ((package or {}).get("package") or {}).get("name")
            if package_name:
                packages.add(str(package_name))
            for vuln in (package or {}).get("vulnerabilities") or []:
                count += 1
                for value in [vuln.get("id"), *((vuln.get("aliases") or []))]:
                    text = str(value or "").strip()
                    if text:
                        ids.add(text)
                    ids.update(CVE_RE.findall(text))
    return ids, packages, count


def summarize_efficiency(rows: list[dict[str, Any]]) -> dict[str, Any]:
    times = [float(row.get("wall_time_sec") or 0.0) for row in rows]
    peak_kb = [int(row.get("peak_rss_kb") or 0) for row in rows]
    avg_kb = [int(row.get("avg_rss_kb") or 0) for row in rows]
    return {
        "cases": len(rows),
        "total_detection_time_sec": round(sum(times), 3),
        "avg_detection_time_sec": round(statistics.mean(times), 3) if times else 0.0,
        "median_detection_time_sec": round(statistics.median(times), 3) if times else 0.0,
        "timeout_rate": round(sum(1 for row in rows if row.get("timed_out")) / len(rows), 6) if rows else 0.0,
        "peak_memory_gb": round(kb_to_gb(max(peak_kb) if peak_kb else 0), 6),
        "average_memory_gb": round(kb_to_gb(round(statistics.mean(avg_kb)) if avg_kb else 0), 6),
        "exit_code_counts": {str(code): sum(1 for row in rows if int(row.get("exit_code") or 0) == code) for code in sorted({int(row.get("exit_code") or 0) for row in rows})},
    }


def summarize_predictions(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    completed = sum(1 for row in rows if not row["tool_failed"])
    target_hits = sum(1 for row in rows if row["target_cve_hit"])
    target_component_hits = sum(1 for row in rows if row["target_component_advisory_hit"])
    any_alerts = sum(1 for row in rows if row["reported_vulnerability_count"] > 0)

    def binary_for(field: str) -> dict[str, Any]:
        risk_rows = [row for row in rows if row["gold_label"] != "unreachable"]
        safe_rows = [row for row in rows if row["gold_label"] == "unreachable"]
        tp = sum(1 for row in risk_rows if row[field])
        fn = sum(1 for row in risk_rows if not row[field])
        fp = sum(1 for row in safe_rows if row[field])
        tn = sum(1 for row in safe_rows if not row[field])
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        accuracy = (tp + tn) / total if total else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        return {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
            "accuracy": round(accuracy, 6),
        }

    return {
        "total_cases": total,
        "completed_cases": completed,
        "tool_failed_cases": total - completed,
        "target_cve_hit_cases": target_hits,
        "target_component_advisory_hit_cases": target_component_hits,
        "any_advisory_cases": any_alerts,
        "target_cve_binary": binary_for("target_cve_hit"),
        "target_component_advisory_binary": binary_for("target_component_advisory_hit"),
    }


def parse_method(method: str, run_root: Path, merged_rows: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    summary_rows = load_json(run_root / "summary.json")
    parsed: list[dict[str, Any]] = []
    for record in summary_rows:
        case_id = str(record.get("case_id") or "")
        merged = merged_rows.get(case_id, {})
        targets = target_cves(merged)
        target_crates = sorted(set(((merged.get("rule_selection") or {}).get("match_crates") or [])))
        if method == "cargo-audit":
            reported_ids, reported_packages, vuln_count = extract_cargo_audit_ids(Path(str(record.get("stdout_path") or "")))
        elif method == "osv-scanner":
            reported_ids, reported_packages, vuln_count = extract_osv_ids(Path(str(record.get("tool_output_path") or "")))
        else:
            raise ValueError(f"unsupported method: {method}")

        target_hit_ids = sorted(set(targets) & reported_ids)
        target_hit_packages = sorted(set(target_crates) & reported_packages)
        parsed.append(
            {
                "method": method,
                "case_id": case_id,
                "component": merged.get("component", ""),
                "project_name": merged.get("project_name", ""),
                "version": merged.get("version", ""),
                "gold_label": merged.get("final_gold_label") or merged.get("gold_label") or "",
                "target_cves": ";".join(targets),
                "target_crates": ";".join(target_crates),
                "target_cve_hit": bool(target_hit_ids),
                "target_cve_hit_ids": ";".join(target_hit_ids),
                "target_component_advisory_hit": bool(target_hit_packages),
                "target_component_hit_packages": ";".join(target_hit_packages),
                "reported_vulnerability_count": int(vuln_count),
                "reported_id_count": len(reported_ids),
                "reported_package_count": len(reported_packages),
                "reported_ids": ";".join(sorted(reported_ids)),
                "reported_packages": ";".join(sorted(reported_packages)),
                "exit_code": int(record.get("exit_code") or 0),
                "tool_failed": bool((not record.get("timed_out")) and int(record.get("exit_code") or 0) not in {0, 1}),
                "timed_out": bool(record.get("timed_out")),
                "wall_time_sec": float(record.get("wall_time_sec") or 0.0),
                "peak_rss_kb": int(record.get("peak_rss_kb") or 0),
                "avg_rss_kb": int(record.get("avg_rss_kb") or 0),
            }
        )
    return parsed, {
        "method": method,
        "efficiency": summarize_efficiency(summary_rows),
        "prediction": summarize_predictions(parsed),
    }


def render_report(method_summaries: list[dict[str, Any]]) -> str:
    lines = [
        "# External Baseline Results (cargo-audit and OSV-Scanner)",
        "",
        "This report summarizes dependency-scanner baselines on the same 143 Top15 projects.",
        "Target-CVE hit is evaluated against each benchmark case's selected target CVE set.",
        "",
        "## Summary",
        "",
        "| Method | Cases | Tool Failures | Target-CVE Hits | Target-Crate Advisory Hits | Any-Advisory Cases | Precision | Recall | F1 | Accuracy | Total Time (s) | Avg Time (s) | Median Time (s) | Timeout Rate | Peak Mem (GB) | Avg Mem (GB) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in method_summaries:
        pred = item["prediction"]
        eff = item["efficiency"]
        binary = pred["target_cve_binary"]
        lines.append(
            "| {method} | {cases} | {failed} | {hits} | {component_hits} | {any_alerts} | {precision:.2%} | {recall:.2%} | {f1:.2%} | {accuracy:.2%} | {total:.2f} | {avg:.2f} | {median:.2f} | {timeout:.1%} | {peak:.3f} | {avg_mem:.3f} |".format(
                method=item["method"],
                cases=pred["total_cases"],
                failed=pred["tool_failed_cases"],
                hits=pred["target_cve_hit_cases"],
                component_hits=pred["target_component_advisory_hit_cases"],
                any_alerts=pred["any_advisory_cases"],
                precision=binary["precision"],
                recall=binary["recall"],
                f1=binary["f1"],
                accuracy=binary["accuracy"],
                total=eff["total_detection_time_sec"],
                avg=eff["avg_detection_time_sec"],
                median=eff["median_detection_time_sec"],
                timeout=eff["timeout_rate"],
                peak=eff["peak_memory_gb"],
                avg_mem=eff["average_memory_gb"],
            )
        )
    lines.extend(
        [
            "",
            "## Target-Component Advisory Metrics",
            "",
            "| Method | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for item in method_summaries:
        binary = item["prediction"]["target_component_advisory_binary"]
        lines.append(
            "| {method} | {tp} | {fp} | {tn} | {fn} | {precision:.2%} | {recall:.2%} | {f1:.2%} | {accuracy:.2%} |".format(
                method=item["method"],
                tp=binary["tp"],
                fp=binary["fp"],
                tn=binary["tn"],
                fn=binary["fn"],
                precision=binary["precision"],
                recall=binary["recall"],
                f1=binary["f1"],
                accuracy=binary["accuracy"],
            )
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `Any-Advisory Cases` counts projects where the tool reported at least one advisory of any kind.",
            "- `Target-CVE Hits` counts projects where the tool reported at least one benchmark target CVE for that case.",
            "- `Target-Crate Advisory Hits` counts projects where the tool reported an advisory on one of the benchmark target crates, even if the advisory ID is not the benchmark target CVE.",
            "- The binary metrics treat `triggerable` and `reachable_but_not_triggerable` as risk-positive, and `unreachable` as risk-negative.",
            "- cargo-audit and OSV-Scanner are dependency advisory scanners; they do not model native-call reachability or triggerability.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--merged-summary", required=True)
    parser.add_argument("--cargo-audit-run-root", required=True)
    parser.add_argument("--osv-scanner-run-root", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out_dir).resolve()
    merged = {str(row.get("case_id") or ""): row for row in load_json(Path(args.merged_summary).resolve())}
    methods = [
        ("cargo-audit", Path(args.cargo_audit_run_root).resolve()),
        ("osv-scanner", Path(args.osv_scanner_run_root).resolve()),
    ]
    all_rows: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    for method, run_root in methods:
        rows, summary = parse_method(method, run_root, merged)
        all_rows.extend(rows)
        summaries.append(summary)
        write_json(out_dir / f"top15_{method.replace('-', '_')}_baseline_results.json", rows)
    headers = [
        "method",
        "case_id",
        "component",
        "project_name",
        "version",
        "gold_label",
        "target_cves",
        "target_crates",
        "target_cve_hit",
        "target_cve_hit_ids",
        "target_component_advisory_hit",
        "target_component_hit_packages",
        "reported_vulnerability_count",
        "reported_id_count",
        "reported_package_count",
        "exit_code",
        "tool_failed",
        "timed_out",
        "wall_time_sec",
        "peak_rss_kb",
        "avg_rss_kb",
        "reported_ids",
        "reported_packages",
    ]
    write_csv(out_dir / "top15_external_baseline_case_results.csv", all_rows, headers)
    write_json(out_dir / "top15_external_baseline_summary.json", summaries)
    (out_dir / "TOP15_EXTERNAL_BASELINE_REPORT_2026-04-27.md").write_text(render_report(summaries), encoding="utf-8")
    print(f"[+] Wrote external baseline summaries to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
