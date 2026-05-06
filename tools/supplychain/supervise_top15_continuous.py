#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent.parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from run_top15_benchmark import build_case_id, configure_analysis_env, preferred_shared_cache_root


DEFAULT_BENCHMARK_JSON = Path("/root/Experiment_Ready_Dataset_Top15/benchmark_project.json")
DEFAULT_RUN_OUTPUT_ROOT = Path("/dev/shm/top15_benchmark_runs")
DEFAULT_PROCESS_ROOT = REPO_ROOT / "output" / "top15_continuous"
FAILED_STATUSES = {"analysis_failed", "analysis_timeout"}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(data, ensure_ascii=False) + "\n")


def slug(text: str) -> str:
    out: list[str] = []
    last_sep = False
    for ch in str(text or "").strip().lower():
        if ch.isalnum() or ch in {".", "-"}:
            out.append(ch)
            last_sep = False
            continue
        if not last_sep:
            out.append("_")
            last_sep = True
    return "".join(out).strip("_") or "na"


def load_benchmark_items(path: Path) -> list[dict[str, Any]]:
    raw = load_json(path, {})
    items = raw.get("projects") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise ValueError(f"invalid benchmark json: {path}")
    return [dict(item) for item in items]


def status_is_complete(status: str) -> bool:
    return bool(status) and status not in FAILED_STATUSES


def entry_rank(entry: dict[str, Any]) -> tuple[int, float]:
    status = str(entry.get("status") or "").strip()
    mtime = float(entry.get("_summary_mtime") or 0.0)
    return (1 if status_is_complete(status) else 0, mtime)


def discover_existing_results(scan_roots: list[Path]) -> dict[str, dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}
    seen_summary_paths: set[Path] = set()
    for scan_root in scan_roots:
        if not scan_root.exists():
            continue
        for skipped_path in sorted(scan_root.rglob("skipped.json")):
            rows = load_json(skipped_path, [])
            if not isinstance(rows, list):
                continue
            try:
                skipped_mtime = skipped_path.stat().st_mtime
            except OSError:
                skipped_mtime = 0.0
            for row in rows:
                if not isinstance(row, dict):
                    continue
                case_id = str(row.get("case_id") or "").strip()
                if not case_id:
                    continue
                issue_owner = str(row.get("issue_owner") or "").strip().lower()
                if issue_owner != "label":
                    continue
                candidate = dict(row)
                candidate["status"] = "dataset_label_issue"
                candidate["_summary_path"] = str(skipped_path)
                candidate["_summary_mtime"] = skipped_mtime
                current = best.get(case_id)
                if current is None or entry_rank(candidate) > entry_rank(current):
                    best[case_id] = candidate
        for summary_path in sorted(scan_root.rglob("summary*.json")):
            if summary_path in seen_summary_paths:
                continue
            seen_summary_paths.add(summary_path)
            rows = load_json(summary_path, [])
            if not isinstance(rows, list):
                continue
            try:
                summary_mtime = summary_path.stat().st_mtime
            except OSError:
                summary_mtime = 0.0
            for row in rows:
                if not isinstance(row, dict):
                    continue
                case_id = str(row.get("case_id") or "").strip()
                if not case_id:
                    continue
                candidate = dict(row)
                candidate["_summary_path"] = str(summary_path)
                candidate["_summary_mtime"] = summary_mtime
                current = best.get(case_id)
                if current is None or entry_rank(candidate) > entry_rank(current):
                    best[case_id] = candidate
    return best


def read_state(path: Path) -> dict[str, Any]:
    return load_json(
        path,
        {
            "started_at": utc_now(),
            "batches": [],
            "attempts": {},
            "paused_cases": {},
            "completed_cases": [],
            "last_batch_index": 0,
        },
    )


def paused_case_ids(state: dict[str, Any], max_retries: int) -> set[str]:
    paused = {
        str(case_id).strip()
        for case_id, attempts in (state.get("attempts") or {}).items()
        if str(case_id).strip() and int(attempts or 0) >= max_retries
    }
    paused.update(
        str(case_id).strip()
        for case_id in (state.get("paused_cases") or {}).keys()
        if str(case_id).strip()
    )
    return paused


def summarize_failure_reason(entry: dict[str, Any]) -> str:
    status = str(entry.get("status") or "").strip()
    mismatch_reason = str(entry.get("mismatch_reason") or "").strip()
    if mismatch_reason:
        return mismatch_reason
    if status == "analysis_timeout":
        return f"timeout after {entry.get('seconds') or 'unknown'} seconds"
    log_path = Path(str(entry.get("log") or ""))
    if log_path.is_file():
        lines = [line.strip() for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
        tail = lines[-8:]
        if tail:
            text = " | ".join(tail)
            return text[:1200]
    detail = str(entry.get("cargo_prefetch_detail") or "").strip()
    if detail:
        return detail[:1200]
    return status or "unknown_failure"


def build_batch_markdown(
    *,
    session_name: str,
    benchmark_total: int,
    completed_count: int,
    remaining_count: int,
    paused_count: int,
    state: dict[str, Any],
) -> str:
    lines = [
        f"# Top15 Continuous Supervisor: {session_name}",
        "",
        f"- updated_at: `{utc_now()}`",
        f"- benchmark_total: `{benchmark_total}`",
        f"- completed_cases: `{completed_count}`",
        f"- remaining_cases: `{remaining_count}`",
        f"- paused_after_max_retries: `{paused_count}`",
        f"- batch_count: `{len(state.get('batches', []))}`",
        "",
        "## Recent Batches",
        "",
    ]
    batches = list(state.get("batches", []))
    if not batches:
        lines.append("- none")
    else:
        for batch in batches[-10:]:
            counts = batch.get("status_counts") or {}
            lines.append(
                f"- `#{batch.get('batch_index')}` `{batch.get('run_name')}` "
                f"processed=`{batch.get('processed_count')}` "
                f"correct_yes=`{batch.get('correct_yes')}` "
                f"correct_no=`{batch.get('correct_no')}` "
                f"failed=`{counts.get('analysis_failed', 0)}` "
                f"timeout=`{counts.get('analysis_timeout', 0)}`"
            )
    lines.extend(["", "## Recent Retries", ""])
    retries: list[dict[str, Any]] = []
    for batch in batches[-10:]:
        retries.extend(batch.get("retries", []))
    if not retries:
        lines.append("- none")
    else:
        for item in retries[-20:]:
            lines.append(
                f"- `{item.get('case_id')}` attempt=`{item.get('attempt')}` "
                f"status=`{item.get('status')}` reason=`{item.get('reason')}`"
            )
    paused_cases = state.get("paused_cases") or {}
    lines.extend(["", "## Paused Cases", ""])
    if not paused_cases:
        lines.append("- none")
    else:
        for case_id, detail in list(sorted(paused_cases.items()))[-20:]:
            reason = str((detail or {}).get("reason") or "").strip()
            attempts = int((detail or {}).get("attempts") or 0)
            lines.append(
                f"- `{case_id}` attempts=`{attempts}` reason=`{reason[:800]}`"
            )
    return "\n".join(lines) + "\n"


def write_subset_benchmark(path: Path, items: list[dict[str, Any]]) -> None:
    write_json(path, {"projects": items})


def run_top15_subset(
    *,
    benchmark_json: Path,
    run_output_root: Path,
    run_name: str,
    timeout_seconds: int,
    log_path: Path,
) -> int:
    cmd = [
        sys.executable,
        str(CURRENT_DIR / "run_top15_benchmark.py"),
        "--benchmark-json",
        str(benchmark_json),
        "--output-root",
        str(run_output_root),
        "--run-name",
        run_name,
        "--timeout-seconds",
        str(timeout_seconds),
    ]
    env = os.environ.copy()
    env.setdefault("SUPPLYCHAIN_SHARED_CACHE_ROOT", str(preferred_shared_cache_root(env=env)))
    env.setdefault("SUPPLYCHAIN_CARGO_HOME_SEED", str(Path.home() / ".cargo"))
    env.setdefault("SUPPLYCHAIN_BENCHMARK_CARGO_HOME_MODE", "shared")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log_fh:
        proc = subprocess.Popen(
            cmd,
            cwd=str(REPO_ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="", flush=True)
            log_fh.write(line)
        return proc.wait()


def load_run_summary(run_output_root: Path, run_name: str) -> list[dict[str, Any]]:
    return load_json(run_output_root / run_name / "summary.json", [])


def analyze_entries(entries: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = Counter(str(entry.get("status") or "").strip() for entry in entries)
    correct_yes = sum(1 for entry in entries if str(entry.get("correct") or "").strip() == "yes")
    correct_no = sum(1 for entry in entries if str(entry.get("correct") or "").strip() == "no")
    failed = []
    mismatches = []
    for entry in entries:
        status = str(entry.get("status") or "").strip()
        item = {
            "case_id": entry.get("case_id"),
            "component": entry.get("component"),
            "project_name": entry.get("project_name") or entry.get("project"),
            "version": entry.get("version"),
            "status": status,
            "correct": entry.get("correct"),
            "predicted_label": entry.get("predicted_label"),
            "gold_label": entry.get("gold_label"),
            "run_dir": entry.get("run_dir"),
            "report": entry.get("report"),
            "log": entry.get("log"),
            "repair_actions": list(entry.get("repair_actions") or []),
            "mismatch_reason": entry.get("mismatch_reason") or "",
            "issue_owner": entry.get("issue_owner") or "",
        }
        if status in FAILED_STATUSES:
            item["reason"] = summarize_failure_reason(entry)
            failed.append(item)
        elif str(entry.get("correct") or "").strip() == "no":
            mismatches.append(item)
    return {
        "processed_count": len(entries),
        "status_counts": dict(status_counts),
        "correct_yes": correct_yes,
        "correct_no": correct_no,
        "failed": failed,
        "mismatches": mismatches,
    }


def discover_session_batch_index(session_name: str, process_root: Path, run_output_root: Path) -> int:
    patterns = [
        (process_root / "subsets", re.compile(rf"^{re.escape(session_name)}__b(\d+)\.benchmark\.json$")),
        (process_root / "logs", re.compile(rf"^{re.escape(session_name)}__b(\d+)\.log$")),
        (run_output_root, re.compile(rf"^{re.escape(session_name)}__b(\d+)$")),
    ]
    max_batch_index = 0
    for root, pattern in patterns:
        if not root.exists():
            continue
        for path in root.iterdir():
            match = pattern.match(path.name)
            if not match:
                continue
            max_batch_index = max(max_batch_index, int(match.group(1)))
    return max_batch_index


def main() -> int:
    parser = argparse.ArgumentParser(description="Continuously run the remaining Top15 benchmark projects in batches.")
    parser.add_argument("--benchmark-json", default=str(DEFAULT_BENCHMARK_JSON))
    parser.add_argument("--run-output-root", default=str(DEFAULT_RUN_OUTPUT_ROOT))
    parser.add_argument("--process-root", default=str(DEFAULT_PROCESS_ROOT))
    parser.add_argument("--session-name", default=f"top15_continuous_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}")
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--batch-timeout-seconds", type=int, default=5400)
    parser.add_argument("--retry-timeout-seconds", type=int, default=10800)
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--scan-root", action="append", default=[])
    parser.add_argument("--max-batches", type=int, default=0)
    parser.add_argument("--sleep-seconds", type=int, default=5)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    configure_analysis_env()

    benchmark_json = Path(args.benchmark_json).resolve()
    run_output_root = Path(args.run_output_root).resolve()
    process_root = Path(args.process_root).resolve() / args.session_name
    process_root.mkdir(parents=True, exist_ok=True)
    state_path = process_root / "state.json"
    report_md_path = process_root / "latest_report.md"
    batch_reports_path = process_root / "batch_reports.jsonl"
    subset_dir = process_root / "subsets"
    batch_log_dir = process_root / "logs"
    scan_roots = [run_output_root]
    for scan_root in args.scan_root:
        scan_roots.append(Path(scan_root).resolve())
    state = read_state(state_path)

    all_items = load_benchmark_items(benchmark_json)
    item_by_case_id = {build_case_id(item): item for item in all_items}
    benchmark_total = len(all_items)
    batch_index = max(
        int(state.get("last_batch_index") or 0),
        discover_session_batch_index(args.session_name, process_root, run_output_root),
    )

    while True:
        existing = discover_existing_results(scan_roots)
        completed_case_ids = {
            case_id
            for case_id, entry in existing.items()
            if status_is_complete(str(entry.get("status") or "").strip())
        }
        completed_case_ids.update(str(case_id).strip() for case_id in (state.get("completed_cases") or []) if str(case_id).strip())
        paused_cases = dict(state.get("paused_cases") or {})
        for case_id in list(paused_cases):
            if case_id in completed_case_ids:
                paused_cases.pop(case_id, None)
        state["paused_cases"] = paused_cases
        paused_case_ids_set = paused_case_ids(state, args.max_retries) - completed_case_ids
        remaining = [item for item in all_items if build_case_id(item) not in completed_case_ids]
        schedulable_remaining = [item for item in remaining if build_case_id(item) not in paused_case_ids_set]
        state["completed_cases"] = sorted(completed_case_ids)
        write_json(state_path, state)
        report_md_path.write_text(
            build_batch_markdown(
                session_name=args.session_name,
                benchmark_total=benchmark_total,
                completed_count=len(completed_case_ids),
                remaining_count=len(remaining),
                paused_count=len(paused_case_ids_set),
                state=state,
            ),
            encoding="utf-8",
        )

        if not remaining:
            break
        if not schedulable_remaining:
            break
        if args.max_batches > 0 and batch_index >= args.max_batches:
            break

        batch_index += 1
        batch_items = schedulable_remaining[: args.batch_size]
        run_name = f"{args.session_name}__b{batch_index:03d}"
        subset_path = subset_dir / f"{run_name}.benchmark.json"
        batch_log_path = batch_log_dir / f"{run_name}.log"
        write_subset_benchmark(subset_path, batch_items)

        batch_record: dict[str, Any] = {
            "batch_index": batch_index,
            "run_name": run_name,
            "started_at": utc_now(),
            "timeout_seconds": args.batch_timeout_seconds,
            "selected_cases": [build_case_id(item) for item in batch_items],
            "selected_projects": [
                {
                    "case_id": build_case_id(item),
                    "component": item.get("component"),
                    "project_name": item.get("project_name"),
                    "version": item.get("version") or item.get("project_version_in_pool"),
                }
                for item in batch_items
            ],
            "batch_log": str(batch_log_path),
            "subset_benchmark": str(subset_path),
            "retries": [],
        }

        if args.dry_run:
            batch_record["dry_run"] = True
            batch_record["finished_at"] = utc_now()
            batch_record["processed_count"] = 0
            batch_record["status_counts"] = {}
            state.setdefault("batches", []).append(batch_record)
            state["last_batch_index"] = batch_index
            append_jsonl(batch_reports_path, batch_record)
            write_json(state_path, state)
            time.sleep(args.sleep_seconds)
            continue

        exit_code = run_top15_subset(
            benchmark_json=subset_path,
            run_output_root=run_output_root,
            run_name=run_name,
            timeout_seconds=args.batch_timeout_seconds,
            log_path=batch_log_path,
        )
        entries = load_run_summary(run_output_root, run_name)
        analysis = analyze_entries(entries)
        batch_record.update(analysis)
        batch_record["exit_code"] = exit_code

        for failed_entry in analysis["failed"]:
            case_id = str(failed_entry.get("case_id") or "").strip()
            if not case_id:
                continue
            attempt = int((state.get("attempts") or {}).get(case_id, 0)) + 1
            if attempt > args.max_retries:
                state.setdefault("paused_cases", {})[case_id] = {
                    "attempts": max(int((state.get("attempts") or {}).get(case_id, 0)), args.max_retries),
                    "reason": failed_entry.get("reason") or "",
                    "updated_at": utc_now(),
                }
                batch_record["retries"].append(
                    {
                        "case_id": case_id,
                        "attempt": attempt - 1,
                        "status": "skipped_max_retries",
                        "reason": failed_entry.get("reason") or "",
                    }
                )
                continue
            retry_item = item_by_case_id.get(case_id)
            if retry_item is None:
                continue
            retry_run_name = f"{run_name}__retry_{slug(case_id)}__a{attempt}"
            retry_subset_path = subset_dir / f"{retry_run_name}.benchmark.json"
            retry_log_path = batch_log_dir / f"{retry_run_name}.log"
            write_subset_benchmark(retry_subset_path, [retry_item])
            retry_exit_code = run_top15_subset(
                benchmark_json=retry_subset_path,
                run_output_root=run_output_root,
                run_name=retry_run_name,
                timeout_seconds=args.retry_timeout_seconds,
                log_path=retry_log_path,
            )
            retry_entries = load_run_summary(run_output_root, retry_run_name)
            retry_analysis = analyze_entries(retry_entries)
            retry_entry = retry_entries[0] if retry_entries else {}
            batch_record["retries"].append(
                {
                    "case_id": case_id,
                    "attempt": attempt,
                    "run_name": retry_run_name,
                    "exit_code": retry_exit_code,
                    "status": retry_entry.get("status") or "missing_summary",
                    "reason": summarize_failure_reason(retry_entry or failed_entry),
                    "correct": retry_entry.get("correct") or "",
                    "processed_count": retry_analysis.get("processed_count") or 0,
                    "log": str(retry_log_path),
                    "summary": str(run_output_root / retry_run_name / "summary.json"),
                }
            )
            state.setdefault("attempts", {})[case_id] = attempt

        batch_record["finished_at"] = utc_now()
        existing = discover_existing_results(scan_roots)
        completed_case_ids = {
            case_id
            for case_id, entry in existing.items()
            if status_is_complete(str(entry.get("status") or "").strip())
        }
        completed_case_ids.update(str(case_id).strip() for case_id in (state.get("completed_cases") or []) if str(case_id).strip())
        batch_record["completed_after_batch"] = len(completed_case_ids)
        batch_record["remaining_after_batch"] = benchmark_total - len(completed_case_ids)

        state.setdefault("batches", []).append(batch_record)
        state["last_batch_index"] = batch_index
        state["completed_cases"] = sorted(completed_case_ids)
        write_json(state_path, state)
        append_jsonl(batch_reports_path, batch_record)
        report_md_path.write_text(
            build_batch_markdown(
                session_name=args.session_name,
                benchmark_total=benchmark_total,
                completed_count=len(completed_case_ids),
                remaining_count=benchmark_total - len(completed_case_ids),
                paused_count=len(paused_case_ids(state, args.max_retries) - completed_case_ids),
                state=state,
            ),
            encoding="utf-8",
        )
        time.sleep(args.sleep_seconds)

    final_existing = discover_existing_results(scan_roots)
    final_completed = {
        case_id for case_id, entry in final_existing.items() if status_is_complete(str(entry.get("status") or "").strip())
    }
    final_completed.update(str(case_id).strip() for case_id in (state.get("completed_cases") or []) if str(case_id).strip())
    final_payload = {
        "session_name": args.session_name,
        "finished_at": utc_now(),
        "benchmark_total": benchmark_total,
        "completed_cases": len(final_completed),
        "remaining_cases": benchmark_total - len(final_completed),
        "paused_after_max_retries": len(paused_case_ids(state, args.max_retries) - final_completed),
        "max_retries": args.max_retries,
        "batch_count": len(state.get("batches", [])),
    }
    write_json(process_root / "final_summary.json", final_payload)
    print(json.dumps(final_payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
