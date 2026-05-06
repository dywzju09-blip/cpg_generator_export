#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from run_top15_benchmark import configure_analysis_env, prefetch_cargo_dependencies, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prefetch Cargo dependencies for Top15 benchmark projects.")
    parser.add_argument("--from-summary", required=True, help="Path to a summary.partial.json or summary.json file")
    parser.add_argument("--summary-out", default="", help="Where to write the cargo prefetch summary JSON")
    parser.add_argument("--timeout-seconds", type=int, default=300)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_analysis_env()
    summary_path = Path(args.from_summary).resolve()
    rows = json.loads(summary_path.read_text(encoding="utf-8"))
    summary_out = Path(args.summary_out).resolve() if args.summary_out else summary_path.with_name("cargo_prefetch_summary.json")

    seen: set[str] = set()
    results: list[dict[str, object]] = []
    counts: Counter[str] = Counter()
    failed_rows = [row for row in rows if str(row.get("status") or "") in {"analysis_failed", "analysis_timeout"}]
    total = len(failed_rows)

    for idx, row in enumerate(failed_rows, start=1):
        project_dir = str(row.get("project_dir") or "").strip()
        if not project_dir or project_dir in seen:
            continue
        seen.add(project_dir)
        result = prefetch_cargo_dependencies(Path(project_dir), timeout_seconds=args.timeout_seconds)
        counts[str(result.get("status") or "unknown")] += 1
        entry = {
            "case_id": row.get("case_id"),
            "component": row.get("component"),
            "project_name": row.get("project_name"),
            "version": row.get("version"),
            "project_dir": project_dir,
            **result,
        }
        results.append(entry)
        write_json(
            summary_out,
            {
                "from_summary": str(summary_path),
                "counts": dict(counts),
                "items": results,
            },
        )
        print(
            f"[{idx}/{total}] {row.get('component')}/{row.get('project_name')}-{row.get('version')} -> {result.get('status')}",
            flush=True,
        )

    payload = {
        "from_summary": str(summary_path),
        "counts": dict(counts),
        "items": results,
    }
    write_json(summary_out, payload)
    print(json.dumps(payload["counts"], ensure_ascii=False, indent=2))
    print(f"summary_out={summary_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
