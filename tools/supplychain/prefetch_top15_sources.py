#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from run_top15_benchmark import (
    DEFAULT_BENCHMARK_JSON,
    DEFAULT_FETCH_ROOT,
    DEFAULT_INVENTORY_CSV,
    benchmark_label,
    build_rule_indexes,
    load_inventory_rows,
    load_json,
    resolve_source,
    target_vuln_id_for_item,
    write_json,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prefetch Top15 benchmark project sources into the local cache.")
    parser.add_argument("--benchmark-json", default=str(DEFAULT_BENCHMARK_JSON))
    parser.add_argument("--inventory-csv", default=str(DEFAULT_INVENTORY_CSV))
    parser.add_argument("--fetch-root", default=str(DEFAULT_FETCH_ROOT))
    parser.add_argument("--runtime-rules", default="")
    parser.add_argument("--component", action="append", default=[])
    parser.add_argument("--project", action="append", default=[])
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--summary-out", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    benchmark_path = Path(args.benchmark_json).resolve()
    inventory_csv = Path(args.inventory_csv).resolve()
    fetch_root = Path(args.fetch_root).resolve()
    summary_out = Path(args.summary_out).resolve() if args.summary_out else fetch_root / "_prefetch_summary.json"

    raw = load_json(benchmark_path)
    items = list(raw.get("projects") or raw)
    if args.component:
        wanted = {value.strip().lower() for value in args.component}
        items = [item for item in items if str(item.get("component") or "").strip().lower() in wanted]
    if args.project:
        wanted = {value.strip().lower() for value in args.project}
        items = [item for item in items if str(item.get("project_name") or "").strip().lower() in wanted]
    if args.limit > 0:
        items = items[: args.limit]

    inventory_lookup = load_inventory_rows(inventory_csv)

    summary: list[dict[str, str]] = []
    counts: Counter[str] = Counter()
    total = len(items)
    for idx, item in enumerate(items, start=1):
        label = benchmark_label(item)
        if not label:
            counts["skip_missing_label"] += 1
            continue
        source_path, resolution, _ = resolve_source(
            item,
            inventory_lookup=inventory_lookup,
            fetch_root=fetch_root,
        )
        method = str(resolution.get("method") or "unknown")
        counts[method] += 1
        entry = {
            "component": str(item.get("component") or ""),
            "project_name": str(item.get("project_name") or ""),
            "version": str(item.get("version") or ""),
            "label": label,
            "target_vuln_id": target_vuln_id_for_item(item),
            "method": method,
            "path": str(source_path or ""),
            "notes": str(resolution.get("notes") or ""),
        }
        summary.append(entry)
        print(f"[{idx}/{total}] {entry['component']}/{entry['project_name']}-{entry['version']} -> {method}", flush=True)

    payload = {
        "benchmark_json": str(benchmark_path),
        "fetch_root": str(fetch_root),
        "total_items": total,
        "counts": dict(counts),
        "items": summary,
    }
    write_json(summary_out, payload)
    print(json.dumps(payload["counts"], ensure_ascii=False, indent=2))
    print(f"summary_out={summary_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
