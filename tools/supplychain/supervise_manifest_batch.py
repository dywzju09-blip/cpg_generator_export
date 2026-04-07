#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from archive_analysis_run import archive_run
from monitor_analysis_run import apt_install
from run_manifest_analysis import normalize_item, run_one, write_run_summary
from watch_vul_directory import configure_analysis_env, infer_packages_from_log


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


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def process_alive(pattern: str) -> bool:
    proc = subprocess.run(
        ["pgrep", "-f", pattern],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0 and bool((proc.stdout or "").strip())


def load_manifest_items(path: Path) -> list[dict[str, Any]]:
    raw = load_json(path, {})
    items = raw.get("items", raw) if isinstance(raw, dict) else raw
    return [normalize_item(item) for item in items]


def entry_key(entry: dict[str, Any]) -> str:
    project_dir = str(Path(entry["project_dir"]).resolve())
    return f"{entry['cve_dir']}::{project_dir}"


def build_status_report(
    *,
    run_root: Path,
    entries: list[dict[str, Any]],
    state: dict[str, Any],
    batch_alive: bool,
) -> str:
    counts = Counter(entry.get("status") for entry in entries)
    lines = [
        f"# Batch Supervisor: {run_root.name}",
        "",
        f"- updated_at: `{utc_now()}`",
        f"- batch_alive: `{batch_alive}`",
        f"- completed: `{len(entries)}`",
        f"- env_installs: `{len(state.get('installed_packages', []))}`",
        f"- reruns: `{len(state.get('reruns', []))}`",
        "",
        "## Status Counts",
        "",
    ]
    for key in sorted(counts):
        lines.append(f"- `{key}`: {counts[key]}")
    lines.extend(["", "## Trigger Queue", ""])
    trigger_entries = state.get("trigger_candidates", [])
    if trigger_entries:
        for item in trigger_entries[-20:]:
            lines.append(
                f"- `{item.get('project')}` -> `{item.get('status')}` `{item.get('symbol') or ''}`"
            )
    else:
        lines.append("- none")
    lines.extend(["", "## Recent Reruns", ""])
    reruns = state.get("reruns", [])
    if reruns:
        for item in reruns[-20:]:
            lines.append(
                f"- `{item.get('project')}` `{item.get('original_status')}` -> `{item.get('retry_status')}`"
            )
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def rerun_entry(
    item: dict[str, Any],
    *,
    original_entry: dict[str, Any],
    output_root: Path,
    archive_root: Path,
    manifest_path: Path,
    base_timeout: int,
    expanded_timeout: int,
) -> dict[str, Any]:
    key_slug = item["rel"].replace("/", "__")
    suffix = "retry_timeout" if original_entry["status"] == "analysis_timeout" else "retry_env"
    run_name = f"{manifest_path.stem}__{key_slug}__{suffix}"
    run_root = output_root / run_name
    if run_root.exists():
        shutil.rmtree(run_root)
    run_root.mkdir(parents=True, exist_ok=True)

    timeout_seconds = expanded_timeout if original_entry["status"] == "analysis_timeout" else base_timeout
    retry_entry = run_one(item, run_root, timeout_seconds)
    write_run_summary(run_root, manifest_path, [retry_entry])
    archive_run(run_root, archive_root)
    if run_root.exists():
        shutil.rmtree(run_root)
    return retry_entry


def maybe_install_from_log(log_path: Path, installed_packages: set[str]) -> list[str]:
    if not log_path.exists():
        return []
    log_text = log_path.read_text(encoding="utf-8", errors="ignore")
    wanted = [pkg for pkg in infer_packages_from_log(log_text) if pkg not in installed_packages]
    if not wanted:
        return []
    installed_now = apt_install(wanted)
    for package in installed_now:
        if not package.startswith("apt-install-failed:"):
            installed_packages.add(package)
    return installed_now


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--archive-root", required=True)
    parser.add_argument("--batch-pattern", required=True)
    parser.add_argument("--state-file", required=True)
    parser.add_argument("--report-file", required=True)
    parser.add_argument("--trigger-queue-file", required=True)
    parser.add_argument("--interval-seconds", type=int, default=120)
    parser.add_argument("--base-timeout-seconds", type=int, default=43200)
    parser.add_argument("--expanded-timeout-seconds", type=int, default=86400)
    args = parser.parse_args()

    configure_analysis_env()

    manifest_path = Path(args.manifest).resolve()
    run_root = Path(args.run_root).resolve()
    output_root = Path(args.output_root).resolve()
    archive_root = Path(args.archive_root).resolve()
    state_path = Path(args.state_file).resolve()
    report_path = Path(args.report_file).resolve()
    trigger_queue_path = Path(args.trigger_queue_file).resolve()

    items = load_manifest_items(manifest_path)
    items_by_key = {entry_key(item): item for item in items}

    state = load_json(
        state_path,
        {
            "installed_packages": [],
            "handled_entries": {},
            "reruns": [],
            "trigger_candidates": [],
        },
    )
    installed_packages = set(state.get("installed_packages", []))
    handled_entries = dict(state.get("handled_entries", {}))
    trigger_seen = {f"{item.get('cve_dir')}::{item.get('project_dir')}" for item in state.get("trigger_candidates", [])}

    while True:
        entries = load_json(run_root / "summary.partial.json", [])
        batch_running = process_alive(args.batch_pattern)

        for entry in entries:
            key = entry_key(entry)
            status = entry.get("status")

            if status in {"triggerable_confirmed", "triggerable_possible", "reachable_only", "observable_triggered", "path_triggered"}:
                if key not in trigger_seen:
                    trigger_seen.add(key)
                    state.setdefault("trigger_candidates", []).append(
                        {
                            "checked_at": utc_now(),
                            "project": entry.get("project"),
                            "project_dir": entry.get("project_dir"),
                            "cve_dir": entry.get("cve_dir"),
                            "status": status,
                            "symbol": entry.get("symbol"),
                            "report": entry.get("report"),
                            "log": entry.get("log"),
                        }
                    )

            if handled_entries.get(key):
                continue

            if status == "analysis_failed":
                installed_now = maybe_install_from_log(Path(entry["log"]), installed_packages)
                handled_entries[key] = {
                    "status": status,
                    "checked_at": utc_now(),
                    "installed": installed_now,
                }
            elif status == "analysis_timeout":
                handled_entries[key] = {
                    "status": status,
                    "checked_at": utc_now(),
                    "installed": [],
                }

        state["installed_packages"] = sorted(installed_packages)
        state["handled_entries"] = handled_entries
        write_json(trigger_queue_path, state.get("trigger_candidates", []))
        report_path.write_text(
            build_status_report(run_root=run_root, entries=entries, state=state, batch_alive=batch_running),
            encoding="utf-8",
        )
        write_json(state_path, state)

        if not batch_running:
            break
        time.sleep(args.interval_seconds)

    entries = load_json(run_root / "summary.partial.json", [])
    for entry in entries:
        key = entry_key(entry)
        status = entry.get("status")
        if status not in {"analysis_failed", "analysis_timeout"}:
            continue
        if any(rerun.get("key") == key for rerun in state.get("reruns", [])):
            continue
        item = items_by_key.get(key)
        if not item:
            continue

        installed_now = []
        if status == "analysis_failed":
            installed_now = maybe_install_from_log(Path(entry["log"]), installed_packages)

        retry_entry = rerun_entry(
            item,
            original_entry=entry,
            output_root=output_root,
            archive_root=archive_root,
            manifest_path=manifest_path,
            base_timeout=args.base_timeout_seconds,
            expanded_timeout=args.expanded_timeout_seconds,
        )
        state.setdefault("reruns", []).append(
            {
                "key": key,
                "project": entry.get("project"),
                "project_dir": entry.get("project_dir"),
                "cve_dir": entry.get("cve_dir"),
                "original_status": status,
                "retry_status": retry_entry.get("status"),
                "installed": installed_now,
                "retry_log": retry_entry.get("log"),
                "retry_report": retry_entry.get("report"),
                "checked_at": utc_now(),
            }
        )
        state["installed_packages"] = sorted(installed_packages)
        write_json(state_path, state)
        write_json(trigger_queue_path, state.get("trigger_candidates", []))
        report_path.write_text(
            build_status_report(run_root=run_root, entries=entries, state=state, batch_alive=False),
            encoding="utf-8",
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
