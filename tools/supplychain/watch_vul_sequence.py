#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent.parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from watch_vul_directory import discover_projects, ensure_dir


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def project_total(watch_root: Path, settle_seconds: int) -> int:
    try:
        return len(discover_projects(watch_root, settle_seconds))
    except Exception:
        return 0


def completed_total(state_path: Path) -> int:
    state = load_json(state_path, {})
    return len((state or {}).get("completed", {}))


def start_child(args: argparse.Namespace, watch_root: Path) -> subprocess.Popen[str]:
    monitor_root = watch_root / "_monitor"
    ensure_dir(monitor_root)
    cmd = [
        sys.executable,
        str(CURRENT_DIR / "watch_vul_directory.py"),
        "--watch-root",
        str(watch_root),
        "--archive-root",
        args.archive_root,
        "--output-root",
        args.output_root,
        "--monitor-root",
        str(monitor_root),
        "--poll-seconds",
        str(args.poll_seconds),
        "--settle-seconds",
        str(args.settle_seconds),
        "--timeout-seconds",
        str(args.timeout_seconds),
        "--expanded-timeout-seconds",
        str(args.expanded_timeout_seconds),
    ]
    return subprocess.Popen(cmd)


def stop_child(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run multiple VUL watch roots sequentially in the foreground.")
    parser.add_argument(
        "--watch-roots",
        nargs="+",
        required=True,
        help="Ordered watch roots. Next root starts only after the previous root is fully processed.",
    )
    parser.add_argument("--archive-root", default="/root/VUL/cases/by-analysis-status")
    parser.add_argument("--output-root", default=str(REPO_ROOT / "output" / "vulnerability_runs"))
    parser.add_argument("--poll-seconds", type=int, default=30)
    parser.add_argument("--settle-seconds", type=int, default=120)
    parser.add_argument("--timeout-seconds", type=int, default=43200)
    parser.add_argument("--expanded-timeout-seconds", type=int, default=86400)
    parser.add_argument("--supervisor-poll-seconds", type=int, default=15)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    children: list[subprocess.Popen[str]] = []
    try:
        for watch_root_text in args.watch_roots:
            watch_root = Path(watch_root_text).resolve()
            monitor_root = watch_root / "_monitor"
            state_path = monitor_root / "state.json"
            total = project_total(watch_root, args.settle_seconds)
            print(f"[sequence] start {watch_root} total_projects={total}", flush=True)
            child = start_child(args, watch_root)
            children.append(child)
            while True:
                time.sleep(args.supervisor_poll_seconds)
                current_total = project_total(watch_root, args.settle_seconds) or total
                done = completed_total(state_path)
                print(
                    f"[sequence] watch_root={watch_root} completed={done}/{current_total} child_alive={child.poll() is None}",
                    flush=True,
                )
                if done >= current_total and current_total > 0:
                    stop_child(child)
                    print(f"[sequence] completed {watch_root}", flush=True)
                    break
                if child.poll() is not None:
                    print(f"[sequence] child exited early for {watch_root}, restarting", flush=True)
                    child = start_child(args, watch_root)
                    children.append(child)
        return 0
    finally:
        for child in children:
            if child.poll() is None:
                stop_child(child)


if __name__ == "__main__":
    raise SystemExit(main())
