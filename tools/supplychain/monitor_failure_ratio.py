#!/usr/bin/env python3
import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone


def _load_entries(run_root: str):
    for name in ("summary.partial.json", "summary.json"):
        path = os.path.join(run_root, name)
        if os.path.exists(path):
            with open(path, "r") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                return data, path
    return [], ""


def _count(entries):
    total = len(entries)
    failed = sum(1 for x in entries if x.get("status") == "analysis_failed")
    return total, failed


def _is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _terminate_tree(root_pid: int):
    try:
        out = subprocess.check_output(["pgrep", "-P", str(root_pid)], text=True)
        children = [int(line.strip()) for line in out.splitlines() if line.strip()]
    except subprocess.CalledProcessError:
        children = []

    for pid in children:
        _terminate_tree(pid)

    try:
        os.kill(root_pid, signal.SIGTERM)
    except ProcessLookupError:
        return


def _log(msg: str, log_path: str):
    line = f"[{datetime.now(timezone.utc).isoformat()}] {msg}"
    print(line, flush=True)
    with open(log_path, "a") as fh:
        fh.write(line + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-root", required=True)
    ap.add_argument("--pid", required=True, type=int)
    ap.add_argument("--threshold", type=float, default=0.60)
    ap.add_argument("--min-completed", type=int, default=20)
    ap.add_argument("--poll-seconds", type=float, default=30.0)
    ap.add_argument("--log-path", required=True)
    args = ap.parse_args()

    _log(
        f"monitor start pid={args.pid} run_root={args.run_root} "
        f"threshold={args.threshold:.2f} min_completed={args.min_completed}",
        args.log_path,
    )

    while True:
        alive = _is_alive(args.pid)
        entries, source = _load_entries(args.run_root)
        completed, failed = _count(entries)
        ratio = (failed / completed) if completed else 0.0
        _log(
            f"heartbeat alive={alive} completed={completed} failed={failed} "
            f"ratio={ratio:.3f} source={source or '-'}",
            args.log_path,
        )

        if completed >= args.min_completed and ratio > args.threshold:
            _log(
                f"threshold exceeded, terminating pid={args.pid} "
                f"completed={completed} failed={failed} ratio={ratio:.3f}",
                args.log_path,
            )
            _terminate_tree(args.pid)
            return 2

        if not alive:
            _log("root process exited; monitor stop", args.log_path)
            return 0

        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    sys.exit(main())
