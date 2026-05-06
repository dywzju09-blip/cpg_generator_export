#!/usr/bin/env python3
"""
Run external baseline scanners (cargo-audit / osv-scanner) for a batch manifest.

Outputs under <output-root>/<run-name>:
- summary.json: per-case metrics (wall_time_sec, peak_rss_kb, avg_rss_kb, timed_out)
- runs/<case_id>/{stdout.log,stderr.log,tool_output.json}
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any


CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent.parent
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "output" / "vulnerability_runs"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _read_process_rss_kb(pid: int) -> int:
    status_path = Path(f"/proc/{int(pid)}/status")
    try:
        with status_path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if not line.startswith("VmRSS:"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    return int(parts[1])
    except Exception:
        return 0
    return 0


def _child_pids_recursive(root_pid: int) -> list[int]:
    root_pid = int(root_pid)
    pending = [root_pid]
    seen = {root_pid}
    children: list[int] = []
    while pending:
        current = pending.pop()
        child_path = Path(f"/proc/{current}/task/{current}/children")
        try:
            raw = child_path.read_text(encoding="utf-8", errors="ignore").strip()
        except Exception:
            continue
        for token in raw.split():
            try:
                child_pid = int(token)
            except ValueError:
                continue
            if child_pid in seen:
                continue
            seen.add(child_pid)
            children.append(child_pid)
            pending.append(child_pid)
    return children


def _process_tree_rss_kb(root_pid: int) -> int:
    rss_total = 0
    for pid in [int(root_pid)] + _child_pids_recursive(int(root_pid)):
        rss_total += max(0, _read_process_rss_kb(pid))
    return rss_total


class ProcessTreeRSSMonitor:
    def __init__(self, root_pid: int, sample_interval_sec: float = 0.2):
        self.root_pid = int(root_pid)
        self.sample_interval_sec = max(float(sample_interval_sec), 0.05)
        self.samples: list[int] = []

    def sample_once(self) -> None:
        self.samples.append(_process_tree_rss_kb(self.root_pid))

    def run_until_done(self, proc: subprocess.Popen[Any], *, timeout_sec: float | None) -> tuple[bool, float]:
        start = time.time()
        timed_out = False
        while True:
            self.sample_once()
            if proc.poll() is not None:
                break
            if timeout_sec is not None and (time.time() - start) >= float(timeout_sec):
                timed_out = True
                break
            time.sleep(self.sample_interval_sec)
        return timed_out, time.time() - start

    def summary(self) -> dict[str, int]:
        if not self.samples:
            return {"peak_rss_kb": 0, "avg_rss_kb": 0}
        return {
            "peak_rss_kb": int(max(self.samples)),
            "avg_rss_kb": int(round(sum(self.samples) / len(self.samples))),
        }


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def normalize_items(payload: Any) -> list[dict[str, Any]]:
    items = payload.get("items", payload) if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        raise ValueError("manifest must be a list or an object with an items array")
    normalized: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        normalized.append(dict(item))
    return normalized


def cargo_lock_path(project_dir: Path) -> Path:
    lock_path = project_dir / "Cargo.lock"
    if not lock_path.exists():
        raise FileNotFoundError(f"Cargo.lock not found under: {project_dir}")
    return lock_path


def build_command(method: str, *, project_dir: Path, out_dir: Path) -> tuple[list[str], Path | None]:
    lock_path = cargo_lock_path(project_dir)
    if method == "cargo-audit":
        return (
            ["cargo", "audit", "--no-fetch", "--file", str(lock_path), "--json"],
            None,
        )
    if method == "osv-scanner":
        tool_output = out_dir / "tool_output.json"
        return (
            [
                "osv-scanner",
                "scan",
                "-L",
                str(lock_path),
                "-f",
                "json",
                "--output",
                str(tool_output),
            ],
            tool_output,
        )
    raise ValueError(f"unsupported method: {method}")


def run_one_case(
    *,
    method: str,
    case_id: str,
    project_dir: Path,
    run_root: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    case_dir = run_root / "runs" / case_id
    ensure_dir(case_dir)
    stdout_path = case_dir / "stdout.log"
    stderr_path = case_dir / "stderr.log"
    cmd, tool_output_path = build_command(method, project_dir=project_dir, out_dir=case_dir)

    start = time.time()
    proc: subprocess.Popen[Any]
    with stdout_path.open("w", encoding="utf-8") as stdout_fh, stderr_path.open("w", encoding="utf-8") as stderr_fh:
        proc = subprocess.Popen(
            cmd,
            cwd=str(project_dir),
            stdout=stdout_fh,
            stderr=stderr_fh,
            text=True,
        )
        monitor = ProcessTreeRSSMonitor(proc.pid)
        timed_out, _ = monitor.run_until_done(proc, timeout_sec=timeout_seconds if timeout_seconds > 0 else None)
        exit_code = proc.poll()
        if timed_out:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except Exception:
                    pass
                proc.wait(timeout=10)
            exit_code = proc.returncode if proc.returncode is not None else -15
            stderr_fh.write(f"\nTimed out after {timeout_seconds} seconds.\n")
        else:
            proc.wait(timeout=10)
            exit_code = proc.returncode if proc.returncode is not None else (exit_code or 0)

    wall_time_sec = round(time.time() - start, 3)
    rss = monitor.summary()

    record = {
        "case_id": case_id,
        "method": method,
        "project_dir": str(project_dir),
        "command": " ".join(cmd),
        "cwd": str(project_dir),
        "exit_code": int(exit_code or 0),
        "wall_time_sec": float(wall_time_sec),
        "peak_rss_kb": int(rss.get("peak_rss_kb") or 0),
        "avg_rss_kb": int(rss.get("avg_rss_kb") or 0),
        "timed_out": bool(timed_out),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "tool_output_path": str(tool_output_path) if tool_output_path else "",
    }
    write_json(case_dir / "result.json", record)
    return record


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="Manifest JSON with at least case_id + project_dir")
    parser.add_argument("--method", required=True, choices=["cargo-audit", "osv-scanner"], help="External tool to run")
    parser.add_argument("--run-name", required=True, help="Run name under output/vulnerability_runs/<run-name>")
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT), help="Base directory for run output")
    parser.add_argument("--timeout-seconds", type=int, default=900, help="Per-case timeout in seconds")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest_path = Path(args.manifest).resolve()
    output_root = Path(args.output_root).resolve()
    run_root = output_root / args.run_name
    if run_root.exists():
        # Keep behavior consistent with run_manifest_analysis: overwrite run directory.
        shutil.rmtree(run_root)
    ensure_dir(run_root)

    items = normalize_items(load_json(manifest_path))
    entries: list[dict[str, Any]] = []
    total = len(items)
    for idx, item in enumerate(items, start=1):
        case_id = str(item.get("case_id") or "").strip()
        project_dir_text = str(item.get("project_dir") or "").strip()
        if not case_id or not project_dir_text:
            raise ValueError("manifest items must include case_id and project_dir")
        project_dir = Path(os.path.expandvars(os.path.expanduser(project_dir_text))).resolve()
        print(f"[{idx}/{total}] {args.method} {case_id}", flush=True)
        entry = run_one_case(
            method=args.method,
            case_id=case_id,
            project_dir=project_dir,
            run_root=run_root,
            timeout_seconds=int(args.timeout_seconds),
        )
        entries.append(entry)

    write_json(run_root / "summary.json", entries)
    write_json(run_root / "summary_seed.json", {"manifest": str(manifest_path), "count": len(entries), "method": args.method})
    print(f"[+] External baseline summary written to {run_root / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
