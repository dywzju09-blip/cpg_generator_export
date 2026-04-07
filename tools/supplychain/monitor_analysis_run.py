#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ENV_RULES = [
    {
        "patterns": [r"\bcmake\b", r"cmake: command not found"],
        "packages": ["cmake"],
        "reason": "cmake missing",
    },
    {
        "patterns": [r"\bpkg-config\b", r"pkg_config", r"pkg-config.*not found"],
        "packages": ["pkg-config"],
        "reason": "pkg-config missing",
    },
    {
        "patterns": [r"clang-sys", r"libclang", r"bindgen"],
        "packages": ["clang", "libclang-dev"],
        "reason": "clang/libclang missing",
    },
    {
        "patterns": [r"openssl-sys", r"openssl/ssl\.h", r"openssl/opensslv\.h", r"OpenSSL .* not found"],
        "packages": ["libssl-dev", "pkg-config"],
        "reason": "OpenSSL headers/libs missing",
    },
    {
        "patterns": [r"libxml/tree\.h", r"xml2-config", r"libxml-2\.0", r"\blibxml2\b"],
        "packages": ["libxml2-dev", "pkg-config"],
        "reason": "libxml2 headers/libs missing",
    },
    {
        "patterns": [r"sqlite3\.h", r"libsqlite3-sys", r"\bsqlite3\b"],
        "packages": ["libsqlite3-dev", "sqlite3", "pkg-config"],
        "reason": "SQLite headers/libs missing",
    },
    {
        "patterns": [r"zlib\.h", r"libz-sys", r"\bzlib\b.*not found"],
        "packages": ["zlib1g-dev"],
        "reason": "zlib headers/libs missing",
    },
    {
        "patterns": [r"curl/curl\.h", r"libcurl-sys", r"\blibcurl\b.*not found"],
        "packages": ["libcurl4-openssl-dev", "pkg-config"],
        "reason": "libcurl headers/libs missing",
    },
    {
        "patterns": [r"libgit2", r"git2\.h", r"libgit2-sys"],
        "packages": ["libgit2-dev", "pkg-config"],
        "reason": "libgit2 headers/libs missing",
    },
    {
        "patterns": [r"libssh2", r"libssh2\.h", r"libssh2-sys"],
        "packages": ["libssh2-1-dev", "pkg-config"],
        "reason": "libssh2 headers/libs missing",
    },
    {
        "patterns": [r"bzlib\.h", r"\bbzip2\b.*not found", r"bzip2-sys"],
        "packages": ["libbz2-dev"],
        "reason": "bzip2 headers/libs missing",
    },
    {
        "patterns": [r"expat\.h", r"\bexpat\b.*not found", r"expat-sys", r"libexpat"],
        "packages": ["libexpat1-dev"],
        "reason": "Expat headers/libs missing",
    },
    {
        "patterns": [r"\bpcre2\.h\b", r"\blibpcre2\b", r"\bpcre2-sys\b", r"\bpcre2\b.*not found"],
        "packages": ["libpcre2-dev", "pkg-config"],
        "reason": "PCRE2 headers/libs missing",
    },
    {
        "patterns": [r"\barchive\.h\b", r"\blibarchive\b", r"\blibarchive3-sys\b", r"\barchive_read_"],
        "packages": ["libarchive-dev", "pkg-config"],
        "reason": "libarchive headers/libs missing",
    },
    {
        "patterns": [r"\bcodec_api\.h\b", r"\bopenh264\b", r"\bopenh264-sys2?\b", r"\bWels"],
        "packages": ["libopenh264-dev", "pkg-config"],
        "reason": "OpenH264 headers/libs missing",
    },
    {
        "patterns": [r"\bgdal\.h\b", r"\bgdal-config\b", r"\bgdal-sys\b", r"\blibgdal\b"],
        "packages": ["libgdal-dev", "gdal-bin", "pkg-config"],
        "reason": "GDAL headers/libs missing",
    },
    {
        "patterns": [r"\blibheif/heif\.h\b", r"\blibheif\.pc\b", r"\blibheif-sys\b", r"library 'heif' not found"],
        "packages": ["libheif-dev", "pkg-config"],
        "reason": "libheif headers/libs missing",
    },
    {
        "patterns": [r"\bwebp/decode\.h\b", r"\blibwebp\.pc\b", r"\blibwebp-sys\b", r"\blibwebp\b"],
        "packages": ["libwebp-dev", "pkg-config"],
        "reason": "libwebp headers/libs missing",
    },
    {
        "patterns": [r"\bft2build\.h\b", r"\bfreetype\b", r"\bfreetype-sys\b"],
        "packages": ["libfreetype6-dev", "pkg-config"],
        "reason": "FreeType headers/libs missing",
    },
    {
        "patterns": [r"\bxmlsec1-config\b", r"\bxmlsec1\b", r"\blibxmlsec1\b"],
        "packages": ["libxmlsec1-dev", "pkg-config"],
        "reason": "xmlsec headers/libs missing",
    },
]


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


def run(cmd: list[str]) -> tuple[int, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def process_alive(pid: int | None) -> bool:
    if not pid:
        return False
    return Path(f"/proc/{pid}").exists()


def read_pid(pid_path: Path) -> int | None:
    if not pid_path.exists():
        return None
    try:
        return int(pid_path.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def scan_logs(run_root: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if not run_root.exists():
        return findings
    for log_path in sorted(run_root.glob("*/run.log")):
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        findings.append({"path": str(log_path), "text": text})
    return findings


def infer_packages(findings: list[dict[str, str]], already_installed: set[str]) -> tuple[list[str], list[str]]:
    wanted: list[str] = []
    reasons: list[str] = []
    for finding in findings:
        text = finding["text"]
        for rule in ENV_RULES:
            if any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in rule["patterns"]):
                reasons.append(f"{rule['reason']} from {finding['path']}")
                for package in rule["packages"]:
                    if package not in already_installed and package not in wanted:
                        wanted.append(package)
    return wanted, reasons


def dpkg_installed(package: str) -> bool:
    code, _ = run(["dpkg", "-s", package])
    return code == 0


def apt_install(packages: list[str]) -> list[str]:
    installed_now: list[str] = []
    missing = [pkg for pkg in packages if not dpkg_installed(pkg)]
    if not missing:
        return installed_now
    run(["apt-get", "update"])
    code, output = run(["apt-get", "install", "-y", *missing])
    if code == 0:
        installed_now.extend(missing)
    else:
        installed_now.append(f"apt-install-failed: {','.join(missing)}")
        log_path = Path("/root/VUL/2026.3.22/monitor_hourly_install_errors.log")
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(f"\n[{datetime.now(timezone.utc).isoformat()}]\n{output}\n")
    return installed_now


def summarize(summary_partial_path: Path) -> tuple[list[dict[str, Any]], Counter]:
    entries = load_json(summary_partial_path, [])
    counts: Counter = Counter(entry.get("status") for entry in entries)
    return entries, counts


def build_report(
    *,
    run_name: str,
    pid: int | None,
    alive: bool,
    entries: list[dict[str, Any]],
    counts: Counter,
    new_entries: list[dict[str, Any]],
    install_actions: list[str],
    install_reasons: list[str],
    archive_root: Path,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"# Monitor Report: {run_name}",
        "",
        f"- checked_at: `{now}`",
        f"- pid: `{pid or 'unknown'}`",
        f"- process_alive: `{alive}`",
        f"- completed: `{len(entries)}`",
        "",
        "## Status Counts",
        "",
    ]
    for key in sorted(counts):
        lines.append(f"- `{key}`: {counts[key]}")
    if entries:
        last = entries[-1]
        lines.extend(
            [
                "",
                "## Last Completed",
                "",
                f"- project: `{last.get('project')}`",
                f"- status: `{last.get('status')}`",
                f"- seconds: `{last.get('seconds')}`",
                f"- log: `{last.get('log')}`",
            ]
        )
    lines.extend(["", "## New Since Last Check", ""])
    if new_entries:
        for entry in new_entries[-10:]:
            lines.append(f"- `{entry.get('project')}` -> `{entry.get('status')}` in `{entry.get('seconds')}` seconds")
    else:
        lines.append("- none")
    lines.extend(["", "## Environment Actions", ""])
    if install_actions:
        for item in install_actions:
            lines.append(f"- {item}")
    else:
        lines.append("- none")
    if install_reasons:
        lines.extend(["", "## Environment Reasons", ""])
        for reason in install_reasons[:20]:
            lines.append(f"- {reason}")
    if archive_root.exists():
        case_json_count = len(list(archive_root.rglob("case.json")))
        lines.extend(["", "## Archive", "", f"- case_json_count: `{case_json_count}`"])
    return "\n".join(lines) + "\n"


def monitor_once(args: argparse.Namespace) -> None:
    run_root = Path(args.run_root)
    summary_partial_path = run_root / "summary.partial.json"
    state_path = Path(args.state_file)
    report_path = Path(args.report_file)
    pid_path = Path(args.pid_file)
    archive_root = Path(args.archive_root)

    state = load_json(
        state_path,
        {
            "seen_logs": [],
            "seen_projects": [],
            "installed_packages": [],
            "history": [],
        },
    )
    entries, counts = summarize(summary_partial_path)
    seen_projects = set(state.get("seen_projects", []))
    new_entries = [entry for entry in entries if entry.get("project") not in seen_projects]

    findings = scan_logs(run_root)
    installed_packages = set(state.get("installed_packages", []))
    wanted_packages, reasons = infer_packages(findings, installed_packages)
    install_actions: list[str] = []
    if wanted_packages:
        installed_now = apt_install(wanted_packages)
        for item in installed_now:
            install_actions.append(f"installed `{item}`")
            if not item.startswith("apt-install-failed:"):
                installed_packages.add(item)

    pid = read_pid(pid_path)
    alive = process_alive(pid)

    report = build_report(
        run_name=args.run_name,
        pid=pid,
        alive=alive,
        entries=entries,
        counts=counts,
        new_entries=new_entries,
        install_actions=install_actions,
        install_reasons=reasons,
        archive_root=archive_root,
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")

    state["seen_projects"] = [entry.get("project") for entry in entries]
    state["installed_packages"] = sorted(installed_packages)
    state.setdefault("history", []).append(
        {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "completed": len(entries),
            "status_counts": dict(counts),
            "new_projects": [entry.get("project") for entry in new_entries],
            "install_actions": install_actions,
        }
    )
    state["history"] = state["history"][-200:]
    write_json(state_path, state)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-name", required=True)
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--archive-root", required=True)
    parser.add_argument("--pid-file", required=True)
    parser.add_argument("--state-file", required=True)
    parser.add_argument("--report-file", required=True)
    parser.add_argument("--interval-seconds", type=int, default=3600)
    parser.add_argument("--once", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    while True:
        monitor_once(args)
        if args.once:
            return 0
        time.sleep(args.interval_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
