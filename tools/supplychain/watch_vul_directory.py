#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import tomllib


CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent.parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from archive_analysis_run import archive_run
from auto_vuln_inputs import can_auto_generate, generate_extras_payload, generate_vulns_payload
from monitor_analysis_run import ENV_RULES, apt_install
from run_manifest_analysis import ensure_dir, normalize_item, run_one, write_json, write_run_summary
from tools.common.path_defaults import infer_archive_root


FAMILY_ALIASES = {
    "sqlite": "sqlite",
    "sqlite3": "sqlite",
    "libsqlite3": "sqlite",
    "openssl": "openssl",
    "libssl": "openssl",
    "libxml2": "libxml2",
    "xml2": "libxml2",
    "libwebp": "libwebp",
    "webp": "libwebp",
    "libheif": "libheif",
    "heif": "libheif",
    "gdal": "gdal",
    "openh264": "openh264",
    "open_h264": "openh264",
    "freetype": "freetype",
    "libgit2": "libgit2",
    "git2": "libgit2",
    "zlib": "zlib",
    "libz": "zlib",
    "pcre2": "pcre2",
    "expat": "expat",
    "libpng": "libpng",
    "gstreamer": "gstreamer",
}

FAMILY_TO_CVE = {
    "openssl": "CVE-2022-3602",
    "zlib": "CVE-2022-37434",
    "sqlite": "CVE-2022-35737",
    "libgit2": "CVE-2024-24575",
    "pcre2": "CVE-2022-1586",
    "libxml2": "CVE-2025-6021",
    "libwebp": "CVE-2023-4863",
    "libheif": "CVE-2025-68431",
    "gdal": "CVE-2021-45943",
    "openh264": "CVE-2025-27091",
    "freetype": "CVE-2025-27363",
    "gstreamer": "CVE-2024-0444",
    "libjpeg-turbo": "CVE-2024-1159",
}

FAMILY_PRIORITY = [
    "openh264",
    "libheif",
    "libwebp",
    "libjpeg-turbo",
    "gdal",
    "gstreamer",
    "pcre2",
    "libxml2",
    "libgit2",
    "sqlite",
    "freetype",
    "openssl",
    "zlib",
]

FAMILY_PATTERNS = {
    "openssl": {"openssl", "native-tls", "tokio-openssl", "openssl-sys"},
    "zlib": {"libz-sys", "zlib", "flate2", "miniz_oxide"},
    "sqlite": {"sqlite", "sqlite3", "libsqlite3-sys", "rusqlite"},
    "libgit2": {"git2", "libgit2-sys", "libgit2"},
    "pcre2": {"pcre2", "pcre2-sys", "grep-pcre2"},
    "libxml2": {"libxml", "libxml2", "libxml2-sys", "libxslt", "xmlsec"},
    "libwebp": {"webp", "libwebp", "libwebp-sys"},
    "libheif": {"heif", "libheif", "libheif-rs", "libheif-sys"},
    "gdal": {"gdal", "gdal-sys"},
    "openh264": {"openh264", "openh264-sys", "openh264-sys2"},
    "freetype": {"freetype", "freetype-rs", "freetype-sys"},
    "gstreamer": {"gstreamer", "gstreamer-sys"},
    "libjpeg-turbo": {"jpeg-decoder", "turbojpeg", "mozjpeg", "zune-jpeg", "libjpeg-turbo"},
}


EXTRA_ENV_RULES = [
    {
        "patterns": [r"\bgdal\.h\b", r"\bgdal-config\b", r"\bgdal-sys\b", r"\blibgdal\b"],
        "packages": ["libgdal-dev", "gdal-bin", "pkg-config"],
    },
    {
        "patterns": [r"\blibheif/heif\.h\b", r"\blibheif\.pc\b", r"\blibheif-sys\b", r"library 'heif' not found"],
        "packages": ["libheif-dev", "pkg-config"],
    },
    {
        "patterns": [r"\bwebp/decode\.h\b", r"\blibwebp\.pc\b", r"\blibwebp-sys\b", r"\blibwebp\b"],
        "packages": ["libwebp-dev", "pkg-config"],
    },
    {
        "patterns": [r"\bft2build\.h\b", r"\bfreetype\b", r"\bfreetype-sys\b"],
        "packages": ["libfreetype6-dev", "pkg-config"],
    },
    {
        "patterns": [r"\bxmlsec1-config\b", r"\bxmlsec1\b", r"\blibxmlsec1\b"],
        "packages": ["libxmlsec1-dev", "pkg-config"],
    },
    {
        "patterns": [r"\bMagickWand\b", r"\bmagickwand\b"],
        "packages": ["libmagickwand-dev", "pkg-config"],
    },
]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_log(path: Path, message: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(f"[{utc_now()}] {message}\n")


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def sanitize_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()) or "unknown"


def sanitize_component(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    return FAMILY_ALIASES.get(raw, raw or "unknown")


def extract_cves(text: str) -> list[str]:
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", str(text or "").upper())))


def latest_mtime(path: Path) -> float:
    newest = path.stat().st_mtime
    for child in path.rglob("*"):
        try:
            child_mtime = child.stat().st_mtime
        except FileNotFoundError:
            continue
        if child_mtime > newest:
            newest = child_mtime
    return newest


def cargo_root_for(project_dir: Path) -> Path | None:
    upstream = project_dir / "upstream"
    if (upstream / "Cargo.toml").exists():
        return upstream
    if (project_dir / "Cargo.toml").exists():
        return project_dir
    return None


def split_feature_token(token: str) -> set[str]:
    parts = re.split(r"[/?:,_-]", token.lower())
    return {part for part in parts if part}


def collect_manifest_tokens(table: object, out: set[str]) -> None:
    if not isinstance(table, dict):
        return
    for key, value in table.items():
        if key in {"dependencies", "dev-dependencies", "build-dependencies"} and isinstance(value, dict):
            for dep_name, spec in value.items():
                out.add(str(dep_name).lower())
                if isinstance(spec, dict):
                    package = spec.get("package")
                    if isinstance(package, str):
                        out.add(package.lower())
                    features = spec.get("features")
                    if isinstance(features, list):
                        for feature in features:
                            if isinstance(feature, str):
                                out.update(split_feature_token(feature))
        elif key == "features" and isinstance(value, dict):
            for feature_values in value.values():
                if isinstance(feature_values, list):
                    for feature in feature_values:
                        if isinstance(feature, str):
                            out.update(split_feature_token(feature))
        elif key == "target" and isinstance(value, dict):
            for nested in value.values():
                collect_manifest_tokens(nested, out)


def detect_families_from_manifest(cargo_toml: Path) -> list[str]:
    data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
    tokens: set[str] = set()
    collect_manifest_tokens(data, tokens)
    matched = []
    for family in FAMILY_PRIORITY:
        if tokens & FAMILY_PATTERNS[family]:
            matched.append(family)
    return matched


def materialize_rule_docs(project_dir: Path, item: dict[str, Any]) -> dict[str, Any]:
    if not can_auto_generate(item):
        return item
    rule_root = project_dir / "analysis_rules" / item["cve_dir"]
    rule_root.mkdir(parents=True, exist_ok=True)
    vulns_path = rule_root / "vulns.json"
    extras_path = rule_root / "extras.json"
    write_json(vulns_path, generate_vulns_payload(item))
    write_json(extras_path, generate_extras_payload(item))
    enriched = dict(item)
    enriched["vulns"] = str(vulns_path.resolve())
    enriched["extras"] = str(extras_path.resolve())
    enriched["source_label"] = f"{item.get('source_label') or 'auto'}+materialized_rule"
    return enriched


def is_stable_project(project_dir: Path, settle_seconds: int) -> bool:
    cargo_root = cargo_root_for(project_dir)
    if not cargo_root:
        return False
    cargo_toml = cargo_root / "Cargo.toml"
    try:
        newest = latest_mtime(project_dir)
    except FileNotFoundError:
        return False
    return (time.time() - newest) >= settle_seconds


def discover_projects(watch_root: Path, settle_seconds: int) -> list[Path]:
    if not watch_root.exists():
        return []
    candidates: list[Path] = []
    seen: set[Path] = set()
    for pattern in ["*/*/upstream/Cargo.toml", "projects/*/Cargo.toml", "*/*/Cargo.toml"]:
        for cargo_toml in sorted(watch_root.glob(pattern)):
            project_dir = cargo_toml.parent.parent if cargo_toml.parent.name == "upstream" else cargo_toml.parent
            resolved = project_dir.resolve()
            if resolved in seen:
                continue
            if is_stable_project(resolved, settle_seconds):
                candidates.append(resolved)
                seen.add(resolved)
    return candidates


def candidate_files_for(project_dir: Path) -> list[Path]:
    date_dir = project_dir.parent
    return sorted(date_dir.glob("candidates*.json"))


def local_source_matches(candidate_source: str, project_dir: Path) -> bool:
    cargo_root = cargo_root_for(project_dir)
    if not cargo_root:
        return False
    try:
        candidate_path = Path(candidate_source).resolve()
    except Exception:
        return False
    return candidate_path == cargo_root.resolve()


def project_rel(vul_root: Path, project_dir: Path) -> str:
    cargo_root = cargo_root_for(project_dir)
    if not cargo_root:
        cargo_root = project_dir / "upstream"
    return str(cargo_root.resolve().relative_to(vul_root.resolve()))


def load_candidate_items(project_dir: Path) -> list[dict[str, Any]]:
    matched: list[dict[str, Any]] = []
    for path in candidate_files_for(project_dir):
        payload = load_json(path, {})
        for item in payload.get("candidates", []):
            if local_source_matches(item.get("local_source", ""), project_dir):
                enriched = dict(item)
                enriched["_candidate_file"] = str(path)
                matched.append(enriched)
    return matched


def derive_items_from_candidates(vul_root: Path, project_dir: Path) -> list[dict[str, Any]]:
    matched = load_candidate_items(project_dir)
    if not matched:
        return []
    rel = project_rel(vul_root, project_dir)
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for candidate in matched:
        component = sanitize_component(candidate.get("component"))
        cve_texts = [
            candidate.get("cve"),
            (candidate.get("resolution") or {}).get("cve"),
        ]
        cves: list[str] = []
        for text in cve_texts:
            cves.extend(extract_cves(str(text or "")))
        if not cves:
            continue
        for cve in cves:
            key = (cve, component)
            if key in seen:
                continue
            seen.add(key)
            sink = candidate.get("sink") or {}
            cpg_input = ""
            sink_file = str(sink.get("file") or "").strip()
            cargo_root = cargo_root_for(project_dir)
            if sink_file:
                candidate_input = (cargo_root or (project_dir / "upstream")) / sink_file
                if candidate_input.exists():
                    cpg_input = str(candidate_input.resolve())
            features = candidate.get("features") or []
            items.append(
                {
                    "rel": rel,
                    "project_dir": str((cargo_root or (project_dir / "upstream")).resolve()),
                    "project": str(candidate.get("crate") or project_dir.name),
                    "version": str(candidate.get("version") or ""),
                    "source_label": f"candidate_file:{Path(candidate['_candidate_file']).name}",
                    "family": component,
                    "component": component,
                    "cve": cve,
                    "cve_dir": f"{cve}__{component}",
                    "cpg_input": cpg_input or None,
                    "cargo_features": ",".join(features) if isinstance(features, list) and features else "",
                    "dependency_evidence": [
                        str(candidate.get("dependency_chain") or ""),
                        str(candidate.get("trigger") or ""),
                    ],
                }
            )
    return items


def derive_items_from_cargo(vul_root: Path, project_dir: Path) -> list[dict[str, Any]]:
    cargo_root = cargo_root_for(project_dir)
    cargo_toml = (cargo_root / "Cargo.toml") if cargo_root else (project_dir / "upstream" / "Cargo.toml")
    matches = [(family, FAMILY_TO_CVE[family]) for family in detect_families_from_manifest(cargo_toml)]
    if not matches:
        return [
            {
                "rel": project_rel(vul_root, project_dir),
                "project_dir": str((cargo_root or (project_dir / "upstream")).resolve()),
                "project": project_dir.name,
                "version": "",
                "source_label": "cargo_toml_scan",
                "family": "unknown",
                "component": "unknown",
                "cve": "UNKNOWN-CVE",
                "cve_dir": "UNKNOWN-CVE__unknown",
                "skip_reason": "error: could not derive a supported target vulnerability family from Cargo.toml or candidates metadata",
            }
        ]
    items = []
    for family, cve in matches[:1]:
        items.append(
            {
                "rel": project_rel(vul_root, project_dir),
                "project_dir": str((cargo_root or (project_dir / "upstream")).resolve()),
                "project": project_dir.name,
                "version": "",
                "source_label": "cargo_toml_scan",
                "family": family,
                "component": family,
                "cve": cve,
                "cve_dir": f"{cve}__{family}",
            }
        )
    return items


def build_manifest_items(vul_root: Path, project_dir: Path) -> list[dict[str, Any]]:
    items = derive_items_from_candidates(vul_root, project_dir)
    if items:
        return [materialize_rule_docs(project_dir, item) for item in items]
    return [materialize_rule_docs(project_dir, item) for item in derive_items_from_cargo(vul_root, project_dir)]


def configure_analysis_env() -> None:
    os.environ.setdefault("SUPPLYCHAIN_VUL_ROOT", "/root/VUL")
    os.environ.setdefault("SUPPLYCHAIN_ARCHIVE_ROOT", "/root/VUL/cases/by-analysis-status")
    os.environ.setdefault("JOERN_PARSE_JAVA_TOOL_OPTIONS", "-Xms4g -Xmx32g -XX:+UseG1GC")
    os.environ.setdefault("JOERN_EXPORT_JAVA_TOOL_OPTIONS", "-Xms8g -Xmx96g -XX:+UseG1GC")
    os.environ.setdefault("JAVA_OPTS", "-Xms4g -Xmx32g -XX:+UseG1GC")


def merged_env_rules() -> list[dict[str, Any]]:
    return list(ENV_RULES) + EXTRA_ENV_RULES


def infer_packages_from_log(log_text: str) -> list[str]:
    wanted: list[str] = []
    for rule in merged_env_rules():
        if any(re.search(pattern, log_text, flags=re.IGNORECASE) for pattern in rule["patterns"]):
            for package in rule["packages"]:
                if package not in wanted:
                    wanted.append(package)
    return wanted


def run_single_attempt(
    item: dict[str, Any],
    *,
    run_name: str,
    timeout_seconds: int,
    output_root: Path,
) -> tuple[dict[str, Any], Path]:
    run_root = output_root / run_name
    if run_root.exists():
        shutil.rmtree(run_root)
    ensure_dir(run_root)
    normalized = normalize_item(item)
    entry = run_one(normalized, run_root, timeout_seconds)
    write_run_summary(run_root, run_root / "manifest.synthetic.json", [entry])
    return entry, run_root


def finalize_run(run_root: Path, archive_root: Path) -> None:
    archive_run(run_root, archive_root)


def cleanup_run(run_root: Path) -> None:
    if run_root.exists():
        shutil.rmtree(run_root)


def analyze_project(
    project_dir: Path,
    items: list[dict[str, Any]],
    *,
    archive_root: Path,
    output_root: Path,
    base_timeout: int,
    expanded_timeout: int,
    monitor_log: Path,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in items:
        rel_slug = sanitize_name(item["rel"].replace("/", "__"))
        run_base = f"watch_326__{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}__{rel_slug}__{sanitize_name(item['cve_dir'])}"
        append_log(monitor_log, f"start analysis project={item['project_dir']} cve_dir={item['cve_dir']}")
        entry, run_root = run_single_attempt(
            item,
            run_name=run_base,
            timeout_seconds=base_timeout,
            output_root=output_root,
        )
        retry_reason = None
        if entry["status"] == "analysis_failed":
            log_text = Path(entry["log"]).read_text(encoding="utf-8", errors="ignore")
            packages = infer_packages_from_log(log_text)
            if packages:
                installed = apt_install(packages)
                retry_reason = f"installed={installed or packages}"
                append_log(
                    monitor_log,
                    f"repair before retry project={item['project_dir']} cve_dir={item['cve_dir']} packages={installed or packages}",
                )
                cleanup_run(run_root)
                entry, run_root = run_single_attempt(
                    item,
                    run_name=f"{run_base}__retry_env",
                    timeout_seconds=base_timeout,
                    output_root=output_root,
                )
        elif entry["status"] == "analysis_timeout":
            retry_reason = f"timeout_expanded_to={expanded_timeout}"
            append_log(
                monitor_log,
                f"timeout retry project={item['project_dir']} cve_dir={item['cve_dir']} timeout={expanded_timeout}",
            )
            cleanup_run(run_root)
            entry, run_root = run_single_attempt(
                item,
                run_name=f"{run_base}__retry_timeout",
                timeout_seconds=expanded_timeout,
                output_root=output_root,
            )
        if retry_reason:
            append_log(
                monitor_log,
                f"retry finished project={item['project_dir']} cve_dir={item['cve_dir']} status={entry['status']} retry={retry_reason}",
            )
        finalize_run(run_root, archive_root)
        append_log(
            monitor_log,
            f"finalized project={item['project_dir']} cve_dir={item['cve_dir']} status={entry['status']} archive={archive_root}",
        )
        results.append(entry)
    return results


def write_status_report(status_path: Path, state: dict[str, Any]) -> None:
    lines = [
        "# Watch 326 Status",
        "",
        f"- updated_at: `{utc_now()}`",
        f"- watch_root: `{state['watch_root']}`",
        f"- processed_projects: `{len(state.get('completed', {}))}`",
        f"- queued_projects: `{len(state.get('queued', []))}`",
        "",
        "## Completed",
        "",
    ]
    completed = state.get("completed", {})
    if completed:
        for key in sorted(completed):
            item = completed[key]
            lines.append(f"- `{key}` -> `{item.get('status')}` at `{item.get('finished_at')}`")
    else:
        lines.append("- none")
    status_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Watch a VUL batch directory and auto-run supply-chain analysis.")
    parser.add_argument("--watch-root", required=True)
    parser.add_argument("--archive-root", default=str(infer_archive_root(REPO_ROOT)))
    parser.add_argument("--output-root", default=str(REPO_ROOT / "output" / "vulnerability_runs"))
    parser.add_argument("--poll-seconds", type=int, default=30)
    parser.add_argument("--settle-seconds", type=int, default=120)
    parser.add_argument("--timeout-seconds", type=int, default=43200)
    parser.add_argument("--expanded-timeout-seconds", type=int, default=86400)
    parser.add_argument("--monitor-root", default="")
    parser.add_argument("--once", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_analysis_env()

    watch_root = Path(args.watch_root).resolve()
    vul_root = watch_root.parent.resolve()
    archive_root = Path(args.archive_root).resolve()
    output_root = Path(args.output_root).resolve()
    monitor_root = Path(args.monitor_root).resolve() if args.monitor_root else (watch_root / "_monitor")
    state_path = monitor_root / "state.json"
    monitor_log = monitor_root / "watch.log"
    status_path = monitor_root / "status.md"
    pid_path = monitor_root / "watch.pid"

    ensure_dir(monitor_root)
    pid_path.write_text(str(os.getpid()), encoding="utf-8")

    state = load_json(
        state_path,
        {
            "watch_root": str(watch_root),
            "queued": [],
            "completed": {},
        },
    )

    while True:
        state["watch_root"] = str(watch_root)
        projects = discover_projects(watch_root, args.settle_seconds)
        project_keys = [str(project.resolve()) for project in projects]
        state["queued"] = project_keys

        for project_key in project_keys:
            if project_key in state.get("completed", {}):
                continue
            project_dir = Path(project_key)
            append_log(monitor_log, f"discovered project={project_key}")
            items = build_manifest_items(vul_root, project_dir)
            append_log(monitor_log, f"prepared manifest_items={len(items)} project={project_key}")
            results = analyze_project(
                project_dir,
                items,
                archive_root=archive_root,
                output_root=output_root,
                base_timeout=args.timeout_seconds,
                expanded_timeout=args.expanded_timeout_seconds,
                monitor_log=monitor_log,
            )
            final_status = "unknown"
            if results:
                non_skipped = [entry for entry in results if entry.get("status")]
                if non_skipped:
                    final_status = ",".join(sorted({entry["status"] for entry in non_skipped}))
            state.setdefault("completed", {})[project_key] = {
                "finished_at": utc_now(),
                "status": final_status,
                "items": [item.get("cve_dir") for item in items],
            }
            write_json(state_path, state)
            write_status_report(status_path, state)

        write_json(state_path, state)
        write_status_report(status_path, state)
        if args.once:
            return 0
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
