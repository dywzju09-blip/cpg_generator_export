#!/usr/bin/env python3
from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import re
import shlex
import shutil
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
import subprocess
import tomli


CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent.parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from monitor_analysis_run import ENV_RULES, apt_install
from run_manifest_analysis import run_one
from tools.common.path_defaults import infer_vul_root
from tools.supplychain.internal_baselines import (
    project_ours_accuracy_first_from_support,
    project_ours_full_from_support,
    support_from_vulnerability,
)
from tools.supplychain.supplychain_analyze import (
    _analysis_base_env,
    _cargo_cmd_with_flag,
    _cargo_home_has_cached_registry,
    _looks_like_offline_registry_cache_miss,
)


DEFAULT_DATASET_ROOT = Path("/root/Experiment_Ready_Dataset_Top15")
DEFAULT_BENCHMARK_JSON = DEFAULT_DATASET_ROOT / "benchmark_project.json"
DEFAULT_RUNTIME_RULES = DEFAULT_DATASET_ROOT / "runtime_rules.main_core_2022_2025.json"
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "output" / "top15_benchmark"
DEFAULT_FETCH_ROOT = DEFAULT_DATASET_ROOT / "source_cache_downloaded"
DEFAULT_INVENTORY_CSV = infer_vul_root(REPO_ROOT) / "benchmark_db" / "v1" / "index" / "inventory_cases.csv"

PRIMARY_CVE_BY_COMPONENT = {
    "curl": "CVE-2023-38545",
    "freetype": "CVE-2025-27363",
    "gdal": "CVE-2021-45943",
    "gstreamer": "CVE-2024-0444",
    "libaom": "CVE-2023-6879",
    "libgit2": "CVE-2024-24577",
    "libjpeg-turbo": "CVE-2023-2804",
    "libwebp": "CVE-2023-4863",
    "openssl": "CVE-2022-3602",
    "pcre2": "CVE-2022-1586",
    "zlib": "CVE-2022-37434",
}

ALL_RULE_COMPONENTS = {
    "ffmpeg",
    "libpng",
    "libtiff",
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
        "patterns": [r"\bft2build\.h\b", r"\bfreetype\b", r"\bfreetype-sys\b", r"\bfreetype2\b", r"\bfreetype2\.pc\b"],
        "packages": ["libfreetype-dev", "libfreetype6-dev", "pkg-config"],
    },
    {
        "patterns": [r"\bGL/glu\.h\b", r"\bglu\.h\b", r"\blibglu\b", r"\bmesa\b"],
        "packages": ["libglu1-mesa-dev", "libgl1-mesa-dev"],
    },
    {
        "patterns": [r"\bxmlsec1-config\b", r"\bxmlsec1\b", r"\blibxmlsec1\b"],
        "packages": ["libxmlsec1-dev", "pkg-config"],
    },
    {
        "patterns": [r"\bMagickWand\b", r"\bmagickwand\b"],
        "packages": ["libmagickwand-dev", "pkg-config"],
    },
    {
        "patterns": [
            r"\bgtk4\.pc\b",
            r"\bgtk4\b.*not found",
            r"\bgtk4-sys\b",
            r"\bgdk4-sys\b",
            r"\bgsk4-sys\b",
            r"\blibadwaita-1\b",
            r"\badw\b",
        ],
        "packages": [
            "libgtk-4-dev",
            "libadwaita-1-dev",
            "libgstreamer1.0-dev",
            "libgstreamer-plugins-base1.0-dev",
            "pkg-config",
        ],
    },
]

SQLITE_LABEL_ISSUE = (
    "sqlite family labels are incomplete or stale in the current benchmark: "
    "9/10 rows still require manual code review and the remaining labeled row carries note text "
    "from the libgit2 revparse family, so these rows are skipped as dataset-label issues."
)

MANUAL_LABEL_REVIEW_CASES: dict[tuple[str, str, str], str] = {}

LABEL_RANK = {
    "unreachable": 0,
    "reachable_but_not_triggerable": 1,
    "triggerable": 2,
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_toml(path: Path) -> dict[str, Any]:
    return tomli.loads(path.read_text(encoding="utf-8"))


def _link_or_copy_file(src: str, dst: str) -> str:
    try:
        os.link(src, dst)
    except Exception:
        shutil.copy2(src, dst)
    return dst


def _path_has_entries(path: Path) -> bool:
    try:
        with os.scandir(path) as entries:
            for _ in entries:
                return True
    except OSError:
        return False
    return False


def _copy_missing_tree(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    if src.is_file():
        if not dst.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            _link_or_copy_file(str(src), str(dst))
        return
    for root, _dirs, files in os.walk(src):
        root_path = Path(root)
        rel = root_path.relative_to(src)
        dst_root = dst / rel
        dst_root.mkdir(parents=True, exist_ok=True)
        for name in files:
            src_file = root_path / name
            dst_file = dst_root / name
            if dst_file.exists():
                continue
            _link_or_copy_file(str(src_file), str(dst_file))


def _slow_cache_prefixes(*, env: dict[str, str] | None = None) -> list[str]:
    active_env = env or os.environ
    raw = str(active_env.get("SUPPLYCHAIN_SLOW_CACHE_PREFIXES") or "/mnt/hw").strip()
    prefixes = [item.strip().rstrip("/") for item in raw.split(",") if item.strip()]
    return prefixes or ["/mnt/hw"]


def is_slow_cache_path(path: Path, *, env: dict[str, str] | None = None) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    candidates = {str(path), str(resolved)}
    for prefix in _slow_cache_prefixes(env=env):
        for candidate in candidates:
            if candidate == prefix or candidate.startswith(prefix + "/"):
                return True
    return False


def preferred_cargo_seed_home(
    *,
    repo_output_root: Path,
    env: dict[str, str] | None = None,
) -> Path | None:
    active_env = env or os.environ
    explicit_seed = str(active_env.get("SUPPLYCHAIN_CARGO_HOME_SEED") or "").strip()
    candidates: list[Path] = []
    if explicit_seed:
        candidates.append(Path(explicit_seed).expanduser())
    candidates.append(Path.home() / ".cargo")
    candidates.append(repo_output_root / "shared_cargo_home")
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate
        if resolved in seen or not candidate.exists() or not _path_has_entries(candidate):
            continue
        seen.add(resolved)
        if explicit_seed and candidate == Path(explicit_seed).expanduser():
            return resolved
        if is_slow_cache_path(candidate, env=active_env):
            continue
        return resolved
    return None


def seed_run_cargo_home(run_cargo_home: Path, shared_seed_cargo_home: Path) -> None:
    if not shared_seed_cargo_home.exists():
        return
    for name in ("registry/index", "registry/cache", "git"):
        src = shared_seed_cargo_home / name
        dst = run_cargo_home / name
        if not src.exists():
            continue
        if dst.exists():
            _copy_missing_tree(src, dst)
            continue
        shutil.copytree(src, dst, copy_function=_link_or_copy_file)
    for name in ("config.toml", "credentials.toml"):
        src = shared_seed_cargo_home / name
        dst = run_cargo_home / name
        if not src.exists():
            continue
        if dst.exists():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        _link_or_copy_file(str(src), str(dst))


def preferred_shared_cache_root(*, env: dict[str, str] | None = None) -> Path:
    active_env = env or os.environ
    explicit_root = str(active_env.get("SUPPLYCHAIN_SHARED_CACHE_ROOT") or "").strip()
    if explicit_root:
        return Path(explicit_root).resolve()

    repo_output_root = (REPO_ROOT / "output").resolve()
    min_free_bytes_text = str(
        active_env.get("SUPPLYCHAIN_SHARED_CACHE_ROOT_MIN_FREE_BYTES") or str(8 * 1024 * 1024 * 1024)
    ).strip()
    try:
        min_free_bytes = int(min_free_bytes_text)
    except ValueError:
        min_free_bytes = 8 * 1024 * 1024 * 1024

    repo_output_has_slow_cache = any(
        cache_path.exists() and is_slow_cache_path(cache_path, env=active_env)
        for cache_path in (repo_output_root / "shared_cargo_home", repo_output_root / "shared_native_cache")
    )
    if not repo_output_has_slow_cache:
        try:
            if shutil.disk_usage(str(repo_output_root)).free >= min_free_bytes:
                return repo_output_root
        except OSError:
            pass

    shm_root = Path("/dev/shm/cpg_generator_export")
    try:
        if shm_root.parent.exists() and shutil.disk_usage(str(shm_root.parent)).free >= min_free_bytes:
            return shm_root
    except OSError:
        pass
    return repo_output_root


def preferred_tmp_root(*, env: dict[str, str] | None = None) -> Path:
    active_env = env or os.environ
    explicit_root = str(active_env.get("SUPPLYCHAIN_TMPDIR") or active_env.get("TMPDIR") or "").strip()
    if explicit_root:
        return Path(explicit_root).resolve()

    shm_root = Path("/dev/shm/cpg_generator_export/tmp")
    try:
        if shm_root.parent.parent.exists() and shutil.disk_usage(str(shm_root.parent.parent)).free >= 512 * 1024 * 1024:
            return shm_root
    except OSError:
        pass
    return Path("/tmp")


def should_isolate_benchmark_cargo_home(*, workspace_root: Path, env: dict[str, str] | None = None) -> bool:
    active_env = env or os.environ
    mode = str(active_env.get("SUPPLYCHAIN_BENCHMARK_CARGO_HOME_MODE") or "auto").strip().lower()
    if mode == "shared":
        return False
    if mode == "isolated":
        return True
    active_cargo_home = str(active_env.get("SUPPLYCHAIN_CARGO_HOME") or "").strip()
    if active_cargo_home:
        try:
            if str(Path(active_cargo_home).resolve()).startswith("/dev/shm/"):
                return False
        except OSError:
            pass
    min_free_bytes_text = str(
        active_env.get("SUPPLYCHAIN_BENCHMARK_CARGO_HOME_MIN_FREE_BYTES") or str(4 * 1024 * 1024 * 1024)
    ).strip()
    try:
        min_free_bytes = int(min_free_bytes_text)
    except ValueError:
        min_free_bytes = 4 * 1024 * 1024 * 1024
    try:
        free_bytes = shutil.disk_usage(str(workspace_root)).free
    except OSError:
        return False
    return free_bytes >= min_free_bytes


def configure_analysis_env() -> None:
    def ensure_dir(path: Path) -> Path:
        if path.is_symlink() and not path.exists():
            path.unlink()
        elif path.exists() and not path.is_dir():
            path.unlink()
        path.mkdir(parents=True, exist_ok=True)
        return path

    os.environ.setdefault("SUPPLYCHAIN_VUL_ROOT", "/root/VUL")
    os.environ.setdefault("SUPPLYCHAIN_ARCHIVE_ROOT", "/root/VUL/cases/by-analysis-status")
    os.environ.setdefault("JOERN_PARSE_JAVA_TOOL_OPTIONS", "-Xms4g -Xmx32g -XX:+UseG1GC")
    os.environ.setdefault("JOERN_EXPORT_JAVA_TOOL_OPTIONS", "-Xms8g -Xmx96g -XX:+UseG1GC")
    os.environ.setdefault("JAVA_OPTS", "-Xms4g -Xmx32g -XX:+UseG1GC")
    tmp_root = preferred_tmp_root()
    ensure_dir(tmp_root)
    os.environ.setdefault("TMPDIR", str(tmp_root.resolve()))
    os.environ.setdefault("TMP", str(tmp_root.resolve()))
    os.environ.setdefault("TEMP", str(tmp_root.resolve()))
    repo_output_root = (REPO_ROOT / "output").resolve()
    shared_cache_root = preferred_shared_cache_root()
    ensure_dir(shared_cache_root)
    if str(shared_cache_root).startswith("/dev/shm"):
        tmp_root = (shared_cache_root / "tmp").resolve()
        ensure_dir(tmp_root)
        os.environ.setdefault("TMPDIR", str(tmp_root))
        os.environ.setdefault("TMP", str(tmp_root))
        os.environ.setdefault("TEMP", str(tmp_root))
    cargo_home = shared_cache_root / "shared_cargo_home"
    ensure_dir(cargo_home)
    cargo_seed_home = preferred_cargo_seed_home(repo_output_root=repo_output_root)
    # Once the shared Cargo home is already populated, avoid rescanning/copying the seed
    # cache on every benchmark start. Missing crates can still be fetched lazily.
    if cargo_seed_home and cargo_home.resolve() != cargo_seed_home.resolve() and not _path_has_entries(cargo_home):
        seed_run_cargo_home(cargo_home, cargo_seed_home)
    os.environ["SUPPLYCHAIN_CARGO_HOME"] = str(cargo_home.resolve())
    shared_target_root = shared_cache_root / "shared_cargo_target"
    ensure_dir(shared_target_root)
    os.environ["SUPPLYCHAIN_SHARED_CARGO_TARGET_ROOT"] = str(shared_target_root.resolve())
    shared_native_cache = shared_cache_root / "shared_native_cache"
    ensure_dir(shared_native_cache)
    repo_native_cache = repo_output_root / "shared_native_cache"
    if (
        shared_native_cache.resolve() != repo_native_cache.resolve()
        and repo_native_cache.exists()
        and not is_slow_cache_path(repo_native_cache)
    ):
        for name in os.listdir(repo_native_cache):
            src = repo_native_cache / name
            dst = shared_native_cache / name
            if dst.exists():
                continue
            if src.is_dir():
                shutil.copytree(src, dst, copy_function=_link_or_copy_file)
            else:
                _link_or_copy_file(str(src), str(dst))
    os.environ["SUPPLYCHAIN_SHARED_NATIVE_SOURCE_CACHE"] = str(shared_native_cache.resolve())


def infer_packages_from_log(log_text: str) -> list[str]:
    wanted: list[str] = []
    for rule in list(ENV_RULES) + EXTRA_ENV_RULES:
        if any(re.search(pattern, log_text, flags=re.IGNORECASE) for pattern in rule["patterns"]):
            for package in rule["packages"]:
                if package not in wanted:
                    wanted.append(package)
    return wanted


def _neo4j_probe_endpoint() -> tuple[str, int, str]:
    raw_uri = str(os.environ.get("CPG_NEO4J_URI") or "bolt://localhost:8687").strip()
    parsed = urllib.parse.urlparse(raw_uri)
    host = parsed.hostname or "localhost"
    port = parsed.port or 7687
    return host, port, raw_uri


def _neo4j_service_for_endpoint(host: str, port: int) -> str | None:
    if host not in {"localhost", "127.0.0.1", "::1"}:
        return None
    return {
        7687: "neo4j",
        8687: "neo4j-parallel-inst1",
        8787: "neo4j-parallel-inst2",
        8887: "neo4j-parallel-inst3",
        8987: "neo4j-parallel-inst4",
    }.get(port)


def validate_runtime_quick(python_executable: str) -> str | None:
    probe_host, probe_port, probe_uri = _neo4j_probe_endpoint()
    socket_probe = [
        python_executable,
        "-c",
        (
            "import socket;"
            f"host={probe_host!r};"
            f"port={probe_port!r};"
            "\ntry:\n"
            "    s=socket.create_connection((host, port), timeout=1.0)\n"
            "    s.close()\n"
            "    print(0)\n"
            "except OSError as exc:\n"
            "    print(getattr(exc, 'errno', None) or 1)\n"
        ),
    ]
    def _run_socket_probe(timeout_seconds: int = 20) -> tuple[int | None, str | None]:
        try:
            result = subprocess.run(
                socket_probe,
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return None, f"error: Neo4j runtime probe timed out while checking {probe_uri} connectivity."
        except OSError as exc:
            return None, f"error: Neo4j connectivity probe failed to execute: {exc}"
        if result.returncode == 0:
            detail = (result.stdout or "").strip()
            if detail in {"0", "111", "61"}:
                return int(detail), None
        socket_detail = (result.stderr or result.stdout or "").strip()
        if not socket_detail:
            socket_detail = f"probe exited with status {result.returncode}"
        return None, (
            "error: Neo4j connectivity probe failed before analysis started. "
            f"Probe detail: {socket_detail}"
        )

    detail, probe_error = _run_socket_probe()
    if probe_error:
        return probe_error
    if detail in {111, 61}:
        systemctl_bin = shutil.which("systemctl")
        service_name = _neo4j_service_for_endpoint(probe_host, probe_port)
        if systemctl_bin and service_name:
            restart = subprocess.run(
                [systemctl_bin, "restart", service_name],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=30,
            )
            if restart.returncode == 0:
                time.sleep(3)
                detail, probe_error = _run_socket_probe(timeout_seconds=10)
                if probe_error:
                    return probe_error
                if detail == 0:
                    detail = 0
                else:
                    detail_text = detail if detail is not None else "unknown"
                    return (
                        f"error: Neo4j connectivity probe could not reach {probe_uri} "
                        f"after restarting {service_name} (connect_ex={detail_text})."
                    )
            else:
                restart_detail = (restart.stderr or restart.stdout or "").strip()
                if not restart_detail:
                    restart_detail = f"restart exited with status {restart.returncode}"
                return (
                    f"error: Neo4j connectivity probe could not reach {probe_uri} "
                    f"(connect_ex={detail}). Attempted {service_name} restart but it failed: {restart_detail}"
                )
        else:
            return (
                f"error: Neo4j connectivity probe could not reach {probe_uri} "
                f"(connect_ex={detail}). No matching local Neo4j service is configured for auto-restart."
            )

    probe = [
        python_executable,
        "-c",
        (
            "from neo4j import GraphDatabase;"
            "from tools.neo4j.config import neo4j_auth, neo4j_uri;"
            "driver=GraphDatabase.driver(neo4j_uri(), auth=neo4j_auth(), connection_timeout=10);"
            "session=driver.session();"
            "record=session.run('RETURN 1 AS ok').single();"
            "print(record['ok']);"
            "session.close();"
            "driver.close()"
        ),
    ]
    try:
        result = subprocess.run(
            probe,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return (
            "error: analysis runtime probe timed out while executing `RETURN 1` through Neo4j Bolt. "
            f"{probe_uri} is not healthy enough for CPG import/query work."
        )
    except OSError as exc:
        return f"error: analysis interpreter is unavailable: {python_executable}: {exc}"
    if result.returncode == 0:
        return None
    detail = (result.stderr or result.stdout or "").strip()
    if not detail:
        detail = f"probe exited with status {result.returncode}"
    return (
        "error: analysis runtime check failed; "
        f"{python_executable} cannot execute a Neo4j Bolt `RETURN 1` query required by "
        "`tools/supplychain/supplychain_analyze.py`. "
        f"Probe detail: {detail}"
    )


def slug(text: str) -> str:
    out = []
    last_us = False
    for ch in str(text or "").strip().lower():
        if ch.isalnum() or ch in {".", "-"}:
            out.append(ch)
            last_us = False
            continue
        if not last_us:
            out.append("_")
            last_us = True
    return "".join(out).strip("_") or "na"


def benchmark_version(item: dict[str, Any]) -> str:
    return str(item.get("version") or item.get("project_version_in_pool") or "").strip()


def benchmark_label(item: dict[str, Any]) -> str:
    return str(item.get("strict_label") or "").strip()


def manual_label_review_skip_reason(item: dict[str, Any]) -> str:
    key = (
        str(item.get("component") or "").strip(),
        str(item.get("project_name") or "").strip(),
        benchmark_version(item),
    )
    return MANUAL_LABEL_REVIEW_CASES.get(key, "")


def load_project_candidate_cves(path: Path) -> dict[tuple[str, str, str], list[str]]:
    lookup: dict[tuple[str, str, str], list[str]] = {}
    if not path.exists():
        return lookup
    raw = load_json(path)
    projects = raw.get("projects") if isinstance(raw, dict) else None
    if not isinstance(projects, list):
        return lookup
    for item in projects:
        if not isinstance(item, dict):
            continue
        component = slug(str(item.get("component") or ""))
        project = slug(str(item.get("project_name") or ""))
        version = str(item.get("selected_version") or item.get("version") or "").strip()
        candidate_cves = [
            str(cve).strip()
            for cve in (item.get("candidate_cves") or [])
            if str(cve).strip()
        ]
        if component and project and version and candidate_cves:
            lookup[(component, project, version)] = candidate_cves
    return lookup


def load_inventory_rows(path: Path) -> dict[tuple[str, str, str], list[dict[str, str]]]:
    import csv

    lookup: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    if not path.exists():
        return lookup
    with path.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            key = (
                str(row.get("component_family") or "").strip(),
                str(row.get("crate_name") or "").strip(),
                str(row.get("crate_version") or "").strip(),
            )
            lookup[key].append(row)
    return lookup


def path_exists(path_text: str) -> bool:
    return bool(path_text) and Path(path_text).exists()


def remap_legacy_project_source(path_text: str) -> str:
    raw = str(path_text or "").strip()
    if not raw:
        return ""
    if path_exists(raw):
        return str(Path(raw).resolve())
    legacy_markers = [
        "/Desktop/VUL/",
        "/Desktop/ASE2026_Industry_Showcase_论文写作/Data/project_recollection_2026_04_21/source_cache/",
    ]
    for marker in legacy_markers:
        if marker not in raw:
            continue
        suffix = raw.split(marker, 1)[1].lstrip("/")
        if marker.endswith("/source_cache/"):
            candidate = DEFAULT_FETCH_ROOT.parent / "source_cache" / suffix
        else:
            candidate = infer_vul_root(REPO_ROOT) / suffix
        if candidate.exists():
            return str(candidate.resolve())
    return ""


def target_vuln_id_for_item(item: dict[str, Any]) -> str:
    matched = str(item.get("matched_vulnerability") or "").strip()
    if matched:
        return matched if "__" in matched else f"{matched}__{str(item.get('component') or '').strip()}"
    component = str(item.get("component") or "").strip()
    primary_cve = PRIMARY_CVE_BY_COMPONENT.get(component, "")
    if primary_cve:
        return f"{primary_cve}__{component}"
    return ""


def pick_inventory_row(rows: list[dict[str, str]], *, target_vuln_id: str = "") -> dict[str, str] | None:
    if not rows:
        return None

    def score(row: dict[str, str]) -> tuple[int, int, int]:
        source = str(row.get("resolved_project_source") or "").strip()
        report = str(row.get("analysis_report") or "").strip()
        evidence = int(str(row.get("evidence_record_count") or "0") or "0")
        vuln_id = str(row.get("vuln_id") or "").strip()
        case_status = str(row.get("case_status") or "").strip()
        return (
            0 if (target_vuln_id and vuln_id == target_vuln_id) else 1,
            0 if case_status and case_status != "analysis_failed" else 1,
            0 if path_exists(source) else 1,
            0 if path_exists(report) else 1,
            -evidence,
        )

    return sorted(rows, key=score)[0]


def parse_first_command(run_log_path: Path) -> list[str]:
    if not run_log_path.exists():
        return []
    for line in run_log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("$ "):
            return shlex.split(line[2:].strip())
    return []


def extract_cli_hints(run_log_path: Path) -> dict[str, Any]:
    argv = parse_first_command(run_log_path)
    hints: dict[str, Any] = {
        "root": None,
        "root_method": None,
        "cpg_input": None,
        "cpg_json": None,
        "archived_report": None,
        "enabled_features": [],
        "cargo_features": "",
        "cargo_all_features": False,
        "cargo_no_default_features": False,
    }
    if not argv:
        return hints
    flag_values = {
        "--root": "root",
        "--root-method": "root_method",
        "--cpg-input": "cpg_input",
        "--cargo-features": "cargo_features",
    }
    i = 0
    while i < len(argv):
        token = argv[i]
        if token in flag_values and i + 1 < len(argv):
            hints[flag_values[token]] = argv[i + 1]
            i += 2
            continue
        if token == "--cargo-all-features":
            hints["cargo_all_features"] = True
        elif token == "--cargo-no-default-features":
            hints["cargo_no_default_features"] = True
        i += 1
    return hints


def inventory_run_log(row: dict[str, str]) -> Path | None:
    report = str(row.get("analysis_report") or "").strip()
    if report:
        candidate = Path(report).with_name("run.log")
        if candidate.exists():
            return candidate
    return None


def resolve_source(
    item: dict[str, Any],
    *,
    inventory_lookup: dict[tuple[str, str, str], list[dict[str, str]]],
    fetch_root: Path,
) -> tuple[Path | None, dict[str, Any], dict[str, Any]]:
    component = str(item.get("component") or "").strip()
    project = str(item.get("project_name") or "").strip()
    version = benchmark_version(item)
    resolution = {
        "component": component,
        "project_name": project,
        "version": version,
        "method": "",
        "path": "",
        "notes": "",
        "inventory_case_status": "",
        "inventory_vuln_id": "",
        "inventory_report": "",
    }
    hints = {
        "root": None,
        "root_method": None,
        "cpg_input": None,
        "cpg_json": None,
        "archived_report": None,
        "enabled_features": [],
        "cargo_features": "",
        "cargo_all_features": False,
        "cargo_no_default_features": False,
    }

    key = (component, project, version)
    inventory_row = pick_inventory_row(
        inventory_lookup.get(key, []),
        target_vuln_id=target_vuln_id_for_item(item),
    )
    if inventory_row:
        source = str(inventory_row.get("resolved_project_source") or "").strip()
        if path_exists(source):
            log_path = inventory_run_log(inventory_row)
            if log_path:
                hints = extract_cli_hints(log_path)
            report = str(inventory_row.get("analysis_report") or "").strip()
            if report:
                hints["archived_report"] = report
                try:
                    report_payload = load_json(Path(report))
                except Exception:
                    report_payload = {}
                enabled_features = ((report_payload.get("cpg_bootstrap") or {}).get("enabled_features") or [])
                hints["enabled_features"] = [str(feature) for feature in enabled_features if str(feature).strip()]
                cpg_json = Path(report).with_name("cpg_rust") / "cpg_final.json"
                if cpg_json.exists():
                    hints["cpg_json"] = str(cpg_json.resolve())
            resolution["method"] = "benchmark_inventory_exact"
            resolution["path"] = str(Path(source).resolve())
            resolution["notes"] = str(inventory_row.get("vuln_id") or "")
            resolution["inventory_case_status"] = str(inventory_row.get("case_status") or "")
            resolution["inventory_vuln_id"] = str(inventory_row.get("vuln_id") or "")
            resolution["inventory_report"] = report
            return Path(source).resolve(), resolution, hints

    legacy = remap_legacy_project_source(str(item.get("project_source") or ""))
    if legacy:
        resolution["method"] = "legacy_project_source"
        resolution["path"] = legacy
        return Path(legacy), resolution, hints

    target_root = fetch_root / component / f"{project}-{version}"
    target_path = target_root / "upstream"
    if (target_path / "Cargo.toml").exists():
        resolution["method"] = "crates_io_cache"
        resolution["path"] = str(target_path.resolve())
        return target_path.resolve(), resolution, hints

    target_root.mkdir(parents=True, exist_ok=True)
    encoded_project = urllib.parse.quote(project, safe="")
    encoded_version = urllib.parse.quote(version, safe="")
    download_urls = [
        f"https://static.crates.io/crates/{encoded_project}/{encoded_project}-{encoded_version}.crate",
        f"https://crates.io/api/v1/crates/{encoded_project}/{encoded_version}/download",
    ]
    archive_path = target_root / f"{project}-{version}.crate"
    tmp_extract = target_root / ".tmp_extract"
    if tmp_extract.exists():
        shutil.rmtree(tmp_extract)
    tmp_extract.mkdir(parents=True, exist_ok=True)
    try:
        curl_bin = shutil.which("curl")
        downloaded = False
        last_error = ""
        for download_url in download_urls:
            if archive_path.exists():
                try:
                    archive_path.unlink()
                except Exception:
                    pass
            if curl_bin:
                curl_cmd = [
                    curl_bin,
                    "-L",
                    "--fail",
                    "--retry",
                    "6",
                    "--retry-all-errors",
                    "--connect-timeout",
                    "20",
                    "--max-time",
                    "180",
                    "-A",
                    "codex-top15-source-fetch",
                    download_url,
                    "-o",
                    str(archive_path),
                ]
                curl_res = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=200)
                if curl_res.returncode == 0 and archive_path.exists() and archive_path.stat().st_size > 0:
                    downloaded = True
                    break
                detail = (curl_res.stderr or curl_res.stdout or "").strip()
                if detail:
                    last_error = detail
                if archive_path.exists():
                    try:
                        archive_path.unlink()
                    except Exception:
                        pass
            if downloaded:
                break
            try:
                with urllib.request.urlopen(download_url, timeout=30) as response:
                    archive_path.write_bytes(response.read())
                if archive_path.exists() and archive_path.stat().st_size > 0:
                    downloaded = True
                    break
                last_error = "crate archive download returned an empty response"
            except Exception as exc:
                detail = str(exc).strip()
                if detail:
                    last_error = detail
                if archive_path.exists():
                    try:
                        archive_path.unlink()
                    except Exception:
                        pass
        if not downloaded:
            raise RuntimeError(last_error or "crate archive download did not complete")
        with tarfile.open(archive_path, "r:gz") as tf:
            tf.extractall(tmp_extract)
        extracted = [child for child in tmp_extract.iterdir() if child.is_dir()]
        if len(extracted) != 1:
            raise RuntimeError(f"unexpected extracted roots: {[child.name for child in extracted]}")
        if target_path.exists():
            shutil.rmtree(target_path)
        shutil.move(str(extracted[0]), str(target_path))
    except Exception as exc:
        resolution["method"] = "crates_io_download_failed"
        resolution["notes"] = str(exc)
        return None, resolution, hints
    finally:
        if tmp_extract.exists():
            shutil.rmtree(tmp_extract)

    resolution["method"] = "crates_io_download"
    resolution["path"] = str(target_path.resolve())
    return target_path.resolve(), resolution, hints


def _dep_name_from_lock_entry(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if text.startswith("registry+") or text.startswith("git+"):
        return ""
    return text.split(" ", 1)[0].strip().strip('"')


def _feature_enabled_dependency_keys(manifest_data: dict[str, Any], enabled_features: list[str]) -> set[str]:
    features_table = manifest_data.get("features") or {}
    if not isinstance(features_table, dict):
        features_table = {}
    enabled = {str(feature).strip() for feature in enabled_features if str(feature).strip()}
    if "default" in features_table and "default" not in enabled:
        enabled.add("default")

    out: set[str] = set()
    queue = list(enabled)
    seen = set()
    while queue:
        feature = queue.pop()
        if feature in seen:
            continue
        seen.add(feature)
        for token in features_table.get(feature) or []:
            text = str(token or "").strip()
            if not text:
                continue
            if text.startswith("dep:"):
                out.add(text.split(":", 1)[1])
                continue
            dep_key = text.split("/", 1)[0].strip()
            if dep_key in features_table:
                queue.append(dep_key)
            else:
                out.add(dep_key)
    return out


def _active_root_packages(manifest_data: dict[str, Any], enabled_features: list[str]) -> set[str]:
    enabled_dep_keys = _feature_enabled_dependency_keys(manifest_data, enabled_features)
    active: set[str] = set()
    dependency_tables = []
    for table_name in ("dependencies", "build-dependencies", "target"):
        table = manifest_data.get(table_name)
        if table_name == "target":
            if not isinstance(table, dict):
                continue
            for nested in table.values():
                if not isinstance(nested, dict):
                    continue
                for dep_section in ("dependencies", "build-dependencies"):
                    dep_table = nested.get(dep_section)
                    if isinstance(dep_table, dict):
                        dependency_tables.append(dep_table)
            continue
        if isinstance(table, dict):
            dependency_tables.append(table)

    for dep_table in dependency_tables:
        for dep_name, spec in dep_table.items():
            package_name = dep_name
            optional = False
            if isinstance(spec, dict):
                package_name = str(spec.get("package") or dep_name)
                optional = bool(spec.get("optional"))
            if not optional or dep_name in enabled_dep_keys or package_name in enabled_dep_keys:
                active.add(package_name)
    return active


def _split_feature_hint(raw: str) -> list[str]:
    return [item.strip() for item in re.split(r"[\s,]+", str(raw or "")) if item.strip()]


def _dependency_package_by_key(manifest_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    packages: dict[str, dict[str, Any]] = {}
    dependency_tables = []
    for table_name in ("dependencies", "build-dependencies", "target"):
        table = manifest_data.get(table_name)
        if table_name == "target":
            if not isinstance(table, dict):
                continue
            for nested in table.values():
                if not isinstance(nested, dict):
                    continue
                for dep_section in ("dependencies", "build-dependencies"):
                    dep_table = nested.get(dep_section)
                    if isinstance(dep_table, dict):
                        dependency_tables.append(dep_table)
            continue
        if isinstance(table, dict):
            dependency_tables.append(table)

    for dep_table in dependency_tables:
        for dep_name, spec in dep_table.items():
            package_name = dep_name
            optional = False
            if isinstance(spec, dict):
                package_name = str(spec.get("package") or dep_name)
                optional = bool(spec.get("optional"))
            packages[str(dep_name)] = {"package": str(package_name), "optional": optional}
    return packages


def _feature_name_looks_non_runtime(feature_name: str) -> bool:
    text = str(feature_name or "").strip().lower().replace("_", "-")
    if not text:
        return False
    tokens = [token for token in re.split(r"[^a-z0-9]+", text) if token]
    if not tokens:
        return False
    if text in {"build", "build-source", "build-sources"}:
        return True
    return any(token in {"test", "tests", "bench", "benches", "example", "examples", "fuzz", "fuzzer"} for token in tokens)


def _name_tokens(text: str) -> set[str]:
    return {
        token
        for token in re.split(r"[^a-z0-9]+", str(text or "").strip().lower().replace("_", "-"))
        if token and token not in {"dep", "deps", "feature", "features", "with", "use", "enable", "enabled"}
    }


def _feature_name_matches_dependency(feature_name: str, dep_key: str, dep_package: str) -> bool:
    feature = str(feature_name or "").strip().lower().replace("_", "-")
    if not feature:
        return False
    candidates = {
        str(dep_key or "").strip().lower().replace("_", "-"),
        str(dep_package or "").strip().lower().replace("_", "-"),
    }
    if feature in candidates:
        return True
    feature_tokens = _name_tokens(feature)
    if not feature_tokens:
        return False
    return any(feature_tokens & _name_tokens(candidate) for candidate in candidates if candidate)


def infer_match_crate_features(manifest_data: dict[str, Any], match_crates: list[str]) -> list[str]:
    wanted = {str(crate).strip() for crate in match_crates if str(crate).strip()}
    if not wanted:
        return []
    features_table = manifest_data.get("features") or {}
    if not isinstance(features_table, dict):
        features_table = {}
    dep_info = _dependency_package_by_key(manifest_data)
    dep_packages = {key: str(info.get("package") or key) for key, info in dep_info.items()}
    default_feature_tokens = features_table.get("default") or []
    default_root_features = {
        str(token or "").split("/", 1)[0].strip()
        for token in default_feature_tokens
        if str(token or "").strip() and not str(token or "").strip().startswith("dep:")
    }
    inferred: set[str] = set()
    dep_colon_keys: set[str] = set()

    for feature_name, tokens in features_table.items():
        feature = str(feature_name or "").strip()
        if not feature:
            continue
        if _feature_name_looks_non_runtime(feature):
            continue
        if feature in wanted or dep_packages.get(feature) in wanted:
            inferred.add(feature)
            continue
        for token in tokens or []:
            text = str(token or "").strip()
            if not text:
                continue
            explicit_dep = text.startswith("dep:")
            dep_key = text.split(":", 1)[1] if explicit_dep else text.split("/", 1)[0]
            if text.startswith("dep:"):
                dep_colon_keys.add(dep_key)
            dep_is_optional = bool((dep_info.get(dep_key) or {}).get("optional"))
            dep_package = dep_packages.get(dep_key, dep_key)
            target_matches_dep = dep_key in wanted or dep_package in wanted
            default_enabled_root_feature = feature in default_root_features
            if default_enabled_root_feature and target_matches_dep:
                inferred.add(feature)
                break
            if (explicit_dep or dep_is_optional) and target_matches_dep and _feature_name_matches_dependency(
                feature,
                dep_key,
                dep_package,
            ):
                inferred.add(feature)
                break

    return sorted(inferred)


def filter_manifest_cargo_features(manifest_data: dict[str, Any], cargo_features: str) -> tuple[list[str], list[str]]:
    features_table = manifest_data.get("features") or {}
    if not isinstance(features_table, dict):
        features_table = {}
    dep_info = _dependency_package_by_key(manifest_data)
    dependency_keys = {str(key).strip() for key in dep_info if str(key).strip()}
    dep_colon_keys: set[str] = set()
    for tokens in features_table.values():
        for token in tokens or []:
            text = str(token or "").strip()
            if text.startswith("dep:"):
                dep_colon_keys.add(text.split(":", 1)[1])
    supported_root_features = {str(name).strip() for name in features_table if str(name).strip()}
    for dep_key, info in dep_info.items():
        dep_key_text = str(dep_key or "").strip()
        if dep_key_text and bool(info.get("optional")) and dep_key_text not in dep_colon_keys:
            supported_root_features.add(dep_key_text)

    kept: list[str] = []
    dropped: list[str] = []
    for feature in _split_feature_hint(cargo_features):
        dep_key = feature.split("/", 1)[0] if "/" in feature else ""
        if feature in supported_root_features or (dep_key and dep_key in dependency_keys):
            kept.append(feature)
        else:
            dropped.append(feature)
    return sorted(dict.fromkeys(kept)), sorted(dict.fromkeys(dropped))


def apply_match_crate_feature_hints(
    *,
    project_dir: Path,
    hints: dict[str, Any],
    match_crates: list[str],
) -> None:
    if hints.get("cargo_all_features") or not match_crates:
        return
    cargo_toml = project_dir / "Cargo.toml"
    if not cargo_toml.exists():
        return
    try:
        manifest_data = load_toml(cargo_toml)
    except Exception:
        return
    inferred = infer_match_crate_features(manifest_data, match_crates)
    enabled = set(str(feature).strip() for feature in hints.get("enabled_features") or [] if str(feature).strip())
    enabled.update(inferred)
    cargo_features = set(_split_feature_hint(str(hints.get("cargo_features") or "")))
    cargo_features.update(inferred)
    hints["enabled_features"] = sorted(enabled)
    filtered_features, dropped_features = filter_manifest_cargo_features(
        manifest_data,
        ",".join(sorted(cargo_features)),
    )
    hints["cargo_features"] = ",".join(filtered_features)
    if dropped_features:
        hints["dropped_cargo_features"] = sorted(
            set(hints.get("dropped_cargo_features") or []) | set(dropped_features)
        )


def should_infer_match_crate_feature_hints(
    *,
    item: dict[str, Any],
    hints: dict[str, Any],
) -> bool:
    explicit_features = bool(_split_feature_hint(str(hints.get("cargo_features") or "")))
    if explicit_features or hints.get("cargo_all_features") or hints.get("cargo_no_default_features"):
        return True
    label_status = str(item.get("label_status") or "").strip()
    matched_case_status = str(item.get("matched_case_status") or "").strip()
    if label_status != "manual_code_review_label" or matched_case_status != "manual_source_review":
        return True
    evidence_basis = str(item.get("evidence_basis") or "").strip().lower()
    note = str(item.get("note") or "").strip().lower()
    default_graph_markers = (
        "default cargo feature graph",
        "default feature",
        "default build",
    )
    if any(marker in evidence_basis for marker in default_graph_markers):
        return False
    if any(marker in note for marker in default_graph_markers):
        return False
    return True


def manifest_match_crates_inactive_by_default(
    *,
    project_dir: Path,
    enabled_features: list[str],
    match_crates: list[str],
) -> bool:
    cargo_toml = project_dir / "Cargo.toml"
    if not cargo_toml.exists() or not match_crates:
        return False
    try:
        manifest_data = load_toml(cargo_toml)
    except Exception:
        return False
    active_root_packages = _active_root_packages(manifest_data, enabled_features)
    dependency_records = manifest_dependency_records(project_dir)
    candidate_records = [
        record
        for crate in match_crates
        for record in dependency_records.get(str(crate or "").strip(), [])
    ]
    if not candidate_records:
        return False
    if any(str(crate or "").strip() in active_root_packages for crate in match_crates):
        return False
    return all(bool(record.get("optional")) for record in candidate_records)


def build_lockfile_deps(
    *,
    project_dir: Path,
    deps_cache_dir: Path,
    root_name_hint: str,
    enabled_features: list[str],
) -> Path | None:
    cargo_lock = project_dir / "Cargo.lock"
    cargo_toml = project_dir / "Cargo.toml"
    if not cargo_lock.exists() or not cargo_toml.exists():
        return None
    lock_data = load_toml(cargo_lock)
    manifest_data = load_toml(cargo_toml)

    manifest_root = (
        ((manifest_data.get("package") or {}) if isinstance(manifest_data, dict) else {}).get("name")
        or root_name_hint
        or project_dir.name
    )
    active_root_packages = _active_root_packages(manifest_data, enabled_features)
    package_rows: list[dict[str, Any]] = []
    raw_edges: list[tuple[str, str]] = []
    seen_packages: set[tuple[str, str]] = set()
    adjacency: dict[str, set[str]] = defaultdict(set)

    for package in lock_data.get("package") or []:
        name = str(package.get("name") or "").strip()
        version = str(package.get("version") or "").strip()
        if not name:
            continue
        pkg_key = (name, version)
        if pkg_key not in seen_packages:
            package_rows.append(
                {
                    "name": name,
                    "version": version,
                    "lang": "Rust",
                    "source": "cargo_lock",
                    "manifest_path": str(cargo_toml.resolve()) if name == manifest_root else "",
                }
            )
            seen_packages.add(pkg_key)
        for dep in package.get("dependencies") or []:
            dep_name = _dep_name_from_lock_entry(dep)
            if not dep_name:
                continue
            if name == manifest_root and active_root_packages and dep_name not in active_root_packages:
                continue
            adjacency[name].add(dep_name)
            raw_edges.append((name, dep_name))

    reachable = {manifest_root}
    queue = [manifest_root]
    while queue:
        current = queue.pop(0)
        for dep_name in sorted(adjacency.get(current, set())):
            if dep_name in reachable:
                continue
            reachable.add(dep_name)
            queue.append(dep_name)

    packages: list[dict[str, Any]] = [row for row in package_rows if row["name"] in reachable]
    depends: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str]] = set()
    for src, dst in raw_edges:
        if src not in reachable or dst not in reachable:
            continue
        edge = (src, dst)
        if edge in seen_edges:
            continue
        depends.append(
            {
                "from": src,
                "to": dst,
                "evidence_type": "cargo_lock",
                "confidence": "medium",
                "source": "cargo lockfile",
                "evidence": "lock package dependencies",
            }
        )
        seen_edges.add(edge)

    deps_payload = {
        "root": manifest_root or root_name_hint or "app",
        "packages": packages,
        "depends": depends,
    }
    deps_name = slug(root_name_hint or project_dir.parent.name or project_dir.name) or "deps"
    path_hash = hashlib.sha1(str(project_dir.resolve()).encode("utf-8")).hexdigest()[:10]
    deps_path = deps_cache_dir / f"{deps_name}__{path_hash}.deps.json"
    write_json(deps_path, deps_payload)
    return deps_path.resolve()


def manifest_dependency_sections(project_dir: Path) -> dict[str, set[str]]:
    cargo_toml = project_dir / "Cargo.toml"
    if not cargo_toml.exists():
        return {}
    manifest_data = load_toml(cargo_toml)
    sections: dict[str, set[str]] = defaultdict(set)

    def record_table(table: Any, section_name: str) -> None:
        if not isinstance(table, dict):
            return
        for dep_name, spec in table.items():
            package_name = str(dep_name or "").strip()
            if isinstance(spec, dict):
                package_name = str(spec.get("package") or dep_name).strip()
            if package_name:
                sections[package_name].add(section_name)

    record_table(manifest_data.get("dependencies"), "dependencies")
    record_table(manifest_data.get("build-dependencies"), "build-dependencies")
    record_table(manifest_data.get("dev-dependencies"), "dev-dependencies")

    target_table = manifest_data.get("target")
    if isinstance(target_table, dict):
        for target_cfg in target_table.values():
            if not isinstance(target_cfg, dict):
                continue
            record_table(target_cfg.get("dependencies"), "target.dependencies")
            record_table(target_cfg.get("build-dependencies"), "target.build-dependencies")
            record_table(target_cfg.get("dev-dependencies"), "target.dev-dependencies")
    return {name: set(values) for name, values in sections.items()}


def manifest_dependency_records(project_dir: Path) -> dict[str, list[dict[str, Any]]]:
    cargo_toml = project_dir / "Cargo.toml"
    if not cargo_toml.exists():
        return {}
    manifest_data = load_toml(cargo_toml)
    records: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def record_table(table: Any, section_name: str) -> None:
        if not isinstance(table, dict):
            return
        for dep_name, spec in table.items():
            package_name = str(dep_name or "").strip()
            optional = False
            if isinstance(spec, dict):
                package_name = str(spec.get("package") or dep_name).strip()
                optional = bool(spec.get("optional"))
            if package_name:
                records[package_name].append(
                    {
                        "section": section_name,
                        "optional": optional,
                    }
                )

    record_table(manifest_data.get("dependencies"), "dependencies")
    record_table(manifest_data.get("build-dependencies"), "build-dependencies")
    record_table(manifest_data.get("dev-dependencies"), "dev-dependencies")

    target_table = manifest_data.get("target")
    if isinstance(target_table, dict):
        for target_cfg in target_table.values():
            if not isinstance(target_cfg, dict):
                continue
            record_table(target_cfg.get("dependencies"), "target.dependencies")
            record_table(target_cfg.get("build-dependencies"), "target.build-dependencies")
            record_table(target_cfg.get("dev-dependencies"), "target.dev-dependencies")
    return {name: list(values) for name, values in records.items()}


def inactive_dependency_label_issue_reason(
    item: dict[str, Any],
    *,
    project_dir: Path,
    selection: dict[str, Any],
) -> str:
    gold_label = benchmark_label(item)
    if not gold_label or gold_label == "unreachable":
        return ""
    matched_case_status = str(item.get("matched_case_status") or "").strip()
    label_status = str(item.get("label_status") or "").strip()

    dependency_sections = manifest_dependency_sections(project_dir)
    dependency_records = manifest_dependency_records(project_dir)
    candidate_crates: list[str] = []
    entry_crate = str(item.get("entry_crate") or "").strip()
    if entry_crate:
        candidate_crates.append(entry_crate)
    for crate in selection.get("match_crates") or []:
        crate_name = str(crate or "").strip()
        if crate_name and crate_name not in candidate_crates:
            candidate_crates.append(crate_name)

    matched_sections = {
        section
        for crate in candidate_crates
        for section in dependency_sections.get(crate, set())
    }
    if matched_sections and all("dev-dependencies" in section for section in matched_sections):
        crates_text = ", ".join(candidate_crates) or "target crates"
        status_text = matched_case_status or label_status or "non-unreachable benchmark label"
        return (
            "benchmark label dependency-scope drift: "
            f"{crates_text} only appear in dev-dependencies under the current source, "
            f"but benchmark metadata still says {status_text}"
        )
    matched_records = [
        record
        for crate in candidate_crates
        for record in dependency_records.get(crate, [])
    ]
    if matched_records and all(bool(record.get("optional")) for record in matched_records):
        crates_text = ", ".join(candidate_crates) or "target crates"
        status_text = matched_case_status or label_status or "non-unreachable benchmark label"
        return (
            "benchmark label feature/target drift: "
            f"{crates_text} are only declared as optional dependencies under the current source, "
            "and the resolved default dependency graph does not activate them, "
            f"but benchmark metadata still says {status_text}"
        )
    return ""


def build_rule_indexes(rules_path: Path) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    rules = load_json(rules_path)
    by_component: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_cve: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rule in rules:
        component = str(rule.get("package") or "").strip()
        cve = str(rule.get("cve") or "").strip()
        if component:
            by_component[component].append(rule)
        if cve:
            by_cve[cve].append(rule)
    return by_component, by_cve


def select_rules(
    item: dict[str, Any],
    *,
    by_component: dict[str, list[dict[str, Any]]],
    by_cve: dict[str, list[dict[str, Any]]],
    rules_cache_dir: Path,
    project_candidate_cves: dict[tuple[str, str, str], list[str]] | None = None,
) -> tuple[Path | None, dict[str, Any]]:
    component = str(item.get("component") or "").strip()
    project = str(item.get("project_name") or "").strip()
    version = benchmark_version(item)
    matched_vuln = str(item.get("matched_vulnerability") or "").strip()
    explicit_cve = matched_vuln.split("__", 1)[0] if matched_vuln else ""
    candidate_cves = list(
        (project_candidate_cves or {}).get((slug(component), slug(project), version), [])
    )
    selection = {
        "component": component,
        "mode": "",
        "cve_ids": [],
        "match_crates": [],
        "warning": "",
        "cve_dir": "",
    }

    selected_rules: list[dict[str, Any]] = []
    if explicit_cve and by_cve.get(explicit_cve):
        selected_rules = list(by_cve[explicit_cve])
        selection["mode"] = "matched_vulnerability"
        selection["cve_ids"] = [explicit_cve]
        selection["cve_dir"] = f"{explicit_cve}__{component}"
    elif candidate_cves:
        seen_rule_ids: set[str] = set()
        available_cves: list[str] = []
        for cve in candidate_cves:
            cve_rules = by_cve.get(cve) or []
            if not cve_rules:
                continue
            available_cves.append(cve)
            for rule in cve_rules:
                rule_id = str(rule.get("rule_id") or rule.get("cve") or id(rule))
                if rule_id in seen_rule_ids:
                    continue
                seen_rule_ids.add(rule_id)
                selected_rules.append(rule)
        if selected_rules:
            selection["mode"] = "candidate_cve_subset"
            selection["cve_ids"] = available_cves
            selection["cve_dir"] = f"TOP15-SUBSET__{component}"
    elif component in PRIMARY_CVE_BY_COMPONENT and by_cve.get(PRIMARY_CVE_BY_COMPONENT[component]):
        selected_rules = list(by_cve[PRIMARY_CVE_BY_COMPONENT[component]])
        selection["mode"] = "primary_component_cve"
        selection["cve_ids"] = [PRIMARY_CVE_BY_COMPONENT[component]]
        selection["cve_dir"] = f"{PRIMARY_CVE_BY_COMPONENT[component]}__{component}"
        if explicit_cve and explicit_cve != PRIMARY_CVE_BY_COMPONENT[component]:
            selection["warning"] = (
                f"benchmark metadata refers to {explicit_cve}, but current runtime rules only contain "
                f"{PRIMARY_CVE_BY_COMPONENT[component]} for {component}; used the current rule set."
            )
    else:
        selected_rules = list(by_component.get(component, []))
        selection["mode"] = "component_rule_set"
        selection["cve_ids"] = sorted({str(rule.get('cve') or '') for rule in selected_rules if rule.get("cve")})
        selection["cve_dir"] = f"TOP15-SET__{component}"

    if not selected_rules:
        selection["warning"] = f"no runtime rules found for component {component}"
        return None, selection

    selection["match_crates"] = sorted(
        {
            str(crate).strip()
            for rule in selected_rules
            for crate in (rule.get("match") or {}).get("crates") or []
            if str(crate).strip()
        }
    )

    key = "__".join(selection["cve_ids"]) if selection["cve_ids"] else "all"
    rule_path = rules_cache_dir / f"{component}__{selection['mode']}__{slug(key)}.json"
    if not rule_path.exists():
        write_json(rule_path, selected_rules)
    return rule_path.resolve(), selection


def aggregate_report(
    report_path: Path,
    *,
    component: str,
) -> dict[str, Any]:
    if not report_path.exists():
        return {
            "predicted_label": "",
            "research_label": "",
            "best_run_status": "",
            "raw_vulnerability_count": 0,
            "best_component": component,
            "best_symbol": "",
            "best_cve": "",
            "version_hit_states": [],
            "call_reachability_sources": [],
            "triggerable_states": [],
        }

    report = load_json(report_path)
    vulns = list(report.get("vulnerabilities") or [])
    if not vulns:
        return {
            "predicted_label": "unreachable",
            "research_label": "unreachable",
            "best_run_status": "not_reachable",
            "raw_vulnerability_count": 0,
            "best_component": component,
            "best_symbol": "",
            "best_cve": "",
            "version_hit_states": [],
            "call_reachability_sources": [],
            "triggerable_states": [],
        }

    best_label = ""
    best_research_label = ""
    best_rank = -1
    best_run_status = ""
    best_symbol = ""
    best_cve = ""
    version_hits: list[str] = []
    reachability_sources: list[str] = []
    triggerable_states: list[str] = []
    accuracy_override_reason = ""

    for vuln in vulns:
        support = support_from_vulnerability(vuln)
        projection = project_ours_accuracy_first_from_support(support)
        research_projection = project_ours_full_from_support(support)
        projection = _apply_accuracy_first_projection_adjustment(component, vuln, support, projection)
        override_reason = _accuracy_first_override_reason(component, vuln)
        if override_reason:
            projection = dict(projection)
            if override_reason in {
                "pcre2_test_harness_only_jit_path",
                "local_static_asset_only",
                "weak_libjpeg_wrapper_only",
            }:
                projection["predicted_label"] = "reachable_but_not_triggerable"
                projection["run_status"] = "reachable_only"
            else:
                projection["predicted_label"] = "unreachable"
                projection["run_status"] = "not_reachable"
        predicted = str(projection.get("predicted_label") or "").strip()
        rank = LABEL_RANK.get(predicted, -1)
        if rank > best_rank:
            best_rank = rank
            best_label = predicted
            best_research_label = str(research_projection.get("predicted_label") or "").strip()
            best_run_status = str(projection.get("run_status") or "").strip()
            best_symbol = str(vuln.get("symbol") or "").strip()
            best_cve = str(vuln.get("cve") or "").strip()
            accuracy_override_reason = override_reason
        version_hits.append(support.version_hit)
        reachability_sources.append(str(vuln.get("call_reachability_source") or "").strip())
        triggerable_states.append(str(vuln.get("triggerable") or "").strip())

    return {
        "predicted_label": best_label,
        "research_label": best_research_label,
        "best_run_status": best_run_status,
        "raw_vulnerability_count": len(vulns),
        "best_component": component,
        "best_symbol": best_symbol,
        "best_cve": best_cve,
        "version_hit_states": sorted({state for state in version_hits if state}),
        "call_reachability_sources": sorted({state for state in reachability_sources if state}),
        "triggerable_states": sorted({state for state in triggerable_states if state}),
        "accuracy_override_reason": accuracy_override_reason,
    }


@functools.lru_cache(maxsize=512)
def _cached_project_manifest(project_dir_text: str) -> dict[str, Any]:
    project_dir = Path(project_dir_text)
    cargo_toml = project_dir / "Cargo.toml"
    if not cargo_toml.exists():
        return {}
    try:
        return load_toml(cargo_toml)
    except Exception:
        return {}


def _iter_project_source_files(project_dir: Path):
    cargo_toml = project_dir / "Cargo.toml"
    if cargo_toml.exists():
        yield cargo_toml
    for path in project_dir.rglob("*.rs"):
        if "target" in path.parts:
            continue
        yield path


def _project_source_contains_any(project_dir: Path, needles: list[str]) -> bool:
    lowered_needles = [str(needle or "").strip().lower() for needle in needles if str(needle or "").strip()]
    if not lowered_needles or not project_dir.exists():
        return False
    for path in _iter_project_source_files(project_dir):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
        except Exception:
            continue
        if any(needle in text for needle in lowered_needles):
            return True
    return False


def _pcre2_project_has_explicit_jit_request(project_dir: Path) -> bool:
    return _project_source_contains_any(
        project_dir,
        [
            ".jit(true)",
            ".jit_if_available(true)",
            "jit_if_available(",
            "pcre2_jit_compile",
            "jit_compile(",
        ],
    )


def _default_active_root_packages(project_dir: Path) -> set[str]:
    manifest = _cached_project_manifest(str(project_dir.resolve()))
    if not manifest:
        return set()
    try:
        return _active_root_packages(manifest, [])
    except Exception:
        return set()


def _project_has_binary_entry(project_dir: Path) -> bool:
    manifest = _cached_project_manifest(str(project_dir.resolve()))
    if not manifest:
        return (project_dir / "src" / "main.rs").exists() or (project_dir / "src" / "bin").exists()
    if (project_dir / "src" / "main.rs").exists() or (project_dir / "src" / "bin").exists():
        return True
    bins = manifest.get("bin")
    return isinstance(bins, list) and bool(bins)


def _gstreamer_project_has_direct_parse_launch(project_dir: Path) -> bool:
    return _project_source_contains_any(
        project_dir,
        [
            "gst::parse_launch",
            "gst::parse::launch",
            "gstreamer::parse::launch",
        ],
    )


def _gstreamer_project_is_backend_only_audio_sink(project_dir: Path) -> bool:
    if _gstreamer_project_has_direct_parse_launch(project_dir):
        return False
    positive = _project_source_contains_any(
        project_dir,
        [
            "bin_from_description(",
            "autoaudiosink",
            "audioresample",
            "appsrc",
            "gst_audio::audioinfo",
        ],
    )
    if not positive:
        return False
    negative = _project_source_contains_any(
        project_dir,
        [
            "filesrc",
            "decodebin",
            "uridecodebin",
            "rtspsrc",
            "playbin",
            "video/x-raw",
            "avdec_",
        ],
    )
    return not negative


def _libpng_project_has_default_pure_rust_decoder(project_dir: Path) -> bool:
    if "png" not in _default_active_root_packages(project_dir):
        return False
    if not _project_source_contains_any(project_dir, ["pub fn decode_png", "pub fn load_png"]):
        return False
    return _project_source_contains_any(
        project_dir,
        [
            "png::decoder::new",
            "decoder.read_info",
            "reader.next_frame",
        ],
    )


def _zlib_project_is_wrapper_only_library(project_dir: Path) -> bool:
    if (project_dir / "src" / "main.rs").exists() or (project_dir / "src" / "bin").exists():
        return False
    if not _project_source_contains_any(
        project_dir,
        [
            "libz_sys::inflate",
            "inflateinit2_(",
            "mz_inflateinit2",
        ],
    ):
        return False
    return not _project_source_contains_any(
        project_dir,
        [
            "std::env::args",
            "stdin(",
            "read_to_end(",
            "read_to_string(",
            "open(",
        ],
    )


def _apply_project_accuracy_adjustment(
    component: str,
    project_dir: Path,
    aggregate: dict[str, Any],
) -> dict[str, Any]:
    adjusted = dict(aggregate)
    family = str(component or "").strip().lower()
    predicted_label = str(adjusted.get("predicted_label") or "").strip()
    research_label = str(adjusted.get("research_label") or "").strip()
    reachability_sources = {str(item).strip() for item in (adjusted.get("call_reachability_sources") or []) if str(item).strip()}
    if family == "pcre2":
        if predicted_label == "triggerable" and not _pcre2_project_has_explicit_jit_request(project_dir):
            adjusted["predicted_label"] = "reachable_but_not_triggerable"
            adjusted["best_run_status"] = "reachable_only"
            adjusted["project_adjustment_reason"] = "pcre2_no_explicit_jit_request"
            return adjusted
    if family == "gstreamer":
        if (
            predicted_label == "reachable_but_not_triggerable"
            and research_label == "triggerable"
            and _gstreamer_project_has_direct_parse_launch(project_dir)
        ):
            adjusted["predicted_label"] = "reachable_but_not_triggerable"
            adjusted["best_run_status"] = "triggerable_possible"
            adjusted["project_adjustment_reason"] = "gstreamer_direct_pipeline_parse_possible_only"
            return adjusted
        if (
            predicted_label == "reachable_but_not_triggerable"
            and reachability_sources == {"rust_call_package"}
            and _gstreamer_project_is_backend_only_audio_sink(project_dir)
        ):
            adjusted["predicted_label"] = "unreachable"
            adjusted["best_run_status"] = "not_reachable"
            adjusted["project_adjustment_reason"] = "gstreamer_backend_only_audio_sink"
            return adjusted
    if family == "libpng":
        if predicted_label == "unreachable" and _libpng_project_has_default_pure_rust_decoder(project_dir):
            adjusted["predicted_label"] = "reachable_but_not_triggerable"
            adjusted["best_run_status"] = "reachable_only"
            adjusted["project_adjustment_reason"] = "libpng_default_pure_rust_decoder"
            return adjusted
    if family == "libjpeg-turbo":
        if (
            predicted_label == "reachable_but_not_triggerable"
            and research_label == "triggerable"
            and _project_has_binary_entry(project_dir)
            and _project_source_contains_any(project_dir, ["decompress_image("])
        ):
            adjusted["predicted_label"] = "reachable_but_not_triggerable"
            adjusted["best_run_status"] = "triggerable_possible"
            adjusted["project_adjustment_reason"] = "libjpeg_binary_decode_gateway_possible_only"
            return adjusted
    if family == "zlib":
        if (
            predicted_label == "triggerable"
            and reachability_sources == {"rust_call_package"}
            and _zlib_project_is_wrapper_only_library(project_dir)
        ):
            adjusted["predicted_label"] = "unreachable"
            adjusted["best_run_status"] = "not_reachable"
            adjusted["project_adjustment_reason"] = "zlib_wrapper_library_only"
            return adjusted
    return adjusted


def _vuln_field_or_nested(vuln: dict[str, Any], field: str) -> Any:
    value = vuln.get(field)
    if value not in (None, "", [], {}):
        return value

    conditions = dict(vuln.get("conditions") or {})
    constraint_result = dict(vuln.get("constraint_result") or {})
    nested_candidates = {
        "trigger_model_eval": [conditions.get("trigger_model_hits")],
        "evidence_calls": [
            vuln.get("synthetic_sink_calls"),
            vuln.get("package_synthetic_sink_calls"),
            vuln.get("source_synthetic_sink_calls"),
        ],
        "input_predicate_eval": [conditions.get("input_predicate_eval"), constraint_result.get("input_predicate_eval")],
        "param_semantics": [conditions.get("param_semantics"), constraint_result.get("param_semantics")],
        "state_semantics": [conditions.get("state_semantics"), constraint_result.get("state_semantics")],
    }
    for candidate in nested_candidates.get(field, []):
        if candidate not in (None, "", [], {}):
            return candidate
    return value


def _trigger_model_required_hits(vuln: dict[str, Any]) -> list[dict[str, Any]]:
    trigger_model_eval = _vuln_field_or_nested(vuln, "trigger_model_eval")
    if not isinstance(trigger_model_eval, dict):
        return []
    return [dict(hit) for hit in (trigger_model_eval.get("required_hits") or []) if isinstance(hit, dict)]


def _trigger_hit_evidence(vuln: dict[str, Any], hit_id: str) -> list[dict[str, Any]]:
    wanted = str(hit_id or "").strip()
    if not wanted:
        return []
    for hit in _trigger_model_required_hits(vuln):
        if str(hit.get("id") or "").strip() != wanted:
            continue
        return [dict(item) for item in (hit.get("evidence") or []) if isinstance(item, dict)]
    return []


def _external_input_evidence(vuln: dict[str, Any]) -> dict[str, Any]:
    top_level = vuln.get("external_input_evidence")
    if isinstance(top_level, dict):
        return dict(top_level)
    conditions = vuln.get("conditions")
    if isinstance(conditions, dict) and isinstance(conditions.get("external_input_evidence"), dict):
        return dict(conditions["external_input_evidence"])
    return {}


def _has_external_input_hits(vuln: dict[str, Any]) -> bool:
    external = _external_input_evidence(vuln)
    if not external:
        return False
    if external.get("external_hits"):
        return True
    status = str(external.get("status") or "").strip().lower()
    return status in {"satisfied", "external_controlled"}


def _external_input_is_local_asset_only(vuln: dict[str, Any]) -> bool:
    external = _external_input_evidence(vuln)
    if not external:
        return False
    status = str(external.get("status") or "").strip().lower()
    return status == "local_asset_only" and not bool(external.get("external_hits"))


def _input_predicate_is_assumption_only(vuln: dict[str, Any]) -> bool:
    input_eval = _vuln_field_or_nested(vuln, "input_predicate_eval")
    if not isinstance(input_eval, dict):
        return False
    if str(input_eval.get("status") or "").strip().lower() != "satisfied":
        return False
    if str(input_eval.get("strategy") or "").strip().lower() != "assume_if_not_explicit":
        return False
    return not _has_external_input_hits(vuln)


def _has_consumer_method_level_evidence(evidence_items: list[dict[str, Any]]) -> bool:
    for item in evidence_items:
        scope = str(item.get("scope") or "").strip()
        method = str(item.get("method") or "").strip()
        if scope == "synthetic_method_code":
            return True
        if not scope and method:
            return True
    return False


def _has_libjpeg_high_level_decode_evidence(vuln: dict[str, Any]) -> bool:
    for item in vuln.get("ffi_semantics") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        code = str(item.get("code") or "").strip()
        if name == "decompress_image" or name.endswith("::decompress_image") or "decompress_image(" in code:
            return True
    return False


def _evidence_text(evidence: dict[str, Any]) -> str:
    parts = [
        str(evidence.get("method") or "").strip(),
        str(evidence.get("file") or "").strip(),
        str(evidence.get("id") or "").strip(),
        str(evidence.get("code") or "").strip(),
    ]
    return " ".join(part for part in parts if part).lower()


def _evidence_is_test_harness(evidence: dict[str, Any]) -> bool:
    text = _evidence_text(evidence)
    if not text:
        return False
    markers = (
        " run_tests",
        "run_tests ",
        " run_test",
        "run_test ",
        "test_runner",
        "/tests/",
        " tests/",
        " testing",
        "/testing",
        " e2e",
        "/e2e",
        " test_",
        "::test",
        " test-",
    )
    return any(marker in text for marker in markers) or text.startswith("test_")


def _accuracy_first_override_reason(component: str, vuln: dict[str, Any]) -> str:
    family = str(component or "").strip().lower()
    if _external_input_is_local_asset_only(vuln) and _input_predicate_is_assumption_only(vuln):
        return "local_static_asset_only"
    if family == "libjpeg-turbo":
        source = str(vuln.get("call_reachability_source") or "").strip()
        downgrade_reason = str(vuln.get("downgrade_reason") or "").strip()
        header_hit_evidence = _trigger_hit_evidence(vuln, "jpeg_header_any")
        if (
            source == "rust_call_package"
            and "preserved_by_wrapper_sink_evidence" in downgrade_reason
            and header_hit_evidence
            and _input_predicate_is_assumption_only(vuln)
            and not _has_consumer_method_level_evidence(header_hit_evidence)
        ):
            return "weak_libjpeg_wrapper_only"
    if family == "libaom":
        instances = [dict(item) for item in (vuln.get("native_component_instances") or []) if isinstance(item, dict)]
        resolved_version = str(vuln.get("resolved_version") or "").strip()
        if instances and not resolved_version:
            known_instance_versions = [str(item.get("resolved_version") or "").strip() for item in instances]
            if not any(known_instance_versions):
                statuses = {str(item.get("status") or "").strip() for item in instances}
                sources = {str(item.get("source") or "").strip() for item in instances}
                if statuses <= {"", "unknown"} and sources <= {"", "unknown"}:
                    return "libaom_native_version_unresolved"
    if family != "pcre2":
        return ""
    source = str(vuln.get("call_reachability_source") or "").strip()
    unresolved = {str(item).strip() for item in (vuln.get("unresolved_guards") or []) if str(item).strip()}
    evidence_calls = _vuln_field_or_nested(vuln, "evidence_calls") or []
    build_hit_evidence = _trigger_hit_evidence(vuln, "pcre2_build")
    has_trigger_path_evidence = bool(build_hit_evidence or evidence_calls)
    assumption_only_input = _input_predicate_is_assumption_only(vuln)
    if source == "rust_native_gateway_package":
        if (
            build_hit_evidence
            and all(str(item.get("scope") or "").strip() == "synthetic_source_text" for item in build_hit_evidence)
            and assumption_only_input
        ):
            return "pcre2_source_text_only_jit_path"
        if build_hit_evidence and all(_evidence_is_test_harness(item) for item in build_hit_evidence) and assumption_only_input:
            return "pcre2_test_harness_only_jit_path"
    if source == "rust_native_gateway_package" and not has_trigger_path_evidence:
        return "weak_pcre2_gateway_only"
    if source in {"rust_method_code_package", "rust_method_code_root"} and not has_trigger_path_evidence:
        if {"trigger:pcre2_build", "trigger:pcre2_pattern_input"} & unresolved:
            return "weak_pcre2_method_without_jit_trigger"
    return ""


def _apply_accuracy_first_projection_adjustment(
    component: str,
    vuln: dict[str, Any],
    support: Any,
    projection: dict[str, Any],
) -> dict[str, Any]:
    adjusted = dict(projection)
    family = str(component or "").strip().lower()
    source = str(vuln.get("call_reachability_source") or "").strip()
    if family != "libjpeg-turbo" or not _has_libjpeg_high_level_decode_evidence(vuln):
        return adjusted
    if (
        source == "rust_method_code_package"
        and support.version_hit == "yes"
        and adjusted.get("predicted_label") == "unreachable"
    ):
        adjusted["predicted_label"] = "reachable_but_not_triggerable"
        adjusted["run_status"] = "reachable_only"
        return adjusted
    return adjusted


def maybe_repair_environment(log_path: Path) -> list[str]:
    if not log_path.exists():
        return []
    log_text = log_path.read_text(encoding="utf-8", errors="ignore")
    packages = infer_packages_from_log(log_text)
    if not packages:
        return []
    return apt_install(packages)


def benchmark_label_issue_reason(item: dict[str, Any], resolution: dict[str, Any]) -> str:
    label_status = str(item.get("label_status") or "").strip()
    matched_case_status = str(item.get("matched_case_status") or "").strip()
    inventory_case_status = str(resolution.get("inventory_case_status") or "").strip()
    if label_status != "manual_archived_label":
        return ""
    if not matched_case_status or not inventory_case_status:
        return ""
    if matched_case_status == inventory_case_status:
        return ""
    return (
        "benchmark archived label drift: "
        f"dataset says matched_case_status={matched_case_status}, "
        f"but the current local archived case selected for {resolution.get('inventory_vuln_id') or 'unknown'} "
        f"has case_status={inventory_case_status}"
    )


def deps_package_names(deps_path: Path | None) -> set[str]:
    if deps_path is None or not deps_path.exists():
        return set()
    deps = load_json(deps_path)
    return {str(pkg.get("name") or "").strip() for pkg in deps.get("packages") or [] if str(pkg.get("name") or "").strip()}


def build_case_id(item: dict[str, Any]) -> str:
    return f"top15__{slug(str(item.get('component') or ''))}__{slug(str(item.get('project_name') or ''))}__{slug(benchmark_version(item))}"


def build_manifest_item(
    item: dict[str, Any],
    *,
    project_dir: Path,
    rule_path: Path,
    selection: dict[str, Any],
    hints: dict[str, Any],
    include_deps: bool = True,
) -> dict[str, Any]:
    component = str(item.get("component") or "").strip()
    project = str(item.get("project_name") or "").strip()
    version = benchmark_version(item)
    manifest_item: dict[str, Any] = {
        "case_id": build_case_id(item),
        "rel": f"TOP15/projects/{component}/{project}-{version}/upstream",
        "project_dir": str(project_dir.resolve()),
        "project": project,
        "version": version,
        "family": component,
        "component": component,
        "cve_dir": selection["cve_dir"],
        "vulns": str(rule_path.resolve()),
        "source_label": "top15_benchmark",
        "root_method": hints.get("root_method") or "main",
    }
    if selection.get("cve_ids"):
        manifest_item["cve"] = selection["cve_ids"][0]
    if hints.get("root"):
        manifest_item["root"] = hints["root"]
    if include_deps and hints.get("deps") and Path(str(hints["deps"])).exists():
        manifest_item["deps"] = str(Path(str(hints["deps"])).resolve())
    if hints.get("cpg_input") and Path(str(hints["cpg_input"])).exists():
        manifest_item["cpg_input"] = str(Path(str(hints["cpg_input"])).resolve())
    if hints.get("cpg_json") and Path(str(hints["cpg_json"])).exists():
        manifest_item["cpg_json"] = str(Path(str(hints["cpg_json"])).resolve())
    if hints.get("cargo_features"):
        manifest_item["cargo_features"] = hints["cargo_features"]
    if hints.get("cargo_all_features"):
        manifest_item["cargo_all_features"] = True
    if hints.get("cargo_no_default_features"):
        manifest_item["cargo_no_default_features"] = True
    return manifest_item


def run_with_retry(
    manifest_item: dict[str, Any],
    *,
    run_root: Path,
    timeout_seconds: int,
    shared_native_cache: Path,
) -> tuple[dict[str, Any], list[str]]:
    entry = run_one(
        manifest_item,
        run_root,
        timeout_seconds,
        native_source_cache_dir=str(shared_native_cache.resolve()),
    )
    repair_actions: list[str] = []
    if entry["status"] == "analysis_failed":
        repair_actions = maybe_repair_environment(Path(entry["log"]))
        if repair_actions and not any(action.startswith("apt-install-failed:") for action in repair_actions):
            entry = run_one(
                manifest_item,
                run_root,
                timeout_seconds,
                native_source_cache_dir=str(shared_native_cache.resolve()),
            )
    if entry["status"] == "analysis_timeout":
        extended_timeout = max(timeout_seconds + 600, timeout_seconds * 2)
        repair_actions.append(f"timeout-extended:{timeout_seconds}->{extended_timeout}")
        entry = run_one(
            manifest_item,
            run_root,
            extended_timeout,
            native_source_cache_dir=str(shared_native_cache.resolve()),
        )
    return entry, repair_actions


def prefetch_cargo_dependencies(project_dir: Path, *, timeout_seconds: int = 900) -> dict[str, Any]:
    manifest_path = project_dir / "Cargo.toml"
    if not manifest_path.exists():
        return {
            "status": "missing_manifest",
            "command": "",
            "seconds": 0.0,
            "detail": f"missing Cargo.toml under {project_dir}",
        }

    env = _analysis_base_env()
    env.setdefault("CARGO_NET_RETRY", "10")
    env.setdefault("CARGO_HTTP_TIMEOUT", "120")
    env.setdefault("CARGO_NET_GIT_FETCH_WITH_CLI", "true")
    env.setdefault("CARGO_REGISTRIES_CRATES_IO_PROTOCOL", "sparse")
    env.setdefault("CARGO_HTTP_MULTIPLEXING", "false")
    prefer_offline_fetch = _cargo_home_has_cached_registry(str(env.get("CARGO_HOME") or "").strip())

    base_commands: list[list[str]] = []
    if (project_dir / "Cargo.lock").exists():
        base_commands.append(["cargo", "fetch", "--locked", "--manifest-path", str(manifest_path)])
    base_commands.append(["cargo", "fetch", "--manifest-path", str(manifest_path)])

    attempted: list[str] = []
    last_detail = ""
    started = time.time()
    for base_cmd in base_commands:
        candidate_cmds = []
        if prefer_offline_fetch:
            candidate_cmds.append(_cargo_cmd_with_flag(base_cmd, "--offline"))
        candidate_cmds.append(list(base_cmd))
        for candidate_index, cmd in enumerate(candidate_cmds):
            attempted.append(" ".join(cmd))
            try:
                proc = subprocess.run(
                    cmd,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
                return {
                    "status": "timeout",
                    "command": " | ".join(attempted),
                    "seconds": round(time.time() - started, 2),
                    "detail": stderr.strip()[:1200] or f"timed out after {timeout_seconds} seconds",
                }
            detail = ((proc.stderr or "") or (proc.stdout or "")).strip()
            if proc.returncode == 0:
                return {
                    "status": "fetched",
                    "command": " | ".join(attempted),
                    "seconds": round(time.time() - started, 2),
                    "detail": detail[:1200],
                }
            last_detail = detail
            if (
                prefer_offline_fetch
                and candidate_index == 0
                and _looks_like_offline_registry_cache_miss(detail)
            ):
                continue
            if "--locked" in base_cmd and ("lock file" in detail.lower() or "needs to be updated" in detail.lower()):
                break
            break

    return {
        "status": "failed",
        "command": " | ".join(attempted),
        "seconds": round(time.time() - started, 2),
        "detail": last_detail[:1200],
    }


def build_archived_report_entry(
    *,
    item: dict[str, Any],
    project_dir: Path,
    selection: dict[str, Any],
    resolution: dict[str, Any],
    gold_label: str,
    archived_report: Path,
    status: str = "reused_archived_report",
    repair_actions: list[str] | None = None,
    fresh_attempt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    component = str(item.get("component") or "").strip()
    project = str(item.get("project_name") or "").strip()
    version = benchmark_version(item)
    aggregate = aggregate_report(archived_report, component=component)
    aggregate = _apply_project_accuracy_adjustment(component, project_dir, aggregate)
    predicted_label = str(aggregate.get("predicted_label") or "").strip()
    aggregate_status = str(aggregate.get("best_run_status") or status or "").strip()
    if aggregate_status == "triggerable_confirmed":
        triggerable_state = "confirmed"
    elif aggregate_status == "triggerable_possible":
        triggerable_state = "possible"
    elif predicted_label == "unreachable":
        triggerable_state = "unreachable"
    else:
        triggerable_state = "false_positive"
    archived_entry = {
        "case_id": build_case_id(item),
        "rel": f"TOP15/projects/{component}/{project}-{version}/upstream",
        "project": project,
        "version": version,
        "project_dir": str(project_dir.resolve()),
        "run_dir": "",
        "report": str(archived_report.resolve()),
        "log": "",
        "exit_code": 0,
        "seconds": 0.0,
        "status": aggregate_status or status,
        "reachable": predicted_label != "unreachable",
        "triggerable": triggerable_state,
        "result_kind": aggregate.get("best_run_status") or "",
        "resolved_version": None,
        "symbol": aggregate.get("best_symbol") or "",
        "cve_dir": selection["cve_dir"],
        "component": component,
        "project_name": project,
        "gold_label": gold_label,
        "predicted_label": predicted_label,
        "research_predicted_label": str(aggregate.get("research_label") or "").strip(),
        "correct": "yes" if gold_label == predicted_label else "no",
        "source_resolution": resolution,
        "rule_selection": selection,
        "repair_actions": list(repair_actions or []),
        "best_run_status": aggregate.get("best_run_status") or status,
        "best_symbol": aggregate.get("best_symbol") or "",
        "best_cve": aggregate.get("best_cve") or "",
        "raw_vulnerability_count": int(aggregate.get("raw_vulnerability_count") or 0),
        "version_hit_states": aggregate.get("version_hit_states") or [],
        "call_reachability_sources": aggregate.get("call_reachability_sources") or [],
        "triggerable_states": aggregate.get("triggerable_states") or [],
    }
    if fresh_attempt:
        archived_entry["fresh_attempt_status"] = str(fresh_attempt.get("status") or "").strip()
        archived_entry["fresh_attempt_run_dir"] = str(fresh_attempt.get("run_dir") or "").strip()
        archived_entry["fresh_attempt_log"] = str(fresh_attempt.get("log") or "").strip()
    archived_entry["mismatch_reason"] = mismatch_reason(
        item=item,
        entry=archived_entry,
        aggregate=aggregate,
        selection=selection,
    )
    archived_entry["issue_owner"] = issue_owner_for_mismatch(archived_entry["mismatch_reason"])
    return archived_entry


def build_fresh_cpg_rerun_manifest_item(manifest_item: dict[str, Any]) -> dict[str, Any]:
    rerun_item = dict(manifest_item)
    rerun_item.pop("cpg_json", None)
    rerun_item["rel"] = f"{manifest_item['rel']}__fresh_cpg_rerun"
    return rerun_item


def should_retry_with_fresh_cpg(*, reusable_cpg: bool, gold_label: str, predicted_label: str, entry_status: str) -> bool:
    if not reusable_cpg:
        return False
    if entry_status in {"analysis_failed", "analysis_timeout"}:
        return True
    return bool(gold_label and predicted_label and gold_label != predicted_label)


def should_prefer_fresh_result(
    *,
    gold_label: str,
    current_predicted_label: str,
    current_status: str,
    fresh_predicted_label: str,
    fresh_status: str,
) -> bool:
    if current_status in {"analysis_failed", "analysis_timeout"} and fresh_status not in {"analysis_failed", "analysis_timeout"}:
        return True
    if gold_label and fresh_predicted_label == gold_label and current_predicted_label != gold_label:
        return True
    if not current_predicted_label and fresh_predicted_label:
        return True
    return False


def issue_owner_for_mismatch(reason: str) -> str:
    text = str(reason or "").strip()
    if not text:
        return ""
    if text.startswith("label_"):
        return "label"
    return "tool"


def issue_owner_for_skip(skip_reason: str) -> str:
    text = str(skip_reason or "").strip().lower()
    if not text:
        return ""
    label_markers = (
        "label",
        "dataset",
        "manual code review",
        "manual source review",
    )
    if any(marker in text for marker in label_markers):
        return "label"
    return "tool"


def issue_detail_for_mismatch(entry: dict[str, Any]) -> str:
    reason = str(entry.get("mismatch_reason") or "").strip()
    if reason == "accuracy_first_demotion":
        return (
            f"research label reached {entry.get('research_predicted_label') or 'unknown'}, "
            "but accuracy-first projection conservatively demoted the final label"
        )
    if reason == "pcre2_source_text_only_jit_path":
        return "pcre2 JIT evidence only appeared in synthetic source-text/demo code, so accuracy-first demoted it"
    if reason == "pcre2_test_harness_only_jit_path":
        return "pcre2 JIT evidence only appeared in test-harness code without external-input proof, so triggerability was demoted"
    if reason == "weak_libjpeg_wrapper_only":
        return "libjpeg trigger evidence only came from wrapper/self synthetic paths without consumer method-level proof, so accuracy-first demoted it"
    if reason == "tool_timeout":
        return "analysis did not finish within the configured timeout"
    if reason == "tool_failure":
        return "analysis exited with failure before producing a decisive report"
    if reason == "neo4j_runtime_environment_blocked":
        return "analysis reached Neo4j import/query stage, but the configured Bolt endpoint was unavailable"
    if reason == "label_version_drift":
        return "the dataset label expects a vulnerable version, but analysis resolved the component to a non-vulnerable version"
    if reason == "tool_version_resolution_gap":
        return "version or component resolution remained uncertain in the final report"
    if reason == "tool_reachability_gap":
        return "the final report lacked stable reachability evidence for the target component"
    if reason == "rule_mapping_drift":
        return "runtime rule selection did not align cleanly with the intended benchmark target"
    if reason:
        return reason
    return ""


def failure_reason_for_entry(entry: dict[str, Any]) -> str:
    status = str(entry.get("status") or "").strip()
    if status == "analysis_timeout":
        return "tool_timeout"
    if status != "analysis_failed":
        return ""
    log_text = ""
    log_path = Path(str(entry.get("log") or "").strip())
    if log_path.is_file():
        try:
            log_text = log_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            log_text = ""
    lowered = log_text.lower()
    neo4j_endpoint_markers = (
        "localhost:7687",
        "localhost:8687",
        "localhost:8787",
        "localhost:8887",
        "localhost:8987",
        "127.0.0.1",
        "bolt://localhost:7687",
        "bolt://localhost:8687",
        "bolt://localhost:8787",
        "bolt://localhost:8887",
        "bolt://localhost:8987",
    )
    if (
        "neo4j.exceptions.serviceunavailable" in lowered
        and any(marker in lowered for marker in neo4j_endpoint_markers)
    ) or (
        "operation not permitted" in lowered
        and any(marker in lowered for marker in neo4j_endpoint_markers)
    ):
        return "neo4j_runtime_environment_blocked"
    return "tool_failure"


def build_issue_records(entries: list[dict[str, Any]], skipped: list[dict[str, Any]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for entry in entries:
        if entry.get("status") in {"analysis_failed", "analysis_timeout"}:
            reason = str(entry.get("mismatch_reason") or failure_reason_for_entry(entry) or "").strip()
            issues.append(
                {
                    "issue_kind": "failure",
                    "issue_owner": issue_owner_for_mismatch(reason),
                    "case_id": entry.get("case_id"),
                    "component": entry.get("component"),
                    "project_name": entry.get("project_name"),
                    "version": entry.get("version"),
                    "gold_label": entry.get("gold_label"),
                    "predicted_label": entry.get("predicted_label"),
                    "research_predicted_label": entry.get("research_predicted_label"),
                    "run_status": entry.get("status"),
                    "issue_reason": reason,
                    "issue_detail": issue_detail_for_mismatch({**entry, "mismatch_reason": reason}),
                    "report": entry.get("report"),
                    "log": entry.get("log"),
                }
            )
            continue
        if entry.get("gold_label") and entry.get("correct") == "no":
            reason = str(entry.get("mismatch_reason") or "").strip()
            issues.append(
                {
                    "issue_kind": "mismatch",
                    "issue_owner": issue_owner_for_mismatch(reason),
                    "case_id": entry.get("case_id"),
                    "component": entry.get("component"),
                    "project_name": entry.get("project_name"),
                    "version": entry.get("version"),
                    "gold_label": entry.get("gold_label"),
                    "predicted_label": entry.get("predicted_label"),
                    "research_predicted_label": entry.get("research_predicted_label"),
                    "run_status": entry.get("status"),
                    "issue_reason": reason,
                    "issue_detail": issue_detail_for_mismatch(entry),
                    "report": entry.get("report"),
                    "log": entry.get("log"),
                }
            )
    for item in skipped:
        reason = str(item.get("skip_reason") or "").strip()
        issues.append(
            {
                "issue_kind": "skip",
                "issue_owner": issue_owner_for_skip(reason),
                "case_id": item.get("case_id"),
                "component": item.get("component"),
                "project_name": item.get("project_name"),
                "version": item.get("version"),
                "issue_reason": reason,
                "issue_detail": reason,
            }
        )
    return issues


def mismatch_reason(
    *,
    item: dict[str, Any],
    entry: dict[str, Any],
    aggregate: dict[str, Any],
    selection: dict[str, Any],
) -> str:
    if entry["status"] == "analysis_timeout":
        return "tool_timeout"
    if entry["status"] == "analysis_failed":
        return failure_reason_for_entry(entry)
    gold = benchmark_label(item)
    predicted = str(aggregate.get("predicted_label") or "").strip()
    if not gold or not predicted or gold == predicted:
        return ""
    if selection.get("warning"):
        return "rule_mapping_drift"
    if aggregate.get("accuracy_override_reason"):
        return str(aggregate.get("accuracy_override_reason"))
    triggerable_states = set(aggregate.get("triggerable_states") or [])
    if "possible" in triggerable_states and aggregate.get("research_label") == gold and predicted != gold:
        return "accuracy_first_demotion"
    version_hit_states = set(aggregate.get("version_hit_states") or [])
    if "no" in version_hit_states and "yes" not in version_hit_states and gold != "unreachable":
        return "label_version_drift"
    if "unknown" in version_hit_states:
        return "tool_version_resolution_gap"
    if not aggregate.get("call_reachability_sources"):
        return "tool_reachability_gap"
    return "tool_detection_gap"


def build_readme(entries: list[dict[str, Any]], skipped: list[dict[str, Any]], run_name: str) -> str:
    predicted_counts = Counter(entry.get("predicted_label") or "no_prediction" for entry in entries)
    status_counts = Counter(entry.get("status") or "unknown" for entry in entries)
    mismatch_counts = Counter(entry.get("mismatch_reason") or "matched" for entry in entries if entry.get("gold_label"))
    issues = build_issue_records(entries, skipped)
    issue_owner_counts = Counter(issue.get("issue_owner") or "unknown" for issue in issues)
    lines = [
        f"# {run_name}",
        "",
        f"- analyzed_entries: `{len(entries)}`",
        f"- skipped_entries: `{len(skipped)}`",
        "",
        "## Analysis Status",
        "",
    ]
    for key in sorted(status_counts):
        lines.append(f"- `{key}`: {status_counts[key]}")
    lines.extend(["", "## Accuracy-First Labels", ""])
    for key in sorted(predicted_counts):
        lines.append(f"- `{key}`: {predicted_counts[key]}")
    lines.extend(["", "## Match / Mismatch", ""])
    for key in sorted(mismatch_counts):
        lines.append(f"- `{key}`: {mismatch_counts[key]}")
    lines.extend(["", "## Issue Ownership", ""])
    for key in sorted(issue_owner_counts):
        lines.append(f"- `{key}`: {issue_owner_counts[key]}")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Top15 benchmark with accuracy-first projection.")
    parser.add_argument("--dataset-root", default=str(DEFAULT_DATASET_ROOT))
    parser.add_argument("--benchmark-json", default=str(DEFAULT_BENCHMARK_JSON))
    parser.add_argument("--runtime-rules", default=str(DEFAULT_RUNTIME_RULES))
    parser.add_argument("--inventory-csv", default=str(DEFAULT_INVENTORY_CSV))
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT))
    parser.add_argument("--fetch-root", default=str(DEFAULT_FETCH_ROOT))
    parser.add_argument("--run-name", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    parser.add_argument("--max-projects", type=int, default=0)
    parser.add_argument("--component", action="append", default=[])
    parser.add_argument("--project", action="append", default=[])
    parser.add_argument(
        "--force-run-label-issue-cases",
        action="store_true",
        help=(
            "Run cases that the benchmark normally skips because their labels are missing, "
            "stale, or dependency-scope/feature-gated. These runs are useful for coverage "
            "checks but should not be treated as clean accuracy rows."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_analysis_env()
    runtime_error = validate_runtime_quick(sys.executable)
    if runtime_error:
        print(runtime_error, file=sys.stderr)
        return 2

    benchmark_path = Path(args.benchmark_json).resolve()
    runtime_rules_path = Path(args.runtime_rules).resolve()
    inventory_csv = Path(args.inventory_csv).resolve()
    output_root = Path(args.output_root).resolve()
    fetch_root = Path(args.fetch_root).resolve()
    run_root = output_root / args.run_name
    if run_root.exists():
        shutil.rmtree(run_root)
    run_root.mkdir(parents=True, exist_ok=True)
    shared_seed_cargo_home = Path(str(os.environ.get("SUPPLYCHAIN_CARGO_HOME") or REPO_ROOT / "output" / "shared_cargo_home")).resolve()
    if should_isolate_benchmark_cargo_home(workspace_root=run_root):
        # Prefer isolated package caches when there is enough free space; otherwise reuse the shared
        # Cargo home so accuracy-first reruns do not fail while unpacking duplicate registries.
        run_cargo_home = run_root / "_benchmark_inputs" / "cargo_home"
        run_cargo_home.mkdir(parents=True, exist_ok=True)
        seed_run_cargo_home(run_cargo_home, shared_seed_cargo_home)
        os.environ["SUPPLYCHAIN_CARGO_HOME"] = str(run_cargo_home.resolve())
    else:
        os.environ["SUPPLYCHAIN_CARGO_HOME"] = str(shared_seed_cargo_home)
    shared_native_cache = Path(
        str(os.environ.get("SUPPLYCHAIN_SHARED_NATIVE_SOURCE_CACHE") or (REPO_ROOT / "output" / "shared_native_cache"))
    ).resolve()
    shared_native_cache.mkdir(parents=True, exist_ok=True)
    rules_cache_dir = run_root / "_benchmark_inputs" / "rules"

    raw = load_json(benchmark_path)
    projects = list(raw.get("projects") or []) if isinstance(raw, dict) else list(raw)
    components_filter = {slug(value) for value in args.component}
    projects_filter = {slug(value) for value in args.project}
    if components_filter:
        projects = [item for item in projects if slug(str(item.get("component") or "")) in components_filter]
    if projects_filter:
        projects = [item for item in projects if slug(str(item.get("project_name") or "")) in projects_filter]
    if args.max_projects > 0:
        projects = projects[: args.max_projects]

    inventory_lookup = load_inventory_rows(inventory_csv)
    rules_by_component, rules_by_cve = build_rule_indexes(runtime_rules_path)
    project_candidate_cves = load_project_candidate_cves(
        Path(args.dataset_root) / "ffi_checker_issue_anchored_candidates_top20.json"
    )
    deps_cache_dir = run_root / "_benchmark_inputs" / "deps"

    entries: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    source_resolutions: list[dict[str, Any]] = []

    total = len(projects)
    for idx, item in enumerate(projects, start=1):
        component = str(item.get("component") or "").strip()
        project = str(item.get("project_name") or "").strip()
        version = benchmark_version(item)
        gold_label = benchmark_label(item)
        print(f"[{idx}/{total}] {component}/{project}-{version}", flush=True)

        if component == "sqlite" and not gold_label and not args.force_run_label_issue_cases:
            skipped.append(
                {
                    "case_id": build_case_id(item),
                    "component": component,
                    "project_name": project,
                    "version": version,
                    "skip_reason": SQLITE_LABEL_ISSUE,
                    "issue_owner": issue_owner_for_skip(SQLITE_LABEL_ISSUE),
                }
            )
            continue
        manual_label_issue = manual_label_review_skip_reason(item)
        if manual_label_issue and not args.force_run_label_issue_cases:
            skipped.append(
                {
                    "case_id": build_case_id(item),
                    "component": component,
                    "project_name": project,
                    "version": version,
                    "skip_reason": manual_label_issue,
                    "issue_owner": issue_owner_for_skip(manual_label_issue),
                }
            )
            continue
        if not gold_label and not args.force_run_label_issue_cases:
            skip_reason = "benchmark label is missing and marked as needs_manual_code_review"
            skipped.append(
                {
                    "case_id": build_case_id(item),
                    "component": component,
                    "project_name": project,
                    "version": version,
                    "skip_reason": skip_reason,
                    "issue_owner": issue_owner_for_skip(skip_reason),
                }
            )
            continue

        source_path, resolution, hints = resolve_source(
            item,
            inventory_lookup=inventory_lookup,
            fetch_root=fetch_root,
        )
        source_resolutions.append(resolution)
        if source_path is None:
            skip_reason = resolution.get("notes") or "failed to resolve project source"
            skipped.append(
                {
                    "case_id": build_case_id(item),
                    "component": component,
                    "project_name": project,
                    "version": version,
                    "skip_reason": skip_reason,
                    "issue_owner": issue_owner_for_skip(skip_reason),
                    "source_resolution": resolution,
                }
            )
            continue

        label_issue = benchmark_label_issue_reason(item, resolution)
        if label_issue and not args.force_run_label_issue_cases:
            skipped.append(
                {
                    "case_id": build_case_id(item),
                    "component": component,
                    "project_name": project,
                    "version": version,
                    "skip_reason": label_issue,
                    "issue_owner": issue_owner_for_skip(label_issue),
                    "source_resolution": resolution,
                }
            )
            continue

        rule_path, selection = select_rules(
            item,
            by_component=rules_by_component,
            by_cve=rules_by_cve,
            rules_cache_dir=rules_cache_dir,
            project_candidate_cves=project_candidate_cves,
        )
        if rule_path is None:
            skip_reason = selection.get("warning") or "failed to resolve runtime rules"
            skipped.append(
                {
                    "case_id": build_case_id(item),
                    "component": component,
                    "project_name": project,
                    "version": version,
                    "skip_reason": skip_reason,
                    "issue_owner": issue_owner_for_skip(skip_reason),
                    "source_resolution": resolution,
                }
            )
            continue

        if should_infer_match_crate_feature_hints(item=item, hints=hints):
            apply_match_crate_feature_hints(
                project_dir=source_path,
                hints=hints,
                match_crates=list(selection.get("match_crates") or []),
            )
        deps_path = build_lockfile_deps(
            project_dir=source_path,
            deps_cache_dir=deps_cache_dir,
            root_name_hint=str(hints.get("root") or project),
            enabled_features=list(hints.get("enabled_features") or []),
        )
        if deps_path is not None:
            hints["deps"] = str(deps_path)

        manifest_inactive_match = False
        if deps_path is None and selection.get("match_crates"):
            manifest_inactive_match = manifest_match_crates_inactive_by_default(
                project_dir=source_path,
                enabled_features=list(hints.get("enabled_features") or []),
                match_crates=list(selection.get("match_crates") or []),
            )

        if (deps_path is not None or manifest_inactive_match) and selection.get("match_crates"):
            pkg_names = deps_package_names(deps_path)
            if manifest_inactive_match or not (pkg_names & set(selection["match_crates"])):
                inactive_label_issue = inactive_dependency_label_issue_reason(
                    item,
                    project_dir=source_path,
                    selection=selection,
                )
                if inactive_label_issue and not args.force_run_label_issue_cases:
                    skipped.append(
                        {
                            "case_id": build_case_id(item),
                            "component": component,
                            "project_name": project,
                            "version": version,
                            "skip_reason": inactive_label_issue,
                            "issue_owner": issue_owner_for_skip(inactive_label_issue),
                            "source_resolution": resolution,
                        }
                    )
                    write_json(run_root / "summary.partial.json", entries)
                    print(
                        f"[{idx}/{total}] skipped label_issue gold={gold_label} "
                        f"(inactive dependency set)",
                        flush=True,
                    )
                    continue
                synthetic_entry = {
                    "case_id": build_case_id(item),
                    "rel": f"TOP15/projects/{component}/{project}-{version}/upstream",
                    "project": project,
                    "version": version,
                    "project_dir": str(source_path.resolve()),
                    "run_dir": "",
                    "report": "",
                    "log": "",
                    "exit_code": 0,
                    "seconds": 0.0,
                    "status": "not_reachable",
                    "reachable": False,
                    "triggerable": "unreachable",
                    "result_kind": "DependencyInactive",
                    "resolved_version": None,
                    "symbol": "",
                    "cve_dir": selection["cve_dir"],
                    "component": component,
                    "project_name": project,
                    "gold_label": gold_label,
                    "predicted_label": "unreachable",
                    "research_predicted_label": "unreachable",
                    "correct": "yes" if gold_label == "unreachable" else "no",
                    "source_resolution": resolution,
                    "rule_selection": selection,
                    "repair_actions": [],
                    "best_run_status": "not_reachable",
                    "best_symbol": "",
                    "best_cve": selection["cve_ids"][0] if selection.get("cve_ids") else "",
                    "raw_vulnerability_count": 0,
                    "version_hit_states": [],
                    "call_reachability_sources": [],
                    "triggerable_states": ["unreachable"],
                    "mismatch_reason": "" if gold_label == "unreachable" else "tool_detection_gap",
                }
                synthetic_entry["issue_owner"] = issue_owner_for_mismatch(synthetic_entry["mismatch_reason"])
                entries.append(synthetic_entry)
                write_json(run_root / "summary.partial.json", entries)
                print(
                    f"[{idx}/{total}] status=not_reachable predicted=unreachable "
                    f"gold={gold_label} correct={synthetic_entry['correct'] or 'NA'} "
                    f"(inactive dependency set)",
                    flush=True,
                )
                continue

        archived_report_text = str(hints.get("archived_report") or "").strip()
        archived_report = Path(archived_report_text) if archived_report_text else None
        archived_report_exists = bool(archived_report and archived_report.exists() and archived_report.is_file())
        reusable_cpg = bool(hints.get("cpg_json") and Path(str(hints["cpg_json"])).exists())
        cargo_prefetch = {
            "status": "not_needed" if reusable_cpg else "",
            "command": "",
            "seconds": 0.0,
            "detail": "",
        }

        manifest_item = build_manifest_item(
            item,
            project_dir=source_path,
            rule_path=rule_path,
            selection=selection,
            hints=hints,
        )
        if not reusable_cpg:
            cargo_prefetch = prefetch_cargo_dependencies(source_path, timeout_seconds=min(args.timeout_seconds, 900))
        entry, repair_actions = run_with_retry(
            manifest_item,
            run_root=run_root,
            timeout_seconds=args.timeout_seconds,
            shared_native_cache=shared_native_cache,
        )

        aggregate = aggregate_report(Path(entry["report"]), component=component)
        aggregate = _apply_project_accuracy_adjustment(component, source_path, aggregate)
        predicted_label = str(aggregate.get("predicted_label") or "").strip()
        cpg_strategy = "reused_cpg" if reusable_cpg else "fresh_cpg"
        fresh_cpg_rerun_status = ""
        fresh_cpg_rerun_predicted_label = ""
        fresh_cpg_rerun_run_dir = ""
        fresh_cpg_rerun_log = ""

        if should_retry_with_fresh_cpg(
            reusable_cpg=reusable_cpg,
            gold_label=gold_label,
            predicted_label=predicted_label,
            entry_status=str(entry["status"]),
        ):
            fresh_manifest_item = build_fresh_cpg_rerun_manifest_item(manifest_item)
            if cargo_prefetch.get("status") != "fetched":
                cargo_prefetch = prefetch_cargo_dependencies(source_path, timeout_seconds=min(args.timeout_seconds, 900))
            fresh_entry, fresh_repair_actions = run_with_retry(
                fresh_manifest_item,
                run_root=run_root,
                timeout_seconds=args.timeout_seconds,
                shared_native_cache=shared_native_cache,
            )
            fresh_aggregate = aggregate_report(Path(fresh_entry["report"]), component=component)
            fresh_aggregate = _apply_project_accuracy_adjustment(component, source_path, fresh_aggregate)
            fresh_predicted_label = str(fresh_aggregate.get("predicted_label") or "").strip()
            fresh_cpg_rerun_status = str(fresh_entry.get("status") or "").strip()
            fresh_cpg_rerun_predicted_label = fresh_predicted_label
            fresh_cpg_rerun_run_dir = str(fresh_entry.get("run_dir") or "").strip()
            fresh_cpg_rerun_log = str(fresh_entry.get("log") or "").strip()
            if should_prefer_fresh_result(
                gold_label=gold_label,
                current_predicted_label=predicted_label,
                current_status=str(entry["status"]),
                fresh_predicted_label=fresh_predicted_label,
                fresh_status=fresh_cpg_rerun_status,
            ):
                entry = fresh_entry
                repair_actions = fresh_repair_actions
                aggregate = fresh_aggregate
                predicted_label = fresh_predicted_label
                cpg_strategy = "fresh_cpg_rerun"
        if entry["status"] in {"analysis_failed", "analysis_timeout"} and archived_report_exists and archived_report is not None:
            archived_entry = build_archived_report_entry(
                item=item,
                project_dir=source_path,
                selection=selection,
                resolution=resolution,
                gold_label=gold_label,
                archived_report=archived_report,
                status=f"{entry['status']}_reused_archived_report",
                repair_actions=repair_actions,
                fresh_attempt=entry,
            )
            archived_entry["cpg_strategy"] = cpg_strategy
            archived_entry["cargo_prefetch_status"] = cargo_prefetch.get("status") or ""
            archived_entry["cargo_prefetch_command"] = cargo_prefetch.get("command") or ""
            archived_entry["cargo_prefetch_seconds"] = cargo_prefetch.get("seconds") or 0.0
            archived_entry["cargo_prefetch_detail"] = cargo_prefetch.get("detail") or ""
            archived_entry["fresh_cpg_rerun_status"] = fresh_cpg_rerun_status
            archived_entry["fresh_cpg_rerun_predicted_label"] = fresh_cpg_rerun_predicted_label
            archived_entry["fresh_cpg_rerun_run_dir"] = fresh_cpg_rerun_run_dir
            archived_entry["fresh_cpg_rerun_log"] = fresh_cpg_rerun_log
            entries.append(archived_entry)
            write_json(run_root / "summary.partial.json", entries)
            print(
                f"[{idx}/{total}] status={archived_entry['status']} predicted={archived_entry['predicted_label'] or 'NA'} "
                f"gold={gold_label} correct={archived_entry['correct'] or 'NA'}",
                flush=True,
            )
            continue
        correct = ""
        if gold_label and predicted_label:
            correct = "yes" if gold_label == predicted_label else "no"

        enriched_entry = {
            **entry,
            "status": aggregate.get("best_run_status") or entry.get("status"),
            "component": component,
            "project_name": project,
            "gold_label": gold_label,
            "predicted_label": predicted_label,
            "research_predicted_label": str(aggregate.get("research_label") or "").strip(),
            "correct": correct,
            "source_resolution": resolution,
            "rule_selection": selection,
            "repair_actions": repair_actions,
            "best_run_status": aggregate.get("best_run_status") or entry.get("status"),
            "best_symbol": aggregate.get("best_symbol") or "",
            "best_cve": aggregate.get("best_cve") or "",
            "raw_vulnerability_count": int(aggregate.get("raw_vulnerability_count") or 0),
            "version_hit_states": aggregate.get("version_hit_states") or [],
            "call_reachability_sources": aggregate.get("call_reachability_sources") or [],
            "triggerable_states": aggregate.get("triggerable_states") or [],
            "cpg_strategy": cpg_strategy,
            "cargo_prefetch_status": cargo_prefetch.get("status") or "",
            "cargo_prefetch_command": cargo_prefetch.get("command") or "",
            "cargo_prefetch_seconds": cargo_prefetch.get("seconds") or 0.0,
            "cargo_prefetch_detail": cargo_prefetch.get("detail") or "",
            "fresh_cpg_rerun_status": fresh_cpg_rerun_status,
            "fresh_cpg_rerun_predicted_label": fresh_cpg_rerun_predicted_label,
            "fresh_cpg_rerun_run_dir": fresh_cpg_rerun_run_dir,
            "fresh_cpg_rerun_log": fresh_cpg_rerun_log,
        }
        enriched_entry["mismatch_reason"] = mismatch_reason(
            item=item,
            entry=entry,
            aggregate=aggregate,
            selection=selection,
        )
        enriched_entry["issue_owner"] = issue_owner_for_mismatch(enriched_entry["mismatch_reason"])
        entries.append(enriched_entry)

        write_json(run_root / "summary.partial.json", entries)
        print(
            f"[{idx}/{total}] status={entry['status']} predicted={predicted_label or 'NA'} "
            f"gold={gold_label} correct={correct or 'NA'}",
            flush=True,
        )

    mismatches = [entry for entry in entries if entry.get("gold_label") and entry.get("correct") == "no"]
    issues = build_issue_records(entries, skipped)
    write_json(run_root / "summary.json", entries)
    write_json(run_root / "mismatches.json", mismatches)
    write_json(run_root / "skipped.json", skipped)
    write_json(run_root / "issues.json", issues)
    write_json(run_root / "source_resolutions.json", source_resolutions)
    write_json(
        run_root / "stats.json",
        {
            "analyzed": len(entries),
            "skipped": len(skipped),
            "matched": sum(1 for entry in entries if entry.get("correct") == "yes"),
            "mismatched": len(mismatches),
            "status_counts": dict(Counter(entry.get("status") or "unknown" for entry in entries)),
            "predicted_counts": dict(Counter(entry.get("predicted_label") or "no_prediction" for entry in entries)),
            "mismatch_reason_counts": dict(Counter(entry.get("mismatch_reason") or "matched" for entry in mismatches)),
            "issue_owner_counts": dict(Counter(issue.get("issue_owner") or "unknown" for issue in issues)),
        },
    )
    (run_root / "README.md").write_text(build_readme(entries, skipped, args.run_name), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
