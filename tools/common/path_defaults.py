from __future__ import annotations

import os
from pathlib import Path


def repo_root_from(file_path: str | Path) -> Path:
    return Path(file_path).resolve().parents[2]


def _candidate_vul_roots(repo_root: Path) -> list[Path]:
    cwd = Path.cwd().resolve()
    return [
        repo_root.parent / "VUL",
        repo_root.parent.parent / "VUL",
        cwd / "VUL",
        repo_root / "VUL",
    ]


def infer_vul_root(repo_root: str | Path) -> Path:
    env_value = os.environ.get("SUPPLYCHAIN_VUL_ROOT")
    if env_value:
        return Path(env_value).expanduser().resolve()
    repo_root_path = Path(repo_root).resolve()
    candidates = _candidate_vul_roots(repo_root_path)
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return candidates[0].resolve()


def infer_archive_root(repo_root: str | Path) -> Path:
    env_value = os.environ.get("SUPPLYCHAIN_ARCHIVE_ROOT")
    if env_value:
        return Path(env_value).expanduser().resolve()
    return (infer_vul_root(repo_root) / "cases" / "by-analysis-status").resolve()

