#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import tarfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VUL_ROOT = Path("/Users/dingyanwen/Desktop/VUL")

TOOL_ITEMS = [
    "README.md",
    "generate_cpgs.sh",
    "PROJECT_RULES.md",
    "docs",
    "c_tools",
    "rust_src",
    "tools",
]

TOOL_EXCLUDES = {
    "output",
    ".git",
    ".DS_Store",
}


def copy_tree(src: Path, dst: Path) -> None:
    if src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=True, ignore=shutil.ignore_patterns("target", "target_cpg", ".DS_Store", "__pycache__"))
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def main() -> int:
    parser = argparse.ArgumentParser(description="Package the analysis tool and selected VUL projects for a Linux server.")
    parser.add_argument("--bundle-root", required=True, help="Directory to create the unpacked bundle in.")
    parser.add_argument("--archive", help="Optional output .tar.gz path.")
    parser.add_argument("--vul-root", default=str(DEFAULT_VUL_ROOT), help="Local VUL root.")
    parser.add_argument("--include", action="append", default=[], help="Project or batch path to copy into VUL/. Repeatable.")
    args = parser.parse_args()

    bundle_root = Path(args.bundle_root).resolve()
    vul_root = Path(args.vul_root).resolve()
    bundle_repo = bundle_root / "cpg_generator_export"
    bundle_vul = bundle_root / "VUL"

    if bundle_root.exists():
        shutil.rmtree(bundle_root)
    bundle_repo.mkdir(parents=True, exist_ok=True)
    bundle_vul.mkdir(parents=True, exist_ok=True)

    for item in TOOL_ITEMS:
        src = REPO_ROOT / item
        if not src.exists() or src.name in TOOL_EXCLUDES:
            continue
        copy_tree(src, bundle_repo / item)

    copied = []
    for raw in args.include:
        src = Path(raw).resolve()
        rel = src.relative_to(vul_root) if src.is_relative_to(vul_root) else Path(src.name)
        dst = bundle_vul / rel
        copy_tree(src, dst)
        copied.append({"src": str(src), "dst": str(dst)})

    manifest = {
        "bundle_root": str(bundle_root),
        "tool_root": str(bundle_repo),
        "vul_root": str(bundle_vul),
        "copied": copied,
    }
    (bundle_root / "BUNDLE_MANIFEST.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.archive:
        archive_path = Path(args.archive).resolve()
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(bundle_root, arcname=bundle_root.name)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
