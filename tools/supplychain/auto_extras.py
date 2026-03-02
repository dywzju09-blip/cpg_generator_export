#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import shutil
from typing import Dict, List, Set, Tuple

SYSTEM_LIB_EXACT = {
    "libc", "libm", "libpthread", "librt", "libdl",
    "libgcc", "libstdc++", "libobjc", "libz", "libiconv",
}

LIB_EXTS = (".so", ".so.", ".dylib")


def run_cmd(cmd: List[str]) -> str:
    out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    return out.decode("utf-8", errors="replace")


def is_system_lib(name: str) -> bool:
    base = os.path.basename(name)
    stem = base
    if stem.endswith(".dylib"):
        stem = stem[:-6]
    if ".so" in stem:
        stem = stem.split(".so")[0]
    if stem.startswith("libSystem"):
        return True
    return stem in SYSTEM_LIB_EXACT


def normalize_lib_name(name: str) -> str:
    base = os.path.basename(name)
    if base.startswith("lib"):
        base = base[3:]
    # strip extensions and version suffixes
    if base.endswith(".dylib"):
        base = base[:-6]
    elif ".so" in base:
        base = base.split(".so")[0]
    return base


def find_lib_files(lib: str, search_dirs: List[str]) -> List[str]:
    matches = []
    patterns = [f"lib{lib}.so", f"lib{lib}.so.", f"lib{lib}.dylib"]
    for d in search_dirs:
        if not d or not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for f in files:
                for p in patterns:
                    if f == p or f.startswith(p):
                        matches.append(os.path.join(root, f))
    return matches


def parse_build_rs(root: str) -> Tuple[Set[str], Set[str]]:
    link_libs: Set[str] = set()
    link_dirs: Set[str] = set()
    for base, _, files in os.walk(root):
        if "build.rs" in files:
            path = os.path.join(base, "build.rs")
            try:
                content = open(path, "r", encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            for m in re.finditer(r"cargo:rustc-link-lib=([^\\n\"]+)", content):
                val = m.group(1).strip()
                # handle static=foo
                if "=" in val:
                    val = val.split("=", 1)[-1]
                if val:
                    link_libs.add(val)
            for m in re.finditer(r"cargo:rustc-link-search=native=([^\\n\"]+)", content):
                d = m.group(1).strip()
                if d:
                    link_dirs.add(d)
    return link_libs, link_dirs


def cargo_root_package(cargo_dir: str) -> str:
    try:
        out = run_cmd(["cargo", "metadata", "--no-deps", "--format-version", "1", "--manifest-path", os.path.join(cargo_dir, "Cargo.toml")])
        data = json.loads(out)
        # prefer workspace root package named "app" or first package
        pkgs = data.get("packages", [])
        if not pkgs:
            return "app"
        for p in pkgs:
            if p.get("name") == "app":
                return "app"
        return pkgs[0].get("name", "app")
    except Exception:
        return "app"


def parse_deps_with_otool(path: str) -> List[str]:
    out = run_cmd(["otool", "-L", path])
    deps = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        dep = line.split(" ", 1)[0]
        deps.append(dep)
    return deps


def parse_deps_with_ldd(path: str) -> List[str]:
    out = run_cmd(["ldd", path])
    deps = []
    for line in out.splitlines():
        line = line.strip()
        if "=>" in line:
            parts = line.split("=>", 1)
            dep = parts[1].strip().split(" ", 1)[0]
            deps.append(dep)
        else:
            # handle direct path lines
            if line.startswith("/"):
                deps.append(line.split(" ", 1)[0])
    return deps


def file_deps(path: str) -> List[str]:
    if shutil.which("otool"):
        return parse_deps_with_otool(path)
    if shutil.which("ldd"):
        return parse_deps_with_ldd(path)
    return []


def detect_version_from_path(path: str) -> str:
    m = re.search(r"(\d+\.\d+\.\d+)", path)
    if m:
        return m.group(1)
    return ""


def detect_abi_version(path: str) -> str:
    if shutil.which("otool"):
        out = run_cmd(["otool", "-L", path])
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            lib = line.split(" ", 1)[0]
            base = os.path.basename(lib)
            m = re.search(r"(\d+\.\d+\.\d+)", base)
            if m:
                return m.group(1)
    if shutil.which("readelf"):
        out = run_cmd(["readelf", "-d", path])
        for line in out.splitlines():
            if "SONAME" in line:
                m = re.search(r"\[(.*?)\]", line)
                if m:
                    name = m.group(1)
                    m2 = re.search(r"(\d+\.\d+\.\d+)", name)
                    if m2:
                        return m2.group(1)
    if shutil.which("objdump"):
        out = run_cmd(["objdump", "-p", path])
        for line in out.splitlines():
            if "SONAME" in line:
                m = re.search(r"(\d+\.\d+\.\d+)", line)
                if m:
                    return m.group(1)
    return ""


def detect_pkg_config_version(lib: str, search_dirs: List[str]) -> str:
    if not shutil.which("pkg-config"):
        return ""
    env = os.environ.copy()
    pc_dirs = []
    for d in search_dirs:
        if not d:
            continue
        pc_dirs.append(os.path.join(d, "pkgconfig"))
        pc_dirs.append(os.path.join(os.path.dirname(d), "lib", "pkgconfig"))
        pc_dirs.append(os.path.join(os.path.dirname(d), "share", "pkgconfig"))
    pc_dirs = [p for p in pc_dirs if os.path.isdir(p)]
    if pc_dirs:
        env["PKG_CONFIG_PATH"] = os.pathsep.join(pc_dirs) + os.pathsep + env.get("PKG_CONFIG_PATH", "")
    try:
        out = subprocess.check_output(["pkg-config", "--modversion", lib], env=env, stderr=subprocess.DEVNULL)
        return out.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def main():
    parser = argparse.ArgumentParser(description="Auto-generate supplychain extras from build.rs and .so deps")
    parser.add_argument("--cargo-dir", required=True, help="Cargo workspace directory")
    parser.add_argument("--root", default=None, help="Root package name override")
    parser.add_argument("--so-dir", action="append", default=[], help="Directory to search for .so/.dylib (repeatable)")
    parser.add_argument("--out", required=True, help="Output extras JSON")
    parser.add_argument("--include", action="append", default=[], help="Force include extra lib names")
    parser.add_argument("--ignore", action="append", default=[], help="Ignore lib name prefixes")
    args = parser.parse_args()

    cargo_dir = os.path.abspath(args.cargo_dir)
    root_pkg = args.root or cargo_root_package(cargo_dir)

    link_libs, link_dirs = parse_build_rs(cargo_dir)
    for lib in args.include:
        link_libs.add(lib)

    search_dirs = list(args.so_dir) + list(link_dirs)

    lib_to_file: Dict[str, str] = {}
    for lib in sorted(link_libs):
        files = find_lib_files(lib, search_dirs)
        if files:
            lib_to_file[lib] = files[0]

    # build dependency graph among libs (recursive .so/.dylib traversal)
    deps: Set[Tuple[str, str]] = set()
    packages: Dict[str, Dict] = {}

    def add_pkg(name: str, version_hint: str = "", version_source: str = "", abi_version: str = ""):
        if name in packages:
            return
        pkg = {"name": name, "lang": "C"}
        if version_hint:
            pkg["version"] = version_hint
        if version_source:
            pkg["version_source"] = version_source
        if abi_version:
            pkg["abi_version"] = abi_version
        packages[name] = pkg

    # add direct linked libs as packages
    for lib, path in lib_to_file.items():
        ver = detect_version_from_path(path)
        source = "path" if ver else ""
        if not ver:
            ver = detect_pkg_config_version(lib, search_dirs)
            if ver:
                source = "pkg-config"
        abi = detect_abi_version(path)
        if not ver and abi:
            source = "soname"
        add_pkg(lib, ver, source, abi)

    queue: List[Tuple[str, str]] = list(lib_to_file.items())
    visited: Set[str] = set()

    while queue:
        lib, path = queue.pop(0)
        if lib in visited:
            continue
        visited.add(lib)

        dep_paths = file_deps(path)
        for dep in dep_paths:
            base = os.path.basename(dep)
            if not base:
                continue
            if is_system_lib(base):
                continue
            dep_name = normalize_lib_name(base)
            if not dep_name or dep_name in args.ignore:
                continue
            if dep_name == lib:
                continue

            dep_path = dep if dep.startswith("/") and os.path.exists(dep) else None
            if not dep_path:
                found = find_lib_files(dep_name, search_dirs)
                dep_path = found[0] if found else None

            dep_ver = detect_version_from_path(dep if dep_path is None else dep_path)
            dep_source = "path" if dep_ver else ""
            if not dep_ver:
                dep_ver = detect_pkg_config_version(dep_name, search_dirs)
                if dep_ver:
                    dep_source = "pkg-config"
            dep_abi = detect_abi_version(dep_path) if dep_path else ""
            if not dep_ver and dep_abi:
                dep_source = "soname"
            add_pkg(dep_name, dep_ver, dep_source, dep_abi)
            deps.add((lib, dep_name))

            if dep_path and dep_name not in lib_to_file:
                lib_to_file[dep_name] = dep_path
                queue.append((dep_name, dep_path))

    # root -> top-level libs (those not depended on by other linked libs)
    depended = {d for (_, d) in deps}
    for lib in lib_to_file.keys():
        if lib not in depended:
            deps.add((root_pkg, lib))

    # build output
    out = {
        "packages": list(packages.values()),
        "depends": [{"from": a, "to": b} for (a, b) in sorted(deps)]
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)

    print(f"[+] Wrote extras: {args.out}")


if __name__ == "__main__":
    main()
