from neo4j import GraphDatabase
import argparse
import copy
import glob
import json
import os
import re
import sys
import subprocess
import hashlib
from pathlib import Path

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from tools.neo4j.config import neo4j_auth, neo4j_uri
from tools.supplychain.vuln_db import default_component_kb_path, default_runtime_rules_path

try:
    from tools.verification.path_solver import PathConstraintSolver, extract_numeric_constraints
except Exception:
    PathConstraintSolver = None
    extract_numeric_constraints = None

try:
    from tools.verification.constraint_extractor import build_path_constraint_bundle
except Exception:
    build_path_constraint_bundle = None

try:
    from tools.verification.abi_contracts import build_abi_contracts
except Exception:
    build_abi_contracts = None

try:
    from tools.verification.param_semantics import evaluate_param_semantics
except Exception:
    evaluate_param_semantics = None

try:
    from tools.verification.state_semantics import (
        evaluate_state_semantics,
        has_state_semantics_rules,
    )
except Exception:
    evaluate_state_semantics = None
    has_state_semantics_rules = None

try:
    from tools.fetch.native_source_resolver import (
        choose_c_analysis_scope,
        choose_c_analysis_scope_from_relative_paths,
        ensure_native_source_tree,
        find_symbol_definition_files,
        find_symbol_source_files,
        infer_native_source_dependencies,
    )
except Exception:
    choose_c_analysis_scope = None
    choose_c_analysis_scope_from_relative_paths = None
    ensure_native_source_tree = None
    find_symbol_definition_files = None
    find_symbol_source_files = None
    infer_native_source_dependencies = None

try:
    from tools.fetch.native_symbol_resolver import resolve_strict_native_dependencies
except Exception:
    resolve_strict_native_dependencies = None

# Neo4j configuration
URI = neo4j_uri()
AUTH = neo4j_auth()

DEFAULT_DEPS = ""
DEFAULT_VULNS = str(default_runtime_rules_path().relative_to(REPO_ROOT))
DEFAULT_REPORT = "output/analysis_report.json"
DEFAULT_SINK_KB = str(default_component_kb_path().relative_to(REPO_ROOT))

SUPPLYCHAIN_REL_TYPES = [
    "DEPENDS_ON", "HAS_VERSION", "EXPOSES_VULN",
    "PROVIDES_SYMBOL", "RESOLVES_TO", "USES_SYMBOL", "PKG_CALL",
    "NATIVE_DEPENDS_ON", "NATIVE_CALL",
    "HAS_BINARY", "EXPORTS_SYMBOL", "IMPORTS_SYMBOL", "RESOLVES_EXTERN_TO", "RESOLVES_TO_EXPORT",
]

def parse_version(v):
    parts = []
    for p in str(v).split("."):
        try:
            parts.append(int(p))
        except:
            parts.append(0)
    return tuple(parts)

def cmp_version(a, b):
    a_t = parse_version(a)
    b_t = parse_version(b)
    max_len = max(len(a_t), len(b_t))
    a_t = a_t + (0,) * (max_len - len(a_t))
    b_t = b_t + (0,) * (max_len - len(b_t))
    if a_t < b_t:
        return -1
    if a_t > b_t:
        return 1
    return 0

def version_in_range(version, range_expr):
    if not range_expr:
        return True
    groups = [group.strip() for group in str(range_expr).split("||") if group.strip()]
    if not groups:
        groups = [str(range_expr)]
    for group in groups:
        matched = True
        clauses = [c.strip() for c in group.split(",") if c.strip()]
        for clause in clauses:
            if clause.startswith(">="):
                if cmp_version(version, clause[2:]) < 0:
                    matched = False
                    break
            elif clause.startswith(">"):
                if cmp_version(version, clause[1:]) <= 0:
                    matched = False
                    break
            elif clause.startswith("<="):
                if cmp_version(version, clause[2:]) > 0:
                    matched = False
                    break
            elif clause.startswith("<"):
                if cmp_version(version, clause[1:]) >= 0:
                    matched = False
                    break
            elif clause.startswith("=="):
                if cmp_version(version, clause[2:]) != 0:
                    matched = False
                    break
            else:
                # Fallback: exact match
                if cmp_version(version, clause) != 0:
                    matched = False
                    break
        if matched:
            return True
    return False

def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def load_manual_evidence(path):
    if not path:
        return []
    try:
        payload = load_json(path)
    except FileNotFoundError:
        return []
    except Exception:
        return []
    if isinstance(payload, list):
        entries = payload
    elif isinstance(payload, dict):
        entries = payload.get("entries") or payload.get("items") or [payload]
    else:
        entries = []
    return [item for item in entries if isinstance(item, dict)]

def _split_feature_list(text):
    items = []
    seen = set()
    raw = str(text or "")
    for token in re.split(r"[,\s]+", raw):
        feat = token.strip()
        if not feat:
            continue
        if feat in seen:
            continue
        seen.add(feat)
        items.append(feat)
    return items


def _normalize_native_crate_name(name):
    text = str(name or "").strip().lower().replace("_", "-")
    if not text:
        return ""
    text = re.sub(r"-(sys|src|bindings)\d*$", "", text)
    text = re.sub(r"-(ffi)\d*$", "", text)
    return text


def _candidate_native_crate_aliases(name):
    raw = str(name or "").strip()
    if not raw:
        return []
    norm = raw.lower().replace("_", "-")
    out = [norm]
    out.append(_normalize_native_crate_name(norm))
    underscored = norm.replace("-", "_")
    out.append(underscored)
    out.append(_normalize_native_crate_name(norm).replace("-", "_"))
    base = _normalize_native_crate_name(norm)
    if base.startswith("lib") and len(base) > 3:
        short = base[3:]
        out.extend([short, short.replace("-", "_")])
    return list(dict.fromkeys([item for item in out if item]))


def _root_package_has_feature_variants(meta):
    root_pkg = _metadata_root_package(meta)
    if not root_pkg:
        return False
    if root_pkg.get("features"):
        return True
    for dep in root_pkg.get("dependencies") or []:
        if dep.get("optional"):
            return True
    return False


def maybe_collect_expanded_feature_deps(cargo_dir, meta, *, cargo_features="", cargo_all_features=False, cargo_no_default_features=False):
    if cargo_all_features or cargo_no_default_features:
        return None
    if not _root_package_has_feature_variants(meta):
        return None
    try:
        expanded_meta = run_metadata(
            cargo_dir,
            cargo_features=cargo_features,
            cargo_all_features=True,
            cargo_no_default_features=False,
        )
    except Exception:
        return None
    return {
        "meta": expanded_meta,
        "deps": build_deps_from_cargo(expanded_meta),
        "root_enabled_features": _metadata_enabled_features(
            expanded_meta,
            (_metadata_root_package(expanded_meta) or {}).get("id"),
        ),
    }


def _analysis_base_env(base_env=None):
    env = dict(base_env or os.environ)
    env.setdefault("RUSTUP_TOOLCHAIN", "stable")

    toolchain_name = env.get("RUSTUP_TOOLCHAIN") or "stable"
    toolchain_lib = os.path.expanduser(f"~/.rustup/toolchains/{toolchain_name}-x86_64-unknown-linux-gnu/lib")
    linker_candidates = []
    if os.path.isdir(toolchain_lib):
        linker_candidates.append(toolchain_lib)

    gcc_runtime_globs = [
        "/usr/lib/gcc/x86_64-linux-gnu/*",
        "/usr/lib/gcc/*/*",
    ]
    for pattern in gcc_runtime_globs:
        for candidate in sorted(glob.glob(pattern), reverse=True):
            if os.path.isdir(candidate):
                linker_candidates.append(candidate)
                break

    for candidate in [
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib64",
        "/usr/lib",
        "/lib/x86_64-linux-gnu",
        "/lib64",
        "/lib",
    ]:
        if os.path.isdir(candidate):
            linker_candidates.append(candidate)

    dedup_linker = []
    for candidate in linker_candidates:
        if candidate and candidate not in dedup_linker:
            dedup_linker.append(candidate)

    existing_library = [p for p in str(env.get("LIBRARY_PATH") or "").split(":") if p]
    merged_library = []
    # Preserve caller-provided library search paths ahead of system defaults.
    for candidate in existing_library + dedup_linker:
        if candidate and candidate not in merged_library and os.path.isdir(candidate):
            merged_library.append(candidate)
    if merged_library:
        env["LIBRARY_PATH"] = ":".join(merged_library)

    existing_ld = [p for p in str(env.get("LD_LIBRARY_PATH") or "").split(":") if p]
    merged_ld = []
    for candidate in existing_ld + dedup_linker:
        if candidate and candidate not in merged_ld and os.path.isdir(candidate):
            merged_ld.append(candidate)
    if merged_ld:
        env["LD_LIBRARY_PATH"] = ":".join(merged_ld)

    rustflag_parts = [part for part in str(env.get("RUSTFLAGS") or "").split() if part]
    # for candidate in merged_library:
    #     token = f"native={candidate}"
    #     if token in rustflag_parts:
    #         continue
    #     rustflag_parts.extend(["-L", token])
    # if rustflag_parts:
    #     env["RUSTFLAGS"] = " ".join(rustflag_parts)

    pkg_config_candidates = [
        "/usr/lib/x86_64-linux-gnu/pkgconfig",
        "/usr/lib/pkgconfig",
        "/usr/share/pkgconfig",
    ]
    existing_pkg = [p for p in str(env.get("PKG_CONFIG_PATH") or "").split(":") if p]
    merged_pkg = []
    # Preserve caller-provided pkg-config roots ahead of system pkg-config roots.
    for candidate in existing_pkg + pkg_config_candidates:
        if candidate and candidate not in merged_pkg and os.path.isdir(candidate):
            merged_pkg.append(candidate)
    if merged_pkg:
        env["PKG_CONFIG_PATH"] = ":".join(merged_pkg)

    cmake_candidates = [p for p in ["/usr", "/usr/local"] if os.path.isdir(p)]
    existing_cmake = [p for p in str(env.get("CMAKE_PREFIX_PATH") or "").split(":") if p]
    merged_cmake = []
    for candidate in existing_cmake + cmake_candidates:
        if candidate and candidate not in merged_cmake:
            merged_cmake.append(candidate)
    if merged_cmake:
        env["CMAKE_PREFIX_PATH"] = ":".join(merged_cmake)

    llvm_config_candidates = [
        "/usr/bin/llvm-config",
        "/usr/bin/llvm-config-18",
        "/usr/bin/llvm-config-14",
        "/usr/lib/llvm-18/bin/llvm-config",
        "/usr/lib/llvm-14/bin/llvm-config",
    ]
    if not str(env.get("LLVM_CONFIG_PATH") or "").strip():
        for candidate in llvm_config_candidates:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                env["LLVM_CONFIG_PATH"] = candidate
                break

    libclang_candidates = [
        "/usr/lib/llvm-18/lib",
        "/usr/lib/llvm-14/lib",
        "/usr/lib/x86_64-linux-gnu",
    ]
    if not str(env.get("LIBCLANG_PATH") or "").strip():
        for candidate in libclang_candidates:
            if os.path.isdir(candidate):
                env["LIBCLANG_PATH"] = candidate
                break

    llvm_bin_candidates = [
        "/usr/lib/llvm-18/bin",
        "/usr/lib/llvm-14/bin",
    ]
    existing_path = [p for p in str(env.get("PATH") or "").split(":") if p]
    merged_path = []
    for candidate in existing_path + llvm_bin_candidates:
        if candidate and candidate not in merged_path and os.path.isdir(candidate):
            merged_path.append(candidate)
    if merged_path:
        env["PATH"] = ":".join(merged_path)

    return env


def run_metadata(cargo_dir, cargo_features="", cargo_all_features=False, cargo_no_default_features=False):
    cmd = ["cargo", "metadata", "--format-version", "1"]
    if cargo_all_features:
        cmd.append("--all-features")
    else:
        feature_items = _split_feature_list(cargo_features)
        if feature_items:
            cmd.extend(["--features", ",".join(feature_items)])
    if cargo_no_default_features:
        cmd.append("--no-default-features")
    res = subprocess.run(cmd, cwd=cargo_dir, env=_analysis_base_env(), capture_output=True, text=True)
    if res.returncode != 0:
        print(res.stderr)
        raise RuntimeError("cargo metadata failed")
    return json.loads(res.stdout)


def _run_cmd(cmd, cwd=None, env=None, label="command"):
    res = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if res.returncode != 0:
        out = (res.stdout or "").strip()
        err = (res.stderr or "").strip()
        raise RuntimeError(
            f"{label} failed (exit={res.returncode})\ncmd: {' '.join(cmd)}\nstdout:\n{out}\nstderr:\n{err}"
        )
    return res


def _safe_is_relative_to(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except Exception:
        return False


def _placeholder_text_for_path(path):
    suffix = str(Path(path).suffix or "").lower()
    if suffix == ".css":
        return "/* analysis placeholder */\n"
    if suffix in {".json", ".ron"}:
        return "{}\n"
    if suffix in {".toml"}:
        return "# analysis placeholder\n"
    return "analysis placeholder\n"


def _extract_missing_include_paths(stderr_text, cargo_dir):
    missing = []
    cargo_root = Path(cargo_dir).resolve()
    for match in re.finditer(r"couldn't read `([^`]+)`", str(stderr_text or "")):
        raw_path = match.group(1).strip()
        if not raw_path:
            continue
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = cargo_root / candidate
        candidate = candidate.resolve()
        if candidate.exists():
            continue
        if not _safe_is_relative_to(candidate, cargo_root):
            continue
        missing.append(candidate)
    unique = []
    seen = set()
    for path in missing:
        key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def _create_placeholder_include_files(paths):
    created = []
    for path in paths:
        try:
            if path.exists():
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_placeholder_text_for_path(path), encoding="utf-8")
            created.append(str(path))
        except Exception:
            continue
    return created


def _build_cargo_feature_args(cargo_features="", cargo_all_features=False, cargo_no_default_features=False):
    args = []
    if cargo_all_features:
        args.append("--all-features")
    else:
        features = _split_feature_list(cargo_features)
        if features:
            args.extend(["--features", ",".join(features)])
    if cargo_no_default_features:
        args.append("--no-default-features")
    return args


def _extract_out_dir_relpaths_from_text(text):
    if 'env!("OUT_DIR")' not in text:
        return []
    rels = []
    for match in re.finditer(r'env!\("OUT_DIR"\)\s*,\s*"(/[^"]+)"', text):
        rels.append(match.group(1).lstrip("/"))
    return list(dict.fromkeys([r for r in rels if r]))


def _extract_out_dir_relpaths(input_file):
    try:
        text = open(input_file, "r", encoding="utf-8", errors="ignore").read()
    except Exception:
        return []
    return _extract_out_dir_relpaths_from_text(text)


def _extract_out_dir_relpaths_from_crate(cargo_dir, input_file, max_files=400):
    rels = _extract_out_dir_relpaths(input_file)
    src_root = Path(cargo_dir) / "src"
    if not src_root.exists():
        return rels
    scanned = 0
    for path in src_root.rglob("*.rs"):
        if scanned >= max_files:
            break
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rels.extend(_extract_out_dir_relpaths_from_text(text))
    return list(dict.fromkeys([r for r in rels if r]))


def _find_generator_out_dir(input_file, target_dir, cargo_dir=""):
    rels = _extract_out_dir_relpaths_from_crate(cargo_dir, input_file) if cargo_dir else _extract_out_dir_relpaths(input_file)
    build_root = os.path.join(target_dir, "debug", "build")
    if not os.path.isdir(build_root):
        return ""

    out_dirs = []
    for base, dirnames, _ in os.walk(build_root):
        if os.path.basename(base) == "out":
            out_dirs.append(base)
    if not out_dirs:
        return ""

    if rels:
        matches = []
        for out_dir in out_dirs:
            if all(os.path.exists(os.path.join(out_dir, rel)) for rel in rels):
                matches.append(out_dir)
        if len(matches) == 1:
            return matches[0]
        if matches:
            return sorted(matches, key=len)[0]

    if len(out_dirs) == 1:
        return out_dirs[0]
    return ""


def _metadata_root_package(meta):
    id_to_pkg = {p.get("id"): p for p in (meta.get("packages") or [])}
    root_ids = list(meta.get("workspace_default_members") or [])
    if root_ids:
        return id_to_pkg.get(root_ids[0])
    if meta.get("packages"):
        return meta["packages"][0]
    return None


def _metadata_enabled_features(meta, package_id):
    if not package_id:
        return []
    for node in (meta.get("resolve", {}) or {}).get("nodes", []) or []:
        if node.get("id") == package_id:
            return list(node.get("features") or [])
    return []


def _pick_rust_input_file(meta, cargo_dir, explicit_input="", prefer_main=True):
    if explicit_input:
        p = os.path.abspath(explicit_input)
        if not os.path.exists(p):
            raise RuntimeError(f"cpg input file does not exist: {p}")
        return p
    root_pkg = _metadata_root_package(meta)
    if not root_pkg:
        raise RuntimeError("cannot infer root package from cargo metadata")
    targets = list(root_pkg.get("targets") or [])
    if not targets:
        raise RuntimeError("root package has no targets")

    bins = [t for t in targets if "bin" in (t.get("kind") or [])]
    libs = [t for t in targets if "lib" in (t.get("kind") or [])]
    chosen = None
    if prefer_main:
        main_bins = [t for t in bins if os.path.basename(str(t.get("src_path") or "")) == "main.rs"]
        chosen = main_bins[0] if main_bins else (bins[0] if bins else None)
    if not chosen:
        chosen = libs[0] if libs else (bins[0] if bins else targets[0])
    src_path = str(chosen.get("src_path") or "").strip()
    if not src_path:
        raise RuntimeError("failed to infer rust input file from cargo targets")
    if not os.path.isabs(src_path):
        src_path = os.path.join(cargo_dir, src_path)
    src_path = os.path.abspath(src_path)
    if not os.path.exists(src_path):
        raise RuntimeError(f"inferred rust input file missing: {src_path}")
    return src_path


def _collect_extern_artifacts(deps_dir):
    externs = {}
    patterns = ["lib*.rlib", "lib*.so", "lib*.dylib"]
    for pattern in patterns:
        for artifact in sorted(glob.glob(os.path.join(deps_dir, pattern))):
            base = os.path.basename(artifact)
            name = base[3:]
            if "." in name:
                name = name.split(".", 1)[0]
            if "-" in name:
                name = name.split("-", 1)[0]
            if name not in externs:
                externs[name] = artifact
    return externs


def _normalize_crate_ident(name):
    text = str(name or "").strip()
    if not text:
        return ""
    text = text.replace("-", "_")
    text = re.sub(r"[^A-Za-z0-9_]", "_", text)
    return text


def _collect_dependency_rename_externs(meta, root_pkg, extern_artifacts):
    rename_map = {}
    if not isinstance(root_pkg, dict):
        return rename_map

    pkg_rows = list((meta or {}).get("packages") or [])
    by_name = {}
    for pkg in pkg_rows:
        name = str(pkg.get("name") or "").strip()
        if not name:
            continue
        by_name.setdefault(name, []).append(pkg)

    for dep in root_pkg.get("dependencies") or []:
        dep_name = str(dep.get("name") or "").strip()
        dep_rename = str(dep.get("rename") or "").strip()
        if not dep_name or not dep_rename:
            continue

        alias = _normalize_crate_ident(dep_rename)
        if not alias:
            continue

        candidates = []
        for row in by_name.get(dep_name, []):
            for target in row.get("targets") or []:
                kinds = set(target.get("kind") or [])
                if kinds & {"lib", "rlib", "dylib", "staticlib", "cdylib", "proc-macro"}:
                    tname = _normalize_crate_ident(target.get("name"))
                    if tname:
                        candidates.append(tname)
        dep_norm = _normalize_crate_ident(dep_name)
        if dep_norm:
            candidates.append(dep_norm)

        for key in list(dict.fromkeys(candidates)):
            artifact = extern_artifacts.get(key)
            if artifact:
                rename_map[alias] = artifact
                break
    return rename_map


def _extract_stablecrateid_conflicts(stderr_text):
    pairs = []
    for match in re.finditer(r"found crates \(`([^`]+)` and `([^`]+)`\) with colliding StableCrateId values", str(stderr_text or ""), re.I):
        left = match.group(1).strip()
        right = match.group(2).strip()
        if left and right:
            pairs.append((left, right))
    return pairs


def _select_prunable_stablecrateid_conflicts(conflict_pairs):
    removable = []
    for left, right in conflict_pairs:
        if left == right:
            if left.endswith("_core"):
                removable.append(left)
            continue
        for candidate in [left, right]:
            if candidate.endswith("_core"):
                removable.append(candidate)
    return list(dict.fromkeys(removable))


def _ensure_rust_cpg_generator(generator_bin):
    if os.path.exists(generator_bin):
        return
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    manifest = os.path.join(root, "rust_src", "Cargo.toml")
    if not os.path.exists(manifest):
        raise RuntimeError(f"rust-cpg-generator manifest not found: {manifest}")
    build_env = _analysis_base_env()
    build_env.setdefault("RUSTC_BOOTSTRAP", "1")
    _run_cmd(
        ["cargo", "build", "--release", "--manifest-path", manifest],
        cwd=root,
        env=build_env,
        label="build rust-cpg-generator",
    )
    if not os.path.exists(generator_bin):
        raise RuntimeError(f"rust-cpg-generator build finished but binary missing: {generator_bin}")


def _prepare_rustc_dynlib_env(base_env=None):
    env = dict(base_env or os.environ)
    try:
        sysroot = subprocess.run(
            ["rustc", "--print", "sysroot"],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        host = ""
        for line in subprocess.run(
            ["rustc", "-vV"],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines():
            if line.startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        if sysroot and host:
            sysroot_lib = os.path.join(sysroot, "lib")
            rustc_lib = os.path.join(sysroot, "lib", "rustlib", host, "lib")
            dylib_paths = []
            for candidate in [sysroot_lib, rustc_lib]:
                if os.path.isdir(candidate) and candidate not in dylib_paths:
                    dylib_paths.append(candidate)
            if dylib_paths:
                dyld_prev = [p for p in str(env.get("DYLD_LIBRARY_PATH") or "").split(":") if p]
                ld_prev = [p for p in str(env.get("LD_LIBRARY_PATH") or "").split(":") if p]
                env["DYLD_LIBRARY_PATH"] = ":".join(dylib_paths + [p for p in dyld_prev if p not in dylib_paths])
                env["LD_LIBRARY_PATH"] = ":".join(dylib_paths + [p for p in ld_prev if p not in dylib_paths])
    except Exception:
        pass
    return env


def generate_rust_cpg_for_cargo(
    cargo_dir,
    meta,
    cpg_input="",
    output_dir="",
    cargo_features="",
    cargo_all_features=False,
    cargo_no_default_features=False,
):
    root_pkg = _metadata_root_package(meta)
    if not root_pkg:
        raise RuntimeError("cannot resolve root package for CPG generation")
    root_pkg_id = root_pkg.get("id")
    root_pkg_name = str(root_pkg.get("name") or "crate")
    root_pkg_version = str(root_pkg.get("version") or "0.0.0")
    root_pkg_authors = ";".join(root_pkg.get("authors") or [])
    root_pkg_description = str(root_pkg.get("description") or "")
    root_pkg_homepage = str(root_pkg.get("homepage") or "")
    root_pkg_repository = str(root_pkg.get("repository") or "")
    root_pkg_license = str(root_pkg.get("license") or "")
    root_pkg_license_file = str(root_pkg.get("license_file") or "")
    root_manifest = str(root_pkg.get("manifest_path") or "")
    root_manifest_dir = os.path.dirname(root_manifest) if root_manifest else os.path.abspath(cargo_dir)
    edition = str(root_pkg.get("edition") or "2021")
    enabled_features = _metadata_enabled_features(meta, root_pkg_id)

    input_file = _pick_rust_input_file(meta, cargo_dir, explicit_input=cpg_input, prefer_main=False)
    if not output_dir:
        output_dir = os.path.join(cargo_dir, ".cpg")
    os.makedirs(output_dir, exist_ok=True)
    cpg_json = os.path.join(output_dir, "cpg_final.json")

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    generator_bin = os.path.join(repo_root, "rust_src", "target", "release", "rust-cpg-generator")
    _ensure_rust_cpg_generator(generator_bin)

    target_dir_name = os.environ.get("SUPPLYCHAIN_CARGO_TARGET_DIR_NAME", "target_cpg_analysis")
    target_dir = os.path.join(cargo_dir, target_dir_name)
    deps_dir = os.path.join(target_dir, "debug", "deps")
    created_placeholder_files = []
    build_cmd = [
        "cargo",
        "build",
        "--manifest-path",
        os.path.join(cargo_dir, "Cargo.toml"),
    ] + _build_cargo_feature_args(
        cargo_features=cargo_features,
        cargo_all_features=cargo_all_features,
        cargo_no_default_features=cargo_no_default_features,
    )
    build_env = _analysis_base_env()
    build_env["CARGO_TARGET_DIR"] = target_dir
    try:
        try:
            _run_cmd(build_cmd, cwd=cargo_dir, env=build_env, label="cargo build for CPG deps")
        except RuntimeError as exc:
            missing_paths = _extract_missing_include_paths(str(exc), cargo_dir)
            if not missing_paths:
                raise
            created_placeholder_files.extend(_create_placeholder_include_files(missing_paths))
            if created_placeholder_files:
                print(
                    "[analysis-support] created placeholder include files for cargo build retry: "
                    + ", ".join(created_placeholder_files),
                    file=sys.stderr,
                )
            _run_cmd(build_cmd, cwd=cargo_dir, env=build_env, label="cargo build for CPG deps (after placeholder retry)")

        extern_artifacts = _collect_extern_artifacts(deps_dir)
        if not extern_artifacts:
            raise RuntimeError(f"no dependency artifacts found for CPG generation under: {deps_dir}")

        gen_env = dict(os.environ)
        gen_env.setdefault("RUSTUP_TOOLCHAIN", os.environ.get("SUPPLYCHAIN_CPG_TOOLCHAIN", "stable"))
        gen_env.setdefault("RUSTC_BOOTSTRAP", "1")
        gen_env["CARGO_PKG_VERSION"] = root_pkg_version
        gen_env["CARGO_PKG_NAME"] = root_pkg_name
        gen_env["CARGO_PKG_AUTHORS"] = root_pkg_authors
        gen_env["CARGO_PKG_DESCRIPTION"] = root_pkg_description
        gen_env["CARGO_PKG_HOMEPAGE"] = root_pkg_homepage
        gen_env["CARGO_PKG_REPOSITORY"] = root_pkg_repository
        gen_env["CARGO_PKG_LICENSE"] = root_pkg_license
        gen_env["CARGO_PKG_LICENSE_FILE"] = root_pkg_license_file
        parts = root_pkg_version.split("-", 1)
        core = parts[0]
        pre = parts[1] if len(parts) > 1 else ""
        core_items = core.split(".")
        gen_env["CARGO_PKG_VERSION_MAJOR"] = core_items[0] if len(core_items) >= 1 else "0"
        gen_env["CARGO_PKG_VERSION_MINOR"] = core_items[1] if len(core_items) >= 2 else "0"
        gen_env["CARGO_PKG_VERSION_PATCH"] = core_items[2] if len(core_items) >= 3 else "0"
        gen_env["CARGO_PKG_VERSION_PRE"] = pre
        gen_env["CARGO_MANIFEST_DIR"] = root_manifest_dir
        out_dir = _find_generator_out_dir(input_file, target_dir, cargo_dir=cargo_dir)
        if out_dir:
            gen_env.setdefault("OUT_DIR", out_dir)
        gen_env = _prepare_rustc_dynlib_env(gen_env)

        dep_rename_externs = _collect_dependency_rename_externs(meta, root_pkg, extern_artifacts)
        active_externs = dict(extern_artifacts)
        for alias, artifact in dep_rename_externs.items():
            active_externs.setdefault(alias, artifact)
        pruned_externs = []
        while True:
            rustc_args = [
                f"--edition={edition}",
                "-L",
                f"dependency={deps_dir}",
            ]
            for feat in enabled_features:
                feat_text = str(feat or "").strip()
                if not feat_text:
                    continue
                rustc_args.extend(["--cfg", f'feature="{feat_text}"'])
            for name, artifact in active_externs.items():
                rustc_args.extend(["--extern", f"{name}={artifact}"])

            gen_cmd = [generator_bin, "--input", input_file, "--output", cpg_json]
            for arg in rustc_args:
                gen_cmd.extend(["--rustc-arg", arg])
            try:
                _run_cmd(gen_cmd, cwd=cargo_dir, env=gen_env, label="rust-cpg-generator")
                break
            except RuntimeError as exc:
                conflicts = _extract_stablecrateid_conflicts(str(exc))
                removable = [crate for crate in _select_prunable_stablecrateid_conflicts(conflicts) if crate in active_externs]
                if not removable:
                    raise
                for crate in removable:
                    pruned_externs.append(crate)
                    active_externs.pop(crate, None)
                print(
                    "[analysis-support] pruned externs after StableCrateId collision: "
                    + ", ".join(removable),
                    file=sys.stderr,
                )

        if not os.path.exists(cpg_json):
            raise RuntimeError(f"CPG generation finished but output missing: {cpg_json}")
        return {
            "cpg_json": cpg_json,
            "input_file": input_file,
            "edition": edition,
            "enabled_features": enabled_features,
            "extern_count": len(active_externs),
            "placeholder_files": created_placeholder_files,
            "pruned_externs": pruned_externs,
        }
    finally:
        for path in reversed(created_placeholder_files):
            try:
                Path(path).unlink(missing_ok=True)
            except Exception:
                pass


def import_rust_cpg_json(cpg_json_path, clear_db=True):
    from tools.neo4j.import_cpg import import_json_to_neo4j
    import_json_to_neo4j(cpg_json_path, clear_db=clear_db, id_offset=0, label_tag="Rust")


def import_c_cpg_json(cpg_json_path, clear_db=False, id_offset=0):
    from tools.neo4j.import_cpg import import_json_to_neo4j
    import_json_to_neo4j(cpg_json_path, clear_db=clear_db, id_offset=id_offset, label_tag="C")


def _next_graph_id(session):
    record = session.run("MATCH (n) RETURN coalesce(max(n.id), 0) AS max_id").single()
    return int((record or {}).get("max_id") or 0)


def _cpg_import_bounds(cpg_json_path, id_offset):
    data = load_json(cpg_json_path)
    node_ids = [int(node.get("id")) for node in (data.get("nodes") or []) if node.get("id") is not None]
    if not node_ids:
        return (id_offset, id_offset)
    return (id_offset + min(node_ids), id_offset + max(node_ids))


def annotate_imported_c_nodes(
    session,
    lower_id,
    upper_id,
    *,
    component,
    resolved_version,
    source_status,
    source_root,
    provenance,
):
    session.run(
        """
        MATCH (n:C)
        WHERE n.id >= $lower AND n.id <= $upper
        SET n.package = coalesce(n.package, $component),
            n.source_status = $source_status,
            n.source_root = $source_root,
            n.source_provenance = $provenance,
            n.component_version = $resolved_version
        """,
        lower=int(lower_id),
        upper=int(upper_id),
        component=component,
        resolved_version=resolved_version,
        source_status=source_status,
        source_root=source_root,
        provenance=provenance,
    )


def ensure_package_version_node(session, package_name, *, lang="C", version=None, version_source="", extra_props=None):
    props = dict(extra_props or {})
    session.run(
        """
        MERGE (p:PACKAGE {name: $name})
        SET p.lang = coalesce(p.lang, $lang)
        SET p += $props
        """,
        name=package_name,
        lang=lang,
        props=props,
    )
    if version:
        session.run(
            """
            MERGE (v:VERSION {semver: $version})
            WITH v
            MATCH (p:PACKAGE {name: $name})
            MERGE (p)-[:HAS_VERSION]->(v)
            SET v.source = coalesce(v.source, $version_source)
            """,
            name=package_name,
            version=version,
            version_source=version_source or "",
        )


def attach_vulnerability_to_component(session, vuln_rule, component, resolved_version):
    cve = str(vuln_rule.get("cve") or "").strip()
    if not cve or not component:
        return
    ensure_package_version_node(session, component, lang="C", version=resolved_version or None, version_source="native-source")
    if resolved_version and version_in_range(resolved_version, vuln_rule.get("version_range", "")):
        session.run(
            """
            MATCH (p:PACKAGE {name: $pkg})
            MATCH (vuln:VULNERABILITY {cve: $cve})
            MATCH (ver:VERSION {semver: $ver})
            MERGE (p)-[:HAS_VERSION]->(ver)
            MERGE (ver)-[:EXPOSES_VULN]->(vuln)
            """,
            pkg=component,
            cve=cve,
            ver=resolved_version,
        )
    else:
        session.run(
            """
            MATCH (p:PACKAGE {name: $pkg})
            MATCH (vuln:VULNERABILITY {cve: $cve})
            MERGE (p)-[:EXPOSES_VULN]->(vuln)
            """,
            pkg=component,
            cve=cve,
        )


def create_native_depends_on(session, parent_component, child_component, *, evidence_type="source-scan", confidence="medium", source="native-source", evidence=""):
    if not parent_component or not child_component or parent_component == child_component:
        return
    ensure_package_version_node(session, parent_component, lang="C")
    ensure_package_version_node(session, child_component, lang="C")
    session.run(
        """
        MATCH (a:PACKAGE {name: $parent})
        MATCH (b:PACKAGE {name: $child})
        MERGE (a)-[r:NATIVE_DEPENDS_ON]->(b)
        SET r.evidence_type = coalesce(r.evidence_type, $evidence_type),
            r.confidence = coalesce(r.confidence, $confidence),
            r.source = coalesce(r.source, $source),
            r.evidence = coalesce(r.evidence, $evidence)
        """,
        parent=parent_component,
        child=child_component,
        evidence_type=evidence_type,
        confidence=confidence,
        source=source,
        evidence=evidence or "",
    )


def build_native_pkg_edges(session):
    session.run(
        """
        MATCH (owner:METHOD:C)-[:AST*0..40]->(call:CALL:C)-[:CALL]->(callee:METHOD:C)
        WHERE coalesce(owner.package, "") <> ""
          AND coalesce(callee.package, "") <> ""
          AND owner.package <> callee.package
        MATCH (p1:PACKAGE {name: owner.package})
        MATCH (p2:PACKAGE {name: callee.package})
        MERGE (p1)-[r:NATIVE_CALL]->(p2)
        SET r.derived = true
        """
    )


def register_binary_symbol_inventory(session, component, strict_resolution):
    if not component:
        return {"binaries": 0, "imports": 0, "exports": 0}
    detail = dict(strict_resolution or {})
    binaries = list(detail.get("binaries") or [])
    imports_by_binary = dict(detail.get("imports_by_binary") or {})
    dependency_rows = list(detail.get("dependencies") or [])

    export_edges = 0
    import_edges = 0
    for binary in binaries:
        session.run(
            """
            MERGE (p:PACKAGE {name: $component})
            SET p.lang = coalesce(p.lang, "C")
            MERGE (b:BINARY {path: $path})
            SET b.component = $component
            MERGE (p)-[:HAS_BINARY]->(b)
            """,
            component=component,
            path=binary,
        )
    for binary, symbols in imports_by_binary.items():
        for symbol in list(symbols or [])[:256]:
            import_edges += 1
            session.run(
                """
                MATCH (b:BINARY {path: $path})
                MERGE (s:SYMBOL:IMPORTED_SYMBOL {name: $symbol, binary_path: $path, package: $component})
                SET s.lang = "C"
                MERGE (b)-[:IMPORTS_SYMBOL]->(s)
                """,
                path=binary,
                symbol=symbol,
                component=component,
            )

    for row in dependency_rows:
        child_component = str(row.get("component") or "").strip()
        provider_binaries = list(row.get("provider_binaries") or [])
        provider_exports = list(row.get("provider_export_sample") or [])
        if not child_component:
            continue
        for provider_binary in provider_binaries:
            session.run(
                """
                MERGE (p:PACKAGE {name: $component})
                SET p.lang = coalesce(p.lang, "C")
                MERGE (b:BINARY {path: $path})
                SET b.component = $component
                MERGE (p)-[:HAS_BINARY]->(b)
                """,
                component=child_component,
                path=provider_binary,
            )
        for symbol in provider_exports:
            for provider_binary in provider_binaries[:4]:
                export_edges += 1
                session.run(
                    """
                    MATCH (b:BINARY {path: $path})
                    MERGE (s:SYMBOL:EXPORTED_SYMBOL {name: $symbol, binary_path: $path, package: $component})
                    SET s.lang = "C"
                    MERGE (b)-[:EXPORTS_SYMBOL]->(s)
                    """,
                    path=provider_binary,
                    symbol=symbol,
                    component=child_component,
                )
        for evidence in row.get("evidence") or []:
            symbol = str(evidence.get("symbol") or "").strip()
            src_binary = str(evidence.get("binary") or "").strip()
            if not symbol or not src_binary:
                continue
            for provider_binary in provider_binaries[:4]:
                session.run(
                    """
                    MATCH (src:SYMBOL:IMPORTED_SYMBOL {name: $symbol, binary_path: $src_binary, package: $src_component})
                    MATCH (dst:SYMBOL:EXPORTED_SYMBOL {name: $symbol, binary_path: $dst_binary, package: $dst_component})
                    MERGE (src)-[:RESOLVES_TO_EXPORT]->(dst)
                    """,
                    symbol=symbol,
                    src_binary=src_binary,
                    src_component=component,
                    dst_binary=provider_binary,
                    dst_component=child_component,
                )
    return {
        "binaries": len(binaries),
        "imports": import_edges,
        "exports": export_edges,
    }


def resolve_external_c_calls_to_binary_symbols(session, parent_component, strict_resolution):
    if not parent_component:
        return 0
    detail = dict(strict_resolution or {})
    resolved_edges = 0
    for row in list(detail.get("dependencies") or []):
        child_component = str(row.get("component") or "").strip()
        provider_binaries = list(row.get("provider_binaries") or [])
        if not child_component or not provider_binaries:
            continue
        for evidence in row.get("evidence") or []:
            symbol = str(evidence.get("symbol") or "").strip()
            src_binary = str(evidence.get("binary") or "").strip()
            if not symbol:
                continue
            for provider_binary in provider_binaries[:4]:
                session.run(
                    """
                    MATCH (owner:METHOD:C)-[:AST*0..40]->(call:CALL:C)
                    WHERE owner.package = $parent_component
                      AND call.name = $symbol
                    MATCH (dst:SYMBOL:EXPORTED_SYMBOL {name: $symbol, binary_path: $provider_binary, package: $child_component})
                    MERGE (call)-[:RESOLVES_EXTERN_TO]->(dst)
                    WITH DISTINCT owner, dst
                    MATCH (p1:PACKAGE {name: owner.package})
                    MATCH (p2:PACKAGE {name: dst.package})
                    MERGE (p1)-[r:NATIVE_CALL]->(p2)
                    SET r.derived = true,
                        r.evidence_type = "binary-symbol-callsite",
                        r.source = "native-symbol",
                        r.last_symbol = $symbol,
                        r.from_binary = $src_binary,
                        r.to_binary = $provider_binary
                    """,
                    parent_component=parent_component,
                    child_component=child_component,
                    symbol=symbol,
                    src_binary=src_binary,
                    provider_binary=provider_binary,
                )
                resolved_edges += 1
    return resolved_edges


def generate_c_cpg_for_input(source_input, output_dir):
    script = os.path.join(REPO_ROOT, "generate_cpgs.sh")
    os.makedirs(output_dir, exist_ok=True)
    cmd = [script, "--lang", "c", "--input", source_input, "--output", output_dir]
    _run_cmd(cmd, cwd=REPO_ROOT, label="generate c cpg")
    cpg_json = os.path.join(output_dir, "cpg_final.json")
    if not os.path.exists(cpg_json):
        raise RuntimeError(f"C CPG generation finished but output missing: {cpg_json}")
    return cpg_json


def _import_native_component_source(
    session,
    *,
    vuln_rule,
    component,
    resolved_version,
    source_info,
    root_pkg,
    imported_cache,
    cache_root,
    symbol=None,
    scope_input_override="",
):
    source_root = source_info.get("source_root")
    symbol_definition_files = (
        find_symbol_definition_files(source_root, [symbol])
        if symbol and find_symbol_definition_files is not None
        else []
    )
    symbol_files = symbol_definition_files or (find_symbol_source_files(source_root, [symbol]) if symbol else [])
    scope_input = str(scope_input_override or "").strip()
    if not scope_input:
        scope_input = choose_c_analysis_scope(source_root, symbol_files) if symbol else source_root
    if (
        symbol
        and not scope_input_override
        and source_root
        and scope_input
        and os.path.abspath(scope_input) == os.path.abspath(source_root)
    ):
        return {
            "status": "skipped",
            "component": component,
            "resolved_version": resolved_version,
            "source_root": source_root,
            "scope_input": os.path.abspath(source_root),
            "symbol_files": symbol_files,
            "symbol_definition_files": symbol_definition_files,
            "reason": "symbol_scope_too_broad",
            "symbol": symbol,
        }
    if not scope_input:
        scope_input = source_root
    cache_key = (component, resolved_version, os.path.abspath(scope_input))
    cached = imported_cache.get(cache_key)
    if cached:
        return cached

    scope_hash = hashlib.sha1(os.path.abspath(scope_input).encode("utf-8")).hexdigest()[:12]
    component_dir = component.lower().replace("/", "_")
    version_dir = resolved_version or "unknown"
    cpg_output_dir = os.path.join(
        os.path.abspath(cache_root),
        "cpg_cache",
        component_dir,
        version_dir,
        scope_hash,
    )
    cpg_json = os.path.join(cpg_output_dir, "cpg_final.json")
    if not os.path.exists(cpg_json):
        cpg_json = generate_c_cpg_for_input(scope_input, cpg_output_dir)

    offset = _next_graph_id(session) + 1
    import_c_cpg_json(cpg_json, clear_db=False, id_offset=offset)
    lower_id, upper_id = _cpg_import_bounds(cpg_json, offset)
    annotate_imported_c_nodes(
        session,
        lower_id,
        upper_id,
        component=component,
        resolved_version=resolved_version,
        source_status=source_info.get("provenance") or "downloaded-official",
        source_root=source_root,
        provenance=source_info.get("provenance") or "downloaded-official",
    )
    ensure_package_version_node(
        session,
        component,
        lang="C",
        version=resolved_version or None,
        version_source=source_info.get("provenance") or "native-source",
        extra_props={
            "source_root": source_root,
            "source_provenance": source_info.get("provenance") or "downloaded-official",
        },
    )
    if component == str(vuln_rule.get("package") or "").strip():
        attach_vulnerability_to_component(session, vuln_rule, component, resolved_version)
        attach_symbols(session, [vuln_rule])
    link_c_calls_by_name(session)
    build_symbol_usage(session)
    build_pkg_call(session, root_pkg)
    build_native_pkg_edges(session)

    result = {
        "status": "imported",
        "component": component,
        "resolved_version": resolved_version,
        "source_root": source_root,
        "scope_input": os.path.abspath(scope_input),
        "symbol_files": symbol_files,
        "symbol_definition_files": symbol_definition_files,
        "cpg_json": cpg_json,
        "provenance": source_info.get("provenance"),
        "download_url": source_info.get("download_url"),
        "validation": source_info.get("validation"),
        "lower_id": lower_id,
        "upper_id": upper_id,
    }
    imported_cache[cache_key] = result
    return result


def _merge_native_dependency_candidates(strict_candidates, source_candidates):
    merged = {}
    for item in list(strict_candidates or []) + list(source_candidates or []):
        component = str(item.get("component") or "").strip()
        if not component:
            continue
        row = merged.setdefault(
            component,
            {
                "component": component,
                "confidence": item.get("confidence") or "medium",
                "evidence_type": item.get("evidence_type") or "source-scan",
                "source": item.get("source") or "native-source",
                "evidence": [],
            },
        )
        current_confidence = row.get("confidence") or "medium"
        candidate_confidence = item.get("confidence") or "medium"
        if current_confidence != "high" and candidate_confidence == "high":
            row["confidence"] = candidate_confidence
        if row.get("evidence_type") != "binary-symbol" and item.get("evidence_type") == "binary-symbol":
            row["evidence_type"] = "binary-symbol"
            row["source"] = item.get("source") or "native-symbol"
        row["evidence"].extend(list(item.get("evidence") or []))
    for row in merged.values():
        row["evidence"] = row["evidence"][:12]
    return sorted(merged.values(), key=lambda item: item["component"])


def _collect_native_dependency_candidates(component, source_root, resolved_version=""):
    strict_detail = {
        "status": "unavailable",
        "dependencies": [],
        "component": component,
        "resolved_version": resolved_version,
    }
    if resolve_strict_native_dependencies is not None:
        try:
            strict_detail = resolve_strict_native_dependencies(component, resolved_version=resolved_version)
        except Exception as exc:
            strict_detail = {
                "status": "failed",
                "component": component,
                "resolved_version": resolved_version,
                "reason": str(exc),
                "dependencies": [],
            }

    source_candidates = []
    if infer_native_source_dependencies is not None:
        try:
            source_candidates = list(infer_native_source_dependencies(component, source_root) or [])
        except Exception as exc:
            source_candidates = [{"component": "", "confidence": "low", "evidence": [{"path": "", "tokens": [f"dependency_scan_failed:{exc}"]}]}]

    merged = _merge_native_dependency_candidates(
        strict_detail.get("dependencies") or [],
        source_candidates,
    )
    return {
        "candidates": merged,
        "strict_resolution": strict_detail,
        "source_scan_dependencies": source_candidates,
    }


def _recursive_import_native_dependencies(
    session,
    *,
    vuln_rule,
    parent_component,
    parent_resolved_version,
    source_root,
    cache_root,
    root_pkg,
    imported_cache,
    recursion_depth,
    max_depth,
    max_components,
    visited_components,
):
    if recursion_depth >= max_depth:
        return {"status": "depth_limited", "imports": [], "missing": [], "discovered": []}
    discovery = _collect_native_dependency_candidates(
        parent_component,
        source_root,
        resolved_version=parent_resolved_version or "",
    )
    discovered = discovery.get("candidates", [])
    imports = []
    missing = []
    budget = max(0, int(max_components))
    for item in discovered[:budget]:
        child_component = str(item.get("component") or "").strip()
        if not child_component:
            continue
        create_native_depends_on(
            session,
            parent_component,
            child_component,
            evidence_type=item.get("evidence_type") or "source-scan",
            confidence=item.get("confidence") or "medium",
            source=item.get("source") or "native-source",
            evidence=json.dumps(item.get("evidence") or [], ensure_ascii=False),
        )
        component_key = child_component.lower()
        if component_key in visited_components:
            imports.append(
                {
                    "status": "cached",
                    "component": child_component,
                    "resolved_version": "",
                    "dependency_evidence": item.get("evidence") or [],
                }
            )
            continue
        visited_components.add(component_key)
        child_probe = _probe_system_native_version(child_component)
        child_version = str((child_probe or {}).get("version") or "").strip()
        source_info = ensure_native_source_tree(
            child_component,
            child_version,
            [],
            cache_root,
            allow_download=True,
        )
        if source_info.get("status") not in {"local", "downloaded"}:
            missing.append(
                {
                    "component": child_component,
                    "resolved_version": child_version,
                    "reason": source_info.get("reason") or source_info.get("status"),
                    "dependency_evidence": item.get("evidence") or [],
                }
            )
            continue
        child_scope = (
            choose_c_analysis_scope_from_relative_paths(
                source_info.get("source_root"),
                [row.get("path") for row in (item.get("evidence") or [])],
            )
            if choose_c_analysis_scope_from_relative_paths is not None
            else ""
        )
        if not child_scope:
            missing.append(
                {
                    "component": child_component,
                    "resolved_version": child_version,
                    "reason": "no_precise_ffi_scope",
                    "dependency_evidence": item.get("evidence") or [],
                }
            )
            continue
        child_import = _import_native_component_source(
            session,
            vuln_rule=vuln_rule,
            component=child_component,
            resolved_version=child_version,
            source_info=source_info,
            root_pkg=root_pkg,
            imported_cache=imported_cache,
            cache_root=cache_root,
            symbol=None,
            scope_input_override=child_scope,
        )
        child_recursive = _recursive_import_native_dependencies(
            session,
            vuln_rule=vuln_rule,
            parent_component=child_component,
            parent_resolved_version=child_version,
            source_root=source_info.get("source_root"),
            cache_root=cache_root,
            root_pkg=root_pkg,
            imported_cache=imported_cache,
            recursion_depth=recursion_depth + 1,
            max_depth=max_depth,
            max_components=max_components,
            visited_components=visited_components,
        )
        child_import["dependency_evidence"] = item.get("evidence") or []
        child_import["recursive"] = child_recursive
        imports.append(child_import)
    return {
        "status": "expanded",
        "imports": imports,
        "missing": missing,
        "discovered": discovered[:budget],
        "strict_resolution": discovery.get("strict_resolution"),
        "source_scan_dependencies": discovery.get("source_scan_dependencies", []),
    }


def maybe_import_native_source_for_symbol(
    session,
    *,
    vuln_rule,
    symbol,
    native_component_instances,
    cache_root,
    root_pkg,
    imported_cache,
    allow_download=True,
    max_dependency_depth=2,
    max_dependency_components=6,
):
    if (
        ensure_native_source_tree is None
        or choose_c_analysis_scope is None
        or find_symbol_source_files is None
    ):
        return {"status": "unavailable", "reason": "native_source_resolver_import_failed"}

    if not native_component_instances:
        return {"status": "unavailable", "reason": "missing_component_instance"}

    primary = dict(native_component_instances[0] or {})
    component = str(primary.get("component") or vuln_rule.get("package") or "").strip()
    resolved_version = str(primary.get("resolved_version") or "").strip()
    matched_manifest_paths = []
    for row in primary.get("matched_crates") or []:
        matched_manifest_paths.extend(list(row.get("manifest_paths") or []))

    source_info = ensure_native_source_tree(
        component,
        resolved_version,
        matched_manifest_paths,
        cache_root,
        allow_download=allow_download,
    )
    if source_info.get("status") not in {"local", "downloaded"}:
        return source_info

    result = _import_native_component_source(
        session,
        vuln_rule=vuln_rule,
        component=component,
        resolved_version=resolved_version,
        source_info=source_info,
        root_pkg=root_pkg,
        imported_cache=imported_cache,
        cache_root=cache_root,
        symbol=symbol,
    )
    recursive = _recursive_import_native_dependencies(
        session,
        vuln_rule=vuln_rule,
        parent_component=component,
        parent_resolved_version=resolved_version,
        source_root=source_info.get("source_root"),
        cache_root=cache_root,
        root_pkg=root_pkg,
        imported_cache=imported_cache,
        recursion_depth=0,
        max_depth=max_dependency_depth,
        max_components=max_dependency_components,
        visited_components={component.lower()},
    )
    result["dependency_imports"] = recursive.get("imports", [])
    result["missing_dependencies"] = recursive.get("missing", [])
    result["discovered_dependencies"] = recursive.get("discovered", [])
    result["strict_dependency_resolution"] = recursive.get("strict_resolution", {})
    result["source_scan_dependencies"] = recursive.get("source_scan_dependencies", [])
    result["binary_symbol_inventory"] = register_binary_symbol_inventory(
        session,
        component,
        result["strict_dependency_resolution"],
    )
    result["strict_callsite_edges"] = resolve_external_c_calls_to_binary_symbols(
        session,
        component,
        result["strict_dependency_resolution"],
    )
    result["native_analysis_coverage"] = (
        "target_plus_key_subdeps"
        if result["dependency_imports"] and not result["missing_dependencies"]
        else ("target_only" if result["status"] == "imported" else "none")
    )
    if result["missing_dependencies"]:
        result["native_analysis_coverage"] = "target_only_incomplete"
    return result


def get_cpg_stats(session):
    rust_methods = session.run("MATCH (m:METHOD:Rust) RETURN count(m) AS c").single()["c"]
    rust_calls = session.run("MATCH (c:CALL:Rust) RETURN count(c) AS c").single()["c"]
    return {
        "rust_methods": int(rust_methods or 0),
        "rust_calls": int(rust_calls or 0),
    }

def build_deps_from_cargo(meta):
    id_to_pkg = {p["id"]: p for p in meta.get("packages", [])}
    resolve = meta.get("resolve", {})
    node_features = {}
    for node in resolve.get("nodes", []) or []:
        pkg_id = node.get("id")
        features = list(node.get("features") or [])
        if pkg_id:
            node_features[pkg_id] = features
    packages = []
    for p in meta.get("packages", []):
        packages.append({
            "name": p["name"],
            "version": p["version"],
            "lang": "Rust",
            "features": list(node_features.get(p.get("id"), [])),
            "source": "cargo",
            "crate_source": p.get("source"),
            "manifest_path": p.get("manifest_path"),
        })

    depends = []
    for node in resolve.get("nodes", []):
        src = id_to_pkg.get(node["id"])
        if not src:
            continue
        for dep in node.get("deps", []):
            dst = id_to_pkg.get(dep["pkg"])
            if not dst:
                continue
            depends.append({
                "from": src["name"],
                "to": dst["name"],
                "evidence_type": "cargo",
                "confidence": "high",
                "source": "cargo metadata",
                "evidence": "resolve graph"
            })

    root = None
    if meta.get("workspace_default_members"):
        root_id = meta["workspace_default_members"][0]
        root = id_to_pkg.get(root_id, {}).get("name")
    if not root and meta.get("packages"):
        root = meta["packages"][0]["name"]
    return {"root": root or "app", "packages": packages, "depends": depends}

def merge_extras(deps, extras):
    if not extras:
        return
    existing = {(p["name"], p.get("version", "")) for p in deps.get("packages", [])}
    for p in extras.get("packages", []):
        key = (p["name"], p.get("version", ""))
        if key not in existing:
            deps["packages"].append(p)
            existing.add(key)
    for d in extras.get("depends", []):
        deps["depends"].append(d)


def collect_package_versions(deps):
    versions = {}
    for pkg in deps.get("packages", []) or []:
        name = pkg.get("name")
        ver = pkg.get("version")
        if not name or not ver:
            continue
        versions.setdefault(name, [])
        if ver not in versions[name]:
            versions[name].append(ver)
    return versions


def collect_package_metadata(deps):
    metadata = {}
    for pkg in deps.get("packages", []) or []:
        name = pkg.get("name")
        if not name:
            continue
        row = metadata.setdefault(
            name,
            {
                "versions": [],
                "sources": [],
                "features": [],
                "langs": [],
                "crate_sources": [],
                "manifest_paths": [],
            },
        )
        version = pkg.get("version")
        if version and version not in row["versions"]:
            row["versions"].append(version)
        source = pkg.get("source")
        if source and source not in row["sources"]:
            row["sources"].append(source)
        lang = pkg.get("lang")
        if lang and lang not in row["langs"]:
            row["langs"].append(lang)
        crate_source = pkg.get("crate_source")
        if crate_source and crate_source not in row["crate_sources"]:
            row["crate_sources"].append(crate_source)
        manifest_path = pkg.get("manifest_path")
        if manifest_path and manifest_path not in row["manifest_paths"]:
            row["manifest_paths"].append(manifest_path)
        for feat in pkg.get("features", []) or []:
            if feat and feat not in row["features"]:
                row["features"].append(feat)
    return metadata


def _ensure_list(val):
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


def load_sink_knowledge(path):
    if not path:
        return {}
    if not os.path.exists(path):
        return {}
    try:
        data = load_json(path)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _component_lookup_keys(component):
    name = str(component or "").strip()
    if not name:
        return []
    keys = [name, name.lower()]
    if name.lower().startswith("lib") and len(name) > 3:
        keys.append(name[3:])
        keys.append(name[3:].lower())
    keys.append(name.replace("-", "_"))
    keys.append(name.replace("_", "-"))
    return list(dict.fromkeys([k for k in keys if k]))


def _append_unique_text(items, value):
    text = str(value or "").strip()
    if text and text not in items:
        items.append(text)


def _append_unique_rust_sink(items, sink):
    if isinstance(sink, dict):
        path = str(sink.get("path") or sink.get("name") or "").strip()
        name_regex = str(sink.get("name_regex") or "").strip()
        contains = tuple(str(tok or "").strip() for tok in _ensure_list(sink.get("contains") or sink.get("code_contains")))
        key = ("dict", path, name_regex, contains)
    else:
        key = ("text", str(sink or "").strip())
    if not key[-1] and key[0] == "text":
        return
    for existing in items:
        if isinstance(existing, dict):
            ekey = (
                "dict",
                str(existing.get("path") or existing.get("name") or "").strip(),
                str(existing.get("name_regex") or "").strip(),
                tuple(str(tok or "").strip() for tok in _ensure_list(existing.get("contains") or existing.get("code_contains"))),
            )
        else:
            ekey = ("text", str(existing or "").strip())
        if ekey == key:
            return
    items.append(copy.deepcopy(sink))


def _expand_symbol_family(rule):
    out = copy.deepcopy(rule or {})
    package = str(out.get("package") or "").strip().lower().replace("_", "-")
    symbols = [str(sym or "").strip() for sym in _ensure_list(out.get("symbols")) if str(sym or "").strip()]
    native_sinks = [str(sym or "").strip() for sym in _ensure_list(out.get("native_sinks")) if str(sym or "").strip()]
    rust_sinks = list(_ensure_list(out.get("rust_sinks")))

    symbol_tokens_lower = {sym.lower() for sym in symbols + native_sinks}
    is_webp_rule = package in {"libwebp", "webp", "libwebp-sys", "libwebp-sys2", "webp-sys", "webp-sys2", "webp-sys3"}
    has_webp_seed = any(tok.startswith("webpdecode") or tok.startswith("webpanimdecoder") for tok in symbol_tokens_lower)
    if is_webp_rule or has_webp_seed:
        for sym in ("WebPDecode", "WebPDecodeRGBA", "WebPAnimDecoderGetNext"):
            _append_unique_text(symbols, sym)
            _append_unique_text(native_sinks, sym)
        for sink in (
            {"path": "WebPDecode"},
            {"path": "WebPDecodeRGBA"},
            {"path": "WebPAnimDecoderGetNext"},
        ):
            _append_unique_rust_sink(rust_sinks, sink)

    is_pcre2_rule = package in {"pcre2", "pcre2-sys", "pcre2-sys2", "pcre2_sys", "grep-pcre2", "grep_pcre2"}
    has_pcre2_seed = any(tok.startswith("pcre2_") for tok in symbol_tokens_lower)
    if is_pcre2_rule or has_pcre2_seed:
        for sym in ("pcre2_match_8", "pcre2_match"):
            _append_unique_text(symbols, sym)
            _append_unique_text(native_sinks, sym)
        for sink in (
            {"path": "pcre2::bytes::RegexBuilder::build"},
            {"path": "grep_pcre2::RegexMatcherBuilder::build"},
            {"path": "RegexBuilder::build", "context_tokens": ["pcre2"]},
            {"path": "RegexMatcherBuilder::build", "context_tokens": ["pcre2", "regex", "matcher"]},
        ):
            _append_unique_rust_sink(rust_sinks, sink)

    if symbols:
        out["symbols"] = symbols
    if native_sinks:
        out["native_sinks"] = native_sinks
    if rust_sinks:
        out["rust_sinks"] = rust_sinks
    return out


def _deep_merge_dict(base, extra):
    if not isinstance(base, dict):
        base = {}
    if not isinstance(extra, dict):
        return base
    out = copy.deepcopy(base)
    for key, value in extra.items():
        if key not in out:
            out[key] = copy.deepcopy(value)
            continue
        if isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = _deep_merge_dict(out[key], value)
            continue
        if isinstance(out[key], list) and isinstance(value, list):
            merged = list(out[key])
            for item in value:
                if item not in merged:
                    merged.append(copy.deepcopy(item))
            out[key] = merged
            continue
        if out[key] in (None, "", [], {}):
            out[key] = copy.deepcopy(value)
    return out


def apply_sink_knowledge(vuln, sink_knowledge):
    rule = copy.deepcopy(vuln or {})
    component = rule.get("package")
    if not component:
        return rule
    entry = None
    for key in _component_lookup_keys(component):
        if key in (sink_knowledge or {}):
            entry = sink_knowledge[key]
            break
    if not isinstance(entry, dict):
        return rule

    for field in ("match", "rust_sinks", "native_sinks", "input_predicate", "env_guards"):
        if field not in rule or rule.get(field) in (None, "", [], {}):
            if field in entry:
                rule[field] = copy.deepcopy(entry[field])
    if "trigger_model" in entry:
        rule["trigger_model"] = _deep_merge_dict(rule.get("trigger_model", {}), entry.get("trigger_model", {}))
    if "symbols" in entry:
        existing = list(rule.get("symbols") or [])
        for sym in _ensure_list(entry.get("symbols")):
            if sym and sym not in existing:
                existing.append(sym)
        if existing:
            rule["symbols"] = existing
    return rule


def _guess_component_match_crates(component):
    name = str(component or "").strip()
    if not name:
        return []
    base = name.lower()
    if base.startswith("lib") and len(base) > 3:
        short = base[3:]
    else:
        short = base
    out = [base, short, f"{short}-sys", f"{short}_sys", f"{short}-sys2", f"{short}_sys2"]
    if short == "git2":
        out.extend(["libgit2-sys", "git2", "git2-sys"])
    if short == "webp":
        out.extend(["webp", "libwebp-sys"])
    if short == "zlib":
        out.extend(["libz-sys", "zlib-sys", "zlib"])
    if short == "pcre2":
        out.extend(["pcre2", "pcre2-sys"])
    if short == "sqlite":
        out.extend(["rusqlite", "libsqlite3-sys"])
    return list(dict.fromkeys([n for n in out if n]))


def _infer_source_from_features(features):
    feats = {str(f).lower() for f in (features or [])}
    bundled_markers = {"vendored", "bundled", "source", "static", "build-vendored", "vendored-libgit2"}
    system_markers = {"system", "pkg-config", "pkg_config", "dynamic", "vcpkg"}
    if feats & bundled_markers and not (feats & system_markers):
        return ("bundled", sorted(feats & bundled_markers))
    if feats & system_markers and not (feats & bundled_markers):
        return ("system", sorted(feats & system_markers))
    if feats & bundled_markers and feats & system_markers:
        return ("unknown", sorted((feats & bundled_markers) | (feats & system_markers)))
    return (None, [])


def _source_selector_markers():
    return {
        "vendored",
        "bundled",
        "source",
        "static",
        "build-vendored",
        "vendored-libgit2",
        "system",
        "pkg-config",
        "pkg_config",
        "dynamic",
        "vcpkg",
    }


def _build_feature_map_from_deps(deps):
    mapping = {}
    for pkg in deps.get("packages", []) or []:
        mapping[str(pkg.get("name") or "")] = list(pkg.get("features") or [])
    return mapping


def _filter_speculative_source_features(deps, base_feature_map):
    selectors = _source_selector_markers()
    for pkg in deps.get("packages", []) or []:
        name = str(pkg.get("name") or "")
        base_features = list(base_feature_map.get(name) or [])
        base_set = {str(f).lower() for f in base_features}
        merged = []
        for feat in pkg.get("features", []) or []:
            feat_text = str(feat or "")
            if not feat_text:
                continue
            feat_lower = feat_text.lower()
            if feat_lower in selectors and feat_lower not in base_set:
                continue
            if feat_text not in merged:
                merged.append(feat_text)
        pkg["features"] = merged


def _inspect_build_script(manifest_path):
    if not manifest_path:
        return {"exists": False, "source_hint": None, "signals": [], "native_versions": [], "linked_libs": []}
    crate_dir = os.path.dirname(manifest_path)
    build_rs = os.path.join(crate_dir, "build.rs")
    if not os.path.exists(build_rs):
        return {"exists": False, "source_hint": None, "signals": [], "native_versions": [], "linked_libs": []}
    try:
        with open(build_rs, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception:
        return {"exists": True, "source_hint": None, "signals": [], "native_versions": [], "linked_libs": []}

    lowered = text.lower()
    signals = []
    has_cc = "cc::build" in lowered or ".compile(" in lowered
    has_cmake = "cmake::config" in lowered or "cmake::" in lowered
    has_pkg_config = "pkg_config" in lowered or "pkg-config" in lowered
    has_vcpkg = "vcpkg" in lowered
    has_vendor_word = "vendored" in lowered or "bundled" in lowered
    linked_libs = []
    for match in re.finditer(r"cargo:rustc-link-lib(?:=[^\"\\n]*)?=([A-Za-z0-9_\\-\\.]+)", text):
        lib = match.group(1).strip()
        if lib and lib not in linked_libs:
            linked_libs.append(lib)
    if linked_libs:
        signals.append("cargo_link_lib")

    if has_cc:
        signals.append("cc_build")
    if has_cmake:
        signals.append("cmake")
    if has_pkg_config:
        signals.append("pkg_config")
    if has_vcpkg:
        signals.append("vcpkg")
    if has_vendor_word:
        signals.append("vendor_word")

    if linked_libs and not (has_cc or has_cmake or has_vendor_word):
        source_hint = "system"
    elif (has_cc or has_cmake or has_vendor_word) and not (has_pkg_config or has_vcpkg):
        source_hint = "bundled"
    elif (has_pkg_config or has_vcpkg) and not (has_cc or has_cmake):
        source_hint = "system"
    elif has_pkg_config or has_vcpkg or has_cc or has_cmake:
        source_hint = "unknown"
    else:
        source_hint = None

    native_versions = []
    for m in re.finditer(r"([0-9]+\.[0-9]+\.[0-9]+)", text):
        ver = m.group(1)
        if ver not in native_versions:
            native_versions.append(ver)
    return {
        "exists": True,
        "source_hint": source_hint,
        "signals": signals,
        "native_versions": native_versions[:8],
        "linked_libs": linked_libs,
    }


def _read_manifest_identity(manifest_path):
    info = {"name": None, "version": None}
    if not manifest_path or not os.path.exists(manifest_path):
        return info
    try:
        text = Path(manifest_path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return info
    for key in ("name", "version"):
        match = re.search(rf'(?m)^\\s*{re.escape(key)}\\s*=\\s*"([^"]+)"', text)
        if match:
            info[key] = match.group(1).strip()
    return info


def _root_lib_rs_path(cargo_dir):
    root = str(cargo_dir or "").strip()
    if not root:
        return ""
    path = os.path.join(root, "src", "lib.rs")
    return path if os.path.exists(path) else ""


def _root_has_bindings_include(cargo_dir):
    path = _root_lib_rs_path(cargo_dir)
    if not path:
        return False
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    lowered = text.lower()
    include_markers = [
        'include!(concat!(env!("out_dir"), "/bindings.rs"))',
        "include!(concat!(env!(\"out_dir\"), '/bindings.rs'))",
        'include!(concat!(env!("out_dir"),"/bindings.rs"))',
    ]
    if any(marker in lowered for marker in include_markers):
        return True
    # Common wrapper pattern:
    #   mod bindings { include!(concat!(env!("OUT_DIR"), "/bindings.rs")); }
    if "mod bindings" in lowered and "bindings.rs" in lowered and "out_dir" in lowered:
        return True
    return False


def _root_is_thin_bindings_gateway(cargo_dir, max_code_lines=16):
    path = _root_lib_rs_path(cargo_dir)
    if not path:
        return False
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return False
    if not _root_has_bindings_include(cargo_dir):
        return False

    code_lines = []
    for line in lines:
        text = str(line or "").strip()
        if not text:
            continue
        if text.startswith("//"):
            continue
        if text.startswith("#!"):
            continue
        code_lines.append(text)
    return len(code_lines) <= max(1, int(max_code_lines or 16))


def _native_component_probe_aliases(component):
    text = str(component or "").strip().lower().replace("_", "-")
    if not text:
        return set()
    short = text[3:] if text.startswith("lib") and len(text) > 3 else text
    aliases = {
        text,
        short,
        text.replace("-", "_"),
        short.replace("-", "_"),
    }
    if short == "webp":
        aliases.update({"webpdecoder", "webpdemux", "webpmux"})
    if short == "pcre2":
        aliases.update({"pcre2-8", "pcre2_8"})
    for token in list(aliases):
        normalized = str(token or "").strip().lower().replace("_", "-")
        if not normalized:
            continue
        stripped = re.sub(r"-(sys|src|bindings|ffi)\d*$", "", normalized)
        if stripped:
            aliases.add(stripped)
        if stripped.startswith("lib") and len(stripped) > 3:
            aliases.add(stripped[3:])
    return {item for item in aliases if item}


def _root_wrapper_component_instance(cargo_dir, component, vuln_rule=None):
    cargo_root = str(cargo_dir or "").strip()
    if not cargo_root or not os.path.isdir(cargo_root):
        return None
    manifest_path = os.path.join(cargo_root, "Cargo.toml")
    build_info = _inspect_build_script(manifest_path)
    aliases = _native_component_probe_aliases(component)
    linked = {
        str(item or "").strip().lower().replace("_", "-")
        for item in (build_info.get("linked_libs") or [])
        if str(item or "").strip()
    }
    link_hit = bool(linked & aliases)

    source_hit = False
    symbol_tokens = []
    for sym in _ensure_list((vuln_rule or {}).get("symbols")):
        symbol_tokens.append(str(sym or "").strip())
    for token in list(aliases) + symbol_tokens:
        if not token:
            continue
        pattern = re.compile(rf"\\b{re.escape(token)}\\b", re.IGNORECASE)
        for path in Path(cargo_root).rglob("*.rs"):
            rel = str(path).replace("\\\\", "/")
            if "/target" in rel:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if pattern.search(text):
                source_hit = True
                break
        if source_hit:
            break

    if not link_hit and not source_hit and not build_info.get("exists"):
        return None

    manifest_info = _read_manifest_identity(manifest_path)
    system_probe = _probe_system_native_version(component)

    source = build_info.get("source_hint") or ("system" if link_hit and system_probe else "unknown")
    resolved_version = None
    if source == "system" and system_probe and system_probe.get("version"):
        resolved_version = system_probe.get("version")
    elif build_info.get("native_versions"):
        resolved_version = build_info["native_versions"][0]
    elif manifest_info.get("version") and source == "bundled":
        resolved_version = manifest_info["version"]

    return {
        "component": component,
        "status": "resolved" if resolved_version else "unknown",
        "resolved_version": resolved_version,
        "source": source,
        "enabled_features": [],
        "matched_crates": [
            {
                "crate": manifest_info.get("name") or Path(cargo_root).name,
                "versions": [manifest_info.get("version")] if manifest_info.get("version") else [],
                "features": [],
                "sources": ["cargo"],
                "manifest_paths": [manifest_path] if os.path.exists(manifest_path) else [],
            }
        ],
        "resolution_evidence": [
            {"kind": "root_wrapper_probe", "build_script": build_info, "link_hit": link_hit, "source_hit": source_hit},
            *([{"kind": "system_probe", "probe": system_probe}] if system_probe else []),
        ],
    }


_SYSTEM_NATIVE_VERSION_CACHE = {}


def _extract_semver_token(text):
    match = re.search(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", str(text or ""))
    if not match:
        return None
    return match.group(1)


def _native_version_override(component):
    normalized = str(component or "").strip().lower().replace("-", "_")
    if not normalized:
        return None
    env_key = f"SUPPLYCHAIN_NATIVE_VERSION_{normalized.upper()}"
    raw = os.environ.get(env_key, "")
    version = _extract_semver_token(raw)
    if not version:
        return None
    return {
        "tool": "env_override",
        "command": [env_key],
        "version": version,
    }


def _system_probe_component_keys(component):
    normalized = str(component or "").strip().lower().replace("_", "-")
    if not normalized:
        return []
    keys = []
    for token in _native_component_probe_aliases(component):
        lowered = str(token or "").strip().lower().replace("_", "-")
        if not lowered:
            continue
        if lowered not in keys:
            keys.append(lowered)
        stripped = re.sub(r"-(sys|src|bindings|ffi)\d*$", "", lowered)
        if stripped and stripped not in keys:
            keys.append(stripped)
        if stripped.startswith("lib") and len(stripped) > 3:
            short = stripped[3:]
            if short and short not in keys:
                keys.append(short)
    if normalized not in keys:
        keys.insert(0, normalized)
    return keys


def _system_probe_candidates(component_key):
    key = str(component_key or "").strip().lower().replace("_", "-")
    if key == "openssl":
        return [
            ("pkg-config", ["pkg-config", "--modversion", "openssl"]),
            ("openssl-cli", ["openssl", "version"]),
        ]
    if key in {"libxml2", "xml2"}:
        return [
            ("pkg-config", ["pkg-config", "--modversion", "libxml-2.0"]),
            ("xml2-config", ["xml2-config", "--version"]),
        ]
    if key in {"libheif", "heif"}:
        return [
            ("pkg-config", ["pkg-config", "--modversion", "libheif"]),
        ]
    if key in {"libwebp", "webp"}:
        return [
            ("pkg-config", ["pkg-config", "--modversion", "libwebp"]),
        ]
    if key in {"pcre2", "libpcre2", "pcre2-8"}:
        return [
            ("pkg-config", ["pkg-config", "--modversion", "libpcre2-8"]),
            ("pkg-config", ["pkg-config", "--modversion", "pcre2"]),
            ("pcre2-config", ["pcre2-config", "--version"]),
        ]
    if key in {"freetype", "freetype2"}:
        return [
            ("freetype-config", ["freetype-config", "--ftversion"]),
            ("pkg-config", ["pkg-config", "--modversion", "freetype2"]),
        ]
    if key == "zlib":
        return [
            (
                "python-ctypes",
                [
                    "python3",
                    "-c",
                    "import ctypes,ctypes.util;name=ctypes.util.find_library('z') or 'libz.dylib';lib=ctypes.CDLL(name);lib.zlibVersion.restype=ctypes.c_char_p;print(lib.zlibVersion().decode())",
                ],
            ),
            ("pkg-config", ["pkg-config", "--modversion", "zlib"]),
        ]
    return []


def _probe_system_native_version(component):
    normalized = str(component or "").strip().lower().replace("_", "-")
    if not normalized:
        return None
    override = _native_version_override(component)
    cache_key = (normalized, override.get("version") if override else None)
    if cache_key in _SYSTEM_NATIVE_VERSION_CACHE:
        return _SYSTEM_NATIVE_VERSION_CACHE[cache_key]
    if override:
        _SYSTEM_NATIVE_VERSION_CACHE[cache_key] = override
        return override

    seen_commands = set()
    for probe_key in _system_probe_component_keys(component):
        for tool_name, cmd in _system_probe_candidates(probe_key):
            cmd_key = tuple(cmd)
            if cmd_key in seen_commands:
                continue
            seen_commands.add(cmd_key)
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
            except Exception:
                continue
            if proc.returncode != 0:
                continue
            version = _extract_semver_token(proc.stdout) or _extract_semver_token(proc.stderr)
            if (
                probe_key in {"freetype", "freetype2"}
                and tool_name == "pkg-config"
                and version
                and re.match(r"^\d+\.\d+\.\d+$", version)
            ):
                try:
                    major = int(version.split(".", 1)[0])
                except ValueError:
                    major = None
                if major is not None and major >= 10:
                    continue
            if not version:
                continue
            result = {
                "tool": tool_name,
                "command": cmd,
                "version": version,
                "component_key": probe_key,
            }
            _SYSTEM_NATIVE_VERSION_CACHE[cache_key] = result
            return result

    _SYSTEM_NATIVE_VERSION_CACHE[cache_key] = None
    return None


def resolve_native_component_instances(vuln_rule, package_metadata, cargo_dir=""):
    component = vuln_rule.get("package")
    if not component:
        return []
    source_status_hint = str(vuln_rule.get("source_status") or "").strip().lower()
    system_probe = _probe_system_native_version(component) if source_status_hint == "system" else None
    match = vuln_rule.get("match") or {}
    candidate_crates = list(_ensure_list(match.get("crates")))
    if not candidate_crates:
        candidate_crates = _guess_component_match_crates(component)
    norm_candidates = {c.lower().replace("_", "-"): c for c in candidate_crates}
    normalized_candidates = {
        _normalize_native_crate_name(c.lower().replace("_", "-")): c
        for c in candidate_crates
        if _normalize_native_crate_name(c.lower().replace("_", "-"))
    }

    matched_crates = []
    for crate_name, meta in (package_metadata or {}).items():
        norm = crate_name.lower().replace("_", "-")
        if norm in norm_candidates:
            matched_crates.append((crate_name, meta))
            continue
        if _normalize_native_crate_name(norm) in normalized_candidates:
            matched_crates.append((crate_name, meta))
            continue
        if crate_name == component:
            matched_crates.append((crate_name, meta))

    if not matched_crates:
        root_wrapper = _root_wrapper_component_instance(cargo_dir, component, vuln_rule=vuln_rule)
        if root_wrapper:
            root_wrapper["resolution_evidence"] = list(root_wrapper.get("resolution_evidence") or [])
            root_wrapper["resolution_evidence"].append({"kind": "missing_candidate_crates"})
            return [root_wrapper]
        if system_probe and system_probe.get("version"):
            return [
                {
                    "component": component,
                    "status": "resolved",
                    "resolved_version": system_probe.get("version"),
                    "source": "system",
                    "enabled_features": [],
                    "matched_crates": [],
                    "resolution_evidence": [
                        {"kind": "missing_candidate_crates"},
                        {"kind": "system_probe", "probe": system_probe},
                    ],
                }
            ]
        return [
            {
                "component": component,
                "status": "unknown",
                "resolved_version": None,
                "source": "unknown",
                "enabled_features": [],
                "matched_crates": [],
                "resolution_evidence": [{"kind": "missing_candidate_crates"}],
            }
        ]

    all_versions = []
    all_features = []
    all_sources = []
    all_manifest_paths = []
    crate_rows = []
    for crate_name, meta in matched_crates:
        versions = list(meta.get("versions") or [])
        features = list(meta.get("features") or [])
        sources = list(meta.get("sources") or [])
        manifests = list(meta.get("manifest_paths") or [])
        for v in versions:
            if v not in all_versions:
                all_versions.append(v)
        for f in features:
            if f not in all_features:
                all_features.append(f)
        for s in sources:
            if s not in all_sources:
                all_sources.append(s)
        for p in manifests:
            if p not in all_manifest_paths:
                all_manifest_paths.append(p)
        crate_rows.append(
            {
                "crate": crate_name,
                "versions": versions,
                "features": features,
                "sources": sources,
                "manifest_paths": manifests,
            }
        )

    source_by_feat, feat_signals = _infer_source_from_features(all_features)
    build_inspects = [_inspect_build_script(p) for p in all_manifest_paths]
    build_hints = [r.get("source_hint") for r in build_inspects if r.get("source_hint")]
    build_versions = []
    sys_like_matched = False
    for row in crate_rows:
        crate_name = str(row.get("crate") or "").lower().replace("_", "-")
        if re.search(r"-(sys|src|bindings|ffi)\d*$", crate_name):
            sys_like_matched = True
    for row in build_inspects:
        for ver in row.get("native_versions") or []:
            if ver not in build_versions:
                build_versions.append(ver)
    if source_by_feat:
        source = source_by_feat
    elif build_hints and all(h == "bundled" for h in build_hints):
        source = "bundled"
    elif build_hints and all(h == "system" for h in build_hints):
        source = "system"
    elif build_hints:
        source = "unknown"
    else:
        source = "unknown"

    if source_status_hint == "system" and system_probe and system_probe.get("version"):
        source = "system"
    elif sys_like_matched and source != "bundled":
        system_probe = system_probe or _probe_system_native_version(component)
        if system_probe and system_probe.get("version"):
            source = "system"
    resolved_version = None
    if source_status_hint == "system" and system_probe and system_probe.get("version"):
        resolved_version = system_probe.get("version")
    elif source == "system":
        system_probe = system_probe or _probe_system_native_version(component)
        if system_probe and system_probe.get("version"):
            resolved_version = system_probe.get("version")

    if not resolved_version:
        if build_versions:
            resolved_version = build_versions[0]
        elif component in package_metadata and (package_metadata.get(component) or {}).get("versions"):
            resolved_version = list((package_metadata.get(component) or {}).get("versions") or [None])[0]
        elif all_versions:
            resolved_version = all_versions[0]

    evidence = []
    if feat_signals:
        evidence.append({"kind": "feature_signal", "signals": feat_signals})
    if build_inspects:
        evidence.append({"kind": "build_script_signal", "items": build_inspects})
    if system_probe:
        evidence.append({"kind": "system_probe", "probe": system_probe})
    if all_versions:
        evidence.append({"kind": "crate_versions", "versions": all_versions})

    return [
        {
            "component": component,
            "status": "resolved" if resolved_version else "unknown",
            "resolved_version": resolved_version,
            "source": source,
            "enabled_features": all_features,
            "matched_crates": crate_rows,
            "resolution_evidence": evidence,
        }
    ]


def _coerce_call_name(name):
    text = str(name or "").strip()
    if not text:
        return ""
    if "::" in text:
        return text.split("::")[-1]
    return text


def _parse_sink_arg_ref(text):
    token = str(text or "").strip()
    if not token:
        return (None, None)
    match = re.match(r"^(.+?)\.arg(\d+)$", token)
    if not match:
        return (token, None)
    return (match.group(1).strip(), int(match.group(2)))


def _compile_must_flow_item(item, idx):
    if isinstance(item, dict) and item.get("type"):
        cond = dict(item)
        cond.setdefault("id", f"must_flow_{idx}")
        return [cond]
    if isinstance(item, str):
        parts = [p.strip() for p in item.split("->") if p.strip()]
        if len(parts) >= 2:
            item = {"source": parts[0], "sink": parts[-1]}
        else:
            return []
    if not isinstance(item, dict):
        return []
    source = str(item.get("source") or "").strip()
    sink = str(item.get("sink") or "").strip()
    if not source or not sink:
        return []

    sink_name, sink_arg_index = _parse_sink_arg_ref(sink)
    sink_name = _coerce_call_name(sink_name)
    conds = []
    if sink_name:
        if source.startswith("File::open.bytes") or source.startswith("file.bytes"):
            cond = {
                "id": f"must_flow_io_{idx}",
                "type": "io_to_call_arg",
                "sink": {"name": sink_name, "lang": "Rust", "arg_index": sink_arg_index or 1},
                "open_call": {"name": "File::open", "lang": "Rust"},
                "read_call": {"name_regex": "(^|::)read_to_end$|(^|::)read$", "lang": "Rust"},
                "same_method": True,
            }
            conds.append(cond)
        else:
            lower_source = source.lower()
            if ".len()" in lower_source or ".capacity()" in lower_source:
                source_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:len|capacity)\s*\(", source)
                conds.append(
                    {
                        "id": f"must_flow_len_{idx}",
                        "type": "len_to_call_arg",
                        "sink": {"name": sink_name, "lang": "Rust", "arg_index": sink_arg_index or 1},
                        "source_var": source_match.group(1) if source_match else None,
                    }
                )
                return conds
            if "option" in lower_source or "as_deref" in lower_source or "as_ref" in lower_source:
                conds.append(
                    {
                        "id": f"must_flow_option_{idx}",
                        "type": "option_to_call_arg",
                        "sink": {"name": sink_name, "lang": "Rust", "arg_index": sink_arg_index or 1},
                        "allow_assume_if_no_direct": True,
                        "assumption_reason": "option_source_is_abstract_model",
                    }
                )
                return conds
            field = None
            match = re.search(r"\.([A-Za-z_][A-Za-z0-9_]*)$", source)
            if match:
                field = match.group(1)
            if field:
                conds.append(
                    {
                        "id": f"must_flow_field_{idx}",
                        "type": "field_to_call_arg",
                        "sink": {"name": sink_name, "lang": "Rust", "arg_index": sink_arg_index or 1},
                        "source_field": field,
                    }
                )
            else:
                conds.append(
                    {
                        "id": f"must_flow_call_{idx}",
                        "type": "call",
                        "name": sink_name,
                        "lang": "Rust",
                    }
                )
    return conds


def _compile_text_guard_heuristic(text, idx, prefix):
    raw = str(text or "").strip()
    lowered = raw.lower()
    if not raw:
        return None
    if "only encoder" in lowered:
        return {
            "id": f"{prefix}_{idx}",
            "type": "call",
            "name_regex": "(?i)(^|::)encode$",
            "lang": "Rust",
        }
    if "image_type constrained to" in lowered:
        rhs = raw.split("to", 1)[-1]
        items = [t.strip() for t in re.split(r"[|,/]", rhs) if t.strip()]
        if items:
            return {
                "id": f"{prefix}_{idx}",
                "type": "control_code_contains",
                "contains": items,
                "contains_all": False,
            }
    if "unreachable" in lowered:
        tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_:]*", raw)
        names = [t for t in tokens if t.lower() not in {"unreachable", "path", "only", "no", "entry", "reachable"}]
        if names:
            return {
                "id": f"{prefix}_{idx}",
                "type": "call",
                "name_regex": "(?i)" + "|".join(re.escape(n) for n in names[:3]),
            }
    return None


def _compile_guard_atom(atom, idx, prefix):
    if isinstance(atom, dict):
        if atom.get("type"):
            cond = dict(atom)
            cond.setdefault("id", f"{prefix}_{idx}")
            return cond
        if atom.get("call") or atom.get("name") or atom.get("names") or atom.get("name_regex"):
            cond = {
                "id": f"{prefix}_{idx}",
                "type": "call_code_contains" if atom.get("contains") else "call",
                "name": atom.get("name") or atom.get("call"),
                "names": atom.get("names"),
                "name_regex": atom.get("name_regex"),
                "contains": atom.get("contains"),
                "contains_all": atom.get("contains_all", True),
                "lang": atom.get("lang", "Rust"),
            }
            return {k: v for k, v in cond.items() if v is not None and v != ""}
        if atom.get("contains"):
            return {
                "id": f"{prefix}_{idx}",
                "type": "control_code_contains",
                "contains": _ensure_list(atom.get("contains")),
                "contains_all": atom.get("contains_all", True),
            }
    if isinstance(atom, str):
        heuristic = _compile_text_guard_heuristic(atom, idx, prefix)
        if heuristic:
            return heuristic
        return {
            "id": f"{prefix}_{idx}",
            "type": "control_code_contains",
            "contains": [atom],
            "contains_all": True,
        }
    return None


def _compile_guard_expr(expr, prefix="guard"):
    if expr is None:
        return None
    if isinstance(expr, dict):
        if "all" in expr:
            sub = [_compile_guard_expr(it, prefix=prefix) for it in _ensure_list(expr.get("all"))]
            sub = [it for it in sub if it]
            return {"id": f"{prefix}_all", "type": "all_of", "conditions": sub} if sub else None
        if "any" in expr:
            sub = [_compile_guard_expr(it, prefix=prefix) for it in _ensure_list(expr.get("any"))]
            sub = [it for it in sub if it]
            return {"id": f"{prefix}_any", "type": "any_of", "conditions": sub} if sub else None
        if "not" in expr:
            sub = _compile_guard_expr(expr.get("not"), prefix=prefix)
            if not sub:
                return None
            return {"id": f"{prefix}_not", "type": "not", "condition": sub}
        return _compile_guard_atom(expr, 0, prefix)
    if isinstance(expr, list):
        sub = [_compile_guard_expr(it, prefix=prefix) for it in expr]
        sub = [it for it in sub if it]
        return {"id": f"{prefix}_all", "type": "all_of", "conditions": sub} if sub else None
    return _compile_guard_atom(expr, 0, prefix)


def _merge_trigger_conditions(trigger_model, conditions=None, mitigations=None):
    out = copy.deepcopy(trigger_model or {})
    out.setdefault("conditions", [])
    out.setdefault("mitigations", [])

    def add_unique(target, items):
        seen = {(str(c.get("id") or ""), str(c.get("type") or ""), str(c.get("name") or c.get("name_regex") or "")) for c in target if isinstance(c, dict)}
        for cond in items or []:
            if not isinstance(cond, dict):
                continue
            key = (str(cond.get("id") or ""), str(cond.get("type") or ""), str(cond.get("name") or cond.get("name_regex") or ""))
            if key in seen:
                continue
            seen.add(key)
            target.append(cond)

    add_unique(out["conditions"], conditions or [])
    add_unique(out["mitigations"], mitigations or [])
    return out


def normalize_vuln_rule(vuln):
    rule = copy.deepcopy(vuln or {})
    rule = _expand_symbol_family(rule)
    compiled_conditions = []
    compiled_mitigations = []
    explicit_trigger_conditions = list((rule.get("trigger_model", {}) or {}).get("conditions") or [])
    enforce_rust_sinks = bool(rule.get("enforce_rust_sinks", False))

    for idx, item in enumerate(_ensure_list(rule.get("must_flow"))):
        compiled_conditions.extend(_compile_must_flow_item(item, idx))

    guard_expr = rule.get("rust_guards")
    if guard_expr is None:
        guard_expr = rule.get("guards")
    if guard_expr is not None:
        guard_cond = _compile_guard_expr(guard_expr, prefix="rust_guard")
        if guard_cond:
            compiled_conditions.append(guard_cond)

    prune_expr = rule.get("prune_predicate")
    if prune_expr is None:
        prune_expr = rule.get("prune")
    if prune_expr is not None:
        prune_cond = _compile_guard_expr(prune_expr, prefix="prune")
        if prune_cond:
            compiled_mitigations.append(prune_cond)

    rust_sinks = []
    for sink in _ensure_list(rule.get("rust_sinks")):
        if isinstance(sink, dict):
            path = sink.get("path") or sink.get("name")
            contains = _ensure_list(sink.get("contains") or sink.get("code_contains"))
            contains_all = sink.get("contains_all", True)
        else:
            path = sink
            contains = []
            contains_all = True
        name = _coerce_call_name(path)
        if not name:
            continue
        cond = {
            "id": f"rust_sink_{name}",
            "type": "call_code_contains" if contains else "call",
            "name": name,
            "lang": "Rust",
        }
        if contains:
            cond["contains"] = contains
            cond["contains_all"] = contains_all
        rust_sinks.append(cond)
    compiled_rust_sink_conditions = 0
    if rust_sinks and (enforce_rust_sinks or not explicit_trigger_conditions):
        compiled_conditions.extend(rust_sinks)
        compiled_rust_sink_conditions = len(rust_sinks)

    trigger_model = _merge_trigger_conditions(
        rule.get("trigger_model", {}),
        conditions=compiled_conditions,
        mitigations=compiled_mitigations,
    )
    rule["trigger_model"] = trigger_model

    if not rule.get("symbols"):
        symbols = []
        for sink in _ensure_list(rule.get("native_sinks")):
            if isinstance(sink, dict):
                name = sink.get("name")
            else:
                name = sink
            if name and name not in symbols:
                symbols.append(name)
        if symbols:
            rule["symbols"] = symbols

    rule["rule_compile_meta"] = {
        "compiled_conditions": len(compiled_conditions),
        "compiled_mitigations": len(compiled_mitigations),
        "compiled_rust_sink_conditions": compiled_rust_sink_conditions,
        "used_high_level_fields": bool(compiled_conditions or compiled_mitigations),
    }
    return rule

def _extract_name_candidates(spec):
    if not isinstance(spec, dict):
        return []
    names = []
    for item in _ensure_list(spec.get("name") or spec.get("names")):
        token = str(item or "").strip()
        if token:
            names.append(token)
    return names


def _normalize_sink_candidate_specs(sink_names):
    specs = []
    seen = set()

    def add_spec(item):
        is_mapping = isinstance(item, dict)
        if isinstance(item, dict):
            name_regex = str(item.get("name_regex") or "").strip()
            raw = str(item.get("path") or item.get("name") or item.get("raw") or item.get("token") or "").strip()
            if not raw and not name_regex:
                return
            contains = [str(tok).strip().lower() for tok in _ensure_list(item.get("contains") or item.get("code_contains")) if str(tok).strip()]
            contains_all = bool(item.get("contains_all", True))
            context_tokens = [str(tok).strip().lower() for tok in _ensure_list(item.get("context_tokens")) if str(tok).strip()]
        else:
            name_regex = ""
            raw = str(item or "").strip()
            if not raw:
                return
            contains = []
            contains_all = True
            context_tokens = []

        token = _coerce_call_name(raw) if raw else ""
        if not token and not name_regex:
            return

        if is_mapping and not context_tokens and ("::" in raw or "." in raw):
            for part in re.split(r"::|\.", raw)[:-1]:
                lowered = str(part or "").strip().lower()
                if len(lowered) >= 3 and lowered not in {"crate", "self", "super"}:
                    context_tokens.append(lowered)

        spec = {
            "raw": raw or name_regex,
            "token": token,
            "name_regex": name_regex,
            "contains": contains,
            "contains_all": contains_all,
            "context_tokens": context_tokens,
        }
        key = (
            spec["raw"].lower(),
            spec["name_regex"],
            tuple(spec["contains"]),
            spec["contains_all"],
            tuple(spec["context_tokens"]),
        )
        if key in seen:
            return
        seen.add(key)
        specs.append(spec)

    for item in sink_names or []:
        add_spec(item)
    return specs


def _sink_spec_matches_text(spec, text):
    haystack = str(text or "").lower()
    if not haystack:
        return False

    contains = list(spec.get("contains") or [])
    if contains:
        if spec.get("contains_all", True):
            if not all(tok in haystack for tok in contains):
                return False
        elif not any(tok in haystack for tok in contains):
            return False

    context_tokens = list(spec.get("context_tokens") or [])
    if context_tokens and not any(tok in haystack for tok in context_tokens):
        return False

    return True


def _iter_condition_atoms(cond):
    if not isinstance(cond, dict):
        return
    yield cond
    ctype = str(cond.get("type") or "").strip()
    if ctype in {"all_of", "any_of"}:
        for sub in cond.get("conditions") or []:
            yield from _iter_condition_atoms(sub)
    elif ctype == "not":
        yield from _iter_condition_atoms(cond.get("condition") or {})


def _derive_symbol_sink_candidates(symbol):
    text = str(symbol or "").strip()
    if not text:
        return []
    out = [text]
    if text.startswith("git_") and len(text) > 4:
        out.append(text[4:])
    if "_" in text:
        tail = text.split("_", 1)[1].strip()
        if tail:
            out.append(tail)
    short = _coerce_call_name(text)
    if short:
        out.append(short)
    dedup = []
    seen = set()
    for item in out:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        dedup.append(item)
    return dedup


def collect_rust_sink_candidates(vuln_rule):
    rule = vuln_rule or {}
    candidates = []

    rust_sinks = _ensure_list(rule.get("rust_sinks"))
    if rust_sinks:
        candidates.extend(rust_sinks)
    else:
        trigger_model = rule.get("trigger_model", {}) or {}
        for cond in trigger_model.get("conditions", []) or []:
            for atom in _iter_condition_atoms(cond):
                ctype = str(atom.get("type") or "").strip()
                if ctype in {"call", "call_code_contains", "field_to_call_arg", "io_to_call_arg", "option_to_call_arg", "len_to_call_arg", "builder_flag_chain"}:
                    if atom.get("name") or atom.get("names") or atom.get("name_regex"):
                        candidates.append(
                            {
                                "name": atom.get("name") or atom.get("names"),
                                "name_regex": atom.get("name_regex"),
                                "contains": atom.get("contains") or atom.get("code_contains"),
                                "contains_all": atom.get("contains_all", True),
                            }
                        )
                    if atom.get("sink"):
                        candidates.append(atom.get("sink"))
                elif ctype == "call_order":
                    if atom.get("first"):
                        candidates.append(atom.get("first"))
                    if atom.get("second"):
                        candidates.append(atom.get("second"))
                elif ctype in {"api_sequence", "setup_sequence"}:
                    candidates.extend(atom.get("steps") or [])

    for symbol in _ensure_list(rule.get("symbols")):
        for candidate in _derive_symbol_sink_candidates(symbol):
            candidates.append(candidate)

    return _normalize_sink_candidate_specs(candidates)


def evaluate_version_guard(package_versions, package_name, version_range):
    versions = list(package_versions.get(package_name) or [])
    if not version_range:
        return {
            "status": "not_applicable",
            "versions": versions,
            "matched_versions": versions,
            "reason": "empty_version_range",
        }
    if not versions:
        return {
            "status": "unknown",
            "versions": [],
            "matched_versions": [],
            "reason": "missing_component_version",
        }
    matched = [v for v in versions if version_in_range(v, version_range)]
    if matched:
        return {
            "status": "satisfied",
            "versions": versions,
            "matched_versions": matched,
            "reason": "version_in_range",
        }
    return {
        "status": "failed",
        "versions": versions,
        "matched_versions": [],
        "reason": "all_versions_out_of_range",
    }


def _should_relax_version_guard_failure(vuln_rule, component_instances, version_eval):
    if str((version_eval or {}).get("status") or "") != "failed":
        return False
    pkg = str((vuln_rule or {}).get("package") or "").strip().lower().replace("-", "_")
    if pkg not in {"pcre2", "pcre2_sys"}:
        return False
    source_hint = str((vuln_rule or {}).get("source_status") or "").strip().lower()
    if source_hint == "system":
        return True
    for inst in component_instances or []:
        if str((inst or {}).get("source") or "").strip().lower() == "system":
            return True
    return False


def _extract_text_corpus(chain_nodes=None, control_nodes=None, calls=None):
    texts = []
    for node in chain_nodes or []:
        code = node.get("code")
        name = node.get("name")
        if isinstance(name, str) and name.strip():
            texts.append(name)
        if isinstance(code, str) and code.strip():
            texts.append(code)
    for node in control_nodes or []:
        code = node.get("code")
        if isinstance(code, str) and code.strip():
            texts.append(code)
        for child in node.get("child_codes") or []:
            if isinstance(child, str) and child.strip():
                texts.append(child)
    for call in calls or []:
        name = call.get("name")
        code = call.get("code")
        if isinstance(name, str) and name.strip():
            texts.append(name)
        if isinstance(code, str) and code.strip():
            texts.append(code)
    return texts


def _extract_text_window(text, start, end, radius=120):
    body = str(text or "")
    if not body:
        return ""
    try:
        lo = max(0, int(start or 0) - int(radius or 0))
        hi = min(len(body), int(end or 0) + int(radius or 0))
    except Exception:
        return body[: max(0, int(radius or 0) * 2)]
    snippet = body[lo:hi].strip()
    return snippet or body[lo:hi]


def _eval_env_guard_atom(atom, package_metadata, vuln_package, component_instances=None, analysis_context=None):
    if isinstance(atom, str):
        return {"status": "unknown", "guard": atom, "reason": "string_guard_not_machine_readable"}
    if not isinstance(atom, dict):
        return {"status": "unknown", "guard": atom, "reason": "unsupported_env_guard_atom"}
    gtype = str(atom.get("type") or "").strip()
    if not gtype:
        return {"status": "unknown", "guard": atom, "reason": "missing_env_guard_type"}

    if gtype == "component_source":
        target_pkg = atom.get("package") or vuln_package
        expected = _ensure_list(atom.get("expected") or atom.get("source"))
        inst_sources = []
        for inst in component_instances or []:
            if inst.get("component") == target_pkg and inst.get("source"):
                inst_sources.append(inst.get("source"))
        sources = inst_sources or list((package_metadata.get(target_pkg) or {}).get("sources") or [])
        if not expected:
            return {"status": "unknown", "guard": atom, "reason": "missing_expected_source"}
        if not sources:
            return {"status": "unknown", "guard": atom, "reason": "source_unknown", "package": target_pkg}
        if any(src in expected for src in sources):
            return {
                "status": "satisfied",
                "guard": atom,
                "package": target_pkg,
                "observed_sources": sources,
            }
        return {
            "status": "failed",
            "guard": atom,
            "package": target_pkg,
            "observed_sources": sources,
            "expected_sources": expected,
        }

    if gtype == "feature_enabled":
        target_pkg = atom.get("package") or vuln_package
        feature = atom.get("feature")
        inst_features = []
        for inst in component_instances or []:
            if inst.get("component") == target_pkg:
                for feat in inst.get("enabled_features") or []:
                    if feat not in inst_features:
                        inst_features.append(feat)
        features = inst_features or list((package_metadata.get(target_pkg) or {}).get("features") or [])
        if not feature:
            return {"status": "unknown", "guard": atom, "reason": "missing_feature_name"}
        if not features:
            return {"status": "unknown", "guard": atom, "reason": "feature_unknown", "package": target_pkg}
        if feature in features:
            return {
                "status": "satisfied",
                "guard": atom,
                "package": target_pkg,
                "feature": feature,
            }
        return {
            "status": "failed",
            "guard": atom,
            "package": target_pkg,
            "feature": feature,
            "observed_features": features,
        }

    if gtype == "package_present":
        target_pkg = atom.get("package")
        if not target_pkg:
            return {"status": "unknown", "guard": atom, "reason": "missing_package_name"}
        if target_pkg in package_metadata:
            return {"status": "satisfied", "guard": atom, "package": target_pkg}
        return {"status": "failed", "guard": atom, "package": target_pkg, "reason": "package_not_found"}

    if gtype == "version_in_range":
        target_pkg = atom.get("package") or vuln_package
        range_expr = atom.get("range") or atom.get("version_range") or ""
        versions = []
        for inst in component_instances or []:
            if inst.get("component") == target_pkg and inst.get("resolved_version"):
                versions.append(inst.get("resolved_version"))
        if not versions:
            versions = list((package_metadata.get(target_pkg) or {}).get("versions") or [])
        if not versions:
            return {"status": "unknown", "guard": atom, "reason": "missing_component_version", "package": target_pkg}
        if not range_expr:
            return {"status": "unknown", "guard": atom, "reason": "missing_version_range", "package": target_pkg}
        matched = [v for v in versions if version_in_range(v, range_expr)]
        if matched:
            return {"status": "satisfied", "guard": atom, "package": target_pkg, "matched_versions": matched}
        return {
            "status": "failed",
            "guard": atom,
            "package": target_pkg,
            "reason": "version_out_of_range",
            "observed_versions": versions,
        }

    if gtype in {"runtime_mode", "runtime_mode_contains"}:
        expected = _ensure_list(atom.get("expected") or atom.get("contains") or atom.get("mode"))
        texts = _extract_text_corpus(
            chain_nodes=(analysis_context or {}).get("chain_nodes"),
            control_nodes=(analysis_context or {}).get("control_nodes"),
            calls=(analysis_context or {}).get("calls"),
        )
        haystack = "\n".join(str(t) for t in texts).lower()
        if not expected:
            return {"status": "unknown", "guard": atom, "reason": "missing_runtime_mode_tokens"}
        hits = [tok for tok in expected if str(tok).lower() in haystack]
        if hits:
            return {"status": "satisfied", "guard": atom, "hits": hits}
        strict = bool(atom.get("strict", False))
        if strict:
            return {"status": "failed", "guard": atom, "reason": "runtime_mode_not_matched"}
        return {"status": "unknown", "guard": atom, "reason": "runtime_mode_not_observed"}

    if gtype == "build_mode":
        expected = str(atom.get("expected") or atom.get("mode") or "").strip().lower()
        observed = str((analysis_context or {}).get("build_mode") or "").strip().lower()
        if not expected:
            return {"status": "unknown", "guard": atom, "reason": "missing_build_mode"}
        if not observed:
            return {"status": "unknown", "guard": atom, "reason": "build_mode_unknown"}
        if expected == observed:
            return {"status": "satisfied", "guard": atom, "build_mode": observed}
        return {"status": "failed", "guard": atom, "build_mode": observed, "expected": expected}

    return {"status": "unknown", "guard": atom, "reason": f"unsupported_env_guard_type:{gtype}"}


def _eval_env_guard_expr(expr, package_metadata, vuln_package, component_instances=None, analysis_context=None):
    if isinstance(expr, dict) and "all" in expr:
        details = [
            _eval_env_guard_expr(
                it,
                package_metadata,
                vuln_package,
                component_instances=component_instances,
                analysis_context=analysis_context,
            )
            for it in _ensure_list(expr.get("all"))
        ]
        statuses = [d.get("status") for d in details]
        if "failed" in statuses:
            status = "failed"
        elif statuses and all(s == "satisfied" for s in statuses):
            status = "satisfied"
        else:
            status = "unknown"
        return {"status": status, "mode": "all", "details": details}
    if isinstance(expr, dict) and "any" in expr:
        details = [
            _eval_env_guard_expr(
                it,
                package_metadata,
                vuln_package,
                component_instances=component_instances,
                analysis_context=analysis_context,
            )
            for it in _ensure_list(expr.get("any"))
        ]
        statuses = [d.get("status") for d in details]
        if "satisfied" in statuses:
            status = "satisfied"
        elif statuses and all(s == "failed" for s in statuses):
            status = "failed"
        else:
            status = "unknown"
        return {"status": status, "mode": "any", "details": details}
    if isinstance(expr, dict) and "not" in expr:
        detail = _eval_env_guard_expr(
            expr.get("not"),
            package_metadata,
            vuln_package,
            component_instances=component_instances,
            analysis_context=analysis_context,
        )
        if detail.get("status") == "satisfied":
            status = "failed"
        elif detail.get("status") == "failed":
            status = "satisfied"
        else:
            status = "unknown"
        return {"status": status, "mode": "not", "details": [detail]}
    return _eval_env_guard_atom(
        expr,
        package_metadata,
        vuln_package,
        component_instances=component_instances,
        analysis_context=analysis_context,
    )


def _flatten_env_guard_items(result):
    if not isinstance(result, dict):
        return []
    if "details" not in result:
        return [result]
    out = []
    for d in result.get("details") or []:
        out.extend(_flatten_env_guard_items(d))
    return out


def evaluate_env_guards(vuln_rule, package_metadata, package_versions, component_instances=None, analysis_context=None):
    package_name = vuln_rule.get("package")
    version_range = vuln_rule.get("version_range", "")
    resolved_versions = []
    for inst in component_instances or []:
        if inst.get("component") == package_name and inst.get("resolved_version"):
            resolved_versions.append(inst.get("resolved_version"))
    if resolved_versions:
        version_map = dict(package_versions or {})
        version_map[package_name] = resolved_versions
    else:
        version_map = package_versions
    version_eval = evaluate_version_guard(version_map, package_name, version_range)
    status_items = []
    if version_eval.get("status") == "satisfied":
        status_items.append({"status": "satisfied", "kind": "version_range", "detail": version_eval})
    elif version_eval.get("status") == "failed":
        if _should_relax_version_guard_failure(vuln_rule, component_instances, version_eval):
            relaxed = dict(version_eval)
            relaxed["status"] = "unknown"
            relaxed["reason"] = "system_version_env_dependent"
            status_items.append({"status": "unknown", "kind": "version_range", "detail": relaxed})
        else:
            status_items.append({"status": "failed", "kind": "version_range", "detail": version_eval})
    elif version_eval.get("status") == "unknown":
        status_items.append({"status": "unknown", "kind": "version_range", "detail": version_eval})

    env_expr = vuln_rule.get("env_guards")
    if env_expr is None:
        env_expr = vuln_rule.get("env_guard")
    if env_expr:
        env_eval = _eval_env_guard_expr(
            env_expr,
            package_metadata,
            package_name,
            component_instances=component_instances,
            analysis_context=analysis_context,
        )
        for item in _flatten_env_guard_items(env_eval):
            kind = "env_guard"
            status_items.append({"status": item.get("status"), "kind": kind, "detail": item})

    satisfied = [it for it in status_items if it.get("status") == "satisfied"]
    failed = [it for it in status_items if it.get("status") == "failed"]
    unresolved = [it for it in status_items if it.get("status") not in {"satisfied", "failed"}]
    return {
        "status": "failed" if failed else ("satisfied" if satisfied and not unresolved else "unknown"),
        "version_eval": version_eval,
        "satisfied": satisfied,
        "failed": failed,
        "unresolved": unresolved,
        "raw": status_items,
    }


def build_empty_path_bundle():
    return {
        "path_constraints": [],
        "seed_constraints": [],
        "combined_constraints": [],
        "control_structures_relevant": [],
        "sink_calls": [],
        "sink_args": [],
        "sink_vars": [],
        "method_calls": [],
        "call_graph_edges": [],
        "method_signatures": {},
        "interproc_context": {
            "method_calls": [],
            "call_graph_edges": [],
            "method_signatures": {},
        },
        "abi_contracts": {
            "status": "unknown",
            "reason": "abi_contracts_not_evaluated",
            "constraints": [],
            "arg_bindings": [],
            "boundary_assumptions": [],
            "evidence": [],
            "conflict_reason": None,
        },
        "arg_bindings": [],
        "boundary_assumptions": [],
        "constants": {},
        "const_map": {},
        "value_env": {},
        "bundle_error": None,
    }


def build_param_semantics_default(reason):
    return {
        "status": "unknown",
        "reason": reason,
        "flags_eval": [],
        "len_eval": [],
        "nonnull_eval": [],
        "enum_eval": [],
        "callback_eval": [],
        "abi_contract_eval": {
            "status": "unknown",
            "reason": reason,
            "constraints_used": [],
            "conflict_reason": None,
            "evidence": [],
            "boundary_assumptions": [],
        },
        "interproc_eval": {
            "engine_version": "interproc_v2",
            "status": "unknown",
            "trace": [],
            "unresolved": [],
            "alias_summary": {
                "must_alias_sets": 0,
                "may_alias_entries": 0,
                "points_to_entries": 0,
            },
        },
    }


def build_state_semantics_default(status="not_applicable", reason=None):
    out = {
        "status": status,
        "rules": [],
        "field_observations": {},
        "constraints_used": [],
        "boundary_assumptions": [],
        "assumptions_used": [],
    }
    if reason is not None:
        out["reason"] = reason
    return out


def collect_assumption_evidence(vuln_rule, existential_input_result, path_bundle):
    assumptions = []
    for rule in existential_input_result.get("rules", []) or []:
        if rule.get("used_assumption"):
            assumptions.append(
                {
                    "source": "state_semantics",
                    "rule_index": rule.get("rule_index"),
                    "field": rule.get("field"),
                    "symbolic_var": (rule.get("observed_field") or {}).get("field") or rule.get("field"),
                    "reason": "used_assumption",
                }
            )
    for item in path_bundle.get("boundary_assumptions", []) or []:
        assumptions.append({"source": "path_bundle", "detail": item})

    input_predicate = vuln_rule.get("input_predicate") or {}
    strategy = str(input_predicate.get("strategy") or "").strip()
    if strategy in {"assume_if_not_explicit", "solve_if_length_explicit_else_assume"} and not assumptions:
        assumptions.append(
            {
                "source": "input_predicate",
                "class": input_predicate.get("class"),
                "strategy": strategy,
                "reason": "strategy_requires_assumption_when_explicit_constraints_absent",
            }
        )
    return assumptions


def _manual_name_variants(text):
    raw = str(text or "").strip()
    if not raw:
        return set()
    variants = {raw, raw.lower(), raw.replace("-", "_"), raw.replace("_", "-")}
    lowered = raw.lower()
    if lowered.startswith("lib") and len(lowered) > 3:
        variants.add(lowered[3:])
    suffixes = ("-sys2", "_sys2", "-sys", "_sys", "-rs", "_rs")
    for variant in list(variants):
        lowered_variant = variant.lower()
        for suffix in suffixes:
            if lowered_variant.endswith(suffix) and len(lowered_variant) > len(suffix):
                stripped = lowered_variant[: -len(suffix)]
                variants.add(stripped)
                variants.add(stripped.replace("-", "_"))
                variants.add(stripped.replace("_", "-"))
    return {item for item in variants if item}


def select_manual_evidence(entries, *, cve=None, package=None, symbol=None):
    if not entries:
        return None
    cve_text = str(cve or "").strip()
    pkg_variants = _manual_name_variants(package)
    sym_text = str(symbol or "").strip()
    for entry in entries:
        entry_cve = str(entry.get("cve") or "").strip()
        if entry_cve and cve_text and entry_cve != cve_text:
            continue
        entry_pkg = str(entry.get("package") or entry.get("component") or "").strip()
        if entry_pkg and pkg_variants and not (_manual_name_variants(entry_pkg) & pkg_variants):
            continue
        entry_symbol = str(entry.get("symbol") or "").strip()
        if entry_symbol and sym_text and entry_symbol != sym_text:
            continue
        return entry
    return None


def map_result_kind(triggerable_internal, reachable, assumptions_used, manual_status=None):
    if manual_status == "observable_triggered":
        return "ObservableTriggered"
    if manual_status == "path_triggered":
        return "PathTriggered"
    if not reachable:
        return "NotTriggerable"
    if triggerable_internal in {"false_positive", "unreachable"}:
        return "NotTriggerable"
    if triggerable_internal == "confirmed":
        if assumptions_used:
            return "TriggerableWithInputAssumption"
        return "Triggerable"
    return "Reachable"


def has_actionable_trigger_hits(trigger_hits):
    hits = list((trigger_hits or {}).get("required_hits") or [])
    if not hits:
        return False
    for item in hits:
        guard_id = str(item.get("id") or "")
        if guard_id.startswith("rust_sink_") or guard_id.startswith("must_flow_"):
            return True
        evidences = item.get("evidence") or []
        for ev in evidences:
            if isinstance(ev, dict):
                lang = str(ev.get("lang") or "")
                name = str(ev.get("name") or ev.get("call_name") or "")
                if lang == "Rust":
                    return True
                if name:
                    return True
    return False


def has_cross_language_native_evidence(
    *,
    source_status,
    call_reachability_source,
    has_method,
    strict_callsite_edges,
    native_analysis_coverage,
    native_dependency_imports,
    strict_dependency_resolution,
):
    status = str(source_status or "").strip()
    if status not in {"stub", "binary-only", "system"}:
        return True
    if has_method and call_reachability_source in {"c_method", "c_call", "symbol_usage"}:
        return True
    if int(strict_callsite_edges or 0) > 0:
        return True
    if str(native_analysis_coverage or "") in {"symbol_level", "callsite_level"}:
        return True
    if (strict_dependency_resolution or {}).get("dependencies") and native_dependency_imports:
        return True
    return False


def has_explicit_native_symbol_bridge(symbol, evidence_call_sets):
    target = str(symbol or "").strip().lower()
    if not target:
        return False
    ffi_markers = ("sys::", "ffi::", "bindings::", "gdal_sys::", "libxml::bindings::", "pcre2_sys::")
    for call in evidence_call_sets or []:
        call = call or {}
        name = str((call or {}).get("name") or "").strip().lower()
        code = str((call or {}).get("code") or "").strip().lower()
        scope = str(call.get("scope") or "")
        file_path = str(call.get("file") or "").replace("\\", "/").lower()
        if _native_symbol_names_match(target, name) and scope == "synthetic_package_method_code":
            return True
        if (
            target
            and code
            and _code_references_native_symbol(code, target)
            and (
                scope == "synthetic_package_method_code"
                or (
                    scope == "synthetic_source_text"
                    and file_path
                    and "/src/" in file_path
                    and "/target_" not in file_path
                    and not file_path.endswith("/readme.md")
                    and any(marker in code for marker in ffi_markers)
                )
            )
        ):
            return True
    return False


def _native_symbol_names_match(target, observed):
    target_raw = str(target or "").strip()
    observed_raw = str(observed or "").strip()
    target_text = target_raw.lower()
    observed_text = observed_raw.lower()
    if not target_text or not observed_text:
        return False
    if target_text == observed_text:
        return True
    if observed_text.startswith(target_text) and len(observed_text) > len(target_text):
        suffix_raw = observed_raw[len(target_raw):]
        if suffix_raw and (suffix_raw[0].isupper() or suffix_raw[0].isdigit() or suffix_raw[0] == "_"):
            return True
    return False


def _code_references_native_symbol(code, target):
    target_text = str(target or "").strip().lower()
    text = str(code or "").strip().lower()
    if not target_text or not text:
        return False
    if target_text in text:
        return True
    pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for match in pattern.finditer(text):
        if _native_symbol_names_match(target_text, match.group(2).lower()):
            return True
    return False


def has_dependency_source_symbol_bridge(symbol, deps, crate_hints=None):
    target = str(symbol or "").strip()
    if not target:
        return False
    target_lower = target.lower()
    ffi_markers = (
        f"sys::{target_lower}",
        f"ffi::{target_lower}",
        f"bindings::{target_lower}",
        f"gdal_sys::{target_lower}",
        f"pcre2_sys::{target_lower}",
    )
    crate_hints = {str(item or "").strip().lower() for item in (crate_hints or []) if str(item or "").strip()}
    packages = list((deps or {}).get("packages") or [])
    for pkg in packages:
        pkg = pkg or {}
        name = str(pkg.get("name") or "").strip().lower()
        if crate_hints and name not in crate_hints:
            continue
        manifest_path = str(pkg.get("manifest_path") or "").strip()
        if not manifest_path:
            continue
        src_dir = os.path.join(os.path.dirname(manifest_path), "src")
        if not os.path.isdir(src_dir):
            continue
        for base, _, files in os.walk(src_dir):
            for filename in files:
                if not filename.endswith(".rs"):
                    continue
                path = os.path.join(base, filename)
                try:
                    text = Path(path).read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                text_lower = text.lower()
                if target_lower not in text_lower:
                    continue
                if any(marker in text_lower for marker in ffi_markers):
                    return True
                if "use crate::bindings::*;" in text_lower and f"{target_lower}(" in text_lower:
                    return True
    return False


def _looks_like_comment_line(text):
    stripped = str(text or "").lstrip()
    return stripped.startswith("//") or stripped.startswith("///") or stripped.startswith("//!") or stripped.startswith("*") or stripped.startswith("/*")


def collect_package_native_gateway_calls(session, root_pkg, crate_aliases, max_methods=800):
    aliases = {str(item or "").strip().lower() for item in (crate_aliases or []) if str(item or "").strip()}
    if not aliases:
        return []
    rows = session.run(
        """
        MATCH (m:METHOD:Rust)
        WHERE coalesce(m.package, "") = $pkg
        RETURN m.id AS id, m.name AS name, m.code AS code
        LIMIT $limit
        """,
        pkg=root_pkg,
        limit=max(1, int(max_methods)),
    )
    pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    out = []
    seen = set()
    for row in rows:
        code = str(row.get("code") or "")
        if not code:
            continue
        for match in pattern.finditer(code):
            alias = match.group(1).lower()
            symbol = match.group(2)
            if alias not in aliases:
                continue
            key = (row.get("id"), alias, symbol)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "id": f"nativegateway:{row.get('id')}:{alias}:{symbol}",
                    "name": symbol,
                    "code": _extract_text_window(code, match.start(), match.end()),
                    "lang": "Rust",
                    "method": row.get("name"),
                    "scope": "synthetic_native_gateway_package",
                    "gateway_alias": alias,
                }
            )
    return out


def collect_source_native_gateway_calls(project_dir, crate_aliases, max_files=4000, max_hits=400):
    root = str(project_dir or "").strip()
    aliases = {str(item or "").strip().lower() for item in (crate_aliases or []) if str(item or "").strip()}
    if not root or not os.path.isdir(root) or not aliases:
        return []
    pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    out = []
    seen = set()
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {"target", "target_cpg", ".git", ".idea", ".vscode"}]
        for filename in filenames:
            if scanned >= max_files or len(out) >= max_hits:
                break
            if not filename.endswith(".rs"):
                continue
            scanned += 1
            path = os.path.join(dirpath, filename)
            try:
                if os.path.getsize(path) > 2 * 1024 * 1024:
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    content = handle.read()
            except Exception:
                continue
            relpath = os.path.relpath(path, root)
            for match in pattern.finditer(content):
                alias = match.group(1).lower()
                symbol = match.group(2)
                if alias not in aliases:
                    continue
                line_no = content.count("\n", 0, match.start()) + 1
                line_start = content.rfind("\n", 0, match.start()) + 1
                line_end = content.find("\n", match.start())
                if line_end < 0:
                    line_end = len(content)
                line_text = content[line_start:line_end].strip()
                if _looks_like_comment_line(line_text):
                    continue
                key = (relpath, line_no, alias, symbol)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    {
                        "id": f"nativegwsrc:{relpath}:{line_no}:{alias}:{symbol}",
                        "name": symbol,
                        "code": line_text,
                        "lang": "Rust",
                        "method": f"{relpath}:{line_no}",
                        "scope": "synthetic_native_gateway_source",
                        "file": relpath,
                        "line": line_no,
                        "gateway_alias": alias,
                    }
                )
                if len(out) >= max_hits:
                    break
        if scanned >= max_files or len(out) >= max_hits:
            break
    return out


def _native_component_dependency_candidates(component, native_component_instances):
    candidates = []
    seen = set()

    def add(name):
        text = str(name or "").strip()
        if not text:
            return
        key = text.lower()
        if key in seen:
            return
        seen.add(key)
        candidates.append(text)

    add(component)
    for instance in native_component_instances or []:
        for row in instance.get("matched_crates") or []:
            crate_name = row.get("crate")
            add(crate_name)
            for alias in _candidate_native_crate_aliases(crate_name):
                add(alias)
    return candidates


def find_best_dep_chain(session, root, pkg, native_component_instances=None):
    candidates = _native_component_dependency_candidates(pkg, native_component_instances)
    if not candidates:
        return {"target": None, "chain": [], "edges": []}
    rows = session.run(
        """
        MATCH p=(root:PACKAGE {name: $root})-[:DEPENDS_ON|NATIVE_DEPENDS_ON*0..]->(pkg:PACKAGE)
        WHERE pkg.name IN $pkg_names
        RETURN pkg.name AS target,
               CASE WHEN pkg.name = $preferred THEN 0 ELSE 1 END AS preferred_rank,
               length(p) AS plen,
               [n IN nodes(p) | n.name] AS chain,
               [rel IN relationships(p) | {
                   from: startNode(rel).name,
                   to: endNode(rel).name,
                   type: type(rel),
                   evidence_type: rel.evidence_type,
                   confidence: rel.confidence,
                   source: rel.source,
                   evidence: rel.evidence
               }] AS edges
        ORDER BY preferred_rank ASC, plen ASC
        LIMIT 8
        """,
        root=root,
        preferred=pkg,
        pkg_names=candidates,
    )
    for row in rows:
        return {
            "target": row.get("target"),
            "chain": list(row.get("chain") or []),
            "edges": list(row.get("edges") or []),
        }
    return {"target": None, "chain": [], "edges": []}


def has_transitive_native_symbol_bridge(session, component, gateway_symbols, target_symbol, max_depth=10):
    if session is None or not component or not target_symbol:
        return False
    symbols = [str(item or "").strip() for item in (gateway_symbols or []) if str(item or "").strip()]
    if not symbols:
        return False
    target = str(target_symbol or "").strip()
    if any(_native_symbol_names_match(target, sym) for sym in symbols):
        return True
    try:
        record = session.run(
            """
            UNWIND $sources AS src_name
            MATCH p = (:METHOD:C {package: $component, name: src_name})-[:CALL*1..10]->(:METHOD:C {package: $component, name: $target})
            RETURN 1 AS ok
            LIMIT 1
            """,
            component=component,
            sources=symbols[:64],
            target=target,
        ).single()
    except Exception:
        return False
    return bool(record)


def _is_weak_rust_code_reachability_source(source):
    return str(source or "").strip() in {"rust_method_code_root", "rust_method_code_package"}


def _score_public_entry_name(name):
    text = str(name or "").strip()
    lowered = text.lower()
    if not lowered:
        return 0
    score = 0
    # Prefer realistic externally-used entry methods over constructors/formatters.
    strong_tokens = (
        "search_slice",
        "search_reader",
        "from_bytes",
        "read_from_bytes",
        "blob2image",
        "decode",
        "parse",
        "scan",
        "search",
        "match",
        "find",
        "compile",
        "open",
        "load",
    )
    if any(tok in lowered for tok in strong_tokens):
        score += 120
    if lowered in {"new", "default", "fmt", "clone", "drop"}:
        score -= 180
    if lowered.startswith("test_") or lowered.startswith("bench_"):
        score -= 120
    if "src/" in lowered and ":" in lowered:
        # "src/foo.rs:123" pseudo methods from source scans are weaker than real method names.
        score -= 20
    return score


def _score_native_gateway_call(call, symbol="", sink_candidates=None):
    row = dict(call or {})
    name = str(row.get("name") or "").strip()
    code = str(row.get("code") or "").strip()
    method = str(row.get("method") or "").strip()
    score = 0
    if symbol and _native_symbol_names_match(symbol, name):
        score += 1000
    if symbol and _code_references_native_symbol(code, symbol):
        score += 700

    for spec in _normalize_sink_candidate_specs(sink_candidates or []):
        token = str(spec.get("token") or "").strip()
        if token and _name_matches_sink_token(name, token):
            score += 240
        if token and _name_matches_sink_token(method, token):
            score += 80
        if _sink_spec_matches_text(spec, code):
            score += 40

    score += _score_public_entry_name(name)
    score += _score_public_entry_name(method)

    lowered = name.lower()
    if re.search(r"(decode|parse|read|open|load|compile|scan|next)$", lowered):
        score += 60
    if re.search(r"(clear|delete|free|destroy|drop|release)$", lowered):
        score -= 120

    scope = str(row.get("scope") or "")
    if scope == "synthetic_native_gateway_source":
        score += 20
    elif scope == "synthetic_native_gateway_package":
        score += 10

    line = row.get("line")
    try:
        score -= min(int(line or 0), 10000) / 100000.0
    except Exception:
        pass
    return score


def select_relevant_native_gateway_calls(calls, symbol="", sink_candidates=None, limit=2):
    ranked = []
    for idx, call in enumerate(calls or []):
        ranked.append(
            (
                _score_native_gateway_call(call, symbol=symbol, sink_candidates=sink_candidates),
                -idx,
                call,
            )
        )
    ranked.sort(reverse=True)
    out = []
    seen = set()
    for _, _, call in ranked:
        key = (
            str(call.get("id") or ""),
            str(call.get("method") or ""),
            str(call.get("name") or ""),
            str(call.get("code") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(call)
        if len(out) >= max(1, int(limit or 1)):
            break
    return out
    return bool(record and record.get("ok"))


def summarize_guard_status(trigger_model_hits, env_guard_eval):
    trigger_model_hits = trigger_model_hits or {}
    satisfied = []
    unresolved = []
    failed = []

    for item in trigger_model_hits.get("required_hits", []) or []:
        guard_id = item.get("id") or item.get("name") or "trigger_condition"
        satisfied.append(f"trigger:{guard_id}")
    for item in trigger_model_hits.get("required_miss", []) or []:
        guard_id = item.get("id") or item.get("name") or "trigger_condition"
        unresolved.append(f"trigger:{guard_id}")
    for item in trigger_model_hits.get("mitigations_hit", []) or []:
        guard_id = item.get("id") or item.get("name") or "mitigation"
        failed.append(f"mitigation:{guard_id}")

    for idx, item in enumerate(env_guard_eval.get("satisfied", []) or []):
        kind = item.get("kind") or "env_guard"
        satisfied.append(f"{kind}:{idx}")
    for idx, item in enumerate(env_guard_eval.get("unresolved", []) or []):
        kind = item.get("kind") or "env_guard"
        unresolved.append(f"{kind}:{idx}")
    for idx, item in enumerate(env_guard_eval.get("failed", []) or []):
        kind = item.get("kind") or "env_guard"
        failed.append(f"{kind}:{idx}")

    return {
        "satisfied_guards": satisfied,
        "unresolved_guards": unresolved,
        "failed_guards": failed,
    }


def apply_manual_evidence(entry, manual_entry):
    if not manual_entry:
        entry["manual_evidence"] = None
        entry["manual_trigger_status"] = None
        return entry

    manual_status = str(manual_entry.get("status") or "").strip()
    if manual_status not in {"observable_triggered", "path_triggered"}:
        entry["manual_evidence"] = manual_entry
        entry["manual_trigger_status"] = None
        return entry

    entry["reachable"] = True
    entry["triggerable"] = "confirmed"
    entry["triggerable_internal"] = "confirmed"
    entry["trigger_confidence"] = "manual"
    entry["manual_evidence"] = manual_entry
    entry["manual_trigger_status"] = manual_status
    entry["result_kind"] = map_result_kind(
        entry.get("triggerable_internal"),
        entry.get("reachable"),
        entry.get("assumptions_used"),
        manual_status=manual_status,
    )
    notes = list(entry.get("evidence_notes") or [])
    summary = str(manual_entry.get("summary") or "").strip()
    if manual_status == "observable_triggered":
        notes.append("Manual reproduction recorded: observable vulnerability trigger confirmed.")
    else:
        notes.append("Manual reproduction recorded: attacker-controlled input reaches the vulnerable native path.")
    if summary:
        notes.append(f"Manual evidence summary: {summary}")
    artifacts = manual_entry.get("artifacts") or []
    if artifacts:
        notes.append(f"Manual evidence artifacts: {artifacts}")
    entry["evidence_notes"] = notes
    return entry


def clear_supplychain(session):
    session.run("""
        MATCH ()-[r]-()
        WHERE type(r) IN $rel_types
        DELETE r
    """, rel_types=SUPPLYCHAIN_REL_TYPES)
    session.run("""
        MATCH (n)
        WHERE n:PACKAGE OR n:VERSION OR n:VULNERABILITY OR n:SYMBOL OR n:BINARY OR n:EXPORTED_SYMBOL OR n:IMPORTED_SYMBOL
        DETACH DELETE n
    """)

def import_dependencies(session, deps):
    packages = deps.get("packages", [])
    depends = deps.get("depends", [])

    for p in packages:
        session.run("""
            MERGE (pkg:PACKAGE {name: $name})
            SET pkg.lang = $lang
        """, name=p["name"], lang=p.get("lang", "Unknown"))

        if p.get("version"):
            session.run("""
                MERGE (ver:VERSION {semver: $ver})
                WITH ver
                MATCH (pkg:PACKAGE {name: $name})
                MERGE (pkg)-[:HAS_VERSION]->(ver)
            """, name=p["name"], ver=p["version"])

    for d in depends:
        session.run("""
            MATCH (a:PACKAGE {name: $from})
            MATCH (b:PACKAGE {name: $to})
            MERGE (a)-[r:DEPENDS_ON]->(b)
            SET r.evidence_type = coalesce($evidence_type, r.evidence_type)
            SET r.confidence = coalesce($confidence, r.confidence)
            SET r.source = coalesce($source, r.source)
            SET r.evidence = coalesce($evidence, r.evidence)
        """, parameters={
            "from": d["from"],
            "to": d["to"],
            "evidence_type": d.get("evidence_type"),
            "confidence": d.get("confidence"),
            "source": d.get("source"),
            "evidence": d.get("evidence")
        })

def import_vulns(session, vulns, deps):
    package_versions = {}
    for p in deps.get("packages", []):
        if p.get("version"):
            package_versions.setdefault(p["name"], []).append(p["version"])

    for v in vulns:
        cve = v["cve"]
        pkg_name = v["package"]
        vrange = v.get("version_range", "")
        session.run("""
            MERGE (v:VULNERABILITY {cve: $cve})
            SET v.description = $desc
        """, cve=cve, desc=v.get("description", ""))

        # Attach to versions that satisfy the range
        matched = False
        for ver in package_versions.get(pkg_name, []):
            if version_in_range(ver, vrange):
                matched = True
                session.run("""
                    MERGE (p:PACKAGE {name: $pkg})
                    SET p.lang = coalesce(p.lang, "C")
                    WITH p
                    MATCH (ver:VERSION {semver: $ver})
                    MATCH (v:VULNERABILITY {cve: $cve})
                    MERGE (p)-[:HAS_VERSION]->(ver)
                    MERGE (ver)-[:EXPOSES_VULN]->(v)
                """, pkg=pkg_name, ver=ver, cve=cve)

        if not matched:
            # Fallback: attach to package if no version info
            session.run("""
                MERGE (p:PACKAGE {name: $pkg})
                SET p.lang = coalesce(p.lang, "C")
                WITH p
                MATCH (v:VULNERABILITY {cve: $cve})
                MERGE (p)-[:EXPOSES_VULN]->(v)
            """, pkg=pkg_name, cve=cve)

def attach_symbols(session, vulns):
    for v in vulns:
        pkg_name = v["package"]
        source_status = v.get("source_status")
        for sym in v.get("symbols", []):
            session.run("""
                MERGE (s:SYMBOL {name: $sym, lang: "C"})
                SET s.source_status = coalesce($status, s.source_status)
                WITH s
                MERGE (p:PACKAGE {name: $pkg})
                SET p.lang = coalesce(p.lang, "C")
                MERGE (p)-[:PROVIDES_SYMBOL]->(s)
            """, sym=sym, pkg=pkg_name, status=source_status)

            # Resolve to C method if present
            session.run("""
                MATCH (s:SYMBOL {name: $sym, lang:"C"})
                MATCH (m:METHOD:C {name: $sym})
                MERGE (s)-[:RESOLVES_TO]->(m)
                SET m.package = $pkg
            """, sym=sym, pkg=pkg_name)

def attach_root_package_to_rust_methods(session, root_pkg):
    session.run("""
        MATCH (m:METHOD:Rust)
        WHERE m.package IS NULL
        SET m.package = $pkg
    """, pkg=root_pkg)

def build_symbol_usage(session):
    session.run("""
        MATCH (c:CALL:Rust)-[:FFI_CALL]->(m:METHOD:C)
        MATCH (s:SYMBOL {name: m.name, lang:"C"})
        MERGE (c)-[:USES_SYMBOL]->(s)
    """)
    # Fallback for missing C bodies: link Rust FFI calls by name to symbols
    session.run("""
        MATCH (c:CALL:Rust {is_ffi: true})
        MATCH (s:SYMBOL {lang:"C"})
        WHERE c.name = s.name
        MERGE (c)-[:USES_SYMBOL]->(s)
    """)
    # Link C calls to symbols (binary-only .so usage)
    session.run("""
        MATCH (c:CALL:C)
        MATCH (s:SYMBOL {lang:"C"})
        WHERE c.name = s.name
        MERGE (c)-[:USES_SYMBOL]->(s)
    """)
    # Lift call-level symbol usage to the containing Rust method so wrapper methods
    # remain discoverable even when the concrete extern call node is missing.
    session.run("""
        MATCH (m:METHOD:Rust)-[:CFG|AST*0..40]->(c:CALL:Rust)-[:USES_SYMBOL]->(s:SYMBOL {lang:"C"})
        MERGE (m)-[:USES_SYMBOL]->(s)
    """)

def link_c_calls_by_name(session):
    session.run("""
        MATCH (c:CALL:C), (m:METHOD:C)
        WHERE c.name = m.name
          AND NOT c.name STARTS WITH "<"
          AND NOT c.name STARTS WITH "operator"
        MERGE (c)-[:CALL]->(m)
    """)

def build_pkg_call(session, root_pkg):
    session.run("""
        MATCH (c:CALL:Rust)-[:FFI_CALL]->(m:METHOD:C)
        WITH DISTINCT m
        MATCH (p1:PACKAGE {name: $root})
        MATCH (p2:PACKAGE {name: m.package})
        MERGE (p1)-[:PKG_CALL {derived:true}]->(p2)
    """, root=root_pkg)
    session.run("""
        MATCH (p1:PACKAGE {name: $root})
        MATCH (c:CALL:Rust)-[:USES_SYMBOL]->(s:SYMBOL)-[:PROVIDES_SYMBOL]->(p2:PACKAGE)
        MERGE (p1)-[:PKG_CALL {derived:true}]->(p2)
    """, root=root_pkg)
    session.run("""
        MATCH (p1:PACKAGE {name: $root})
        MATCH (c:CALL:C)-[:USES_SYMBOL]->(s:SYMBOL)-[:PROVIDES_SYMBOL]->(p2:PACKAGE)
        MERGE (p1)-[:PKG_CALL {derived:true}]->(p2)
    """, root=root_pkg)
    session.run("""
        MATCH (p1:PACKAGE {name: $root})
        MATCH (m:METHOD:Rust {package: $root})-[:USES_SYMBOL]->(s:SYMBOL)-[:PROVIDES_SYMBOL]->(p2:PACKAGE)
        MERGE (p1)-[:PKG_CALL {derived:true}]->(p2)
    """, root=root_pkg)

def find_dep_chain(session, root, pkg):
    res = session.run("""
        MATCH p=(root:PACKAGE {name: $root})-[:DEPENDS_ON|NATIVE_DEPENDS_ON*0..]->(pkg:PACKAGE {name: $pkg})
        RETURN [n IN nodes(p) | n.name] AS chain
        LIMIT 1
    """, root=root, pkg=pkg).single()
    return res["chain"] if res else []

def find_dep_chain_evidence(session, root, pkg):
    res = session.run("""
        MATCH p=(root:PACKAGE {name: $root})-[:DEPENDS_ON|NATIVE_DEPENDS_ON*0..]->(pkg:PACKAGE {name: $pkg})
        RETURN [rel IN relationships(p) | {
            from: startNode(rel).name,
            to: endNode(rel).name,
            type: type(rel),
            evidence_type: rel.evidence_type,
            confidence: rel.confidence,
            source: rel.source,
            evidence: rel.evidence
        }] AS edges
        LIMIT 1
    """, root=root, pkg=pkg).single()
    return res["edges"] if res else []

def find_call_chain_to_method(session, root_method, symbol):
    res = session.run("""
        MATCH p=shortestPath(
            (m:METHOD:Rust {name: $root})-[:CFG|AST|CALL|FFI_CALL*0..]->(cm:METHOD:C {name: $sym})
        )
        RETURN [n IN nodes(p) | {id: n.id, labels: labels(n), name: n.name, code: n.code}] AS chain
        LIMIT 1
    """, root=root_method, sym=symbol).single()
    return res["chain"] if res else []

def find_call_chain_to_call(session, root_method, symbol):
    res = session.run("""
        MATCH p=shortestPath(
            (m:METHOD:Rust {name: $root})-[:CFG|AST|CALL|FFI_CALL*0..]->(c:CALL:C {name: $sym})
        )
        RETURN [n IN nodes(p) | {id: n.id, labels: labels(n), name: n.name, code: n.code}] AS chain
        LIMIT 1
    """, root=root_method, sym=symbol).single()
    return res["chain"] if res else []

def find_call_chain_to_symbol_usage(session, root_method, symbol):
    res = session.run("""
        MATCH p=shortestPath(
            (m:METHOD:Rust {name: $root})-[:CFG|AST|CALL*0..]->(c:CALL:Rust)
        )
        WHERE (c)-[:USES_SYMBOL]->(:SYMBOL {name: $sym, lang:"C"})
        RETURN [n IN nodes(p) | {id: n.id, labels: labels(n), name: n.name, code: n.code}] AS chain
        LIMIT 1
    """, root=root_method, sym=symbol).single()
    return res["chain"] if res else []

def find_call_chain_to_method_symbol_usage(session, root_method, symbol, root_pkg=None):
    res = session.run("""
        MATCH (m:METHOD:Rust {name: $root})
        WHERE $pkg = "" OR coalesce(m.package, "") = $pkg
        MATCH (target:METHOD:Rust)-[:USES_SYMBOL]->(:SYMBOL {name: $sym, lang:"C"})
        WHERE $pkg = "" OR coalesce(target.package, "") = $pkg
        MATCH p=shortestPath((m)-[:CFG|AST|CALL*0..40]->(target))
        RETURN length(p) AS plen,
               [n IN nodes(p) | {id: n.id, labels: labels(n), name: n.name, code: n.code}] AS chain
        ORDER BY plen ASC
        LIMIT 1
    """, root=root_method, sym=symbol, pkg=root_pkg or "").single()
    return res["chain"] if res else []

def _normalize_sink_tokens(sink_names):
    out = []
    seen = set()
    for spec in _normalize_sink_candidate_specs(sink_names):
        token = str(spec.get("token") or "").strip()
        if not token:
            continue
        key = token.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(token)
    return out


def _name_matches_sink_token(name, token, full_name=None):
    lowered = str(name or "").lower()
    token_lower = str(token or "").lower()
    if not lowered or not token_lower:
        return False
    if lowered == token_lower or lowered.endswith("::" + token_lower):
        return True
    full_lower = str(full_name or "").lower()
    return bool(full_lower and (full_lower == token_lower or full_lower.endswith("::" + token_lower)))


def find_call_chain_to_rust_call(session, root_method, sink_names, root_pkg=None):
    specs = _normalize_sink_candidate_specs(sink_names)
    tokens = [spec.get("token") for spec in specs if spec.get("token")]
    if not tokens:
        return []
    rows = session.run(
        """
        MATCH (m:METHOD:Rust {name: $root})
        WHERE $pkg = "" OR coalesce(m.package, "") = $pkg
        MATCH (c:CALL:Rust)
        WHERE any(s IN $sink_tokens WHERE
            toLower(coalesce(c.name, "")) = toLower(s)
            OR toLower(coalesce(c.name, "")) ENDS WITH ("::" + toLower(s))
        )
        MATCH p=shortestPath((m)-[:CFG|AST|CALL*0..40]->(c))
        RETURN length(p) AS plen,
               c.name AS call_name,
               c.code AS call_code,
               [n IN nodes(p) | {id: n.id, labels: labels(n), name: n.name, code: n.code}] AS chain
        ORDER BY plen ASC
        LIMIT 80
        """,
        root=root_method,
        pkg=root_pkg or "",
        sink_tokens=tokens,
    )
    for row in rows:
        call_name = row.get("call_name")
        call_code = row.get("call_code")
        for spec in specs:
            if _name_matches_sink_token(call_name, spec.get("token")) and _sink_spec_matches_text(spec, call_code):
                return row["chain"]
    return []


def find_call_chain_to_rust_method(session, root_method, sink_names, root_pkg=None):
    specs = _normalize_sink_candidate_specs(sink_names)
    tokens = [spec.get("token") for spec in specs if spec.get("token")]
    if not tokens:
        return []
    rows = session.run(
        """
        MATCH (m:METHOD:Rust {name: $root})
        WHERE $pkg = "" OR coalesce(m.package, "") = $pkg
        MATCH (target:METHOD:Rust)
        WHERE any(s IN $sink_tokens WHERE
            toLower(coalesce(target.name, "")) = toLower(s)
            OR toLower(coalesce(target.full_name, "")) = toLower(s)
            OR toLower(coalesce(target.name, "")) ENDS WITH ("::" + toLower(s))
            OR toLower(coalesce(target.full_name, "")) ENDS WITH ("::" + toLower(s))
        )
        MATCH p=shortestPath((m)-[:CFG|AST|CALL*0..40]->(target))
        RETURN length(p) AS plen,
               target.name AS target_name,
               target.full_name AS target_full_name,
               target.code AS target_code,
               [n IN nodes(p) | {id: n.id, labels: labels(n), name: n.name, code: n.code}] AS chain
        ORDER BY plen ASC
        LIMIT 80
        """,
        root=root_method,
        pkg=root_pkg or "",
        sink_tokens=tokens,
    )
    for row in rows:
        for spec in specs:
            if _name_matches_sink_token(row.get("target_name"), spec.get("token"), row.get("target_full_name")) and _sink_spec_matches_text(spec, row.get("target_code")):
                return row["chain"]
    return []


def find_call_chain_to_rust_method_code_sink(session, root_method, sink_names, root_pkg=None):
    specs = [spec for spec in _normalize_sink_candidate_specs(sink_names) if len(_coerce_call_name(spec.get("token"))) >= 3]
    tokens = [spec.get("token") for spec in specs if spec.get("token")]
    if not tokens:
        return []
    rows = session.run(
        """
        MATCH (m:METHOD:Rust {name: $root})
        WHERE $pkg = "" OR coalesce(m.package, "") = $pkg
        MATCH (target:METHOD:Rust)
        WHERE any(s IN $sink_tokens WHERE
            toLower(coalesce(target.code, "")) CONTAINS toLower(s)
        )
        MATCH p=shortestPath((m)-[:CFG|AST|CALL*0..40]->(target))
        RETURN length(p) AS plen,
               target.code AS target_code,
               [n IN nodes(p) | {id: n.id, labels: labels(n), name: n.name, code: n.code}] AS chain
        ORDER BY plen ASC
        LIMIT 80
        """,
        root=root_method,
        pkg=root_pkg or "",
        sink_tokens=tokens,
    )
    for row in rows:
        for spec in specs:
            if _sink_spec_matches_text(spec, row.get("target_code")):
                return row["chain"]
    return []


def find_pkg_call_chain_to_rust_call(session, root_pkg, sink_names):
    specs = _normalize_sink_candidate_specs(sink_names)
    tokens = [spec.get("token") for spec in specs if spec.get("token")]
    if not tokens:
        return []
    rows = session.run(
        """
        MATCH (m:METHOD:Rust)
        WHERE coalesce(m.package, "") = $pkg
        MATCH (c:CALL:Rust)
        WHERE any(s IN $sink_tokens WHERE
            toLower(coalesce(c.name, "")) = toLower(s)
            OR toLower(coalesce(c.name, "")) ENDS WITH ("::" + toLower(s))
        )
        MATCH p=shortestPath((m)-[:CFG|AST|CALL*0..40]->(c))
        RETURN length(p) AS plen,
               c.name AS call_name,
               c.code AS call_code,
               [n IN nodes(p) | {id: n.id, labels: labels(n), name: n.name, code: n.code}] AS chain
        ORDER BY plen ASC
        LIMIT 80
        """,
        pkg=root_pkg,
        sink_tokens=tokens,
    )
    best_chain = []
    best_score = None
    for row in rows:
        call_name = row.get("call_name")
        call_code = row.get("call_code")
        chain = list(row.get("chain") or [])
        root_name = str((chain[0] or {}).get("name") or "") if chain else ""
        matched = False
        row_score = _score_public_entry_name(root_name) + _score_public_entry_name(call_name)
        try:
            row_score -= int(row.get("plen") or 0)
        except Exception:
            pass
        for spec in specs:
            if _name_matches_sink_token(call_name, spec.get("token")) and _sink_spec_matches_text(spec, call_code):
                matched = True
                token = str(spec.get("token") or "")
                if token:
                    row_score += 30
                break
        if not matched:
            continue
        if best_score is None or row_score > best_score:
            best_score = row_score
            best_chain = chain
    return best_chain


def find_pkg_method_code_sink(session, root_pkg, sink_names):
    specs = [spec for spec in _normalize_sink_candidate_specs(sink_names) if len(_coerce_call_name(spec.get("token"))) >= 3]
    tokens = [spec.get("token") for spec in specs if spec.get("token")]
    if not tokens:
        return []
    rows = session.run(
        """
        MATCH (m:METHOD:Rust)
        WHERE coalesce(m.package, "") = $pkg
          AND any(s IN $sink_tokens WHERE toLower(coalesce(m.code, "")) CONTAINS toLower(s))
        RETURN {id: m.id, labels: labels(m), name: m.name, code: m.code} AS node
        LIMIT 120
        """,
        pkg=root_pkg,
        sink_tokens=tokens,
    )
    best_node = None
    best_score = None
    for row in rows:
        node = row["node"]
        node_name = str(node.get("name") or "")
        node_code = node.get("code")
        row_score = _score_public_entry_name(node_name)
        matched = False
        for spec in specs:
            if _sink_spec_matches_text(spec, node_code):
                matched = True
                token = str(spec.get("token") or "")
                if token and _name_matches_sink_token(node_name, token):
                    row_score += 40
                else:
                    row_score += 10
                break
        if not matched:
            continue
        if best_score is None or row_score > best_score:
            best_score = row_score
            best_node = node
    return [best_node] if best_node else []

def find_pkg_method_symbol_usage(session, root_pkg, symbol):
    res = session.run(
        """
        MATCH (m:METHOD:Rust {package: $pkg})-[:USES_SYMBOL]->(:SYMBOL {name: $sym, lang:"C"})
        RETURN {id: m.id, labels: labels(m), name: m.name, code: m.code} AS node
        LIMIT 40
        """,
        pkg=root_pkg,
        sym=symbol,
    )
    best_node = None
    best_score = None
    for row in res:
        node = row.get("node") or {}
        name = str(node.get("name") or "")
        score = _score_public_entry_name(name)
        if best_score is None or score > best_score:
            best_score = score
            best_node = node
    return [best_node] if best_node else []

def extract_function_names(chain_nodes):
    out = []
    for n in chain_nodes:
        labels = n.get("labels", [])
        if "METHOD" in labels or "CALL" in labels:
            name = n.get("name")
            if name:
                out.append(name)
    return out

def pick_trigger_point(chain_nodes, symbol):
    if not chain_nodes:
        return None
    for n in reversed(chain_nodes):
        labels = n.get("labels", [])
        if "CALL" in labels and n.get("name") == symbol:
            return {"id": n.get("id"), "label": "CALL", "name": n.get("name")}
    for n in reversed(chain_nodes):
        labels = n.get("labels", [])
        if "METHOD" in labels and n.get("name") == symbol:
            return {"id": n.get("id"), "label": "METHOD", "name": n.get("name")}
    last = chain_nodes[-1]
    return {"id": last.get("id"), "label": ",".join(last.get("labels", [])), "name": last.get("name")}

def collect_method_calls(session, method_id, lang, method_name=None):
    if lang == "Rust":
        res = session.run("""
            MATCH (m:METHOD:Rust {id: $mid})-[:CFG]->(entry:BLOCK)
            MATCH (entry)-[:CFG*0..]->(b:BLOCK)-[:AST]->(c:CALL)
            RETURN DISTINCT c.id as id, c.name as name, c.code as code
        """, mid=method_id)
    else:
        res = session.run("""
            MATCH (m:METHOD:C {id: $mid})-[:AST*0..]->(c:CALL:C)
            RETURN DISTINCT c.id as id, c.name as name, c.code as code
        """, mid=method_id)

    calls = []
    for r in res:
        if not r.get("name"):
            continue
        calls.append({
            "id": r.get("id"),
            "name": r.get("name"),
            "code": r.get("code"),
            "lang": lang,
            "method": method_name
        })
    return calls

def find_enclosing_method(session, call_id):
    res = session.run("""
        MATCH (m:METHOD:Rust)-[:CFG]->(entry:BLOCK)
        MATCH (entry)-[:CFG*0..]->(b:BLOCK)-[:AST]->(c:CALL {id: $cid})
        RETURN m.id as id, m.name as name
        LIMIT 1
    """, cid=call_id).single()
    return (res["id"], res["name"]) if res else (None, None)

def collect_chain_calls(chain_nodes):
    calls = []
    for n in chain_nodes:
        labels = n.get("labels", [])
        if "CALL" not in labels:
            continue
        name = n.get("name")
        if not name:
            continue
        lang = "Rust" if "Rust" in labels else ("C" if "C" in labels else None)
        calls.append({
            "id": n.get("id"),
            "name": name,
            "code": n.get("code"),
            "lang": lang,
            "method": None,
            "scope": "chain"
        })
    return calls

def collect_evidence_calls(session, chain_nodes):
    chain_calls = collect_chain_calls(chain_nodes)
    methods = []
    for n in chain_nodes:
        if "METHOD" in n.get("labels", []) and n.get("id"):
            methods.append(n)

    method_calls = []
    for m in methods:
        labels = m.get("labels", [])
        if "Rust" in labels:
            lang = "Rust"
        elif "C" in labels:
            lang = "C"
        else:
            continue
        method_calls.extend(collect_method_calls(session, m["id"], lang, method_name=m.get("name")))

    by_key = {}
    for c in chain_calls + method_calls:
        key = (c.get("id"), c.get("name"), c.get("lang"))
        prev = by_key.get(key)
        if prev is None:
            by_key[key] = c
            continue
        # Prefer entries that preserve method context for inter-procedural reasoning.
        prev_method = prev.get("method")
        new_method = c.get("method")
        if (not prev_method) and new_method:
            merged = dict(prev)
            merged.update(c)
            by_key[key] = merged

    all_calls = list(by_key.values())

    return {
        "chain_calls": chain_calls,
        "all_calls": all_calls
    }

def _find_sink_match_in_text(text, token="", name_regex=""):
    if not text:
        return None
    if token:
        try:
            return re.search(rf"\b{re.escape(token)}\s*\(", text)
        except re.error:
            return None
    if not name_regex:
        return None
    try:
        call_matches = re.finditer(r"\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(", text)
    except re.error:
        return None
    for match in call_matches:
        call_name = match.group(1)
        try:
            if re.search(name_regex, call_name or "") is not None:
                return match
        except re.error:
            return None
    return None


def _extract_code_snippet_for_sink(code, sink_name, width=120):
    text = str(code or "")
    token = ""
    name_regex = ""
    if isinstance(sink_name, dict):
        token = _coerce_call_name(sink_name.get("token") or sink_name.get("raw"))
        name_regex = str(sink_name.get("name_regex") or "").strip()
    else:
        token = _coerce_call_name(sink_name)
    if not text or (not token and not name_regex):
        return text
    match = _find_sink_match_in_text(text, token=token, name_regex=name_regex)
    if not match:
        return text
    start = max(0, match.start() - width)
    end = min(len(text), match.end() + width)
    return text[start:end]


def synthesize_sink_calls_from_method_code(chain_nodes, sink_names):
    specs = [
        spec
        for spec in _normalize_sink_candidate_specs(sink_names)
        if len(spec.get("token") or "") >= 3 or spec.get("name_regex")
    ]
    if not specs:
        return []

    synthetic = []
    synthetic_seen = set()
    for node in chain_nodes or []:
        labels = node.get("labels") or []
        if "METHOD" not in labels:
            continue
        method_code = str(node.get("code") or "")
        if not method_code:
            continue
        method_name = node.get("name")
        method_id = node.get("id")
        for spec in specs:
            token = spec.get("token")
            hit = _find_sink_match_in_text(method_code, token=token, name_regex=spec.get("name_regex"))
            if not hit:
                continue
            snippet = _extract_code_snippet_for_sink(method_code, spec)
            if not _sink_spec_matches_text(spec, snippet or method_code):
                continue
            key_token = (token or spec.get("name_regex") or "").lower()
            key = (method_id, key_token)
            if key in synthetic_seen:
                continue
            synthetic_seen.add(key)
            synthetic.append(
                {
                    "id": f"synthetic:{method_id}:{key_token}",
                    "name": token or spec.get("raw"),
                    "code": _extract_code_snippet_for_sink(method_code, spec),
                    "lang": "Rust",
                    "method": method_name,
                    "scope": "synthetic_method_code",
                }
            )
    return synthetic


def collect_package_synthetic_sink_calls(session, root_pkg, sink_names, max_methods=800):
    specs = [
        spec
        for spec in _normalize_sink_candidate_specs(sink_names)
        if len(spec.get("token") or "") >= 3 or spec.get("name_regex")
    ]
    if not specs:
        return []

    rows = session.run(
        """
        MATCH (m:METHOD:Rust)
        WHERE coalesce(m.package, "") = $pkg
        RETURN m.id AS id, m.name AS name, m.code AS code
        LIMIT $limit
        """,
        pkg=root_pkg,
        limit=max(1, int(max_methods)),
    )
    synthetic = []
    synthetic_seen = set()
    for row in rows:
        method_id = row.get("id")
        method_name = row.get("name")
        method_code = str(row.get("code") or "")
        if not method_code:
            continue
        for spec in specs:
            token = spec.get("token")
            hit = _find_sink_match_in_text(method_code, token=token, name_regex=spec.get("name_regex"))
            if not hit:
                continue
            snippet = _extract_code_snippet_for_sink(method_code, spec)
            if not _sink_spec_matches_text(spec, snippet or method_code):
                continue
            key_token = (token or spec.get("name_regex") or "").lower()
            key = (method_id, key_token)
            if key in synthetic_seen:
                continue
            synthetic_seen.add(key)
            synthetic.append(
                {
                    "id": f"pkgsynthetic:{method_id}:{key_token}",
                    "name": token or spec.get("raw"),
                    "code": _extract_code_snippet_for_sink(method_code, spec),
                    "lang": "Rust",
                    "method": method_name,
                    "scope": "synthetic_package_method_code",
                }
            )
    return synthetic


def collect_source_synthetic_sink_calls(project_dir, sink_names, max_files=4000, max_hits=400):
    root = str(project_dir or "").strip()
    if not root or not os.path.isdir(root):
        return []
    specs = [
        spec
        for spec in _normalize_sink_candidate_specs(sink_names)
        if len(spec.get("token") or "") >= 3 or spec.get("name_regex")
    ]
    if not specs:
        return []

    synthetic = []
    synthetic_seen = set()
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {"target", "target_cpg", ".git", ".idea", ".vscode"}]
        for filename in filenames:
            if scanned >= max_files or len(synthetic) >= max_hits:
                break
            if not filename.endswith(".rs"):
                continue
            scanned += 1
            path = os.path.join(dirpath, filename)
            try:
                if os.path.getsize(path) > 2 * 1024 * 1024:
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    content = handle.read()
            except Exception:
                continue
            relpath = os.path.relpath(path, root)
            for spec in specs:
                token = spec.get("token")
                if len(synthetic) >= max_hits:
                    break
                if token:
                    try:
                        matches = re.finditer(rf"\b{re.escape(token)}\s*\(", content)
                    except re.error:
                        continue
                else:
                    try:
                        all_calls = re.finditer(r"\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(", content)
                    except re.error:
                        continue
                    matches = []
                    for call_match in all_calls:
                        call_name = call_match.group(1)
                        try:
                            if re.search(spec.get("name_regex"), call_name or "") is not None:
                                matches.append(call_match)
                        except re.error:
                            matches = []
                            break
                for match in matches:
                    if len(synthetic) >= max_hits:
                        break
                    line_no = content.count("\n", 0, match.start()) + 1
                    line_start = content.rfind("\n", 0, match.start()) + 1
                    line_end = content.find("\n", match.start())
                    if line_end < 0:
                        line_end = len(content)
                    line_text = content[line_start:line_end].strip()
                    if _looks_like_comment_line(line_text):
                        continue
                    key_token = (token or spec.get("name_regex") or "").lower()
                    key = (relpath, key_token, line_no)
                    if key in synthetic_seen:
                        continue
                    if not _sink_spec_matches_text(spec, line_text):
                        continue
                    synthetic_seen.add(key)
                    synthetic.append(
                        {
                            "id": f"srcsynthetic:{relpath}:{line_no}:{key_token}",
                            "name": token or spec.get("raw"),
                            "code": line_text,
                            "lang": "Rust",
                            "method": f"{relpath}:{line_no}",
                            "scope": "synthetic_source_text",
                            "file": relpath,
                            "line": line_no,
                        }
                    )
        if scanned >= max_files or len(synthetic) >= max_hits:
            break
    return synthetic


def merge_evidence_calls(evidence_calls, extra_calls):
    base = {
        "chain_calls": list((evidence_calls or {}).get("chain_calls") or []),
        "all_calls": list((evidence_calls or {}).get("all_calls") or []),
    }
    if not extra_calls:
        return base
    by_key = {}
    for call in base["chain_calls"] + base["all_calls"] + list(extra_calls):
        key = (str(call.get("id")), str(call.get("name")), str(call.get("lang")))
        if key not in by_key:
            by_key[key] = call
    merged = list(by_key.values())
    base["all_calls"] = merged
    base["chain_calls"] = merged
    return base

def _infer_method_ids_for_nodes(session, node_ids):
    if not node_ids:
        return []
    res = session.run("""
        UNWIND $node_ids AS nid
        MATCH (n {id: nid})
        MATCH (m:METHOD)-[:AST|CFG*0..16]->(n)
        RETURN DISTINCT m.id AS mid
    """, node_ids=node_ids)
    out = []
    for row in res:
        mid = row.get("mid")
        if mid is not None:
            out.append(mid)
    return out

def collect_control_structures_for_path(session, chain_nodes):
    node_ids = sorted({n.get("id") for n in chain_nodes if n.get("id") is not None})
    method_ids = sorted(
        {n.get("id") for n in chain_nodes if "METHOD" in n.get("labels", []) and n.get("id") is not None}
    )
    if not method_ids:
        method_ids = sorted(set(_infer_method_ids_for_nodes(session, node_ids)))
    if not method_ids:
        return []

    res = session.run("""
        UNWIND $method_ids AS mid
        MATCH (m:METHOD {id: mid})
        MATCH p=(m)-[:AST*1..20]->(cs:CONTROL_STRUCTURE)
        WITH mid, cs, min(length(p)) AS min_depth
        OPTIONAL MATCH (cs)-[:AST]->(child)
        RETURN cs.id AS id,
               mid AS method_id,
               coalesce(cs.control_structure_type, cs.controlStructureType, cs.parser_type_name) AS control_type,
               cs.code AS code,
               collect(DISTINCT child.code) AS child_codes,
               min_depth AS depth
        ORDER BY depth ASC, id ASC
    """, method_ids=method_ids)

    out = []
    seen = {}
    for row in res:
        cs_id = row.get("id")
        if cs_id is None:
            continue
        child_codes = [c for c in (row.get("child_codes") or []) if isinstance(c, str) and c.strip()]
        code = row.get("code")
        if not code and not child_codes:
            continue
        item = {
            "id": cs_id,
            "method_id": row.get("method_id"),
            "control_type": row.get("control_type"),
            "code": code,
            "child_codes": child_codes,
            "depth": row.get("depth"),
        }
        prev = seen.get(cs_id)
        if prev is None or ((item.get("depth") or 10**9) < (prev.get("depth") or 10**9)):
            seen[cs_id] = item
    out.extend(seen.values())
    out.sort(key=lambda x: ((x.get("depth") if x.get("depth") is not None else 10**9), x.get("id")))
    return out

def _append_reason(existing_reason, new_reason):
    if not existing_reason:
        return new_reason
    if new_reason in existing_reason:
        return existing_reason
    return f"{existing_reason};{new_reason}"

def _dedupe_numeric_constraints(constraints):
    out = []
    seen = set()
    for c in constraints or []:
        if not isinstance(c, dict):
            continue
        key = (c.get("variable"), c.get("operator"), c.get("value"), c.get("source"), c.get("source_id"))
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def _merge_abi_constraints_into_bundle(path_bundle):
    abi_contracts = path_bundle.get("abi_contracts") or {}
    abi_constraints = []
    for cons in abi_contracts.get("constraints") or []:
        if not isinstance(cons, dict):
            continue
        op = cons.get("operator")
        var = cons.get("variable")
        if op not in {"<", "<=", ">", ">=", "==", "!="}:
            continue
        if not isinstance(var, str) or not var:
            continue
        try:
            value = int(cons.get("value"))
        except Exception:
            continue
        row = dict(cons)
        row["value"] = value
        row.setdefault("source", "abi_contract")
        abi_constraints.append(row)
    path_bundle["combined_constraints"] = _dedupe_numeric_constraints(
        list(path_bundle.get("combined_constraints") or []) + abi_constraints
    )
    path_bundle["arg_bindings"] = list(abi_contracts.get("arg_bindings") or path_bundle.get("arg_bindings") or [])
    path_bundle["boundary_assumptions"] = list(
        abi_contracts.get("boundary_assumptions") or path_bundle.get("boundary_assumptions") or []
    )
    return path_bundle

def has_existential_input_rules(trigger_model):
    if not isinstance(trigger_model, dict):
        return False
    rules = trigger_model.get("existential_inputs")
    return isinstance(rules, list) and len(rules) > 0

def _strip_numeric_expr(expr):
    text = str(expr or "").strip()
    if not text:
        return text
    prefixes = ("move ", "copy ", "const ", "&mut ", "&raw mut ", "&raw const ", "&", "*")
    changed = True
    while changed and text:
        changed = False
        for prefix in prefixes:
            if text.startswith(prefix):
                text = text[len(prefix):].strip()
                changed = True
    text = re.sub(r"\s+as\s+[A-Za-z_][A-Za-z0-9_:<>]*", "", text).strip()
    while text.startswith("(") and text.endswith(")"):
        inner = text[1:-1].strip()
        if not inner:
            break
        text = inner
    return text.strip(",;")

def _resolve_numeric_expr(expr, value_env, const_map):
    text = _strip_numeric_expr(expr)
    if not text:
        return None
    lowered = text.lower()
    if lowered in ("true", "false"):
        return 1 if lowered == "true" else 0
    try:
        return int(text, 16 if lowered.startswith("0x") or lowered.startswith("-0x") else 10)
    except Exception:
        pass
    for candidate in (text, text.split("::")[-1], text.split(".")[-1]):
        if candidate in value_env:
            try:
                return int(value_env[candidate])
            except Exception:
                pass
        if candidate in const_map:
            try:
                return int(const_map[candidate])
            except Exception:
                pass
    return None

def _collect_code_blobs(chain_nodes, evidence_calls):
    blobs = []
    for node in chain_nodes or []:
        code = node.get("code")
        if isinstance(code, str) and code.strip():
            blobs.append({"kind": "chain_node", "id": node.get("id"), "code": code})
    for call in evidence_calls or []:
        code = call.get("code")
        if isinstance(code, str) and code.strip():
            blobs.append({"kind": "call", "id": call.get("id"), "code": code, "name": call.get("name")})
    return blobs

def _extract_field_observations(chain_nodes, evidence_calls, field_names, value_env, const_map):
    observations = {name: [] for name in field_names or []}
    if not field_names:
        return observations
    patterns = {}
    for field in field_names:
        token = re.escape(field.split(".")[-1])
        patterns[field] = [
            re.compile(rf"\b{token}\b\s*:\s*([^,\n}};]+)"),
            re.compile(rf"\b{token}\b\s*=\s*([^,\n}};]+)"),
        ]

    for blob in _collect_code_blobs(chain_nodes, evidence_calls):
        code = blob.get("code") or ""
        for field, regex_list in patterns.items():
            for regex in regex_list:
                for match in regex.finditer(code):
                    expr = match.group(1).strip()
                    observations[field].append({
                        "field": field,
                        "expr": expr,
                        "value": _resolve_numeric_expr(expr, value_env, const_map),
                        "source_kind": blob.get("kind"),
                        "source_id": blob.get("id"),
                        "call_name": blob.get("name"),
                    })
    return observations

def _pick_numeric_observation(items):
    for item in items or []:
        if item.get("value") is not None:
            return item
    return None

def evaluate_existential_inputs(trigger_model, chain_nodes, evidence_calls, path_bundle, solver=None):
    rules = list((trigger_model or {}).get("existential_inputs") or [])
    result = {
        "status": "not_applicable",
        "rules": [],
        "field_observations": {},
        "constraints_used": [],
        "boundary_assumptions": [],
    }
    if not rules:
        return result

    value_env = dict(path_bundle.get("value_env") or {})
    const_map = dict(path_bundle.get("const_map") or path_bundle.get("constants") or {})
    base_constraints = list(path_bundle.get("combined_constraints") or [])

    field_names = set()
    for rule in rules:
        field = rule.get("field")
        target_field = rule.get("greater_than_field") or rule.get("less_than_field")
        if field:
            field_names.add(field)
        if target_field:
            field_names.add(target_field)

    observations = _extract_field_observations(
        chain_nodes=chain_nodes,
        evidence_calls=evidence_calls,
        field_names=sorted(field_names),
        value_env=value_env,
        const_map=const_map,
    )
    result["field_observations"] = observations

    local_solver = solver
    if local_solver is None and PathConstraintSolver is not None:
        local_solver = PathConstraintSolver(domain="octagon")

    overall_status = "sat"
    combined_used = []
    boundary_assumptions = []

    for idx, rule in enumerate(rules):
        field = rule.get("field")
        symbolic_var = rule.get("symbolic_var") or rule.get("name") or f"existential_{idx}"
        use_observed_value = bool(rule.get("use_observed_value", True))
        min_value = rule.get("min_value")
        min_operator = rule.get("min_operator", ">=")
        target_field = rule.get("greater_than_field")
        target_operator = rule.get("target_operator", ">")
        field_obs = _pick_numeric_observation(observations.get(field, [])) if field else None
        target_obs = _pick_numeric_observation(observations.get(target_field, [])) if target_field else None

        rule_constraints = list(base_constraints)
        used_assumption = False
        rule_notes = []

        if use_observed_value and field_obs and field_obs.get("value") is not None:
            rule_constraints.append({
                "variable": symbolic_var,
                "operator": "==",
                "value": int(field_obs["value"]),
                "source": "existential_observed_field",
                "source_id": field_obs.get("source_id"),
            })
            rule_notes.append(f"observed {field}={field_obs['value']}")
        else:
            used_assumption = True
            boundary_assumptions.append({
                "kind": "existential_input_assumed",
                "rule_index": idx,
                "field": field,
                "symbolic_var": symbolic_var,
                "detail": "using attacker-controlled symbolic input",
            })

        if target_field:
            if target_obs and target_obs.get("value") is not None:
                rule_constraints.append({
                    "variable": symbolic_var,
                    "operator": target_operator,
                    "value": int(target_obs["value"]),
                    "source": "existential_target_field",
                    "source_id": target_obs.get("source_id"),
                })
                rule_notes.append(f"{symbolic_var} {target_operator} {target_field}({target_obs['value']})")
            else:
                overall_status = "unknown"
                result["rules"].append({
                    "rule_index": idx,
                    "field": field,
                    "status": "unknown",
                    "reason": f"unresolved_target_field:{target_field}",
                    "used_assumption": used_assumption,
                    "notes": rule_notes,
                })
                continue

        if min_value is not None:
            try:
                coerced_min = int(min_value)
                rule_constraints.append({
                    "variable": symbolic_var,
                    "operator": min_operator,
                    "value": coerced_min,
                    "source": "existential_min_value",
                    "source_id": idx,
                })
                rule_notes.append(f"{symbolic_var} {min_operator} {coerced_min}")
            except Exception:
                pass

        combined_used.extend(rule_constraints[len(base_constraints):])

        if local_solver is None:
            rule_status = "unknown"
            reason = "solver_unavailable"
        else:
            solved = local_solver.solve_with_explain(rule_constraints)
            rule_status = "sat" if solved.get("feasible", True) else "unsat"
            reason = solved.get("bottom_reason")
            rule_notes.append(f"solver={solved.get('backend')}")

        if rule_status == "unsat":
            overall_status = "unsat"
        elif rule_status == "unknown" and overall_status != "unsat":
            overall_status = "unknown"

        result["rules"].append({
            "rule_index": idx,
            "field": field,
            "status": rule_status,
            "reason": reason,
            "used_assumption": used_assumption,
            "observed_field": field_obs,
            "target_field": target_field,
            "observed_target": target_obs,
            "constraints_used": rule_constraints[len(base_constraints):],
            "notes": rule_notes,
        })

    result["status"] = overall_status
    result["constraints_used"] = combined_used
    result["boundary_assumptions"] = boundary_assumptions
    return result


def build_path_constraint_bundle_for_symbol(chain_nodes, control_nodes, symbol, trigger_model=None, evidence_calls=None):
    if build_path_constraint_bundle is not None:
        try:
            bundle = build_path_constraint_bundle(
                chain_nodes,
                control_nodes,
                symbol,
                trigger_model=trigger_model,
                evidence_calls=evidence_calls,
            )
            if build_abi_contracts is not None:
                abi_contracts = build_abi_contracts(
                    trigger_model=trigger_model or {},
                    evidence_calls=list(evidence_calls or []),
                    path_bundle=bundle,
                )
                bundle["abi_contracts"] = abi_contracts
                bundle = _merge_abi_constraints_into_bundle(bundle)
            bundle["bundle_error"] = None
            return bundle
        except Exception as exc:
            bundle_error = str(exc)
    else:
        bundle_error = "tools.verification.constraint_extractor import failed"

    fallback_constraints = []
    if extract_numeric_constraints is not None:
        fallback_constraints = extract_numeric_constraints(control_nodes)
    fallback_bundle = build_empty_path_bundle()
    fallback_bundle["path_constraints"] = fallback_constraints
    fallback_bundle["combined_constraints"] = fallback_constraints
    fallback_bundle["control_structures_relevant"] = list(control_nodes or [])
    fallback_bundle["method_calls"] = list(evidence_calls or [])
    fallback_bundle["interproc_context"]["method_calls"] = list(evidence_calls or [])
    fallback_bundle["bundle_error"] = bundle_error
    return fallback_bundle

def _build_analysis_key(cve, symbol, call_chain_nodes):
    node_ids = [n.get("id") for n in call_chain_nodes if n.get("id") is not None]
    digest_input = ",".join(str(v) for v in node_ids)
    digest = hashlib.sha1(digest_input.encode("utf-8")).hexdigest()[:16] if digest_input else "empty"
    return f"{cve}:{symbol}:{digest}", node_ids

def write_path_analysis_overlay(
    session,
    cve,
    pkg,
    symbol,
    call_chain_nodes,
    combined_constraints,
    relevant_control_nodes,
    path_feasible,
    solver_backend,
    solver_error,
):
    analysis_key, path_node_ids = _build_analysis_key(cve, symbol, call_chain_nodes)
    constraint_rows = []
    for idx, cons in enumerate(combined_constraints or []):
        constraint_rows.append(
            {
                "idx": idx,
                "variable": cons.get("variable"),
                "operator": cons.get("operator"),
                "value": cons.get("value"),
                "source": cons.get("source"),
                "source_id": cons.get("source_id"),
                "branch_polarity": cons.get("branch_polarity"),
            }
        )
    control_ids = [n.get("id") for n in (relevant_control_nodes or []) if n.get("id") is not None]

    session.run(
        """
        MERGE (pa:PATH_ANALYSIS {analysis_key: $analysis_key})
        SET pa.cve = $cve,
            pa.package = $pkg,
            pa.symbol = $symbol,
            pa.path_feasible = $path_feasible,
            pa.solver_backend = $solver_backend,
            pa.solver_error = $solver_error,
            pa.constraint_count = $constraint_count,
            pa.path_node_ids = $path_node_ids,
            pa.updated_at = datetime()
        """,
        analysis_key=analysis_key,
        cve=cve,
        pkg=pkg,
        symbol=symbol,
        path_feasible=bool(path_feasible),
        solver_backend=solver_backend,
        solver_error=solver_error,
        constraint_count=len(constraint_rows),
        path_node_ids=path_node_ids,
    )
    session.run(
        """
        MATCH (pa:PATH_ANALYSIS {analysis_key: $analysis_key})-[r:HAS_CONSTRAINT]->(pc:PATH_CONSTRAINT)
        DETACH DELETE pc
        """,
        analysis_key=analysis_key,
    )
    session.run(
        """
        MATCH (pa:PATH_ANALYSIS {analysis_key: $analysis_key})-[r:ANALYZES_PATH_NODE]->()
        DELETE r
        """,
        analysis_key=analysis_key,
    )
    session.run(
        """
        MATCH (pa:PATH_ANALYSIS {analysis_key: $analysis_key})-[r:USES_CONTROL_STRUCTURE]->()
        DELETE r
        """,
        analysis_key=analysis_key,
    )
    if constraint_rows:
        session.run(
            """
            MATCH (pa:PATH_ANALYSIS {analysis_key: $analysis_key})
            UNWIND $constraints AS c
            MERGE (pc:PATH_CONSTRAINT {analysis_key: $analysis_key, idx: c.idx})
            SET pc.variable = c.variable,
                pc.operator = c.operator,
                pc.value = c.value,
                pc.source = c.source,
                pc.source_id = c.source_id,
                pc.branch_polarity = c.branch_polarity
            MERGE (pa)-[:HAS_CONSTRAINT]->(pc)
            """,
            analysis_key=analysis_key,
            constraints=constraint_rows,
        )
    if path_node_ids:
        session.run(
            """
            MATCH (pa:PATH_ANALYSIS {analysis_key: $analysis_key})
            UNWIND $node_ids AS nid
            MATCH (n {id: nid})
            MERGE (pa)-[:ANALYZES_PATH_NODE]->(n)
            """,
            analysis_key=analysis_key,
            node_ids=path_node_ids,
        )
    if control_ids:
        session.run(
            """
            MATCH (pa:PATH_ANALYSIS {analysis_key: $analysis_key})
            UNWIND $control_ids AS cid
            MATCH (cs:CONTROL_STRUCTURE {id: cid})
            MERGE (pa)-[:USES_CONTROL_STRUCTURE]->(cs)
            """,
            analysis_key=analysis_key,
            control_ids=control_ids,
        )

def _as_list(val):
    return _ensure_list(val)

def _call_name_equivalent(actual_name, expected_name):
    actual = str(actual_name or "").strip()
    expected = str(expected_name or "").strip()
    if not actual or not expected:
        return False

    actual_l = actual.lower()
    expected_l = expected.lower()
    if actual_l == expected_l:
        return True
    if actual_l.endswith("::" + expected_l):
        return True
    if expected_l.endswith("::" + actual_l):
        return True

    actual_short = _coerce_call_name(actual).lower()
    expected_short = _coerce_call_name(expected).lower()
    if actual_short and actual_short == expected_short:
        return True
    return False

def _match_call_name(call_name, names, name_regex):
    if names:
        return any(_call_name_equivalent(call_name, expected) for expected in names)
    if name_regex:
        try:
            return re.search(name_regex, call_name or "") is not None
        except re.error:
            return False
    return False

def _match_code_contains(code, contains_list, contains_all=True):
    if not contains_list:
        return True
    if not code:
        return False
    if contains_all:
        return all(c in code for c in contains_list)
    return any(c in code for c in contains_list)


def _collect_method_code_map(chain_nodes):
    method_code = {}
    for node in chain_nodes or []:
        labels = node.get("labels") or []
        if "METHOD" not in labels:
            continue
        name = node.get("name")
        code = node.get("code")
        if not isinstance(name, str) or not name:
            continue
        if not isinstance(code, str) or not code.strip():
            continue
        method_code[name] = code
    return method_code


def _extract_identifiers_from_expr(expr):
    return re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expr or "")


def _extract_field_accesses_from_expr(expr):
    return re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\b", expr or "")


def _extract_receiver_var(code):
    text = str(code or "").strip()
    match = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*[A-Za-z_][A-Za-z0-9_:]*\s*\(", text)
    if match:
        return match.group(1)
    return None


def _safe_int(value):
    try:
        return int(value)
    except Exception:
        return None


def _extract_assignment_map(method_code):
    assignments = {}
    if not isinstance(method_code, str) or not method_code.strip():
        return assignments
    for raw_stmt in method_code.split(";"):
        stmt = raw_stmt.strip()
        if not stmt:
            continue
        if "==" in stmt or "!=" in stmt or "<=" in stmt or ">=" in stmt:
            continue
        match = re.match(r"^(?:let\s+(?:mut\s+)?)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$", stmt)
        if not match:
            continue
        lhs = match.group(1).strip()
        rhs = match.group(2).strip()
        if not lhs or not rhs:
            continue
        assignments.setdefault(lhs, [])
        if rhs not in assignments[lhs]:
            assignments[lhs].append(rhs)
    return assignments


def _expr_reaches_field(expr, field_name, assignment_map, max_depth=6):
    if not field_name:
        return False
    queue = [str(expr or "")]
    seen_expr = set(queue)
    depth = 0
    while queue and depth <= max_depth:
        current = queue.pop(0)
        for _, fld in _extract_field_accesses_from_expr(current):
            if fld == field_name:
                return True
        idents = _extract_identifiers_from_expr(current)
        for ident in idents:
            for rhs in assignment_map.get(ident, []):
                if rhs in seen_expr:
                    continue
                seen_expr.add(rhs)
                queue.append(rhs)
        depth += 1
    return False


def _expr_reaches_identifier(expr, target_ident, assignment_map, max_depth=6):
    if not target_ident:
        return False
    queue = [str(expr or "")]
    seen_expr = set(queue)
    depth = 0
    while queue and depth <= max_depth:
        current = queue.pop(0)
        if target_ident in _extract_identifiers_from_expr(current):
            return True
        idents = _extract_identifiers_from_expr(current)
        for ident in idents:
            for rhs in assignment_map.get(ident, []):
                if rhs in seen_expr:
                    continue
                seen_expr.add(rhs)
                queue.append(rhs)
        depth += 1
    return False


def _calls_match_spec(calls, spec):
    spec = dict(spec or {})
    names = _as_list(spec.get("name") or spec.get("names"))
    name_regex = spec.get("name_regex", "")
    lang = spec.get("lang")
    contains = _as_list(spec.get("contains") or spec.get("code_contains"))
    contains_all = spec.get("contains_all", True)
    matched = []
    for call in calls or []:
        if lang and call.get("lang") != lang:
            continue
        if names or name_regex:
            if not _match_call_name(call.get("name"), names, name_regex):
                continue
        if contains and not _match_code_contains(call.get("code"), contains, contains_all):
            continue
        matched.append(call)
    return matched


def _extract_assigned_vars_for_call(method_code, call_spec):
    out = set()
    if not isinstance(method_code, str) or not method_code.strip():
        return out
    names = _as_list(call_spec.get("name") or call_spec.get("names"))
    name_regex = call_spec.get("name_regex", "")
    call_matchers = []
    for name in names:
        if name:
            call_matchers.append(re.compile(rf"\b{re.escape(name)}\s*\("))
    if name_regex:
        try:
            call_matchers.append(re.compile(name_regex))
        except re.error:
            pass
    if not call_matchers:
        return out
    for raw_stmt in method_code.split(";"):
        stmt = raw_stmt.strip()
        if not stmt:
            continue
        match = re.match(r"^(?:let\s+(?:mut\s+)?)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$", stmt)
        if not match:
            continue
        lhs = match.group(1).strip()
        rhs = match.group(2).strip()
        if any(m.search(rhs) for m in call_matchers):
            out.add(lhs)
    return out


def _eval_control_contains(cond, control_nodes):
    contains = _as_list(cond.get("contains") or cond.get("code_contains"))
    contains_all = cond.get("contains_all", True)
    matched = []
    for node in control_nodes or []:
        texts = []
        code = node.get("code")
        if isinstance(code, str) and code.strip():
            texts.append(code)
        for child in node.get("child_codes") or []:
            if isinstance(child, str) and child.strip():
                texts.append(child)
        hit = False
        for text in texts:
            if _match_code_contains(text, contains, contains_all):
                hit = True
                break
        if hit:
            matched.append(node)
    return {"ok": len(matched) > 0, "evidence": matched}


def _eval_field_to_call_arg(cond, calls):
    sink_spec = dict(cond.get("sink") or {})
    if not sink_spec:
        sink_spec = {
            "name": cond.get("name"),
            "names": cond.get("names"),
            "name_regex": cond.get("name_regex"),
            "lang": cond.get("lang"),
        }
    arg_index = int(cond.get("arg_index") or sink_spec.get("arg_index") or 1)
    field_name = cond.get("source_field") or cond.get("field")
    max_depth = int(cond.get("max_depth") or 6)
    method_code_map = _collect_method_code_map(cond.get("chain_nodes") or [])
    matched = []
    for call in _calls_match_spec(calls, sink_spec):
        args = _extract_args_from_call(call.get("code") or "")
        if arg_index <= 0 or arg_index > len(args):
            continue
        arg_expr = args[arg_index - 1].strip()
        method_name = call.get("method")
        assignment_map = _extract_assignment_map(method_code_map.get(method_name))
        if _expr_reaches_field(arg_expr, field_name, assignment_map, max_depth=max_depth):
            matched.append(
                {
                    "call_id": call.get("id"),
                    "call_name": call.get("name"),
                    "method": method_name,
                    "arg_expr": arg_expr,
                    "source_field": field_name,
                }
            )
    return {"ok": len(matched) > 0, "evidence": matched}


def _eval_io_to_call_arg(cond, calls):
    sink_spec = dict(cond.get("sink") or {})
    open_spec = dict(cond.get("open_call") or {"name_regex": "(^|::)open$"})
    read_spec = dict(cond.get("read_call") or {"name_regex": "(^|::)read_to_end$|(^|::)read$"})
    sink_arg_index = int(cond.get("sink_arg_index") or sink_spec.get("arg_index") or 1)
    read_buf_arg_index = int(cond.get("read_buf_arg_index") or 1)
    same_method = cond.get("same_method", True)
    max_depth = int(cond.get("max_depth") or 6)
    method_code_map = _collect_method_code_map(cond.get("chain_nodes") or [])
    sink_calls = _calls_match_spec(calls, sink_spec)
    open_calls = _calls_match_spec(calls, open_spec)
    read_calls = _calls_match_spec(calls, read_spec)
    matched = []
    for sink_call in sink_calls:
        sink_args = _extract_args_from_call(sink_call.get("code") or "")
        if sink_arg_index <= 0 or sink_arg_index > len(sink_args):
            continue
        sink_arg_expr = sink_args[sink_arg_index - 1].strip()
        sink_method = sink_call.get("method")
        method_open_calls = [c for c in open_calls if (not same_method) or c.get("method") == sink_method]
        method_read_calls = [c for c in read_calls if (not same_method) or c.get("method") == sink_method]
        method_code = method_code_map.get(sink_method)
        assignment_map = _extract_assignment_map(method_code)
        open_assigned_vars = _extract_assigned_vars_for_call(method_code, open_spec)
        for read_call in method_read_calls:
            read_id = _safe_int(read_call.get("id"))
            sink_id = _safe_int(sink_call.get("id"))
            if read_id is not None and sink_id is not None and read_id > sink_id:
                continue
            read_args = _extract_args_from_call(read_call.get("code") or "")
            if read_buf_arg_index <= 0 or read_buf_arg_index > len(read_args):
                continue
            read_buf_expr = read_args[read_buf_arg_index - 1].strip()
            read_buf_ident = None
            read_buf_tokens = _extract_identifiers_from_expr(read_buf_expr)
            if read_buf_tokens:
                read_buf_ident = read_buf_tokens[-1]
            if not read_buf_ident:
                continue
            if not _expr_reaches_identifier(sink_arg_expr, read_buf_ident, assignment_map, max_depth=max_depth):
                continue
            receiver = _extract_receiver_var(read_call.get("code"))
            open_before_read = False
            for open_call in method_open_calls:
                open_id = _safe_int(open_call.get("id"))
                if open_id is not None and read_id is not None and open_id > read_id:
                    continue
                if receiver and open_assigned_vars:
                    if receiver in open_assigned_vars:
                        open_before_read = True
                        break
                else:
                    open_before_read = True
                    break
            if not open_before_read:
                continue
            matched.append(
                {
                    "sink_call_id": sink_call.get("id"),
                    "sink_call_name": sink_call.get("name"),
                    "sink_arg_expr": sink_arg_expr,
                    "read_call_id": read_call.get("id"),
                    "read_call_name": read_call.get("name"),
                    "read_buf_expr": read_buf_expr,
                    "read_receiver": receiver,
                }
            )
            break
    return {"ok": len(matched) > 0, "evidence": matched}


def _eval_call_order(cond, calls):
    first_spec = dict(cond.get("first") or {})
    second_spec = dict(cond.get("second") or {})
    same_method = cond.get("same_method", True)
    require_same_receiver = bool(cond.get("require_same_receiver", False))
    method_code_map = _collect_method_code_map(cond.get("chain_nodes") or [])
    first_calls = _calls_match_spec(calls, first_spec)
    second_calls = _calls_match_spec(calls, second_spec)
    matched = []
    for first_call in first_calls:
        for second_call in second_calls:
            if same_method and first_call.get("method") != second_call.get("method"):
                continue
            first_id = _safe_int(first_call.get("id"))
            second_id = _safe_int(second_call.get("id"))
            if first_id is None or second_id is None:
                continue
            if second_id <= first_id:
                continue
            if require_same_receiver:
                receiver = _extract_receiver_var(second_call.get("code"))
                if not receiver:
                    continue
                method_code = method_code_map.get(first_call.get("method"))
                assigned_vars = _extract_assigned_vars_for_call(method_code, first_spec)
                if receiver not in assigned_vars:
                    continue
            matched.append(
                {
                    "first_call_id": first_call.get("id"),
                    "first_call_name": first_call.get("name"),
                    "second_call_id": second_call.get("id"),
                    "second_call_name": second_call.get("name"),
                    "method": second_call.get("method"),
                }
            )
            break
    return {"ok": len(matched) > 0, "evidence": matched}


def _call_matches_spec(call, spec):
    return bool(_calls_match_spec([call], spec))


def _eval_api_sequence(cond, calls):
    steps = list(cond.get("steps") or [])
    if not steps:
        return {"ok": False, "evidence": []}
    same_method = cond.get("same_method", True)

    method_to_calls = {}
    for c in calls or []:
        method_to_calls.setdefault(c.get("method"), []).append(c)

    evidences = []
    for method_name, method_calls in method_to_calls.items():
        ordered = sorted(method_calls, key=lambda x: (_safe_int(x.get("id")) if _safe_int(x.get("id")) is not None else 10**12))
        if not ordered:
            continue
        pos = 0
        step_evidence = []
        for step in steps:
            spec = step if isinstance(step, dict) else {"name": step}
            found = None
            for idx in range(pos, len(ordered)):
                call = ordered[idx]
                if same_method and call.get("method") != method_name:
                    continue
                if _call_matches_spec(call, spec):
                    found = (idx, call)
                    break
            if found is None:
                step_evidence = []
                break
            pos = found[0] + 1
            step_evidence.append(
                {
                    "step": spec.get("name") or spec.get("name_regex") or spec,
                    "call_id": found[1].get("id"),
                    "call_name": found[1].get("name"),
                    "method": found[1].get("method"),
                }
            )
        if step_evidence:
            evidences.append({"method": method_name, "steps": step_evidence})
    return {"ok": len(evidences) > 0, "evidence": evidences}


def _is_c_only_order_condition(cond):
    if not isinstance(cond, dict):
        return False
    ctype = str(cond.get("type") or "").strip()
    if ctype in {"api_sequence", "setup_sequence"}:
        steps = list(cond.get("steps") or [])
        if not steps:
            return False
        saw_explicit_lang = False
        for step in steps:
            if not isinstance(step, dict):
                return False
            lang = str(step.get("lang") or "").strip()
            if not lang:
                return False
            saw_explicit_lang = True
            if lang != "C":
                return False
        return saw_explicit_lang
    if ctype == "call_order":
        specs = [cond.get("first"), cond.get("second")]
        saw_explicit_lang = False
        for spec in specs:
            if not isinstance(spec, dict):
                return False
            lang = str(spec.get("lang") or "").strip()
            if not lang:
                return False
            saw_explicit_lang = True
            if lang != "C":
                return False
        return saw_explicit_lang
    return False


def adapt_trigger_model_for_source_availability(trigger_model, *, has_c_method):
    model = copy.deepcopy(trigger_model or {})
    conditions = list(model.get("conditions") or [])
    if has_c_method or not conditions:
        return model, []

    filtered_conditions = []
    skipped_conditions = []
    for cond in conditions:
        if _is_c_only_order_condition(cond):
            skipped_conditions.append(
                {
                    "id": cond.get("id") or cond.get("name") or cond.get("type") or "trigger_condition",
                    "type": cond.get("type", "condition"),
                    "reason": "missing_c_body_for_order_guard",
                }
            )
            continue
        filtered_conditions.append(cond)

    model["conditions"] = filtered_conditions
    return model, skipped_conditions


def _extract_option_bindings(method_code):
    bindings = []
    if not isinstance(method_code, str) or not method_code.strip():
        return bindings
    for stmt in method_code.split(";"):
        line = stmt.strip()
        if not line:
            continue
        m = re.match(
            r"^(?:let\s+(?:mut\s+)?)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(as_deref|as_ref|unwrap|expect)\s*\(",
            line,
        )
        if m:
            bindings.append({"derived": m.group(1), "source": m.group(2), "via": m.group(3)})
            continue
        m2 = re.search(r"if\s+let\s+Some\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)", line)
        if m2:
            bindings.append({"derived": m2.group(1), "source": m2.group(2), "via": "if_let_some"})
    return bindings


def _eval_option_to_call_arg(cond, calls):
    sink_spec = dict(cond.get("sink") or {})
    if not sink_spec:
        sink_spec = {"name": cond.get("name"), "name_regex": cond.get("name_regex"), "lang": cond.get("lang")}
    arg_index = int(cond.get("arg_index") or sink_spec.get("arg_index") or 1)
    option_var = cond.get("option_var")
    method_code_map = _collect_method_code_map(cond.get("chain_nodes") or [])

    matched = []
    for call in _calls_match_spec(calls, sink_spec):
        args = _extract_args_from_call(call.get("code") or "")
        if arg_index <= 0 or arg_index > len(args):
            continue
        arg_expr = args[arg_index - 1].strip()
        method_name = call.get("method")
        method_code = method_code_map.get(method_name)
        assignment_map = _extract_assignment_map(method_code)
        option_bindings = _extract_option_bindings(method_code)
        hits = []

        lowered_arg = arg_expr.lower()
        if any(tok in lowered_arg for tok in (".as_deref(", ".as_ref(", ".unwrap(", ".expect(")):
            hits.append({"kind": "direct_option_transform", "arg_expr": arg_expr})

        for rel in option_bindings:
            derived = rel.get("derived")
            source = rel.get("source")
            if option_var and option_var != source:
                continue
            if _expr_reaches_identifier(arg_expr, derived, assignment_map, max_depth=6):
                hits.append({"kind": "derived_option_value", "derived": derived, "source_option": source, "via": rel.get("via")})

        if hits:
            matched.append(
                {
                    "call_id": call.get("id"),
                    "call_name": call.get("name"),
                    "method": method_name,
                    "arg_expr": arg_expr,
                    "hits": hits,
                }
            )
    if matched:
        return {"ok": True, "evidence": matched}

    if cond.get("allow_assume_if_no_direct"):
        assumed = []
        sink_calls = _calls_match_spec(calls, sink_spec)
        assumption_reason = cond.get("assumption_reason") or "option_flow_assumed_without_local_evidence"
        for call in sink_calls:
            assumed.append(
                {
                    "call_id": call.get("id"),
                    "call_name": call.get("name"),
                    "method": call.get("method"),
                    "assumed": True,
                    "reason": assumption_reason,
                }
            )
        if assumed:
            return {"ok": True, "evidence": assumed}

    return {"ok": False, "evidence": []}


def _expr_has_len_access(expr):
    text = str(expr or "")
    pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(len|capacity)\s*\(\s*\)")
    return [{"source": m.group(1), "op": m.group(2)} for m in pattern.finditer(text)]


def _eval_len_to_call_arg(cond, calls):
    sink_spec = dict(cond.get("sink") or {})
    if not sink_spec:
        sink_spec = {"name": cond.get("name"), "name_regex": cond.get("name_regex"), "lang": cond.get("lang")}
    arg_index = int(cond.get("arg_index") or sink_spec.get("arg_index") or 1)
    source_var = cond.get("source_var")
    max_depth = int(cond.get("max_depth") or 6)
    method_code_map = _collect_method_code_map(cond.get("chain_nodes") or [])
    matched = []
    for call in _calls_match_spec(calls, sink_spec):
        args = _extract_args_from_call(call.get("code") or "")
        if arg_index <= 0 or arg_index > len(args):
            continue
        arg_expr = args[arg_index - 1].strip()
        method_name = call.get("method")
        assignment_map = _extract_assignment_map(method_code_map.get(method_name))
        direct_hits = _expr_has_len_access(arg_expr)
        if source_var:
            direct_hits = [h for h in direct_hits if h.get("source") == source_var]
        if not direct_hits and source_var:
            probe_expr = f"{source_var}.len()"
            if _expr_reaches_identifier(arg_expr, source_var, assignment_map, max_depth=max_depth):
                direct_hits.append({"source": source_var, "op": "len", "derived": True, "probe": probe_expr})
        if direct_hits:
            matched.append(
                {
                    "call_id": call.get("id"),
                    "call_name": call.get("name"),
                    "method": method_name,
                    "arg_expr": arg_expr,
                    "hits": direct_hits,
                }
            )
    return {"ok": len(matched) > 0, "evidence": matched}


def _normalize_setter_specs(setters):
    out = []
    for item in setters or []:
        if isinstance(item, str):
            out.append({"name": item})
        elif isinstance(item, dict):
            out.append(dict(item))
    return out


def _eval_builder_flag_chain(cond, calls):
    sink_spec = dict(cond.get("sink") or {})
    if not sink_spec:
        sink_spec = {"name": cond.get("name"), "name_regex": cond.get("name_regex"), "lang": cond.get("lang")}
    setters = _normalize_setter_specs(cond.get("setters") or cond.get("flags"))
    required_contains = _ensure_list(cond.get("required_contains"))
    same_method = cond.get("same_method", True)
    require_same_receiver = bool(cond.get("require_same_receiver", True))

    sink_calls = _calls_match_spec(calls, sink_spec)
    matched = []
    for sink_call in sink_calls:
        sink_method = sink_call.get("method")
        sink_id = _safe_int(sink_call.get("id"))
        sink_code = sink_call.get("code") or ""
        if required_contains and all(tok in sink_code for tok in required_contains):
            matched.append(
                {
                    "sink_call_id": sink_call.get("id"),
                    "sink_call_name": sink_call.get("name"),
                    "method": sink_method,
                    "mode": "sink_contains",
                    "required_contains": required_contains,
                }
            )
            continue

        receiver = _extract_receiver_var(sink_code)
        prior_calls = []
        for c in calls or []:
            if same_method and c.get("method") != sink_method:
                continue
            cid = _safe_int(c.get("id"))
            if sink_id is not None and cid is not None and cid >= sink_id:
                continue
            prior_calls.append(c)

        setter_hits = []
        for spec in setters:
            hit = None
            for c in prior_calls:
                if not _call_matches_spec(c, spec):
                    continue
                if require_same_receiver and receiver:
                    rcv = _extract_receiver_var(c.get("code"))
                    if rcv and rcv != receiver:
                        continue
                hit = c
                break
            if hit is None:
                setter_hits = []
                break
            setter_hits.append({"setter_name": hit.get("name"), "call_id": hit.get("id"), "method": hit.get("method")})
        if setter_hits:
            matched.append(
                {
                    "sink_call_id": sink_call.get("id"),
                    "sink_call_name": sink_call.get("name"),
                    "method": sink_method,
                    "receiver": receiver,
                    "setter_hits": setter_hits,
                }
            )
    return {"ok": len(matched) > 0, "evidence": matched}


INPUT_CLASS_TOKEN_MAP = {
    "crafted_webp_lossless": {
        "positive": ["webp", "image/webp", "imagetype::webp", "mime::webp"],
        "negative": ["jpeg", "png", "image/jpeg", "image/png"],
    },
    "gzip_with_crafted_extra_field": {
        "positive": ["gzip", "inflategetheader", "inflateinit2", "fextra", "extra_len", "extra_max"],
        "negative": ["deflate", "zlib header only", "raw deflate only"],
    },
    "crafted_revspec": {
        "positive": ["revparse", "revspec"],
        "negative": [],
    },
    "crafted_regex_pattern": {
        "positive": ["regex", "pattern", "jit"],
        "negative": [],
    },
    "extremely_large_string": {
        "positive": ["len()", "capacity()", "bind_text", "bind_blob", "text64", "blob64"],
        "negative": [],
    },
    "tar_longlink": {
        "positive": ["tar", "longlink", "archive"],
        "negative": [],
    },
}


def evaluate_input_predicate(vuln_rule, chain_nodes, control_nodes, calls):
    predicate = dict((vuln_rule or {}).get("input_predicate") or {})
    input_class = str(predicate.get("class") or "").strip()
    if not input_class:
        return {
            "status": "not_applicable",
            "class": None,
            "strategy": predicate.get("strategy"),
            "positive_hits": [],
            "negative_hits": [],
        }

    token_meta = dict(INPUT_CLASS_TOKEN_MAP.get(input_class, {}))
    positive_tokens = _ensure_list(predicate.get("positive_tokens") or token_meta.get("positive"))
    negative_tokens = _ensure_list(predicate.get("negative_tokens") or token_meta.get("negative"))

    texts = _extract_text_corpus(chain_nodes=chain_nodes, control_nodes=control_nodes, calls=calls)
    haystack = "\n".join(str(t) for t in texts).lower()

    positive_hits = [tok for tok in positive_tokens if str(tok).lower() in haystack]
    negative_hits = [tok for tok in negative_tokens if str(tok).lower() in haystack]

    if positive_hits:
        status = "satisfied"
    elif negative_hits:
        status = "failed"
    else:
        status = "unknown"

    return {
        "status": status,
        "class": input_class,
        "strategy": predicate.get("strategy"),
        "positive_hits": positive_hits,
        "negative_hits": negative_hits,
        "positive_tokens": positive_tokens,
        "negative_tokens": negative_tokens,
    }


def _eval_input_class_condition(cond, chain_nodes, control_nodes, calls):
    fake_rule = {
        "input_predicate": {
            "class": cond.get("class"),
            "positive_tokens": cond.get("positive_tokens"),
            "negative_tokens": cond.get("negative_tokens"),
            "strategy": cond.get("strategy"),
        }
    }
    result = evaluate_input_predicate(fake_rule, chain_nodes, control_nodes, calls)
    return {"ok": result.get("status") == "satisfied", "evidence": [result]}


def eval_condition(cond, calls_all, calls_chain, chain_nodes=None, control_nodes=None):
    ctype = cond.get("type", "call")
    if ctype in ["any_of", "all_of"]:
        sub = cond.get("conditions", [])
        results = [eval_condition(s, calls_all, calls_chain, chain_nodes=chain_nodes, control_nodes=control_nodes) for s in sub]
        if ctype == "any_of":
            ok = any(r["ok"] for r in results)
            evidence = []
            for r in results:
                if r["ok"]:
                    evidence.extend(r["evidence"])
            return {"ok": ok, "evidence": evidence}
        ok = all(r["ok"] for r in results)
        evidence = []
        for r in results:
            if r["ok"]:
                evidence.extend(r["evidence"])
        return {"ok": ok, "evidence": evidence}
    if ctype == "not":
        sub = cond.get("condition") or {}
        res = eval_condition(sub, calls_all, calls_chain, chain_nodes=chain_nodes, control_nodes=control_nodes)
        return {"ok": not res["ok"], "evidence": res["evidence"]}
    if ctype in ["control_code_contains", "branch_code_contains"]:
        return _eval_control_contains(cond, control_nodes or [])
    if ctype == "field_to_call_arg":
        local_cond = dict(cond)
        local_cond["chain_nodes"] = chain_nodes or []
        scope = cond.get("scope", "any")
        target_calls = calls_chain if scope == "chain" else calls_all
        return _eval_field_to_call_arg(local_cond, target_calls)
    if ctype == "io_to_call_arg":
        local_cond = dict(cond)
        local_cond["chain_nodes"] = chain_nodes or []
        scope = cond.get("scope", "any")
        target_calls = calls_chain if scope == "chain" else calls_all
        return _eval_io_to_call_arg(local_cond, target_calls)
    if ctype == "call_order":
        local_cond = dict(cond)
        local_cond["chain_nodes"] = chain_nodes or []
        scope = cond.get("scope", "any")
        target_calls = calls_chain if scope == "chain" else calls_all
        return _eval_call_order(local_cond, target_calls)
    if ctype in {"api_sequence", "setup_sequence"}:
        scope = cond.get("scope", "any")
        target_calls = calls_chain if scope == "chain" else calls_all
        return _eval_api_sequence(cond, target_calls)
    if ctype == "option_to_call_arg":
        local_cond = dict(cond)
        local_cond["chain_nodes"] = chain_nodes or []
        scope = cond.get("scope", "any")
        target_calls = calls_chain if scope == "chain" else calls_all
        return _eval_option_to_call_arg(local_cond, target_calls)
    if ctype == "len_to_call_arg":
        local_cond = dict(cond)
        local_cond["chain_nodes"] = chain_nodes or []
        scope = cond.get("scope", "any")
        target_calls = calls_chain if scope == "chain" else calls_all
        return _eval_len_to_call_arg(local_cond, target_calls)
    if ctype == "builder_flag_chain":
        scope = cond.get("scope", "any")
        target_calls = calls_chain if scope == "chain" else calls_all
        return _eval_builder_flag_chain(cond, target_calls)
    if ctype == "input_class":
        scope = cond.get("scope", "any")
        target_calls = calls_chain if scope == "chain" else calls_all
        return _eval_input_class_condition(cond, chain_nodes or [], control_nodes or [], target_calls)

    scope = cond.get("scope", "any")
    calls = calls_chain if scope == "chain" else calls_all

    names = _as_list(cond.get("name") or cond.get("names"))
    name_regex = cond.get("name_regex", "")
    lang = cond.get("lang")
    contains = _as_list(cond.get("contains") or cond.get("code_contains"))
    contains_all = cond.get("contains_all", True)

    matched = []
    for c in calls:
        if lang and c.get("lang") != lang:
            continue
        if names or name_regex:
            if not _match_call_name(c.get("name"), names, name_regex):
                continue
        if ctype in ["call", "call_code_contains"]:
            if ctype == "call_code_contains" and not _match_code_contains(c.get("code"), contains, contains_all):
                continue
            matched.append(c)
            continue
        if ctype == "code_contains":
            if _match_code_contains(c.get("code"), contains, contains_all):
                matched.append(c)
        else:
            matched.append(c)

    return {"ok": len(matched) > 0, "evidence": matched}

def extract_pattern_context(chain_nodes, call_evidence):
    names = []
    code_terms = []
    for n in chain_nodes:
        if n.get("name"):
            names.append(n.get("name"))
        if n.get("code"):
            code_terms.extend(re.findall(r"\b[A-Za-z_][A-Za-z0-9_:]*\b", n.get("code")))
    for c in call_evidence:
        if c.get("name"):
            names.append(c.get("name"))
        if c.get("method"):
            names.append(c.get("method"))
        if c.get("code"):
            code_terms.extend(re.findall(r"\b[A-Za-z_][A-Za-z0-9_:]*\b", c.get("code")))
    return list(set(names + code_terms))

def _split_args(arg_str):
    args = []
    current = []
    depth = 0
    for ch in arg_str:
        if ch == "(" or ch == "[" or ch == "{":
            depth += 1
        elif ch == ")" or ch == "]" or ch == "}":
            if depth > 0:
                depth -= 1
        if ch == "," and depth == 0:
            token = "".join(current).strip()
            if token:
                args.append(token)
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        args.append(tail)
    return args

def _extract_args_from_call(code):
    if not code:
        return []
    l = code.find("(")
    r = code.rfind(")")
    if l == -1 or r == -1 or r <= l:
        return []
    return _split_args(code[l + 1:r])

def _guess_role(arg):
    a = arg.strip()
    lower = a.lower()
    if "XML_" in a or "FLAG" in a or "OPTION" in a:
        return "flags"
    if any(k in lower for k in ["len", "length", "size", "strlen", "sizeof"]):
        return "len"
    if any(k in lower for k in ["buf", "buffer", "data", "xml", "ptr"]):
        return "buf"
    if any(k in lower for k in ["flag", "flags", "option", "options"]):
        return "flags"
    if re.search(r"\b(cb|callback|handler|hook)\b", lower) or re.search(r"\bon_\w+\b", lower):
        return "callback"
    return None

def _extract_flags(arg):
    if not arg:
        return []
    return re.findall(r"\b[A-Z0-9_]{3,}\b", arg)

def build_ffi_semantics(calls):
    semantics = []
    for c in calls:
        code = c.get("code")
        name = c.get("name")
        if not code:
            continue
        lang = c.get("lang")
        args = _extract_args_from_call(code)
        if not args:
            continue
        param_roles = {}
        flags_evidence = []
        for idx, arg in enumerate(args, start=1):
            role = _guess_role(arg)
            if role:
                param_roles[f"arg{idx}"] = role
            flags_evidence.extend(_extract_flags(arg))

        notes = []
        if "buf" in param_roles.values() and "len" in param_roles.values():
            notes.append("buf/len pattern matched")
        if flags_evidence:
            notes.append("flags tokens detected")

        semantics.append({
            "id": c.get("id"),
            "name": name,
            "lang": lang,
            "code": code,
            "param_roles": param_roles,
            "flags_evidence": sorted(set(flags_evidence)),
            "notes": notes
        })
    return semantics

def build_constraint_result(trigger_model, trigger_hits, ffi_semantics, sanitizer_hits, param_semantics_result=None):
    constraints = []
    status = "unknown"

    total_required = len(trigger_model.get("conditions", [])) if trigger_model else 0
    required_hits = len(trigger_hits.get("required_hits", [])) if trigger_hits else 0
    mitigations_hit = len(trigger_hits.get("mitigations_hit", [])) if trigger_hits else 0

    if total_required > 0:
        constraints.append(f"trigger_conditions_matched={required_hits}/{total_required}")

    has_buf_len = False
    flags_observed = False
    for s in ffi_semantics or []:
        roles = s.get("param_roles", {})
        if "buf" in roles.values() and "len" in roles.values():
            has_buf_len = True
        if s.get("flags_evidence"):
            flags_observed = True

    if has_buf_len:
        constraints.append("buf_len_pattern_present")
    if flags_observed:
        constraints.append("flags_observed")
    if sanitizer_hits:
        constraints.append("sanitizer_present")
    if mitigations_hit > 0:
        constraints.append("mitigation_hit")

    if total_required > 0 and required_hits == total_required and mitigations_hit == 0:
        status = "satisfiable"
    elif mitigations_hit > 0:
        status = "unsatisfiable"
    else:
        status = "unknown"

    result = {
        "status": status,
        "solver": "lightweight",
        "constraints": constraints
    }
    if param_semantics_result is not None:
        result["param_semantics"] = param_semantics_result
    return result


def has_param_semantics_rules(trigger_model):
    if not isinstance(trigger_model, dict):
        return False
    rules = trigger_model.get("param_semantics")
    if not isinstance(rules, dict):
        return False
    for key in ("flags", "len", "nonnull", "enum_range", "callback"):
        items = rules.get(key)
        if isinstance(items, list) and items:
            return True
    return False


def _condition_contains_type(cond, target_types):
    if not isinstance(cond, dict):
        return False
    ctype = str(cond.get("type") or "").strip()
    if ctype in target_types:
        return True
    if ctype in {"any_of", "all_of"}:
        for sub in cond.get("conditions") or []:
            if _condition_contains_type(sub, target_types):
                return True
        return False
    if ctype == "not":
        return _condition_contains_type(cond.get("condition") or {}, target_types)
    return False


def has_control_structure_rules(trigger_model):
    if not isinstance(trigger_model, dict):
        return False
    target_types = {"control_code_contains", "branch_code_contains"}
    for cond in (trigger_model.get("conditions") or []):
        if _condition_contains_type(cond, target_types):
            return True
    for cond in (trigger_model.get("mitigations") or []):
        if _condition_contains_type(cond, target_types):
            return True
    return False

def match_patterns(names, patterns):
    hits = []
    for n in names:
        for p in patterns:
            if p in n:
                hits.append(n)
                break
    return sorted(set(hits))

def analyze_triggerability(
    session,
    chain_nodes,
    trigger_model,
    source_patterns,
    sanitizer_patterns,
    context_keywords=[],
    control_nodes=None,
    evidence_calls_override=None,
):
    evidence = evidence_calls_override or collect_evidence_calls(session, chain_nodes)
    all_calls = list((evidence or {}).get("all_calls") or [])
    chain_calls = list((evidence or {}).get("chain_calls") or [])
    evidence_only_mode = False

    if not chain_nodes:
        if not all_calls:
            return {
                "triggerable": "unknown",
                "confidence": "none",
                "evidence_notes": ["No call path analyzed"],
                "method": None,
                "call_id": None,
                "source_calls": [],
                "sanitizer_calls": [],
                "trigger_model": {
                    "required_hits": [],
                    "required_miss": [],
                    "mitigations_hit": []
                }
            }
        evidence_only_mode = True
        if not chain_calls:
            chain_calls = list(all_calls)

    context_names = extract_pattern_context(chain_nodes, all_calls)
    sources = match_patterns(context_names, source_patterns)
    sanitizers = match_patterns(context_names, sanitizer_patterns)
    contexts = match_patterns(context_names, context_keywords)

    trigger_required = []
    trigger_mitigations = []
    if trigger_model:
        trigger_required = trigger_model.get("conditions", [])
        trigger_mitigations = trigger_model.get("mitigations", [])

    required_hits = []
    required_miss = []
    mitigations_hit = []

    for cond in trigger_required:
        res = eval_condition(cond, all_calls, chain_calls, chain_nodes=chain_nodes, control_nodes=control_nodes or [])
        entry = {
            "id": cond.get("id"),
            "type": cond.get("type", "call"),
            "name": cond.get("name") or cond.get("names") or cond.get("name_regex"),
            "evidence": res["evidence"]
        }
        if res["ok"]:
            required_hits.append(entry)
        else:
            required_miss.append(entry)

    for cond in trigger_mitigations:
        res = eval_condition(cond, all_calls, chain_calls, chain_nodes=chain_nodes, control_nodes=control_nodes or [])
        if res["ok"]:
            mitigations_hit.append({
                "id": cond.get("id"),
                "type": cond.get("type", "call"),
                "name": cond.get("name") or cond.get("names") or cond.get("name_regex"),
                "evidence": res["evidence"]
            })

    total_required = len(trigger_required)
    hit_required = len(required_hits)

    evidence_notes = []
    confidence = "low"

    if total_required > 0:
        ratio = hit_required / total_required
        evidence_notes.append(f"Trigger conditions matched: {hit_required}/{total_required}")
        if ratio == 1.0 and not mitigations_hit:
            confidence = "medium" if evidence_only_mode else "high"
        elif ratio >= 0.5:
            confidence = "medium"
        else:
            confidence = "low"
    else:
        evidence_notes.append("No trigger model provided; using heuristic signals")

    if sources:
        evidence_notes.append("Untrusted source detected")
        if confidence == "low":
            confidence = "medium"
    if sanitizers:
        evidence_notes.append(f"Sanitizers present: {sanitizers}")
        if confidence == "high":
            confidence = "medium"
    if contexts:
        evidence_notes.append(f"Relevant context found: {contexts}")
        if confidence == "low":
            confidence = "medium"

    if total_required > 0 and hit_required == total_required and not mitigations_hit:
        triggerable = "possible" if evidence_only_mode else "confirmed"
    elif total_required > 0 and hit_required > 0:
        triggerable = "possible"
    elif total_required == 0 and (sources or contexts):
        triggerable = "possible"
    else:
        triggerable = "unknown"

    if evidence_only_mode:
        evidence_notes.append(
            "No explicit call-chain path; trigger model evaluated from synthetic/source evidence."
        )

    return {
        "triggerable": triggerable,
        "confidence": confidence,
        "evidence_notes": evidence_notes,
        "method": None,
        "call_id": None,
        "source_calls": sources,
        "sanitizer_calls": sanitizers,
        "trigger_model": {
            "required_hits": required_hits,
            "required_miss": required_miss,
            "mitigations_hit": mitigations_hit
        }
    }

def get_symbol_status(session, symbol):
    res = session.run("""
        MATCH (s:SYMBOL {name: $sym, lang:"C"})
        OPTIONAL MATCH (s)-[:RESOLVES_TO]->(m:METHOD:C {name: $sym})
        RETURN s.source_status AS s_status, m.source_status AS m_status, m.id AS mid
        LIMIT 1
    """, sym=symbol).single()

    if not res:
        return "binary-only", False

    if res["m_status"]:
        return res["m_status"], True
    if res["mid"]:
        return "local", True
    if res["s_status"]:
        return res["s_status"], False
    return "binary-only", False

def main():
    parser = argparse.ArgumentParser(description="Supply-chain reachability/triggerability analysis")
    parser.add_argument("--deps", default=DEFAULT_DEPS, help="Path to dependency JSON (optional if --cargo-dir is set)")
    parser.add_argument("--cargo-dir", default="", help="Cargo workspace directory (auto-generate deps)")
    parser.add_argument("--cpg-input", default="", help="Rust input file for CPG generation (optional)")
    parser.add_argument("--cpg-json", default="", help="Existing CPG JSON path for import (optional)")
    parser.add_argument("--cpg-output-dir", default="", help="Directory for generated CPG JSON (default: <report_dir>/cpg_rust)")
    parser.add_argument("--regen-cpg", action="store_true", help="Force regenerate CPG even if cpg-json exists")
    parser.add_argument("--skip-cpg-generation", action="store_true", help="Skip auto CPG generation from cargo project")
    parser.add_argument("--keep-existing-graph", action="store_true", help="Do not clear Neo4j before CPG import")
    parser.add_argument("--allow-no-cpg", action="store_true", help="Allow analysis to run without Rust CPG (default: false)")
    parser.add_argument("--extras", default="", help="Extra JSON with packages/depends (C components)")
    parser.add_argument("--vulns", default=DEFAULT_VULNS, help="Path to vulnerabilities JSON")
    parser.add_argument("--root", default="", help="Root package name (override deps.root)")
    parser.add_argument("--root-method", default="main", help="Root method name for call chain")
    parser.add_argument("--report", default=DEFAULT_REPORT, help="Output report JSON")
    parser.add_argument("--manual-evidence", default="", help="Optional JSON with manual trigger evidence to merge into the report")
    parser.add_argument("--sink-kb", default=DEFAULT_SINK_KB, help="Sink knowledge base JSON path")
    parser.add_argument("--cargo-features", default="", help="Extra cargo metadata features (comma/space separated)")
    parser.add_argument("--cargo-all-features", action="store_true", help="Use --all-features for cargo metadata")
    parser.add_argument("--cargo-no-default-features", action="store_true", help="Use --no-default-features for cargo metadata")
    parser.add_argument("--disable-native-source-supplement", action="store_true", help="Disable on-demand native source supplementation")
    parser.add_argument("--native-source-cache-dir", default="", help="Cache directory for discovered/downloaded native sources and C CPGs")
    parser.add_argument("--clear-supplychain", action="store_true", help="Clear supply-chain nodes/edges")
    parser.add_argument("--enable-path-solving", action="store_true", help="Enable path-feasibility solving using Apron/interval fallback")
    parser.add_argument("--interproc-depth", type=int, default=2, help="Max inter-procedural propagation depth (default: 2)")
    args = parser.parse_args()

    meta = None
    cpg_bootstrap = {
        "generated": False,
        "imported": False,
        "cpg_json": None,
        "input_file": None,
        "edition": None,
        "enabled_features": [],
        "extern_count": 0,
        "expanded_feature_view": False,
        "expanded_enabled_features": [],
    }

    if args.cargo_dir:
        meta = run_metadata(
            args.cargo_dir,
            cargo_features=args.cargo_features,
            cargo_all_features=args.cargo_all_features,
            cargo_no_default_features=args.cargo_no_default_features,
        )
        deps = build_deps_from_cargo(meta)
        base_feature_map = _build_feature_map_from_deps(deps)
        expanded_feature_view = maybe_collect_expanded_feature_deps(
            args.cargo_dir,
            meta,
            cargo_features=args.cargo_features,
            cargo_all_features=args.cargo_all_features,
            cargo_no_default_features=args.cargo_no_default_features,
        )
        if expanded_feature_view:
            merge_extras(deps, expanded_feature_view["deps"])
            _filter_speculative_source_features(deps, base_feature_map)
            cpg_bootstrap["expanded_feature_view"] = True
            cpg_bootstrap["expanded_enabled_features"] = list(expanded_feature_view.get("root_enabled_features") or [])
        if args.extras:
            merge_extras(deps, load_json(args.extras))
    else:
        if not args.deps:
            raise RuntimeError("Missing dependency input: set --cargo-dir or --deps")
        deps = load_json(args.deps)
        if args.extras:
            merge_extras(deps, load_json(args.extras))
    raw_vulns = load_json(args.vulns)
    sink_knowledge = load_sink_knowledge(args.sink_kb)
    manual_evidence_entries = load_manual_evidence(args.manual_evidence)
    vulns = [normalize_vuln_rule(apply_sink_knowledge(v, sink_knowledge)) for v in raw_vulns]
    root_pkg = args.root or deps.get("root", "app")
    package_versions = collect_package_versions(deps)
    package_metadata = collect_package_metadata(deps)
    path_solver = None
    path_solver_enabled = args.enable_path_solving and PathConstraintSolver is not None
    path_solver_init_error = None
    if args.enable_path_solving and PathConstraintSolver is None:
        path_solver_init_error = "tools.verification.path_solver import failed"
        print(f"[!] {path_solver_init_error}", file=sys.stderr)
    elif path_solver_enabled:
        path_solver = PathConstraintSolver(domain="octagon")
        if not path_solver.apron_available:
            print(
                f"[!] Apron unavailable, fallback to interval solver: {path_solver.apron_error}",
                file=sys.stderr,
            )
        if build_path_constraint_bundle is None:
            print(
                "[!] constraint_extractor unavailable, using control-structure constraints only.",
                file=sys.stderr,
            )

    if args.cargo_dir and not args.skip_cpg_generation:
        cpg_json_for_import = ""
        if args.cpg_json and os.path.exists(args.cpg_json) and not args.regen_cpg:
            cpg_json_for_import = os.path.abspath(args.cpg_json)
        else:
            output_dir = args.cpg_output_dir
            if not output_dir:
                report_dir = os.path.dirname(os.path.abspath(args.report)) or os.path.abspath("output")
                output_dir = os.path.join(report_dir, "cpg_rust")
            gen_info = generate_rust_cpg_for_cargo(
                cargo_dir=os.path.abspath(args.cargo_dir),
                meta=meta,
                cpg_input=args.cpg_input,
                output_dir=os.path.abspath(output_dir),
                cargo_features=args.cargo_features,
                cargo_all_features=args.cargo_all_features,
                cargo_no_default_features=args.cargo_no_default_features,
            )
            cpg_json_for_import = gen_info["cpg_json"]
            cpg_bootstrap.update(
                {
                    "generated": True,
                    "cpg_json": cpg_json_for_import,
                    "input_file": gen_info.get("input_file"),
                    "edition": gen_info.get("edition"),
                    "enabled_features": list(gen_info.get("enabled_features") or []),
                    "extern_count": int(gen_info.get("extern_count") or 0),
                }
            )
        import_rust_cpg_json(cpg_json_for_import, clear_db=(not args.keep_existing_graph))
        cpg_bootstrap["imported"] = True
        cpg_bootstrap["cpg_json"] = cpg_json_for_import
    elif args.cpg_json:
        cpg_json_for_import = os.path.abspath(args.cpg_json)
        if not os.path.exists(cpg_json_for_import):
            raise RuntimeError(f"cpg json does not exist: {cpg_json_for_import}")
        import_rust_cpg_json(cpg_json_for_import, clear_db=(not args.keep_existing_graph))
        cpg_bootstrap["imported"] = True
        cpg_bootstrap["cpg_json"] = cpg_json_for_import

    skip_without_fresh_cpg = bool(
        args.cargo_dir
        and args.skip_cpg_generation
        and not args.cpg_json
        and not cpg_bootstrap.get("imported")
        and not args.keep_existing_graph
    )
    if skip_without_fresh_cpg:
        print(
            "[!] skip-cpg-generation enabled without importing a fresh CPG; "
            "results may otherwise depend on stale graph state.",
            file=sys.stderr,
        )

    driver = GraphDatabase.driver(URI, auth=AUTH)
    native_source_cache_dir = args.native_source_cache_dir
    if not native_source_cache_dir:
        report_dir = os.path.dirname(os.path.abspath(args.report)) or os.path.abspath("output")
        native_source_cache_dir = os.path.join(report_dir, "native_source_cache")
    native_source_import_cache = {}
    report = {
        "root": root_pkg,
        "cpg_bootstrap": cpg_bootstrap,
        "native_source_bootstrap": [],
        "vulnerabilities": []
    }

    try:
        with driver.session() as session:
            cpg_stats = get_cpg_stats(session)
            report["cpg_bootstrap"]["stats"] = cpg_stats
            if skip_without_fresh_cpg and not args.allow_no_cpg:
                raise RuntimeError(
                    "Refusing to run with --skip-cpg-generation without a fresh imported CPG "
                    "(and without --keep-existing-graph)."
                )
            if (not args.allow_no_cpg) and (
                cpg_stats.get("rust_methods", 0) <= 0 or cpg_stats.get("rust_calls", 0) <= 0
            ):
                raise RuntimeError(
                    "Rust CPG not available in Neo4j (METHOD:Rust/CALL:Rust missing). "
                    "Please generate/import CPG before running analysis."
                )

            if args.clear_supplychain:
                clear_supplychain(session)

            import_dependencies(session, deps)
            import_vulns(session, vulns, deps)
            attach_symbols(session, vulns)
            attach_root_package_to_rust_methods(session, root_pkg)
            link_c_calls_by_name(session)
            build_symbol_usage(session)
            build_pkg_call(session, root_pkg)
            build_native_pkg_edges(session)

            for v in vulns:
                pkg = v["package"]
                cve = v["cve"]
                vrange = v.get("version_range", "")
                symbols = v.get("symbols", [])
                rust_sink_candidates = collect_rust_sink_candidates(v)
                package_synthetic_sink_calls = collect_package_synthetic_sink_calls(
                    session,
                    root_pkg,
                    rust_sink_candidates,
                )
                source_synthetic_sink_calls = collect_source_synthetic_sink_calls(
                    args.cargo_dir,
                    rust_sink_candidates,
                )
                root_has_bindings_include = _root_has_bindings_include(args.cargo_dir or "")
                root_is_thin_bindings_gateway = _root_is_thin_bindings_gateway(args.cargo_dir or "")

                native_component_instances = resolve_native_component_instances(v, package_metadata, args.cargo_dir)
                dep_match = find_best_dep_chain(
                    session,
                    root_pkg,
                    pkg,
                    native_component_instances=native_component_instances,
                )
                dep_chain = dep_match.get("chain") or []
                dep_chain_evidence = dep_match.get("edges") or []
                dep_chain_target = dep_match.get("target")
                dep_reachable = True if dep_chain else False
                if not dep_reachable:
                    root_norm = str(root_pkg or "").strip().lower().replace("_", "-")
                    root_norm_base = _normalize_native_crate_name(root_norm)
                    for inst in native_component_instances or []:
                        evidence_kinds = {
                            str(item.get("kind") or "")
                            for item in (inst.get("resolution_evidence") or [])
                            if isinstance(item, dict)
                        }
                        matched_rows = list(inst.get("matched_crates") or [])
                        root_crate_hit = False
                        for row in matched_rows:
                            crate_name = str((row or {}).get("crate") or "").strip().lower().replace("_", "-")
                            crate_norm = _normalize_native_crate_name(crate_name)
                            if crate_name == root_norm or (crate_norm and crate_norm == root_norm_base):
                                root_crate_hit = True
                                break
                        if "root_wrapper_probe" in evidence_kinds or root_crate_hit:
                            dep_reachable = True
                            if not dep_chain and root_pkg:
                                dep_chain = [root_pkg]
                            if not dep_chain_target and root_pkg:
                                dep_chain_target = root_pkg
                            if not dep_chain_evidence:
                                dep_chain_evidence = [
                                    {
                                        "from": root_pkg,
                                        "to": pkg,
                                        "type": "NATIVE_DEPENDS_ON",
                                        "evidence_type": "root_wrapper_probe",
                                        "confidence": "medium",
                                        "source": "wrapper-fallback",
                                        "evidence": {"root_wrapper_probe": True},
                                    }
                                ]
                            break

                for sym in symbols:
                    source_status, has_method = get_symbol_status(session, sym)
                    native_source_import = None
                    if (
                        not args.disable_native_source_supplement
                        and not has_method
                        and source_status in ["stub", "binary-only", "system"]
                    ):
                        native_source_import = maybe_import_native_source_for_symbol(
                            session,
                            vuln_rule=v,
                            symbol=sym,
                            native_component_instances=native_component_instances,
                            cache_root=native_source_cache_dir,
                            root_pkg=root_pkg,
                            imported_cache=native_source_import_cache,
                            allow_download=True,
                        )
                        if native_source_import:
                            report["native_source_bootstrap"].append({
                                "package": pkg,
                                "symbol": sym,
                                **native_source_import,
                            })
                        source_status, has_method = get_symbol_status(session, sym)

                    call_chain_nodes = []
                    call_reachability_source = None
                    if has_method:
                        call_chain_nodes = find_call_chain_to_method(session, args.root_method, sym)
                        if call_chain_nodes:
                            call_reachability_source = "c_method"
                    if not call_chain_nodes:
                        call_chain_nodes = find_call_chain_to_call(session, args.root_method, sym)
                        if call_chain_nodes:
                            call_reachability_source = "c_call"
                    if not call_chain_nodes:
                        call_chain_nodes = find_call_chain_to_symbol_usage(session, args.root_method, sym)
                        if call_chain_nodes:
                            call_reachability_source = "c_symbol_usage"
                    if not call_chain_nodes:
                        call_chain_nodes = find_call_chain_to_method_symbol_usage(
                            session,
                            args.root_method,
                            sym,
                            root_pkg=root_pkg,
                        )
                        if call_chain_nodes:
                            call_reachability_source = "c_method_symbol_usage"
                    if not call_chain_nodes and rust_sink_candidates:
                        call_chain_nodes = find_call_chain_to_rust_call(
                            session,
                            args.root_method,
                            rust_sink_candidates,
                            root_pkg=root_pkg,
                        )
                        if call_chain_nodes:
                            call_reachability_source = "rust_call_root"
                    if not call_chain_nodes and rust_sink_candidates:
                        call_chain_nodes = find_call_chain_to_rust_method(
                            session,
                            args.root_method,
                            rust_sink_candidates,
                            root_pkg=root_pkg,
                        )
                        if call_chain_nodes:
                            call_reachability_source = "rust_method_root"
                    crate_aliases = []
                    for instance in native_component_instances or []:
                        for row in instance.get("matched_crates") or []:
                            crate_aliases.extend(_candidate_native_crate_aliases(row.get("crate")))
                    crate_aliases.extend(_candidate_native_crate_aliases(pkg))
                    package_native_gateway_calls = collect_package_native_gateway_calls(
                        session,
                        root_pkg,
                        crate_aliases,
                    )
                    source_native_gateway_calls = collect_source_native_gateway_calls(
                        args.cargo_dir or "",
                        crate_aliases,
                    )
                    if not call_chain_nodes and rust_sink_candidates:
                        call_chain_nodes = find_call_chain_to_rust_method_code_sink(
                            session,
                            args.root_method,
                            rust_sink_candidates,
                            root_pkg=root_pkg,
                        )
                        if call_chain_nodes:
                            call_reachability_source = "rust_method_code_root"
                    if not call_chain_nodes and rust_sink_candidates:
                        call_chain_nodes = find_pkg_call_chain_to_rust_call(
                            session,
                            root_pkg,
                            rust_sink_candidates,
                        )
                        if call_chain_nodes:
                            call_reachability_source = "rust_call_package"
                    if not call_chain_nodes and rust_sink_candidates:
                        call_chain_nodes = find_pkg_method_code_sink(
                            session,
                            root_pkg,
                            rust_sink_candidates,
                        )
                        if call_chain_nodes:
                            call_reachability_source = "rust_method_code_package"
                    if not call_chain_nodes:
                        call_chain_nodes = find_pkg_method_symbol_usage(
                            session,
                            root_pkg,
                            sym,
                        )
                        if call_chain_nodes:
                            call_reachability_source = "c_method_symbol_usage_package"

                    relevant_gateway_calls = select_relevant_native_gateway_calls(
                        list(package_native_gateway_calls or []) + list(source_native_gateway_calls or []),
                        symbol=sym,
                        sink_candidates=rust_sink_candidates,
                        limit=2,
                    )
                    relevant_synthetic_calls = select_relevant_native_gateway_calls(
                        list(package_synthetic_sink_calls or []) + list(source_synthetic_sink_calls or []),
                        symbol=sym,
                        sink_candidates=rust_sink_candidates,
                        limit=2,
                    )
                    bindings_gateway_calls = []
                    if (
                        not call_chain_nodes
                        and not relevant_synthetic_calls
                        and root_has_bindings_include
                        and (root_is_thin_bindings_gateway or str(root_pkg or "").lower().endswith(("sys", "-sys", "_sys")))
                    ):
                        bindings_gateway_calls = [
                            {
                                "id": f"bindingsgw:{root_pkg}:{sym}",
                                "name": sym,
                                "code": f"pub fn {sym}(...)",
                                "lang": "Rust",
                                "method": "bindings_gateway",
                                "scope": "synthetic_bindings_gateway",
                            }
                        ]
                    if relevant_gateway_calls and (
                        not call_chain_nodes
                        or _is_weak_rust_code_reachability_source(call_reachability_source)
                    ):
                        gateway_seed = relevant_gateway_calls
                        call_chain_nodes = [
                            {
                                "id": call.get("id"),
                                "labels": ["METHOD", "Rust"],
                                "name": call.get("method") or call.get("name"),
                                "code": call.get("code"),
                            }
                            for call in gateway_seed
                        ]
                        if call_chain_nodes:
                            call_reachability_source = "rust_native_gateway_package"
                    if not call_chain_nodes and relevant_synthetic_calls:
                        call_chain_nodes = [
                            {
                                "id": call.get("id"),
                                "labels": ["METHOD", "Rust"],
                                "name": call.get("method") or call.get("name"),
                                "code": call.get("code"),
                            }
                            for call in relevant_synthetic_calls
                        ]
                        if call_chain_nodes:
                            call_reachability_source = "rust_synthetic_sink_seed"
                    if not call_chain_nodes and bindings_gateway_calls:
                        call_chain_nodes = [
                            {
                                "id": f"bindings_gateway:{root_pkg}:{sym}",
                                "labels": ["METHOD", "Rust"],
                                "name": "bindings_gateway",
                                "code": 'include!(concat!(env!("OUT_DIR"), "/bindings.rs"));',
                            }
                        ]
                        call_reachability_source = "rust_bindings_gateway_root"

                    call_reachable = True if call_chain_nodes else False
                    call_chain = [n.get("name") or n.get("code") for n in call_chain_nodes if n.get("name") or n.get("code")]
                    call_functions = extract_function_names(call_chain_nodes)
                    trigger_point = pick_trigger_point(call_chain_nodes, sym)
                    evidence_calls = collect_evidence_calls(session, call_chain_nodes)
                    synthetic_sink_calls = synthesize_sink_calls_from_method_code(
                        call_chain_nodes,
                        rust_sink_candidates,
                    )
                    evidence_calls = merge_evidence_calls(evidence_calls, synthetic_sink_calls)
                    evidence_calls = merge_evidence_calls(evidence_calls, package_synthetic_sink_calls)
                    evidence_calls = merge_evidence_calls(evidence_calls, source_synthetic_sink_calls)
                    evidence_calls = merge_evidence_calls(evidence_calls, package_native_gateway_calls)
                    evidence_calls = merge_evidence_calls(evidence_calls, source_native_gateway_calls)
                    evidence_calls = merge_evidence_calls(evidence_calls, bindings_gateway_calls)
                    ffi_semantics = build_ffi_semantics(evidence_calls["all_calls"])

                    analysis_context = {
                        "chain_nodes": call_chain_nodes,
                        "control_nodes": [],
                        "calls": evidence_calls.get("all_calls", []),
                        "build_mode": None,
                    }
                    env_guard_eval = evaluate_env_guards(
                        v,
                        package_metadata,
                        package_versions,
                        component_instances=native_component_instances,
                        analysis_context=analysis_context,
                    )
                    version_eval = env_guard_eval.get("version_eval", {})
                    version_matched = list(version_eval.get("matched_versions") or [])
                    component_version = (
                        [inst.get("resolved_version") for inst in native_component_instances if inst.get("resolved_version")]
                        or version_matched
                        or package_versions.get(pkg)
                        or [None]
                    )[0]

                    reachable = dep_reachable and call_reachable
                    downgrade_reason = None
                    path_feasible = True
                    path_constraints = []
                    control_structures = []
                    input_predicate_eval = {
                        "status": "not_applicable",
                        "class": None,
                        "strategy": None,
                        "positive_hits": [],
                        "negative_hits": [],
                    }
                    path_bundle = build_empty_path_bundle()
                    path_solver_error = None
                    path_solve_detail = {}
                    param_semantics_result = build_param_semantics_default("param_semantics_not_evaluated")
                    existential_input_result = build_state_semantics_default(status="not_applicable")

                    trigger_model = v.get("trigger_model", {}) or {}
                    effective_trigger_model, skipped_trigger_conditions = adapt_trigger_model_for_source_availability(
                        trigger_model,
                        has_c_method=has_method,
                    )
                    control_rules_enabled = has_control_structure_rules(effective_trigger_model)
                    input_predicate_enabled = bool((v.get("input_predicate") or {}).get("class"))
                    if reachable and (control_rules_enabled or input_predicate_enabled):
                        control_structures = collect_control_structures_for_path(session, call_chain_nodes)
                        analysis_context["control_nodes"] = control_structures
                        env_guard_eval = evaluate_env_guards(
                            v,
                            package_metadata,
                            package_versions,
                            component_instances=native_component_instances,
                            analysis_context=analysis_context,
                        )

                    failed_guard_items = list(env_guard_eval.get("failed") or [])
                    version_guard_failed_items = [item for item in failed_guard_items if item.get("kind") == "version_range"]
                    env_guard_failed_items = [item for item in failed_guard_items if item.get("kind") != "version_range"]
                    env_guard_blocked = bool(version_guard_failed_items or env_guard_failed_items)
                    input_predicate_eval = evaluate_input_predicate(
                        v,
                        call_chain_nodes,
                        control_structures,
                        evidence_calls.get("all_calls", []),
                    )

                    trig = analyze_triggerability(
                        session,
                        call_chain_nodes,
                        effective_trigger_model,
                        v.get("source_patterns", []),
                        v.get("sanitizer_patterns", []),
                        context_keywords=v.get("context_patterns", []),
                        control_nodes=control_structures,
                        evidence_calls_override=evidence_calls,
                    )
                    if call_reachability_source and (
                        call_reachability_source.startswith("rust_")
                        or "symbol_usage" in call_reachability_source
                    ):
                        trig["evidence_notes"].append(
                            f"Call reachability inferred via {call_reachability_source}."
                        )
                    if dep_chain_target and dep_chain_target != pkg:
                        trig["evidence_notes"].append(
                            f"Dependency reachability established via matched native crate: {dep_chain_target} -> {pkg}."
                        )
                    if synthetic_sink_calls:
                        trig["evidence_notes"].append(
                            f"Synthetic sink evidence recovered from method code: {len(synthetic_sink_calls)}"
                        )
                    if package_synthetic_sink_calls:
                        trig["evidence_notes"].append(
                            f"Package-level synthetic sink evidence: {len(package_synthetic_sink_calls)}"
                        )
                    if source_synthetic_sink_calls:
                        trig["evidence_notes"].append(
                            f"Source-text synthetic sink evidence: {len(source_synthetic_sink_calls)}"
                        )
                    if native_source_import and native_source_import.get("status") == "imported":
                        trig["evidence_notes"].append(
                            "Native source supplemented via "
                            f"{native_source_import.get('provenance')} from {native_source_import.get('scope_input')}."
                        )
                    if skipped_trigger_conditions:
                        skipped_ids = [item.get("id") for item in skipped_trigger_conditions if item.get("id")]
                        trig["evidence_notes"].append(
                            "Skipped native order guards without C bodies: "
                            + ", ".join(skipped_ids)
                        )

                    trigger_hits = trig.get("trigger_model", {}) or {}

                    constraint_result = build_constraint_result(
                        effective_trigger_model,
                        trigger_hits,
                        ffi_semantics,
                        trig.get("sanitizer_calls", [])
                    )

                    param_rules_enabled = has_param_semantics_rules(effective_trigger_model)
                    existential_rules_enabled = bool(
                        has_state_semantics_rules is not None and has_state_semantics_rules(effective_trigger_model)
                    )
                    needs_bundle = (reachable and (not env_guard_blocked)) and (
                        path_solver_enabled or param_rules_enabled or existential_rules_enabled
                    )

                    if needs_bundle:
                        if not control_structures:
                            control_structures = collect_control_structures_for_path(session, call_chain_nodes)
                        path_bundle = build_path_constraint_bundle_for_symbol(
                            call_chain_nodes,
                            control_structures,
                            sym,
                            trigger_model=effective_trigger_model,
                            evidence_calls=evidence_calls.get("all_calls", []),
                        )
                        path_constraints = path_bundle.get("combined_constraints", [])
                    elif control_structures:
                        path_bundle["control_structures_relevant"] = list(control_structures)

                    if path_solver_enabled and reachable and (not env_guard_blocked):
                        try:
                            solved = path_solver.solve_with_explain(path_constraints)
                            path_solve_detail = solved
                            path_feasible = bool(solved.get("feasible", True))
                        except Exception as exc:
                            path_feasible = True
                            path_solver_error = str(exc)
                        try:
                            write_path_analysis_overlay(
                                session=session,
                                cve=cve,
                                pkg=pkg,
                                symbol=sym,
                                call_chain_nodes=call_chain_nodes,
                                combined_constraints=path_constraints,
                                relevant_control_nodes=path_bundle.get("control_structures_relevant", control_structures),
                                path_feasible=path_feasible,
                                solver_backend=(path_solver.backend if path_solver else "unavailable"),
                                solver_error=path_solver_error or path_bundle.get("bundle_error"),
                            )
                        except Exception as exc:
                            path_solver_error = _append_reason(path_solver_error, f"neo4j_overlay_write_failed:{exc}")

                    if param_rules_enabled:
                        if evaluate_param_semantics is None:
                            param_semantics_result = build_param_semantics_default(
                                "tools.verification.param_semantics import failed"
                            )
                        elif reachable and (not env_guard_blocked):
                            try:
                                param_semantics_result = evaluate_param_semantics(
                                    trigger_model=effective_trigger_model,
                                    evidence_calls=evidence_calls.get("all_calls", []),
                                    control_nodes=control_structures,
                                    path_bundle=path_bundle,
                                    solver=path_solver,
                                    abi_contracts=path_bundle.get("abi_contracts"),
                                    interproc_depth=max(0, int(args.interproc_depth)),
                                )
                            except Exception as exc:
                                param_semantics_result = build_param_semantics_default(
                                    f"param_semantics_eval_error:{exc}"
                                )
                        else:
                            param_semantics_result = build_param_semantics_default(
                                "unreachable_skip_param_semantics"
                            )

                    if existential_rules_enabled and (not env_guard_blocked):
                        if evaluate_state_semantics is None:
                            existential_input_result = build_state_semantics_default(
                                status="unknown",
                                reason="tools.verification.state_semantics import failed",
                            )
                        else:
                            existential_input_result = evaluate_state_semantics(
                                trigger_model=effective_trigger_model,
                                chain_nodes=call_chain_nodes,
                                evidence_calls=evidence_calls.get("all_calls", []),
                                path_bundle=path_bundle,
                                component_name=pkg,
                                component_version=component_version,
                                deps=deps,
                                solver=path_solver,
                            )

                    native_missing_components = list((native_source_import or {}).get("missing_dependencies") or [])
                    native_dependency_imports = list((native_source_import or {}).get("dependency_imports") or [])
                    strict_dependency_resolution = dict((native_source_import or {}).get("strict_dependency_resolution") or {})
                    strict_callsite_edges = int((native_source_import or {}).get("strict_callsite_edges") or 0)
                    native_analysis_coverage = str(
                        (native_source_import or {}).get("native_analysis_coverage")
                        or ("target_only" if (native_source_import or {}).get("status") == "imported" else "none")
                    )
                    if strict_callsite_edges > 0 and not native_missing_components:
                        native_analysis_coverage = "callsite_level"
                    elif strict_dependency_resolution.get("dependencies") and not native_missing_components:
                        native_analysis_coverage = "symbol_level"

                    preserve_binary_decision = has_actionable_trigger_hits(trigger_hits)
                    wrapper_sink_evidence = bool(
                        synthetic_sink_calls or package_synthetic_sink_calls or source_synthetic_sink_calls
                    )
                    explicit_native_symbol_bridge = has_explicit_native_symbol_bridge(
                        sym,
                        list(synthetic_sink_calls or [])
                        + list(package_synthetic_sink_calls or [])
                        + list(source_synthetic_sink_calls or []),
                    )
                    gateway_symbols = []
                    for gateway_call in list(package_native_gateway_calls or []) + list(source_native_gateway_calls or []):
                        gateway_name = str(gateway_call.get("name") or "").strip()
                        if gateway_name and gateway_name not in gateway_symbols:
                            gateway_symbols.append(gateway_name)
                    dependency_source_symbol_bridge = has_dependency_source_symbol_bridge(
                        sym,
                        deps,
                        crate_hints=((v.get("match") or {}).get("crates") or []),
                    )
                    transitive_native_symbol_bridge = has_transitive_native_symbol_bridge(
                        session,
                        pkg,
                        gateway_symbols,
                        sym,
                    )
                    wrapper_input_satisfied = input_predicate_eval.get("status") == "satisfied"
                    native_cross_language_evidence = has_cross_language_native_evidence(
                        source_status=source_status,
                        call_reachability_source=call_reachability_source,
                        has_method=has_method,
                        strict_callsite_edges=strict_callsite_edges,
                        native_analysis_coverage=native_analysis_coverage,
                        native_dependency_imports=native_dependency_imports,
                        strict_dependency_resolution=strict_dependency_resolution,
                    ) or explicit_native_symbol_bridge or dependency_source_symbol_bridge or transitive_native_symbol_bridge
                    conservative_wrapper_reachability = (
                        not reachable
                        and call_reachable
                        and bool(native_component_instances)
                        and preserve_binary_decision
                        and source_status in {"stub", "binary-only", "system", "downloaded-official"}
                        and call_reachability_source in {
                            "rust_call_root",
                            "rust_method_root",
                            "rust_method_code_root",
                            "rust_call_package",
                            "rust_method_code_package",
                            "rust_native_gateway_package",
                            "c_method_symbol_usage_package",
                        }
                        and (wrapper_sink_evidence or native_cross_language_evidence)
                    )
                    if conservative_wrapper_reachability:
                        reachable = True
                        trig["evidence_notes"].append(
                            "Reachability preserved via conservative Rust-wrapper/native bridge despite missing dependency-chain edge."
                        )
                        downgrade_reason = _append_reason(
                            downgrade_reason,
                            "reachable_via_wrapper_bridge_without_dep_chain",
                        )
                    if source_status in ["stub", "binary-only", "system"]:
                        if reachable and preserve_binary_decision and native_cross_language_evidence:
                            triggerable = trig["triggerable"]
                            downgrade_reason = f"source_status={source_status};preserved_by_cross_language_trigger_evidence"
                        elif reachable and wrapper_sink_evidence and wrapper_input_satisfied:
                            triggerable = "possible"
                            downgrade_reason = f"source_status={source_status};preserved_by_wrapper_sink_evidence"
                        else:
                            triggerable = "unknown" if reachable else "unreachable"
                            downgrade_reason = f"source_status={source_status}"
                    else:
                        if reachable:
                            triggerable = trig["triggerable"]
                        else:
                            triggerable = "unreachable"

                    if reachable and version_guard_failed_items:
                        triggerable = "false_positive"
                        downgrade_reason = _append_reason(downgrade_reason, "version_guard_unsatisfied")
                        trig["evidence_notes"].append("Version range guard is unsatisfied; marked as false positive.")

                    if reachable and env_guard_failed_items:
                        triggerable = "false_positive"
                        downgrade_reason = _append_reason(downgrade_reason, "env_guard_unsatisfied")
                        trig["evidence_notes"].append("Environment guards are unsatisfied; marked as false positive.")

                    if reachable and input_predicate_eval.get("status") == "failed":
                        triggerable = "false_positive"
                        downgrade_reason = _append_reason(downgrade_reason, "input_class_excluded")
                        trig["evidence_notes"].append("Input class is explicitly excluded by reachable code path.")
                    elif reachable and input_predicate_eval.get("status") == "satisfied":
                        trig["evidence_notes"].append(f"Input class satisfied: {input_predicate_eval.get('class')}.")

                    if reachable and param_semantics_result.get("status") == "unsat":
                        triggerable = "false_positive"
                        downgrade_reason = _append_reason(downgrade_reason, "param_semantics_unsat")
                        trig["evidence_notes"].append("Parameter semantics are unsatisfiable; marked as false positive.")

                    if reachable and (param_semantics_result.get("interproc_eval") or {}).get("status") == "unsat":
                        triggerable = "false_positive"
                        downgrade_reason = _append_reason(downgrade_reason, "interproc_unsat")
                        trig["evidence_notes"].append("Interprocedural semantics are unsatisfiable; marked as false positive.")

                    if path_solver_enabled and reachable and not path_feasible:
                        triggerable = "false_positive"
                        downgrade_reason = _append_reason(downgrade_reason, "path_constraints_unsat")
                        trig["evidence_notes"].append("Path constraints are unsatisfiable; marked as false positive.")

                    if reachable and existential_input_result.get("status") == "unsat":
                        triggerable = "false_positive"
                        downgrade_reason = _append_reason(downgrade_reason, "existential_input_unsat")
                        trig["evidence_notes"].append("Existential input model is unsatisfiable; marked as false positive.")
                    elif reachable and existential_input_result.get("status") == "sat":
                        used_assumption = any(r.get("used_assumption") for r in existential_input_result.get("rules", []))
                        if used_assumption:
                            trig["evidence_notes"].append("Existential input model satisfied using attacker-controlled length assumptions.")
                        else:
                            trig["evidence_notes"].append("Existential input model satisfied using observed code lengths.")

                    if (
                        reachable
                        and native_analysis_coverage in {"none", "target_only_incomplete"}
                        and not explicit_native_symbol_bridge
                    ):
                        if triggerable == "confirmed":
                            triggerable = "possible"
                        downgrade_reason = _append_reason(downgrade_reason, "native_dependency_graph_incomplete")
                        if native_missing_components:
                            trig["evidence_notes"].append(
                                "Native dependency graph is incomplete; missing source for: "
                                + ", ".join(sorted({str(item.get("component") or "") for item in native_missing_components if item.get("component")}))
                            )
                        else:
                            trig["evidence_notes"].append(
                                "Native dependency graph is incomplete; result preserved using partial native source coverage."
                            )

                    if (
                        reachable
                        and source_status in ["stub", "binary-only", "system"]
                        and triggerable == "confirmed"
                        and not native_cross_language_evidence
                    ):
                        triggerable = "possible"
                        downgrade_reason = _append_reason(downgrade_reason, "cross_language_native_evidence_missing")
                        trig["evidence_notes"].append(
                            "Cross-language native evidence is insufficient; downgraded from confirmed to possible."
                        )
                    elif reachable and explicit_native_symbol_bridge:
                        trig["evidence_notes"].append(
                            f"Cross-language bridge satisfied by explicit native symbol reference in Rust wrapper: {sym}."
                        )
                    elif reachable and dependency_source_symbol_bridge:
                        trig["evidence_notes"].append(
                            f"Cross-language bridge satisfied by dependency wrapper source referencing native symbol: {sym}."
                        )
                    elif reachable and transitive_native_symbol_bridge:
                        trig["evidence_notes"].append(
                            f"Cross-language bridge satisfied transitively via native gateway symbol(s): {', '.join(gateway_symbols[:6])} -> {sym}."
                        )

                    if path_solver_enabled:
                        constraint_result["path_solver"] = {
                            "enabled": True,
                            "backend": path_solver.backend if path_solver else "unavailable",
                            "apron_available": bool(path_solver and path_solver.apron_available),
                            "apron_error": (path_solver.apron_error if path_solver else path_solver_init_error),
                            "feasible": path_feasible,
                            "error": path_solver_error,
                            "constraints": path_constraints,
                            "ranges": path_solve_detail.get("ranges", {}),
                            "bottom_reason": path_solve_detail.get("bottom_reason"),
                            "path_constraints": path_bundle.get("path_constraints", []),
                            "seed_constraints": path_bundle.get("seed_constraints", []),
                            "sink_vars": path_bundle.get("sink_vars", []),
                            "arg_bindings": path_bundle.get("arg_bindings", []),
                            "boundary_assumptions": path_bundle.get("boundary_assumptions", []),
                            "value_env": path_bundle.get("value_env", {}),
                            "bundle_error": path_bundle.get("bundle_error"),
                        }
                        if not path_feasible:
                            constraint_result["status"] = "unsatisfiable"
                            constraint_result["solver"] = "apron|interval-path-solver"
                            if "path_constraints_unsat" not in constraint_result["constraints"]:
                                constraint_result["constraints"].append("path_constraints_unsat")

                    constraint_result["param_semantics"] = param_semantics_result
                    constraint_result["state_semantics"] = existential_input_result
                    constraint_result["existential_inputs"] = existential_input_result
                    constraint_result["interproc_depth"] = max(0, int(args.interproc_depth))
                    if param_semantics_result.get("status") == "unsat":
                        constraint_result["status"] = "unsatisfiable"
                        if "param_semantics_unsat" not in constraint_result["constraints"]:
                            constraint_result["constraints"].append("param_semantics_unsat")
                    if existential_input_result.get("status") == "unsat":
                        constraint_result["status"] = "unsatisfiable"
                        if "existential_input_unsat" not in constraint_result["constraints"]:
                            constraint_result["constraints"].append("existential_input_unsat")

                    assumptions_used = collect_assumption_evidence(v, existential_input_result, path_bundle)
                    if assumptions_used and reachable and triggerable == "confirmed":
                        trig["evidence_notes"].append("Triggerability relies on explicit input assumptions.")

                    if env_guard_eval.get("unresolved") and trig["confidence"] == "high":
                        trig["confidence"] = "medium"
                    if env_guard_eval.get("failed"):
                        trig["confidence"] = "low"
                    if input_predicate_eval.get("status") == "unknown" and trig["confidence"] == "high":
                        trig["confidence"] = "medium"
                    if input_predicate_eval.get("status") == "failed":
                        trig["confidence"] = "low"

                    triggerable_internal = triggerable
                    manual_entry = select_manual_evidence(
                        manual_evidence_entries,
                        cve=cve,
                        package=pkg,
                        symbol=sym,
                    )
                    result_kind = map_result_kind(triggerable_internal, reachable, assumptions_used)
                    guard_summary = summarize_guard_status(trig.get("trigger_model", {}), env_guard_eval)
                    prune_not_triggered = (
                        not bool((trig.get("trigger_model", {}) or {}).get("mitigations_hit"))
                        and not bool(env_guard_eval.get("failed"))
                        and input_predicate_eval.get("status") != "failed"
                    )

                    constraint_result["assumptions_used"] = assumptions_used
                    constraint_result["env_guard_eval"] = env_guard_eval
                    constraint_result["input_predicate_eval"] = input_predicate_eval
                    constraint_result["prune_not_triggered"] = prune_not_triggered

                    report_entry = {
                        "cve": cve,
                        "package": pkg,
                        "version_range": vrange,
                        "resolved_version": component_version,
                        "component_source": (native_component_instances[0].get("source") if native_component_instances else "unknown"),
                        "symbol": sym,
                        "reachable": reachable,
                        "triggerable": triggerable,
                        "triggerable_internal": triggerable_internal,
                        "result_kind": result_kind,
                        "trigger_confidence": trig["confidence"],
                        "satisfied_guards": guard_summary["satisfied_guards"],
                        "unresolved_guards": guard_summary["unresolved_guards"],
                        "failed_guards": guard_summary["failed_guards"],
                        "assumptions_used": assumptions_used,
                        "prune_not_triggered": prune_not_triggered,
                        "native_component_instances": native_component_instances,
                        "native_source_import": native_source_import,
                        "strict_dependency_resolution": strict_dependency_resolution,
                        "binary_symbol_inventory": (native_source_import or {}).get("binary_symbol_inventory"),
                        "strict_callsite_edges": (native_source_import or {}).get("strict_callsite_edges"),
                        "native_analysis_coverage": native_analysis_coverage,
                        "native_dependency_imports": native_dependency_imports,
                        "native_missing_components": native_missing_components,
                        "evidence_notes": trig["evidence_notes"],
                        "source_status": source_status,
                        "downgrade_reason": downgrade_reason,
                        "dependency_chain": dep_chain,
                        "dependency_chain_target": dep_chain_target,
                        "dependency_chain_evidence": dep_chain_evidence,
                        "call_chain": call_chain,
                        "call_chain_nodes": call_chain_nodes,
                        "call_reachability_source": call_reachability_source,
                        "functions_involved": call_functions,
                        "trigger_point": trigger_point,
                        "synthetic_sink_calls": synthetic_sink_calls,
                        "package_synthetic_sink_calls": package_synthetic_sink_calls,
                        "source_synthetic_sink_calls": source_synthetic_sink_calls,
                        "ffi_semantics": ffi_semantics,
                        "constraint_result": constraint_result,
                        "path_feasible": path_feasible,
                        "conditions": {
                            "trigger_conditions": v.get("trigger_conditions", []),
                            "trigger_model": effective_trigger_model,
                            "trigger_model_hits": trig.get("trigger_model", {}),
                            "skipped_trigger_conditions": skipped_trigger_conditions,
                            "source_patterns": v.get("source_patterns", []),
                            "sanitizer_patterns": v.get("sanitizer_patterns", []),
                            "source_hits": trig["source_calls"],
                            "sanitizer_hits": trig["sanitizer_calls"],
                            "env_guard_eval": env_guard_eval,
                            "input_predicate_eval": input_predicate_eval,
                            "control_structures": control_structures,
                            "control_structures_relevant": path_bundle.get("control_structures_relevant", []),
                            "path_constraints": path_bundle.get("path_constraints", []),
                            "seed_constraints": path_bundle.get("seed_constraints", []),
                            "combined_constraints": path_constraints,
                            "sink_args": path_bundle.get("sink_args", []),
                            "sink_vars": path_bundle.get("sink_vars", []),
                            "abi_contracts": path_bundle.get("abi_contracts", {}),
                            "arg_bindings": path_bundle.get("arg_bindings", []),
                            "boundary_assumptions": path_bundle.get("boundary_assumptions", []),
                            "value_env": path_bundle.get("value_env", {}),
                            "param_semantics": param_semantics_result,
                            "state_semantics": existential_input_result,
                            "existential_inputs": existential_input_result,
                            "assumptions_used": assumptions_used,
                            "rule_compile_meta": v.get("rule_compile_meta", {}),
                            "call_reachability_source": call_reachability_source,
                            "synthetic_sink_calls": synthetic_sink_calls,
                            "package_synthetic_sink_calls": package_synthetic_sink_calls,
                            "source_synthetic_sink_calls": source_synthetic_sink_calls,
                        },
                        "evidence": {
                            "ffi_call_id": trig["call_id"],
                            "method": trig["method"]
                        }
                    }
                    report["vulnerabilities"].append(apply_manual_evidence(report_entry, manual_entry))

            deduped_native_bootstrap = []
            seen_native_bootstrap = set()
            for item in report.get("native_source_bootstrap", []):
                key = (
                    item.get("package"),
                    item.get("symbol"),
                    item.get("component"),
                    item.get("resolved_version"),
                    item.get("scope_input"),
                    item.get("status"),
                )
                if key in seen_native_bootstrap:
                    continue
                seen_native_bootstrap.add(key)
                deduped_native_bootstrap.append(item)
            report["native_source_bootstrap"] = deduped_native_bootstrap

    finally:
        driver.close()

    os.makedirs(os.path.dirname(args.report), exist_ok=True)
    with open(args.report, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report written to {args.report}")

if __name__ == "__main__":
    main()
