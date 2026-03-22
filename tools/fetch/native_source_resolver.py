import os
import re
import shutil
import tarfile
import urllib.request
import zipfile

from tools.fetch.native_source_providers import (
    canonical_component_name,
    get_provider,
    infer_source_dependencies,
)


_C_FAMILY_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
}


def _normalize_component(component):
    return canonical_component_name(component).strip().lower()


def _has_c_family_files(root_dir):
    if not root_dir or not os.path.isdir(root_dir):
        return False
    for base, _, files in os.walk(root_dir):
        for name in files:
            _, ext = os.path.splitext(name)
            if ext.lower() in _C_FAMILY_EXTENSIONS:
                return True
    return False


def _dedupe_paths(paths):
    seen = set()
    out = []
    for item in paths or []:
        path = os.path.abspath(str(item or ""))
        if not path or path in seen:
            continue
        seen.add(path)
        out.append(path)
    return out


def find_local_native_source_tree(component, manifest_paths):
    provider = get_provider(component)
    if not provider:
        return None
    local_dirs = list(provider.local_dirs or [])
    if not local_dirs:
        return None

    canonical = provider.name
    for manifest_path in _dedupe_paths(manifest_paths):
        crate_dir = os.path.dirname(manifest_path)
        for rel_dir in local_dirs:
            candidate = os.path.join(crate_dir, rel_dir)
            if _has_c_family_files(candidate):
                validation = provider.validate_source_tree(candidate)
                return {
                    "status": "local",
                    "provenance": "bundled-local",
                    "source_root": os.path.abspath(candidate),
                    "component": canonical,
                    "download_url": None,
                    "validation": validation,
                }
    return None


def _extract_archive(archive_path, out_dir):
    if archive_path.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive_path, "r:gz") as handle:
            handle.extractall(out_dir)
        return
    if archive_path.endswith((".tar.xz", ".txz")):
        with tarfile.open(archive_path, "r:xz") as handle:
            handle.extractall(out_dir)
        return
    if archive_path.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as handle:
            handle.extractall(out_dir)
        return
    raise ValueError(f"unsupported archive type for {archive_path}")


def _download_file(url, out_path):
    with urllib.request.urlopen(url) as response, open(out_path, "wb") as handle:
        shutil.copyfileobj(response, handle)


def _official_source_candidates(component, version):
    provider = get_provider(component)
    if not provider:
        return []
    return provider.official_candidates(version)


def _find_extracted_source_root(root_dir, component=""):
    provider = get_provider(component)
    if _has_c_family_files(root_dir):
        return root_dir
    candidates = []
    for name in sorted(os.listdir(root_dir)):
        candidate = os.path.join(root_dir, name)
        if os.path.isdir(candidate) and _has_c_family_files(candidate):
            candidates.append(candidate)
    if not candidates:
        return None
    if provider:
        for candidate in candidates:
            validation = provider.validate_source_tree(candidate)
            if validation.get("status") == "ok":
                return candidate
    return candidates[0]


def download_official_native_source(component, version, cache_root):
    provider = get_provider(component)
    candidates = _official_source_candidates(component, version)
    if not provider or not candidates:
        return {
            "status": "unsupported",
            "provenance": "downloaded-official",
            "source_root": None,
            "component": canonical_component_name(component),
            "download_url": None,
            "reason": "official_download_not_supported",
        }

    component_key = _normalize_component(component).replace("/", "_")
    version_key = str(version or "unknown").strip() or "unknown"
    base_dir = os.path.join(os.path.abspath(cache_root), component_key, version_key)
    source_dir = os.path.join(base_dir, "source")
    archive_dir = os.path.join(base_dir, "archives")
    os.makedirs(archive_dir, exist_ok=True)

    cached_root = _find_extracted_source_root(source_dir, provider.name) if os.path.isdir(source_dir) else None
    if cached_root:
        validation = provider.validate_source_tree(cached_root)
        return {
            "status": "downloaded",
            "provenance": "downloaded-official",
            "source_root": os.path.abspath(cached_root),
            "component": provider.name,
            "download_url": None,
            "validation": validation,
        }

    last_error = None
    for item in candidates:
        url = item["url"]
        archive_path = os.path.join(archive_dir, item["archive_name"])
        try:
            if not os.path.exists(archive_path):
                _download_file(url, archive_path)
            if os.path.isdir(source_dir):
                shutil.rmtree(source_dir)
            os.makedirs(source_dir, exist_ok=True)
            _extract_archive(archive_path, source_dir)
            extracted_root = _find_extracted_source_root(source_dir, provider.name)
            if extracted_root:
                validation = provider.validate_source_tree(extracted_root)
                return {
                    "status": "downloaded",
                    "provenance": "downloaded-official",
                    "source_root": os.path.abspath(extracted_root),
                    "component": provider.name,
                    "download_url": url,
                    "validation": validation,
                }
            last_error = "no_c_family_files_after_extract"
        except Exception as exc:
            last_error = str(exc)

    return {
        "status": "failed",
        "provenance": "downloaded-official",
        "source_root": None,
        "component": provider.name,
        "download_url": None,
        "reason": last_error or "download_failed",
    }


def ensure_native_source_tree(component, version, manifest_paths, cache_root, allow_download=True):
    local = find_local_native_source_tree(component, manifest_paths)
    if local:
        return local
    if allow_download:
        return download_official_native_source(component, version, cache_root)
    return {
        "status": "unavailable",
        "provenance": "none",
        "source_root": None,
        "component": canonical_component_name(component),
        "download_url": None,
        "reason": "download_disabled",
    }


def find_symbol_source_files(source_root, symbols, max_hits_per_symbol=8):
    if not source_root or not os.path.isdir(source_root):
        return []
    normalized_symbols = [str(sym or "").strip() for sym in (symbols or []) if str(sym or "").strip()]
    if not normalized_symbols:
        return []

    patterns = [(sym, re.compile(rf"\b{re.escape(sym)}\b")) for sym in normalized_symbols]
    hits = []
    seen = set()
    per_symbol = {sym: 0 for sym in normalized_symbols}

    for base, _, files in os.walk(source_root):
        for name in files:
            _, ext = os.path.splitext(name)
            if ext.lower() not in _C_FAMILY_EXTENSIONS:
                continue
            file_path = os.path.join(base, name)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                    text = handle.read()
            except Exception:
                continue
            matched = False
            for sym, regex in patterns:
                if per_symbol[sym] >= max_hits_per_symbol:
                    continue
                if regex.search(text):
                    per_symbol[sym] += 1
                    matched = True
            if matched:
                abs_path = os.path.abspath(file_path)
                if abs_path not in seen:
                    seen.add(abs_path)
                    hits.append(abs_path)
    return hits


def choose_c_analysis_scope(source_root, symbol_files):
    root = os.path.abspath(source_root) if source_root else ""
    files = _dedupe_paths(symbol_files)
    if not root or not os.path.exists(root):
        return ""
    if not files:
        return root

    dirs = [os.path.dirname(path) for path in files]
    if len(dirs) == 1:
        return dirs[0]

    try:
        common_dir = os.path.commonpath(dirs)
    except ValueError:
        return root
    if common_dir and common_dir.startswith(root):
        return common_dir
    return root


def infer_native_source_dependencies(component, source_root):
    return infer_source_dependencies(source_root, component)
