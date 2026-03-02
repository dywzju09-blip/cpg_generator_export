import argparse
import json
import os
import shutil
import tarfile
import zipfile
import tempfile
import urllib.request
import time
import fnmatch
import subprocess

DEFAULT_SOURCES = "tools/fetch/so_sources.json"
DEFAULT_INDEX = "output/so_index.json"

def load_sources(path):
    with open(path, "r") as f:
        return json.load(f)

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def download(url, out_path, retries=3, backoff_sec=2):
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(url) as resp, open(out_path, "wb") as f:
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
            return
        except Exception as e:
            last_err = e
            if attempt < retries:
                time.sleep(backoff_sec * attempt)
                continue
            raise last_err

def extract_archive(archive_path, out_dir, kind):
    ensure_dir(out_dir)
    if kind == "tar.gz" or kind == "tgz":
        with tarfile.open(archive_path, "r:gz") as t:
            t.extractall(out_dir)
    elif kind == "tar.xz" or kind == "txz":
        with tarfile.open(archive_path, "r:xz") as t:
            t.extractall(out_dir)
    elif kind == "zip":
        with zipfile.ZipFile(archive_path, "r") as z:
            z.extractall(out_dir)
    else:
        raise ValueError(f"Unsupported archive type: {kind}")

def find_matching_files(root_dir, pattern):
    matches = []
    for base, _, files in os.walk(root_dir):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                matches.append(os.path.join(base, name))
    return matches

def main():
    parser = argparse.ArgumentParser(description="Fetch binary-only .so from official sources")
    parser.add_argument("--sources", default=DEFAULT_SOURCES, help="Path to so_sources.json")
    parser.add_argument("--index", default=DEFAULT_INDEX, help="Output index JSON")
    parser.add_argument("--force", action="store_true", help="Re-download even if exists")
    args = parser.parse_args()

    data = load_sources(args.sources)
    libs = data.get("libraries", [])
    index = []

    ensure_dir(os.path.dirname(args.index))

    for lib in libs:
        name = lib["name"]
        url = lib["official_url"]
        archive = lib.get("archive", "tar.gz")
        so_glob = lib.get("so_glob", "*.so*")
        out_dir = lib.get("output_dir", f"vendor/so/{name}")
        source_status = lib.get("source_status", "binary-only")
        build_cmds = lib.get("build_commands", [])

        ensure_dir(out_dir)
        already = find_matching_files(out_dir, so_glob)
        if already and not args.force:
            index.append({
                "name": name,
                "status": "cached",
                "source_status": source_status,
                "files": already
            })
            continue

        with tempfile.TemporaryDirectory() as tmp:
            archive_path = os.path.join(tmp, f"{name}.{archive.replace('.', '_')}")
            download(url, archive_path)
            extract_dir = os.path.join(tmp, "extract")
            extract_archive(archive_path, extract_dir, archive)

            copied = []
            if build_cmds:
                env = os.environ.copy()
                env["OUTPUT_DIR"] = os.path.abspath(out_dir)
                
                # Auto-detect subdirectory if only one folder exists
                build_cwd = extract_dir
                items = os.listdir(extract_dir)
                if len(items) == 1 and os.path.isdir(os.path.join(extract_dir, items[0])):
                    build_cwd = os.path.join(extract_dir, items[0])
                
                for cmd in build_cmds:
                    cmd = cmd.format(output_dir=os.path.abspath(out_dir))
                    subprocess.run(cmd, shell=True, cwd=build_cwd, check=True, env=env)

                matches = find_matching_files(out_dir, so_glob)
                copied = matches
                status = "built" if copied else "not_found"
            else:
                matches = find_matching_files(extract_dir, so_glob)
                for m in matches:
                    dst = os.path.join(out_dir, os.path.basename(m))
                    shutil.copy2(m, dst)
                    copied.append(dst)
                status = "downloaded" if copied else "not_found"

            index.append({
                "name": name,
                "status": status,
                "source_status": source_status,
                "files": copied,
                "url": url
            })

    with open(args.index, "w") as f:
        json.dump(index, f, indent=2)
    print(f"[+] Wrote index: {args.index}")

if __name__ == "__main__":
    main()
