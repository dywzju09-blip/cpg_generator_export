import argparse
import json
import os
import subprocess
import sys

def run_metadata(cargo_dir):
    cmd = ["cargo", "metadata", "--format-version", "1"]
    res = subprocess.run(cmd, cwd=cargo_dir, capture_output=True, text=True)
    if res.returncode != 0:
        print(res.stderr)
        raise RuntimeError("cargo metadata failed")
    return json.loads(res.stdout)

def load_extras(path):
    if not path:
        return {"packages": [], "depends": []}
    with open(path, "r") as f:
        return json.load(f)

def build_graph(meta):
    id_to_pkg = {p["id"]: p for p in meta.get("packages", [])}
    pkg_list = []
    for p in meta.get("packages", []):
        pkg_list.append({
            "name": p["name"],
            "version": p["version"],
            "lang": "Rust"
        })

    depends = []
    resolve = meta.get("resolve", {})
    for node in resolve.get("nodes", []):
        src = id_to_pkg.get(node["id"])
        if not src:
            continue
        for dep in node.get("deps", []):
            dst = id_to_pkg.get(dep["pkg"])
            if not dst:
                continue
            depends.append({"from": src["name"], "to": dst["name"]})

    # choose root
    root = None
    if meta.get("workspace_default_members"):
        root_id = meta["workspace_default_members"][0]
        root = id_to_pkg.get(root_id, {}).get("name")
    if not root and meta.get("packages"):
        root = meta["packages"][0]["name"]
    return root, pkg_list, depends

def merge_extras(packages, depends, extras):
    existing = {(p["name"], p.get("version", "")) for p in packages}
    for p in extras.get("packages", []):
        key = (p["name"], p.get("version", ""))
        if key not in existing:
            packages.append(p)
            existing.add(key)
    for d in extras.get("depends", []):
        depends.append(d)

def main():
    parser = argparse.ArgumentParser(description="Generate supplychain_deps.json from cargo metadata")
    parser.add_argument("--cargo-dir", required=True, help="Path to Cargo workspace or package")
    parser.add_argument("--extras", default="", help="Extra JSON with packages/depends (C components)")
    parser.add_argument("--root", default="", help="Override root package name")
    parser.add_argument("--out", required=True, help="Output deps JSON")
    args = parser.parse_args()

    meta = run_metadata(args.cargo_dir)
    root, packages, depends = build_graph(meta)
    extras = load_extras(args.extras)
    merge_extras(packages, depends, extras)

    out = {
        "root": args.root or root or "app",
        "packages": packages,
        "depends": depends
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[+] Wrote {args.out}")

if __name__ == "__main__":
    main()
