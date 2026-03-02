import argparse
import json
import os
import re
import sys

DEFAULT_REGISTRY = "tools/supplychain/vuln_registry.json"

def load_registry(path):
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return json.load(f)

def save_registry(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def parse_csv(val):
    if not val:
        return []
    return [v.strip() for v in val.split(",") if v.strip()]

def detect_lang_from_path(path):
    if not path:
        return None
    path = path.lower()
    if path.endswith(".rs"):
        return "rust"
    if path.endswith(".c") or path.endswith(".h"):
        return "c"
    return None

def extract_rust_fn(line):
    m = re.search(r'\b(?:pub\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_]\w*)\s*\(', line)
    return m.group(1) if m else None

def extract_c_fn(line):
    if re.search(r'\b(if|for|while|switch)\b', line):
        return None
    if "typedef" in line or "struct" in line:
        return None
    if "=" in line:
        return None
    m = re.search(r'^[\w\s\*\(\)]+?\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:\{|$)', line.strip())
    return m.group(1) if m else None

def extract_from_context(ctx, lang):
    if not ctx:
        return None
    if lang == "rust":
        return extract_rust_fn(ctx)
    if lang == "c":
        return extract_c_fn(ctx)
    # fallback: try both
    return extract_rust_fn(ctx) or extract_c_fn(ctx)

def extract_symbols_from_diff(diff_path):
    symbols = set()
    current_lang = None

    with open(diff_path, "r", errors="ignore") as f:
        for raw in f:
            line = raw.rstrip("\n")

            if line.startswith("+++ "):
                # +++ b/path
                path = line[4:].strip()
                if path.startswith("b/"):
                    path = path[2:]
                current_lang = detect_lang_from_path(path)
                continue

            if line.startswith("@@"):
                m = re.search(r'@@.*@@\s*(.*)$', line)
                if m:
                    ctx = m.group(1).strip()
                    name = extract_from_context(ctx, current_lang)
                    if name:
                        symbols.add(name)
                continue

            if line.startswith("+++ ") or line.startswith("--- "):
                continue

            if line.startswith("+") or line.startswith("-"):
                if line.startswith("+++") or line.startswith("---"):
                    continue
                code = line[1:].strip()
                name = extract_from_context(code, current_lang)
                if name:
                    symbols.add(name)

    return sorted(symbols)

def find_entry(registry, cve, package):
    for e in registry:
        if e.get("cve") == cve and e.get("package") == package:
            return e
    return None

def merge_unique(dst, src):
    out = list(dst) if dst else []
    for s in src:
        if s not in out:
            out.append(s)
    return out

def add_or_update(args):
    registry = load_registry(args.registry)
    entry = find_entry(registry, args.cve, args.package)
    if entry is None:
        entry = {
            "cve": args.cve,
            "package": args.package
        }
        registry.append(entry)

    if args.version_range:
        entry["version_range"] = args.version_range

    if args.description:
        entry["description"] = args.description

    if args.source_status:
        entry["source_status"] = args.source_status

    if args.trigger_conditions:
        entry["trigger_conditions"] = parse_csv(args.trigger_conditions)

    if args.source_patterns:
        entry["source_patterns"] = parse_csv(args.source_patterns)

    if args.sanitizer_patterns:
        entry["sanitizer_patterns"] = parse_csv(args.sanitizer_patterns)

    symbols = []
    if args.symbols:
        symbols.extend(parse_csv(args.symbols))

    if args.patch:
        extracted = extract_symbols_from_diff(args.patch)
        symbols.extend(extracted)
        entry.setdefault("symbol_sources", {})
        entry["symbol_sources"]["from_patch"] = extracted

    if symbols:
        entry["symbols"] = merge_unique(entry.get("symbols", []), symbols)

    save_registry(args.out or args.registry, registry)
    print(f"[+] Updated registry: {args.out or args.registry}")

def validate_registry(args):
    registry = load_registry(args.registry)
    errors = 0
    for idx, e in enumerate(registry):
        if not e.get("cve") or not e.get("package"):
            print(f"[!] Entry {idx} missing cve/package")
            errors += 1
        if "symbols" in e and not isinstance(e["symbols"], list):
            print(f"[!] Entry {idx} symbols must be list")
            errors += 1
    if errors == 0:
        print("[+] Registry validation passed")
    else:
        print(f"[!] Registry validation failed: {errors} issues")
        sys.exit(1)

def extract_only(args):
    symbols = extract_symbols_from_diff(args.patch)
    print(json.dumps({"symbols": symbols}, indent=2))

def main():
    parser = argparse.ArgumentParser(description="Supply-chain vulnerability registry helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    add = sub.add_parser("add", help="Add or update a vulnerability entry")
    add.add_argument("--registry", default=DEFAULT_REGISTRY, help="Path to registry JSON")
    add.add_argument("--out", default="", help="Output registry path (optional)")
    add.add_argument("--cve", required=True, help="CVE id")
    add.add_argument("--package", required=True, help="Package name")
    add.add_argument("--version-range", default="", help="Version range expression")
    add.add_argument("--symbols", default="", help="Comma-separated symbol names")
    add.add_argument("--patch", default="", help="Unified diff patch path for symbol extraction")
    add.add_argument("--source-status", default="", help="source_status: local|stub|binary-only")
    add.add_argument("--trigger-conditions", default="", help="Comma-separated trigger conditions")
    add.add_argument("--source-patterns", default="", help="Comma-separated source patterns")
    add.add_argument("--sanitizer-patterns", default="", help="Comma-separated sanitizer patterns")
    add.add_argument("--description", default="", help="Description")
    add.set_defaults(func=add_or_update)

    ext = sub.add_parser("extract", help="Extract symbols from patch diff")
    ext.add_argument("--patch", required=True, help="Unified diff patch path")
    ext.set_defaults(func=extract_only)

    val = sub.add_parser("validate", help="Validate registry format")
    val.add_argument("--registry", default=DEFAULT_REGISTRY, help="Path to registry JSON")
    val.set_defaults(func=validate_registry)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
