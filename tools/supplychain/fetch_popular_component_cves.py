#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.supplychain.vuln_db import write_json
from tools.supplychain.vuln_db_seed import COMPONENTS, VULNERABILITIES


API_BASE = "https://cve.circl.lu/api/search/{vendor}/{product}?page={page}"
DEFAULT_OUT = REPO_ROOT / "Data" / "vuln_db" / "catalog" / "auto_cves_2021_2026.json"
PUB_START = datetime.fromisoformat("2021-01-01T00:00:00")
MAX_PER_COMPONENT = 40
TARGET_TOTAL = 200
NON_SYMBOL_WORDS = {
    "Request",
    "Response",
    "ClientHello",
    "ServerHello",
    "Impact",
    "Issue",
    "DEFAULT",
}


COMPONENT_QUERY_CANDIDATES = {
    "libxml2": [("gnome", "libxml2")],
    "expat": [("libexpat", "expat"), ("expat", "expat")],
    "zlib": [("zlib", "zlib")],
    "libwebp": [("google", "libwebp"), ("webmproject", "libwebp")],
    "libgit2": [("libgit2", "libgit2")],
    "sqlite": [("sqlite", "sqlite")],
    "pcre2": [("pcre", "pcre2")],
    "openssl": [("openssl", "openssl")],
    "openh264": [("cisco", "openh264")],
    "gdal": [("osgeo", "gdal")],
    "libheif": [("strukturag", "libheif"), ("libheif", "libheif")],
    "freetype": [("freetype", "freetype")],
    "gstreamer": [("gstreamer", "gstreamer")],
    "libjpeg-turbo": [("libjpeg-turbo", "libjpeg-turbo")],
    "cjson": [("davegamble", "cjson"), ("cjson", "cjson")],
    "libpng": [("pnggroup", "libpng"), ("libpng", "libpng")],
    "libtiff": [("libtiff", "libtiff")],
    "curl": [("curl", "curl")],
    "libarchive": [("libarchive", "libarchive")],
    "libsndfile": [("libsndfile", "libsndfile"), ("libsndfile_project", "libsndfile")],
    "harfbuzz": [("harfbuzz", "harfbuzz")],
    "libssh2": [("libssh2", "libssh2")],
    "libzip": [("libzip", "libzip")],
    "ffmpeg": [("ffmpeg", "ffmpeg")],
    "libvpx": [("webmproject", "libvpx"), ("libvpx", "libvpx")],
    "libaom": [("aomedia", "libaom"), ("libaom", "libaom")],
    "xz": [("tukaani", "xz"), ("xz", "xz")],
    "brotli": [("google", "brotli"), ("brotli", "brotli")],
    "libyaml": [("libyaml", "libyaml")],
    "libraw": [("libraw", "libraw")],
}


def component_index() -> dict[str, dict]:
    return {item["component"]: item for item in COMPONENTS}


def existing_manual_keys() -> set[tuple[str, str]]:
    return {(item["component"], item["cve"]) for item in VULNERABILITIES}


def curl_json(url: str) -> dict[str, Any]:
    proc = subprocess.run(
        ["curl", "-L", url],
        capture_output=True,
        text=True,
        check=True,
    )
    text = proc.stdout.strip()
    if not text:
        return {}
    return json.loads(text)


def parse_published(record: dict) -> datetime | None:
    candidates = [
        (((record.get("cveMetadata") or {}).get("datePublished")) or ""),
        (record.get("published") or ""),
        (((record.get("containers") or {}).get("cna") or {}).get("datePublic") or ""),
    ]
    for item in candidates:
        text = str(item or "").strip().replace("Z", "+00:00")
        if not text:
            continue
        try:
            return datetime.fromisoformat(text).replace(tzinfo=None)
        except Exception:
            continue
    return None


def record_cve_id(record: dict) -> str:
    return str((record.get("cveMetadata") or {}).get("cveId") or record.get("id") or "").strip()


def extract_severity(record: dict) -> str:
    severity_candidates = []
    for metric in (((record.get("containers") or {}).get("cna") or {}).get("metrics") or []):
        other = (metric or {}).get("other") or {}
        content = other.get("content") or {}
        text = str(content.get("text") or "").strip()
        if text:
            severity_candidates.append(text.upper())
    metrics = record.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for item in metrics.get(key) or []:
            cvss = (item or {}).get("cvssData") or {}
            text = str(cvss.get("baseSeverity") or "").strip()
            if text:
                severity_candidates.append(text.upper())
    for severity in severity_candidates:
        if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            return severity.lower()
    return "high"


def select_source_record(raw: dict) -> list[dict]:
    results = raw.get("results") or {}
    best_by_cve: dict[str, dict] = {}
    score_by_cve: dict[str, int] = {}
    for key in ("nvd", "fkie_nvd", "cvelistv5"):
        for entry in results.get(key) or []:
            if isinstance(entry, list) and len(entry) == 2:
                rec = entry[1]
            else:
                rec = entry
            if not isinstance(rec, dict):
                continue
            cve = record_cve_id(rec)
            if not cve:
                continue
            score = 0
            if rec.get("configurations"):
                score += 5
            if (((rec.get("containers") or {}).get("cna") or {}).get("affected")):
                score += 3
            if rec.get("descriptions") or (((rec.get("containers") or {}).get("cna") or {}).get("descriptions")):
                score += 1
            if rec.get("references") or (((rec.get("containers") or {}).get("cna") or {}).get("references")):
                score += 1
            if score > score_by_cve.get(cve, -1):
                best_by_cve[cve] = rec
                score_by_cve[cve] = score
    return list(best_by_cve.values())


def first_description(record: dict) -> str:
    for desc in (((record.get("containers") or {}).get("cna") or {}).get("descriptions") or []):
        if desc.get("lang") == "en" and desc.get("value"):
            return str(desc["value"]).strip()
    for desc in record.get("descriptions") or []:
        if desc.get("lang") == "en" and desc.get("value"):
            return str(desc["value"]).strip()
    return ""


def record_references(record: dict) -> dict:
    refs = {"advisory": [], "patch": [], "poc": []}
    candidates = []
    candidates.extend((((record.get("containers") or {}).get("cna") or {}).get("references") or []))
    candidates.extend(record.get("references") or [])
    for ref in candidates:
        url = str((ref or {}).get("url") or "").strip()
        if not url:
            continue
        tags = {str(tag).lower() for tag in ((ref or {}).get("tags") or [])}
        if "patch" in tags:
            refs["patch"].append(url)
        elif "exploit" in tags or "poc" in tags:
            refs["poc"].append(url)
        else:
            refs["advisory"].append(url)
    for key in refs:
        deduped = []
        for url in refs[key]:
            if url not in deduped:
                deduped.append(url)
        refs[key] = deduped[:12]
    return refs


def extract_symbols(description: str, component_entry: dict) -> list[str]:
    found = []
    for match in re.findall(r"\b[A-Za-z_][A-Za-z0-9_:]*\s*\(", description or ""):
        symbol = match.strip().rstrip("(").strip()
        if symbol in NON_SYMBOL_WORDS:
            continue
        if not ("_" in symbol or "::" in symbol or symbol[:1].islower()):
            continue
        if symbol and symbol not in found:
            found.append(symbol)
    if not found:
        found.extend(component_entry.get("native_symbols") or [])
    return found[:6]


def build_trigger_conditions(description: str, component_entry: dict) -> list[str]:
    text = " ".join((description or "").split())
    conditions = []
    if component_entry.get("input_class"):
        conditions.append(f"attacker-controlled input reaches {component_entry['component']} parsing or processing entrypoints")
    if text:
        conditions.append(text[:280])
    if component_entry.get("native_symbols"):
        conditions.append(f"execution reaches native routines such as {component_entry['native_symbols'][0]}")
    return conditions[:3]


def default_input_predicate(component_entry: dict) -> dict:
    klass = component_entry.get("input_class")
    if not klass:
        return {}
    return {
        "class": klass,
        "positive_tokens": list(component_entry.get("input_tokens") or []),
        "negative_tokens": [],
        "strategy": "assume_if_not_explicit",
    }


def default_rust_sinks(component_entry: dict) -> list[dict]:
    return [{"path": item} for item in (component_entry.get("rust_entrypoints") or [])[:6]]


def pick_native_sinks(component_entry: dict, description: str) -> list[str]:
    symbols = extract_symbols(description, component_entry)
    if symbols:
        return symbols[:6]
    return list(component_entry.get("native_symbols") or [])[:6]


def affected_versions_from_cna(record: dict, component_entry: dict) -> list[dict]:
    component_keys = {
        component_entry["component"].lower(),
        *[str(x).lower() for x in component_entry.get("aliases") or []],
        *[str(x).lower() for x in component_entry.get("package_aliases") or []],
    }
    out = []
    for item in (((record.get("containers") or {}).get("cna") or {}).get("affected") or []):
        product = str(item.get("product") or item.get("packageName") or "").lower()
        vendor = str(item.get("vendor") or "").lower()
        if product and product not in component_keys and not any(key in product for key in component_keys):
            if not any(key in vendor for key in component_keys):
                continue
        for version in item.get("versions") or []:
            normalized = {
                "version": str(version.get("version") or "").strip(),
                "status": str(version.get("status") or "").strip(),
                "lessThan": str(version.get("lessThan") or "").strip(),
                "lessThanOrEqual": str(version.get("lessThanOrEqual") or "").strip(),
                "versionType": str(version.get("versionType") or "").strip(),
            }
            if normalized["version"].lower() in {"", "n/a", "*"} and not normalized["lessThan"] and not normalized["lessThanOrEqual"]:
                continue
            if any(normalized.values()):
                out.append(normalized)
    return out


def affected_versions_from_nvd(record: dict, component_entry: dict) -> list[dict]:
    component_keys = {
        component_entry["component"].lower(),
        *[str(x).lower() for x in component_entry.get("aliases") or []],
        *[str(x).lower() for x in component_entry.get("package_aliases") or []],
    }
    out = []
    for config in record.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                criteria = str(match.get("criteria") or "").lower()
                if component_keys and not any(key in criteria for key in component_keys):
                    continue
                exact_version = ""
                criteria_parts = criteria.split(":")
                if len(criteria_parts) > 5:
                    candidate = criteria_parts[5].strip()
                    if candidate not in {"", "*", "-"}:
                        exact_version = candidate
                out.append(
                    {
                        "version": str(match.get("versionStartIncluding") or match.get("versionStartExcluding") or exact_version).strip(),
                        "status": "affected",
                        "lessThan": str(match.get("versionEndExcluding") or "").strip(),
                        "lessThanOrEqual": str(match.get("versionEndIncluding") or "").strip(),
                        "criteria": str(match.get("criteria") or "").strip(),
                    }
                )
    return out


def version_range_expr(affected_versions: list[dict]) -> str:
    clauses = []
    for item in affected_versions:
        parts = []
        version = str(item.get("version") or "").strip()
        if version and version not in {"0", "n/a", "*"}:
            parts.append(f">={version}")
        if item.get("lessThan"):
            parts.append(f"<{item['lessThan']}")
        elif item.get("lessThanOrEqual"):
            parts.append(f"<={item['lessThanOrEqual']}")
        if not parts and version and version not in {"n/a", "*"}:
            parts.append(version)
        if parts:
            clause = ",".join(parts)
            if clause not in clauses:
                clauses.append(clause)
    return " || ".join(clauses)


def source_pairs(record: dict) -> dict:
    meta = record.get("cveMetadata") or {}
    cna = ((record.get("containers") or {}).get("cna") or {})
    return {
        "assigner": str(meta.get("assignerShortName") or "").strip(),
        "provider": str((cna.get("providerMetadata") or {}).get("shortName") or "").strip(),
    }


def fetch_component_records(component_name: str) -> list[dict]:
    candidates = COMPONENT_QUERY_CANDIDATES.get(component_name) or []
    for vendor, product in candidates:
        try:
            first = curl_json(API_BASE.format(vendor=vendor, product=product, page=1))
        except Exception:
            continue
        total = int(first.get("total_count") or 0)
        if total <= 0:
            continue
        pages = max(1, min(5, (total + 9) // 10))
        records = []
        records.extend(select_source_record(first))
        for page in range(2, pages + 1):
            try:
                data = curl_json(API_BASE.format(vendor=vendor, product=product, page=page))
            except Exception:
                break
            records.extend(select_source_record(data))
        return records
    return []


def build_auto_entries(target_total: int, selected_components: list[str] | None = None, verbose: bool = False) -> list[dict]:
    comp_map = component_index()
    manual_keys = existing_manual_keys()
    per_component: dict[str, list[dict]] = defaultdict(list)
    component_names = selected_components or list(comp_map.keys())
    seen_keys: set[tuple[str, str]] = set()

    for component_name in component_names:
        if component_name not in comp_map:
            continue
        records = fetch_component_records(component_name)
        if verbose:
            print(f"[fetch] {component_name}: records={len(records)}", file=sys.stderr)
        for record in records:
            cve = record_cve_id(record)
            key = (component_name, cve)
            if not cve or key in manual_keys or key in seen_keys:
                continue
            published = parse_published(record)
            if not published or published < PUB_START:
                continue
            component_entry = comp_map[component_name]
            description = first_description(record)
            affected_versions = affected_versions_from_cna(record, component_entry) or affected_versions_from_nvd(record, component_entry)
            range_expr = version_range_expr(affected_versions)
            if not range_expr:
                continue
            entry = {
                "component": component_name,
                "cve": cve,
                "version_range": range_expr,
                "description": description[:400] if description else f"{component_name} vulnerability",
                "severity": extract_severity(record),
                "maturity": "curated",
                "symbols": extract_symbols(description, component_entry),
                "trigger_conditions": build_trigger_conditions(description, component_entry),
                "source_patterns": list(component_entry.get("input_tokens") or [])[:8],
                "sanitizer_patterns": ["validate_input", "size_check", "limit", "allowlist"][:4],
                "source_status": component_entry.get("default_source") or "system",
                "rust_sinks": default_rust_sinks(component_entry),
                "native_sinks": pick_native_sinks(component_entry, description),
                "must_flow": [],
                "env_guards": {},
                "trigger_model": {
                    "conditions": [
                        {
                            "id": f"{component_name}_{cve.lower()}_input",
                            "type": "input_class",
                            "class": component_entry.get("input_class") or "crafted_input",
                            "positive_tokens": list(component_entry.get("input_tokens") or [])[:10],
                            "negative_tokens": [],
                            "strategy": "assume_if_not_explicit",
                        }
                    ],
                    "mitigations": [],
                },
                "input_predicate": default_input_predicate(component_entry),
                "references": record_references(record),
                "web_summary": description[:500],
                "notes": f"Auto-collected from public CVE records for {component_name}.",
                "published": published.isoformat(),
                "official_source": source_pairs(record),
                "source_affected_versions": affected_versions,
            }
            if len(per_component[component_name]) < MAX_PER_COMPONENT:
                per_component[component_name].append(entry)
                seen_keys.add(key)
            if sum(len(items) for items in per_component.values()) >= target_total:
                break
        if sum(len(items) for items in per_component.values()) >= target_total:
            break

    merged = []
    merged_seen = set()
    for component_name, items in per_component.items():
        items.sort(key=lambda item: item["published"], reverse=True)
        for item in items[:MAX_PER_COMPONENT]:
            key = (item["component"], item["cve"])
            if key in merged_seen:
                continue
            merged_seen.add(key)
            merged.append(item)
    merged.sort(key=lambda item: item["published"], reverse=True)
    return merged[:target_total]


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch popular component CVEs from public APIs and generate database-ready entries")
    parser.add_argument("--target-total", type=int, default=TARGET_TOTAL)
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--components", default="", help="Comma-separated component allowlist")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    out_path = Path(args.out).resolve()
    manual_total = len(VULNERABILITIES)
    auto_target = max(0, args.target_total - manual_total)
    selected_components = [item.strip() for item in args.components.split(",") if item.strip()]
    entries = build_auto_entries(auto_target, selected_components=selected_components or None, verbose=args.verbose)
    payload = {
        "schema_version": 1,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "source": "https://cve.circl.lu/api/search/{vendor}/{product}",
        "target_total": args.target_total,
        "manual_total": manual_total,
        "target_auto_total": auto_target,
        "actual_total": len(entries),
        "items": entries,
    }
    write_json(out_path, payload)
    print(json.dumps({"out": str(out_path), "actual_total": len(entries)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
