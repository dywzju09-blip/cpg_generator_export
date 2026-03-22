#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.supplychain.vuln_db import (
    DEFAULT_DB_CATALOG_DIR,
    DEFAULT_DB_COMPONENT_KB,
    DEFAULT_DB_COMPONENTS_DIR,
    DEFAULT_DB_EVIDENCE_DIR,
    DEFAULT_DB_INDEX_DIR,
    DEFAULT_DB_MANIFEST,
    DEFAULT_DB_RUNTIME_RULES,
    DEFAULT_DB_VULNS_DIR,
    DEFAULT_VULN_DB_ROOT,
    component_lookup_keys,
    deep_merge,
    write_json,
)
from tools.supplychain.vuln_db_seed import COMPONENTS, VULNERABILITIES


KNOWN_COMPONENTS = {item["component"] for item in COMPONENTS}


def ensure_clean_json_tree(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for path in root.rglob("*.json"):
        path.unlink()


def dedupe(items):
    out = []
    for item in items or []:
        if item not in out:
            out.append(item)
    return out


def safe_component_name(name: str) -> str:
    return str(name or "").strip().lower().replace("/", "_").replace(" ", "_")


def parse_version_range_info(range_expr: str) -> dict:
    disjunctive_groups = []
    lower_bounds = []
    upper_bounds = []
    exact_versions = []
    fixed_versions = []
    for group_text in [item.strip() for item in str(range_expr or "").split("||") if item.strip()]:
        group = {"range_expr": group_text, "lower_bounds": [], "upper_bounds": [], "exact_versions": []}
        clauses = [item.strip() for item in group_text.split(",") if item.strip()]
        for clause in clauses:
            if clause.startswith(">="):
                item = {"op": ">=", "version": clause[2:].strip()}
                group["lower_bounds"].append(item)
                lower_bounds.append(item)
            elif clause.startswith(">"):
                item = {"op": ">", "version": clause[1:].strip()}
                group["lower_bounds"].append(item)
                lower_bounds.append(item)
            elif clause.startswith("<="):
                item = {"op": "<=", "version": clause[2:].strip()}
                group["upper_bounds"].append(item)
                upper_bounds.append(item)
            elif clause.startswith("<"):
                item = {"op": "<", "version": clause[1:].strip()}
                group["upper_bounds"].append(item)
                upper_bounds.append(item)
            elif clause.startswith("=="):
                version = clause[2:].strip()
                group["exact_versions"].append(version)
                exact_versions.append(version)
            else:
                group["exact_versions"].append(clause)
                exact_versions.append(clause)
        for bound in group["upper_bounds"]:
            if bound["op"] == "<" and bound["version"]:
                fixed_versions.append(bound["version"])
        disjunctive_groups.append(group)
    return {
        "range_expr": str(range_expr or ""),
        "lower_bounds": lower_bounds,
        "upper_bounds": upper_bounds,
        "exact_versions": exact_versions,
        "fixed_versions": dedupe(fixed_versions),
        "disjunctive_groups": disjunctive_groups,
    }


def load_catalog_vulnerabilities() -> list[dict]:
    catalog_path = DEFAULT_DB_CATALOG_DIR / "auto_cves_2021_2026.json"
    if not catalog_path.exists():
        return []
    payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    items = payload.get("items") or []
    out = []
    seen = set()
    for item in items:
        key = (item.get("component"), item.get("cve"))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def merged_vulnerabilities() -> list[dict]:
    merged = []
    seen = set()
    for item in VULNERABILITIES:
        key = (item["component"], item["cve"])
        seen.add(key)
        merged.append(item)
    for item in load_catalog_vulnerabilities():
        key = (item.get("component"), item.get("cve"))
        if not item.get("component") or not item.get("cve") or key in seen:
            continue
        if item["component"] not in KNOWN_COMPONENTS:
            continue
        seen.add(key)
        merged.append(item)
    return merged


def default_input_predicate(component_entry: dict) -> dict:
    if not component_entry.get("input_class"):
        return {}
    return {
        "class": component_entry["input_class"],
        "positive_tokens": list(component_entry.get("input_tokens") or []),
        "negative_tokens": [],
        "strategy": "assume_if_not_explicit",
    }


def component_default_rule(component_entry: dict) -> dict:
    crates = dedupe(
        list(component_entry.get("package_aliases") or [])
        + list(component_entry.get("sys_crates") or [])
        + list(component_entry.get("high_level_crates") or [])
    )
    rule = {
        "match": {"crates": crates},
        "rust_sinks": [{"path": item} for item in component_entry.get("rust_entrypoints") or []],
        "native_sinks": dedupe(component_entry.get("native_symbols") or []),
        "symbols": dedupe(component_entry.get("native_symbols") or []),
        "input_predicate": default_input_predicate(component_entry),
        "env_guards": copy.deepcopy(component_entry.get("default_env_guards") or {}),
        "trigger_model": copy.deepcopy(component_entry.get("default_trigger_model") or {}),
    }
    return rule


def dependency_chain_templates(component_entry: dict) -> list[dict]:
    out = []
    sys_crates = list(component_entry.get("sys_crates") or [])
    high_level = list(component_entry.get("high_level_crates") or [])
    component_name = component_entry["component"]

    for crate in high_level:
        if sys_crates:
            out.append(
                {
                    "from": crate,
                    "to": sys_crates[0],
                    "through": [],
                    "evidence_type": "metadata",
                    "confidence": "high",
                }
            )
        else:
            out.append(
                {
                    "from": crate,
                    "to": component_name,
                    "through": [],
                    "evidence_type": "metadata",
                    "confidence": "medium",
                }
            )
    for crate in sys_crates:
        out.append(
            {
                "from": crate,
                "to": component_name,
                "through": [],
                "evidence_type": "build",
                "confidence": "high",
            }
        )
    return dedupe(out)


def build_component_record(component_entry: dict) -> dict:
    component_name = component_entry["component"]
    return {
        "component": component_name,
        "aliases": list(component_entry.get("aliases") or []),
        "package_aliases": list(component_entry.get("package_aliases") or []),
        "sys_crates": list(component_entry.get("sys_crates") or []),
        "high_level_crates": list(component_entry.get("high_level_crates") or []),
        "provider_hints": {
            "default_source": component_entry.get("default_source") or "system",
            "source_markers": ["vendored", "bundled", "pkg-config", "system", "static", "dynamic"],
        },
        "native_symbols": list(component_entry.get("native_symbols") or []),
        "rust_entrypoints": list(component_entry.get("rust_entrypoints") or []),
        "dependency_chain_templates": dependency_chain_templates(component_entry),
        "input_class": component_entry.get("input_class"),
        "input_tokens": list(component_entry.get("input_tokens") or []),
        "default_source": component_entry.get("default_source") or "system",
        "default_env_guards": copy.deepcopy(component_entry.get("default_env_guards") or {}),
        "default_trigger_model": copy.deepcopy(component_entry.get("default_trigger_model") or {}),
        "maturity": component_entry.get("maturity") or "seed",
        "notes": component_entry.get("notes") or "",
        "default_rule": component_default_rule(component_entry),
        "version_summary": {
            "affected_ranges": [],
            "fixed_versions": [],
            "known_cves": [],
        },
    }


def cve_references(cve: str, overrides: dict | None = None) -> dict:
    refs = {
        "advisory": [f"https://nvd.nist.gov/vuln/detail/{cve}", f"https://www.cve.org/CVERecord?id={cve}"],
        "patch": [],
        "poc": [],
    }
    if not overrides:
        return refs
    return deep_merge(refs, overrides)


def build_runtime_rule(component_record: dict, vuln_entry: dict) -> dict:
    version_info = parse_version_range_info(vuln_entry["version_range"])
    rule = component_default_rule(component_record)
    overrides = {
        "cve": vuln_entry["cve"],
        "package": component_record["component"],
        "version_range": vuln_entry["version_range"],
        "affected_versions": version_info,
        "description": vuln_entry["description"],
        "severity": vuln_entry.get("severity") or "high",
        "maturity": vuln_entry.get("maturity") or component_record.get("maturity") or "seed",
        "references": cve_references(vuln_entry["cve"], vuln_entry.get("references")),
        "symbols": list(vuln_entry.get("symbols") or []),
        "trigger_conditions": list(vuln_entry.get("trigger_conditions") or []),
        "source_patterns": list(vuln_entry.get("source_patterns") or []),
        "sanitizer_patterns": list(vuln_entry.get("sanitizer_patterns") or []),
        "source_status": vuln_entry.get("source_status") or component_record.get("provider_hints", {}).get("default_source") or "system",
        "component_metadata_ref": str((DEFAULT_DB_COMPONENTS_DIR / f"{safe_component_name(component_record['component'])}.json").relative_to(DEFAULT_VULN_DB_ROOT.parent)),
        "db_component": component_record["component"],
        "web_summary": vuln_entry.get("web_summary") or "",
        "db_notes": vuln_entry.get("notes") or component_record.get("notes") or "",
    }
    for key in ("published", "official_source", "source_affected_versions"):
        if vuln_entry.get(key):
            overrides[key] = copy.deepcopy(vuln_entry[key])
    if vuln_entry.get("rust_sinks"):
        overrides["rust_sinks"] = copy.deepcopy(vuln_entry["rust_sinks"])
    if vuln_entry.get("native_sinks"):
        overrides["native_sinks"] = copy.deepcopy(vuln_entry["native_sinks"])
    if vuln_entry.get("must_flow"):
        overrides["must_flow"] = copy.deepcopy(vuln_entry["must_flow"])
    if vuln_entry.get("env_guards"):
        overrides["env_guards"] = copy.deepcopy(vuln_entry["env_guards"])
    if vuln_entry.get("input_predicate"):
        overrides["input_predicate"] = copy.deepcopy(vuln_entry["input_predicate"])
    if vuln_entry.get("trigger_model"):
        overrides["trigger_model"] = copy.deepcopy(vuln_entry["trigger_model"])
    merged = deep_merge(rule, overrides)
    return merged


def build_component_knowledge(components: list[dict]) -> dict:
    knowledge = {}
    for component_record in components:
        default_rule = component_default_rule(component_record)
        entry = deep_merge(
            default_rule,
            {
                "component": component_record["component"],
                "maturity": component_record.get("maturity") or "seed",
                "notes": component_record.get("notes") or "",
            },
        )
        aliases = (
            list(component_record.get("aliases") or [])
            + list(component_record.get("package_aliases") or [])
            + list(component_record.get("sys_crates") or [])
            + list(component_record.get("high_level_crates") or [])
        )
        for key in component_lookup_keys(component_record["component"], aliases):
            knowledge[key] = copy.deepcopy(entry)
    return knowledge


def main() -> None:
    component_map = {item["component"]: build_component_record(item) for item in COMPONENTS}
    all_vulnerabilities = merged_vulnerabilities()
    if len(component_map) != 30:
        raise RuntimeError(f"expected 30 components, got {len(component_map)}")
    if len(VULNERABILITIES) != 30:
        raise RuntimeError(f"expected 30 manual vulnerabilities, got {len(VULNERABILITIES)}")
    if len(all_vulnerabilities) < len(VULNERABILITIES):
        raise RuntimeError("merged vulnerability set is smaller than manual vulnerability set")

    ensure_clean_json_tree(DEFAULT_DB_COMPONENTS_DIR)
    ensure_clean_json_tree(DEFAULT_DB_VULNS_DIR)
    ensure_clean_json_tree(DEFAULT_DB_EVIDENCE_DIR)
    ensure_clean_json_tree(DEFAULT_DB_INDEX_DIR)

    component_records = [component_map[name] for name in sorted(component_map.keys())]
    runtime_rules = []
    curated_rules = []
    alias_index = {}
    components_by_crate: dict[str, list[str]] = defaultdict(list)
    cves_by_component: dict[str, list[str]] = defaultdict(list)

    for component_record in component_records:
        comp_slug = safe_component_name(component_record["component"])
        for alias in [component_record["component"]] + list(component_record.get("aliases") or []):
            alias_index[alias] = component_record["component"]
        for crate in (
            list(component_record.get("package_aliases") or [])
            + list(component_record.get("sys_crates") or [])
            + list(component_record.get("high_level_crates") or [])
        ):
            bucket = components_by_crate[crate]
            if component_record["component"] not in bucket:
                bucket.append(component_record["component"])

    for vuln_entry in all_vulnerabilities:
        component_record = component_map[vuln_entry["component"]]
        rule = build_runtime_rule(component_record, vuln_entry)
        runtime_rules.append(rule)
        if rule.get("maturity") in {"curated", "verified"}:
            curated_rules.append(rule)

        comp_slug = safe_component_name(component_record["component"])
        vuln_dir = DEFAULT_DB_VULNS_DIR / comp_slug
        evidence_dir = DEFAULT_DB_EVIDENCE_DIR / comp_slug
        vuln_dir.mkdir(parents=True, exist_ok=True)
        evidence_dir.mkdir(parents=True, exist_ok=True)
        write_json(vuln_dir / f"{vuln_entry['cve']}.json", rule)
        write_json(
            evidence_dir / f"{vuln_entry['cve']}.json",
            {
                "component": component_record["component"],
                "cve": vuln_entry["cve"],
                "affected_versions": parse_version_range_info(vuln_entry["version_range"]),
                "severity": vuln_entry.get("severity") or "high",
                "maturity": vuln_entry.get("maturity") or "seed",
                "description": vuln_entry["description"],
                "trigger_conditions": vuln_entry.get("trigger_conditions") or [],
                "dependency_chain_templates": component_record.get("dependency_chain_templates") or [],
                "references": cve_references(vuln_entry["cve"], vuln_entry.get("references")),
                "web_summary": vuln_entry.get("web_summary") or "",
                "notes": vuln_entry.get("notes") or component_record.get("notes") or "",
                "published": vuln_entry.get("published") or "",
                "official_source": vuln_entry.get("official_source") or {},
                "source_affected_versions": vuln_entry.get("source_affected_versions") or [],
            },
        )
        cves_by_component[component_record["component"]].append(vuln_entry["cve"])
        version_info = parse_version_range_info(vuln_entry["version_range"])
        component_record["version_summary"]["known_cves"].append(
            {
                "cve": vuln_entry["cve"],
                "affected_range": version_info["range_expr"],
                "fixed_versions": version_info["fixed_versions"],
            }
        )
        if version_info["range_expr"] and version_info["range_expr"] not in component_record["version_summary"]["affected_ranges"]:
            component_record["version_summary"]["affected_ranges"].append(version_info["range_expr"])
        for fixed in version_info["fixed_versions"]:
            if fixed not in component_record["version_summary"]["fixed_versions"]:
                component_record["version_summary"]["fixed_versions"].append(fixed)

    runtime_rules.sort(key=lambda item: (item.get("package") or "", item.get("cve") or ""))
    curated_rules.sort(key=lambda item: (item.get("package") or "", item.get("cve") or ""))
    component_knowledge = build_component_knowledge(component_records)

    for component_record in component_records:
        comp_slug = safe_component_name(component_record["component"])
        component_record["version_summary"]["known_cves"].sort(key=lambda item: item["cve"])
        component_record["version_summary"]["affected_ranges"].sort()
        component_record["version_summary"]["fixed_versions"].sort()
        write_json(DEFAULT_DB_COMPONENTS_DIR / f"{comp_slug}.json", component_record)

    write_json(DEFAULT_DB_RUNTIME_RULES, runtime_rules)
    write_json(DEFAULT_DB_INDEX_DIR / "runtime_rules.curated.json", curated_rules)
    write_json(DEFAULT_DB_COMPONENT_KB, component_knowledge)
    write_json(DEFAULT_DB_INDEX_DIR / "components_by_crate.json", {k: sorted(v) for k, v in sorted(components_by_crate.items())})
    write_json(DEFAULT_DB_INDEX_DIR / "cves_by_component.json", {k: sorted(v) for k, v in sorted(cves_by_component.items())})
    write_json(DEFAULT_DB_INDEX_DIR / "component_alias_index.json", {k: v for k, v in sorted(alias_index.items())})

    write_json(
        DEFAULT_DB_MANIFEST,
        {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "database_root": str(DEFAULT_VULN_DB_ROOT),
            "component_count": len(component_records),
            "vulnerability_count": len(runtime_rules),
            "curated_vulnerability_count": len(curated_rules),
            "build_sources": [
                "tools/supplychain/vuln_db_seed.py",
                str(DEFAULT_DB_CATALOG_DIR / "auto_cves_2021_2026.json"),
            ],
            "manual_vulnerability_count": len(VULNERABILITIES),
            "catalog_vulnerability_count": max(0, len(all_vulnerabilities) - len(VULNERABILITIES)),
            "runtime_rules": str(DEFAULT_DB_RUNTIME_RULES),
            "component_knowledge": str(DEFAULT_DB_COMPONENT_KB),
        },
    )
    print(f"[+] Built vulnerability database at {DEFAULT_VULN_DB_ROOT}")
    print(f"[+] Components: {len(component_records)}")
    print(f"[+] Vulnerabilities: {len(runtime_rules)}")


if __name__ == "__main__":
    main()
