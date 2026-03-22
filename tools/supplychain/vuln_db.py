from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any


CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent.parent
DEFAULT_VULN_DB_ROOT = REPO_ROOT / "Data" / "vuln_db"
DEFAULT_DB_COMPONENTS_DIR = DEFAULT_VULN_DB_ROOT / "components"
DEFAULT_DB_VULNS_DIR = DEFAULT_VULN_DB_ROOT / "vulns"
DEFAULT_DB_EVIDENCE_DIR = DEFAULT_VULN_DB_ROOT / "evidence"
DEFAULT_DB_CATALOG_DIR = DEFAULT_VULN_DB_ROOT / "catalog"
DEFAULT_DB_INDEX_DIR = DEFAULT_VULN_DB_ROOT / "indexes"
DEFAULT_DB_RUNTIME_RULES = DEFAULT_DB_INDEX_DIR / "runtime_rules.full.json"
DEFAULT_DB_COMPONENT_KB = DEFAULT_DB_INDEX_DIR / "component_knowledge.json"
DEFAULT_DB_MANIFEST = DEFAULT_DB_INDEX_DIR / "manifest.json"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def deep_merge(base: Any, extra: Any) -> Any:
    if not isinstance(base, dict):
        return copy.deepcopy(extra)
    if not isinstance(extra, dict):
        return copy.deepcopy(extra)
    out = copy.deepcopy(base)
    for key, value in extra.items():
        if key not in out:
            out[key] = copy.deepcopy(value)
            continue
        if isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = deep_merge(out[key], value)
            continue
        if isinstance(out[key], list) and isinstance(value, list):
            merged = list(out[key])
            for item in value:
                if item not in merged:
                    merged.append(copy.deepcopy(item))
            out[key] = merged
            continue
        out[key] = copy.deepcopy(value)
    return out


def component_lookup_keys(name: str, aliases: list[str] | None = None) -> list[str]:
    values = [name] + list(aliases or [])
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        candidates = [text, text.lower(), text.replace("-", "_"), text.replace("_", "-")]
        lowered = text.lower()
        if lowered.startswith("lib") and len(lowered) > 3:
            short = lowered[3:]
            candidates.extend([short, short.replace("-", "_"), short.replace("_", "-")])
        for cand in candidates:
            if cand and cand not in out:
                out.append(cand)
    return out


def default_runtime_rules_path() -> Path:
    return DEFAULT_DB_RUNTIME_RULES


def default_component_kb_path() -> Path:
    return DEFAULT_DB_COMPONENT_KB


def default_manifest_path() -> Path:
    return DEFAULT_DB_MANIFEST
