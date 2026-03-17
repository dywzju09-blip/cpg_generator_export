from __future__ import annotations

import json
import os
from copy import deepcopy
from typing import Dict, List, Optional

from tools.ffi_semantics.binding import bind_call_summaries


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_REGISTRY = os.path.join(CURRENT_DIR, "ffi_semantics_registry.json")


def _normalize_name(name: Optional[str]) -> str:
    text = str(name or "").strip().lower()
    if not text:
        return ""
    out = []
    for ch in text:
        if ch.isalnum():
            out.append(ch)
    return "".join(out)


def _parse_version(v: str):
    parts = []
    for token in str(v or "").split("."):
        try:
            parts.append(int(token))
        except Exception:
            parts.append(0)
    return tuple(parts)


def _cmp_version(left: str, right: str) -> int:
    l_t = _parse_version(left)
    r_t = _parse_version(right)
    width = max(len(l_t), len(r_t))
    l_t = l_t + (0,) * (width - len(l_t))
    r_t = r_t + (0,) * (width - len(r_t))
    if l_t < r_t:
        return -1
    if l_t > r_t:
        return 1
    return 0


def _version_in_range(version: str, range_expr: str) -> bool:
    if not range_expr:
        return True
    clauses = [item.strip() for item in str(range_expr).split(",") if item.strip()]
    for clause in clauses:
        if clause.startswith(">="):
            if _cmp_version(version, clause[2:]) < 0:
                return False
        elif clause.startswith(">"):
            if _cmp_version(version, clause[1:]) <= 0:
                return False
        elif clause.startswith("<="):
            if _cmp_version(version, clause[2:]) > 0:
                return False
        elif clause.startswith("<"):
            if _cmp_version(version, clause[1:]) >= 0:
                return False
        elif clause.startswith("=="):
            if _cmp_version(version, clause[2:]) != 0:
                return False
        else:
            if _cmp_version(version, clause) != 0:
                return False
    return True


def load_semantic_registry(registry_path: str = DEFAULT_REGISTRY) -> dict:
    with open(registry_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def save_semantic_registry(data: dict, registry_path: str = DEFAULT_REGISTRY) -> None:
    with open(registry_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)


def _merge_summary(base: dict, override: dict) -> dict:
    return bind_call_summaries(base or {}, override or {})


def _component_name_aliases(component: dict) -> set:
    aliases = set()
    for key in ("name", "package_name"):
        aliases.add(_normalize_name(component.get(key)))
    for key in ("aliases", "package_aliases", "crate_aliases"):
        for item in component.get(key) or []:
            aliases.add(_normalize_name(item))
    return {item for item in aliases if item}


def _collect_dep_names(deps: Optional[dict]) -> set:
    names = set()
    deps = deps or {}
    for pkg in deps.get("packages") or []:
        if not isinstance(pkg, dict):
            continue
        names.add(_normalize_name(pkg.get("name")))
    for rel in deps.get("depends") or []:
        if not isinstance(rel, dict):
            continue
        names.add(_normalize_name(rel.get("from")))
        names.add(_normalize_name(rel.get("to")))
    return {item for item in names if item}


def _collect_call_names(calls: Optional[List[dict]]) -> set:
    names = set()
    for call in calls or []:
        if isinstance(call, dict):
            names.add(str(call.get("name") or "").strip())
        elif isinstance(call, str):
            names.add(call.strip())
    return {item for item in names if item}


def _call_aliases(component: dict) -> Dict[str, str]:
    aliases = {}
    raw = component.get("call_aliases") or {}
    if not isinstance(raw, dict):
        return aliases
    for alias_name, canonical_name in raw.items():
        alias_name = str(alias_name or "").strip()
        canonical_name = str(canonical_name or "").strip()
        if not alias_name or not canonical_name:
            continue
        aliases[alias_name] = canonical_name
    return aliases


def _resolve_call_name(component: dict, call_name: str) -> str:
    aliases = _call_aliases(component)
    return aliases.get(call_name, call_name)


def _component_match_score(component: dict, dep_names: set, call_names: set) -> dict:
    aliases = _component_name_aliases(component)
    dep_hits = sorted(name for name in dep_names if name in aliases)
    resolved_calls = {_resolve_call_name(component, name) for name in call_names}
    summary_names = set((component.get("summaries") or {}).keys())
    call_hits = sorted(name for name in resolved_calls if name in summary_names)
    score = len(dep_hits) * 10 + len(call_hits) * 3
    if dep_hits and call_hits:
        score += 5
    return {"score": score, "dep_hits": dep_hits, "call_hits": call_hits}


def discover_project_components(
    deps: Optional[dict] = None,
    calls: Optional[List[dict]] = None,
    registry_path: str = DEFAULT_REGISTRY,
) -> List[dict]:
    registry = load_semantic_registry(registry_path)
    dep_names = _collect_dep_names(deps)
    call_names = _collect_call_names(calls)
    discovered = []
    for component in registry.get("components") or []:
        if not isinstance(component, dict):
            continue
        score_info = _component_match_score(component, dep_names, call_names)
        if score_info["score"] <= 0:
            continue
        discovered.append(
            {
                "name": component.get("name"),
                "version": component.get("version"),
                "version_range": component.get("version_range"),
                "score": score_info["score"],
                "dep_hits": score_info["dep_hits"],
                "call_hits": score_info["call_hits"],
            }
        )
    discovered.sort(key=lambda item: (item.get("score", 0), len(item.get("call_hits", []))), reverse=True)
    return discovered


def _component_internal_bindings(component: dict) -> List[dict]:
    bindings = []
    for item in component.get("internal_bindings") or []:
        if not isinstance(item, dict):
            continue
        entry_call = str(item.get("entry_call") or "").strip()
        bind_call = str(item.get("bind_call") or "").strip()
        if not entry_call or not bind_call:
            continue
        bindings.append(
            {
                "id": str(item.get("id") or f"{entry_call}->{bind_call}"),
                "entry_call": entry_call,
                "bind_call": bind_call,
                "param_map": {str(k): str(v) for k, v in (item.get("param_map") or {}).items()},
                "reason": item.get("reason", ""),
                "allow_create_entry": bool(item.get("allow_create_entry", False)),
            }
        )
    return bindings


def _apply_call_aliases(component: dict, summaries: Dict[str, dict]) -> Dict[str, dict]:
    expanded = dict(summaries or {})
    for alias_name, canonical_name in _call_aliases(component).items():
        if canonical_name not in expanded:
            continue
        alias_summary = deepcopy(expanded[canonical_name])
        alias_summary.setdefault("alias_of", canonical_name)
        alias_summary.setdefault("abi_name", canonical_name)
        alias_summary.setdefault("binding_sources", [])
        if "call_alias" not in alias_summary["binding_sources"]:
            alias_summary["binding_sources"].append("call_alias")
        expanded[alias_name] = alias_summary
    return expanded


def _remap_params(summary: dict, param_map: Dict[str, str], bind_call: str) -> dict:
    remapped = deepcopy(summary or {})
    params = {}
    for old_idx, param_desc in (summary.get("params") or {}).items():
        target_idx = param_map.get(str(old_idx), str(old_idx))
        desc = deepcopy(param_desc or {})
        desc.setdefault("bound_from_call", bind_call)
        params[str(target_idx)] = desc
    remapped["params"] = params
    return remapped


def _apply_internal_bindings(component: dict, summaries: Dict[str, dict]) -> Dict[str, dict]:
    expanded = dict(summaries or {})
    for binding in _component_internal_bindings(component):
        entry_call = binding["entry_call"]
        bind_call = binding["bind_call"]
        bind_summary = expanded.get(bind_call)
        if not bind_summary:
            continue
        if entry_call not in expanded and not binding.get("allow_create_entry"):
            continue
        if entry_call not in expanded and binding.get("allow_create_entry"):
            created = _remap_params(bind_summary, binding.get("param_map") or {}, bind_call)
            created["abi_name"] = bind_summary.get("abi_name", bind_call)
            created["lang"] = bind_summary.get("lang")
            created["summary_source"] = "component_internal_binding"
            created["internal_binding_from"] = bind_call
            expanded[entry_call] = created
            continue
        patch_summary = _remap_params(bind_summary, binding.get("param_map") or {}, bind_call)
        patch_summary["summary_source"] = "component_internal_binding"
        patch_summary["internal_binding_from"] = bind_call
        patch_summary["internal_binding_rule"] = binding.get("id")
        patch_summary["internal_binding_reason"] = binding.get("reason")
        expanded[entry_call] = _merge_summary(expanded.get(entry_call, {}), patch_summary)
    return expanded


def _select_components(
    registry: dict,
    component_name: Optional[str],
    component_version: Optional[str],
    deps: Optional[dict],
    calls: Optional[List[dict]],
) -> List[dict]:
    components = [item for item in (registry.get("components") or []) if isinstance(item, dict)]
    if component_name or component_version:
        return [item for item in components if _component_matches(item, component_name, component_version)]
    if deps or calls:
        dep_names = _collect_dep_names(deps)
        call_names = _collect_call_names(calls)
        scored = []
        for component in components:
            score_info = _component_match_score(component, dep_names, call_names)
            scored.append((score_info["score"], len(score_info["call_hits"]), component))
        scored.sort(reverse=True, key=lambda item: (item[0], item[1]))
        if scored and scored[0][0] > 0:
            best_score = scored[0][0]
            return [item[2] for item in scored if item[0] == best_score]
    return components


def _component_matches(component: dict, component_name: Optional[str], component_version: Optional[str]) -> bool:
    if component_name:
        target = _normalize_name(component_name)
        aliases = _component_name_aliases(component)
        if target not in aliases:
            return False
    if component_version:
        version = component.get("version")
        version_range = component.get("version_range")
        if version and _cmp_version(component_version, version) == 0:
            return True
        if version_range:
            return _version_in_range(component_version, version_range)
        return False
    return True


def _apply_trigger_overrides(summaries: Dict[str, dict], trigger_model: Optional[dict]) -> Dict[str, dict]:
    merged = deepcopy(summaries)
    overrides = (trigger_model or {}).get("ffi_summaries") or {}
    if isinstance(overrides, list):
        overrides = {item.get("name"): item for item in overrides if isinstance(item, dict) and item.get("name")}
    if not isinstance(overrides, dict):
        return merged
    for call_name, summary in overrides.items():
        if not call_name or not isinstance(summary, dict):
            continue
        merged[call_name] = _merge_summary(merged.get(call_name, {}), summary)
        merged[call_name].setdefault("abi_name", call_name)
    return merged


def load_component_summaries(
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
    deps: Optional[dict] = None,
    calls: Optional[List[dict]] = None,
    trigger_model: Optional[dict] = None,
    registry_path: str = DEFAULT_REGISTRY,
) -> Dict[str, dict]:
    registry = load_semantic_registry(registry_path)
    summaries: Dict[str, dict] = {}
    selected_components = _select_components(
        registry=registry,
        component_name=component_name,
        component_version=component_version,
        deps=deps,
        calls=calls,
    )
    for component in selected_components:
        component_summaries = dict(component.get("summaries") or {})
        component_summaries = _apply_internal_bindings(component, component_summaries)
        component_summaries = _apply_call_aliases(component, component_summaries)
        for call_name, summary in component_summaries.items():
            summaries[call_name] = _merge_summary(summaries.get(call_name, {}), summary or {})
            summaries[call_name].setdefault("abi_name", call_name)
            summaries[call_name]["component_name"] = component.get("name")
            summaries[call_name]["component_version"] = component.get("version")
            summaries[call_name]["component_version_range"] = component.get("version_range")
    return _apply_trigger_overrides(summaries, trigger_model)


def resolve_component_summary(
    call_name: str,
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
    deps: Optional[dict] = None,
    calls: Optional[List[dict]] = None,
    trigger_model: Optional[dict] = None,
    registry_path: str = DEFAULT_REGISTRY,
) -> Optional[dict]:
    if not call_name:
        return None
    summaries = load_component_summaries(
        component_name=component_name,
        component_version=component_version,
        deps=deps,
        calls=calls,
        trigger_model=trigger_model,
        registry_path=registry_path,
    )
    return summaries.get(call_name)


def summaries_for_calls(
    calls: List[dict],
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
    deps: Optional[dict] = None,
    trigger_model: Optional[dict] = None,
    registry_path: str = DEFAULT_REGISTRY,
) -> List[dict]:
    summaries = load_component_summaries(
        component_name=component_name,
        component_version=component_version,
        deps=deps,
        calls=calls,
        trigger_model=trigger_model,
        registry_path=registry_path,
    )
    out = []
    for call in calls or []:
        if not isinstance(call, dict):
            continue
        name = call.get("name")
        if not name or name not in summaries:
            continue
        out.append(
            {
                "call_id": call.get("id"),
                "call_name": name,
                "method": call.get("method"),
                "lang": call.get("lang"),
                "summary": deepcopy(summaries[name]),
            }
        )
    return out
