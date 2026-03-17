from __future__ import annotations

from copy import deepcopy
from typing import Dict, Optional


def _summary_family(summary: Optional[dict]) -> str:
    summary = summary or {}
    summary_source = str(summary.get("summary_source") or "").lower()
    lang = str(summary.get("lang") or "").lower()
    if "rust" in summary_source or lang == "rust":
        return "rust"
    if "c_header" in summary_source or lang == "c":
        return "c"
    return "generic"


def _merge_fields(left: Optional[dict], right: Optional[dict]) -> dict:
    merged = deepcopy(left or {})
    for field_name, field_desc in (right or {}).items():
        current = dict(merged.get(field_name) or {})
        if isinstance(field_desc, dict):
            current.update(deepcopy(field_desc))
        else:
            current["kind"] = field_desc
        merged[field_name] = current
    return merged


def _bind_param_variants(c_param: Optional[dict], rust_param: Optional[dict]) -> dict:
    c_param = deepcopy(c_param or {})
    rust_param = deepcopy(rust_param or {})
    merged = {}

    if c_param.get("role") and rust_param.get("role") and c_param.get("role") != rust_param.get("role"):
        merged["role_variants"] = {"c": c_param.get("role"), "rust": rust_param.get("role")}
    merged["role"] = rust_param.get("role") or c_param.get("role")

    native_declared_type = c_param.get("declared_type") or c_param.get("type")
    rust_declared_type = rust_param.get("declared_type") or rust_param.get("type")
    if native_declared_type:
        merged["native_declared_type"] = native_declared_type
    if rust_declared_type:
        merged["rust_declared_type"] = rust_declared_type
    merged["declared_type"] = rust_declared_type or native_declared_type

    merged["arg_shape"] = rust_param.get("arg_shape") or c_param.get("arg_shape") or "value"
    merged["abi_kind"] = rust_param.get("abi_kind") or c_param.get("abi_kind") or "value"
    merged["type"] = rust_param.get("type") or c_param.get("type") or merged.get("declared_type")

    c_pointee = c_param.get("pointee_type")
    rust_pointee = rust_param.get("pointee_type")
    merged["pointee_type"] = rust_pointee or c_pointee
    if c_pointee and rust_pointee and c_pointee != rust_pointee:
        merged["pointee_variants"] = {"c": c_pointee, "rust": rust_pointee}

    merged["fields"] = _merge_fields(c_param.get("fields"), rust_param.get("fields"))
    merged["confidence"] = rust_param.get("confidence") or c_param.get("confidence") or "generated_candidate"
    merged["binding_sources"] = sorted(
        set((c_param.get("binding_sources") or []) + (rust_param.get("binding_sources") or []) + ["c", "rust"])
    )
    return {key: value for key, value in merged.items() if value not in (None, {}, [])}


def _generic_merge_param(base: Optional[dict], override: Optional[dict]) -> dict:
    merged = deepcopy(base or {})
    for key, value in (override or {}).items():
        if key == "fields" and isinstance(value, dict):
            merged["fields"] = _merge_fields(merged.get("fields"), value)
            continue
        merged[key] = deepcopy(value)
    return merged


def bind_call_summaries(base: Optional[dict], override: Optional[dict]) -> dict:
    base = deepcopy(base or {})
    override = deepcopy(override or {})
    base_family = _summary_family(base)
    override_family = _summary_family(override)
    if {base_family, override_family} == {"c", "rust"}:
        c_summary = base if base_family == "c" else override
        rust_summary = override if override_family == "rust" else base
        merged = deepcopy(c_summary)
        merged.update(deepcopy(rust_summary))
        merged["lang"] = rust_summary.get("lang") or c_summary.get("lang")
        merged["summary_source"] = "bound_c_header_and_rust_ffi"
        merged["binding_sources"] = sorted(
            set((c_summary.get("binding_sources") or []) + (rust_summary.get("binding_sources") or []) + ["c", "rust"])
        )
        params: Dict[str, dict] = {}
        param_indexes = set((c_summary.get("params") or {}).keys()) | set((rust_summary.get("params") or {}).keys())
        for raw_idx in sorted(param_indexes, key=lambda x: int(str(x)) if str(x).isdigit() else str(x)):
            params[str(raw_idx)] = _bind_param_variants(
                (c_summary.get("params") or {}).get(str(raw_idx)),
                (rust_summary.get("params") or {}).get(str(raw_idx)),
            )
        merged["params"] = params
        return merged

    merged = deepcopy(base)
    for key, value in (override or {}).items():
        if key == "params" and isinstance(value, dict):
            params = dict(merged.get("params") or {})
            for raw_idx, param_desc in value.items():
                idx = str(raw_idx)
                params[idx] = _generic_merge_param(params.get(idx, {}), param_desc or {})
            merged["params"] = params
            continue
        merged[key] = deepcopy(value)
    return merged

