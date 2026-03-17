from __future__ import annotations

from typing import Dict, List, Optional

from tools.ffi_semantics.registry import (
    load_component_summaries,
    load_semantic_registry,
    resolve_component_summary,
    summaries_for_calls as registry_summaries_for_calls,
)


def load_ffi_summaries(
    trigger_model: Optional[dict] = None,
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
    deps: Optional[dict] = None,
    calls: Optional[List[dict]] = None,
) -> Dict[str, dict]:
    return load_component_summaries(
        component_name=component_name,
        component_version=component_version,
        deps=deps,
        calls=calls,
        trigger_model=trigger_model,
    )


def resolve_ffi_summary(
    call_name: str,
    trigger_model: Optional[dict] = None,
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
    deps: Optional[dict] = None,
    calls: Optional[List[dict]] = None,
) -> Optional[dict]:
    return resolve_component_summary(
        call_name=call_name,
        component_name=component_name,
        component_version=component_version,
        deps=deps,
        calls=calls,
        trigger_model=trigger_model,
    )


def summaries_for_calls(
    calls: List[dict],
    trigger_model: Optional[dict] = None,
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
    deps: Optional[dict] = None,
) -> List[dict]:
    return registry_summaries_for_calls(
        calls=calls,
        component_name=component_name,
        component_version=component_version,
        deps=deps,
        trigger_model=trigger_model,
    )


__all__ = [
    "load_ffi_summaries",
    "resolve_ffi_summary",
    "summaries_for_calls",
    "load_semantic_registry",
]
