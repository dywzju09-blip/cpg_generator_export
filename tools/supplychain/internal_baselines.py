from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


OURS_FULL = "Ours-Full"
BL_DEP = "BL-Dep"
BL_DEP_REACH = "BL-Dep+Reach"
BL_NO_NATIVE_INTERNAL = "BL-NoNativeInternal"
INTERNAL_BASELINE_METHODS = (BL_DEP, BL_DEP_REACH, BL_NO_NATIVE_INTERNAL)
ALL_INTERNAL_METHODS = (OURS_FULL,) + INTERNAL_BASELINE_METHODS


def parse_version(version: Any) -> tuple[int, ...]:
    parts: list[int] = []
    for token in str(version or "").split("."):
        try:
            parts.append(int(token))
        except Exception:
            parts.append(0)
    return tuple(parts)


def cmp_version(left: Any, right: Any) -> int:
    left_parts = parse_version(left)
    right_parts = parse_version(right)
    width = max(len(left_parts), len(right_parts))
    left_parts = left_parts + (0,) * (width - len(left_parts))
    right_parts = right_parts + (0,) * (width - len(right_parts))
    if left_parts < right_parts:
        return -1
    if left_parts > right_parts:
        return 1
    return 0


def version_in_range(version: Any, range_expr: Any) -> bool:
    if not range_expr:
        return True
    groups = [group.strip() for group in str(range_expr).split("||") if group.strip()]
    if not groups:
        groups = [str(range_expr)]
    for group in groups:
        matched = True
        clauses = [clause.strip() for clause in group.split(",") if clause.strip()]
        for clause in clauses:
            if clause.startswith(">="):
                if cmp_version(version, clause[2:]) < 0:
                    matched = False
                    break
            elif clause.startswith(">"):
                if cmp_version(version, clause[1:]) <= 0:
                    matched = False
                    break
            elif clause.startswith("<="):
                if cmp_version(version, clause[2:]) > 0:
                    matched = False
                    break
            elif clause.startswith("<"):
                if cmp_version(version, clause[1:]) >= 0:
                    matched = False
                    break
            elif clause.startswith("=="):
                if cmp_version(version, clause[2:]) != 0:
                    matched = False
                    break
            else:
                if cmp_version(version, clause) != 0:
                    matched = False
                    break
        if matched:
            return True
    return False


def has_cross_language_native_evidence(
    *,
    source_status: Any,
    call_reachability_source: Any,
    has_method: bool,
    strict_callsite_edges: Any,
    native_analysis_coverage: Any,
    native_dependency_imports: Any,
    strict_dependency_resolution: Any,
) -> bool:
    status = str(source_status or "").strip()
    if status not in {"stub", "binary-only", "system"}:
        return True
    if has_method and call_reachability_source in {"c_method", "c_call", "symbol_usage"}:
        return True
    if int(strict_callsite_edges or 0) > 0:
        return True
    if str(native_analysis_coverage or "") in {"symbol_level", "callsite_level"}:
        return True
    if (strict_dependency_resolution or {}).get("dependencies") and native_dependency_imports:
        return True
    return False


def _normalize_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    lowered = str(value or "").strip().lower()
    if lowered in {"yes", "true", "1"}:
        return True
    if lowered in {"no", "false", "0"}:
        return False
    return None


def _truthy_text(value: Any) -> bool:
    return bool(str(value or "").strip())


def _yes_no_unknown(value: bool | None) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def _has_wrapper_sink_evidence(vuln: Mapping[str, Any]) -> bool:
    package_name = str(vuln.get("package") or "").strip().lower().replace("_", "-")
    source = str(vuln.get("call_reachability_source") or "").strip()
    if (
        package_name == "libjpeg-turbo"
        and source == "rust_native_gateway_package"
        and not _has_required_trigger_hit(vuln, "jpeg_header_any")
    ):
        return False
    downgrade_reason = str(vuln.get("downgrade_reason") or "").strip()
    if "preserved_by_wrapper_sink_evidence" in downgrade_reason:
        return True
    if "direct_native_gateway_bridge" in downgrade_reason:
        return True
    for note in vuln.get("evidence_notes") or []:
        note_text = str(note or "").strip().lower()
        if "explicit native symbol reference in rust wrapper" in note_text:
            return True
        if "direct native gateway calls recovered" in note_text:
            return True
    return False


def _required_trigger_hits(vuln: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    conditions = vuln.get("conditions")
    if not isinstance(conditions, Mapping):
        return []
    trigger_model_hits = conditions.get("trigger_model_hits")
    if not isinstance(trigger_model_hits, Mapping):
        return []
    hits = trigger_model_hits.get("required_hits")
    if not isinstance(hits, list):
        return []
    return [item for item in hits if isinstance(item, Mapping)]


def _has_required_trigger_hit(vuln: Mapping[str, Any], hit_id: str) -> bool:
    wanted = str(hit_id or "").strip()
    if not wanted:
        return False
    return any(str(item.get("id") or "").strip() == wanted for item in _required_trigger_hits(vuln))


@dataclass(frozen=True)
class ProjectionSupport:
    dependency_hit: str
    version_hit: str
    rust_reachable: str
    cross_language_linked: str
    has_native_instance: bool
    reachable: bool | None
    triggerable: str
    manual_trigger_status: str
    result_kind: str
    source_status: str
    resolved_version: str
    version_range: str
    call_reachability_source: str


def support_from_vulnerability(vuln: Mapping[str, Any]) -> ProjectionSupport:
    dependency_chain = list(vuln.get("dependency_chain") or [])
    native_component_instances = list(vuln.get("native_component_instances") or [])
    dependency_hit = "yes" if (dependency_chain or native_component_instances) else "no"

    resolved_version = str(vuln.get("resolved_version") or "").strip()
    version_range = str(vuln.get("version_range") or "").strip()
    if resolved_version:
        version_hit = "yes" if version_in_range(resolved_version, version_range) else "no"
    else:
        version_hit = "unknown"

    reachable = _normalize_bool(vuln.get("reachable"))
    call_reachability_source = str(vuln.get("call_reachability_source") or "").strip()
    if reachable is True or call_reachability_source:
        rust_reachable = "yes"
    elif reachable is False:
        rust_reachable = "no"
    else:
        rust_reachable = "unknown"

    manual_trigger_status = str(vuln.get("manual_trigger_status") or "").strip()
    source_status = str(vuln.get("source_status") or "").strip()
    cross_language_linked = has_cross_language_native_evidence(
        source_status=source_status,
        call_reachability_source=call_reachability_source,
        has_method=False,
        strict_callsite_edges=vuln.get("strict_callsite_edges"),
        native_analysis_coverage=vuln.get("native_analysis_coverage"),
        native_dependency_imports=vuln.get("native_dependency_imports") or [],
        strict_dependency_resolution=vuln.get("strict_dependency_resolution") or {},
    )
    if manual_trigger_status in {"observable_triggered", "path_triggered"}:
        cross_language_linked = True
    elif _has_wrapper_sink_evidence(vuln):
        cross_language_linked = True

    return ProjectionSupport(
        dependency_hit=dependency_hit,
        version_hit=version_hit,
        rust_reachable=rust_reachable,
        cross_language_linked=_yes_no_unknown(cross_language_linked),
        has_native_instance=bool(native_component_instances),
        reachable=reachable,
        triggerable=str(vuln.get("triggerable") or "").strip().lower(),
        manual_trigger_status=manual_trigger_status,
        result_kind=str(vuln.get("result_kind") or "").strip(),
        source_status=source_status,
        resolved_version=resolved_version,
        version_range=version_range,
        call_reachability_source=call_reachability_source,
    )


def support_from_results_row(row: Mapping[str, Any]) -> ProjectionSupport:
    predicted_label = str(row.get("predicted_label") or "").strip()
    reachable: bool | None = None
    if predicted_label == "unreachable":
        reachable = False
    elif predicted_label in {"triggerable", "reachable_but_not_triggerable"}:
        reachable = True
    return ProjectionSupport(
        dependency_hit=str(row.get("dependency_hit") or "unknown").strip() or "unknown",
        version_hit=str(row.get("version_hit") or "unknown").strip() or "unknown",
        rust_reachable=str(row.get("rust_reachable") or "unknown").strip() or "unknown",
        cross_language_linked=str(row.get("cross_language_linked") or "unknown").strip() or "unknown",
        has_native_instance=False,
        reachable=reachable,
        triggerable="",
        manual_trigger_status="",
        result_kind="",
        source_status="",
        resolved_version="",
        version_range="",
        call_reachability_source="",
    )


def project_ours_full_from_support(
    support: ProjectionSupport,
    *,
    gold_label: str = "",
    run_status: str = "",
    degraded: str = "no",
    error_type: str = "",
) -> dict[str, str]:
    predicted_label = ""
    risk_level = ""
    native_internal_satisfied = "unknown"

    if support.manual_trigger_status in {"observable_triggered", "path_triggered"}:
        predicted_label = "triggerable"
        risk_level = "high"
        native_internal_satisfied = "yes"
        if not run_status:
            run_status = support.manual_trigger_status
    elif support.triggerable == "confirmed":
        predicted_label = "triggerable"
        risk_level = "high"
        native_internal_satisfied = "yes"
        if not run_status:
            run_status = "triggerable_confirmed"
    elif support.triggerable == "possible":
        predicted_label = "reachable_but_not_triggerable"
        risk_level = "medium"
        native_internal_satisfied = "partial"
        if not run_status:
            run_status = "triggerable_possible"
    elif support.reachable is True or support.result_kind == "Reachable" or support.triggerable == "false_positive":
        predicted_label = "reachable_but_not_triggerable"
        risk_level = "medium"
        native_internal_satisfied = "no"
        if not run_status:
            run_status = "reachable_only"
    elif support.triggerable == "unreachable" or support.reachable is False:
        predicted_label = "unreachable"
        risk_level = "low"
        native_internal_satisfied = "no"
        if not run_status:
            run_status = "not_reachable"

    correct = ""
    if gold_label and predicted_label:
        correct = "yes" if gold_label == predicted_label else "no"

    return {
        "gold_label": gold_label,
        "predicted_label": predicted_label,
        "correct": correct,
        "risk_level": risk_level,
        "dependency_hit": support.dependency_hit,
        "version_hit": support.version_hit,
        "rust_reachable": support.rust_reachable,
        "cross_language_linked": support.cross_language_linked,
        "native_internal_satisfied": native_internal_satisfied,
        "degraded": degraded,
        "run_status": run_status,
        "error_type": error_type,
    }


def project_ours_accuracy_first_from_support(
    support: ProjectionSupport,
    *,
    gold_label: str = "",
    run_status: str = "",
    degraded: str = "no",
    error_type: str = "",
) -> dict[str, str]:
    predicted_label = ""
    risk_level = ""
    native_internal_satisfied = "unknown"
    if support.manual_trigger_status in {"observable_triggered", "path_triggered"}:
        predicted_label = "triggerable"
        risk_level = "high"
        native_internal_satisfied = "yes"
        if not run_status:
            run_status = support.manual_trigger_status
    elif support.triggerable == "confirmed":
        predicted_label = "triggerable"
        risk_level = "high"
        native_internal_satisfied = "yes"
        if not run_status:
            run_status = "triggerable_confirmed"
    elif support.triggerable == "possible":
        predicted_label = "reachable_but_not_triggerable"
        risk_level = "medium"
        native_internal_satisfied = "partial"
        if not run_status:
            run_status = "triggerable_possible"
    elif support.reachable is True or support.result_kind == "Reachable" or support.triggerable == "false_positive":
        predicted_label = "reachable_but_not_triggerable"
        risk_level = "medium"
        native_internal_satisfied = "no"
        if not run_status:
            run_status = "reachable_only"
    elif support.triggerable == "unreachable" or support.reachable is False:
        predicted_label = "unreachable"
        risk_level = "low"
        native_internal_satisfied = "no"
        if not run_status:
            run_status = "not_reachable"

    correct = ""
    if gold_label and predicted_label:
        correct = "yes" if gold_label == predicted_label else "no"

    return {
        "gold_label": gold_label,
        "predicted_label": predicted_label,
        "correct": correct,
        "risk_level": risk_level,
        "dependency_hit": support.dependency_hit,
        "version_hit": support.version_hit,
        "rust_reachable": support.rust_reachable,
        "cross_language_linked": support.cross_language_linked,
        "native_internal_satisfied": native_internal_satisfied,
        "degraded": degraded,
        "run_status": run_status,
        "error_type": error_type,
    }


def project_ours_full_from_results_row(
    row: Mapping[str, Any],
    *,
    gold_label: str = "",
) -> dict[str, str]:
    predicted_label = str(row.get("predicted_label") or "").strip()
    risk_level = str(row.get("risk_level") or "").strip()
    correct = str(row.get("correct") or "").strip()
    if gold_label and predicted_label:
        correct = "yes" if gold_label == predicted_label else "no"
    return {
        "gold_label": gold_label or str(row.get("gold_label") or "").strip(),
        "predicted_label": predicted_label,
        "correct": correct,
        "risk_level": risk_level,
        "dependency_hit": str(row.get("dependency_hit") or "unknown").strip() or "unknown",
        "version_hit": str(row.get("version_hit") or "unknown").strip() or "unknown",
        "rust_reachable": str(row.get("rust_reachable") or "unknown").strip() or "unknown",
        "cross_language_linked": str(row.get("cross_language_linked") or "unknown").strip() or "unknown",
        "native_internal_satisfied": str(row.get("native_internal_satisfied") or "unknown").strip() or "unknown",
        "degraded": str(row.get("degraded") or "no").strip() or "no",
        "run_status": str(row.get("run_status") or "").strip(),
        "error_type": str(row.get("error_type") or "").strip(),
    }


def project_internal_baseline(
    method: str,
    support: ProjectionSupport,
    *,
    gold_label: str = "",
) -> dict[str, str]:
    dep_ok = support.dependency_hit == "yes"
    version_ok = support.version_hit == "yes"
    rust_ok = support.rust_reachable == "yes"
    cross_ok = support.cross_language_linked == "yes"
    native_ok = support.has_native_instance

    predicted_label = "unreachable"
    native_internal_satisfied = "unknown"
    if method == BL_DEP:
        if dep_ok and version_ok:
            predicted_label = "reachable_but_not_triggerable"
        native_internal_satisfied = "no"
    elif method == BL_DEP_REACH:
        if dep_ok and version_ok and rust_ok:
            predicted_label = "reachable_but_not_triggerable"
        native_internal_satisfied = "no"
    elif method == BL_NO_NATIVE_INTERNAL:
        if dep_ok and version_ok and rust_ok and (native_ok or cross_ok):
            predicted_label = "triggerable"
        elif dep_ok and version_ok and rust_ok:
            predicted_label = "reachable_but_not_triggerable"
        native_internal_satisfied = "unknown"
    else:
        raise ValueError(f"unsupported internal baseline method: {method}")

    risk_level = {
        "triggerable": "high",
        "reachable_but_not_triggerable": "medium",
        "unreachable": "low",
    }[predicted_label]
    correct = ""
    if gold_label:
        correct = "yes" if gold_label == predicted_label else "no"
    return {
        "gold_label": gold_label,
        "predicted_label": predicted_label,
        "correct": correct,
        "risk_level": risk_level,
        "dependency_hit": support.dependency_hit,
        "version_hit": support.version_hit,
        "rust_reachable": support.rust_reachable,
        "cross_language_linked": support.cross_language_linked,
        "native_internal_satisfied": native_internal_satisfied,
        "degraded": "no",
        "run_status": "projected",
        "error_type": "",
    }


def has_projection_support(support: ProjectionSupport | None) -> bool:
    if support is None:
        return False
    return any(
        field == "yes"
        for field in (
            support.dependency_hit,
            support.version_hit,
            support.rust_reachable,
            support.cross_language_linked,
        )
    ) or _truthy_text(support.triggerable)
