from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from tools.verification.ffi_summaries import load_ffi_summaries, summaries_for_calls
from tools.verification.field_flow import build_field_flow
from tools.verification.path_solver import PathConstraintSolver


def has_state_semantics_rules(trigger_model: Optional[dict]) -> bool:
    if not isinstance(trigger_model, dict):
        return False
    if isinstance(trigger_model.get("state_rules"), list) and trigger_model.get("state_rules"):
        return True
    if isinstance(trigger_model.get("existential_inputs"), list) and trigger_model.get("existential_inputs"):
        return True
    ffi_summaries = trigger_model.get("ffi_summaries")
    return isinstance(ffi_summaries, (dict, list)) and bool(ffi_summaries)


def _index_field_facts(field_facts: List[dict]) -> Dict[str, List[dict]]:
    index: Dict[str, List[dict]] = {}
    for fact in field_facts or []:
        field = fact.get("field")
        if not field:
            continue
        index.setdefault(field, []).append(fact)
    return index


def _pick_best_fact(facts: List[dict], preferred_state: Optional[str] = None) -> Optional[dict]:
    ranked = []
    for fact in facts or []:
        score = 0
        if preferred_state and fact.get("declared_state") == preferred_state:
            score += 4
        if fact.get("resolved_value") is not None:
            score += 2
        confidence = fact.get("confidence")
        if confidence == "high":
            score += 2
        elif confidence == "medium":
            score += 1
        ranked.append((score, fact))
    if not ranked:
        return None
    ranked.sort(key=lambda item: item[0], reverse=True)
    return ranked[0][1]


def _build_state_views(field_facts: List[dict], ffi_summary_hits: List[dict]) -> dict:
    state_views = {"pre": {}, "post": {}}
    field_index = _index_field_facts(field_facts)
    seen_fields = set(field_index.keys())
    for hit in ffi_summary_hits or []:
        summary = hit.get("summary") or {}
        for param_desc in (summary.get("params") or {}).values():
            for field_name, field_desc in (param_desc.get("fields") or {}).items():
                seen_fields.add(field_name)
                preferred = (field_desc or {}).get("state")
                selected = _pick_best_fact(field_index.get(field_name, []), preferred_state=preferred)
                if selected is None:
                    continue
                state_bucket = preferred or "pre"
                state_views.setdefault(state_bucket, {})[field_name] = selected
    for field_name in seen_fields:
        if field_name in state_views["pre"] or field_name in state_views["post"]:
            continue
        selected = _pick_best_fact(field_index.get(field_name, []))
        if selected is not None:
            state_views["pre"][field_name] = selected
    return state_views


def _coerce_solver(solver):
    if solver is not None:
        return solver
    return PathConstraintSolver(domain="octagon")


def _normalize_state_rules(trigger_model: Optional[dict]) -> List[dict]:
    model = trigger_model or {}
    rules = []
    raw_rules = model.get("state_rules") or []
    if isinstance(raw_rules, list):
        for idx, rule in enumerate(raw_rules):
            if isinstance(rule, dict):
                normalized = dict(rule)
                normalized.setdefault("id", f"state_rule_{idx}")
                rules.append(normalized)
    legacy = model.get("existential_inputs") or []
    if isinstance(legacy, list):
        for idx, item in enumerate(legacy):
            if not isinstance(item, dict):
                continue
            rules.append(
                {
                    "id": item.get("name") or f"existential_input_{idx}",
                    "lhs": {
                        "field": item.get("field"),
                        "state": item.get("field_state", "post"),
                        "source": "observed_or_symbolic" if item.get("use_observed_value", True) else "symbolic",
                        "symbolic_var": item.get("symbolic_var") or item.get("name") or f"existential_input_{idx}",
                    },
                    "op": item.get("target_operator", ">"),
                    "rhs": {
                        "field": item.get("greater_than_field") or item.get("less_than_field"),
                        "state": item.get("target_state", "pre"),
                    },
                    "lhs_constraints": (
                        [
                            {
                                "op": item.get("min_operator", ">="),
                                "value": item.get("min_value"),
                            }
                        ]
                        if item.get("min_value") is not None
                        else []
                    ),
                    "legacy_rule": "existential_inputs",
                }
            )
    return rules


def _normalize_operand(operand, default_state: str, default_source: str = "observed") -> dict:
    if isinstance(operand, dict):
        normalized = dict(operand)
    else:
        normalized = {"field": operand}
    if normalized.get("value") is not None:
        normalized["kind"] = "value"
        return normalized
    normalized.setdefault("kind", "field")
    normalized.setdefault("state", default_state)
    normalized.setdefault("source", default_source)
    if normalized.get("kind") != "value":
        normalized.setdefault("symbolic_var", normalized.get("field"))
    return normalized


def _resolve_operand(
    operand: dict,
    state_views: dict,
    fallback_symbolic: Optional[str] = None,
    allow_symbolic_default: bool = False,
) -> Tuple[Optional[dict], List[dict], List[dict], List[str]]:
    constraints = []
    assumptions = []
    notes = []
    operand = dict(operand or {})
    if operand.get("kind") == "value" or operand.get("value") is not None:
        try:
            value = int(operand.get("value"))
        except Exception:
            return None, constraints, assumptions, notes
        return (
            {
                "kind": "value",
                "value": value,
                "symbolic_var": None,
                "observed": None,
                "used_assumption": False,
            },
            constraints,
            assumptions,
            notes,
        )

    field = operand.get("field")
    state = operand.get("state", "pre")
    source = operand.get("source", "observed")
    symbolic_var = operand.get("symbolic_var") or fallback_symbolic or field
    observed = state_views.get(state, {}).get(field)
    used_assumption = False

    if observed and observed.get("resolved_value") is not None and source in {"observed", "observed_or_symbolic", "auto"}:
        constraints.append(
            {
                "variable": symbolic_var,
                "operator": "==",
                "value": int(observed["resolved_value"]),
                "source": "state_semantics_observed_field",
                "source_id": observed.get("source_id"),
            }
        )
        notes.append(f"observed {state}.{field}={observed['resolved_value']}")
    elif source in {"symbolic", "observed_or_symbolic"} or allow_symbolic_default:
        used_assumption = True
        assumptions.append(
            {
                "kind": "symbolic_field_value",
                "field": field,
                "field_state": state,
                "symbolic_var": symbolic_var,
            }
        )
    else:
        return None, constraints, assumptions, notes

    return (
        {
            "kind": "field",
            "field": field,
            "state": state,
            "symbolic_var": symbolic_var,
            "observed": observed,
            "used_assumption": used_assumption,
        },
        constraints,
        assumptions,
        notes,
    )


def _constraints_from_bound(target_var: str, bound: dict, state_views: dict) -> Tuple[Optional[dict], List[dict], List[dict], List[str]]:
    resolved, constraints, assumptions, notes = _resolve_operand(bound, state_views, allow_symbolic_default=False)
    if resolved is None:
        return None, constraints, assumptions, notes
    if resolved.get("kind") == "value":
        constraints.append(
            {
                "variable": target_var,
                "operator": bound.get("op", ">="),
                "value": int(resolved["value"]),
                "source": "state_semantics_bound_value",
            }
        )
        notes.append(f"{target_var} {bound.get('op', '>=')} {resolved['value']}")
    else:
        observed = resolved.get("observed")
        if observed and observed.get("resolved_value") is not None:
            constraints.append(
                {
                    "variable": target_var,
                    "operator": bound.get("op", ">="),
                    "value": int(observed["resolved_value"]),
                    "source": "state_semantics_bound_field",
                    "source_id": observed.get("source_id"),
                }
            )
            notes.append(f"{target_var} {bound.get('op', '>=')} {resolved['state']}.{resolved['field']}({observed['resolved_value']})")
        else:
            return None, constraints, assumptions, notes
    return resolved, constraints, assumptions, notes


def _evaluate_state_rule(rule: dict, state_views: dict, base_constraints: List[dict], solver) -> dict:
    lhs_spec = _normalize_operand(
        rule.get("lhs") or {"field": rule.get("field"), "state": rule.get("field_state", "post"), "source": "observed_or_symbolic"},
        default_state="post",
        default_source="observed_or_symbolic",
    )
    rhs_input = rule.get("rhs")
    if rhs_input is None:
        rhs_input = {}
        if rule.get("target_field"):
            rhs_input["field"] = rule.get("target_field")
            rhs_input["state"] = rule.get("target_state", "pre")
        if rule.get("value") is not None:
            rhs_input["value"] = rule.get("value")
    rhs_spec = _normalize_operand(rhs_input, default_state="pre", default_source="observed")
    op = rule.get("op") or rule.get("target_operator", ">")

    lhs, lhs_constraints, lhs_assumptions, lhs_notes = _resolve_operand(
        lhs_spec,
        state_views,
        fallback_symbolic=lhs_spec.get("symbolic_var"),
        allow_symbolic_default=True,
    )
    if lhs is None:
        return {
            "status": "unknown",
            "reason": f"unresolved_lhs:{lhs_spec.get('field')}",
            "rule_id": rule.get("id"),
            "lhs": lhs_spec,
            "rhs": rhs_spec,
            "constraints_used": [],
            "boundary_assumptions": lhs_assumptions,
            "notes": lhs_notes,
        }

    rhs, rhs_constraints, rhs_assumptions, rhs_notes = _resolve_operand(rhs_spec, state_views, allow_symbolic_default=False)
    if rhs is None:
        return {
            "status": "unknown",
            "reason": f"unresolved_rhs:{rhs_spec.get('field') or rhs_spec.get('value')}",
            "rule_id": rule.get("id"),
            "lhs": lhs_spec,
            "rhs": rhs_spec,
            "constraints_used": lhs_constraints,
            "boundary_assumptions": lhs_assumptions + rhs_assumptions,
            "notes": lhs_notes + rhs_notes,
        }

    rule_constraints = list(base_constraints or [])
    generated_constraints = list(lhs_constraints + rhs_constraints)
    assumptions = list(lhs_assumptions + rhs_assumptions)
    notes = list(lhs_notes + rhs_notes)

    lhs_var = lhs.get("symbolic_var")
    if rhs.get("kind") == "value":
        generated_constraints.append(
            {
                "variable": lhs_var,
                "operator": op,
                "value": int(rhs["value"]),
                "source": "state_semantics_rhs_value",
            }
        )
        notes.append(f"{lhs_var} {op} {rhs['value']}")
    else:
        observed_rhs = rhs.get("observed")
        if not observed_rhs or observed_rhs.get("resolved_value") is None:
            return {
                "status": "unknown",
                "reason": f"unresolved_rhs_value:{rhs.get('field')}",
                "rule_id": rule.get("id"),
                "lhs": lhs_spec,
                "rhs": rhs_spec,
                "constraints_used": generated_constraints,
                "boundary_assumptions": assumptions,
                "notes": notes,
            }
        generated_constraints.append(
            {
                "variable": lhs_var,
                "operator": op,
                "value": int(observed_rhs["resolved_value"]),
                "source": "state_semantics_rhs_field",
                "source_id": observed_rhs.get("source_id"),
            }
        )
        notes.append(f"{lhs_var} {op} {rhs['state']}.{rhs['field']}({observed_rhs['resolved_value']})")

    for bound in rule.get("lhs_constraints") or []:
        if not isinstance(bound, dict):
            continue
        resolved_bound, bound_constraints, bound_assumptions, bound_notes = _constraints_from_bound(lhs_var, bound, state_views)
        generated_constraints.extend(bound_constraints)
        assumptions.extend(bound_assumptions)
        notes.extend(bound_notes)
        if resolved_bound is None:
            return {
                "status": "unknown",
                "reason": f"unresolved_lhs_constraint:{bound}",
                "rule_id": rule.get("id"),
                "lhs": lhs_spec,
                "rhs": rhs_spec,
                "constraints_used": generated_constraints,
                "boundary_assumptions": assumptions,
                "notes": notes,
            }

    rule_constraints.extend(generated_constraints)
    solver_result = solver.solve_with_explain(rule_constraints)
    notes.append(f"solver={solver_result.get('backend')}")
    return {
        "status": "sat" if solver_result.get("feasible", True) else "unsat",
        "reason": solver_result.get("bottom_reason"),
        "rule_id": rule.get("id"),
        "lhs": lhs_spec,
        "rhs": rhs_spec,
        "resolved_lhs": lhs,
        "resolved_rhs": rhs,
        "used_assumption": bool(lhs.get("used_assumption")),
        "constraints_used": generated_constraints,
        "boundary_assumptions": assumptions,
        "notes": notes,
    }


def evaluate_state_semantics(
    trigger_model: Optional[dict],
    chain_nodes: List[dict],
    evidence_calls: List[dict],
    path_bundle: Optional[dict],
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
    deps: Optional[dict] = None,
    solver=None,
) -> dict:
    path_bundle = dict(path_bundle or {})
    ffi_summaries = load_ffi_summaries(
        trigger_model=trigger_model,
        component_name=component_name,
        component_version=component_version,
        deps=deps,
        calls=evidence_calls,
    )
    ffi_hits = summaries_for_calls(
        evidence_calls or [],
        trigger_model=trigger_model,
        component_name=component_name,
        component_version=component_version,
        deps=deps,
    )
    field_flow = build_field_flow(
        chain_nodes=chain_nodes or [],
        evidence_calls=evidence_calls or [],
        ffi_summaries=ffi_summaries,
        value_env=dict(path_bundle.get("value_env") or {}),
        const_map=dict(path_bundle.get("const_map") or path_bundle.get("constants") or {}),
    )
    state_views = _build_state_views(field_flow.get("field_facts") or [], ffi_hits)

    result = {
        "status": "not_applicable",
        "component_binding": {
            "requested_component": component_name,
            "requested_version": component_version,
            "resolved_components": sorted(
                {
                    f"{(hit.get('summary') or {}).get('component_name')}@{(hit.get('summary') or {}).get('component_version')}"
                    for hit in ffi_hits
                    if (hit.get("summary") or {}).get("component_name")
                }
            ),
        },
        "ffi_summary_hits": ffi_hits,
        "field_flow": field_flow,
        "state_views": state_views,
        "rules": [],
        "constraints_used": [],
        "boundary_assumptions": [],
    }

    state_rules = _normalize_state_rules(trigger_model)
    if not state_rules:
        return result

    local_solver = _coerce_solver(solver)
    base_constraints = list(path_bundle.get("combined_constraints") or [])
    overall_status = "sat"
    for rule in state_rules:
        rule_result = _evaluate_state_rule(
            rule=rule,
            state_views=state_views,
            base_constraints=base_constraints,
            solver=local_solver,
        )
        result["rules"].append(rule_result)
        result["constraints_used"].extend(rule_result.get("constraints_used") or [])
        result["boundary_assumptions"].extend(rule_result.get("boundary_assumptions") or [])
        status = rule_result.get("status")
        if status == "unsat":
            overall_status = "unsat"
        elif status == "unknown" and overall_status != "unsat":
            overall_status = "unknown"
    result["status"] = overall_status
    return result
