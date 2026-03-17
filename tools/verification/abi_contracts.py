"""CLAMS-lite ABI contract extraction for cross-language parameter semantics.

Conservative policy:
- Return `unsat` only when contradiction is provable.
- Return `unknown` on missing bindings / partial evidence.
"""

from __future__ import annotations

import math
import re
from typing import Dict, Iterable, List, Optional, Tuple

_NUM_TOKEN_RE = re.compile(r"^-?(?:0x[0-9A-Fa-f]+|\d+)$")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_UPPER_TOKEN_RE = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")
_NULL_LITERALS = {"0", "NULL", "nullptr"}


def _coerce_int(token) -> Optional[int]:
    if token is None:
        return None
    text = str(token).strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered == "true":
        return 1
    if lowered == "false":
        return 0
    if not _NUM_TOKEN_RE.match(text):
        return None
    base = 16 if text.lower().startswith("0x") or text.lower().startswith("-0x") else 10
    try:
        return int(text, base)
    except Exception:
        return None


def _split_args(arg_str: str) -> List[str]:
    args: List[str] = []
    buf: List[str] = []
    depth = 0
    for ch in arg_str:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            tok = "".join(buf).strip()
            if tok:
                args.append(tok)
            buf = []
            continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        args.append(tail)
    return args


def _extract_call_args(code: str) -> List[str]:
    if not isinstance(code, str):
        return []
    lpos = code.find("(")
    rpos = code.rfind(")")
    if lpos == -1 or rpos == -1 or rpos <= lpos:
        return []
    return _split_args(code[lpos + 1 : rpos])


def _iter_calls(calls: Iterable[dict], call_name: str) -> List[dict]:
    out: List[dict] = []
    for call in calls or []:
        if not isinstance(call, dict):
            continue
        if call.get("name") == call_name:
            out.append(call)
    out.sort(key=lambda c: (str(c.get("method") or ""), int(c.get("id") or 10**18)))
    return out


def _normalize_operator(op: str) -> Optional[str]:
    text = str(op or "").strip()
    if text == "=":
        text = "=="
    if text in {"<", "<=", ">", ">=", "==", "!="}:
        return text
    return None


def _dedupe_constraints(constraints: List[dict]) -> List[dict]:
    out: List[dict] = []
    seen = set()
    for c in constraints:
        key = (
            c.get("variable"),
            c.get("operator"),
            c.get("value"),
            c.get("source"),
            c.get("evidence_ref"),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def _interval_feasibility(constraints: List[dict]) -> dict:
    bounds: Dict[str, dict] = {}
    neq: Dict[str, List[dict]] = {}

    def ensure(var: str) -> dict:
        if var not in bounds:
            bounds[var] = {
                "lo": -math.inf,
                "hi": math.inf,
                "lo_src": None,
                "hi_src": None,
            }
        return bounds[var]

    for cons in constraints:
        var = cons.get("variable")
        op = _normalize_operator(cons.get("operator"))
        val = _coerce_int(cons.get("value"))
        if not isinstance(var, str) or not var or op is None or val is None:
            continue

        b = ensure(var)
        if op == "==":
            if val > b["lo"]:
                b["lo"] = val
                b["lo_src"] = cons
            if val < b["hi"]:
                b["hi"] = val
                b["hi_src"] = cons
        elif op == ">":
            cand = val + 1
            if cand > b["lo"]:
                b["lo"] = cand
                b["lo_src"] = cons
        elif op == ">=":
            if val > b["lo"]:
                b["lo"] = val
                b["lo_src"] = cons
        elif op == "<":
            cand = val - 1
            if cand < b["hi"]:
                b["hi"] = cand
                b["hi_src"] = cons
        elif op == "<=":
            if val < b["hi"]:
                b["hi"] = val
                b["hi_src"] = cons
        elif op == "!=":
            neq.setdefault(var, []).append(cons)

        if b["lo"] > b["hi"]:
            return {
                "feasible": False,
                "ranges": {},
                "bottom_reason": {
                    "variable": var,
                    "lower_bound": b["lo_src"] or cons,
                    "upper_bound": b["hi_src"] or cons,
                },
            }

    for var, neq_list in neq.items():
        b = ensure(var)
        if b["lo"] == b["hi"]:
            point = int(b["lo"])
            for cons in neq_list:
                if _coerce_int(cons.get("value")) == point:
                    return {
                        "feasible": False,
                        "ranges": {},
                        "bottom_reason": {
                            "variable": var,
                            "point_constraint": b["lo_src"] or b["hi_src"],
                            "not_equal_constraint": cons,
                        },
                    }

    ranges = {}
    for var, b in bounds.items():
        lo = None if b["lo"] == -math.inf else int(b["lo"])
        hi = None if b["hi"] == math.inf else int(b["hi"])
        ranges[var] = [lo, hi]
    return {"feasible": True, "ranges": ranges, "bottom_reason": None}


def _resolve_arg_binding(call: dict, arg_index: int, method_signatures: Dict[str, List[str]]) -> Tuple[Optional[dict], Optional[dict]]:
    if arg_index <= 0:
        return None, {
            "kind": "invalid_arg_index",
            "call": call.get("name"),
            "call_id": call.get("id"),
            "arg_index": arg_index,
        }

    args = []
    if isinstance(call.get("args"), list):
        args = [str(v) for v in call.get("args")]
    if not args:
        args = _extract_call_args(call.get("code") or "")

    if arg_index <= len(args):
        expr = (args[arg_index - 1] or "").strip()
        return {
            "call": call.get("name"),
            "call_id": call.get("id"),
            "arg_index": arg_index,
            "arg_expr": expr,
            "bound_var": expr if _IDENT_RE.match(expr or "") else None,
            "binding_confidence": "high",
        }, None

    call_name = call.get("name")
    params = method_signatures.get(call_name) or []
    if arg_index <= len(params):
        expr = params[arg_index - 1]
        return {
            "call": call_name,
            "call_id": call.get("id"),
            "arg_index": arg_index,
            "arg_expr": expr,
            "bound_var": expr,
            "binding_confidence": "medium",
        }, {
            "kind": "missing_sink_args_fallback_signature",
            "call": call_name,
            "call_id": call.get("id"),
            "arg_index": arg_index,
            "detail": "arg text absent, use method_signatures index mapping",
        }

    return {
        "call": call_name,
        "call_id": call.get("id"),
        "arg_index": arg_index,
        "arg_expr": "",
        "bound_var": None,
        "binding_confidence": "low",
    }, {
        "kind": "arg_binding_failed",
        "call": call_name,
        "call_id": call.get("id"),
        "arg_index": arg_index,
        "detail": "missing both call args and signature fallback",
    }


def _expr_is_null(expr: str) -> bool:
    return str(expr or "").strip() in _NULL_LITERALS


def _tokens_from_expr(expr: str, const_map: Dict[str, int]) -> List[str]:
    text = str(expr or "").strip()
    if not text:
        return []
    tokens = list(dict.fromkeys(_UPPER_TOKEN_RE.findall(text)))
    number = _coerce_int(text)
    if number is not None:
        for name, value in (const_map or {}).items():
            if not isinstance(name, str) or not isinstance(value, int):
                continue
            if value <= 0:
                continue
            if (number & value) == value:
                if name not in tokens:
                    tokens.append(name)
    return tokens


def _new_result() -> dict:
    return {
        "status": "unknown",
        "ptr_len_pairs": [],
        "nullability": [],
        "flag_domain": [],
        "callback_contracts": [],
        "constraints": [],
        "arg_bindings": [],
        "boundary_assumptions": [],
        "evidence": [],
        "conflict_reason": None,
        "reason": None,
    }


def build_abi_contracts(trigger_model: dict, evidence_calls: List[dict], path_bundle: dict) -> dict:
    result = _new_result()
    param_semantics = ((trigger_model or {}).get("param_semantics") or {})
    abi_rules = (param_semantics.get("abi_contracts") or {})

    ptr_len_rules = list(abi_rules.get("ptr_len_pairs") or [])
    nullability_rules = list(abi_rules.get("nullability") or [])
    flag_domain_rules = list(abi_rules.get("flag_domain") or [])
    callback_rules = list(abi_rules.get("callback_contracts") or [])

    has_any = bool(ptr_len_rules or nullability_rules or flag_domain_rules or callback_rules)
    if not has_any:
        result["reason"] = "abi_contracts_not_configured"
        return result

    all_calls = list(evidence_calls or [])
    if not all_calls:
        all_calls = list((path_bundle or {}).get("sink_calls") or [])

    method_signatures = dict((path_bundle or {}).get("method_signatures") or {})
    const_map = dict((path_bundle or {}).get("const_map") or (path_bundle or {}).get("constants") or {})

    unsat_reasons: List[dict] = []

    # ptr/len contracts.
    for ridx, rule in enumerate(ptr_len_rules):
        call_name = rule.get("call")
        ptr_arg = int(rule.get("ptr_arg") or 0)
        len_arg = int(rule.get("len_arg") or 0)
        len_constraints = list(rule.get("len_constraints") or rule.get("constraints") or [])
        null_ptr_requires_len_zero = bool(rule.get("null_ptr_requires_len_zero", False))

        matches = _iter_calls(all_calls, call_name)
        if not matches:
            result["boundary_assumptions"].append(
                {
                    "kind": "contract_call_not_found",
                    "call": call_name,
                    "rule": f"ptr_len_pairs[{ridx}]",
                }
            )
            continue

        eval_items = []
        for call in matches:
            ptr_binding, ptr_assump = _resolve_arg_binding(call, ptr_arg, method_signatures)
            len_binding, len_assump = _resolve_arg_binding(call, len_arg, method_signatures)
            if ptr_binding:
                result["arg_bindings"].append(ptr_binding)
            if len_binding:
                result["arg_bindings"].append(len_binding)
            if ptr_assump:
                result["boundary_assumptions"].append(ptr_assump)
            if len_assump:
                result["boundary_assumptions"].append(len_assump)

            ptr_expr = (ptr_binding or {}).get("arg_expr") or ""
            len_expr = (len_binding or {}).get("arg_expr") or ""
            len_var = (len_binding or {}).get("bound_var")
            len_literal = _coerce_int(len_expr)

            entry = {
                "call_id": call.get("id"),
                "call": call_name,
                "ptr_expr": ptr_expr,
                "len_expr": len_expr,
                "len_var": len_var,
                "len_literal": len_literal,
                "status": "unknown",
                "rule_index": ridx,
                "constraints_added": [],
            }

            for cidx, c in enumerate(len_constraints):
                op = _normalize_operator(c.get("op") or c.get("operator"))
                value = _coerce_int(c.get("value"))
                if op is None or value is None:
                    continue
                if len_var:
                    cons = {
                        "variable": len_var,
                        "operator": op,
                        "value": value,
                        "source": "abi_contract",
                        "source_id": call.get("id"),
                        "evidence_ref": f"ptr_len_pairs[{ridx}].len_constraints[{cidx}]",
                    }
                    result["constraints"].append(cons)
                    entry["constraints_added"].append(cons)
                elif len_literal is not None:
                    ok = True
                    if op == "==":
                        ok = len_literal == value
                    elif op == "!=":
                        ok = len_literal != value
                    elif op == ">":
                        ok = len_literal > value
                    elif op == ">=":
                        ok = len_literal >= value
                    elif op == "<":
                        ok = len_literal < value
                    elif op == "<=":
                        ok = len_literal <= value
                    if not ok:
                        unsat_reasons.append(
                            {
                                "kind": "ptr_len_literal_conflict",
                                "call": call_name,
                                "call_id": call.get("id"),
                                "len_expr": len_expr,
                                "constraint": {"operator": op, "value": value},
                            }
                        )
                else:
                    result["boundary_assumptions"].append(
                        {
                            "kind": "len_constraint_unbound",
                            "call": call_name,
                            "call_id": call.get("id"),
                            "detail": "len binding not numeric and no variable",
                        }
                    )

            if null_ptr_requires_len_zero and _expr_is_null(ptr_expr):
                if len_var:
                    cons = {
                        "variable": len_var,
                        "operator": "==",
                        "value": 0,
                        "source": "abi_contract",
                        "source_id": call.get("id"),
                        "evidence_ref": f"ptr_len_pairs[{ridx}].null_ptr_requires_len_zero",
                    }
                    result["constraints"].append(cons)
                    entry["constraints_added"].append(cons)
                elif len_literal is not None:
                    if len_literal != 0:
                        unsat_reasons.append(
                            {
                                "kind": "null_ptr_nonzero_len",
                                "call": call_name,
                                "call_id": call.get("id"),
                                "len_expr": len_expr,
                            }
                        )
                else:
                    result["boundary_assumptions"].append(
                        {
                            "kind": "null_ptr_len_zero_unknown",
                            "call": call_name,
                            "call_id": call.get("id"),
                            "detail": "ptr is null but len cannot be proven",
                        }
                    )

            if ptr_binding and len_binding:
                entry["status"] = "bound"
            eval_items.append(entry)
            result["evidence"].append(
                {
                    "kind": "ptr_len_pair",
                    "rule": f"ptr_len_pairs[{ridx}]",
                    "call": call_name,
                    "call_id": call.get("id"),
                    "code": call.get("code"),
                    "ptr_arg": ptr_arg,
                    "len_arg": len_arg,
                    "ptr_expr": ptr_expr,
                    "len_expr": len_expr,
                }
            )

        result["ptr_len_pairs"].append({"rule": rule, "evaluations": eval_items})

    # nullability contracts.
    for ridx, rule in enumerate(nullability_rules):
        call_name = rule.get("call")
        arg_index = int(rule.get("arg_index") or 0)
        must_be = str(rule.get("must_be") or "unknown")
        matches = _iter_calls(all_calls, call_name)
        if not matches:
            result["boundary_assumptions"].append(
                {
                    "kind": "contract_call_not_found",
                    "call": call_name,
                    "rule": f"nullability[{ridx}]",
                }
            )
            continue

        eval_items = []
        for call in matches:
            binding, assumption = _resolve_arg_binding(call, arg_index, method_signatures)
            if binding:
                result["arg_bindings"].append(binding)
            if assumption:
                result["boundary_assumptions"].append(assumption)
            expr = (binding or {}).get("arg_expr") or ""
            observed = "unknown"
            val = _coerce_int(expr)
            if _expr_is_null(expr):
                observed = "null"
            elif val is not None and val != 0:
                observed = "nonnull"

            status = "unknown"
            if must_be == "nonnull":
                status = "sat" if observed == "nonnull" else ("unsat" if observed == "null" else "unknown")
            elif must_be == "null":
                status = "sat" if observed == "null" else ("unsat" if observed == "nonnull" else "unknown")

            if status == "unsat":
                unsat_reasons.append(
                    {
                        "kind": "nullability_conflict",
                        "call": call_name,
                        "call_id": call.get("id"),
                        "arg_index": arg_index,
                        "must_be": must_be,
                        "observed": observed,
                    }
                )

            eval_items.append(
                {
                    "call_id": call.get("id"),
                    "arg_index": arg_index,
                    "arg_expr": expr,
                    "must_be": must_be,
                    "observed": observed,
                    "status": status,
                }
            )

            result["evidence"].append(
                {
                    "kind": "nullability",
                    "rule": f"nullability[{ridx}]",
                    "call": call_name,
                    "call_id": call.get("id"),
                    "code": call.get("code"),
                    "arg_index": arg_index,
                    "arg_expr": expr,
                    "must_be": must_be,
                    "observed": observed,
                }
            )

        result["nullability"].append({"rule": rule, "evaluations": eval_items})

    # flag domain contracts.
    for ridx, rule in enumerate(flag_domain_rules):
        call_name = rule.get("call")
        arg_index = int(rule.get("arg_index") or 0)
        allowed = set(rule.get("allowed") or [])
        requires_all = set(rule.get("requires_all") or [])
        forbids = set(rule.get("forbids") or [])

        if requires_all & forbids:
            unsat_reasons.append(
                {
                    "kind": "flag_rule_self_conflict",
                    "rule": f"flag_domain[{ridx}]",
                    "overlap": sorted(requires_all & forbids),
                }
            )

        matches = _iter_calls(all_calls, call_name)
        if not matches:
            result["boundary_assumptions"].append(
                {
                    "kind": "contract_call_not_found",
                    "call": call_name,
                    "rule": f"flag_domain[{ridx}]",
                }
            )
            continue

        eval_items = []
        for call in matches:
            binding, assumption = _resolve_arg_binding(call, arg_index, method_signatures)
            if binding:
                result["arg_bindings"].append(binding)
            if assumption:
                result["boundary_assumptions"].append(assumption)

            expr = (binding or {}).get("arg_expr") or ""
            tokens = _tokens_from_expr(expr, const_map)
            status = "unknown"
            reasons = []

            if tokens:
                tset = set(tokens)
                if allowed and not tset.issubset(allowed):
                    disallowed = sorted(tset - allowed)
                    reasons.append({"kind": "flag_token_not_allowed", "tokens": disallowed})
                if requires_all and not requires_all.issubset(tset):
                    reasons.append({"kind": "flag_required_missing", "tokens": sorted(requires_all - tset)})
                if forbids and (tset & forbids):
                    reasons.append({"kind": "flag_forbidden_present", "tokens": sorted(tset & forbids)})
                status = "unsat" if reasons else "sat"
            else:
                status = "unknown"

            if status == "unsat":
                unsat_reasons.append(
                    {
                        "kind": "flag_domain_conflict",
                        "call": call_name,
                        "call_id": call.get("id"),
                        "arg_index": arg_index,
                        "details": reasons,
                    }
                )

            eval_items.append(
                {
                    "call_id": call.get("id"),
                    "arg_index": arg_index,
                    "arg_expr": expr,
                    "tokens": tokens,
                    "status": status,
                    "reasons": reasons,
                }
            )

            result["evidence"].append(
                {
                    "kind": "flag_domain",
                    "rule": f"flag_domain[{ridx}]",
                    "call": call_name,
                    "call_id": call.get("id"),
                    "code": call.get("code"),
                    "arg_index": arg_index,
                    "arg_expr": expr,
                    "tokens": tokens,
                }
            )

        result["flag_domain"].append({"rule": rule, "evaluations": eval_items})

    # callback contracts.
    for ridx, rule in enumerate(callback_rules):
        call_name = rule.get("call")
        arg_index = int(rule.get("arg_index") or 0)
        must_be_set = bool(rule.get("must_be_set", True))
        must_be_invocable = bool(rule.get("must_be_invocable", False))

        matches = _iter_calls(all_calls, call_name)
        if not matches:
            result["boundary_assumptions"].append(
                {
                    "kind": "contract_call_not_found",
                    "call": call_name,
                    "rule": f"callback_contracts[{ridx}]",
                }
            )
            continue

        eval_items = []
        for call in matches:
            binding, assumption = _resolve_arg_binding(call, arg_index, method_signatures)
            if binding:
                result["arg_bindings"].append(binding)
            if assumption:
                result["boundary_assumptions"].append(assumption)

            expr = (binding or {}).get("arg_expr") or ""
            observed = "unknown"
            if _expr_is_null(expr):
                observed = "null"
            elif expr:
                observed = "nonnull"

            status = "unknown"
            if must_be_set:
                if observed == "null":
                    status = "unsat"
                elif observed == "nonnull":
                    status = "sat"
            else:
                status = "sat"

            if must_be_invocable and status == "sat":
                # This layer only guarantees binding contracts; invocability requires semantic layer.
                status = "unknown"
                result["boundary_assumptions"].append(
                    {
                        "kind": "invocability_deferred",
                        "call": call_name,
                        "call_id": call.get("id"),
                        "arg_index": arg_index,
                        "detail": "callback invocability checked in param_semantics",
                    }
                )

            if status == "unsat":
                unsat_reasons.append(
                    {
                        "kind": "callback_null_conflict",
                        "call": call_name,
                        "call_id": call.get("id"),
                        "arg_index": arg_index,
                    }
                )

            eval_items.append(
                {
                    "call_id": call.get("id"),
                    "arg_index": arg_index,
                    "arg_expr": expr,
                    "observed": observed,
                    "must_be_set": must_be_set,
                    "must_be_invocable": must_be_invocable,
                    "status": status,
                }
            )

            result["evidence"].append(
                {
                    "kind": "callback_contract",
                    "rule": f"callback_contracts[{ridx}]",
                    "call": call_name,
                    "call_id": call.get("id"),
                    "code": call.get("code"),
                    "arg_index": arg_index,
                    "arg_expr": expr,
                    "must_be_set": must_be_set,
                    "must_be_invocable": must_be_invocable,
                }
            )

        result["callback_contracts"].append({"rule": rule, "evaluations": eval_items})

    constraints = _dedupe_constraints(result["constraints"])
    result["constraints"] = constraints
    interval = _interval_feasibility(constraints)

    if unsat_reasons:
        result["status"] = "unsat"
        result["conflict_reason"] = unsat_reasons
    elif interval.get("feasible") is False:
        result["status"] = "unsat"
        result["conflict_reason"] = interval.get("bottom_reason")
    else:
        has_assumptions = bool(result["boundary_assumptions"])
        result["status"] = "unknown" if has_assumptions else "sat"
        result["conflict_reason"] = None

    if result["status"] == "unknown" and not result["reason"] and result["boundary_assumptions"]:
        result["reason"] = "abi_contract_binding_partial"

    return result
