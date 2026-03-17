"""Parameter-semantics evaluator for triggerability refinement.

This module keeps analysis conservative:
- Return `unsat` only when contradiction is provable.
- Fall back to `unknown` on partial information.
"""

from __future__ import annotations

import math
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from tools.verification.path_solver import PathConstraintSolver, parse_condition_expression
from tools.verification.interproc_flags import evaluate_flags_interproc
from tools.verification.alias_analysis import analyze_aliases
from tools.verification.interproc_valueflow import build_interproc_index, propagate_from_sink

_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_FLAG_TOKEN_RE = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")
_ASSIGN_RE = re.compile(
    r"^\s*(?:[A-Za-z_][A-Za-z0-9_\s\*]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(\|=|&=|\^=|=)\s*(.+?)\s*;?\s*$"
)
_NULL_LITERALS = {"0", "NULL", "nullptr"}
_IGNORED_IDENTIFIERS = {"if", "else", "while", "for", "switch", "return", "true", "false", "NULL"}
_NUM_TOKEN_RE = re.compile(r"^-?(?:0x[0-9A-Fa-f]+|\d+)$")
_GEN_ASSIGN_RE = re.compile(r"^\s*(?P<lhs>[^=]+?)\s*(?P<op>\|=|&=|\^=|=)\s*(?P<rhs>.+?)\s*;?\s*$")
_ADDRESS_OF_RE = re.compile(r"^\s*&\s*([A-Za-z_][A-Za-z0-9_]*)\s*$")
_DEREF_RE = re.compile(r"^\s*\(?\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)?\s*$")


def _coerce_int(token: str) -> Optional[int]:
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
    out = []
    for call in calls or []:
        if not isinstance(call, dict):
            continue
        if call.get("name") == call_name:
            out.append(call)
    out.sort(key=lambda c: (str(c.get("method") or ""), int(c.get("id") or 10**18)))
    return out


def _normalize_ws(text: str) -> str:
    return " ".join((text or "").split())


def _extract_guard_constraints(control_node: dict) -> Tuple[str, List[dict]]:
    candidates: List[str] = []
    for child in control_node.get("child_codes") or []:
        if isinstance(child, str) and child.strip():
            candidates.append(child)
    code = control_node.get("code")
    if isinstance(code, str) and code.strip():
        candidates.append(code)

    for cand in candidates:
        parsed = parse_condition_expression(cand)
        if parsed:
            return cand, parsed
    return "", []


def _eval_simple_constraint(op: str, lhs: int, rhs: int) -> Optional[bool]:
    if op == "==":
        return lhs == rhs
    if op == "!=":
        return lhs != rhs
    if op == ">":
        return lhs > rhs
    if op == ">=":
        return lhs >= rhs
    if op == "<":
        return lhs < rhs
    if op == "<=":
        return lhs <= rhs
    return None


def _evaluate_guard_truth(guard_constraints: List[dict], value_env: Dict[str, int]) -> str:
    if not guard_constraints:
        return "unknown"
    known = []
    for cons in guard_constraints:
        var = cons.get("variable")
        if var not in value_env:
            continue
        lhs = value_env[var]
        rhs = cons.get("value")
        try:
            rhs_int = int(rhs)
        except Exception:
            continue
        res = _eval_simple_constraint(str(cons.get("operator")), lhs, rhs_int)
        if res is not None:
            known.append(res)
    if not known:
        return "unknown"
    if all(known):
        return "true"
    if any(v is False for v in known):
        return "false"
    return "unknown"


def _infer_branch_polarity(control_code: str, stmt_code: str) -> str:
    if not control_code or not stmt_code:
        return "unknown"
    normalized_control = _normalize_ws(control_code)
    normalized_stmt = _normalize_ws(stmt_code)
    if " else " not in f" {normalized_control} ":
        return "true_branch"
    idx = normalized_control.find(" else ")
    if idx == -1:
        return "unknown"
    before = normalized_control[:idx]
    after = normalized_control[idx + len(" else ") :]
    if normalized_stmt and normalized_stmt in before:
        return "true_branch"
    if normalized_stmt and normalized_stmt in after:
        return "false_branch"
    return "unknown"


def _find_related_control(stmt_code: str, control_nodes: List[dict]) -> Optional[dict]:
    if not stmt_code:
        return None
    normalized_stmt = _normalize_ws(stmt_code)
    best = None
    best_score = None
    for node in control_nodes or []:
        if not isinstance(node, dict):
            continue
        texts = []
        code = node.get("code")
        if isinstance(code, str) and code.strip():
            texts.append(code)
        for child in node.get("child_codes") or []:
            if isinstance(child, str) and child.strip():
                texts.append(child)
        matched = False
        for txt in texts:
            if normalized_stmt and normalized_stmt in _normalize_ws(txt):
                matched = True
                break
        if not matched:
            continue
        depth = node.get("depth")
        depth_val = depth if isinstance(depth, int) else 10**9
        score = (depth_val, len(code or ""))
        if best is None or score < best_score:
            best = node
            best_score = score
    return best


def _parse_assignment(code: str) -> Optional[dict]:
    if not isinstance(code, str):
        return None
    match = _ASSIGN_RE.match(code.strip())
    if not match:
        return None
    lhs, op, rhs = match.groups()
    rhs = rhs.strip()
    if not lhs or not rhs:
        return None
    return {"lhs": lhs, "op": op, "rhs": rhs}


def _tokens_from_numeric(mask: int, const_map: Dict[str, int]) -> List[str]:
    if not isinstance(mask, int):
        return []
    tokens: List[str] = []
    for name, value in (const_map or {}).items():
        if not isinstance(name, str):
            continue
        if not isinstance(value, int):
            continue
        if value <= 0:
            continue
        if (mask & value) == value:
            tokens.append(name)
    return sorted(set(tokens))


def _extract_flag_tokens(expr: str, const_map: Dict[str, int]) -> Tuple[set, bool]:
    if not isinstance(expr, str):
        return set(), True
    text = expr.strip()
    if not text:
        return set(), True
    tokens = set(_FLAG_TOKEN_RE.findall(text))

    # Exact constant token.
    if text in const_map and isinstance(const_map[text], int):
        tokens.add(text)

    # Numeric mask decoding fallback.
    number = _coerce_int(text)
    if number is not None:
        tokens.update(_tokens_from_numeric(number, const_map))
        return tokens, False

    # Basic mixed expressions are still acceptable if we extracted flag tokens.
    unknown = not bool(tokens)
    return tokens, unknown


def _flip_truth(truth: str) -> str:
    if truth == "true":
        return "false"
    if truth == "false":
        return "true"
    return "unknown"


def _make_flag_state() -> dict:
    return {
        "must_set": set(),
        "may_set": set(),
        "forbid": set(),
        "unknown": False,
        "evidence": [],
    }


def _append_flag_evidence(state: dict, call: dict, reason: str, guard_info: dict) -> None:
    state["evidence"].append(
        {
            "call_id": call.get("id"),
            "call_name": call.get("name"),
            "code": call.get("code"),
            "reason": reason,
            "guard": guard_info,
        }
    )


def _apply_flag_update(state: dict, op: str, rhs: str, certainty: str, call: dict, guard_info: dict, const_map: Dict[str, int]) -> None:
    tokens, expr_unknown = _extract_flag_tokens(rhs, const_map)
    if expr_unknown:
        state["unknown"] = True

    if certainty == "false":
        _append_flag_evidence(state, call, "assignment_guarded_out", guard_info)
        return

    mode = "must" if certainty == "true" else "may"
    if mode == "may":
        state["unknown"] = True

    if op == "=":
        if mode == "must":
            old_must = set(state["must_set"])
            state["must_set"] = set(tokens)
            state["may_set"].update(tokens)
            removed = old_must - set(tokens)
            state["forbid"].update(removed)
        else:
            state["may_set"].update(tokens)
    elif op == "|=":
        if mode == "must":
            state["must_set"].update(tokens)
        state["may_set"].update(tokens)
        state["forbid"].difference_update(tokens)
    elif op == "&=" and rhs.strip().startswith("~"):
        clear_tokens, clear_unknown = _extract_flag_tokens(rhs.strip()[1:].strip(), const_map)
        if clear_unknown:
            state["unknown"] = True
        if mode == "must":
            state["must_set"].difference_update(clear_tokens)
            state["may_set"].difference_update(clear_tokens)
            state["forbid"].update(clear_tokens)
        else:
            state["unknown"] = True
    elif op == "&=":
        if mode == "must":
            allow = set(tokens)
            removed = set(state["must_set"]) | set(state["may_set"])
            removed.difference_update(allow)
            state["must_set"].intersection_update(allow)
            state["may_set"].intersection_update(allow)
            state["forbid"].update(removed)
        else:
            state["unknown"] = True
            state["may_set"].update(tokens)
    elif op == "^=":
        if mode == "must":
            for tok in tokens:
                if tok in state["must_set"]:
                    state["must_set"].remove(tok)
                    state["forbid"].add(tok)
                elif tok in state["forbid"]:
                    state["forbid"].remove(tok)
                    state["must_set"].add(tok)
                else:
                    state["may_set"].add(tok)
                    state["unknown"] = True
        else:
            state["may_set"].update(tokens)
            state["unknown"] = True
    else:
        state["unknown"] = True

    _append_flag_evidence(state, call, f"applied_{mode}_{op}", guard_info)


def _evaluate_flags_rule_fallback(
    rule: dict,
    calls: List[dict],
    control_nodes: List[dict],
    const_map: Dict[str, int],
    value_env: Dict[str, int],
) -> dict:
    call_name = rule.get("call")
    arg_index = int(rule.get("arg_index") or 0)
    requires_all = list(rule.get("requires_all") or [])
    requires_any = list(rule.get("requires_any") or [])
    forbids = list(rule.get("forbids") or [])

    sink_calls = _iter_calls(calls, call_name)
    if not sink_calls:
        return {
            "type": "flags",
            "rule": rule,
            "status": "unknown",
            "reason": "sink_call_not_found",
            "state": {
                "must_set": [],
                "may_set": [],
                "forbid": [],
                "unknown": True,
            },
            "evidence": [],
        }

    aggregate_state = _make_flag_state()
    for sink in sink_calls:
        args = _extract_call_args(sink.get("code") or "")
        if arg_index <= 0 or arg_index > len(args):
            aggregate_state["unknown"] = True
            _append_flag_evidence(
                aggregate_state,
                sink,
                "sink_arg_missing",
                {"guard_text": None, "guard_truth": "unknown", "branch": "unknown"},
            )
            continue
        target_expr = args[arg_index - 1].strip()
        target_tokens, expr_unknown = _extract_flag_tokens(target_expr, const_map)
        if target_tokens:
            aggregate_state["must_set"].update(target_tokens)
            aggregate_state["may_set"].update(target_tokens)
            _append_flag_evidence(
                aggregate_state,
                sink,
                "sink_expr_tokens",
                {"guard_text": None, "guard_truth": "true", "branch": "direct_arg"},
            )
        if expr_unknown and not _IDENT_RE.fullmatch(target_expr):
            aggregate_state["unknown"] = True

        target_ident = target_expr if _IDENT_RE.fullmatch(target_expr) else None
        if not target_ident:
            continue

        for call in calls:
            code = call.get("code")
            if not isinstance(code, str) or target_ident not in code:
                continue
            parsed = _parse_assignment(code)
            if not parsed:
                continue
            if parsed["lhs"] != target_ident:
                continue
            related_control = _find_related_control(code, control_nodes)
            guard_text = None
            guard_truth = "true"
            branch = "unconditional"
            if related_control is not None:
                guard_text, guard_constraints = _extract_guard_constraints(related_control)
                guard_truth = _evaluate_guard_truth(guard_constraints, value_env)
                branch = _infer_branch_polarity(related_control.get("code") or "", code)
                if branch == "false_branch":
                    guard_truth = _flip_truth(guard_truth)
            guard_info = {
                "guard_text": guard_text,
                "guard_truth": guard_truth,
                "branch": branch,
                "control_id": related_control.get("id") if related_control else None,
            }
            _apply_flag_update(aggregate_state, parsed["op"], parsed["rhs"], guard_truth, call, guard_info, const_map)

    must_set = set(aggregate_state["must_set"])
    may_set = set(aggregate_state["may_set"])
    forbid_set = set(aggregate_state["forbid"])

    unsat_reasons = []
    for tok in requires_all:
        if tok in forbid_set:
            unsat_reasons.append(f"required_token_forbidden:{tok}")
        elif tok not in must_set and tok not in may_set and not aggregate_state["unknown"]:
            unsat_reasons.append(f"required_token_absent:{tok}")
    for tok in forbids:
        if tok in must_set:
            unsat_reasons.append(f"forbidden_token_must_set:{tok}")
    if requires_any:
        if not any(tok in must_set for tok in requires_any):
            if all(tok in forbid_set for tok in requires_any):
                unsat_reasons.append("requires_any_all_forbidden")

    if unsat_reasons:
        status = "unsat"
    else:
        all_required_must = all(tok in must_set for tok in requires_all) if requires_all else True
        any_required_must = any(tok in must_set for tok in requires_any) if requires_any else True
        any_forbid_may_or_must = any(tok in must_set or tok in may_set for tok in forbids)
        if all_required_must and any_required_must and not any_forbid_may_or_must and not aggregate_state["unknown"]:
            status = "sat"
        else:
            status = "unknown"

    return {
        "type": "flags",
        "engine": "intra_fallback",
        "rule": rule,
        "status": status,
        "reason": unsat_reasons if unsat_reasons else None,
        "state": {
            "must_set": sorted(must_set),
            "may_set": sorted(may_set),
            "forbid": sorted(forbid_set),
            "unknown": bool(aggregate_state["unknown"]),
        },
        "evidence": aggregate_state["evidence"],
    }


def _evaluate_flags_rule(
    rule: dict,
    calls: List[dict],
    control_nodes: List[dict],
    const_map: Dict[str, int],
    value_env: Dict[str, int],
    path_bundle: Optional[dict] = None,
    interproc_depth: int = 2,
) -> dict:
    try:
        return evaluate_flags_interproc(
            rule=rule,
            calls=calls,
            control_nodes=control_nodes,
            const_map=const_map,
            value_env=value_env,
            path_bundle=path_bundle or {},
            max_depth=interproc_depth,
        )
    except Exception as exc:
        fallback = _evaluate_flags_rule_fallback(
            rule=rule,
            calls=calls,
            control_nodes=control_nodes,
            const_map=const_map,
            value_env=value_env,
        )
        fallback["interproc_error"] = str(exc)
        return fallback


def _constraint_from_rule(var: str, item: dict) -> Optional[dict]:
    op = item.get("op") or item.get("operator")
    val = item.get("value")
    if op == "=":
        op = "=="
    if op not in {"<", "<=", ">", ">=", "==", "!="}:
        return None
    try:
        ival = int(val)
    except Exception:
        return None
    return {
        "variable": var,
        "operator": op,
        "value": ival,
        "source": "param_semantics_rule",
        "raw": f"{var} {op} {ival}",
    }


def _interval_fallback(constraints: List[dict]) -> dict:
    bounds: Dict[str, dict] = {}
    bottom_reason = None
    neq: Dict[str, List[Tuple[int, dict]]] = {}

    def ensure(var: str) -> dict:
        if var not in bounds:
            bounds[var] = {"lo": -math.inf, "hi": math.inf, "lo_src": None, "hi_src": None}
        return bounds[var]

    for cons in constraints:
        var = cons.get("variable")
        op = cons.get("operator")
        val = cons.get("value")
        if not isinstance(var, str):
            continue
        try:
            value = int(val)
        except Exception:
            continue
        b = ensure(var)
        lo_before, hi_before = b["lo"], b["hi"]

        if op == "==":
            if value > b["lo"]:
                b["lo"] = value
                b["lo_src"] = cons
            if value < b["hi"]:
                b["hi"] = value
                b["hi_src"] = cons
        elif op == ">":
            candidate = value + 1
            if candidate > b["lo"]:
                b["lo"] = candidate
                b["lo_src"] = cons
        elif op == ">=":
            if value > b["lo"]:
                b["lo"] = value
                b["lo_src"] = cons
        elif op == "<":
            candidate = value - 1
            if candidate < b["hi"]:
                b["hi"] = candidate
                b["hi_src"] = cons
        elif op == "<=":
            if value < b["hi"]:
                b["hi"] = value
                b["hi_src"] = cons
        elif op == "!=":
            neq.setdefault(var, []).append((value, cons))
        else:
            continue

        if b["lo"] > b["hi"]:
            bottom_reason = {
                "variable": var,
                "lower_bound": b["lo_src"] or cons,
                "upper_bound": b["hi_src"] or cons,
            }
            return {"feasible": False, "ranges": {}, "bottom_reason": bottom_reason}

        if lo_before != b["lo"] or hi_before != b["hi"]:
            if b["lo"] > b["hi"]:
                bottom_reason = {
                    "variable": var,
                    "lower_bound": b["lo_src"] or cons,
                    "upper_bound": b["hi_src"] or cons,
                }
                return {"feasible": False, "ranges": {}, "bottom_reason": bottom_reason}

    for var, pairs in neq.items():
        b = ensure(var)
        if b["lo"] == b["hi"]:
            point = int(b["lo"])
            for neq_value, neq_cons in pairs:
                if neq_value == point:
                    bottom_reason = {
                        "variable": var,
                        "point_constraint": b["lo_src"] or b["hi_src"],
                        "not_equal_constraint": neq_cons,
                    }
                    return {"feasible": False, "ranges": {}, "bottom_reason": bottom_reason}

    ranges = {}
    for var, b in bounds.items():
        lo = None if b["lo"] == -math.inf else int(b["lo"])
        hi = None if b["hi"] == math.inf else int(b["hi"])
        ranges[var] = [lo, hi]
    return {"feasible": True, "ranges": ranges, "bottom_reason": None}


def _slot(method: str, ident: str) -> str:
    return f"{method}::{ident}"


def _tail_name(slot_name: str) -> str:
    if not isinstance(slot_name, str):
        return ""
    if "::" in slot_name:
        return slot_name.split("::", 1)[1]
    return slot_name


def _extract_identifiers(text: str) -> List[str]:
    out = []
    seen = set()
    for token in _IDENT_RE.findall(text or ""):
        if token in _IGNORED_IDENTIFIERS:
            continue
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def _build_interproc_runtime(
    calls: List[dict],
    path_bundle: dict,
    const_map: Dict[str, int],
    interproc_depth: int,
) -> dict:
    interproc_context = dict(path_bundle.get("interproc_context") or {})
    method_signatures = dict(path_bundle.get("method_signatures") or interproc_context.get("method_signatures") or {})
    method_calls = list(interproc_context.get("method_calls") or calls or [])
    index = build_interproc_index(method_calls, method_signatures)
    index["const_map"] = dict(const_map or {})
    alias_result = analyze_aliases(method_calls, method_signatures, max_depth=interproc_depth)
    return {
        "index": index,
        "alias_result": alias_result,
        "method_signatures": method_signatures,
        "method_calls": method_calls,
    }


def _propagate_for_sink(
    sink: dict,
    arg_index: int,
    runtime: Optional[dict],
    control_nodes: List[dict],
    value_env: Dict[str, int],
    interproc_depth: int,
) -> dict:
    if not runtime or not runtime.get("index"):
        return {
            "engine_version": "interproc_v2",
            "status": "unknown",
            "state": {},
            "trace": [],
            "unresolved": [{"kind": "interproc_runtime_missing"}],
            "target_expr": "",
            "related_symbols": [],
            "alias_result": {},
        }
    return propagate_from_sink(
        index=runtime["index"],
        sink_call=sink,
        arg_index=arg_index,
        controls=control_nodes,
        value_env=value_env,
        max_depth=interproc_depth,
    )


def _aliases_for_identifier(identifier: str, method: str, alias_result: dict) -> Set[str]:
    out: Set[str] = set()
    if not identifier:
        return out
    out.add(identifier)
    if not isinstance(alias_result, dict):
        return out

    slot_name = _slot(method, identifier) if method else identifier

    for group in alias_result.get("must_alias_sets") or []:
        if slot_name in group or identifier in group:
            for member in group:
                tail = _tail_name(member)
                if tail:
                    out.add(tail)

    may_map = dict(alias_result.get("may_alias_map") or {})
    for key, members in may_map.items():
        key_tail = _tail_name(key)
        if key in {slot_name, identifier} or key_tail == identifier:
            out.add(key_tail)
            for member in members or []:
                tail = _tail_name(member)
                if tail:
                    out.add(tail)

    points_to = dict(alias_result.get("points_to") or {})
    for key, members in points_to.items():
        key_tail = _tail_name(key)
        if key in {slot_name, identifier} or key_tail == identifier:
            out.add(key_tail)
            for member in members or []:
                tail = _tail_name(member)
                if tail:
                    out.add(tail)

    return {name for name in out if name}


def _nullability_from_flow_state(flow_state: dict) -> str:
    if not isinstance(flow_state, dict):
        return "unknown"
    nullability = dict(flow_state.get("nullability") or {})
    must_null = bool(nullability.get("must_null"))
    must_nonnull = bool(nullability.get("must_nonnull"))
    may_null = bool(nullability.get("may_null"))
    may_nonnull = bool(nullability.get("may_nonnull"))
    if must_null and not (must_nonnull or may_nonnull):
        return "null"
    if must_nonnull and not (must_null or may_null):
        return "nonnull"
    return "unknown"


def _extract_interproc_var_candidates(flow: dict, arg_expr: str) -> List[str]:
    names: List[str] = []
    seen = set()
    for tok in _extract_identifiers(arg_expr):
        if tok not in seen:
            seen.add(tok)
            names.append(tok)
    for sym in flow.get("related_symbols") or []:
        if sym in _IGNORED_IDENTIFIERS:
            continue
        if sym not in seen:
            seen.add(sym)
            names.append(sym)
    return names


def _best_len_variable(arg_expr: str, combined_constraints: List[dict]) -> Tuple[str, List[str]]:
    direct_identifiers = [tok for tok in _IDENT_RE.findall(arg_expr or "") if tok not in _IGNORED_IDENTIFIERS]
    if not direct_identifiers:
        return "", []
    if len(direct_identifiers) == 1:
        return direct_identifiers[0], direct_identifiers
    constrained_vars = {c.get("variable") for c in combined_constraints or []}
    for name in direct_identifiers:
        if name in constrained_vars:
            return name, direct_identifiers
    return direct_identifiers[0], direct_identifiers


def _guess_len_variable_from_context(combined_constraints: List[dict], value_env: Dict[str, int]) -> str:
    candidates = []
    seen = set()
    for cons in combined_constraints or []:
        var = cons.get("variable")
        if not isinstance(var, str) or not var or var in seen:
            continue
        seen.add(var)
        candidates.append(var)
    for key in value_env or {}:
        if not isinstance(key, str) or not key or key in seen:
            continue
        seen.add(key)
        candidates.append(key)
    preferred = [v for v in candidates if any(tag in v.lower() for tag in ("len", "length", "size"))]
    if preferred:
        preferred.sort(key=lambda x: (0 if "len" in x.lower() else 1, len(x)))
        return preferred[0]
    return candidates[0] if candidates else ""


def _evaluate_len_rule(
    rule: dict,
    calls: List[dict],
    path_bundle: dict,
    solver: Optional[PathConstraintSolver],
    runtime: Optional[dict],
    interproc_depth: int,
) -> dict:
    call_name = rule.get("call")
    arg_index = int(rule.get("arg_index") or 0)
    sink_calls = _iter_calls(calls, call_name)
    if not sink_calls:
        return {
            "type": "len",
            "rule": rule,
            "status": "unknown",
            "reason": "sink_call_not_found",
            "constraints_used": [],
            "range_estimate": None,
            "conflict_reason": None,
            "evidence": [],
        }

    combined_constraints = list(path_bundle.get("combined_constraints") or [])
    value_env = dict(path_bundle.get("value_env") or {})
    control_nodes = list(path_bundle.get("control_structures_relevant") or [])
    alias_result = dict((runtime or {}).get("alias_result") or {})
    rule_constraints = list(rule.get("constraints") or [])

    per_call = []
    merged_status = "sat"
    for sink in sink_calls:
        args = _extract_call_args(sink.get("code") or "")
        arg_expr = args[arg_index - 1].strip() if arg_index > 0 and arg_index <= len(args) else ""
        flow = _propagate_for_sink(
            sink=sink,
            arg_index=arg_index,
            runtime=runtime,
            control_nodes=control_nodes,
            value_env=value_env,
            interproc_depth=interproc_depth,
        )
        flow_state = dict(flow.get("state") or {})

        len_var, idents = _best_len_variable(arg_expr, combined_constraints) if arg_expr else ("", [])
        candidates = _extract_interproc_var_candidates(flow, arg_expr)
        if not len_var:
            for candidate in candidates:
                if any(tag in candidate.lower() for tag in ("len", "length", "size")):
                    len_var = candidate
                    break
        if not len_var:
            len_var = _guess_len_variable_from_context(combined_constraints, value_env)
        if len_var and len_var not in idents:
            idents = list(idents) + [len_var]

        target_names: Set[str] = set()
        method_name = str(sink.get("method") or "")
        for name in idents or []:
            target_names.update(_aliases_for_identifier(name, method_name, alias_result))
        for name in candidates:
            target_names.update(_aliases_for_identifier(name, method_name, alias_result))
        if len_var:
            target_names.update(_aliases_for_identifier(len_var, method_name, alias_result))
        if not target_names and len_var:
            target_names.add(len_var)
        if not target_names:
            target_names.update(idents)

        constraints_to_solve: List[dict] = []
        numeric_arg = _coerce_int(arg_expr)
        if numeric_arg is not None:
            literal_var = f"arg_{arg_index}_value"
            len_var = literal_var
            target_names.add(literal_var)
            constraints_to_solve.append(
                {
                    "variable": literal_var,
                    "operator": "==",
                    "value": int(numeric_arg),
                    "source": "sink_arg_literal",
                    "raw": f"{literal_var} == {numeric_arg}",
                }
            )

        for cons in combined_constraints:
            if cons.get("variable") in target_names:
                constraints_to_solve.append(cons)

        for name in list(target_names):
            if name in value_env:
                constraints_to_solve.append(
                    {
                        "variable": name,
                        "operator": "==",
                        "value": int(value_env[name]),
                        "source": "value_env",
                        "raw": f"{name} == {value_env[name]}",
                    }
                )

        # Inject interval hints from interproc valueflow.
        for var_name, var_range in dict(flow_state.get("intervals") or {}).items():
            tail = _tail_name(var_name)
            if tail not in target_names and var_name not in target_names:
                continue
            if not isinstance(var_range, list) or len(var_range) != 2:
                continue
            lo, hi = var_range
            if lo is not None:
                constraints_to_solve.append(
                    {
                        "variable": tail,
                        "operator": ">=",
                        "value": int(lo),
                        "source": "interproc_interval",
                        "raw": f"{tail} >= {int(lo)}",
                    }
                )
            if hi is not None:
                constraints_to_solve.append(
                    {
                        "variable": tail,
                        "operator": "<=",
                        "value": int(hi),
                        "source": "interproc_interval",
                        "raw": f"{tail} <= {int(hi)}",
                    }
                )

        if not len_var and target_names:
            len_var = sorted(target_names)[0]
        for rc in rule_constraints:
            if not len_var:
                continue
            parsed = _constraint_from_rule(len_var, rc)
            if parsed is not None:
                constraints_to_solve.append(parsed)

        if not constraints_to_solve:
            per_call.append(
                {
                    "call_id": sink.get("id"),
                    "code": sink.get("code"),
                    "status": "unknown",
                    "reason": "no_numeric_constraints_or_len_var",
                    "len_var": len_var,
                    "identifiers": sorted(target_names),
                    "constraints_used": [],
                    "interproc_trace": flow.get("trace") or [],
                    "interproc_unresolved": flow.get("unresolved") or [],
                }
            )
            merged_status = "unknown"
            continue

        if solver and hasattr(solver, "solve_with_explain"):
            solved = solver.solve_with_explain(constraints_to_solve)
        else:
            solved = _interval_fallback(constraints_to_solve)
            solved.update({"backend": "interval_fallback"})

        feasible = bool(solved.get("feasible", True))
        call_status = "sat" if feasible else "unsat"
        if feasible and len_var and (len_var not in (solved.get("ranges") or {})):
            call_status = "unknown"
        if call_status == "unsat":
            merged_status = "unsat"
        elif call_status == "unknown" and merged_status != "unsat":
            merged_status = "unknown"

        per_call.append(
            {
                "call_id": sink.get("id"),
                "code": sink.get("code"),
                "status": call_status,
                "len_var": len_var,
                "identifiers": sorted(target_names),
                "constraints_used": constraints_to_solve,
                "range_estimate": (solved.get("ranges") or {}).get(len_var) if len_var else None,
                "conflict_reason": solved.get("bottom_reason"),
                "solver_backend": solved.get("backend"),
                "interproc_trace": flow.get("trace") or [],
                "interproc_unresolved": flow.get("unresolved") or [],
            }
        )

    return {
        "type": "len",
        "rule": rule,
        "status": merged_status,
        "reason": None,
        "constraints_used": [item.get("constraints_used", []) for item in per_call],
        "range_estimate": [item.get("range_estimate") for item in per_call],
        "conflict_reason": [item.get("conflict_reason") for item in per_call if item.get("conflict_reason")],
        "evidence": per_call,
    }


def _arg_nullability(arg_expr: str, var_constraints: List[dict], value_env: Dict[str, int]) -> str:
    expr = (arg_expr or "").strip()
    if expr in _NULL_LITERALS:
        return "null"
    val = _coerce_int(expr)
    if val is not None:
        return "null" if val == 0 else "nonnull"
    if expr.lower().startswith("some("):
        return "nonnull"

    if _IDENT_RE.fullmatch(expr):
        if expr in value_env:
            return "null" if int(value_env[expr]) == 0 else "nonnull"
        has_eq0 = any(c.get("variable") == expr and c.get("operator") == "==" and int(c.get("value")) == 0 for c in var_constraints if c.get("value") is not None)
        has_neq0 = any(c.get("variable") == expr and c.get("operator") == "!=" and int(c.get("value")) == 0 for c in var_constraints if c.get("value") is not None)
        if has_eq0 and not has_neq0:
            return "null"
        if has_neq0 and not has_eq0:
            return "nonnull"
    return "unknown"


def _evaluate_nonnull_rule(
    rule: dict,
    calls: List[dict],
    path_bundle: dict,
    runtime: Optional[dict],
    interproc_depth: int,
) -> dict:
    call_name = rule.get("call")
    arg_index = int(rule.get("arg_index") or 0)
    must_be = rule.get("must_be")
    sink_calls = _iter_calls(calls, call_name)
    if not sink_calls:
        return {
            "type": "nonnull",
            "rule": rule,
            "status": "unknown",
            "reason": "sink_call_not_found",
            "evidence": [],
        }

    combined_constraints = list(path_bundle.get("combined_constraints") or [])
    value_env = dict(path_bundle.get("value_env") or {})
    control_nodes = list(path_bundle.get("control_structures_relevant") or [])
    alias_result = dict((runtime or {}).get("alias_result") or {})
    call_results = []
    merged = "sat"

    for sink in sink_calls:
        args = _extract_call_args(sink.get("code") or "")
        if arg_index <= 0 or arg_index > len(args):
            call_results.append({"call_id": sink.get("id"), "status": "unknown", "reason": "sink_arg_missing"})
            merged = "unknown"
            continue
        arg_expr = args[arg_index - 1].strip()
        flow = _propagate_for_sink(
            sink=sink,
            arg_index=arg_index,
            runtime=runtime,
            control_nodes=control_nodes,
            value_env=value_env,
            interproc_depth=interproc_depth,
        )
        observed = _nullability_from_flow_state(flow.get("state") or {})
        fallback_observed = _arg_nullability(arg_expr, combined_constraints, value_env)
        if observed == "unknown":
            observed = fallback_observed

        arg_ident = arg_expr if _IDENT_RE.fullmatch(arg_expr) else ""
        alias_names = _aliases_for_identifier(arg_ident, str(sink.get("method") or ""), alias_result) if arg_ident else set()
        if alias_names:
            has_eq0 = any(
                c.get("variable") in alias_names and c.get("operator") == "==" and int(c.get("value")) == 0
                for c in combined_constraints
                if c.get("value") is not None
            )
            has_neq0 = any(
                c.get("variable") in alias_names and c.get("operator") == "!=" and int(c.get("value")) == 0
                for c in combined_constraints
                if c.get("value") is not None
            )
            if has_eq0 and not has_neq0:
                observed = "null"
            elif has_neq0 and not has_eq0 and observed == "unknown":
                observed = "nonnull"

        if must_be == "nonnull":
            status = "sat" if observed == "nonnull" else ("unsat" if observed == "null" else "unknown")
        elif must_be == "null":
            status = "sat" if observed == "null" else ("unsat" if observed == "nonnull" else "unknown")
        else:
            status = "unknown"
        if status == "unsat":
            merged = "unsat"
        elif status == "unknown" and merged != "unsat":
            merged = "unknown"
        call_results.append(
            {
                "call_id": sink.get("id"),
                "code": sink.get("code"),
                "arg_expr": arg_expr,
                "observed": observed,
                "status": status,
                "alias_names": sorted(alias_names),
                "interproc_trace": flow.get("trace") or [],
                "interproc_unresolved": flow.get("unresolved") or [],
            }
        )

    return {"type": "nonnull", "rule": rule, "status": merged, "reason": None, "evidence": call_results}


def _evaluate_enum_rule(rule: dict, calls: List[dict]) -> dict:
    call_name = rule.get("call")
    arg_index = int(rule.get("arg_index") or 0)
    allowed = set(rule.get("allowed") or [])
    min_value = rule.get("min")
    max_value = rule.get("max")

    sink_calls = _iter_calls(calls, call_name)
    if not sink_calls:
        return {"type": "enum_range", "rule": rule, "status": "unknown", "reason": "sink_call_not_found", "evidence": []}

    merged = "sat"
    evidence = []
    for sink in sink_calls:
        args = _extract_call_args(sink.get("code") or "")
        if arg_index <= 0 or arg_index > len(args):
            merged = "unknown" if merged != "unsat" else merged
            evidence.append({"call_id": sink.get("id"), "status": "unknown", "reason": "sink_arg_missing"})
            continue
        arg_expr = args[arg_index - 1].strip()
        status = "unknown"
        tokens = set(_FLAG_TOKEN_RE.findall(arg_expr))
        num = _coerce_int(arg_expr)
        if allowed and tokens:
            if tokens.issubset(allowed):
                status = "sat"
            elif tokens.intersection(allowed):
                status = "unknown"
            else:
                status = "unsat"
        elif num is not None and (min_value is not None or max_value is not None):
            status = "sat"
            if min_value is not None and num < int(min_value):
                status = "unsat"
            if max_value is not None and num > int(max_value):
                status = "unsat"
        if status == "unsat":
            merged = "unsat"
        elif status == "unknown" and merged != "unsat":
            merged = "unknown"
        evidence.append({"call_id": sink.get("id"), "code": sink.get("code"), "arg_expr": arg_expr, "status": status})
    return {"type": "enum_range", "rule": rule, "status": merged, "reason": None, "evidence": evidence}


def _build_method_call_index(calls: List[dict]) -> Dict[str, List[dict]]:
    by_method: Dict[str, List[dict]] = {}
    for call in calls or []:
        method = call.get("method")
        if not method:
            continue
        by_method.setdefault(method, []).append(call)
    for rows in by_method.values():
        rows.sort(key=lambda c: int(c.get("id") or 10**18))
    return by_method


def _compact_expr(text: str) -> str:
    return re.sub(r"\s+", "", text or "")


def _parse_generic_assignment(code: str) -> Optional[dict]:
    if not isinstance(code, str):
        return None
    match = _GEN_ASSIGN_RE.match(code.strip())
    if not match:
        return None
    lhs = (match.group("lhs") or "").strip()
    op = (match.group("op") or "").strip()
    rhs = (match.group("rhs") or "").strip()
    if not lhs or not rhs:
        return None
    if rhs.startswith("="):
        return None
    if lhs.endswith(("!", "<", ">")):
        return None
    return {"lhs": lhs, "op": op, "rhs": rhs}


def _address_of_ident(text: str) -> Optional[str]:
    match = _ADDRESS_OF_RE.match(str(text or ""))
    if match:
        return match.group(1)
    return None


def _deref_ident(text: str) -> Optional[str]:
    match = _DEREF_RE.match(str(text or ""))
    if match:
        return match.group(1)
    return None


def _is_null_literal_expr(text: str) -> bool:
    return str(text or "").strip() in _NULL_LITERALS


def _guard_certainty_for_call(call: dict, control_nodes: List[dict], value_env: Dict[str, int]) -> Tuple[str, dict]:
    related_control = _find_related_control(call.get("code") or "", control_nodes)
    guard_text = None
    guard_truth = "true"
    branch = "unconditional"
    if related_control is not None:
        guard_text, guard_constraints = _extract_guard_constraints(related_control)
        guard_truth = _evaluate_guard_truth(guard_constraints, value_env)
        branch = _infer_branch_polarity(related_control.get("code") or "", call.get("code") or "")
        if branch == "false_branch":
            guard_truth = _flip_truth(guard_truth)
    guard_info = {
        "guard_text": guard_text,
        "guard_truth": guard_truth,
        "branch": branch,
        "control_id": related_control.get("id") if related_control else None,
    }
    if guard_truth == "true":
        return "true", guard_info
    if guard_truth == "false":
        return "false", guard_info
    return "may", guard_info


def _combine_certainty(parent: str, child: str) -> str:
    if parent == "false" or child == "false":
        return "false"
    if parent == "true" and child == "true":
        return "true"
    return "may"


def _arg_alias_kind_for_callback(arg_expr: str, slot_aliases: set, ptr_aliases: set, direct_target: str) -> Optional[str]:
    expr = str(arg_expr or "").strip()
    if not expr:
        return None
    if direct_target and _compact_expr(expr) == direct_target:
        return "value"

    if _IDENT_RE.fullmatch(expr):
        if expr in slot_aliases:
            return "value"
        if expr in ptr_aliases:
            return "by_ref"
    addr = _address_of_ident(expr)
    if addr and addr in slot_aliases:
        return "by_ref"
    deref = _deref_ident(expr)
    if deref and deref in ptr_aliases:
        return "value"
    return None


def _matches_callback_invoke(code: str, slot_aliases: set, ptr_aliases: set, direct_target: str) -> bool:
    if not isinstance(code, str):
        return False
    if direct_target:
        escaped = re.escape(direct_target)
        if re.search(rf"{escaped}\s*\(", _compact_expr(code)):
            return True
    for name in slot_aliases:
        escaped = re.escape(name)
        if re.search(rf"\b{escaped}\s*\(", code):
            return True
        if re.search(rf"\(\s*\*\s*{escaped}\s*\)\s*\(", code):
            return True
    for ptr in ptr_aliases:
        escaped = re.escape(ptr)
        if re.search(rf"\(\s*\*\s*{escaped}\s*\)\s*\(", code):
            return True
    return False


def _scan_callback_reachability(
    method_name: str,
    target_expr: str,
    by_ref: bool,
    method_calls: Dict[str, List[dict]],
    method_signatures: Dict[str, List[str]],
    control_nodes: List[dict],
    value_env: Dict[str, int],
    max_depth: int,
    depth: int = 0,
    start_after_id: Optional[int] = None,
    stack: Optional[set] = None,
) -> dict:
    if depth > max_depth:
        return {"may_called": False, "saw_null": False, "saw_nonnull": False, "evidence": []}
    if stack is None:
        stack = set()
    key = (method_name or "", target_expr or "", bool(by_ref))
    if key in stack:
        return {"may_called": False, "saw_null": False, "saw_nonnull": False, "evidence": []}

    calls = method_calls.get(method_name) or []
    if not calls:
        return {"may_called": False, "saw_null": False, "saw_nonnull": False, "evidence": []}

    local_stack = set(stack)
    local_stack.add(key)

    slot_aliases = set()
    ptr_aliases = set()
    direct_target = ""
    if _IDENT_RE.fullmatch(target_expr or ""):
        if by_ref:
            ptr_aliases.add(target_expr)
        else:
            slot_aliases.add(target_expr)
    else:
        direct_target = _compact_expr(target_expr)

    may_called = False
    saw_null = False
    saw_nonnull = False
    evidence = []

    for call in calls:
        cid = call.get("id")
        if start_after_id is not None:
            try:
                if cid is not None and int(cid) <= int(start_after_id):
                    continue
            except Exception:
                pass

        code = call.get("code") or ""
        certainty, guard_info = _guard_certainty_for_call(call, control_nodes, value_env)
        if certainty == "false":
            continue

        parsed = _parse_generic_assignment(code)
        if parsed is not None and parsed.get("op") == "=":
            lhs = parsed.get("lhs") or ""
            rhs = parsed.get("rhs") or ""

            lhs_ident = lhs if _IDENT_RE.fullmatch(lhs) else None
            rhs_ident = rhs if _IDENT_RE.fullmatch(rhs) else None

            if lhs_ident:
                # Alias propagation.
                if rhs_ident and rhs_ident in slot_aliases:
                    slot_aliases.add(lhs_ident)
                if rhs_ident and rhs_ident in ptr_aliases:
                    ptr_aliases.add(lhs_ident)
                rhs_addr = _address_of_ident(rhs)
                if rhs_addr and rhs_addr in slot_aliases:
                    ptr_aliases.add(lhs_ident)

                # Slot overwrite tracking.
                if lhs_ident in slot_aliases:
                    if _is_null_literal_expr(rhs):
                        saw_null = True
                        evidence.append(
                            {
                                "kind": "slot_assign_null",
                                "call_id": call.get("id"),
                                "method": method_name,
                                "code": code,
                                "guard": guard_info,
                                "depth": depth,
                            }
                        )
                    else:
                        saw_nonnull = True
                        evidence.append(
                            {
                                "kind": "slot_assign_nonnull",
                                "call_id": call.get("id"),
                                "method": method_name,
                                "code": code,
                                "guard": guard_info,
                                "depth": depth,
                            }
                        )

        if _matches_callback_invoke(code, slot_aliases, ptr_aliases, direct_target):
            may_called = True
            evidence.append(
                {
                    "kind": "callback_invoke",
                    "call_id": call.get("id"),
                    "method": method_name,
                    "code": code,
                    "guard": guard_info,
                    "depth": depth,
                }
            )

        call_name = call.get("name") or ""
        if not call_name or call_name.startswith("<operator>") or call_name.startswith("<operators>"):
            continue
        if depth >= max_depth:
            continue
        if call_name not in method_calls:
            continue
        params = method_signatures.get(call_name) or []
        args = _extract_call_args(code)
        if not params or not args:
            continue
        for idx, arg in enumerate(args):
            if idx >= len(params):
                break
            alias_kind = _arg_alias_kind_for_callback(arg, slot_aliases, ptr_aliases, direct_target)
            if not alias_kind:
                continue
            child = _scan_callback_reachability(
                method_name=call_name,
                target_expr=params[idx],
                by_ref=(alias_kind == "by_ref"),
                method_calls=method_calls,
                method_signatures=method_signatures,
                control_nodes=control_nodes,
                value_env=value_env,
                max_depth=max_depth,
                depth=depth + 1,
                start_after_id=None,
                stack=local_stack,
            )
            may_called = may_called or child.get("may_called", False)
            saw_null = saw_null or child.get("saw_null", False)
            saw_nonnull = saw_nonnull or child.get("saw_nonnull", False)
            child_evidence = child.get("evidence") or []
            for item in child_evidence:
                merged = dict(item)
                merged["via_call_id"] = call.get("id")
                merged["via_call_code"] = call.get("code")
                merged["via_method"] = method_name
                evidence.append(merged)

    return {
        "may_called": may_called,
        "saw_null": saw_null,
        "saw_nonnull": saw_nonnull,
        "evidence": evidence,
    }


def _evaluate_callback_rule(
    rule: dict,
    calls: List[dict],
    path_bundle: dict,
    runtime: Optional[dict],
    interproc_depth: int,
) -> dict:
    call_name = rule.get("call")
    arg_index = int(rule.get("arg_index") or 0)
    must_be_set = bool(rule.get("must_be_set", True))
    must_be_called = bool(rule.get("must_be_called", False))
    sink_calls = _iter_calls(calls, call_name)
    if not sink_calls:
        return {"type": "callback", "rule": rule, "status": "unknown", "reason": "sink_call_not_found", "evidence": []}

    combined_constraints = list(path_bundle.get("combined_constraints") or [])
    value_env = dict(path_bundle.get("value_env") or {})
    control_nodes = list(path_bundle.get("control_structures_relevant") or [])

    merged = "sat"
    per_call = []

    for sink in sink_calls:
        args = _extract_call_args(sink.get("code") or "")
        if arg_index <= 0:
            per_call.append({"call_id": sink.get("id"), "status": "unknown", "reason": "invalid_arg_index"})
            if merged != "unsat":
                merged = "unknown"
            continue

        arg_missing = arg_index > len(args)
        arg_expr = args[arg_index - 1].strip() if not arg_missing else ""
        observed = _arg_nullability(arg_expr, combined_constraints, value_env) if arg_expr else "unknown"
        flow = _propagate_for_sink(
            sink=sink,
            arg_index=arg_index,
            runtime=runtime,
            control_nodes=control_nodes,
            value_env=value_env,
            interproc_depth=interproc_depth,
        )
        flow_state = dict(flow.get("state") or {})
        trace = list(flow.get("trace") or [])
        unresolved = list(flow.get("unresolved") or [])

        # Also inspect the callee body using formal parameter view.
        method_signatures = dict((runtime or {}).get("method_signatures") or {})
        callee_params = list(method_signatures.get(call_name) or [])
        if callee_params and arg_index <= len(callee_params):
            synthetic_call = {
                "id": 10**18,
                "method": call_name,
                "name": call_name,
                "code": f"{call_name}({', '.join(callee_params)});",
            }
            callee_flow = _propagate_for_sink(
                sink=synthetic_call,
                arg_index=arg_index,
                runtime=runtime,
                control_nodes=control_nodes,
                value_env=value_env,
                interproc_depth=interproc_depth,
            )
            callee_state = dict(callee_flow.get("state") or {})
            callback_invoked_main = dict(flow_state.get("callback_invoked") or {})
            callback_invoked_callee = dict(callee_state.get("callback_invoked") or {})
            flow_state["callback_invoked"] = {
                "must": bool(callback_invoked_main.get("must") or callback_invoked_callee.get("must")),
                "may": bool(callback_invoked_main.get("may") or callback_invoked_callee.get("may")),
            }
            trace.extend(list(callee_flow.get("trace") or []))
            unresolved.extend(list(callee_flow.get("unresolved") or []))

        flow_nullability = _nullability_from_flow_state(flow_state)
        if flow_nullability != "unknown":
            observed = flow_nullability

        reachability = "unknown"
        reach_evidence = [item for item in trace if item.get("kind") == "callback_invoke"]
        callback_invoked = dict(flow_state.get("callback_invoked") or {})
        if observed == "null":
            reachability = "forbid_called"
        elif callback_invoked.get("must") or callback_invoked.get("may"):
            reachability = "may_called"
        else:
            reachability = "unknown"

        if must_be_set:
            if observed == "null":
                status = "unsat"
            elif observed == "nonnull":
                status = "sat"
            else:
                status = "unknown"
        else:
            status = "sat"

        if must_be_called:
            if reachability == "may_called":
                status = "sat" if status != "unsat" else "unsat"
            elif reachability == "forbid_called":
                status = "unsat"
            else:
                status = "unknown" if status != "unsat" else status

        if status == "unsat":
            merged = "unsat"
        elif status == "unknown" and merged != "unsat":
            merged = "unknown"

        per_call.append(
            {
                "call_id": sink.get("id"),
                "code": sink.get("code"),
                "arg_expr": arg_expr,
                "arg_missing": arg_missing,
                "observed": observed,
                "reachability": reachability,
                "status": status,
                "must_be_set": must_be_set,
                "must_be_called": must_be_called,
                "reachability_evidence": reach_evidence,
                "reason": "sink_arg_missing" if arg_missing else None,
                "interproc_trace": trace,
                "interproc_unresolved": unresolved,
            }
        )

    return {"type": "callback", "rule": rule, "status": merged, "reason": None, "evidence": per_call}


def _summarize_status(rule_results: List[dict]) -> str:
    if not rule_results:
        return "unknown"
    statuses = [r.get("status") for r in rule_results]
    if any(s == "unsat" for s in statuses):
        return "unsat"
    if all(s == "sat" for s in statuses):
        return "sat"
    return "unknown"


def _has_abi_contract_rules(abi_contracts: dict) -> bool:
    if not isinstance(abi_contracts, dict):
        return False
    for key in ("ptr_len_pairs", "nullability", "flag_domain", "callback_contracts", "constraints"):
        items = abi_contracts.get(key)
        if isinstance(items, list) and items:
            return True
    return False


def _convert_abi_flag_rules(abi_contracts: dict) -> List[dict]:
    out = []
    for item in list((abi_contracts or {}).get("flag_domain") or []):
        rule = item.get("rule") if isinstance(item, dict) and isinstance(item.get("rule"), dict) else item
        if not isinstance(rule, dict):
            continue
        if not rule.get("call") or not rule.get("arg_index"):
            continue
        out.append(
            {
                "call": rule.get("call"),
                "arg_index": rule.get("arg_index"),
                "requires_all": list(rule.get("requires_all") or []),
                "requires_any": list(rule.get("requires_any") or []),
                "forbids": list(rule.get("forbids") or []),
                "allowed": list(rule.get("allowed") or []),
                "__source": "abi_contracts.flag_domain",
            }
        )
    return out


def _convert_abi_len_rules(abi_contracts: dict) -> List[dict]:
    out = []
    for item in list((abi_contracts or {}).get("ptr_len_pairs") or []):
        rule = item.get("rule") if isinstance(item, dict) and isinstance(item.get("rule"), dict) else item
        if not isinstance(rule, dict):
            continue
        call = rule.get("call")
        len_arg = rule.get("len_arg")
        if not call or not len_arg:
            continue
        len_constraints = list(rule.get("len_constraints") or rule.get("constraints") or [])
        if not len_constraints:
            continue
        out.append(
            {
                "call": call,
                "arg_index": len_arg,
                "constraints": len_constraints,
                "__source": "abi_contracts.ptr_len_pairs",
            }
        )
    return out


def _convert_abi_nonnull_rules(abi_contracts: dict) -> List[dict]:
    out = []
    for item in list((abi_contracts or {}).get("nullability") or []):
        rule = item.get("rule") if isinstance(item, dict) and isinstance(item.get("rule"), dict) else item
        if not isinstance(rule, dict):
            continue
        call = rule.get("call")
        arg_index = rule.get("arg_index")
        must_be = rule.get("must_be")
        if call and arg_index and must_be in {"nonnull", "null"}:
            out.append(
                {
                    "call": call,
                    "arg_index": arg_index,
                    "must_be": must_be,
                    "__source": "abi_contracts.nullability",
                }
            )
    return out


def _convert_abi_callback_rules(abi_contracts: dict) -> List[dict]:
    out = []
    for item in list((abi_contracts or {}).get("callback_contracts") or []):
        rule = item.get("rule") if isinstance(item, dict) and isinstance(item.get("rule"), dict) else item
        if not isinstance(rule, dict):
            continue
        call = rule.get("call")
        arg_index = rule.get("arg_index")
        if not call or not arg_index:
            continue
        out.append(
            {
                "call": call,
                "arg_index": arg_index,
                "must_be_set": bool(rule.get("must_be_set", True)),
                "must_be_called": bool(rule.get("must_be_invocable", rule.get("must_be_called", False))),
                "__source": "abi_contracts.callback_contracts",
            }
        )
    return out


def _build_abi_contract_eval(abi_contracts: dict) -> dict:
    if not isinstance(abi_contracts, dict):
        return {
            "status": "unknown",
            "reason": "abi_contracts_missing",
            "constraints_used": [],
            "conflict_reason": None,
            "evidence": [],
            "boundary_assumptions": [],
        }
    return {
        "status": abi_contracts.get("status", "unknown"),
        "reason": abi_contracts.get("reason"),
        "constraints_used": list(abi_contracts.get("constraints") or []),
        "conflict_reason": abi_contracts.get("conflict_reason"),
        "evidence": list(abi_contracts.get("evidence") or []),
        "boundary_assumptions": list(abi_contracts.get("boundary_assumptions") or []),
        "arg_bindings": list(abi_contracts.get("arg_bindings") or []),
    }


def _collect_traces_from_rule_results(rule_results: List[dict]) -> Tuple[List[dict], List[dict]]:
    traces: List[dict] = []
    unresolved: List[dict] = []
    seen_trace = set()
    seen_unresolved = set()

    for item in rule_results or []:
        if not isinstance(item, dict):
            continue
        # flags_eval stores evidence directly at top-level.
        if item.get("type") == "flags":
            for ev in item.get("evidence") or []:
                if not isinstance(ev, dict):
                    continue
                key = (ev.get("call_id"), ev.get("kind"), ev.get("reason"), ev.get("depth"))
                if key in seen_trace:
                    continue
                seen_trace.add(key)
                traces.append(ev)
            for ur in item.get("unresolved") or []:
                key = str(ur)
                if key in seen_unresolved:
                    continue
                seen_unresolved.add(key)
                unresolved.append(ur)
            continue

        for ev in item.get("evidence") or []:
            if not isinstance(ev, dict):
                continue
            for trace in ev.get("interproc_trace") or []:
                if not isinstance(trace, dict):
                    continue
                key = (trace.get("call_id"), trace.get("kind"), trace.get("reason"), trace.get("depth"))
                if key in seen_trace:
                    continue
                seen_trace.add(key)
                traces.append(trace)
            for ur in ev.get("interproc_unresolved") or []:
                key = str(ur)
                if key in seen_unresolved:
                    continue
                seen_unresolved.add(key)
                unresolved.append(ur)
    return traces, unresolved


def _build_interproc_eval_summary(
    runtime: Optional[dict],
    flags_eval: List[dict],
    len_eval: List[dict],
    nonnull_eval: List[dict],
    callback_eval: List[dict],
) -> dict:
    all_results = list(flags_eval or []) + list(len_eval or []) + list(nonnull_eval or []) + list(callback_eval or [])
    status = _summarize_status(all_results)
    trace, unresolved = _collect_traces_from_rule_results(all_results)

    alias_result = dict((runtime or {}).get("alias_result") or {})
    alias_summary = {
        "must_alias_sets": len(alias_result.get("must_alias_sets") or []),
        "may_alias_entries": len(alias_result.get("may_alias_map") or {}),
        "points_to_entries": len(alias_result.get("points_to") or {}),
    }
    if alias_result.get("unresolved"):
        unresolved.extend(list(alias_result.get("unresolved") or []))
        if status != "unsat":
            status = "unknown"

    return {
        "engine_version": "interproc_v2",
        "status": status,
        "trace": trace,
        "unresolved": unresolved,
        "alias_summary": alias_summary,
    }


def evaluate_param_semantics(
    trigger_model: dict,
    evidence_calls: List[dict],
    control_nodes: List[dict],
    path_bundle: dict,
    solver: Optional[PathConstraintSolver] = None,
    abi_contracts: Optional[dict] = None,
    interproc_depth: int = 2,
) -> dict:
    param_rules = ((trigger_model or {}).get("param_semantics") or {})
    flags_rules = list(param_rules.get("flags") or [])
    len_rules = list(param_rules.get("len") or [])
    nonnull_rules = list(param_rules.get("nonnull") or [])
    enum_rules = list(param_rules.get("enum_range") or [])
    callback_rules = list(param_rules.get("callback") or [])

    abi_contracts = abi_contracts if abi_contracts is not None else dict(path_bundle.get("abi_contracts") or {})
    abi_flag_rules = _convert_abi_flag_rules(abi_contracts)
    abi_len_rules = _convert_abi_len_rules(abi_contracts)
    abi_nonnull_rules = _convert_abi_nonnull_rules(abi_contracts)
    abi_callback_rules = _convert_abi_callback_rules(abi_contracts)

    const_map = dict(path_bundle.get("const_map") or path_bundle.get("constants") or {})
    value_env = dict(path_bundle.get("value_env") or {})
    runtime = _build_interproc_runtime(
        calls=evidence_calls,
        path_bundle=path_bundle,
        const_map=const_map,
        interproc_depth=interproc_depth,
    )

    merged_flags_rules = flags_rules + abi_flag_rules
    merged_len_rules = len_rules + abi_len_rules
    merged_nonnull_rules = nonnull_rules + abi_nonnull_rules
    merged_callback_rules = callback_rules + abi_callback_rules

    flags_eval = [
        _evaluate_flags_rule(
            rule,
            evidence_calls,
            control_nodes,
            const_map,
            value_env,
            path_bundle,
            interproc_depth=interproc_depth,
        )
        for rule in merged_flags_rules
    ]
    len_eval = [
        _evaluate_len_rule(rule, evidence_calls, path_bundle, solver, runtime, interproc_depth)
        for rule in merged_len_rules
    ]
    nonnull_eval = [
        _evaluate_nonnull_rule(rule, evidence_calls, path_bundle, runtime, interproc_depth)
        for rule in merged_nonnull_rules
    ]
    enum_eval = [_evaluate_enum_rule(rule, evidence_calls) for rule in enum_rules]
    callback_eval = [
        _evaluate_callback_rule(rule, evidence_calls, path_bundle, runtime, interproc_depth)
        for rule in merged_callback_rules
    ]

    abi_contract_eval = _build_abi_contract_eval(abi_contracts)
    interproc_eval = _build_interproc_eval_summary(runtime, flags_eval, len_eval, nonnull_eval, callback_eval)

    all_rule_results = flags_eval + len_eval + nonnull_eval + enum_eval + callback_eval
    if _has_abi_contract_rules(abi_contracts):
        all_rule_results = all_rule_results + [{"status": abi_contract_eval.get("status", "unknown")}]
    if interproc_eval.get("status") == "unsat":
        all_rule_results = all_rule_results + [{"status": "unsat"}]
    status = _summarize_status(all_rule_results)
    return {
        "status": status,
        "rules_evaluated": {
            "flags": len(merged_flags_rules),
            "len": len(merged_len_rules),
            "nonnull": len(merged_nonnull_rules),
            "enum_range": len(enum_rules),
            "callback": len(merged_callback_rules),
            "abi_contract_rules": (
                len(list(abi_contracts.get("ptr_len_pairs") or []))
                + len(list(abi_contracts.get("nullability") or []))
                + len(list(abi_contracts.get("flag_domain") or []))
                + len(list(abi_contracts.get("callback_contracts") or []))
            ),
        },
        "flags_eval": flags_eval,
        "len_eval": len_eval,
        "nonnull_eval": nonnull_eval,
        "enum_eval": enum_eval,
        "callback_eval": callback_eval,
        "abi_contract_eval": abi_contract_eval,
        "interproc_eval": interproc_eval,
        "evidence": {
            "control_count": len(control_nodes or []),
            "value_env_keys": sorted(value_env.keys()),
        },
    }
