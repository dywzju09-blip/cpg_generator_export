"""Lightweight inter-procedural flags evaluation.

Goal: improve flags semantics without full symbolic execution.
- Track assignments/bitwise updates for one target flags expression.
- Support simple alias forms (`y = x`, `p = &x`, `*p |= FLAG`).
- Follow calls up to max_depth using method signatures.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from tools.verification.path_solver import parse_condition_expression
from tools.verification.interproc_valueflow import build_interproc_index, propagate_from_sink

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_UPPER_TOKEN_RE = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")
_NUM_TOKEN_RE = re.compile(r"^-?(?:0x[0-9A-Fa-f]+|\d+)$")
_ASSIGN_RE = re.compile(r"^\s*(?P<lhs>[^=]+?)\s*(?P<op>\|=|&=|\^=|=)\s*(?P<rhs>.+?)\s*;?\s*$")
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


def _compact_expr(text: str) -> str:
    return re.sub(r"\s+", "", text or "")


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
        try:
            lhs = int(value_env[var])
            rhs = int(cons.get("value"))
        except Exception:
            continue
        res = _eval_simple_constraint(str(cons.get("operator")), lhs, rhs)
        if res is not None:
            known.append(res)
    if not known:
        return "unknown"
    if all(known):
        return "true"
    if any(v is False for v in known):
        return "false"
    return "unknown"


def _flip_truth(truth: str) -> str:
    if truth == "true":
        return "false"
    if truth == "false":
        return "true"
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


def _guard_for_call(call: dict, control_nodes: List[dict], value_env: Dict[str, int]) -> Tuple[str, dict]:
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
    info = {
        "guard_text": guard_text,
        "guard_truth": guard_truth,
        "branch": branch,
        "control_id": related_control.get("id") if related_control else None,
    }
    if guard_truth == "true":
        return "true", info
    if guard_truth == "false":
        return "false", info
    return "may", info


def _combine_certainty(parent: str, child: str) -> str:
    if parent == "false" or child == "false":
        return "false"
    if parent == "true" and child == "true":
        return "true"
    return "may"


def _simple_ident(text: str) -> Optional[str]:
    tok = str(text or "").strip()
    while tok.startswith("(") and tok.endswith(")") and len(tok) > 2:
        tok = tok[1:-1].strip()
    if _IDENT_RE.match(tok):
        return tok
    return None


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


def _parse_assignment(code: str) -> Optional[dict]:
    if not isinstance(code, str):
        return None
    text = code.strip()
    if "==" in text or "!=" in text or ">=" in text or "<=" in text:
        pass
    match = _ASSIGN_RE.match(text)
    if not match:
        return None
    lhs = (match.group("lhs") or "").strip()
    op = (match.group("op") or "").strip()
    rhs = (match.group("rhs") or "").strip()
    if not lhs or not rhs:
        return None
    return {"lhs": lhs, "op": op, "rhs": rhs}


def _tokens_from_numeric(mask: int, const_map: Dict[str, int]) -> List[str]:
    if not isinstance(mask, int):
        return []
    tokens: List[str] = []
    for name, value in (const_map or {}).items():
        if not isinstance(name, str) or not isinstance(value, int):
            continue
        if value <= 0:
            continue
        if (mask & value) == value:
            tokens.append(name)
    return sorted(set(tokens))


def _extract_flag_tokens(expr: str, const_map: Dict[str, int]) -> Tuple[Set[str], bool]:
    if not isinstance(expr, str):
        return set(), True
    text = expr.strip()
    if not text:
        return set(), True
    tokens = set(_UPPER_TOKEN_RE.findall(text))
    if text in const_map and isinstance(const_map[text], int):
        tokens.add(text)
    number = _coerce_int(text)
    if number is not None:
        tokens.update(_tokens_from_numeric(number, const_map))
        return tokens, False
    unknown = not bool(tokens)
    return tokens, unknown


def _new_state() -> dict:
    return {
        "must_set": set(),
        "may_set": set(),
        "forbid": set(),
        "unknown": False,
        "evidence": [],
    }


def _append_evidence(state: dict, event: dict, reason: str) -> None:
    state["evidence"].append(
        {
            "call_id": event.get("call", {}).get("id"),
            "call_name": event.get("call", {}).get("name"),
            "method": event.get("call", {}).get("method"),
            "code": event.get("call", {}).get("code"),
            "reason": reason,
            "guard": event.get("guard"),
            "depth": event.get("depth"),
            "provenance": event.get("provenance") or {},
        }
    )


def _normalize_assignment_op(lhs: str, op: str, rhs: str) -> Tuple[str, str]:
    if op != "=":
        return op, rhs
    lhs_ident = _simple_ident(lhs)
    if not lhs_ident:
        return op, rhs

    rhs_text = str(rhs or "").strip()
    escaped_lhs = re.escape(lhs_ident)

    or_m = re.match(rf"^\s*{escaped_lhs}\s*\|\s*(.+)$", rhs_text) or re.match(rf"^\s*(.+)\|\s*{escaped_lhs}\s*$", rhs_text)
    if or_m:
        return "|=", or_m.group(1).strip()

    xor_m = re.match(rf"^\s*{escaped_lhs}\s*\^\s*(.+)$", rhs_text) or re.match(rf"^\s*(.+)\^\s*{escaped_lhs}\s*$", rhs_text)
    if xor_m:
        return "^=", xor_m.group(1).strip()

    and_not_m = re.match(rf"^\s*{escaped_lhs}\s*&\s*~\s*(.+)$", rhs_text) or re.match(rf"^\s*~\s*(.+)&\s*{escaped_lhs}\s*$", rhs_text)
    if and_not_m:
        return "&=", f"~{and_not_m.group(1).strip()}"

    return op, rhs


def _apply_event(state: dict, event: dict, const_map: Dict[str, int]) -> None:
    certainty = event.get("certainty") or "may"
    if certainty == "false":
        _append_evidence(state, event, "assignment_guarded_out")
        return

    op = event.get("op")
    rhs = event.get("rhs") or ""
    tokens, expr_unknown = _extract_flag_tokens(rhs, const_map)
    if expr_unknown:
        state["unknown"] = True

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

    _append_evidence(state, event, f"applied_{mode}_{op}")


def _lhs_targets_target(lhs: str, tracked_values: Set[str], ptr_aliases: Set[str], direct_target: str) -> bool:
    lhs_ident = _simple_ident(lhs)
    if lhs_ident and lhs_ident in tracked_values:
        return True

    deref_ident = _deref_ident(lhs)
    if deref_ident and deref_ident in ptr_aliases:
        return True

    if direct_target and _compact_expr(lhs) == direct_target:
        return True
    return False


def _update_aliases(
    parsed: dict,
    tracked_values: Set[str],
    ptr_aliases: Set[str],
    direct_target: str,
    root_target: Optional[str],
) -> None:
    if parsed.get("op") != "=":
        return
    lhs_ident = _simple_ident(parsed.get("lhs") or "")
    if not lhs_ident:
        return

    rhs = parsed.get("rhs") or ""
    rhs_ident = _simple_ident(rhs)
    rhs_addr = _address_of_ident(rhs)

    if rhs_ident and rhs_ident in tracked_values:
        tracked_values.add(lhs_ident)
    elif rhs_ident and rhs_ident in ptr_aliases:
        ptr_aliases.add(lhs_ident)
    elif rhs_addr and rhs_addr in tracked_values:
        ptr_aliases.add(lhs_ident)
    elif direct_target and _compact_expr(rhs) == direct_target:
        tracked_values.add(lhs_ident)
    else:
        # Conservative kill for overwritten aliases.
        if lhs_ident in tracked_values and lhs_ident != root_target:
            tracked_values.discard(lhs_ident)
        if lhs_ident in ptr_aliases and lhs_ident != root_target:
            ptr_aliases.discard(lhs_ident)


def _arg_alias_kind(arg_expr: str, tracked_values: Set[str], ptr_aliases: Set[str], direct_target: str) -> Optional[str]:
    expr = str(arg_expr or "").strip()
    if not expr:
        return None
    if direct_target and _compact_expr(expr) == direct_target:
        return "value"

    ident = _simple_ident(expr)
    if ident and ident in tracked_values:
        return "value"
    if ident and ident in ptr_aliases:
        return "by_ref"

    addr = _address_of_ident(expr)
    if addr and addr in tracked_values:
        return "by_ref"

    deref = _deref_ident(expr)
    if deref and deref in ptr_aliases:
        return "value"
    return None


def _build_method_index(calls: List[dict]) -> Dict[str, List[dict]]:
    methods: Dict[str, List[dict]] = {}
    for call in calls or []:
        method = call.get("method")
        if not method:
            continue
        methods.setdefault(method, []).append(call)
    for items in methods.values():
        items.sort(key=lambda c: int(c.get("id") or 10**18))
    return methods


def _collect_updates_for_target(
    method_name: str,
    target_expr: str,
    by_ref: bool,
    method_calls: Dict[str, List[dict]],
    method_signatures: Dict[str, List[str]],
    control_nodes: List[dict],
    value_env: Dict[str, int],
    max_depth: int,
    depth: int,
    until_call_id: Optional[int],
    stack: Set[Tuple[str, str, bool]],
) -> List[dict]:
    if depth > max_depth:
        return []
    key = (method_name or "", target_expr or "", bool(by_ref))
    if key in stack:
        return []

    calls = method_calls.get(method_name) or []
    if not calls:
        return []

    local_stack = set(stack)
    local_stack.add(key)

    tracked_values: Set[str] = set()
    ptr_aliases: Set[str] = set()
    target_ident = _simple_ident(target_expr or "")
    root_target = target_ident
    direct_target = ""
    if target_ident:
        if by_ref:
            ptr_aliases.add(target_ident)
        else:
            tracked_values.add(target_ident)
    else:
        direct_target = _compact_expr(target_expr or "")

    updates: List[dict] = []
    for call in calls:
        cid = call.get("id")
        if until_call_id is not None:
            try:
                if cid is not None and int(cid) >= int(until_call_id):
                    break
            except Exception:
                pass

        code = call.get("code") or ""
        parsed = _parse_assignment(code)
        if parsed is not None:
            lhs = parsed.get("lhs") or ""
            if _lhs_targets_target(lhs, tracked_values, ptr_aliases, direct_target):
                certainty, guard_info = _guard_for_call(call, control_nodes, value_env)
                norm_op, norm_rhs = _normalize_assignment_op(lhs, parsed.get("op") or "", parsed.get("rhs") or "")
                updates.append(
                    {
                        "call": call,
                        "lhs": lhs,
                        "op": norm_op,
                        "rhs": norm_rhs,
                        "certainty": certainty,
                        "guard": guard_info,
                        "depth": depth,
                        "provenance": {},
                    }
                )
            _update_aliases(parsed, tracked_values, ptr_aliases, direct_target, root_target)
            continue

        call_name = call.get("name") or ""
        if not call_name or call_name.startswith("<operator>") or call_name.startswith("<operators>"):
            continue
        if depth >= max_depth:
            continue
        if call_name not in method_calls:
            continue

        args = _extract_call_args(code)
        params = method_signatures.get(call_name) or []
        if not args or not params:
            continue

        call_certainty, call_guard = _guard_for_call(call, control_nodes, value_env)
        if call_certainty == "false":
            continue

        for idx, arg in enumerate(args):
            if idx >= len(params):
                break
            alias_kind = _arg_alias_kind(arg, tracked_values, ptr_aliases, direct_target)
            if not alias_kind:
                continue
            child_target = params[idx]
            child_by_ref = alias_kind == "by_ref"
            child_updates = _collect_updates_for_target(
                method_name=call_name,
                target_expr=child_target,
                by_ref=child_by_ref,
                method_calls=method_calls,
                method_signatures=method_signatures,
                control_nodes=control_nodes,
                value_env=value_env,
                max_depth=max_depth,
                depth=depth + 1,
                until_call_id=None,
                stack=local_stack,
            )
            for child in child_updates:
                merged = dict(child)
                merged["certainty"] = _combine_certainty(call_certainty, child.get("certainty") or "may")
                prov = dict(merged.get("provenance") or {})
                prov["via_call_id"] = call.get("id")
                prov["via_call_code"] = call.get("code")
                prov["via_method"] = method_name
                prov["via_guard"] = call_guard
                merged["provenance"] = prov
                updates.append(merged)

    return updates


def evaluate_flags_interproc(
    rule: dict,
    calls: List[dict],
    control_nodes: List[dict],
    const_map: Dict[str, int],
    value_env: Dict[str, int],
    path_bundle: Optional[dict] = None,
    max_depth: int = 2,
) -> dict:
    call_name = rule.get("call")
    arg_index = int(rule.get("arg_index") or 0)
    requires_all = list(rule.get("requires_all") or [])
    requires_any = list(rule.get("requires_any") or [])
    forbids = list(rule.get("forbids") or [])
    allowed = set(rule.get("allowed") or [])

    sink_calls = _iter_calls(calls, call_name)
    if not sink_calls:
        return {
            "type": "flags",
            "engine": "interproc_v2",
            "engine_version": "interproc_v2",
            "rule": rule,
            "status": "unknown",
            "reason": "sink_call_not_found",
            "state": {"must_set": [], "may_set": [], "forbid": [], "unknown": True},
            "evidence": [],
        }

    method_signatures = dict((path_bundle or {}).get("method_signatures") or {})
    interproc_context = dict((path_bundle or {}).get("interproc_context") or {})
    index_calls = list(interproc_context.get("method_calls") or calls or [])
    index = build_interproc_index(index_calls, method_signatures)
    index["const_map"] = dict(const_map or {})

    state = _new_state()
    unresolved: List[dict] = []
    for sink in sink_calls:
        if arg_index <= 0:
            state["unknown"] = True
            state["evidence"].append(
                {
                    "call_id": sink.get("id"),
                    "call_name": sink.get("name"),
                    "method": sink.get("method"),
                    "code": sink.get("code"),
                    "reason": "sink_arg_missing",
                    "guard": {"guard_text": None, "guard_truth": "unknown", "branch": "unknown", "control_id": None},
                    "depth": 0,
                    "provenance": {},
                }
            )
            continue

        flow = propagate_from_sink(
            index=index,
            sink_call=sink,
            arg_index=arg_index,
            controls=control_nodes,
            value_env=value_env,
            max_depth=max_depth,
        )
        flow_state = dict(flow.get("state") or {})
        state["must_set"].update(flow_state.get("flags_must") or [])
        state["may_set"].update(flow_state.get("flags_may") or [])
        state["forbid"].update(flow_state.get("flags_forbid") or [])
        if flow_state.get("unknown"):
            state["unknown"] = True

        unresolved.extend(list(flow.get("unresolved") or []))
        for trace in flow.get("trace") or []:
            if not isinstance(trace, dict):
                continue
            state["evidence"].append(
                {
                    "call_id": trace.get("call_id"),
                    "call_name": sink.get("name"),
                    "method": trace.get("method"),
                    "code": trace.get("code"),
                    "reason": trace.get("reason"),
                    "guard": trace.get("guard"),
                    "depth": trace.get("depth"),
                    "provenance": trace.get("provenance") or {},
                    "kind": trace.get("kind"),
                }
            )

    must_set = set(state["must_set"])
    may_set = set(state["may_set"])
    forbid_set = set(state["forbid"])

    unsat_reasons = []
    if allowed:
        for tok in requires_all:
            if tok not in allowed:
                unsat_reasons.append(f"required_token_outside_allowed:{tok}")
        for tok in requires_any:
            if tok not in allowed:
                unsat_reasons.append(f"requires_any_token_outside_allowed:{tok}")
    overlap = set(requires_all) & set(forbids)
    for tok in sorted(overlap):
        unsat_reasons.append(f"required_and_forbidden:{tok}")
    for tok in requires_all:
        if tok in forbid_set:
            unsat_reasons.append(f"required_token_forbidden:{tok}")
        elif tok not in must_set and tok not in may_set and not state["unknown"]:
            unsat_reasons.append(f"required_token_absent:{tok}")
    for tok in forbids:
        if tok in must_set:
            unsat_reasons.append(f"forbidden_token_must_set:{tok}")
    if allowed:
        disallowed_must = sorted(tok for tok in must_set if tok not in allowed)
        for tok in disallowed_must:
            unsat_reasons.append(f"disallowed_token_must_set:{tok}")
    if requires_any:
        if not any(tok in must_set or tok in may_set for tok in requires_any) and not state["unknown"]:
            unsat_reasons.append("requires_any_absent")

    if unsat_reasons:
        status = "unsat"
    else:
        all_required = all(tok in must_set for tok in requires_all) if requires_all else True
        any_required = any(tok in must_set for tok in requires_any) if requires_any else True
        any_forbidden = any(tok in must_set or tok in may_set for tok in forbids)
        if all_required and any_required and not any_forbidden and not state["unknown"]:
            status = "sat"
        else:
            status = "unknown"

    return {
        "type": "flags",
        "engine": "interproc_v2",
        "engine_version": "interproc_v2",
        "rule": rule,
        "status": status,
        "reason": unsat_reasons if unsat_reasons else None,
        "state": {
            "must_set": sorted(must_set),
            "may_set": sorted(may_set),
            "forbid": sorted(forbid_set),
            "unknown": bool(state["unknown"]),
        },
        "evidence": state["evidence"],
        "unresolved": unresolved,
    }
