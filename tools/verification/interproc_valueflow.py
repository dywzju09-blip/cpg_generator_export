"""General inter-procedural value-flow propagation (interproc_v2).

This module unifies propagation for:
- flags bitmasks
- numeric interval hints
- nullability
- callback assignment / invocation evidence

The design is intentionally conservative and reports unresolved edges instead of
forcing overly precise conclusions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from tools.verification.alias_analysis import analyze_aliases
from tools.verification.path_solver import parse_condition_expression

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TOKEN_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_UPPER_TOKEN_RE = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")
_NUM_TOKEN_RE = re.compile(r"^-?(?:0x[0-9A-Fa-f]+|\d+)$")
_ASSIGN_RE = re.compile(r"^\s*(?P<lhs>[^=]+?)\s*(?P<op>\|=|&=|\^=|=)\s*(?P<rhs>.+?)\s*;?\s*$")
_ADDRESS_OF_RE = re.compile(r"^\s*&\s*([A-Za-z_][A-Za-z0-9_]*)\s*$")
_DEREF_RE = re.compile(r"^\s*\(?\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)?\s*$")
_NULL_LITERALS = {"0", "NULL", "nullptr"}


@dataclass
class ValueState:
    constants: Set[str] = field(default_factory=set)
    intervals: Dict[str, List[Optional[int]]] = field(default_factory=dict)
    flags_must: Set[str] = field(default_factory=set)
    flags_may: Set[str] = field(default_factory=set)
    flags_forbid: Set[str] = field(default_factory=set)
    null_must: bool = False
    nonnull_must: bool = False
    null_may: bool = False
    nonnull_may: bool = False
    callback_targets: Set[str] = field(default_factory=set)
    callback_invoked_must: bool = False
    callback_invoked_may: bool = False
    unknown: bool = False

    def to_dict(self) -> dict:
        return {
            "constants": sorted(self.constants),
            "intervals": {k: list(v) for k, v in sorted(self.intervals.items())},
            "flags_must": sorted(self.flags_must),
            "flags_may": sorted(self.flags_may),
            "flags_forbid": sorted(self.flags_forbid),
            "nullability": {
                "must_null": bool(self.null_must),
                "must_nonnull": bool(self.nonnull_must),
                "may_null": bool(self.null_may),
                "may_nonnull": bool(self.nonnull_may),
                "unknown": bool(self.unknown),
            },
            "callback_targets": sorted(self.callback_targets),
            "callback_invoked": {
                "must": bool(self.callback_invoked_must),
                "may": bool(self.callback_invoked_may),
            },
            "unknown": bool(self.unknown),
        }


@dataclass
class FlowTrace:
    call_id: Optional[int]
    method: Optional[str]
    code: Optional[str]
    guard: dict
    depth: int
    provenance: dict
    kind: str
    reason: str

    def to_dict(self) -> dict:
        return {
            "call_id": self.call_id,
            "method": self.method,
            "code": self.code,
            "guard": self.guard,
            "depth": self.depth,
            "provenance": self.provenance,
            "kind": self.kind,
            "reason": self.reason,
        }


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


def _slot(method: str, ident: str) -> str:
    return f"{method}::{ident}"


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
            token = "".join(buf).strip()
            if token:
                args.append(token)
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


def _simple_ident(text: str) -> Optional[str]:
    token = str(text or "").strip()
    while token.startswith("(") and token.endswith(")") and len(token) > 2:
        token = token[1:-1].strip()
    if _IDENT_RE.match(token):
        return token
    return None


def _address_of_ident(text: str) -> Optional[str]:
    match = _ADDRESS_OF_RE.match(str(text or ""))
    return match.group(1) if match else None


def _deref_ident(text: str) -> Optional[str]:
    match = _DEREF_RE.match(str(text or ""))
    return match.group(1) if match else None


def _compact_expr(text: str) -> str:
    return re.sub(r"\s+", "", text or "")


def _normalize_ws(text: str) -> str:
    return " ".join((text or "").split())


def _parse_assignment(code: str) -> Optional[dict]:
    if not isinstance(code, str):
        return None
    match = _ASSIGN_RE.match(code.strip())
    if not match:
        return None
    lhs = (match.group("lhs") or "").strip()
    op = (match.group("op") or "").strip()
    rhs = (match.group("rhs") or "").strip()
    if not lhs or not rhs:
        return None
    return {"lhs": lhs, "op": op, "rhs": rhs}


def _normalize_assignment_op(lhs: str, op: str, rhs: str) -> Tuple[str, str]:
    """Normalize `x = x | Y` and `x = x & ~Y` into compound updates."""
    if op != "=":
        return op, rhs

    lhs_ident = _simple_ident(lhs)
    rhs_text = str(rhs or "").strip()
    if lhs_ident:
        escaped_lhs = re.escape(lhs_ident)
        or_match = re.match(rf"^\s*{escaped_lhs}\s*\|\s*(.+)$", rhs_text) or re.match(
            rf"^\s*(.+)\|\s*{escaped_lhs}\s*$", rhs_text
        )
        if or_match:
            return "|=", or_match.group(1).strip()

        xor_match = re.match(rf"^\s*{escaped_lhs}\s*\^\s*(.+)$", rhs_text) or re.match(
            rf"^\s*(.+)\^\s*{escaped_lhs}\s*$", rhs_text
        )
        if xor_match:
            return "^=", xor_match.group(1).strip()

        and_not_match = re.match(rf"^\s*{escaped_lhs}\s*&\s*~\s*(.+)$", rhs_text) or re.match(
            rf"^\s*~\s*(.+)&\s*{escaped_lhs}\s*$", rhs_text
        )
        if and_not_match:
            return "&=", f"~{and_not_match.group(1).strip()}"

    # Generic compact fallback also supports deref lhs (`*p = *p | FLAG`).
    lhs_compact = _compact_expr(lhs)
    rhs_compact = _compact_expr(rhs_text)
    if lhs_compact and rhs_compact.startswith(lhs_compact + "|"):
        return "|=", rhs_compact[len(lhs_compact) + 1 :]
    if lhs_compact and rhs_compact.endswith("|" + lhs_compact):
        return "|=", rhs_compact[: -len(lhs_compact) - 1]
    if lhs_compact and rhs_compact.startswith(lhs_compact + "^"):
        return "^=", rhs_compact[len(lhs_compact) + 1 :]
    if lhs_compact and rhs_compact.endswith("^" + lhs_compact):
        return "^=", rhs_compact[: -len(lhs_compact) - 1]
    if lhs_compact and rhs_compact.startswith(lhs_compact + "&~"):
        return "&=", "~" + rhs_compact[len(lhs_compact) + 2 :]
    if lhs_compact and rhs_compact.startswith("~") and rhs_compact.endswith("&" + lhs_compact):
        return "&=", "~" + rhs_compact[1 : -len(lhs_compact) - 1]

    return op, rhs


def _extract_guard_constraints(control_node: dict) -> Tuple[str, List[dict]]:
    candidates: List[str] = []
    for child in control_node.get("child_codes") or []:
        if isinstance(child, str) and child.strip():
            candidates.append(child)
    code = control_node.get("code")
    if isinstance(code, str) and code.strip():
        candidates.append(code)

    for candidate in candidates:
        parsed = parse_condition_expression(candidate)
        if parsed:
            return candidate, parsed
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
    known: List[bool] = []
    for cons in guard_constraints:
        variable = cons.get("variable")
        if variable not in value_env:
            continue
        try:
            lhs = int(value_env[variable])
            rhs = int(cons.get("value"))
        except Exception:
            continue
        evaluated = _eval_simple_constraint(str(cons.get("operator")), lhs, rhs)
        if evaluated is not None:
            known.append(evaluated)
    if not known:
        return "unknown"
    if all(known):
        return "true"
    if any(item is False for item in known):
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
        for text in texts:
            if normalized_stmt and normalized_stmt in _normalize_ws(text):
                matched = True
                break
        if not matched:
            continue
        depth = node.get("depth")
        depth_value = depth if isinstance(depth, int) else 10**9
        score = (depth_value, len(code or ""))
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
    return tokens, (not bool(tokens))


def _contains_callback_name(token: str) -> bool:
    lowered = (token or "").lower()
    return (
        "callback" in lowered
        or lowered.endswith("_cb")
        or lowered.startswith("cb_")
        or "handler" in lowered
        or "hook" in lowered
        or lowered.startswith("on_")
    )


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
    rhs_deref = _deref_ident(rhs)

    if rhs_ident and rhs_ident in tracked_values:
        tracked_values.add(lhs_ident)
    elif rhs_ident and rhs_ident in ptr_aliases:
        ptr_aliases.add(lhs_ident)
    elif rhs_addr and rhs_addr in tracked_values:
        ptr_aliases.add(lhs_ident)
    elif rhs_deref and rhs_deref in ptr_aliases:
        tracked_values.add(lhs_ident)
    elif direct_target and _compact_expr(rhs) == direct_target:
        tracked_values.add(lhs_ident)
    else:
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


def _matches_callback_invoke(code: str, tracked_values: Set[str], ptr_aliases: Set[str], direct_target: str) -> bool:
    if not isinstance(code, str):
        return False
    if direct_target:
        if re.search(rf"{re.escape(direct_target)}\s*\(", _compact_expr(code)):
            return True
    for name in tracked_values:
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


def _extract_identifiers(text: str) -> Set[str]:
    out: Set[str] = set()
    for token in _TOKEN_IDENT_RE.findall(text or ""):
        if token in {"if", "else", "while", "for", "switch", "return", "true", "false", "NULL"}:
            continue
        out.add(token)
    return out


def _collect_events_for_target(
    method_name: str,
    target_expr: str,
    by_ref: bool,
    index: dict,
    controls: List[dict],
    value_env: Dict[str, int],
    max_depth: int,
    depth: int,
    until_call_id: Optional[int],
    stack: Set[Tuple[str, str, bool]],
) -> Tuple[List[dict], Set[str], List[dict]]:
    if depth > max_depth:
        return [], set(), [{"kind": "max_depth_reached", "method": method_name, "target": target_expr, "depth": depth}]

    key = (method_name or "", target_expr or "", bool(by_ref))
    if key in stack:
        return [], set(), [{"kind": "cycle_truncated", "method": method_name, "target": target_expr, "depth": depth}]

    calls = list(index.get("calls_by_method", {}).get(method_name) or [])
    if not calls:
        return [], set(), [{"kind": "method_calls_missing", "method": method_name, "target": target_expr, "depth": depth}]

    local_stack = set(stack)
    local_stack.add(key)

    target_ident = _simple_ident(target_expr)
    root_target = target_ident
    direct_target = ""
    tracked_values: Set[str] = set()
    ptr_aliases: Set[str] = set()
    related_symbols: Set[str] = set()
    unresolved: List[dict] = []

    if target_ident:
        related_symbols.add(target_ident)
        if by_ref:
            ptr_aliases.add(target_ident)
        else:
            tracked_values.add(target_ident)
    else:
        direct_target = _compact_expr(target_expr)
        related_symbols.update(_extract_identifiers(target_expr))

    events: List[dict] = []
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
            rhs = parsed.get("rhs") or ""
            if _lhs_targets_target(lhs, tracked_values, ptr_aliases, direct_target):
                certainty, guard = _guard_for_call(call, controls, value_env)
                norm_op, norm_rhs = _normalize_assignment_op(lhs, parsed.get("op") or "", rhs)
                events.append(
                    {
                        "kind": "assign",
                        "call": call,
                        "lhs": lhs,
                        "op": norm_op,
                        "rhs": norm_rhs,
                        "certainty": certainty,
                        "guard": guard,
                        "depth": depth,
                        "provenance": {},
                    }
                )
                related_symbols.update(_extract_identifiers(lhs))
                related_symbols.update(_extract_identifiers(norm_rhs))
            _update_aliases(parsed, tracked_values, ptr_aliases, direct_target, root_target)

        if _matches_callback_invoke(code, tracked_values, ptr_aliases, direct_target):
            certainty, guard = _guard_for_call(call, controls, value_env)
            events.append(
                {
                    "kind": "callback_invoke",
                    "call": call,
                    "certainty": certainty,
                    "guard": guard,
                    "depth": depth,
                    "provenance": {},
                }
            )

        call_name = str(call.get("name") or "")
        if not call_name or call_name.startswith("<operator>") or call_name.startswith("<operators>"):
            continue
        if depth >= max_depth:
            continue
        if call_name not in index.get("calls_by_method", {}):
            continue

        args = _extract_call_args(code)
        params = list(index.get("method_signatures", {}).get(call_name) or [])
        if not args or not params:
            unresolved.append(
                {
                    "kind": "call_signature_or_args_missing",
                    "call_id": call.get("id"),
                    "method": method_name,
                    "callee": call_name,
                    "depth": depth,
                }
            )
            continue

        call_certainty, call_guard = _guard_for_call(call, controls, value_env)
        if call_certainty == "false":
            continue

        for idx, arg in enumerate(args):
            if idx >= len(params):
                break
            alias_kind = _arg_alias_kind(arg, tracked_values, ptr_aliases, direct_target)
            if not alias_kind:
                continue

            child_target = params[idx]
            child_events, child_symbols, child_unresolved = _collect_events_for_target(
                method_name=call_name,
                target_expr=child_target,
                by_ref=(alias_kind == "by_ref"),
                index=index,
                controls=controls,
                value_env=value_env,
                max_depth=max_depth,
                depth=depth + 1,
                until_call_id=None,
                stack=local_stack,
            )
            related_symbols.update(child_symbols)
            unresolved.extend(child_unresolved)

            for child in child_events:
                merged = dict(child)
                merged["certainty"] = _combine_certainty(call_certainty, child.get("certainty") or "may")
                provenance = dict(merged.get("provenance") or {})
                provenance["via_call_id"] = call.get("id")
                provenance["via_call_code"] = call.get("code")
                provenance["via_method"] = method_name
                provenance["via_guard"] = call_guard
                merged["provenance"] = provenance
                events.append(merged)

    return events, related_symbols, unresolved


def _apply_flag_update(state: ValueState, op: str, rhs: str, certainty: str, const_map: Dict[str, int]) -> None:
    tokens, unknown_expr = _extract_flag_tokens(rhs, const_map)
    if unknown_expr:
        state.unknown = True
    if certainty == "false":
        return

    mode = "must" if certainty == "true" else "may"
    if mode == "may":
        state.unknown = True

    if op == "=":
        if mode == "must":
            old_must = set(state.flags_must)
            state.flags_must = set(tokens)
            state.flags_may.update(tokens)
            removed = old_must - set(tokens)
            state.flags_forbid.update(removed)
        else:
            state.flags_may.update(tokens)
    elif op == "|=":
        if mode == "must":
            state.flags_must.update(tokens)
        state.flags_may.update(tokens)
        state.flags_forbid.difference_update(tokens)
    elif op == "&=" and rhs.strip().startswith("~"):
        clear_tokens, clear_unknown = _extract_flag_tokens(rhs.strip()[1:].strip(), const_map)
        if clear_unknown:
            state.unknown = True
        if mode == "must":
            state.flags_must.difference_update(clear_tokens)
            state.flags_may.difference_update(clear_tokens)
            state.flags_forbid.update(clear_tokens)
        else:
            state.unknown = True
    elif op == "&=":
        if mode == "must":
            allow = set(tokens)
            removed = set(state.flags_must) | set(state.flags_may)
            removed.difference_update(allow)
            state.flags_must.intersection_update(allow)
            state.flags_may.intersection_update(allow)
            state.flags_forbid.update(removed)
        else:
            state.unknown = True
            state.flags_may.update(tokens)
    elif op == "^=":
        if mode == "must":
            for token in tokens:
                if token in state.flags_must:
                    state.flags_must.remove(token)
                    state.flags_forbid.add(token)
                elif token in state.flags_forbid:
                    state.flags_forbid.remove(token)
                    state.flags_must.add(token)
                else:
                    state.flags_may.add(token)
                    state.unknown = True
        else:
            state.flags_may.update(tokens)
            state.unknown = True
    else:
        state.unknown = True


def _set_interval(state: ValueState, name: str, lo: Optional[int], hi: Optional[int]) -> None:
    state.intervals[name] = [lo, hi]


def _apply_interval_update(state: ValueState, lhs: str, op: str, rhs: str, certainty: str) -> None:
    if certainty == "false":
        return

    lhs_ident = _simple_ident(lhs)
    if not lhs_ident:
        lhs_ident = _deref_ident(lhs)
    if not lhs_ident:
        return

    rhs_number = _coerce_int(rhs)
    rhs_ident = _simple_ident(rhs)

    if op == "=" and rhs_number is not None:
        _set_interval(state, lhs_ident, rhs_number, rhs_number)
        state.constants.add(str(rhs_number))
        return

    if op == "=" and rhs_ident and rhs_ident in state.intervals:
        _set_interval(state, lhs_ident, state.intervals[rhs_ident][0], state.intervals[rhs_ident][1])
        return

    lhs_interval = state.intervals.get(lhs_ident)
    if not lhs_interval or lhs_interval[0] != lhs_interval[1]:
        return
    current = lhs_interval[0]
    if current is None:
        return

    if rhs_number is None and rhs.startswith("~"):
        rhs_number = _coerce_int(rhs[1:].strip())
        if rhs_number is not None:
            rhs_number = ~rhs_number

    if rhs_number is None:
        return

    updated = None
    if op == "|=":
        updated = int(current) | int(rhs_number)
    elif op == "&=":
        updated = int(current) & int(rhs_number)
    elif op == "^=":
        updated = int(current) ^ int(rhs_number)

    if updated is not None:
        _set_interval(state, lhs_ident, updated, updated)
        state.constants.add(str(updated))


def _mark_nullability(state: ValueState, nullable: Optional[bool], certainty: str) -> None:
    if nullable is None or certainty == "false":
        return
    if certainty == "true":
        if nullable:
            state.null_must = True
            state.null_may = True
        else:
            state.nonnull_must = True
            state.nonnull_may = True
        return

    # may-branch
    state.unknown = True
    if nullable:
        state.null_may = True
    else:
        state.nonnull_may = True


def _infer_expr_nullability(expr: str) -> Optional[bool]:
    text = str(expr or "").strip()
    if not text:
        return None
    if text in _NULL_LITERALS:
        return True
    num = _coerce_int(text)
    if num is not None:
        return num == 0
    if _address_of_ident(text):
        return False
    if text.lower().startswith("some("):
        return False
    return None


def _apply_nullability_update(state: ValueState, op: str, rhs: str, certainty: str) -> None:
    if op != "=":
        return
    nullable = _infer_expr_nullability(rhs)
    _mark_nullability(state, nullable, certainty)


def _apply_callback_target_update(state: ValueState, op: str, rhs: str, certainty: str) -> None:
    if op != "=" or certainty == "false":
        return
    rhs_ident = _simple_ident(rhs)
    if not rhs_ident:
        return
    if not _contains_callback_name(rhs_ident):
        return
    state.callback_targets.add(rhs_ident)


def _serialize_trace(event: dict, reason: str) -> FlowTrace:
    call = event.get("call") or {}
    return FlowTrace(
        call_id=call.get("id"),
        method=call.get("method"),
        code=call.get("code"),
        guard=event.get("guard") or {},
        depth=int(event.get("depth") or 0),
        provenance=dict(event.get("provenance") or {}),
        kind=str(event.get("kind") or "unknown"),
        reason=reason,
    )


def build_interproc_index(calls: List[dict], method_signatures: Dict[str, List[str]]) -> dict:
    """Build method/call index for inter-procedural propagation."""

    rows = [c for c in (calls or []) if isinstance(c, dict)]
    rows.sort(key=lambda c: (str(c.get("method") or ""), int(c.get("id") or 10**18)))

    by_method: Dict[str, List[dict]] = {}
    for call in rows:
        method = call.get("method")
        if not method:
            continue
        by_method.setdefault(method, []).append(call)

    call_edges = []
    seen_edges: Set[Tuple[str, str, int]] = set()
    for call in rows:
        caller = str(call.get("method") or "")
        callee = str(call.get("name") or "")
        cid = int(call.get("id") or -1)
        if not caller or not callee:
            continue
        if callee not in by_method and callee not in method_signatures:
            continue
        edge = (caller, callee, cid)
        if edge in seen_edges:
            continue
        seen_edges.add(edge)
        call_edges.append({"caller": caller, "callee": callee, "call_id": cid})

    return {
        "calls": rows,
        "calls_by_method": by_method,
        "method_signatures": dict(method_signatures or {}),
        "call_graph_edges": call_edges,
        "engine_version": "interproc_v2",
    }


def propagate_from_sink(
    index: dict,
    sink_call: dict,
    arg_index: int,
    controls: List[dict],
    value_env: Dict[str, int],
    max_depth: int,
) -> dict:
    """Propagate value facts from a sink argument through wrappers and aliases."""

    state = ValueState()
    traces: List[FlowTrace] = []
    unresolved: List[dict] = []
    controls = list(controls or [])
    value_env = dict(value_env or {})

    const_map = dict(index.get("const_map") or {})
    if not const_map:
        # Reuse uppercase numeric bindings from environment when available.
        for key, value in value_env.items():
            if isinstance(key, str) and key.upper() == key and isinstance(value, int):
                const_map[key] = int(value)

    call_code = sink_call.get("code") or ""
    args = _extract_call_args(call_code)
    if arg_index <= 0 or arg_index > len(args):
        unresolved.append(
            {
                "kind": "sink_arg_missing",
                "call_id": sink_call.get("id"),
                "arg_index": arg_index,
                "code": call_code,
            }
        )
        return {
            "engine_version": "interproc_v2",
            "status": "unknown",
            "state": state.to_dict(),
            "trace": [],
            "unresolved": unresolved,
            "target_expr": "",
            "related_symbols": [],
            "alias_result": analyze_aliases(index.get("calls") or [], index.get("method_signatures") or {}, max_depth=max_depth),
        }

    target_expr = args[arg_index - 1].strip()
    related_symbols = set(_extract_identifiers(target_expr))

    # Direct sink expression facts.
    direct_flags, direct_unknown = _extract_flag_tokens(target_expr, const_map)
    if direct_flags:
        state.flags_must.update(direct_flags)
        state.flags_may.update(direct_flags)
        traces.append(
            FlowTrace(
                call_id=sink_call.get("id"),
                method=sink_call.get("method"),
                code=sink_call.get("code"),
                guard={"guard_truth": "true", "branch": "direct_arg", "control_id": None, "guard_text": None},
                depth=0,
                provenance={},
                kind="direct_sink_flags",
                reason="sink_expr_tokens",
            )
        )
    if direct_unknown and not _simple_ident(target_expr):
        state.unknown = True

    direct_num = _coerce_int(target_expr)
    if direct_num is not None:
        key = f"arg_{arg_index}_value"
        state.constants.add(str(direct_num))
        state.intervals[key] = [direct_num, direct_num]
        related_symbols.add(key)

    direct_nullable = _infer_expr_nullability(target_expr)
    if direct_nullable is not None:
        _mark_nullability(state, direct_nullable, "true")

    sink_method = sink_call.get("method")
    events: List[dict] = []
    event_symbols: Set[str] = set()
    event_unresolved: List[dict] = []

    if sink_method and sink_method in index.get("calls_by_method", {}) and target_expr:
        events, event_symbols, event_unresolved = _collect_events_for_target(
            method_name=sink_method,
            target_expr=target_expr,
            by_ref=False,
            index=index,
            controls=controls,
            value_env=value_env,
            max_depth=max_depth,
            depth=0,
            until_call_id=sink_call.get("id"),
            stack=set(),
        )
    elif target_expr:
        synthetic_calls = sorted(index.get("calls") or [], key=lambda c: int(c.get("id") or 10**18))
        synthetic_index = dict(index)
        synthetic_index["calls_by_method"] = {"__synthetic__": synthetic_calls}
        events, event_symbols, event_unresolved = _collect_events_for_target(
            method_name="__synthetic__",
            target_expr=target_expr,
            by_ref=False,
            index=synthetic_index,
            controls=controls,
            value_env=value_env,
            max_depth=0,
            depth=0,
            until_call_id=sink_call.get("id"),
            stack=set(),
        )

    # Also model callee-side parameter flow at the sink call site itself.
    callee_name = str(sink_call.get("name") or "")
    signatures = dict(index.get("method_signatures") or {})
    if callee_name and callee_name in signatures and arg_index <= len(signatures.get(callee_name) or []):
        param_name = (signatures.get(callee_name) or [])[arg_index - 1]
        callee_events, callee_symbols, callee_unresolved = _collect_events_for_target(
            method_name=callee_name,
            target_expr=param_name,
            by_ref=False,
            index=index,
            controls=controls,
            value_env=value_env,
            max_depth=max_depth,
            depth=0,
            until_call_id=None,
            stack=set(),
        )
        for child in callee_events:
            merged = dict(child)
            provenance = dict(merged.get("provenance") or {})
            provenance["sink_call_id"] = sink_call.get("id")
            provenance["sink_call_code"] = sink_call.get("code")
            provenance["sink_method"] = sink_call.get("method")
            merged["provenance"] = provenance
            events.append(merged)
        event_symbols.update(callee_symbols)
        event_unresolved.extend(callee_unresolved)

    related_symbols.update(event_symbols)
    unresolved.extend(event_unresolved)

    for event in events:
        kind = event.get("kind")
        certainty = event.get("certainty") or "may"
        if kind == "assign":
            lhs = event.get("lhs") or ""
            op = event.get("op") or ""
            rhs = event.get("rhs") or ""
            _apply_flag_update(state, op, rhs, certainty, const_map)
            _apply_interval_update(state, lhs, op, rhs, certainty)
            _apply_nullability_update(state, op, rhs, certainty)
            _apply_callback_target_update(state, op, rhs, certainty)
            traces.append(_serialize_trace(event, reason=f"applied_{certainty}_{op}"))
            related_symbols.update(_extract_identifiers(lhs))
            related_symbols.update(_extract_identifiers(rhs))
            continue

        if kind == "callback_invoke":
            if certainty == "true":
                state.callback_invoked_must = True
                state.callback_invoked_may = True
            elif certainty == "may":
                state.callback_invoked_may = True
                state.unknown = True
            traces.append(_serialize_trace(event, reason=f"callback_invoke_{certainty}"))
            continue

        traces.append(_serialize_trace(event, reason="event_ignored"))

    # Nullability contradiction is handled by consumers; mark unknown for mixed may facts.
    if state.null_may and state.nonnull_may and not (state.null_must or state.nonnull_must):
        state.unknown = True

    alias_result = analyze_aliases(
        index.get("calls") or [],
        index.get("method_signatures") or {},
        max_depth=max_depth,
    )

    return {
        "engine_version": "interproc_v2",
        "status": "unknown",
        "state": state.to_dict(),
        "trace": [trace.to_dict() for trace in traces],
        "unresolved": unresolved,
        "target_expr": target_expr,
        "related_symbols": sorted(related_symbols),
        "alias_result": alias_result,
    }
