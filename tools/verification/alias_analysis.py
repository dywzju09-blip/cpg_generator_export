"""Lightweight must/may alias analysis for inter-procedural value flow.

The analyzer is intentionally conservative:
- Prefer `unknown` over unsound precision.
- Build simple must-alias sets for direct value copies.
- Build may-alias edges from pointer/address flows and parameter passing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ASSIGN_RE = re.compile(r"^\s*(?P<lhs>[^=]+?)\s*(?P<op>\|=|&=|\^=|=)\s*(?P<rhs>.+?)\s*;?\s*$")
_ADDRESS_OF_RE = re.compile(r"^\s*&\s*([A-Za-z_][A-Za-z0-9_]*)\s*$")
_DEREF_RE = re.compile(r"^\s*\(?\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)?\s*$")


@dataclass
class _UnionFind:
    parent: Dict[str, str] = field(default_factory=dict)

    def add(self, item: str) -> None:
        if item not in self.parent:
            self.parent[item] = item

    def find(self, item: str) -> str:
        self.add(item)
        parent = self.parent[item]
        if parent != item:
            self.parent[item] = self.find(parent)
        return self.parent[item]

    def union(self, left: str, right: str) -> None:
        root_l = self.find(left)
        root_r = self.find(right)
        if root_l != root_r:
            self.parent[root_r] = root_l

    def groups(self) -> List[List[str]]:
        buckets: Dict[str, List[str]] = {}
        for item in self.parent:
            root = self.find(item)
            buckets.setdefault(root, []).append(item)
        out = []
        for members in buckets.values():
            members.sort()
            out.append(members)
        out.sort()
        return out


def _slot(method: str, ident: str) -> str:
    return f"{method}::{ident}"


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


def _add_may_alias(may_graph: Dict[str, Set[str]], left: str, right: str) -> None:
    if left == right:
        return
    may_graph.setdefault(left, set()).add(right)
    may_graph.setdefault(right, set()).add(left)


def _iter_method_calls(method_calls: Iterable[dict]) -> List[dict]:
    rows = [c for c in (method_calls or []) if isinstance(c, dict)]
    rows.sort(key=lambda c: (str(c.get("method") or ""), int(c.get("id") or 10**18)))
    return rows


def _slot_or_none(method: str, text: str) -> Optional[str]:
    ident = _simple_ident(text)
    if not ident:
        return None
    return _slot(method, ident)


def _closure_limited(graph: Dict[str, Set[str]], seed: str, max_depth: int) -> Set[str]:
    if max_depth <= 0:
        return set()
    out: Set[str] = set()
    frontier = {seed}
    visited = {seed}
    depth = 0
    while frontier and depth < max_depth:
        nxt: Set[str] = set()
        for node in frontier:
            for nei in graph.get(node, set()):
                if nei in visited:
                    continue
                visited.add(nei)
                out.add(nei)
                nxt.add(nei)
        frontier = nxt
        depth += 1
    return out


def analyze_aliases(method_calls: List[dict], method_signatures: Dict[str, List[str]], max_depth: int = 2) -> dict:
    """Build lightweight must/may alias facts.

    Returns:
        {
          "must_alias_sets": List[List[str]],
          "may_alias_map": Dict[str, List[str]],
          "points_to": Dict[str, List[str]],
          "evidence": List[dict],
          "unresolved": List[dict],
        }
    """

    uf = _UnionFind()
    may_graph: Dict[str, Set[str]] = {}
    points_to: Dict[str, Set[str]] = {}
    evidence: List[dict] = []
    unresolved: List[dict] = []

    calls = _iter_method_calls(method_calls)
    for call in calls:
        method = str(call.get("method") or "")
        if not method:
            continue
        code = call.get("code") or ""
        parsed = _parse_assignment(code)
        if parsed:
            lhs = parsed.get("lhs") or ""
            rhs = parsed.get("rhs") or ""
            op = parsed.get("op") or ""
            lhs_slot = _slot_or_none(method, lhs)
            rhs_slot = _slot_or_none(method, rhs)
            lhs_deref = _deref_ident(lhs)
            rhs_deref = _deref_ident(rhs)
            rhs_addr = _address_of_ident(rhs)

            if op != "=":
                # Non-direct assignment still contributes may effects for deref writes.
                if lhs_deref:
                    ptr_slot = _slot(method, lhs_deref)
                    bases = set(points_to.get(ptr_slot, set()))
                    if not bases:
                        unresolved.append(
                            {
                                "kind": "deref_write_unknown_target",
                                "call_id": call.get("id"),
                                "method": method,
                                "code": code,
                            }
                        )
                    for base in bases:
                        evidence.append(
                            {
                                "kind": "deref_write_may_alias",
                                "call_id": call.get("id"),
                                "method": method,
                                "code": code,
                                "base": base,
                            }
                        )
                continue

            if lhs_slot and rhs_slot:
                uf.union(lhs_slot, rhs_slot)
                _add_may_alias(may_graph, lhs_slot, rhs_slot)
                evidence.append(
                    {
                        "kind": "must_alias_assign",
                        "call_id": call.get("id"),
                        "method": method,
                        "code": code,
                        "left": lhs_slot,
                        "right": rhs_slot,
                    }
                )
                continue

            if lhs_slot and rhs_addr:
                base_slot = _slot(method, rhs_addr)
                points_to.setdefault(lhs_slot, set()).add(base_slot)
                _add_may_alias(may_graph, lhs_slot, base_slot)
                evidence.append(
                    {
                        "kind": "points_to_addr",
                        "call_id": call.get("id"),
                        "method": method,
                        "code": code,
                        "ptr": lhs_slot,
                        "base": base_slot,
                    }
                )
                continue

            if lhs_slot and rhs_deref:
                ptr_slot = _slot(method, rhs_deref)
                bases = set(points_to.get(ptr_slot, set()))
                if not bases:
                    unresolved.append(
                        {
                            "kind": "deref_read_unknown_target",
                            "call_id": call.get("id"),
                            "method": method,
                            "code": code,
                        }
                    )
                for base in bases:
                    _add_may_alias(may_graph, lhs_slot, base)
                    evidence.append(
                        {
                            "kind": "deref_read_may_alias",
                            "call_id": call.get("id"),
                            "method": method,
                            "code": code,
                            "left": lhs_slot,
                            "base": base,
                        }
                    )
                continue

            if lhs_deref and rhs_slot:
                ptr_slot = _slot(method, lhs_deref)
                bases = set(points_to.get(ptr_slot, set()))
                if not bases:
                    unresolved.append(
                        {
                            "kind": "deref_store_unknown_target",
                            "call_id": call.get("id"),
                            "method": method,
                            "code": code,
                        }
                    )
                for base in bases:
                    _add_may_alias(may_graph, base, rhs_slot)
                    evidence.append(
                        {
                            "kind": "deref_store_may_alias",
                            "call_id": call.get("id"),
                            "method": method,
                            "code": code,
                            "base": base,
                            "right": rhs_slot,
                        }
                    )
                continue

            # Preserve unknown cases for explainability.
            unresolved.append(
                {
                    "kind": "assignment_not_resolved",
                    "call_id": call.get("id"),
                    "method": method,
                    "code": code,
                }
            )

        call_name = str(call.get("name") or "")
        if not call_name or call_name.startswith("<operator>") or call_name.startswith("<operators>"):
            continue
        params = list(method_signatures.get(call_name) or [])
        if not params:
            continue
        args = _extract_call_args(code)
        if not args:
            unresolved.append(
                {
                    "kind": "call_args_missing",
                    "call_id": call.get("id"),
                    "method": method,
                    "callee": call_name,
                    "code": code,
                }
            )
            continue

        for idx, param in enumerate(params):
            if idx >= len(args):
                unresolved.append(
                    {
                        "kind": "call_arg_short",
                        "call_id": call.get("id"),
                        "method": method,
                        "callee": call_name,
                        "param": param,
                        "arg_index": idx + 1,
                    }
                )
                continue
            arg = args[idx].strip()
            param_slot = _slot(call_name, param)
            uf.add(param_slot)

            arg_slot = _slot_or_none(method, arg)
            arg_addr = _address_of_ident(arg)
            arg_deref = _deref_ident(arg)

            if arg_slot:
                # Value-passing rename edge: conservative may-alias.
                _add_may_alias(may_graph, param_slot, arg_slot)
                evidence.append(
                    {
                        "kind": "param_bind_value",
                        "call_id": call.get("id"),
                        "method": method,
                        "callee": call_name,
                        "param": param_slot,
                        "arg": arg_slot,
                    }
                )
            elif arg_addr:
                base_slot = _slot(method, arg_addr)
                points_to.setdefault(param_slot, set()).add(base_slot)
                _add_may_alias(may_graph, param_slot, base_slot)
                evidence.append(
                    {
                        "kind": "param_bind_by_ref",
                        "call_id": call.get("id"),
                        "method": method,
                        "callee": call_name,
                        "param": param_slot,
                        "base": base_slot,
                    }
                )
            elif arg_deref:
                ptr_slot = _slot(method, arg_deref)
                bases = set(points_to.get(ptr_slot, set()))
                if not bases:
                    unresolved.append(
                        {
                            "kind": "param_bind_deref_unknown",
                            "call_id": call.get("id"),
                            "method": method,
                            "callee": call_name,
                            "arg": arg,
                        }
                    )
                for base in bases:
                    _add_may_alias(may_graph, param_slot, base)
            else:
                unresolved.append(
                    {
                        "kind": "param_bind_expr_unknown",
                        "call_id": call.get("id"),
                        "method": method,
                        "callee": call_name,
                        "arg": arg,
                    }
                )

    must_alias_sets = uf.groups()

    # Expand may-alias with bounded transitive closure to account for wrappers.
    may_alias_map: Dict[str, List[str]] = {}
    for node in sorted(may_graph.keys()):
        expanded = set(may_graph.get(node, set()))
        expanded.update(_closure_limited(may_graph, node, max_depth=max_depth))
        if node in expanded:
            expanded.remove(node)
        may_alias_map[node] = sorted(expanded)

    points_to_map = {key: sorted(values) for key, values in points_to.items()}

    return {
        "must_alias_sets": must_alias_sets,
        "may_alias_map": may_alias_map,
        "points_to": points_to_map,
        "evidence": evidence,
        "unresolved": unresolved,
        "max_depth": int(max_depth),
    }
