"""Extract and propagate path constraints from chain/control-structure evidence."""

from __future__ import annotations

import os
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from tools.verification.path_solver import extract_numeric_constraints
from tools.verification.abi_contracts import build_abi_contracts

_NUM_TOKEN_RE = re.compile(r"^-?(?:0x[0-9A-Fa-f]+|\d+)$")
_BOOL_TOKEN = {"true": 1, "false": 0}
_CONST_DEF_RE = re.compile(
    r"\bconst\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[^=]+=\s*"
    r"(-?(?:0x[0-9A-Fa-f]+|\d+)|true|false)\b"
)
_C_DEFINE_RE = re.compile(
    r"#define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(-?(?:0x[0-9A-Fa-f]+|\d+)|true|false)\b"
)
_FUNC_SIG_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
_CALL_RE_TEMPLATE = r"\b{func}\s*\(([^;]*)\)"
_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_SRC_PATH_RE = re.compile(r"(/[^\s:]+?\.(?:rs|c|h|cc|cpp|hpp)):\d+:\d+")

_IGNORED_IDENTIFIER = {
    "NULL",
    "true",
    "false",
    "const",
    "move",
    "copy",
    "return",
    "if",
    "while",
    "for",
    "switch",
}


def _coerce_int(token: str) -> Optional[int]:
    if token is None:
        return None
    text = token.strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered in _BOOL_TOKEN:
        return _BOOL_TOKEN[lowered]
    if _NUM_TOKEN_RE.match(text):
        base = 16 if text.lower().startswith("-0x") or text.lower().startswith("0x") else 10
        return int(text, base)
    return None


def _split_args(arg_str: str) -> List[str]:
    args = []
    current = []
    depth = 0
    for ch in arg_str:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            token = "".join(current).strip()
            if token:
                args.append(token)
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        args.append(tail)
    return args


def _extract_param_names(signature_args: str) -> List[str]:
    if not signature_args.strip() or signature_args.strip() == "void":
        return []
    out = []
    for raw in _split_args(signature_args):
        part = raw.strip()
        part = part.split("=")[0].strip()
        part = part.replace("*", " ")
        part = part.replace("&", " ")
        token_candidates = _IDENT_RE.findall(part)
        if not token_candidates:
            continue
        out.append(token_candidates[-1])
    return out


def _collect_text_blobs(chain_nodes: Iterable[dict]) -> List[str]:
    blobs: List[str] = []
    for node in chain_nodes:
        if not isinstance(node, dict):
            continue
        code = node.get("code")
        if isinstance(code, str) and code.strip():
            blobs.append(code)
    return blobs

def _extract_source_paths(chain_nodes: Iterable[dict]) -> List[str]:
    out: List[str] = []
    seen = set()
    for blob in _collect_text_blobs(chain_nodes):
        for match in _SRC_PATH_RE.finditer(blob):
            path = match.group(1)
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
    return out

def _scan_constants_in_text(text: str, const_map: Dict[str, int]) -> None:
    for regex in (_CONST_DEF_RE, _C_DEFINE_RE):
        for match in regex.finditer(text):
            name, value_token = match.groups()
            value = _coerce_int(value_token)
            if value is None:
                continue
            const_map[name] = value


def _extract_constant_map(chain_nodes: Iterable[dict]) -> Dict[str, int]:
    const_map: Dict[str, int] = {}
    for code in _collect_text_blobs(chain_nodes):
        _scan_constants_in_text(code, const_map)
    for src_path in _extract_source_paths(chain_nodes):
        if not os.path.isfile(src_path):
            continue
        try:
            if os.path.getsize(src_path) > 2 * 1024 * 1024:
                continue
            with open(src_path, "r", encoding="utf-8", errors="ignore") as handle:
                _scan_constants_in_text(handle.read(), const_map)
        except OSError:
            continue
    return const_map


def _extract_method_signatures(chain_nodes: Iterable[dict]) -> Dict[str, List[str]]:
    signatures: Dict[str, List[str]] = {}
    for node in chain_nodes:
        if not isinstance(node, dict):
            continue
        labels = node.get("labels") or []
        if "METHOD" not in labels:
            continue
        name = node.get("name")
        code = node.get("code")
        if not isinstance(name, str) or not name:
            continue
        if not isinstance(code, str) or not code.strip():
            continue
        pattern = re.compile(rf"\b{re.escape(name)}\s*\(([^)]*)\)")
        found = pattern.search(code)
        if found:
            params = _extract_param_names(found.group(1))
            if params:
                signatures[name] = params
            continue
        # Fallback: generic signature in code, take the first if function name is present.
        for generic in _FUNC_SIG_RE.finditer(code):
            g_name = generic.group(1)
            if g_name != name:
                continue
            params = _extract_param_names(generic.group(2))
            if params:
                signatures[name] = params
            break
    return signatures


def _normalize_method_calls(evidence_calls: Optional[List[dict]], chain_nodes: Iterable[dict]) -> List[dict]:
    rows: List[dict] = []
    seen = set()

    for call in evidence_calls or []:
        if not isinstance(call, dict):
            continue
        cid = call.get("id")
        key = (cid, call.get("method"), call.get("name"), call.get("code"))
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "id": cid,
                "name": call.get("name"),
                "code": call.get("code"),
                "method": call.get("method"),
                "lang": call.get("lang"),
            }
        )

    # Fallback: use call nodes from chain when evidence_calls is empty.
    if rows:
        rows.sort(key=lambda c: (str(c.get("method") or ""), int(c.get("id") or 10**18)))
        return rows

    for node in chain_nodes or []:
        if not isinstance(node, dict):
            continue
        labels = node.get("labels") or []
        if "CALL" not in labels:
            continue
        cid = node.get("id")
        key = (cid, None, node.get("name"), node.get("code"))
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "id": cid,
                "name": node.get("name"),
                "code": node.get("code"),
                "method": None,
                "lang": "Rust" if "Rust" in labels else ("C" if "C" in labels else None),
            }
        )

    rows.sort(key=lambda c: (str(c.get("method") or ""), int(c.get("id") or 10**18)))
    return rows


def _extract_call_graph_edges(method_calls: List[dict], method_signatures: Dict[str, List[str]]) -> List[dict]:
    edges: List[dict] = []
    seen: Set[Tuple[str, str, int]] = set()
    known_methods: Set[str] = set(str(c.get("method")) for c in method_calls if c.get("method"))
    known_methods.update(str(name) for name in (method_signatures or {}).keys())

    for call in method_calls or []:
        caller = call.get("method")
        callee = call.get("name")
        if not caller or not callee:
            continue
        if str(callee).startswith("<operator>") or str(callee).startswith("<operators>"):
            continue
        if callee not in known_methods:
            continue
        try:
            call_id = int(call.get("id"))
        except Exception:
            call_id = -1
        key = (str(caller), str(callee), call_id)
        if key in seen:
            continue
        seen.add(key)
        edges.append({"caller": caller, "callee": callee, "call_id": call_id})
    return edges


def _iter_call_arg_lists(code: str, func_name: str):
    regex = re.compile(_CALL_RE_TEMPLATE.format(func=re.escape(func_name)))
    for match in regex.finditer(code):
        raw_args = match.group(1)
        args = _split_args(raw_args)
        if args:
            yield args


def _normalize_expr(expr: str) -> str:
    text = expr.strip()
    while text.startswith("(") and text.endswith(")") and len(text) > 2:
        text = text[1:-1].strip()
    for prefix in ("move ", "copy ", "&", "*"):
        if text.startswith(prefix):
            text = text[len(prefix) :].strip()
    if text.startswith("const "):
        text = text[len("const ") :].strip()
    return text


def _resolve_expr_to_int(expr: str, value_env: Dict[str, int], const_map: Dict[str, int]) -> Optional[int]:
    text = _normalize_expr(expr)
    num = _coerce_int(text)
    if num is not None:
        return num
    if text in value_env:
        return value_env[text]
    if text in const_map:
        return const_map[text]
    # Rust MIR often emits `const SAFE_MODE`; extract trailing symbol.
    tokens = _IDENT_RE.findall(text)
    if tokens:
        tail = tokens[-1]
        if tail in value_env:
            return value_env[tail]
        if tail in const_map:
            return const_map[tail]
    return None


def _parse_call_env(chain_nodes: Iterable[dict], signatures: Dict[str, List[str]], const_map: Dict[str, int]) -> Dict[str, int]:
    value_env: Dict[str, int] = dict(const_map)
    code_blobs = _collect_text_blobs(chain_nodes)

    for func_name, params in signatures.items():
        if not params:
            continue
        for code in code_blobs:
            for args in _iter_call_arg_lists(code, func_name):
                if len(args) < len(params):
                    continue
                for idx, param in enumerate(params):
                    resolved = _resolve_expr_to_int(args[idx], value_env, const_map)
                    if resolved is None:
                        continue
                    value_env[param] = resolved
    return value_env


def _extract_sink_args(chain_nodes: Iterable[dict], symbol: str) -> List[str]:
    candidates: List[str] = []
    for node in chain_nodes:
        if not isinstance(node, dict):
            continue
        labels = node.get("labels") or []
        if "CALL" not in labels:
            continue
        if node.get("name") != symbol:
            continue
        code = node.get("code")
        if not isinstance(code, str):
            continue
        for args in _iter_call_arg_lists(code, symbol):
            candidates.extend(args)
            break
    return candidates


def _extract_sink_calls(chain_nodes: Iterable[dict], symbol: str) -> List[dict]:
    out: List[dict] = []
    for node in chain_nodes:
        if not isinstance(node, dict):
            continue
        labels = node.get("labels") or []
        if "CALL" not in labels:
            continue
        if node.get("name") != symbol:
            continue
        code = node.get("code")
        if not isinstance(code, str):
            continue
        call_args = []
        for args in _iter_call_arg_lists(code, symbol):
            call_args = args
            break
        out.append(
            {
                "id": node.get("id"),
                "name": node.get("name"),
                "code": code,
                "args": call_args,
            }
        )
    return out


def _extract_identifiers(exprs: Iterable[str]) -> List[str]:
    out = []
    for expr in exprs:
        for token in _IDENT_RE.findall(expr or ""):
            if token in _IGNORED_IDENTIFIER:
                continue
            out.append(token)
    dedup = []
    seen = set()
    for token in out:
        if token in seen:
            continue
        seen.add(token)
        dedup.append(token)
    return dedup


def _select_relevant_controls(control_nodes: List[dict], relevant_vars: List[str]) -> List[dict]:
    if not control_nodes:
        return []
    if not relevant_vars:
        return control_nodes

    selected = []
    for node in control_nodes:
        texts = []
        code = node.get("code")
        if isinstance(code, str):
            texts.append(code)
        for c in node.get("child_codes") or []:
            if isinstance(c, str):
                texts.append(c)
        blob = "\n".join(texts)
        if any(re.search(rf"\b{re.escape(v)}\b", blob) for v in relevant_vars):
            selected.append(node)
    return selected if selected else control_nodes


def _dedupe_constraints(constraints: List[dict]) -> List[dict]:
    out = []
    seen = set()
    for c in constraints:
        key = (
            c.get("variable"),
            c.get("operator"),
            c.get("value"),
            c.get("source"),
            c.get("source_id"),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def build_path_constraint_bundle(
    chain_nodes: List[dict],
    control_nodes: List[dict],
    symbol: str,
    trigger_model: Optional[dict] = None,
    evidence_calls: Optional[List[dict]] = None,
) -> dict:
    """Build path constraints from controls + propagated call-context facts."""
    const_map = _extract_constant_map(chain_nodes)
    signatures = _extract_method_signatures(chain_nodes)
    value_env = _parse_call_env(chain_nodes, signatures, const_map)
    method_calls = _normalize_method_calls(evidence_calls, chain_nodes)
    call_graph_edges = _extract_call_graph_edges(method_calls, signatures)
    sink_calls = _extract_sink_calls(chain_nodes, symbol)
    sink_args = _extract_sink_args(chain_nodes, symbol)
    sink_vars = _extract_identifiers(sink_args)

    # Keep only practical variable names for numeric seeds.
    seed_constraints = []
    for name, value in value_env.items():
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            continue
        if name.startswith("_"):
            continue
        # Favor runtime variables, not all-uppercase constants.
        if name.upper() == name and "_" in name:
            continue
        seed_constraints.append(
            {
                "variable": name,
                "operator": "==",
                "value": value,
                "source": "call_context",
                "source_id": None,
            }
        )

    relevant_vars = list(dict.fromkeys(sink_vars + [c["variable"] for c in seed_constraints]))
    relevant_controls = _select_relevant_controls(control_nodes, relevant_vars)

    path_constraints = extract_numeric_constraints(relevant_controls)
    # Mark branch constraints explicitly.
    for c in path_constraints:
        c["branch_polarity"] = "true_branch_assumed"

    path_constraints = _dedupe_constraints(path_constraints)
    seed_constraints = _dedupe_constraints(seed_constraints)
    combined_constraints = _dedupe_constraints(path_constraints + seed_constraints)

    abi_contracts = {
        "status": "unknown",
        "reason": "abi_contracts_not_evaluated",
        "ptr_len_pairs": [],
        "nullability": [],
        "flag_domain": [],
        "callback_contracts": [],
        "constraints": [],
        "arg_bindings": [],
        "boundary_assumptions": [],
        "evidence": [],
        "conflict_reason": None,
    }
    arg_bindings: List[dict] = []
    boundary_assumptions: List[dict] = []

    try:
        abi_contracts = build_abi_contracts(
            trigger_model=trigger_model or {},
            evidence_calls=list(evidence_calls or []),
            path_bundle={
                "path_constraints": path_constraints,
                "seed_constraints": seed_constraints,
                "combined_constraints": combined_constraints,
                "control_structures_relevant": relevant_controls,
                "sink_calls": sink_calls,
                "sink_args": sink_args,
                "sink_vars": sink_vars,
                "method_calls": method_calls,
                "call_graph_edges": call_graph_edges,
                "method_signatures": signatures,
                "interproc_context": {
                    "method_calls": method_calls,
                    "call_graph_edges": call_graph_edges,
                    "method_signatures": signatures,
                },
                "constants": const_map,
                "const_map": const_map,
                "value_env": value_env,
            },
        )
    except Exception as exc:
        abi_contracts = {
            "status": "unknown",
            "reason": f"abi_contract_eval_error:{exc}",
            "ptr_len_pairs": [],
            "nullability": [],
            "flag_domain": [],
            "callback_contracts": [],
            "constraints": [],
            "arg_bindings": [],
            "boundary_assumptions": [],
            "evidence": [],
            "conflict_reason": None,
        }

    abi_constraints = []
    for cons in abi_contracts.get("constraints") or []:
        if not isinstance(cons, dict):
            continue
        op = cons.get("operator")
        val = cons.get("value")
        var = cons.get("variable")
        if op not in {"<", "<=", ">", ">=", "==", "!="}:
            continue
        if not isinstance(var, str) or not var:
            continue
        try:
            ival = int(val)
        except Exception:
            continue
        row = dict(cons)
        row["operator"] = op
        row["value"] = ival
        row.setdefault("source", "abi_contract")
        abi_constraints.append(row)

    combined_constraints = _dedupe_constraints(combined_constraints + abi_constraints)
    arg_bindings = list(abi_contracts.get("arg_bindings") or [])
    boundary_assumptions = list(abi_contracts.get("boundary_assumptions") or [])

    return {
        "path_constraints": path_constraints,
        "seed_constraints": seed_constraints,
        "combined_constraints": combined_constraints,
        "control_structures_relevant": relevant_controls,
        "sink_calls": sink_calls,
        "sink_args": sink_args,
        "sink_vars": sink_vars,
        "method_calls": method_calls,
        "call_graph_edges": call_graph_edges,
        "method_signatures": signatures,
        "interproc_context": {
            "method_calls": method_calls,
            "call_graph_edges": call_graph_edges,
            "method_signatures": signatures,
        },
        "abi_contracts": abi_contracts,
        "arg_bindings": arg_bindings,
        "boundary_assumptions": boundary_assumptions,
        "constants": const_map,
        "const_map": const_map,
        "value_env": value_env,
    }
