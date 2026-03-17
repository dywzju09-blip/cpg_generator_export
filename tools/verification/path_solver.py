"""Path constraint solver with Apron-first strategy and interval fallback."""

from __future__ import annotations

import ctypes
import importlib
import math
import os
import re
from typing import Dict, Iterable, List, Optional

VALID_OPERATORS = {"<", "<=", ">", ">=", "==", "!="}

_BOOL_TO_INT = {
    "true": 1,
    "false": 0,
}

_ASSIGNMENT_RE = re.compile(
    r"(?<![<>=!])\b([A-Za-z_][A-Za-z0-9_]*)\b\s*=\s*"
    r"(-?(?:0x[0-9A-Fa-f]+|\d+)|true|false)\b(?!\s*=)"
)

_CMP_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(<=|>=|==|!=|<|>)\s*"
    r"(-?(?:0x[0-9A-Fa-f]+|\d+)|true|false)\s*$"
)
_CMP_RE_REVERSED = re.compile(
    r"^\s*(-?(?:0x[0-9A-Fa-f]+|\d+)|true|false)\s*(<=|>=|==|!=|<|>)\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*$"
)
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_IGNORED_ATOM_IDENTIFIERS = {"else", "if", "while", "for", "switch", "case", "default"}


def _coerce_int(value) -> int:
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        token = value.strip().lower()
        if token in _BOOL_TO_INT:
            return _BOOL_TO_INT[token]
        if token.startswith("0x") or token.startswith("-0x"):
            return int(token, 16)
        return int(token)
    raise ValueError(f"Unsupported numeric value: {value!r}")


def _normalize_operator(op: str) -> str:
    if op == "=":
        return "=="
    return op


def _reverse_operator(op: str) -> str:
    mapping = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}
    return mapping[op]


def _negate_operator(op: str) -> str:
    mapping = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}
    return mapping[op]


def _strip_outer_parens(text: str) -> str:
    expr = text.strip()
    while expr.startswith("(") and expr.endswith(")"):
        depth = 0
        valid = True
        for idx, ch in enumerate(expr):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and idx != len(expr) - 1:
                    valid = False
                    break
            if depth < 0:
                valid = False
                break
        if not valid or depth != 0:
            return expr
        expr = expr[1:-1].strip()
    return expr


def _contains_top_level(expr: str, token: str) -> bool:
    depth = 0
    idx = 0
    while idx <= len(expr) - len(token):
        ch = expr[idx]
        if ch in "([{":
            depth += 1
            idx += 1
            continue
        if ch in ")]}":
            depth = max(0, depth - 1)
            idx += 1
            continue
        if depth == 0 and expr[idx : idx + len(token)] == token:
            return True
        idx += 1
    return False


def _split_top_level(expr: str, token: str) -> List[str]:
    depth = 0
    pieces: List[str] = []
    start = 0
    idx = 0
    while idx <= len(expr) - len(token):
        ch = expr[idx]
        if ch in "([{":
            depth += 1
            idx += 1
            continue
        if ch in ")]}":
            depth = max(0, depth - 1)
            idx += 1
            continue
        if depth == 0 and expr[idx : idx + len(token)] == token:
            part = expr[start:idx].strip()
            if part:
                pieces.append(part)
            start = idx + len(token)
            idx = start
            continue
        idx += 1
    tail = expr[start:].strip()
    if tail:
        pieces.append(tail)
    return pieces


def _normalize_condition_text(text: str) -> str:
    expr = text.strip().strip(";")
    if not expr:
        return expr

    def _extract_first_parenthesized(src: str) -> Optional[str]:
        lpos = src.find("(")
        if lpos == -1:
            return None
        depth = 0
        for idx in range(lpos, len(src)):
            ch = src[idx]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return src[lpos + 1 : idx].strip()
        return None

    lowered = expr.lower()
    for keyword in ("if", "while", "for", "switch"):
        if lowered.startswith(keyword):
            extracted = _extract_first_parenthesized(expr)
            if extracted is not None:
                return extracted
    return expr


def _parse_binary_constraint(atom: str) -> Optional[Dict[str, object]]:
    match = _CMP_RE.match(atom)
    if match:
        variable, operator, token = match.groups()
        return {
            "variable": variable,
            "operator": operator,
            "value": _coerce_int(token),
            "raw": atom,
        }

    match = _CMP_RE_REVERSED.match(atom)
    if match:
        token, operator, variable = match.groups()
        return {
            "variable": variable,
            "operator": _reverse_operator(operator),
            "value": _coerce_int(token),
            "raw": atom,
        }
    return None


def _parse_atom(atom: str) -> Optional[Dict[str, object]]:
    expr = _strip_outer_parens(atom.strip())
    if not expr:
        return None
    if expr.lower() in _IGNORED_ATOM_IDENTIFIERS:
        return None

    if expr.startswith("!"):
        inner = _strip_outer_parens(expr[1:].strip())
        if _IDENT_RE.match(inner):
            return {"variable": inner, "operator": "==", "value": 0, "raw": atom}
        parsed_inner = _parse_binary_constraint(inner)
        if not parsed_inner:
            return None
        parsed_inner["operator"] = _negate_operator(str(parsed_inner["operator"]))
        parsed_inner["raw"] = atom
        return parsed_inner

    if _IDENT_RE.match(expr):
        return {"variable": expr, "operator": "!=", "value": 0, "raw": atom}

    return _parse_binary_constraint(expr)


def parse_condition_expression(condition: str) -> List[Dict[str, object]]:
    """Parse simple numeric constraints from control-flow condition text."""
    if not condition:
        return []

    expr = _strip_outer_parens(_normalize_condition_text(condition))
    if not expr:
        return []

    if _contains_top_level(expr, "||"):
        return []

    atoms = _split_top_level(expr, "&&")
    if not atoms:
        atoms = [expr]

    constraints: List[Dict[str, object]] = []
    for atom in atoms:
        parsed = _parse_atom(atom)
        if parsed is not None:
            constraints.append(parsed)
    return constraints


def extract_assignment_constraints(code: str) -> List[Dict[str, object]]:
    """Extract direct numeric assignments like `safe_mode = 1`."""
    if not code:
        return []

    constraints: List[Dict[str, object]] = []
    for match in _ASSIGNMENT_RE.finditer(code):
        variable, token = match.groups()
        constraints.append(
            {
                "variable": variable,
                "operator": "==",
                "value": _coerce_int(token),
                "raw": match.group(0),
            }
        )
    return constraints


def extract_numeric_constraints(control_nodes: Iterable[dict]) -> List[Dict[str, object]]:
    """Extract constraints from CONTROL_STRUCTURE records."""
    constraints: List[Dict[str, object]] = []
    seen = set()

    for node in control_nodes or []:
        candidates: List[str] = []
        source_id = None
        if isinstance(node, str):
            candidates.append(node)
        elif isinstance(node, dict):
            source_id = node.get("id")
            for key in ("condition", "condition_code", "code"):
                val = node.get(key)
                if isinstance(val, str) and val.strip():
                    candidates.append(val)
            child_codes = node.get("child_codes") or []
            if isinstance(child_codes, list):
                for code in child_codes:
                    if isinstance(code, str) and code.strip():
                        candidates.append(code)

        for candidate in candidates:
            for cons in parse_condition_expression(candidate):
                item = {
                    "variable": cons["variable"],
                    "operator": cons["operator"],
                    "value": cons["value"],
                    "raw": cons.get("raw"),
                    "source": "control_structure",
                    "source_id": source_id,
                }
                key = (item["variable"], item["operator"], item["value"], item["source_id"])
                if key in seen:
                    continue
                seen.add(key)
                constraints.append(item)

    return constraints


class _IntervalState:
    def __init__(self) -> None:
        self._bounds: Dict[str, List[float]] = {}
        self._bottom = False

    def _get_bounds(self, variable: str) -> List[float]:
        if variable not in self._bounds:
            self._bounds[variable] = [-math.inf, math.inf]
        return self._bounds[variable]

    def meet(self, variable: str, operator: str, value: int) -> None:
        if self._bottom:
            return

        bounds = self._get_bounds(variable)
        lo, hi = bounds[0], bounds[1]

        if operator == "==":
            lo = max(lo, value)
            hi = min(hi, value)
        elif operator == "!=":
            if lo == hi == value:
                self._bottom = True
                return
        elif operator == ">":
            lo = max(lo, value + 1)
        elif operator == ">=":
            lo = max(lo, value)
        elif operator == "<":
            hi = min(hi, value - 1)
        elif operator == "<=":
            hi = min(hi, value)
        else:
            return

        if lo > hi:
            self._bottom = True
            return

        bounds[0], bounds[1] = lo, hi

    @property
    def is_bottom(self) -> bool:
        return self._bottom


class _ApronBackend:
    """Best-effort Apron adapter using apronpy if available."""

    def __init__(self, domain: str = "octagon") -> None:
        self.domain = domain
        self._manager = None
        self._abstract_cls = None
        self._init_apronpy()

    @staticmethod
    def _preload_native_libs() -> None:
        """Preload shared libraries to improve apronpy compatibility on macOS."""
        lib_dirs = [
            os.environ.get("APRON_LIB_DIR", "").strip(),
            os.path.expanduser("~/.local/apron/lib"),
            "/usr/local/lib",
            "/opt/homebrew/lib",
        ]
        lib_names = [
            "libgmp.dylib",
            "libmpfr.dylib",
            "libapron.so",
            "libapron.dylib",
            "liboctD.so",
            "liboctMPQ.so",
            "libboxD.so",
            "libboxMPQ.so",
            "libpolkaMPQ.so",
            "libpolkaRll.so",
        ]
        mode = getattr(ctypes, "RTLD_GLOBAL", 0)
        for lib_dir in lib_dirs:
            if not lib_dir:
                continue
            for lib_name in lib_names:
                full = os.path.join(lib_dir, lib_name)
                if os.path.exists(full):
                    try:
                        ctypes.CDLL(full, mode=mode)
                    except OSError:
                        continue

    def _init_apronpy(self) -> None:
        self._preload_native_libs()
        try:
            if self.domain == "interval":
                domain_mod = importlib.import_module("apronpy.box")
                manager_cls = getattr(domain_mod, "PyBoxDManager")
                abstract_cls = getattr(domain_mod, "PyBox")
            elif self.domain == "polyhedra":
                domain_mod = importlib.import_module("apronpy.polka")
                manager_cls = getattr(domain_mod, "PyPolkaMPQlooseManager")
                abstract_cls = getattr(domain_mod, "PyPolka")
            else:
                domain_mod = importlib.import_module("apronpy.oct")
                manager_cls = getattr(domain_mod, "PyOctDManager")
                abstract_cls = getattr(domain_mod, "PyOct")
        except Exception as exc:
            raise RuntimeError(
                "Cannot import apronpy. Install Apron C library and Python binding apronpy/pyapron."
            ) from exc

        self._manager = manager_cls()
        self._abstract_cls = abstract_cls

    def _make_lincons(self, env, constraint: dict):
        lincons0_mod = importlib.import_module("apronpy.lincons0")
        linexpr_mod = importlib.import_module("apronpy.linexpr1")
        lincons_mod = importlib.import_module("apronpy.lincons1")
        var_mod = importlib.import_module("apronpy.var")
        coeff_mod = importlib.import_module("apronpy.coeff")

        ConsTyp = getattr(lincons0_mod, "ConsTyp")
        PyLincons1 = getattr(lincons_mod, "PyLincons1")
        PyVar = getattr(var_mod, "PyVar")
        PyLinexpr1 = getattr(linexpr_mod, "PyLinexpr1")
        PyMPQScalarCoeff = getattr(coeff_mod, "PyMPQScalarCoeff")

        variable = str(constraint["variable"])
        operator = constraint["operator"]
        value = int(constraint["value"])

        if operator == ">":
            coeff = 1
            const = -value
            cons_typ = ConsTyp.AP_CONS_SUP
        elif operator == ">=":
            coeff = 1
            const = -value
            cons_typ = ConsTyp.AP_CONS_SUPEQ
        elif operator == "<":
            coeff = -1
            const = value
            cons_typ = ConsTyp.AP_CONS_SUP
        elif operator == "<=":
            coeff = -1
            const = value
            cons_typ = ConsTyp.AP_CONS_SUPEQ
        elif operator == "==":
            coeff = 1
            const = -value
            cons_typ = ConsTyp.AP_CONS_EQ
        else:
            coeff = 1
            const = -value
            cons_typ = ConsTyp.AP_CONS_DISEQ

        expr = PyLinexpr1(env)
        expr.set_coeff(PyVar(variable), PyMPQScalarCoeff(coeff))
        expr.set_cst(PyMPQScalarCoeff(const))
        return PyLincons1(cons_typ, expr)

    def is_feasible(self, constraints: List[dict]) -> bool:
        env_mod = importlib.import_module("apronpy.environment")
        var_mod = importlib.import_module("apronpy.var")
        lincons_mod = importlib.import_module("apronpy.lincons1")

        PyEnvironment = getattr(env_mod, "PyEnvironment")
        PyVar = getattr(var_mod, "PyVar")
        PyLincons1Array = getattr(lincons_mod, "PyLincons1Array")

        variables = sorted({str(c["variable"]) for c in constraints})
        env = PyEnvironment([PyVar(name) for name in variables], [])
        state = self._abstract_cls.top(self._manager, env)

        lincons_items = [self._make_lincons(env, c) for c in constraints]
        lincons_array = PyLincons1Array(lincons_items)
        state = state.meet(lincons_array)
        return not bool(state.is_bottom())


class PathConstraintSolver:
    """Constraint solver for path feasibility in numeric abstract domains."""

    def __init__(self, domain: str = "octagon") -> None:
        self.domain = domain
        self._constraints: List[dict] = []
        self.backend = "interval"
        self.apron_available = False
        self.apron_error: Optional[str] = None
        self._apron: Optional[_ApronBackend] = None

        try:
            self._apron = _ApronBackend(domain=domain)
            self.backend = "apron"
            self.apron_available = True
        except Exception as exc:
            self.apron_error = str(exc)
            self._apron = None

    def clear_constraints(self) -> None:
        self._constraints = []

    def add_constraint(self, variable: str, operator: str, value: int) -> None:
        if not variable or not isinstance(variable, str):
            raise ValueError("Constraint variable must be a non-empty string.")
        op = _normalize_operator(operator)
        if op not in VALID_OPERATORS:
            raise ValueError(f"Unsupported operator: {operator}")
        self._constraints.append(
            {
                "variable": variable,
                "operator": op,
                "value": _coerce_int(value),
            }
        )

    def _normalize_constraint(self, item: dict) -> Optional[dict]:
        if not isinstance(item, dict):
            return None
        variable = item.get("variable") or item.get("var")
        operator = item.get("operator")
        value = item.get("value")

        if not isinstance(variable, str) or not variable:
            return None
        if not isinstance(operator, str):
            return None

        op = _normalize_operator(operator.strip())
        if op not in VALID_OPERATORS:
            return None

        try:
            int_value = _coerce_int(value)
        except Exception:
            return None

        out = {
            "variable": variable.strip(),
            "operator": op,
            "value": int_value,
        }
        for key in ("raw", "source", "source_id", "branch_polarity"):
            if key in item:
                out[key] = item.get(key)
        return out

    def _normalize_constraints(self, constraints: List[dict]) -> List[dict]:
        normalized: List[dict] = []
        for item in self._constraints + list(constraints or []):
            parsed = self._normalize_constraint(item)
            if parsed is not None:
                normalized.append(parsed)
        return normalized

    def _interval_solve_with_explain(self, normalized: List[dict]) -> dict:
        bounds: Dict[str, dict] = {}
        neq_constraints: Dict[str, List[dict]] = {}

        def _ensure(variable: str) -> dict:
            if variable not in bounds:
                bounds[variable] = {
                    "lo": -math.inf,
                    "hi": math.inf,
                    "lo_cons": None,
                    "hi_cons": None,
                }
            return bounds[variable]

        for cons in normalized:
            var = cons["variable"]
            op = cons["operator"]
            value = int(cons["value"])
            item = _ensure(var)

            if op == "==":
                if value > item["lo"]:
                    item["lo"] = value
                    item["lo_cons"] = cons
                if value < item["hi"]:
                    item["hi"] = value
                    item["hi_cons"] = cons
            elif op == ">":
                candidate = value + 1
                if candidate > item["lo"]:
                    item["lo"] = candidate
                    item["lo_cons"] = cons
            elif op == ">=":
                if value > item["lo"]:
                    item["lo"] = value
                    item["lo_cons"] = cons
            elif op == "<":
                candidate = value - 1
                if candidate < item["hi"]:
                    item["hi"] = candidate
                    item["hi_cons"] = cons
            elif op == "<=":
                if value < item["hi"]:
                    item["hi"] = value
                    item["hi_cons"] = cons
            elif op == "!=":
                neq_constraints.setdefault(var, []).append(cons)
            else:
                continue

            if item["lo"] > item["hi"]:
                return {
                    "feasible": False,
                    "ranges": {},
                    "bottom_reason": {
                        "variable": var,
                        "lower_bound": item["lo_cons"] or cons,
                        "upper_bound": item["hi_cons"] or cons,
                    },
                }

        for var, neq_list in neq_constraints.items():
            item = _ensure(var)
            if item["lo"] == item["hi"]:
                point = int(item["lo"])
                for neq_cons in neq_list:
                    if int(neq_cons["value"]) == point:
                        return {
                            "feasible": False,
                            "ranges": {},
                            "bottom_reason": {
                                "variable": var,
                                "point_constraint": item["lo_cons"] or item["hi_cons"],
                                "not_equal_constraint": neq_cons,
                            },
                        }

        ranges = {}
        for var, item in bounds.items():
            lo = None if item["lo"] == -math.inf else int(item["lo"])
            hi = None if item["hi"] == math.inf else int(item["hi"])
            ranges[var] = [lo, hi]
        return {"feasible": True, "ranges": ranges, "bottom_reason": None}

    def solve_with_explain(self, constraints: List[dict]) -> dict:
        normalized = self._normalize_constraints(constraints)
        if not normalized:
            return {
                "feasible": True,
                "backend": self.backend,
                "normalized_constraints": [],
                "ranges": {},
                "bottom_reason": None,
                "apron_error": self.apron_error,
            }

        apron_feasible = None
        if self._apron is not None:
            try:
                apron_feasible = self._apron.is_feasible(normalized)
            except Exception as exc:
                self.apron_error = f"Apron solve failed, fallback to interval: {exc}"
                self._apron = None
                self.backend = "interval"
                self.apron_available = False

        interval_result = self._interval_solve_with_explain(normalized)
        if apron_feasible is False:
            interval_result["feasible"] = False

        return {
            "feasible": bool(interval_result.get("feasible", True)),
            "backend": self.backend,
            "normalized_constraints": normalized,
            "ranges": interval_result.get("ranges", {}),
            "bottom_reason": interval_result.get("bottom_reason"),
            "apron_error": self.apron_error,
        }

    def is_path_feasible(self, constraints: List[dict]) -> bool:
        solved = self.solve_with_explain(constraints)
        return bool(solved.get("feasible", True))
