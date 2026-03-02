from neo4j import GraphDatabase
import argparse
import json
import os
import re
import sys
import subprocess

# Neo4j configuration
URI = "bolt://localhost:7687"
AUTH = ("neo4j", "password")

DEFAULT_DEPS = ""
DEFAULT_VULNS = "tools/supplychain/supplychain_vulns_libxml2.json"
DEFAULT_REPORT = "output/analysis_report.json"

SUPPLYCHAIN_REL_TYPES = [
    "DEPENDS_ON", "HAS_VERSION", "EXPOSES_VULN",
    "PROVIDES_SYMBOL", "RESOLVES_TO", "USES_SYMBOL", "PKG_CALL"
]

def parse_version(v):
    parts = []
    for p in str(v).split("."):
        try:
            parts.append(int(p))
        except:
            parts.append(0)
    return tuple(parts)

def cmp_version(a, b):
    a_t = parse_version(a)
    b_t = parse_version(b)
    max_len = max(len(a_t), len(b_t))
    a_t = a_t + (0,) * (max_len - len(a_t))
    b_t = b_t + (0,) * (max_len - len(b_t))
    if a_t < b_t:
        return -1
    if a_t > b_t:
        return 1
    return 0

def version_in_range(version, range_expr):
    if not range_expr:
        return True
    clauses = [c.strip() for c in range_expr.split(",") if c.strip()]
    for clause in clauses:
        if clause.startswith(">="):
            if cmp_version(version, clause[2:]) < 0:
                return False
        elif clause.startswith(">"):
            if cmp_version(version, clause[1:]) <= 0:
                return False
        elif clause.startswith("<="):
            if cmp_version(version, clause[2:]) > 0:
                return False
        elif clause.startswith("<"):
            if cmp_version(version, clause[1:]) >= 0:
                return False
        elif clause.startswith("=="):
            if cmp_version(version, clause[2:]) != 0:
                return False
        else:
            # Fallback: exact match
            if cmp_version(version, clause) != 0:
                return False
    return True

def load_json(path):
    with open(path, "r") as f:
        return json.load(f)

def run_metadata(cargo_dir):
    cmd = ["cargo", "metadata", "--format-version", "1"]
    res = subprocess.run(cmd, cwd=cargo_dir, capture_output=True, text=True)
    if res.returncode != 0:
        print(res.stderr)
        raise RuntimeError("cargo metadata failed")
    return json.loads(res.stdout)

def build_deps_from_cargo(meta):
    id_to_pkg = {p["id"]: p for p in meta.get("packages", [])}
    packages = []
    for p in meta.get("packages", []):
        packages.append({
            "name": p["name"],
            "version": p["version"],
            "lang": "Rust"
        })

    depends = []
    resolve = meta.get("resolve", {})
    for node in resolve.get("nodes", []):
        src = id_to_pkg.get(node["id"])
        if not src:
            continue
        for dep in node.get("deps", []):
            dst = id_to_pkg.get(dep["pkg"])
            if not dst:
                continue
            depends.append({
                "from": src["name"],
                "to": dst["name"],
                "evidence_type": "cargo",
                "confidence": "high",
                "source": "cargo metadata",
                "evidence": "resolve graph"
            })

    root = None
    if meta.get("workspace_default_members"):
        root_id = meta["workspace_default_members"][0]
        root = id_to_pkg.get(root_id, {}).get("name")
    if not root and meta.get("packages"):
        root = meta["packages"][0]["name"]
    return {"root": root or "app", "packages": packages, "depends": depends}

def merge_extras(deps, extras):
    if not extras:
        return
    existing = {(p["name"], p.get("version", "")) for p in deps.get("packages", [])}
    for p in extras.get("packages", []):
        key = (p["name"], p.get("version", ""))
        if key not in existing:
            deps["packages"].append(p)
            existing.add(key)
    for d in extras.get("depends", []):
        deps["depends"].append(d)

def clear_supplychain(session):
    session.run("""
        MATCH ()-[r]-()
        WHERE type(r) IN $rel_types
        DELETE r
    """, rel_types=SUPPLYCHAIN_REL_TYPES)
    session.run("""
        MATCH (n)
        WHERE n:PACKAGE OR n:VERSION OR n:VULNERABILITY OR n:SYMBOL
        DETACH DELETE n
    """)

def import_dependencies(session, deps):
    packages = deps.get("packages", [])
    depends = deps.get("depends", [])

    for p in packages:
        session.run("""
            MERGE (pkg:PACKAGE {name: $name})
            SET pkg.lang = $lang
        """, name=p["name"], lang=p.get("lang", "Unknown"))

        if p.get("version"):
            session.run("""
                MERGE (ver:VERSION {semver: $ver})
                WITH ver
                MATCH (pkg:PACKAGE {name: $name})
                MERGE (pkg)-[:HAS_VERSION]->(ver)
            """, name=p["name"], ver=p["version"])

    for d in depends:
        session.run("""
            MATCH (a:PACKAGE {name: $from})
            MATCH (b:PACKAGE {name: $to})
            MERGE (a)-[r:DEPENDS_ON]->(b)
            SET r.evidence_type = coalesce($evidence_type, r.evidence_type)
            SET r.confidence = coalesce($confidence, r.confidence)
            SET r.source = coalesce($source, r.source)
            SET r.evidence = coalesce($evidence, r.evidence)
        """, parameters={
            "from": d["from"],
            "to": d["to"],
            "evidence_type": d.get("evidence_type"),
            "confidence": d.get("confidence"),
            "source": d.get("source"),
            "evidence": d.get("evidence")
        })

def import_vulns(session, vulns, deps):
    package_versions = {}
    for p in deps.get("packages", []):
        if p.get("version"):
            package_versions.setdefault(p["name"], []).append(p["version"])

    for v in vulns:
        cve = v["cve"]
        pkg_name = v["package"]
        vrange = v.get("version_range", "")
        session.run("""
            MERGE (v:VULNERABILITY {cve: $cve})
            SET v.description = $desc
        """, cve=cve, desc=v.get("description", ""))

        # Attach to versions that satisfy the range
        matched = False
        for ver in package_versions.get(pkg_name, []):
            if version_in_range(ver, vrange):
                matched = True
                session.run("""
                    MATCH (p:PACKAGE {name: $pkg})
                    MATCH (ver:VERSION {semver: $ver})
                    MATCH (v:VULNERABILITY {cve: $cve})
                    MERGE (p)-[:HAS_VERSION]->(ver)
                    MERGE (ver)-[:EXPOSES_VULN]->(v)
                """, pkg=pkg_name, ver=ver, cve=cve)

        if not matched:
            # Fallback: attach to package if no version info
            session.run("""
                MATCH (p:PACKAGE {name: $pkg})
                MATCH (v:VULNERABILITY {cve: $cve})
                MERGE (p)-[:EXPOSES_VULN]->(v)
            """, pkg=pkg_name, cve=cve)

def attach_symbols(session, vulns):
    for v in vulns:
        pkg_name = v["package"]
        source_status = v.get("source_status")
        for sym in v.get("symbols", []):
            session.run("""
                MERGE (s:SYMBOL {name: $sym, lang: "C"})
                SET s.source_status = coalesce($status, s.source_status)
                WITH s
                MATCH (p:PACKAGE {name: $pkg})
                MERGE (p)-[:PROVIDES_SYMBOL]->(s)
            """, sym=sym, pkg=pkg_name, status=source_status)

            # Resolve to C method if present
            session.run("""
                MATCH (s:SYMBOL {name: $sym, lang:"C"})
                MATCH (m:METHOD:C {name: $sym})
                MERGE (s)-[:RESOLVES_TO]->(m)
                SET m.package = $pkg
            """, sym=sym, pkg=pkg_name)

def attach_root_package_to_rust_methods(session, root_pkg):
    session.run("""
        MATCH (m:METHOD:Rust)
        WHERE m.package IS NULL
        SET m.package = $pkg
    """, pkg=root_pkg)

def build_symbol_usage(session):
    session.run("""
        MATCH (c:CALL:Rust)-[:FFI_CALL]->(m:METHOD:C)
        MATCH (s:SYMBOL {name: m.name, lang:"C"})
        MERGE (c)-[:USES_SYMBOL]->(s)
    """)
    # Fallback for missing C bodies: link Rust FFI calls by name to symbols
    session.run("""
        MATCH (c:CALL:Rust {is_ffi: true})
        MATCH (s:SYMBOL {lang:"C"})
        WHERE c.name = s.name
        MERGE (c)-[:USES_SYMBOL]->(s)
    """)
    # Link C calls to symbols (binary-only .so usage)
    session.run("""
        MATCH (c:CALL:C)
        MATCH (s:SYMBOL {lang:"C"})
        WHERE c.name = s.name
        MERGE (c)-[:USES_SYMBOL]->(s)
    """)

def link_c_calls_by_name(session):
    session.run("""
        MATCH (c:CALL:C), (m:METHOD:C)
        WHERE c.name = m.name
          AND NOT c.name STARTS WITH "<"
          AND NOT c.name STARTS WITH "operator"
        MERGE (c)-[:CALL]->(m)
    """)

def build_pkg_call(session, root_pkg):
    session.run("""
        MATCH (c:CALL:Rust)-[:FFI_CALL]->(m:METHOD:C)
        WITH DISTINCT m
        MATCH (p1:PACKAGE {name: $root})
        MATCH (p2:PACKAGE {name: m.package})
        MERGE (p1)-[:PKG_CALL {derived:true}]->(p2)
    """, root=root_pkg)
    session.run("""
        MATCH (p1:PACKAGE {name: $root})
        MATCH (c:CALL:Rust)-[:USES_SYMBOL]->(s:SYMBOL)-[:PROVIDES_SYMBOL]->(p2:PACKAGE)
        MERGE (p1)-[:PKG_CALL {derived:true}]->(p2)
    """, root=root_pkg)
    session.run("""
        MATCH (p1:PACKAGE {name: $root})
        MATCH (c:CALL:C)-[:USES_SYMBOL]->(s:SYMBOL)-[:PROVIDES_SYMBOL]->(p2:PACKAGE)
        MERGE (p1)-[:PKG_CALL {derived:true}]->(p2)
    """, root=root_pkg)

def find_dep_chain(session, root, pkg):
    res = session.run("""
        MATCH p=(root:PACKAGE {name: $root})-[:DEPENDS_ON*0..]->(pkg:PACKAGE {name: $pkg})
        RETURN [n IN nodes(p) | n.name] AS chain
        LIMIT 1
    """, root=root, pkg=pkg).single()
    return res["chain"] if res else []

def find_dep_chain_evidence(session, root, pkg):
    res = session.run("""
        MATCH p=(root:PACKAGE {name: $root})-[:DEPENDS_ON*0..]->(pkg:PACKAGE {name: $pkg})
        RETURN [rel IN relationships(p) | {
            from: startNode(rel).name,
            to: endNode(rel).name,
            evidence_type: rel.evidence_type,
            confidence: rel.confidence,
            source: rel.source,
            evidence: rel.evidence
        }] AS edges
        LIMIT 1
    """, root=root, pkg=pkg).single()
    return res["edges"] if res else []

def find_call_chain_to_method(session, root_method, symbol):
    res = session.run("""
        MATCH p=shortestPath(
            (m:METHOD:Rust {name: $root})-[:CFG|AST|CALL|FFI_CALL*0..]->(cm:METHOD:C {name: $sym})
        )
        RETURN [n IN nodes(p) | {id: n.id, labels: labels(n), name: n.name, code: n.code}] AS chain
        LIMIT 1
    """, root=root_method, sym=symbol).single()
    return res["chain"] if res else []

def find_call_chain_to_call(session, root_method, symbol):
    res = session.run("""
        MATCH p=shortestPath(
            (m:METHOD:Rust {name: $root})-[:CFG|AST|CALL|FFI_CALL*0..]->(c:CALL:C {name: $sym})
        )
        RETURN [n IN nodes(p) | {id: n.id, labels: labels(n), name: n.name, code: n.code}] AS chain
        LIMIT 1
    """, root=root_method, sym=symbol).single()
    return res["chain"] if res else []

def extract_function_names(chain_nodes):
    out = []
    for n in chain_nodes:
        labels = n.get("labels", [])
        if "METHOD" in labels or "CALL" in labels:
            name = n.get("name")
            if name:
                out.append(name)
    return out

def pick_trigger_point(chain_nodes, symbol):
    if not chain_nodes:
        return None
    for n in reversed(chain_nodes):
        labels = n.get("labels", [])
        if "CALL" in labels and n.get("name") == symbol:
            return {"id": n.get("id"), "label": "CALL", "name": n.get("name")}
    for n in reversed(chain_nodes):
        labels = n.get("labels", [])
        if "METHOD" in labels and n.get("name") == symbol:
            return {"id": n.get("id"), "label": "METHOD", "name": n.get("name")}
    last = chain_nodes[-1]
    return {"id": last.get("id"), "label": ",".join(last.get("labels", [])), "name": last.get("name")}

def collect_method_calls(session, method_id, lang, method_name=None):
    if lang == "Rust":
        res = session.run("""
            MATCH (m:METHOD:Rust {id: $mid})-[:CFG]->(entry:BLOCK)
            MATCH (entry)-[:CFG*0..]->(b:BLOCK)-[:AST]->(c:CALL)
            RETURN DISTINCT c.id as id, c.name as name, c.code as code
        """, mid=method_id)
    else:
        res = session.run("""
            MATCH (m:METHOD:C {id: $mid})-[:AST*0..]->(c:CALL:C)
            RETURN DISTINCT c.id as id, c.name as name, c.code as code
        """, mid=method_id)

    calls = []
    for r in res:
        if not r.get("name"):
            continue
        calls.append({
            "id": r.get("id"),
            "name": r.get("name"),
            "code": r.get("code"),
            "lang": lang,
            "method": method_name
        })
    return calls

def find_enclosing_method(session, call_id):
    res = session.run("""
        MATCH (m:METHOD:Rust)-[:CFG]->(entry:BLOCK)
        MATCH (entry)-[:CFG*0..]->(b:BLOCK)-[:AST]->(c:CALL {id: $cid})
        RETURN m.id as id, m.name as name
        LIMIT 1
    """, cid=call_id).single()
    return (res["id"], res["name"]) if res else (None, None)

def collect_chain_calls(chain_nodes):
    calls = []
    for n in chain_nodes:
        labels = n.get("labels", [])
        if "CALL" not in labels:
            continue
        name = n.get("name")
        if not name:
            continue
        lang = "Rust" if "Rust" in labels else ("C" if "C" in labels else None)
        calls.append({
            "id": n.get("id"),
            "name": name,
            "code": n.get("code"),
            "lang": lang,
            "method": None,
            "scope": "chain"
        })
    return calls

def collect_evidence_calls(session, chain_nodes):
    chain_calls = collect_chain_calls(chain_nodes)
    methods = []
    for n in chain_nodes:
        if "METHOD" in n.get("labels", []) and n.get("id"):
            methods.append(n)

    method_calls = []
    for m in methods:
        labels = m.get("labels", [])
        if "Rust" in labels:
            lang = "Rust"
        elif "C" in labels:
            lang = "C"
        else:
            continue
        method_calls.extend(collect_method_calls(session, m["id"], lang, method_name=m.get("name")))

    seen = set()
    all_calls = []
    for c in chain_calls + method_calls:
        key = (c.get("id"), c.get("name"), c.get("lang"))
        if key in seen:
            continue
        seen.add(key)
        all_calls.append(c)

    return {
        "chain_calls": chain_calls,
        "all_calls": all_calls
    }

def _as_list(val):
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]

def _match_call_name(call_name, names, name_regex):
    if names:
        return call_name in names
    if name_regex:
        return re.search(name_regex, call_name or "") is not None
    return False

def _match_code_contains(code, contains_list, contains_all=True):
    if not contains_list:
        return True
    if not code:
        return False
    if contains_all:
        return all(c in code for c in contains_list)
    return any(c in code for c in contains_list)

def eval_condition(cond, calls_all, calls_chain):
    ctype = cond.get("type", "call")
    if ctype in ["any_of", "all_of"]:
        sub = cond.get("conditions", [])
        results = [eval_condition(s, calls_all, calls_chain) for s in sub]
        if ctype == "any_of":
            ok = any(r["ok"] for r in results)
            evidence = []
            for r in results:
                if r["ok"]:
                    evidence.extend(r["evidence"])
            return {"ok": ok, "evidence": evidence}
        ok = all(r["ok"] for r in results)
        evidence = []
        for r in results:
            if r["ok"]:
                evidence.extend(r["evidence"])
        return {"ok": ok, "evidence": evidence}
    if ctype == "not":
        sub = cond.get("condition") or {}
        res = eval_condition(sub, calls_all, calls_chain)
        return {"ok": not res["ok"], "evidence": res["evidence"]}

    scope = cond.get("scope", "any")
    calls = calls_chain if scope == "chain" else calls_all

    names = _as_list(cond.get("name") or cond.get("names"))
    name_regex = cond.get("name_regex", "")
    lang = cond.get("lang")
    contains = _as_list(cond.get("contains") or cond.get("code_contains"))
    contains_all = cond.get("contains_all", True)

    matched = []
    for c in calls:
        if lang and c.get("lang") != lang:
            continue
        if names or name_regex:
            if not _match_call_name(c.get("name"), names, name_regex):
                continue
        if ctype in ["call", "call_code_contains"]:
            if ctype == "call_code_contains" and not _match_code_contains(c.get("code"), contains, contains_all):
                continue
            matched.append(c)
            continue
        if ctype == "code_contains":
            if _match_code_contains(c.get("code"), contains, contains_all):
                matched.append(c)
        else:
            matched.append(c)

    return {"ok": len(matched) > 0, "evidence": matched}

def extract_pattern_context(chain_nodes, call_evidence):
    names = []
    for n in chain_nodes:
        if n.get("name"):
            names.append(n.get("name"))
    for c in call_evidence:
        if c.get("name"):
            names.append(c.get("name"))
        if c.get("method"):
            names.append(c.get("method"))
    return list(set(names))

def _split_args(arg_str):
    args = []
    current = []
    depth = 0
    for ch in arg_str:
        if ch == "(" or ch == "[" or ch == "{":
            depth += 1
        elif ch == ")" or ch == "]" or ch == "}":
            if depth > 0:
                depth -= 1
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

def _extract_args_from_call(code):
    if not code:
        return []
    l = code.find("(")
    r = code.rfind(")")
    if l == -1 or r == -1 or r <= l:
        return []
    return _split_args(code[l + 1:r])

def _guess_role(arg):
    a = arg.strip()
    lower = a.lower()
    if "XML_" in a or "FLAG" in a or "OPTION" in a:
        return "flags"
    if any(k in lower for k in ["len", "length", "size", "strlen", "sizeof"]):
        return "len"
    if any(k in lower for k in ["buf", "buffer", "data", "xml", "ptr"]):
        return "buf"
    if any(k in lower for k in ["flag", "flags", "option", "options"]):
        return "flags"
    if re.search(r"\b(cb|callback|handler|hook)\b", lower) or re.search(r"\bon_\w+\b", lower):
        return "callback"
    return None

def _extract_flags(arg):
    if not arg:
        return []
    return re.findall(r"\b[A-Z0-9_]{3,}\b", arg)

def build_ffi_semantics(calls):
    semantics = []
    for c in calls:
        code = c.get("code")
        name = c.get("name")
        if not code:
            continue
        lang = c.get("lang")
        args = _extract_args_from_call(code)
        if not args:
            continue
        param_roles = {}
        flags_evidence = []
        for idx, arg in enumerate(args, start=1):
            role = _guess_role(arg)
            if role:
                param_roles[f"arg{idx}"] = role
            flags_evidence.extend(_extract_flags(arg))

        notes = []
        if "buf" in param_roles.values() and "len" in param_roles.values():
            notes.append("buf/len pattern matched")
        if flags_evidence:
            notes.append("flags tokens detected")

        semantics.append({
            "id": c.get("id"),
            "name": name,
            "lang": lang,
            "code": code,
            "param_roles": param_roles,
            "flags_evidence": sorted(set(flags_evidence)),
            "notes": notes
        })
    return semantics

def build_constraint_result(trigger_model, trigger_hits, ffi_semantics, sanitizer_hits):
    constraints = []
    status = "unknown"

    total_required = len(trigger_model.get("conditions", [])) if trigger_model else 0
    required_hits = len(trigger_hits.get("required_hits", [])) if trigger_hits else 0
    mitigations_hit = len(trigger_hits.get("mitigations_hit", [])) if trigger_hits else 0

    if total_required > 0:
        constraints.append(f"trigger_conditions_matched={required_hits}/{total_required}")

    has_buf_len = False
    flags_observed = False
    for s in ffi_semantics or []:
        roles = s.get("param_roles", {})
        if "buf" in roles.values() and "len" in roles.values():
            has_buf_len = True
        if s.get("flags_evidence"):
            flags_observed = True

    if has_buf_len:
        constraints.append("buf_len_pattern_present")
    if flags_observed:
        constraints.append("flags_observed")
    if sanitizer_hits:
        constraints.append("sanitizer_present")
    if mitigations_hit > 0:
        constraints.append("mitigation_hit")

    if total_required > 0 and required_hits == total_required and mitigations_hit == 0:
        status = "satisfiable"
    elif mitigations_hit > 0:
        status = "unsatisfiable"
    else:
        status = "unknown"

    return {
        "status": status,
        "solver": "lightweight",
        "constraints": constraints
    }

def match_patterns(names, patterns):
    hits = []
    for n in names:
        for p in patterns:
            if p in n:
                hits.append(n)
                break
    return sorted(set(hits))

def analyze_triggerability(session, chain_nodes, trigger_model, source_patterns, sanitizer_patterns, context_keywords=[]):
    if not chain_nodes:
        return {
            "triggerable": "unknown",
            "confidence": "none",
            "evidence_notes": ["No call path analyzed"],
            "method": None,
            "call_id": None,
            "source_calls": [],
            "sanitizer_calls": [],
            "trigger_model": {
                "required_hits": [],
                "required_miss": [],
                "mitigations_hit": []
            }
        }

    evidence = collect_evidence_calls(session, chain_nodes)
    all_calls = evidence["all_calls"]
    chain_calls = evidence["chain_calls"]

    context_names = extract_pattern_context(chain_nodes, all_calls)
    sources = match_patterns(context_names, source_patterns)
    sanitizers = match_patterns(context_names, sanitizer_patterns)
    contexts = match_patterns(context_names, context_keywords)

    trigger_required = []
    trigger_mitigations = []
    if trigger_model:
        trigger_required = trigger_model.get("conditions", [])
        trigger_mitigations = trigger_model.get("mitigations", [])

    required_hits = []
    required_miss = []
    mitigations_hit = []

    for cond in trigger_required:
        res = eval_condition(cond, all_calls, chain_calls)
        entry = {
            "id": cond.get("id"),
            "type": cond.get("type", "call"),
            "name": cond.get("name") or cond.get("names") or cond.get("name_regex"),
            "evidence": res["evidence"]
        }
        if res["ok"]:
            required_hits.append(entry)
        else:
            required_miss.append(entry)

    for cond in trigger_mitigations:
        res = eval_condition(cond, all_calls, chain_calls)
        if res["ok"]:
            mitigations_hit.append({
                "id": cond.get("id"),
                "type": cond.get("type", "call"),
                "name": cond.get("name") or cond.get("names") or cond.get("name_regex"),
                "evidence": res["evidence"]
            })

    total_required = len(trigger_required)
    hit_required = len(required_hits)

    evidence_notes = []
    confidence = "low"

    if total_required > 0:
        ratio = hit_required / total_required
        evidence_notes.append(f"Trigger conditions matched: {hit_required}/{total_required}")
        if ratio == 1.0 and not mitigations_hit:
            confidence = "high"
        elif ratio >= 0.5:
            confidence = "medium"
        else:
            confidence = "low"
    else:
        evidence_notes.append("No trigger model provided; using heuristic signals")

    if sources:
        evidence_notes.append("Untrusted source detected")
        if confidence == "low":
            confidence = "medium"
    if sanitizers:
        evidence_notes.append(f"Sanitizers present: {sanitizers}")
        if confidence == "high":
            confidence = "medium"
    if contexts:
        evidence_notes.append(f"Relevant context found: {contexts}")
        if confidence == "low":
            confidence = "medium"

    if total_required > 0 and hit_required == total_required and not mitigations_hit:
        triggerable = "confirmed"
    elif total_required > 0 and hit_required > 0:
        triggerable = "possible"
    elif total_required == 0 and (sources or contexts):
        triggerable = "possible"
    else:
        triggerable = "unknown"

    return {
        "triggerable": triggerable,
        "confidence": confidence,
        "evidence_notes": evidence_notes,
        "method": None,
        "call_id": None,
        "source_calls": sources,
        "sanitizer_calls": sanitizers,
        "trigger_model": {
            "required_hits": required_hits,
            "required_miss": required_miss,
            "mitigations_hit": mitigations_hit
        }
    }

def get_symbol_status(session, symbol):
    res = session.run("""
        MATCH (s:SYMBOL {name: $sym, lang:"C"})
        OPTIONAL MATCH (s)-[:RESOLVES_TO]->(m:METHOD:C {name: $sym})
        RETURN s.source_status AS s_status, m.source_status AS m_status, m.id AS mid
        LIMIT 1
    """, sym=symbol).single()

    if not res:
        return "binary-only", False

    if res["m_status"]:
        return res["m_status"], True
    if res["mid"]:
        return "local", True
    if res["s_status"]:
        return res["s_status"], False
    return "binary-only", False

def main():
    parser = argparse.ArgumentParser(description="Supply-chain reachability/triggerability analysis")
    parser.add_argument("--deps", default=DEFAULT_DEPS, help="Path to dependency JSON (optional if --cargo-dir is set)")
    parser.add_argument("--cargo-dir", default="", help="Cargo workspace directory (auto-generate deps)")
    parser.add_argument("--extras", default="", help="Extra JSON with packages/depends (C components)")
    parser.add_argument("--vulns", default=DEFAULT_VULNS, help="Path to vulnerabilities JSON")
    parser.add_argument("--root", default="", help="Root package name (override deps.root)")
    parser.add_argument("--root-method", default="main", help="Root method name for call chain")
    parser.add_argument("--report", default=DEFAULT_REPORT, help="Output report JSON")
    parser.add_argument("--clear-supplychain", action="store_true", help="Clear supply-chain nodes/edges")
    args = parser.parse_args()

    if args.cargo_dir:
        meta = run_metadata(args.cargo_dir)
        deps = build_deps_from_cargo(meta)
        if args.extras:
            merge_extras(deps, load_json(args.extras))
    else:
        if not args.deps:
            raise RuntimeError("Missing dependency input: set --cargo-dir or --deps")
        deps = load_json(args.deps)
        if args.extras:
            merge_extras(deps, load_json(args.extras))
    vulns = load_json(args.vulns)
    root_pkg = args.root or deps.get("root", "app")

    driver = GraphDatabase.driver(URI, auth=AUTH)
    report = {
        "root": root_pkg,
        "vulnerabilities": []
    }

    try:
        with driver.session() as session:
            if args.clear_supplychain:
                clear_supplychain(session)

            import_dependencies(session, deps)
            import_vulns(session, vulns, deps)
            attach_symbols(session, vulns)
            attach_root_package_to_rust_methods(session, root_pkg)
            link_c_calls_by_name(session)
            build_symbol_usage(session)
            build_pkg_call(session, root_pkg)

            for v in vulns:
                pkg = v["package"]
                cve = v["cve"]
                vrange = v.get("version_range", "")
                symbols = v.get("symbols", [])

                dep_chain = find_dep_chain(session, root_pkg, pkg)
                dep_chain_evidence = find_dep_chain_evidence(session, root_pkg, pkg)
                dep_reachable = True if dep_chain else False

                for sym in symbols:
                    source_status, has_method = get_symbol_status(session, sym)

                    if has_method:
                        call_chain_nodes = find_call_chain_to_method(session, args.root_method, sym)
                    else:
                        call_chain_nodes = find_call_chain_to_call(session, args.root_method, sym)

                    call_reachable = True if call_chain_nodes else False
                    call_chain = [n.get("name") or n.get("code") for n in call_chain_nodes if n.get("name") or n.get("code")]
                    call_functions = extract_function_names(call_chain_nodes)
                    trigger_point = pick_trigger_point(call_chain_nodes, sym)
                    evidence_calls = collect_evidence_calls(session, call_chain_nodes)
                    ffi_semantics = build_ffi_semantics(evidence_calls["all_calls"])

                    reachable = dep_reachable and call_reachable
                    downgrade_reason = None

                    trig = analyze_triggerability(
                        session,
                        call_chain_nodes,
                        v.get("trigger_model", {}),
                        v.get("source_patterns", []),
                        v.get("sanitizer_patterns", []),
                        context_keywords=v.get("context_patterns", [])
                    )

                    constraint_result = build_constraint_result(
                        v.get("trigger_model", {}),
                        trig.get("trigger_model", {}),
                        ffi_semantics,
                        trig.get("sanitizer_calls", [])
                    )

                    if source_status in ["stub", "binary-only"]:
                        triggerable = "unknown" if reachable else "unreachable"
                        downgrade_reason = f"source_status={source_status}"
                    else:
                        if reachable:
                            triggerable = trig["triggerable"]
                        else:
                            triggerable = "unreachable"

                    report["vulnerabilities"].append({
                        "cve": cve,
                        "package": pkg,
                        "version_range": vrange,
                        "symbol": sym,
                        "reachable": reachable,
                        "triggerable": triggerable,
                        "trigger_confidence": trig["confidence"],
                        "evidence_notes": trig["evidence_notes"],
                        "source_status": source_status,
                        "downgrade_reason": downgrade_reason,
                        "dependency_chain": dep_chain,
                        "dependency_chain_evidence": dep_chain_evidence,
                        "call_chain": call_chain,
                        "call_chain_nodes": call_chain_nodes,
                        "functions_involved": call_functions,
                        "trigger_point": trigger_point,
                        "ffi_semantics": ffi_semantics,
                        "constraint_result": constraint_result,
                        "conditions": {
                            "trigger_conditions": v.get("trigger_conditions", []),
                            "trigger_model": v.get("trigger_model", {}),
                            "trigger_model_hits": trig.get("trigger_model", {}),
                            "source_patterns": v.get("source_patterns", []),
                            "sanitizer_patterns": v.get("sanitizer_patterns", []),
                            "source_hits": trig["source_calls"],
                            "sanitizer_hits": trig["sanitizer_calls"]
                        },
                        "evidence": {
                            "ffi_call_id": trig["call_id"],
                            "method": trig["method"]
                        }
                    })

    finally:
        driver.close()

    os.makedirs(os.path.dirname(args.report), exist_ok=True)
    with open(args.report, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report written to {args.report}")

if __name__ == "__main__":
    main()
