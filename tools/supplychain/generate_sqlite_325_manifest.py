#!/usr/bin/env python3
from __future__ import annotations

import json
import tomllib
from pathlib import Path


ROOT = Path("/root/VUL/325/2026.3.25")
CANDIDATES_JSON = ROOT / "candidates.json"
DOCS_DIR = ROOT / "docs"
RULES_DIR = DOCS_DIR / "rules"
MANIFEST_PATH = DOCS_DIR / "analysis_manifest_generated.json"


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sqlite_rule(*, cve: str, version_range: str, fixed_in: str, description: str) -> list[dict]:
    return [
        {
            "cve": cve,
            "package": "sqlite",
            "version_range": version_range,
            "description": description,
            "match": {
                "crates": ["rusqlite", "libsqlite3-sys"],
            },
            "symbols": [
                "sqlite3_bind_text64",
                "sqlite3_bind_blob64",
                "sqlite3_exec",
            ],
            "source_status": "system",
            "enforce_rust_sinks": True,
            "rust_sinks": [
                {"path": "rusqlite::Connection::execute"},
                {"path": "rusqlite::Connection::execute_batch"},
                {"path": "rusqlite::Statement::execute"},
                {"path": "rusqlite::Connection::query_row"},
                {"path": "rusqlite::Connection::query_map"},
                {"path": "rusqlite::Statement::query"},
                {"path": "rusqlite::Connection::prepare"},
                {"path": "Connection::execute"},
                {"path": "Connection::query_row"},
                {"path": "Connection::prepare"},
            ],
            "input_predicate": {
                "class": "crafted_sql_or_database_input",
                "positive_tokens": ["sql", "sqlite", "query", "insert", "update", "select", "blob", "text", "string", "db"],
                "negative_tokens": [],
                "strategy": "assume_if_not_explicit",
            },
            "context_patterns": [
                "sqlite",
                "rusqlite",
                "sql",
                "query",
                "execute",
                "prepare",
                "statement",
                "blob",
                "text",
                "database",
            ],
            "trigger_conditions": [
                "project resolves to bundled SQLite below the fixed version",
                "Rust code reaches rusqlite statement execution or query preparation paths",
                "attacker-controlled SQL text, bound values, or database content reaches SQLite parsing or execution logic",
            ],
            "trigger_model": {
                "conditions": [
                    {
                        "id": "sqlite_exec_any",
                        "type": "any_of",
                        "conditions": [
                            {"id": "sqlite_execute", "type": "call", "name": "execute", "lang": "Rust"},
                            {"id": "sqlite_execute_batch", "type": "call", "name": "execute_batch", "lang": "Rust"},
                            {"id": "sqlite_statement_execute", "type": "call", "name": "Statement::execute", "lang": "Rust"},
                            {"id": "sqlite_query_row", "type": "call", "name": "query_row", "lang": "Rust"},
                            {"id": "sqlite_query_map", "type": "call", "name": "query_map", "lang": "Rust"},
                            {"id": "sqlite_statement_query", "type": "call", "name": "Statement::query", "lang": "Rust"},
                            {"id": "sqlite_prepare", "type": "call", "name": "prepare", "lang": "Rust"},
                        ],
                    },
                    {
                        "id": "sqlite_sql_input",
                        "type": "input_class",
                        "class": "crafted_sql_or_database_input",
                        "positive_tokens": ["sql", "sqlite", "query", "insert", "update", "select", "blob", "text", "string", "database", "db"],
                        "negative_tokens": [],
                        "strategy": "assume_if_not_explicit",
                    },
                ],
                "mitigations": [],
            },
            "notes": {
                "fixed_in": fixed_in,
                "family": "sqlite",
            },
        }
    ]


def cve_for_candidate(candidate: dict) -> tuple[str, str, Path]:
    sqlite_version = str(candidate.get("resolution", {}).get("sqlite") or "").strip()
    if sqlite_version == "3.49.1":
        cve = "CVE-2025-6965"
        cve_dir = "CVE-2025-6965__sqlite"
        rules_path = RULES_DIR / "sqlite_cve_2025_6965.json"
    else:
        cve = "CVE-2025-7709"
        cve_dir = "CVE-2025-7709__sqlite"
        rules_path = RULES_DIR / "sqlite_cve_2025_7709.json"
    return cve, cve_dir, rules_path


def detect_sqlite_feature(project_dir: Path) -> tuple[str, bool]:
    cargo_toml = project_dir / "Cargo.toml"
    if not cargo_toml.exists():
        return "", False
    data = tomllib.loads(cargo_toml.read_text(encoding="utf-8", errors="ignore"))
    deps = {
        name
        for table_name in ("dependencies", "dev-dependencies", "build-dependencies")
        for name in (data.get(table_name) or {}).keys()
    }
    sqlite_related = {"rusqlite", "r2d2_sqlite", "rusqlite_migration", "libsqlite3-sys"}
    if not deps & sqlite_related:
        return "", False

    features = data.get("features") or {}
    priority = ["rusqlite-bundled", "rusqlite", "sqlite", "sql", "blocking"]
    for name in priority:
        values = features.get(name)
        if not isinstance(values, list):
            continue
        tokens = " ".join(str(value) for value in values)
        if any(dep in tokens for dep in ("rusqlite", "r2d2_sqlite", "rusqlite_migration", "libsqlite3")):
            return name, True
    for name, values in features.items():
        if not isinstance(values, list):
            continue
        tokens = " ".join(str(value) for value in values)
        if any(dep in tokens for dep in ("rusqlite", "r2d2_sqlite", "rusqlite_migration", "libsqlite3")):
            return str(name), True
    return "", False


def choose_sqlite_entry(project_dir: Path, sink_file: str) -> str:
    for pattern in ("src/lib.rs", "src/main.rs", "src/rusqlite.rs", "src/sqlite.rs"):
        path = project_dir / pattern
        if path.exists():
            return str(path.resolve())
    candidates: list[Path] = []
    if sink_file:
        sink_path = project_dir / sink_file
        if sink_path.exists() and sink_path not in candidates:
            candidates.append(sink_path)
    for path in sorted(project_dir.rglob("*.rs")):
        rel = path.relative_to(project_dir).as_posix().lower()
        parts = tuple(part.lower() for part in path.relative_to(project_dir).parts)
        if any(part.startswith("target") for part in parts):
            continue
        if "tests" in parts or "examples" in parts:
            continue
        if "mysql" in rel or "postgres" in rel:
            continue
        if "sqlite" in rel or "rusqlite" in rel:
            candidates.append(path)
    for path in candidates:
        if path.exists():
            return str(path.resolve())
    return ""


def build_manifest() -> list[dict]:
    payload = load_json(CANDIDATES_JSON)
    items: list[dict] = []
    for candidate in payload.get("candidates", []):
        project_dir = Path(candidate["local_source"]).resolve()
        rel = str(project_dir.relative_to(Path("/root/VUL")))
        cve, cve_dir, rules_path = cve_for_candidate(candidate)
        sink_file = candidate.get("sink", {}).get("file") or ""
        cpg_input = choose_sqlite_entry(project_dir, sink_file)
        cargo_features, cargo_no_default_features = detect_sqlite_feature(project_dir)
        dependency_evidence = [
            {
                "crate": "rusqlite",
                "version": candidate.get("resolution", {}).get("rusqlite"),
                "reason": candidate.get("resolution", {}).get("evidence"),
            },
            {
                "crate": "libsqlite3-sys",
                "reason": "bundled SQLite dependency path",
            },
        ]
        items.append(
            {
                "rel": rel,
                "project_dir": str(project_dir),
                "cve_dir": cve_dir,
                "vulns": str(rules_path.resolve()),
                "root": str(candidate.get("crate") or "").replace("-", "_"),
                "root_method": "main",
                "cpg_input": cpg_input if cpg_input and Path(cpg_input).exists() else "",
                "project": candidate.get("crate"),
                "version": candidate.get("version"),
                "family": "sqlite",
                "component": "sqlite",
                "cve": cve,
                "code_hit_file": sink_file,
                "source_label": "325 rusqlite bundled sqlite candidates",
                "dependency_evidence": dependency_evidence,
                "cargo_features": cargo_features,
                "cargo_no_default_features": cargo_no_default_features,
            }
        )
    return items


def main() -> None:
    write_json(
        RULES_DIR / "sqlite_cve_2025_7709.json",
        sqlite_rule(
            cve="CVE-2025-7709",
            version_range="<3.50.3",
            fixed_in="3.50.3",
            description="SQLite bundled dependency below 3.50.3 reachable through rusqlite statement execution or query preparation.",
        ),
    )
    write_json(
        RULES_DIR / "sqlite_cve_2025_6965.json",
        sqlite_rule(
            cve="CVE-2025-6965",
            version_range="<3.50.2",
            fixed_in="3.50.2",
            description="SQLite bundled dependency below 3.50.2 reachable through rusqlite statement execution or query preparation.",
        ),
    )
    items = build_manifest()
    write_json(MANIFEST_PATH, items)
    print(json.dumps({"manifest": str(MANIFEST_PATH), "count": len(items)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
