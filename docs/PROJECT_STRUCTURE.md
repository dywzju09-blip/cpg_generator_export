# 项目结构说明

以下是当前项目的标准化结构与职责划分。

```
/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export
├── README.md
├── generate_cpgs.sh
├── run_pipeline.sh
├── run_pipeline_expat.sh
├── c_tools/
│   └── convert_graphml_to_json.py
├── docs/
│   ├── cpg_schema.json
│   ├── Rust_CPG_格式说明.md
│   └── PROJECT_STRUCTURE.md
├── examples/
│   ├── c/
│   │   └── indirect_libxml2/
│   │       ├── component_a.c
│   │       ├── component_b.c
│   │       └── README.md
│   │   └── indirect_expat/
│   │       ├── component_a.c
│   │       ├── component_b.c
│   │       └── README.md
│   └── rust/
│       └── indirect_libxml2_app/
│           ├── Cargo.toml
│           ├── Cargo.lock
│           ├── app/
│           │   ├── Cargo.toml
│           │   ├── build.rs
│           │   └── src/main.rs
│           ├── crate_a/
│           │   ├── Cargo.toml
│           │   └── src/lib.rs
│           └── crate_b/
│               ├── Cargo.toml
│               └── src/lib.rs
│       └── indirect_expat_app/
│           ├── Cargo.toml
│           ├── app/
│           │   ├── Cargo.toml
│           │   ├── build.rs
│           │   └── src/main.rs
│           ├── crate_a/
│           │   ├── Cargo.toml
│           │   └── src/lib.rs
│           └── crate_b/
│               ├── Cargo.toml
│               └── src/lib.rs
├── rust_src/
│   ├── Cargo.toml
│   └── src/...
└── tools/
    ├── fetch/
    │   ├── fetch_official_so.py
    │   └── so_sources.json
    ├── neo4j/
    │   ├── import_cpg.py
    │   └── link_cpgs.py
    ├── pipeline/
    │   ├── build_indirect_libxml2.sh
    │   └── build_indirect_expat.sh
    └── supplychain/
        ├── auto_extras.py
        ├── deps_from_cargo.py
        ├── supplychain_analyze.py
        ├── supplychain_extras_expat.json
        ├── supplychain_vulns_expat.json
        ├── supplychain_extras_libxml2.json
        ├── supplychain_vulns_libxml2.json
        ├── vuln_registry.json
        └── vuln_registry.py
```

## 目录职责

- `c_tools/`: C 语言 CPG 生成与 GraphML → JSON 转换。
- `rust_src/`: Rust CPG 生成器实现。
- `examples/`: 真实漏洞链示例（间接依赖 + libxml2 XXE / expat entity expansion）。
- `tools/`: 工程化脚本统一归档（fetch / neo4j / supplychain / pipeline）。
- `docs/`: CPG schema 与项目结构说明。
