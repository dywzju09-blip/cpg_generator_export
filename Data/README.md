# 漏洞数据库说明

本目录用于保存项目默认使用的 Rust-native 组件漏洞数据库。

## 目录结构

```text
Data/
└── vuln_db/
    ├── catalog/
    ├── components/
    ├── vulns/
    ├── evidence/
    └── indexes/
```

各目录职责如下：

- `components/`: 组件级知识。包括 crate 映射、默认 sink、输入类别、间接依赖模板。
- `catalog/`: 从公开漏洞源抓取并标准化后的补充规则原始目录。
- `vulns/`: 单个组件漏洞规则。格式兼容当前 `supplychain_analyze.py`。
- `evidence/`: 单个漏洞的证据摘要与引用入口。
- `indexes/`: 运行时索引。分析器默认直接读取这里的总表。

## 版本信息

数据库现在包含两层版本信息：

- 漏洞层：每条规则都有 `version_range` 和结构化的 `affected_versions`
- 组件层：每个组件文件都有 `version_summary`

其中 `affected_versions` 会拆成：

- `range_expr`
- `lower_bounds`
- `upper_bounds`
- `exact_versions`
- `fixed_versions`

这比只存一条字符串更适合后续做版本过滤和规则裁剪。

## 默认入口

当前分析器默认读取以下文件：

- 规则总表：`Data/vuln_db/indexes/runtime_rules.full.json`
- 组件知识库：`Data/vuln_db/indexes/component_knowledge.json`

对应代码入口：

- [`tools/supplychain/supplychain_analyze.py`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
- [`tools/supplychain/run_manifest_analysis.py`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/run_manifest_analysis.py)

如果命令行显式传入 `--vulns` 或 `--sink-kb`，则会覆盖默认数据库路径。

批量分析默认会先通过裁剪器按项目依赖筛出子规则，再写入当前 case 的 `analysis_inputs/vulns.json`。

## 重建数据库

数据库源定义位于：

- [`tools/supplychain/vuln_db_seed.py`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/vuln_db_seed.py)
- `Data/vuln_db/catalog/auto_cves_2021_2026.json`

聚合脚本位于：

- [`tools/supplychain/build_vuln_db.py`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/build_vuln_db.py)
- [`tools/supplychain/select_vuln_rules.py`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/select_vuln_rules.py)
- [`tools/supplychain/fetch_popular_component_cves.py`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/fetch_popular_component_cves.py)

重建命令：

```bash
python3 tools/supplychain/fetch_popular_component_cves.py --target-total 200
python3 tools/supplychain/build_vuln_db.py
```

执行后会重写：

- `Data/vuln_db/components/*.json`
- `Data/vuln_db/vulns/**/*.json`
- `Data/vuln_db/evidence/**/*.json`
- `Data/vuln_db/indexes/*.json`

## 首批覆盖范围

当前数据库已内置 30 个常用 native 组件族，并优先覆盖近五年的公开漏洞：

- `libxml2`
- `expat`
- `zlib`
- `libwebp`
- `libgit2`
- `sqlite`
- `pcre2`
- `openssl`
- `openh264`
- `gdal`
- `libheif`
- `freetype`
- `gstreamer`
- `libjpeg-turbo`
- `cjson`
- `libpng`
- `libtiff`
- `curl`
- `libarchive`
- `libsndfile`
- `harfbuzz`
- `libssh2`
- `libzip`
- `ffmpeg`
- `libvpx`
- `libaom`
- `xz`
- `brotli`
- `libyaml`
- `libraw`

当前数据库分成两层来源：

- `vuln_db_seed.py`: 30 条人工维护的高置信基础规则
- `catalog/auto_cves_2021_2026.json`: 从公开 CVE 数据补充出的近五年规则

两层来源在构建时会合并成统一的 `curated` 规则表。自动补充规则会保留：

- `published`
- `official_source`
- `source_affected_versions`
- `web_summary`
- 结构化 `affected_versions`

当前数据库规模：

- 组件数：30
- 规则总数：200
- 人工规则：30
- 公网 catalog 规则：170

## 运行时索引

建议优先使用以下索引：

- `runtime_rules.full.json`: 当前全量规则总表
- `runtime_rules.curated.json`: 当前高置信子集
- `component_knowledge.json`: 组件级默认知识库
- `components_by_crate.json`: crate 到 native 组件映射
- `cves_by_component.json`: 组件到 CVE 映射
- `component_alias_index.json`: 别名索引
- `manifest.json`: 数据库元信息

## 数据库裁剪器

裁剪器会根据项目的 Cargo 依赖，从全量数据库中筛出当前项目相关的规则，避免每次全量扫描整个数据库。

命令行用法：

```bash
python3 tools/supplychain/select_vuln_rules.py \
  --cargo-dir /path/to/project \
  --out /tmp/vulns.selected.json
```

常用参数：

- `--curated-only`: 只保留 `curated` 规则
- `--cargo-features`
- `--cargo-all-features`
- `--cargo-no-default-features`

当前 [`tools/supplychain/run_manifest_analysis.py`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/run_manifest_analysis.py) 已默认接入裁剪器。

## 维护约束

- 新增组件时，先补 `vuln_db_seed.py`，再运行构建脚本，不要手工改 `indexes/` 下聚合结果。
- 需要扩展近五年漏洞覆盖时，先运行 `fetch_popular_component_cves.py` 更新 `catalog/`，再运行构建脚本。
- 项目特异的 `must_flow` 或特殊 wrapper 规则，不应直接提升为组件通用规则；先写进相应漏洞条目，确认复用价值后再抽回组件层。
- 如果新增规则依赖 FFI/结构体字段语义，优先同步补充 [`tools/ffi_semantics/ffi_semantics_registry.json`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/ffi_semantics/ffi_semantics_registry.json)。
