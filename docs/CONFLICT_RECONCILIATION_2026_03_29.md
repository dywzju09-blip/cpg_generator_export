# 冲突项目复核结论（2026-03-29）

## 1. 复核范围

本次复核基于：

- `/root/VUL/cases/by-analysis-status/index.json`
- `/root/VUL/cases/by-analysis-status/_runs/2026.3.28_manual_reclassification/README.md`
- 各冲突 case 的 `logs/analysis_run/analysis_report.json`
- 各冲突 case 的 `logs/analysis_run/run.log`

当前归档总量是 `646` 个 case；其中人工复核触达 `151` 个；真正发生“静态结果 -> 人工结果”迁移的有 `19` 个。

这 `19` 个迁移不能混为一种“检测逻辑错误”。复核后可分成四类：

1. 批处理执行环境错误，分析根本没正常跑起来
2. 历史版本 bug，导致单个项目在分析前阶段直接失败
3. `reachable` 门槛过严，Rust 侧已经抓到 wrapper/sink，但 native 依赖链没建出来时被整体判成 `not_reachable`
4. 工具是保守判 `possible`，人工进一步把它升级成 `path_triggered`

## 2. 总体分类

### A. 不是分析逻辑错，而是批处理环境/执行失败

这一类有 `10` 个迁移，其中大多数原始静态结果是 `analysis_failed`，但失败原因不是项目本身不可分析，而是运行环境问题：

- `2026.3.27__rgx-cli-0.8.1__upstream`
- `2026.3.27__article-extractor-1.0.4__upstream`
- `2026.3.27__dazzle-grove-libxml2-0.4.6__upstream`
- `2026.3.27__orly-0.1.7__upstream`
- `2026.3.27__readah-0.1.4__upstream`
- `2026.3.27__xisf-rs-0.0.4__upstream`

这些 case 的 `run.log` 都直接报：

- `ModuleNotFoundError: No module named 'neo4j'`

根因不是 `supplychain_analyze.py` 的漏洞推理逻辑，而是批量入口 `run_manifest_analysis.py` 用 `sys.executable` 递归调用分析器；如果外层批跑脚本本身是用错误的 Python 解释器启动，就会把整批项目错误打成 `analysis_failed`。

相关代码：

- `tools/supplychain/run_manifest_analysis.py`
  - `build_command()`
  - `main()`

同类执行层问题还包括：

- `2026.3.27__article_scraper-2.3.1__upstream`
  - `cargo build for CPG deps failed`
  - `Disk quota exceeded`
- `2026.3.27__dfe-0.5.0__upstream`
  - `neo4j.exceptions.DatabaseUnavailable`
- `already_a__2026.3.22__2026.3.17__dazzle-grove-libxml2-0.4.6__upstream`
  - `generate c cpg failed`
- `already_a__2026.3.22__fatoora-core-0.1.3__upstream`
  - 历史版本 `_analysis_base_env` 递归导致 `RecursionError`

结论：

- 这批冲突不是“检测逻辑判错”，而是“检测根本没执行到推理阶段”。
- 这类失败会严重污染人工复核统计，因为它们会被误看成静态负例。

## 3. 真正的静态欠近似：`reachable` 判定过严

这类是最值得修正的逻辑问题。

典型 case：

- `2026.3.26__libwebp__ril-0.10.3__upstream`
- `2026.3.26__libwebp__webp-animation-0.9.0__upstream`

它们的 `analysis_report.json` 有共同特征：

- `call_reachability_source` 已经是 `rust_method_code_package` 或 `rust_call_package`
- `package_synthetic_sink_calls` / `source_synthetic_sink_calls` 很多
- `Relevant context found` 很强
- 但 `dependency_chain` 为空
- 最终 `reachable = false`

直接原因在 `tools/supplychain/supplychain_analyze.py`：

- `find_best_dep_chain()` 先找 `root:PACKAGE -> ... -> pkg:PACKAGE`
- `dep_reachable = True if dep_chain else False`
- `reachable = dep_reachable and call_reachable`

也就是说，当前实现把“Rust 侧已经明确找到 wrapper/sink 调用”与“native 组件依赖链在图里被建出来”做了强绑定。只要后者缺失，即使前者很强，也会整体打成 `not_reachable`。

这在以下场景会产生系统性漏报：

- feature-gated 依赖没有按正确 features 跑出来
- bundled/binary-only 组件没有形成稳定的 `DEPENDS_ON/NATIVE_DEPENDS_ON`
- wrapper 在 Rust 包内显式引用 native symbol，但 native package 级链条没补齐

`ril-0.10.3` 还叠加了一个 manifest 配置问题：

- 人工记录明确写了 `requires webp feature; prior static run used default features only`

这说明该 case 不是漏洞规则本身错，而是：

1. 批跑没有带上正确 feature
2. 当前 `reachable` 逻辑又过度依赖 `dependency_chain`

## 4. 保守降级，不是“冲突性误报”

以下 case 从静态 `triggerable_possible` 升级成了人工 `path_triggered`：

- `2026.3.26__pcre2__grep-pcre2-0.1.9__upstream`
- `already_a__2026.3.22__2026.3.17__grep-pcre2-0.1.9__upstream`
- `2026.3.26__libwebp__libwebp-image-0.3.0__upstream`
- `fatoora-core`

这类 case 的共同点是：

- `reachable = true`
- 静态结果已经不是负例，而是 `possible`
- 降级原因通常是 `native_analysis_coverage` 不足，或者 trigger guards 只匹配了一部分

对应代码在 `tools/supplychain/supplychain_analyze.py`：

- `if native_analysis_coverage in {"none", "target_only_incomplete"} ...`
- `triggerable == "confirmed"` 时会被降成 `possible`
- 对 `system/binary-only/stub` 源还会额外要求 cross-language native evidence

因此这批不应定义为“检测结果与实际结果冲突”，更准确地说是：

- 工具给了保守的静态上界
- 人工复现把它从 `possible` 提升到 `path_triggered`

这说明当前工具的主要问题不是“瞎报 positive”，而是“对高置信正例不够敢下结论”。

## 5. 负例迁移里哪些不算真正冲突

以下迁移表面上改了分类，但方向上并不和静态结论冲突：

- `not_reachable -> manual_not_observed`
  - `2026.3.26__libtiff__gdal-sys-0.12.0__upstream`
  - `2026.3.26__libwebp__webp-0.3.1__upstream`
  - `2026.3.26__libxml2__xml_c14n-0.3.0__upstream`

这些 case 的人工结果是“运行了入口，但没有观测到漏洞”，和静态负向结论并不矛盾。区别只是：

- 静态系统不知道“你已经真的跑过了”
- 归档系统需要把“已人工验证但未触发”单独分层

所以这类更像归档语义变化，不是推理 bug。

## 6. 本次复核的最终判断

按优先级排序，真正导致“检测结果与实际结果冲突”的问题是：

1. `run_manifest_analysis.py` 缺少运行时依赖自检，导致错误 Python 解释器可把整批项目误打成 `analysis_failed`
2. `supplychain_analyze.py` 的 `reachable = dep_reachable and call_reachable` 过严；当 wrapper/sink 证据很强但 `dependency_chain` 缺失时，会把本应至少 `possible` 的 case 打成 `not_reachable`
3. 某些 case 的 manifest/批跑参数没有保留正确 feature 信息，导致静态分析与人工触发配置不一致
4. `possible -> path_triggered` 这批不是核心 bug，而是当前工具对 native coverage 不完整时刻意保守

## 7. 已落实的保护

本次已经在 `tools/supplychain/run_manifest_analysis.py` 加了批跑前运行时检查：

- 如果当前 `sys.executable` 无法导入 `neo4j`
- 批跑会在开始前直接失败
- 不再把整批项目错误归档成 `analysis_failed`

这能直接阻断本次复核中最常见的一类伪冲突。
