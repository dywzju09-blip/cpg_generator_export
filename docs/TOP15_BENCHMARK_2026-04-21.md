# Top15 Benchmark Rerun Notes

日期：`2026-04-21`

## 本轮已完成的工具改动

- 在 [`tools/supplychain/internal_baselines.py`](/root/cpg_generator_export/tools/supplychain/internal_baselines.py) 增加了 `project_ours_accuracy_first_from_support(...)`
  - 把 `triggerable=possible` 从旧逻辑的直接映射 `triggerable` 改成更保守的 `reachable_but_not_triggerable`
  - 这符合当前“准确率优先”的要求
- 在 [`tools/supplychain/test_internal_baselines.py`](/root/cpg_generator_export/tools/supplychain/test_internal_baselines.py) 补了对应单测
- 在 [`tools/supplychain/supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py) 放宽了 `--deps` 的使用条件
  - 现在即使同时传 `--cargo-dir` 和 `--deps`，也能优先走外部依赖图，避免强制重跑 `cargo metadata`
- 在 [`tools/supplychain/run_manifest_analysis.py`](/root/cpg_generator_export/tools/supplychain/run_manifest_analysis.py) 让批量入口支持把 `deps` 继续传给分析器
- 新增了 [`tools/supplychain/run_top15_benchmark.py`](/root/cpg_generator_export/tools/supplychain/run_top15_benchmark.py)
  - 读取新 `benchmark_project.json`
  - 优先复用 benchmark inventory 中已有源码/历史报告/旧 CPG
  - 对 `Cargo.lock` 建立 root-reachable 的简化依赖图
  - 对“目标组件依赖未激活”的项目直接判 `unreachable`
  - 对没有旧 CPG 但有旧 `analysis_report.json` 的项目复用历史报告并重新做 accuracy-first 投影

## 当前 partial run

运行目录：

- [`output/top15_benchmark/top15_accuracy_first_20260421/summary.partial.json`](/root/cpg_generator_export/output/top15_benchmark/top15_accuracy_first_20260421/summary.partial.json)

当前已写入 `summary.partial.json` 的条目数：

- `10`

当前统计：

- `not_reachable`: `5`
- `reused_archived_report`: `5`
- `predicted=unreachable`: `6`
- `predicted=reachable_but_not_triggerable`: `4`
- `correct=yes`: `4`
- `correct=no`: `6`

## 已确认的环境阻塞

### 1. Fresh Cargo metadata / dependency resolution 不稳定

现象：

- `cargo metadata --format-version 1` 经常在 crates registry 阶段卡住或报：
  - `SSL connect error`
  - `Connection reset by peer`

影响：

- 不能稳定对“没有旧 CPG / 旧 report / 旧 inventory 命中”的项目做 fresh rerun

### 2. 直接下载 crates.io 源码也不稳定

现象：

- `urllib.request.urlopen(...)` 下载 crate tarball 时会出现 `Connection reset by peer`

影响：

- 一部分“本机无旧源码”的项目甚至拿不到本地源码副本

## 当前已识别出的误差模式

### 1. Optional / inactive dependency 已经能被快速压回 `unreachable`

示例：

- `grok-2.4.1`
- `grep-0.4.1`
- `scutiger-core-0.3.0`

这些项目通过“root-reachable lockfile dependency pruning”后，目标组件 crate 不在激活依赖集中，因此直接判 `unreachable`

### 2. `pcre2` 家族仍然存在 package/wrapper 级过宽上提

示例：

- `csv-groupby-0.10.0`
- `logi-0.0.7`
- `hyperpolyglot-0.1.7`

现象：

- 报告中常见：
  - `call_reachability_source = rust_method_code_package` 或 `rust_native_gateway_package`
  - `trigger_model_eval = None`
  - `evidence_calls = None`
  - `downgrade_reason = source_status=system; ... native_dependency_graph_incomplete`

这说明当前工具仍会把“看到包装层/网关级证据”上提为 `reachable_only/possible`
但对 `CVE-2022-1586` 这类 JIT 相关漏洞，很多项目金标其实是 `unreachable`

### 3. 一部分 benchmark 标签和当前漏洞集/历史材料之间存在漂移

示例：

- `image-webp-0.2.4` 在当前 active-dependency 规则下被压成 `unreachable`，但 benchmark 金标是 `triggerable`

这类项目需要后续再核对：

- benchmark 当前标签是不是仍按旧 family/旧 wrapper 口径标注
- 当前 runtime rule 的 crate mapping 是否过窄

## 已确认的标签漂移记录

### 1. `hyperpolyglot-0.1.7` / `pcre2` / `CVE-2022-1586`

数据集标签：

- `label_status = manual_archived_label`
- `matched_case_status = triggerable_confirmed`

本机当前对齐到的归档证据：

- [`benchmark_project.json`](/root/Experiment_Ready_Dataset_Top15/benchmark_project.json)
- [`case.json`](/root/VUL/cases/by-analysis-status/04_runnable_reachable_only/CVE-2022-1586__pcre2/already_a__2026.3.22__2026.3.17__hyperpolyglot-0.1.7__upstream/docs/case.json)

归档 `case.json` 的实际状态：

- `case_status = reachable_only`

处理策略：

- 认定为 `benchmark archived label drift`
- 不计入当前工具准确率统计
- 在基准跑批结果中记录后跳过

备注：

- 这类问题归因于数据集标签与当前可定位到的历史归档证据不一致，不归因于当前检测器逻辑本身

## 建议的下一步

1. 如果你要我继续把 full batch 跑完，最有效的补充不是再改投影逻辑，而是补一个本地可用的源码缓存
   - 至少把 `benchmark_project.json` 里缺失的那些项目源码放到本机
2. 如果你更关注工具精度，优先继续收紧 `pcre2` 家族
   - 对缺少 `trigger_model_eval/evidence_calls` 的 wrapper 级命中进一步降级
3. 如果你更关注覆盖率，优先解决 crates registry 网络问题
   - 否则 fresh CPG 路径仍然会被 `cargo metadata` 和 crate 下载阻塞
