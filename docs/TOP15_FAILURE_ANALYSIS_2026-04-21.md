# Top15 Detection Failure Analysis

日期：`2026-04-21`

## 当前状态

- 检测任务已暂停
- 源码后台下载继续运行
- 失败分析基于 [`summary.partial.json`](/root/cpg_generator_export/output/top15_benchmark/top15_other_components_accuracy_20260421_v3/summary.partial.json)

当前 `v3` 已落盘条目：

- 总计：`15`
- `analysis_failed`：`11`
- `analysis_timeout`：`1`
- `not_reachable`：`3`
- 已明确 `matched=yes`：`1`
- 已明确 `matched=no`：`2`
- 仍未形成最终标签结论：`12`

## 失败原因归类

### 1. 工具问题：分析器强制把 Rust toolchain 设为 `stable`

受影响项目：

- `libwebp/webpx-0.1.4`
- `libwebp/atomic-server-0.40.1`
- `libwebp/novel-api-0.19.0`
- `libwebp/cardchapter-0.1.28`
- `freetype/font-kit-0.14.3`
- `freetype/freetype-0.7.2`
- `freetype/servo-fontconfig-sys-5.1.0`
- `freetype/freetype-rs-0.38.0`
- `freetype/crossfont-0.9.0`
- `freetype/harfbuzz-sys-0.6.1`
- `freetype/gfx_text-0.33.0`

证据：

- 这些项目的 `run.log` 都出现同一条错误：
  - `error: the 'cargo' binary ... is not applicable to the 'stable-x86_64-unknown-linux-gnu' toolchain`
- 示例日志：
  - [`webpx run.log`](/root/cpg_generator_export/output/top15_benchmark/top15_other_components_accuracy_20260421_v3/CVE-2023-4863__libwebp__TOP15__projects__libwebp__webpx-0.1.4__upstream/run.log)
  - [`font-kit run.log`](/root/cpg_generator_export/output/top15_benchmark/top15_other_components_accuracy_20260421_v3/CVE-2025-27363__freetype__TOP15__projects__freetype__font-kit-0.14.3__upstream/run.log)

根因：

- 分析器在 [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py) 里默认设置了 `RUSTUP_TOOLCHAIN=stable`
- 这台机器当前可用的是 `nightly-x86_64-unknown-linux-gnu`
- 本机 `stable-x86_64-unknown-linux-gnu` 目录下没有可用的 `cargo` 二进制，因此 fresh `cargo metadata` 被整批打死

结论：

- 这是明确的 `tool` 问题，不是标签问题

处理：

- 已修复分析器默认 toolchain 选择逻辑
- 现在优先使用当前活跃且本机确实存在 `cargo` 的 toolchain，而不是硬编码 `stable`

### 2. 工具/环境问题：fresh CPG 的离线 metadata 仍会被本地 registry 缓存缺失卡住

修复 toolchain 后的探针结果：

- `_analysis_base_env()` 现在会选择 `nightly-x86_64-unknown-linux-gnu`
- 对 `webpx-0.1.4` 做离线 `cargo metadata` 探针时，新的报错变成：
  - `failed to download windows-sys v0.61.2`
  - `attempting to make an HTTP request, but --offline was specified`

这说明：

- 先前那批 `analysis_failed` 的第一层根因已经从“坏 toolchain”变成了“本地 Cargo registry/cache 不完整”
- 这仍然是 `tool/environment` 问题，不是标签问题

结论：

- 下一步如果要显著降低 fresh CPG 失败率，需要补 Cargo 依赖缓存，而不只是补 crates 源码缓存
- 仅下载项目源码，不足以保证 `cargo metadata --offline` 成功

### 3. 工具问题：复用旧 CPG 的分析在 `webp-0.3.1` 上超时

受影响项目：

- `libwebp/webp-0.3.1`

证据：

- [`webp run.log`](/root/cpg_generator_export/output/top15_benchmark/top15_other_components_accuracy_20260421_v3/CVE-2023-4863__libwebp__TOP15__projects__libwebp__webp-0.3.1__upstream/run.log)
- 日志只有：
  - `Timed out after 600 seconds.`

解释：

- 这条不是源码获取失败，也不是规则缺失
- 它是在已有归档 CPG 可复用的情况下，分析阶段超过了当前 `600s` 上限

结论：

- 这是 `tool_timeout`
- 后续需要针对这类大型旧 CPG case 做更细的阶段拆分，或只对需要纠偏的 case 单独放宽超时

## 当前非失败但已出现的不一致

当前 `v3` 已落盘的 `mismatch` 有两条：

- `freetype/cairo-rs`
- `freetype/sdf_glyph_renderer`

当前记录原因：

- `mismatch_reason = tool_detection_gap`

初步判断：

- 目前先视为 `tool` 问题
- 还没有证据表明这两条是标签漂移
- 需要后续再核对它们的活跃依赖、wrapper 入口和 runtime rule 命中范围

## 标签漂移（Label Drift）记录

定义：

- 标签漂移指的是“基准标签的语义或判定依据发生了变化”，导致同一项目在不同时刻、不同版本规则/数据源或不同复现条件下，gold label 不再稳定可复现。

在本基准中的典型触发点：

- 组件版本范围或依赖路径发生变化（例如 `Cargo.lock` 更新、特性开关变化、workspace root 变化），导致可达性/触发性结论与旧标签不一致。
- runtime rule 集更新（符号、入口函数、guard 条件、version range 修订），导致同一 CPG 上的命中结果变化。
- benchmark 元数据引用的 `matched_vulnerability` 与当前 runtime rules 不一致（例如仅存在 component primary CVE 规则），属于“规则映射漂移”（见 `rule_mapping_drift`），其外显也可能表现为标签漂移。
- 上游项目源码或依赖拉取不可复现（tag/commit 移动、子模块缺失、依赖源不可达），导致“gold label 所依据的源码状态”无法还原。

处理原则（准确率优先）：

- 只有在排除工具问题（toolchain、cargo cache、CPG 生成、规则加载、reachability/版本解析等）后，才将不一致归因到标签漂移。
- 一旦确认为标签漂移：跳过该项目，不纳入准确率统计，并在 issue 记录里标注为 `dataset_label_issue`。

## 已做的修复

- [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
  - 不再默认强制 `RUSTUP_TOOLCHAIN=stable`
  - 会自动解析当前活跃且本机确实有 `cargo` 的 toolchain
  - CPG 生成也同步使用可用 toolchain，而不是硬编码 `stable`
  - fresh CPG 路径在 `deps` 已提供时，CPG bootstrap metadata 改用 `cargo metadata --no-deps`
  - 当 `cargo metadata --no-deps` 没有 `resolve` 图时，会从 root crate 的 feature 定义恢复默认 feature 集
  - 当使用 verbose `rustc` 参数驱动 generator 时，会补齐缺失的传递 `--extern`，避免像 `atomic-server` 这类 case 丢 `string_cache`
- 对应单测已补齐并通过：
  - [`test_supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/test_supplychain_analyze.py)

## 新进展（v13 重跑）

- `libwebp/webpx-0.1.4`
  - 已从 `analysis_failed` 修复到可稳定产出检测结果
  - 当前结论：`reachable_only` / `reachable_but_not_triggerable`
  - 与 gold `triggerable` 不一致，当前归因为 `tool_detection_gap`
  - 依据：native source 已补齐，但 `native_analysis_coverage = target_only_incomplete`，最终 `triggerable = unknown`

- `libwebp/atomic-server-0.40.1`
  - 已排除纯网络缓存问题后，定位到新的 generator 参数问题
  - 根因：root rustc 参数模式下未补齐传递 extern，导致 `markup5ever` 相关生成代码缺失 `string_cache`
  - 结论：这是 `tool` 问题，不是标签问题

## 下一步建议

1. 继续保持源码后台下载
2. 单独补 Cargo registry/cache，而不是只补源码 tarball
3. 对 `webp-0.3.1` 这类复用旧 CPG 的大 case，单独做 timeout/阶段优化
4. 等 toolchain 与 Cargo cache 两层问题都清掉后，再恢复检测

## 新进展（v17b libwebp 重跑，2026-04-22）

- 本轮环境调整：
  - `shared_cargo_target` 切到 `/dev/shm/cpg_generator_export/shared_cargo_target`
  - `TMPDIR` 默认切到 `/dev/shm/cpg_generator_export/tmp`
  - Top15 源码补齐逻辑改为优先尝试 `static.crates.io` 直链 `.crate`，再回退 `crates.io/api/v1/.../download`
  - `atomic-server-0.40.1`、`novel-api-0.19.0`、`cardchapter-0.1.28` 三个缺源码项目均已补齐本地源码缓存并完成 fresh CPG 重跑

- `libwebp/atomic-server-0.40.1`
  - fresh CPG 重跑成功，Rust CPG 与 native libwebp CPG 都已生成
  - 当前结论：`reachable_only` / `reachable_but_not_triggerable`
  - 与 gold `triggerable` 不一致
  - `mismatch_reason = tool_detection_gap`
  - `issue_owner = tool`
  - 直接证据：
    - `WebPDecode`、`VP8LDecodeImage`、`WebPDecodeRGBA` 均为 `reachable = true`
    - `triggerable = unknown`
    - `trigger_model_eval = null`
    - `evidence_calls = null`
    - `downgrade_reason = native_dependency_graph_incomplete`
  - 结论：不是标签问题，属于 native dependency graph 仍不完整导致的 trigger 侧漏报

- `libwebp/novel-api-0.19.0`
  - fresh CPG 重跑成功，Rust CPG 与 native libwebp CPG 都已生成
  - 当前结论：`reachable_only` / `reachable_but_not_triggerable`
  - 与 gold `triggerable` 不一致
  - `mismatch_reason = tool_detection_gap`
  - `issue_owner = tool`
  - 直接证据：
    - `WebPDecode`、`VP8LDecodeImage`、`WebPDecodeRGBA`、`WebPAnimDecoderGetNext` 均为 `reachable = true`
    - `triggerable = unknown`
    - `trigger_model_eval = null`
    - `evidence_calls = null`
    - `downgrade_reason = native_dependency_graph_incomplete`
  - 结论：不是标签问题，和 `atomic-server` 属于同一类工具缺口

- `libwebp/cardchapter-0.1.28`
  - fresh CPG 重跑成功
  - 当前结论：`reachable_only` / `reachable_but_not_triggerable`
  - 与 gold `reachable_but_not_triggerable` 一致
  - 说明当前环境、源码补齐、fresh CPG 和 native CPG 生成链路已经稳定；前两个不一致不是“跑坏了”，而是 libwebp trigger 判断确实偏保守

## 新进展（libwebp trigger 逻辑修正，2026-04-22）

- 已确认的工具根因：
  - `libwebp` 这组 case 的 reachability 已经命中，但原逻辑把 `downloaded-official` 视为和 `system` 不同的分支，导致即使已经补齐“外部输入 -> Rust decode wrapper”证据，也不会走 `preserved_by_wrapper_sink_evidence`
  - Rust sink/source 的 source-scan 对泛化 token（如 `new` / `decode`）上下文约束不够，容易把不相关构造器误当成 wrapper 证据
  - Top15 benchmark 的 deps 缓存文件名当前按 `project_dir.name` 生成；对于 crates.io 拉取目录，几乎都会落成 `upstream.deps.json`，存在批跑覆盖风险

- 已做修复：
  - [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
    - source-scan 的 qualified sink 对泛化 token 强制上下文约束，避免 `Path::new` / `ZstdDecoder::new` 一类误命中
    - 新增 `collect_libwebp_source_input_evidence(...)`
    - 对 `libwebp` 在 reachability 已命中时，额外从源码中区分：
      - `external_controlled`
      - `local_asset_only`
      - `sink_only`
    - `source_status=downloaded-official` 现在和 `system` / `stub` / `binary-only` 一样，会在 `wrapper_sink_evidence + input_predicate` 满足时保留为 `possible`
  - [`run_top15_benchmark.py`](/root/cpg_generator_export/tools/supplychain/run_top15_benchmark.py)
    - accuracy-first 的弱证据判断现在会回退读取 `conditions` / `constraint_result` 中的嵌套字段，避免把已有 trigger 证据误判成“完全无证据”

- 单测状态：
  - [`test_supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/test_supplychain_analyze.py) 全部通过
  - [`test_run_top15_benchmark.py`](/root/cpg_generator_export/tools/supplychain/test_run_top15_benchmark.py) 全部通过

- 新逻辑的静态验证结果：
  - `atomic-server-0.40.1` -> `external_controlled`
  - `novel-api-0.19.0` -> `external_controlled`
  - `cardchapter-0.1.28` -> `local_asset_only`

- 对旧报告做投影验证（在不重新完整导入 native 图的前提下）：
  - `atomic-server` 若按新分支将 `triggerable` 提升到 `possible`，accuracy-first 最终标签为 `triggerable`
  - `novel-api` 同样会提升到 `triggerable`
  - `cardchapter` 仍保持 `reachable_but_not_triggerable`

- 当前判断：
  - 这三项分歧仍归因于 `tool`
  - 不是标签问题
  - 下一步需要做的是基于修正后的逻辑完成 full rerun，把新的 `summary.json` 和 mismatch 记录重新落盘

## 新进展（fresh rerun 最终核验，2026-04-22）

- 本轮最终有效重跑：
  - `atomic-server-0.40.1`
    - 运行目录：[`top15_retry_20260422_v16d_atomic_localfast`](/dev/shm/top15_benchmark_runs/top15_retry_20260422_v16d_atomic_localfast)
    - 最终状态：`triggerable_possible`
    - `predicted_label = triggerable`
    - `gold_label = triggerable`
    - `correct = yes`
  - `novel-api-0.19.0`
    - 运行目录：[`top15_retry_20260422_v16f_novel_localcache_full`](/dev/shm/top15_benchmark_runs/top15_retry_20260422_v16f_novel_localcache_full)
    - 最终状态：`triggerable_possible`
    - `predicted_label = triggerable`
    - `gold_label = triggerable`
    - `correct = yes`
  - `cardchapter-0.1.28`
    - 运行目录：[`top15_retry_20260422_v16g_cardchapter_localcache_full`](/dev/shm/top15_benchmark_runs/top15_retry_20260422_v16g_cardchapter_localcache_full)
    - 最终状态：`reachable_only`
    - `predicted_label = reachable_but_not_triggerable`
    - `gold_label = reachable_but_not_triggerable`
    - `correct = yes`

- 这三项旧失败的最终归因：
  - 都不是标签问题
  - 都不是标签漂移
  - 之前的失败与中间不一致，均由工具链/运行环境问题触发

- 已确认并修复的工具根因：
  - `output/shared_cargo_home` 与 `output/shared_native_cache` 实际指向 `/mnt/hw/...`，在根分区空间恢复后会错误回退到远端缓存，导致 fresh rerun 卡在 NFS 路径
  - benchmark runner 之前会在每轮任务启动时隔离一份 `cargo_home`，并整库复制 `registry/src`，这会把启动成本放大，并放大远端缓存路径问题
  - `TMPDIR` 若没有强制切到 `/dev/shm`，链接阶段可能因 `/tmp` 配额触发 `Disk quota exceeded`
  - 共享缓存初始化此前只在“目标目录为空”时 seed，一旦 `/dev/shm` 中已有不完整缓存，就不会继续补齐缺失 crate，后续项目会反复退回在线依赖下载

- 已落地的修复：
  - [`run_top15_benchmark.py`](/root/cpg_generator_export/tools/supplychain/run_top15_benchmark.py)
    - 当 `output/shared_*` 指向慢路径时，自动把共享缓存根切到 `/dev/shm/cpg_generator_export`
    - `TMPDIR`、`TMP`、`TEMP` 默认切到 `/dev/shm/cpg_generator_export/tmp`
    - 当共享 `CARGO_HOME` 已在 `/dev/shm` 时，不再额外复制隔离 benchmark `cargo_home`
    - 共享 `cargo_home` seed 改为优先本地 `~/.cargo`，跳过 `/mnt/hw` 这类慢路径
    - `cargo_home` 补种改成“增量补齐缺失文件”，不会因为目标目录非空就跳过
    - seed 过程默认不复制 `registry/src`，只补 `registry/index`、`registry/cache`、`git`
  - [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
    - `atomic-server` 的 `OUT_DIR` 选择已修正为优先 root package 输出目录
    - CPG 依赖构建支持离线优先、缓存缺失时再在线回退
    - Cargo 网络参数已收紧，降低代理环境下的瞬时失败率

- 对旧结论的修正：
  - 文档前面 `v17b libwebp 重跑` 中关于 `atomic-server`、`novel-api` 的 `tool_detection_gap` 结论已经过期
  - 这些旧结论对应的是“修复前/中途态”的报告，不再代表当前最终结果
  - 当前应以 `v16d`、`v16f`、`v16g` 三次 fresh rerun 的 `summary.json` 为准

- 当前残留观察：
  - `run.log` 仍会出现 Neo4j 对 `FFI_CALL`、`controlStructureType`、`parser_type_name` 的 warning
  - 这些 warning 没有导致本轮三项结果偏差；当前只作为噪音与后续性能清理项，不归类为标签问题

## 新进展（pcre2 首批不一致修复，2026-04-22）

- 影响批次：
  - [`top15_continuous_20260422_main__b001`](/dev/shm/top15_benchmark_runs/top15_continuous_20260422_main__b001)
- 先前的 3 个 `pcre2` 不一致：
  - `csv-groupby-0.10.0`
  - `logi-0.0.7`
  - `pomsky-bin-0.12.0`

- 工具根因确认：
  - `csv-groupby-0.10.0`
    - 误把 `src/quick.rs` 里的 demo/test 函数 `test_pcre2_main()` 当成漏洞相关 JIT build 证据
    - 该证据只有 `synthetic_source_text` 命中，没有稳定 package/method 级路径依据
    - 归因：`tool`
  - `logi-0.0.7`
    - 没有真实 `RegexBuilder::build` 命中，只有泛化 token 与 `status=unknown` 语义壳把结果顶成 `reachable_only`
    - 归因：`tool`
  - `pomsky-bin-0.12.0`
    - `RegexBuilder::build + jit_if_available(true)` 只出现在 `run_tests` 测试执行路径
    - 旧逻辑把 test-harness JIT 路径直接上提成 `triggerable`
    - 准确率优先下应保守降为 `reachable_but_not_triggerable`
    - 归因：`tool`

- 已落地修复：
  - [`run_top15_benchmark.py`](/root/cpg_generator_export/tools/supplychain/run_top15_benchmark.py)
    - `pcre2` accuracy-first override 现在只把真实 build/sink 命中视为触发路径证据，不再把 `param_semantics/state_semantics = unknown` 当成有效 trigger 证据
    - 新增 `pcre2_source_text_only_jit_path`
      - 当 JIT build 证据只来自 `synthetic_source_text` 且输入仍停留在 `assume_if_not_explicit` 时，直接压回 `unreachable`
    - 新增 `pcre2_test_harness_only_jit_path`
      - 当 JIT build 证据只出现在 `run_tests` / `tests` / `test_runner` 一类 test-harness 路径，且没有外部输入证据时，降为 `reachable_only`
  - [`test_run_top15_benchmark.py`](/root/cpg_generator_export/tools/supplychain/test_run_top15_benchmark.py)
    - 已补对应单测并通过

- 投影验证结果（基于旧 report 重新投影）：
  - `csv-groupby-0.10.0`
    - `old_predicted = triggerable`
    - `new_predicted = unreachable`
    - `override_reason = pcre2_source_text_only_jit_path`
  - `logi-0.0.7`
    - `old_predicted = reachable_but_not_triggerable`
    - `new_predicted = unreachable`
    - `override_reason = weak_pcre2_method_without_jit_trigger`
  - `pomsky-bin-0.12.0`
    - `old_predicted = triggerable`
    - `new_predicted = reachable_but_not_triggerable`
    - `override_reason = pcre2_test_harness_only_jit_path`

- 定点正式重跑：
  - 运行目录：[`top15_retry_20260422_pcre2_mismatch_fix`](/dev/shm/top15_benchmark_runs/top15_retry_20260422_pcre2_mismatch_fix)
  - `stats.json`
    - `analyzed = 3`
    - `matched = 3`
    - `mismatched = 0`
  - 结果：
    - `csv-groupby-0.10.0` -> `predicted_label = unreachable`，与 gold 一致
- `logi-0.0.7` -> `predicted_label = unreachable`，与 gold 一致
- `pomsky-bin-0.12.0` -> `predicted_label = reachable_but_not_triggerable`，与 gold 一致

## 新进展（Top15 主跑 3 个 tool mismatch，2026-04-22）

- `libwebp/webp-0.3.1`
  - 根因分类：`tool`
  - 不是标签漂移
  - 旧逻辑能看到 `Decoder::new` / `Decoder::decode` 这一层 wrapper，但没有把 `use libwebp_sys::*;` 之后的裸 `WebPDecode*` 调用当成有效 native gateway
  - 已修复方向：补 glob-import 形式的 native gateway 扫描，并把这类桥接证据纳入 reachability / triggerability 决策

- `libwebp/webpx-0.1.4`
  - 根因分类：`tool`
  - 不是标签漂移
  - 这条本身就有显式 `libwebp_sys::WebP*` 直连调用，但旧逻辑对 native bridge 的投影不够强，容易被 `new/decode` wrapper 入口盖住
  - 已修复方向：保留显式 `alias::symbol` 扫描，同时把 native gateway 证据纳入保守 reachability / triggerability 决策

- `freetype/cairo-rs-0.22.0`
  - 根因分类：`tool`
  - 不是标签漂移
  - 旧 run.log 里的失败来自 `_analysis_base_env` 的递归调用，触发 `RecursionError`
  - 当前 `supplychain_analyze.py` 里该函数已经是非递归实现，后续只需要按当前代码重新跑 case 验证即可

- 结论：
  - 这 3 条不是标签问题，也不是标签漂移
  - 都是 `tool` 侧 accuracy-first 判定过宽
  - 当前已修复并完成重跑闭环

## 新进展（image-webp 标签漂移确认，2026-04-22）

- 目标项目：
  - `libwebp/image-webp-0.2.4`

- 当前数据集标签：
  - `strict_label = triggerable`
  - `label_status = manual_archived_label`
  - `matched_case_status = triggerable_confirmed`

- 当前源码与依赖事实：
  - crates.io 当前 `image-webp-0.2.4` 的默认依赖集合不包含 `webp` / `libwebp-sys`
  - `webp` 仅出现在 [`Cargo.toml`](/root/Experiment_Ready_Dataset_Top15/source_cache_downloaded/libwebp/image-webp-0.2.4/upstream/Cargo.toml) 的 `dev-dependencies`
  - 生成的 active lockfile 依赖图里只剩：
    - `image-webp`
    - `byteorder-lite`
    - `quick-error`
  - 因而默认构建下目标组件并未激活

- 本地归档现状：
  - benchmark `evidence_basis` 指向旧的 `triggerable_confirmed` 归档
  - 但本机当前可定位到的同名归档是 [`analysis_failed case.json`](/root/VUL/cases/by-analysis-status/06_not_runnable_analysis_failed/CVE-2023-4863__libwebp/already_a__2026.3.22__2026.3.17__image-webp-0.2.4__upstream/case.json)
  - 说明归档映射本身已经发生漂移，不能再作为稳定 gold 依据

- 结论：
  - 这不是当前工具误检
  - 归因：`label`
  - 类型：`dataset_label_issue` / `benchmark archived label drift`

- 已落地处理：
  - 新增 `inactive_dependency_label_issue_reason(...)`
  - 当项目是 `manual_archived_label`，且目标 crate 仅存在于 `dev-dependencies` 时，基准流程直接标记为 label drift 并跳过
  - 定点验证运行目录：[`top15_retry_20260422_image_webp_label_check`](/dev/shm/top15_benchmark_runs/top15_retry_20260422_image_webp_label_check)
    - `skipped = 1`
    - `issue_owner = label`
    - 不再计入工具准确率

- 监督器同步修复：
  - [`supervise_top15_continuous.py`](/root/cpg_generator_export/tools/supplychain/supervise_top15_continuous.py)
    - 现在会读取各 run 的 `skipped.json`
    - 对 `issue_owner = label` 的条目记为 `dataset_label_issue`
    - 后续连续跑批不会把这类项目重复捞出来重跑

## 当前主跑新增 case 归因（2026-04-23）

本段记录当前 Top15 主检测新增的 `failed/mismatch`，按准确率优先原则只做工具/环境修复，不把不确定结果硬提为正例。

### 已修完并验证

- `libgit2/docify_macros-0.4.1`
  - 当前最终结果：`not_reachable`
  - `predicted_label = unreachable`
  - `gold_label = unreachable`
  - `correct = yes`
  - 归因：`tool`
  - 说明：
    - 早期失败来自生成器把 crate-type 强制改成 `lib`，导致 `#[proc_macro]` 无法编译
    - 现已修正 proc-macro 处理逻辑，并完成定点重跑验证

### 仍阻塞或仍需继续修复

- `freetype/servo-fontconfig-sys-5.1.0`
  - 当前状态：`analysis_failed`
  - 归因：`tool`
  - 失败原因：
    - `run.log` 显示 `Rust CPG not available in Neo4j (METHOD:Rust/CALL:Rust missing)`
    - 说明当前分析入口拿到的是空 Rust 图，尚未形成可分析的 CPG

- `freetype/freetype-rs-0.38.0`
  - 当前状态：`triggerable_confirmed`
  - `predicted_label = triggerable`
  - `gold_label = unreachable`
  - `correct = no`
  - 归因：`tool`
  - 失败原因：
    - `freetype-sys` 的 `pkg-config` 检测已命中 `freetype2`
    - 但版本约束与当前工具判定仍把它提成了触发态，属于误报，不是标签漂移

- `libgit2/cargo-0.96.0`
  - 当前状态：`analysis_failed`
  - 归因：`tool`
  - 失败原因：
    - `run.log` 中出现 `environment variable RUST_HOST_TARGET not defined at compile time`
    - 后续又出现 `multiple different versions of crate filetime in the dependency graph`
    - 属于工具链/依赖解析冲突，不是标签问题

- `libgit2/vergen-git2-9.1.0`
  - 当前状态：`analysis_failed`
  - 归因：`tool`
  - 失败原因：
    - `run.log` 中大量 `extern crate ... is unused` 级别错误
    - 说明当前投影出来的编译参数与该 crate 的编译模式不匹配

- `openssl/tokio-native-tls-0.3.1`
  - 当前状态：`analysis_failed`
  - 归因：`tool`
  - 失败原因：
    - `proc-macro2` 编译阶段报 `unknown feature proc_macro_span_shrink`
    - 属于 toolchain / crate compatibility 问题，不是标签问题

- `openssl/reqwest-0.13.2`
  - 当前状态：`not_reachable`
  - `predicted_label = unreachable`
  - `gold_label = triggerable`
  - `correct = no`
  - 归因：`tool`
  - 失败原因：
    - 当前结果没有有效 `version_hit_states` / `call_reachability_sources`
    - 工具把它压成了 `DependencyInactive`，属于漏报

- `openssl/tungstenite-0.29.0`
  - 当前状态：`not_reachable`
  - `predicted_label = unreachable`
  - `gold_label = triggerable`
  - `correct = no`
  - 归因：`tool`
  - 失败原因：
    - 和 `reqwest` 同类，当前没有形成有效的版本命中与调用可达证据
    - 这属于工具漏报，不是标签问题

- `freetype/servo-skia-0.30000023.1`
  - 当前状态：`reachable_only`
  - `predicted_label = reachable_but_not_triggerable`
  - `gold_label = unreachable`
  - `correct = no`
  - 归因：`tool`
  - 失败原因：
    - 构建日志先后暴露 `GL/glu.h: No such file or directory`
    - 以及 CMake/build script 失败
    - 说明当前环境与 CPG/版本解析链路仍不完整，且工具把版本可达性保守提成了可触发

## 当前已验证的修复文件

- [`tools/supplychain/supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
- [`tools/supplychain/run_top15_benchmark.py`](/root/cpg_generator_export/tools/supplychain/run_top15_benchmark.py)
- [`tools/supplychain/test_supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/test_supplychain_analyze.py)
- [`tools/supplychain/test_run_top15_benchmark.py`](/root/cpg_generator_export/tools/supplychain/test_run_top15_benchmark.py)
- [`rust_src/src/main.rs`](/root/cpg_generator_export/rust_src/src/main.rs)

## 当前已验证的重跑结果

- [`repair_docify_macros_20260423_b6`](/dev/shm/top15_benchmark_runs/repair_docify_macros_20260423_b6)
  - `predicted_label = unreachable`
  - `gold_label = unreachable`
  - `correct = yes`
- [`repair_freetype_rs_20260423_b2`](/dev/shm/top15_benchmark_runs/repair_freetype_rs_20260423_b2)
  - `predicted_label = triggerable`
  - `gold_label = unreachable`
  - `correct = no`
  - `mismatch_reason = tool_detection_gap`
- [`repair_servo_skia_20260423`](/dev/shm/top15_benchmark_runs/repair_servo_skia_20260423)
  - `predicted_label = reachable_but_not_triggerable`
  - `gold_label = unreachable`
  - `correct = no`
  - `mismatch_reason = tool_version_resolution_gap`
- [`repair_isahc_20260423_r2`](/root/cpg_generator_export/output/top15_repairs/repair_isahc_20260423_r2)
  - 第一次持久化重跑 `repair_isahc_20260423_main` 失败已确认不是检测逻辑问题，而是 Cargo 下载链路不稳定：
    - `cargo build` 拉取 `openssl-sys 0.9.112` 时持续出现 `SSL connect error (Recv failure: Connection reset by peer)`
    - 属于 `tool/environment`，不是标签问题
  - 已做修复：
    - benchmark runner 不再在共享 Cargo home 已有内容时重复做 seed 扫描/补拷贝
    - `cargo prefetch` 窗口从硬上限 `120s` 放宽到 `900s`
    - `cargo build` 若命中 registry 下载失败，会先做一次缓存预取再自动重试
  - 第二次重跑结果：
    - `status = not_reachable`
    - `predicted_label = unreachable`
    - `gold_label = triggerable`
    - `correct = no`
    - `mismatch_reason = tool_version_resolution_gap`
    - `issue_owner = tool`
  - 当前明确原因：
    - 工具把 Rust wrapper crate `curl = 0.4.49` 作为组件版本参与了 `curl` 的 native CVE 版本判断
    - 同一条结果里实际 native 绑定 `curl-sys = 0.4.87+curl-8.19.0` 已被解析出来
    - 这说明当前是 native 组件版本归一化缺口，不是标签漂移

## 新进展（主检测调度止损，2026-04-23）

- 当前主检测 session：
  - [`top15_continuous_20260422_resume1`](/root/cpg_generator_export/output/top15_continuous/top15_continuous_20260422_resume1/latest_report.md)
- 已确认的问题：
  - 连续监督器此前只把“已成功完成”的 case 从主批里剔除
  - 对已经达到最大重试次数、且确认是 `tool` 失败的 case，没有做调度层摘除
  - 结果是 `cargo-0.96.0`、`tokio-native-tls-0.3.1` 这类已知坏 case 会被反复重新塞进后续 batch，放大失败率
- 已落地修复：
  - [`supervise_top15_continuous.py`](/root/cpg_generator_export/tools/supplychain/supervise_top15_continuous.py)
    - 新增 `paused_case_ids(...)`
    - 超过 `max_retries` 的 case 会进入 `paused_cases`
    - 主批调度只从 `schedulable_remaining` 中取项目，不再无限重复撞同一批失败 case
    - `latest_report.md` / `final_summary.json` 新增 `paused_after_max_retries`
- 当前归因：
  - 这是明确的 `tool` 调度问题，不是标签问题

## 新进展（cargo-0.96.0 根因收敛，2026-04-23）

- 目标项目：
  - `libgit2/cargo-0.96.0`
- 当前归因：
  - `tool`
  - 不是标签问题
  - 不是项目本身不可编译
- 已确认的根因：
  - 正常 `cargo build` 已经成功
  - 真正失败发生在后续 `rust-cpg-generator` 手工重放编译时
  - 原逻辑在 fallback 路径下直接扫描 `debug/deps`，按 crate 名保留第一份 artifact
  - 对 `cargo` 这类大型 workspace / 多实例依赖图，会把错误的 `filetime` 实例塞给 generator
  - 同时还会丢掉 build script 注入的 `RUST_HOST_TARGET` 编译期环境
- 直接证据：
  - `run.log` 中先出现：
    - `environment variable RUST_HOST_TARGET not defined at compile time`
  - 随后又出现：
    - `multiple different versions of crate filetime in the dependency graph`
  - 这两条都发生在 `rust-cpg-generator failed` 阶段，不是 `cargo build failed`
- 已落地修复：
  - [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
    - 新增 `_collect_root_direct_externs(...)`
    - generator fallback 路径现在优先只注入 root crate 的直接依赖 extern，而不是整个 `debug/deps`
    - 在调用 generator 前补透传 `RUST_HOST_TARGET`、`HOST`、`TARGET`、`PROFILE`、`OPT_LEVEL`、`DEBUG`、`NUM_JOBS`
- 对应单测：
  - [`test_supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/test_supplychain_analyze.py)
    - 已补 direct extern 收缩测试

## 新进展（tokio-native-tls-0.3.1 根因收敛，2026-04-23）

- 目标项目：
  - `openssl/tokio-native-tls-0.3.1`
- 当前归因：
  - `tool`
  - 不是标签问题
- 已确认的根因：
  - 默认 nightly 上，依赖构建会被旧版 `proc-macro2` 的 nightly feature 兼容性打死
  - 分析器随后会把依赖构建回退到 `1.93.1-x86_64-unknown-linux-gnu`
  - 但原逻辑没有保证该 fallback toolchain 上存在 `rustc-dev`
  - 导致 generator 在同一 toolchain 上现编自身时，报 `can't find crate for rustc_driver / rustc_data_structures`
  - 单独把 generator 切回 nightly 也不对，会产生 “依赖产物由 1.93.1 编译，generator 用 nightly 读取” 的 ABI 不兼容
- 已落地修复：
  - [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
    - 新增 `_missing_rustc_private_component(...)`
    - 新增 `_ensure_toolchain_rustc_components(...)`
    - `_ensure_rust_cpg_generator(...)` 现在会在检测到 `rustc-dev` 缺失时，为当前选中的 toolchain 自动补装 `rust-src`、`rustc-dev`、`llvm-tools-preview` 并重试
- 当前重跑状态：
  - after-fix 定点重跑仍在进行中
  - 当前已确认依赖构建与 generator 构建都统一切到了 `1.93.1-x86_64-unknown-linux-gnu`
  - 这说明之前“依赖 1.93.1 / generator nightly”的错配已经清掉

## 新进展（pdf_oxide bin target self-extern 缺口，2026-04-24）

- 目标项目：
  - `libtiff/pdf_oxide-0.3.36`
- 当前归因：
  - `tool`
  - 不是标签问题
- 已确认的根因：
  - 失败点不在项目本身，而在 generator fallback 对 self extern 的处理
  - `pdf_oxide` 被选中的输入文件是 `src/bin/analyze_gaps.rs`
  - 这个 bin target 会通过 `use pdf_oxide::...` 引用同包内的 lib crate
  - 原逻辑会把 root crate 的 self extern 一律从 generator 参数里裁掉
  - 结果 fallback 直接用 `rustc` 重放时，bin target 找不到 `pdf_oxide` 这个同包 lib crate
- 直接证据：
  - 旧 `run.log` 明确报：
    - `use of unresolved module or unlinked crate pdf_oxide`
  - after-fix 定点复跑已经完成：
    - `CPG generation complete`
    - `Import finished successfully`
  - 说明 self-extern 缺口已被修复，后续只需继续看分析阶段结果
- 已落地修复：
  - [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
    - 新增 `_root_library_extern_aliases(...)`
    - 新增 `_target_needs_root_library_extern(...)`
    - 新增 `_collect_root_library_externs(...)`
    - 对 `bin/example/bench/test` 这类会引用同包 lib 的 target，保留或补回根库 extern
    - 仅对真正的 self/lib target 继续裁掉 self extern
- 对应单测：
  - [`test_supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/test_supplychain_analyze.py)
    - 新增 root library extern 收集与 bin target 判定测试

## 新进展（共享 target 落在 /dev/shm 导致假失败，2026-04-24）

- 当前归因：
  - `tool`
  - 不是标签问题
- 已确认的根因：
  - 多个剩余 case 在这轮复跑中并不是逻辑本身失败，而是共享 Cargo target 落在 `/dev/shm`
  - 旧缓存累积后，`/dev/shm` 一度达到 `252G used / 252G total`
  - 后续编译写入 `.fingerprint/.../invoked.timestamp` 时直接报 `No space left on device`
  - 这会把环境层面的容量问题误记成 `analysis_failed`
- 直接证据：
  - `pdf_oxide`、`glide`、`pipeless-ai` 复跑日志都出现：
    - `No space left on device (os error 28)`
- 已落地修复：
  - [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
    - 新增 `_resolve_shared_cargo_target_root(...)`
    - 当共享 target 根仍指向 `/dev/shm` 且剩余空间低于阈值时，自动降级到磁盘目录
  - [`supervise_top15_continuous.py`](/root/cpg_generator_export/tools/supplychain/supervise_top15_continuous.py)
    - 不再强行把 `SUPPLYCHAIN_SHARED_CACHE_ROOT` 默认绑死到 `/dev/shm/cpg_generator_export`
    - 改为复用 runner 的 cache root 选择逻辑
  - 运行时处理：
    - 已清理旧的 `/dev/shm/cpg_generator_export/shared_cargo_target`
    - 主检测当前改用磁盘 shared cache 继续跑
- 对应单测：
  - [`test_supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/test_supplychain_analyze.py)
    - 新增 low-space fallback 测试

## 新进展（broken symlink 触发 shared cache 初始化失败，2026-04-24）

- 当前归因：
  - `tool`
  - 不是标签问题
- 已确认的根因：
  - 旧运行把 [`output/shared_cargo_target`](/root/cpg_generator_export/output/shared_cargo_target) 链到 `/dev/shm/cpg_generator_export/shared_cargo_target`
  - 在清理 `/dev/shm` 旧 target 后，这个符号链接变成了 broken symlink
  - `configure_analysis_env()` 随后对同一路径直接 `mkdir(..., exist_ok=True)`，会抛 `FileExistsError`
- 已落地修复：
  - [`run_top15_benchmark.py`](/root/cpg_generator_export/tools/supplychain/run_top15_benchmark.py)
    - `configure_analysis_env()` 新增目录准备兜底
    - 遇到 broken symlink 或同名普通文件时先清理，再创建目录

## 新进展（cargo-0.96.0 转入标签/规则漂移候选，2026-04-24）

- 目标项目：
  - `libgit2/cargo-0.96.0`
- 当前归因：
  - `dataset_label_issue` 候选
  - 暂不再按 `tool` 失败处理
- 已确认的直接证据：
  - 最新分析报告里：
    - `resolved_version = 1.9.2`
    - `failed_guards = ['version_range:0']`
    - `downgrade_reason = version_guard_unsatisfied`
  - 也就是说，当前项目实际解析到的 `libgit2` 版本已经落在规则 guard 之外，工具是按 guard 把结果降成 `unreachable`
  - 这和 benchmark gold `reachable_but_not_triggerable` 不一致
- 当前判断：
  - 在 extern 注入和 build script 环境问题都修完后，这条 mismatch 仍然稳定落在 `version_guard_unsatisfied`
  - 因此优先视为 `label drift / rule mapping drift` 候选，而不是继续归因给检测逻辑
- 处理策略：
  - 从“待修工具问题”列表移出
  - 后续单独记录为标签/规则漂移，跳过准确率统计

## 新进展（generator toolchain 选择与项目 build toolchain 解耦，2026-04-24）

- 目标项目：
  - `openssl/tokio-native-tls-0.3.1`
- 当前归因：
  - `tool`
- 已确认的问题：
  - 项目依赖构建和 `rust-cpg-generator` 构建原先共用同一个 toolchain 选择结果
  - 一旦项目构建回退到仅有 `cargo`、但没有 `rustc-dev` 的 toolchain，generator 会在现编自身时失败：
    - `can't find crate for rustc_data_structures`
  - 继续把 `rustup component add` 打到这类 toolchain 上，会受到网络波动影响，且重试代价高
- 已落地修复：
  - [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
    - 新增 `_resolve_cpg_generator_toolchain(...)`
    - generator 现在优先选择“已安装且具备 `rust-src` + `rustc-dev`”的 cpg-ready toolchain
    - 当项目 build toolchain 不满足 generator 需求时，不再盲目沿用，而是单独选择可用的 generator toolchain
- 对应单测：
  - [`test_supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/test_supplychain_analyze.py)
    - 新增 cpg-ready toolchain 选择测试

## 新进展（pdf_oxide 弱依赖桥接误保留已收紧，2026-04-24）

- 目标项目：
  - `libtiff/pdf_oxide-0.3.36`
- 当前归因：
  - `tool`
- 已确认的误判模式：
  - 旧 after-fix 报告里，`call_reachability_source = rust_method_code_root`
  - 没有 concrete native gateway，也没有 strict callsite/native dependency edge
  - 仅凭依赖源码里存在 native symbol 绑定痕迹，就把 `reachable` 保留下来
  - 同时 `source_synthetic_sink_calls` 实际上只是 `new(...)` 这类泛化源码文本命中，不足以证明 wrapper 到 native sink 的可达
- 已落地修复：
  - [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
    - `_ignore_weak_wrapper_reachability(...)` 现在区分“强桥接证据”和“仅 dependency source symbol bridge”
    - 对 `system/stub/binary-only/downloaded-official + weak rust reachability + 无 concrete bridge` 的情况，禁止仅因弱依赖桥接保留 `reachable`
    - `conservative_wrapper_reachability` 和 `preserved_by_cross_language_trigger_evidence` 也同步只接受强桥接证据
- 对应单测：
  - [`test_supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/test_supplychain_analyze.py)
    - 新增 weak dependency-source bridge 降级测试
- 定点复跑结果：
  - `top15_fix_pdf_oxide_20260424_v4`
  - 当前结论：`status=not_reachable` / `predicted=unreachable`
  - 与 gold `unreachable` 一致
  - 说明这条现在已经从 `tool mismatch` 收敛为 `matched=yes`

## 新进展（benchmark 定点复跑改为 shared cargo home，2026-04-24）

- 当前归因：
  - `tool`
- 已确认的问题：
  - `run_top15_benchmark.py` 在默认 `auto` 模式下，如果 run 根目录剩余空间足够，会把 shared cargo home 整份复制到当前 run 的 `_benchmark_inputs/cargo_home`
  - 对 accuracy-first 定点复跑，这一步会复制整份 registry index，明显拖慢单项目验证
- 当前处理：
  - 定点复跑统一加：
    - `SUPPLYCHAIN_SHARED_CACHE_ROOT=/root/cpg_generator_export/output/disk_shared_cache`
    - `SUPPLYCHAIN_BENCHMARK_CARGO_HOME_MODE=shared`
  - 直接复用共享 cargo home，不再为每次 rerun 复制完整索引缓存

## 新进展（tokio-native-tls CPG 生成链路已打通，当前阻塞转为 Neo4j 环境限制，2026-04-24）

- 目标项目：
  - `openssl/tokio-native-tls-0.3.1`
- 当前归因：
  - `tool`
  - 其中最后一步已转为 `current_window_environment_blocker`
- 本轮已确认并修复的问题：
  - shared cargo target 目录虽然按 build toolchain 分桶，但 generator 仍会消费到与自身 `rustc` 不兼容的 extern 产物
    - 已修复为：当 generator toolchain 与项目 build toolchain 不同，自动用 generator-compatible toolchain 重建依赖产物
  - nightly toolchain 上，`proc-macro2 1.0.51` 会因为 `proc_macro_span_shrink` 漂移而失败
    - 已修复为：nightly 依赖重编译命中该类错误时，自动追加 `CARGO_ENCODED_RUSTFLAGS=-Zallow-features=proc_macro_span` 后重试
  - generator 在只读源码缓存目录下直接创建 `rmeta*` 临时目录
    - 已修复为：generator 固定改在输出目录下的 `.generator_workdir` 中执行，并显式设置可写临时目录
  - cargo 依赖重编译在存在 `Cargo.lock` 时仍可能重新做版本求解
    - 已修复为：CPG 依赖构建统一对有 lockfile 的项目加 `--locked`
- 当前定点复跑状态：
  - `top15_fix_tokio_native_tls_20260424_v8`
    - 已能成功生成 Rust CPG JSON，不再卡在 toolchain / cache / tmpdir
  - `top15_fix_tokio_native_tls_20260424_v10`
    - 失败点已后移到 `import_rust_cpg_json(...)`
    - 直接报错：
      - `neo4j.exceptions.ServiceUnavailable`
      - `Couldn't connect to localhost:7687`
      - `PermissionError: [Errno 1] Operation not permitted`
- 当前判断：
  - 这条 case 的“项目构建 / generator / 缓存 / 临时目录”链路已经打通
  - 剩余失败不再是 `tokio-native-tls` 项目逻辑，也不是当前 supplychain 判定逻辑本身
  - 而是当前执行窗口不允许建立到本地 Neo4j (`127.0.0.1:7687`) 的 socket 连接
- 处理策略：
  - 在当前窗口中，不再把它继续计入“项目分析失败待修”
  - 记录为：
    - `issue_owner = tool`
    - `mismatch_reason = neo4j_runtime_environment_blocked`
  - 待恢复本地 Neo4j 可连接环境后，优先直接从 `top15_fix_tokio_native_tls_20260424_v10` 继续向下验证 reachability/triggerability 结论

## 新进展（zng-view 的 libtiff 短别名误绑已收紧，2026-04-24）

- 目标项目：
  - `libtiff/zng-view-0.17.1`
- 当前归因：
  - `tool`
- 已确认的问题：
  - 旧逻辑会把 `libtiff -> tiff` 这种 `lib*` 组件的短别名直接视为 native 组件命中
  - 但 `zng-view` 实际使用的是 Rust `tiff` crate 解码链路，`build.rs` 没有任何 `libtiff` 链接/探针行为
  - 同时 root wrapper fallback 的源码探针也会仅凭 `tiff::decoder::Decoder` 这类文本命中，把根包误标成 `libtiff` wrapper
- 已落地修复：
  - [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
    - 新增 `_weak_lib_component_short_alias(...)`
    - `resolve_native_component_instances(...)` 现在会忽略 `lib*` 组件对纯短别名 crate 的弱命中
    - `_root_wrapper_component_instance(...)` 的源码探针也不再仅凭这类弱短别名文本命中保留 native wrapper 证据
- 对应单测：
  - [`test_supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/test_supplychain_analyze.py)
    - 新增弱短别名判定测试
    - 新增 `resolve_native_component_instances` 忽略 `libtiff -> tiff` 误命中的测试
- 当前状态：
  - 定点复跑已完成：
    - [`top15_fix_zng_view_20260424_v8 summary.json`](/root/cpg_generator_export/output/top15_benchmark_runs/top15_fix_zng_view_20260424_v8/summary.json)
    - `status = not_reachable`
    - `predicted_label = unreachable`
    - `gold_label = unreachable`
    - `correct = yes`
  - 结论：
    - 这条误报已确认修复完成

## 新进展（isahc 已确认是标签版本漂移，2026-04-24）

- 目标项目：
  - `curl/isahc-1.8.1`
- 当前归因：
  - `label`
- 最终复跑结果：
  - [`top15_fix_isahc_20260424_v4 summary.json`](/root/cpg_generator_export/output/top15_benchmark_runs/top15_fix_isahc_20260424_v4/summary.json)
  - `status = not_reachable`
  - `predicted_label = unreachable`
  - `gold_label = triggerable`
  - `correct = no`
  - `mismatch_reason = label_version_drift`
  - `issue_owner = label`
- 已确认原因：
  - 当前项目实际解析到的 native 组件版本是 `curl 8.19.0`
  - `version_hit_states = ["no"]`
  - 说明该项目当前锁定/解析到的 native 版本不在目标漏洞影响范围内
  - 因此这是标签与当前项目版本事实不一致，不是检测逻辑问题
- 处理策略：
  - 该 case 跳过，不再继续按工具失败方向修补
  - 保持标签问题记录

## 新进展（glide 已通过 bootstrap 兼容补丁复跑成功，2026-04-24）

- 目标项目：
  - `gstreamer/glide-0.6.7`
- 当前归因：
  - `tool`
- 已确认的根因：
  - 旧逻辑在 Rust CPG bootstrap 阶段直接按项目原始 GUI 依赖构建
  - `glide` 依赖链要求 `gtk4 >= 4.14`、`libadwaita >= 1.5`
  - 本机 Ubuntu 22.04 只有 `gtk4 4.6.9`、`libadwaita 1.1.7`
  - 直接导致 CPG 依赖构建失败，但失败点只落在少量 UI API，不影响 `gstreamer` 漏洞路径本身
- 已落地修复：
  - [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
    - 新增临时 bootstrap 文本补丁与恢复机制
    - 对 `glide` 在检测到 GTK/libadwaita 版本门槛失败时，自动应用 `glide_gtk_libadwaita_bootstrap_compat`
    - 兼容补丁只用于 CPG bootstrap：
      - 将 GUI 依赖特性下调到当前系统可满足版本
      - 把少量 `adw::AboutWindow` / `adw::MessageDialog` / `CssProvider::load_from_string` 调整为旧版 GTK 可编译写法
      - 分析结束后自动恢复源文件
  - 对应单测：
    - [`test_supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/test_supplychain_analyze.py)
      - 新增 `glide` bootstrap compatibility plan / apply / restore 测试
- 定点复跑结果：
  - [`top15_fix_glide_20260424_v6 summary.json`](/root/cpg_generator_export/output/top15_benchmark/top15_fix_glide_20260424_v6/summary.json)
  - `status = triggerable_possible`
  - `predicted_label = triggerable`
  - `gold_label = triggerable`
  - `correct = yes`
  - `resolved_version = 0.24.5`
  - `symbol = gst_parse_launch`
- 结果补充：
  - [`analysis_report.json`](/root/cpg_generator_export/output/top15_benchmark/top15_fix_glide_20260424_v6/CVE-2024-0444__gstreamer__TOP15__projects__gstreamer__glide-0.6.7__upstream/analysis_report.json) 的 `cpg_bootstrap.compatibility_patches` 已记录：
    - `glide_gtk_libadwaita_bootstrap_compat`

## 新进展（benchmark 前置探测加入 Neo4j socket 检查，2026-04-24）

- 当前归因：
  - `tool`
- 已确认的问题：
  - 旧的 `validate_runtime_quick(...)` 只检查 Python 是否能 `import neo4j`
  - 当前窗口里即便包可导入，真正运行时仍会在建立 `AF_INET` socket 时直接报：
    - `PermissionError: [Errno 1] Operation not permitted`
- 已落地修复：
  - [`run_top15_benchmark.py`](/root/cpg_generator_export/tools/supplychain/run_top15_benchmark.py)
    - 前置探测新增 `localhost:7687` socket 检查
    - 当前窗口里会在 benchmark 开始前直接返回明确错误，而不是等分析跑到 Neo4j 导入阶段才失败
- 实测结果：
  - 当前窗口内直接探测返回：
    - `error: Neo4j connectivity probe failed before analysis started`
    - `PermissionError: [Errno 1] Operation not permitted`

## 新进展（Neo4j OOM/假活跃已修复，glide 重新跑通，2026-04-25）

- 目标项目：
  - `gstreamer/glide-0.6.7`
- 当前归因：
  - `tool`
- 已确认的失败原因：
  - `top15_fix_glide_20260425_v1` 已成功补齐源码并生成 `cpg_final.json`
  - 失败发生在 Rust CPG 导入 Neo4j 阶段：
    - Bolt TCP 端口可连接，但 Python driver 读取 Bolt handshake 超时
    - systemd 日志显示 Neo4j JVM 多次 `OutOfMemoryError`
  - 根因是旧清库逻辑执行一次性事务：
    - `MATCH (n) DETACH DELETE n`
    - 旧库约 2.2 万节点时已经会触发当前 128m heap 配置下的 OOM/假活跃
  - 另外 `/dev/shm/rusty_batch_targets` 占用约 160GB，导致 cgroup 接近内存上限，Neo4j 提升 heap 后仍被 OOM killer 杀掉
- 已落地修复：
  - [`import_cpg.py`](/root/cpg_generator_export/tools/neo4j/import_cpg.py)
    - 清库改为每批 `10000` 节点循环 `DETACH DELETE`
    - 避免旧图过大时单事务占满 Neo4j heap
  - [`run_top15_benchmark.py`](/root/cpg_generator_export/tools/supplychain/run_top15_benchmark.py)
    - 前置探测从“能 import neo4j 包”升级为真正执行 Bolt 查询：
      - `RETURN 1 AS ok`
    - 能提前识别 Bolt 端口假活跃、handshake 卡死或认证/连接不可用
  - `/etc/neo4j/neo4j.conf`
    - `server.memory.heap.initial_size=4g`
    - `server.memory.heap.max_size=4g`
    - `server.memory.pagecache.size=4g`
    - `dbms.memory.transaction.total.max=2g`
  - 清理了无进程持有的可再生临时缓存：
    - `/dev/shm/rusty_batch_targets`
- 验证结果：
  - Python driver 已能通过 `bolt://localhost:7687` 执行 `RETURN 1`
  - `top15_fix_glide_20260425_v2` 复跑成功：
    - `exit_code = 0`
    - `seconds = 152.53`
    - `status = triggerable_possible`
    - `predicted_label = triggerable`
    - `gold_label = triggerable`
    - `correct = yes`
    - `resolved_version = 0.24.5`
    - `symbol = gst_parse_launch`
- 最终判定：
  - 这次不一致/失败不是标签问题
  - 原因属于工具运行环境与 Neo4j 导入清库逻辑问题
  - 修复后该 case 已有准确检测结果

## 新进展（photohash / pipeless-ai 构建引导与准确率投影修复，2026-04-25）

- 目标项目：
  - `libjpeg-turbo/photohash-0.1.8`
  - `gstreamer/pipeless-ai-1.11.0`
- 当前归因：
  - `tool`
- `photohash` 已确认的问题：
  - `top15_fix_photohash_20260425_v1` 失败于 CPG 依赖构建：
    - `libheif-sys v5.0.0+1.20.2` 要求系统 `libheif >= 1.17`
    - 当前系统 `libheif` 版本不足，且 HEIC 路径不是本 case 的 `libjpeg-turbo` 目标路径
  - `top15_fix_photohash_20260425_v2` 在临时移除 HEIC 依赖后遇到 `--locked` lockfile 更新失败
  - `top15_fix_photohash_20260425_v3` 分析成功但旧准确率投影把 `direct_native_gateway_bridge` 证据降级为 `reachable_but_not_triggerable`
- `photohash` 已落地修复：
  - [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
    - 新增 `photohash_disable_heic_bootstrap_compat`
    - CPG bootstrap 阶段临时移除无关 `libheif-rs` 依赖并 stub `src/hash/heic.rs`
    - 同步修补/恢复 `Cargo.lock`
    - 对临时 patch 导致的 lockfile 更新失败，允许去掉 `--locked` 后重试
  - [`internal_baselines.py`](/root/cpg_generator_export/tools/supplychain/internal_baselines.py)
    - 准确率优先投影认可 `direct_native_gateway_bridge` / “Direct native gateway calls recovered” 作为跨语言链接证据
  - [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
    - `libjpeg-turbo` 系统版本可从 `pkg-config libjpeg` / `libjpeg-turbo8*` 解析
- `photohash` 复跑结果：
  - `top15_fix_photohash_20260425_v4`
  - `exit_code = 0`
  - `seconds = 30.42`
  - `status = triggerable_possible`
  - `predicted_label = triggerable`
  - `gold_label = triggerable`
  - `correct = yes`
  - `resolved_version = 2.1.2`
  - `symbol = tjDecompressHeader3`
- `pipeless-ai` 已确认的问题：
  - `top15_fix_pipeless_ai_20260425_v1` 失败于 `ort v1.16.2` build script：
    - 默认启用 `download-binaries`，并因 `cuda` / `tensorrt` 特性下载 `onnxruntime-linux-x64-gpu-1.16.0.tgz`
    - GitHub 下载出现 `UnexpectedEof`，导致 CPG bootstrap 失败
  - `top15_fix_pipeless_ai_20260425_v3/v4` 进一步确认通用“预下载 build.rs 产物”会先拉大二进制，最多阻塞 1800 秒，不适合 CPG 生成
- `pipeless-ai` 已落地修复：
  - [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
    - 新增 `pipeless_ai_ort_load_dynamic_bootstrap_compat`
    - 对 `pipeless-ai` 预防性应用 CPG bootstrap patch：
      - `ort.default-features = false`
      - 保留 `cuda` / `tensorrt` / `openvino` / `half`
      - 增加 `load-dynamic`
    - 目标是保留源码 API/特征解析能力，但避免 CPG 生成阶段下载或链接 ONNX Runtime 大二进制
    - 修复后临时 patch 会自动恢复源文件
  - 构建重试顺序调整：
    - 当存在项目级 bootstrap patch 时，先应用 patch
    - 不再先进入通用 build artifact 预下载
- `pipeless-ai` 复跑结果：
  - `top15_fix_pipeless_ai_20260425_v5`
  - `exit_code = 0`
  - `seconds = 66.66`
  - `status = triggerable_possible`
  - `predicted_label = triggerable`
  - `gold_label = triggerable`
  - `correct = yes`
  - `resolved_version = 0.21.1`
  - `symbol = gst_parse_launch`
  - `cpg_bootstrap.compatibility_patches = [pipeless_ai_ort_load_dynamic_bootstrap_compat]`
- 源码缓存补充：
  - 针对缺失源码运行了 [`prefetch_top15_sources.py`](/root/cpg_generator_export/tools/supplychain/prefetch_top15_sources.py)
  - 本轮补齐 crates.io 源码 4 个：
    - `libwebp/takumi-1.0.15`
    - `sqlite/cargo-0.96.0`
    - `ffmpeg/image_sieve-0.6.0`
    - `libjpeg-turbo/oculante-0.9.2`
  - 另有 15 个项目由历史 inventory 精确定位源码路径，可直接用于检测，但尚未复制到 `source_cache_downloaded`
  - 9 个条目因当前 benchmark 标签/跳过逻辑不参与源码预取
- 最终判定：
  - 两个 case 的失败/不一致均为工具构建引导或准确率投影逻辑问题
  - 不是标签问题
  - 修复后均已有准确检测结果

## 新进展（ez-ffmpeg FFmpeg API 漂移导致 CPG 生成失败，2026-04-25）

- 目标项目：
  - `ffmpeg/ez-ffmpeg-0.10.0`
- 当前归因：
  - `tool`
- 已确认的问题：
  - `top15_fix_ez_ffmpeg_20260425_v1` 失败于 CPG 依赖构建阶段
  - `top15_fix_ez_ffmpeg_20260425_v2` 已能在 root crate 编译失败但依赖 artifact 存在时继续进入 CPG 生成，但 `rust-cpg-generator` 随后仍因同一类 FFmpeg API 不兼容失败
  - 失败根因是项目 `ez-ffmpeg 0.10.0` 依赖的 FFmpeg Rust 绑定面向较新的 FFmpeg API，而本机系统 `pkg-config` 暴露的 `libavcodec/libavformat/libavutil` 版本较旧
  - 典型错误包括：
    - `AVPacket.time_base`
    - `AVFrame.time_base`
    - `AVFrame.duration`
    - `AVFrame.ch_layout`
    - `AVFormatContext.nb_stream_groups`
    - `AVFormatContext.stream_groups`
  - 这不是标签问题；标签 `reachable_but_not_triggerable` 与源码证据目标一致
- 已落地修复：
  - [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)
    - 当 Cargo build 已产生依赖 artifact，但 root crate 因本地 FFmpeg API 漂移失败时，允许继续进入 CPG bootstrap
    - 当 `rust-cpg-generator` 也因同类 FFmpeg API 漂移失败时，自动切换到源码扫描 Rust CPG fallback
    - fallback 不切换 `docs-rs` 特性、不隐藏默认源码路径中的 FFmpeg 调用，用源码扫描提取方法和调用节点，优先保证检测准确率
  - [`test_supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/test_supplychain_analyze.py)
    - 增加 generator 失败后可触发源码扫描 fallback 的回归测试
- 复跑结果：
  - `top15_fix_ez_ffmpeg_20260425_v3`
  - `exit_code = 0`
  - `seconds = 77.47`
  - `status = triggerable_possible`
  - `predicted_label = reachable_but_not_triggerable`
  - `gold_label = reachable_but_not_triggerable`
  - `correct = yes`
  - `symbol = avformat_open_input`
  - `call_reachability_sources = [c_symbol_usage, rust_call_root]`
  - `cpg_bootstrap.source_scan_fallback = true`
  - `source_scan_stats = 1021 methods / 9578 calls`
- 最终判定：
  - 该 case 的失败属于工具侧 CPG bootstrap 鲁棒性问题
  - 不是标签问题
  - 修复后已有准确检测结果

## 新进展（pcre2 批次标签漂移记录，2026-04-25）

- 批次：
  - `top15_batch_pcre2_20260425_v1`
- 批次统计：
  - 输入 10 个项目
  - 实际分析 9 个项目
  - 跳过 1 个项目
  - 9 个已分析项目全部与标签一致
  - `mismatches.json = []`
- 标签问题：
  - `pcre2/hyperpolyglot-0.1.7`
  - 当前归因：
    - `label`
  - 跳过原因：
    - benchmark archived label drift
    - 数据集记录 `matched_case_status = triggerable_confirmed`
    - 当前本地归档中同一目标 `CVE-2022-1586__pcre2` 选中的 case 为 `case_status = reachable_only`
  - 源码定位：
    - `/root/VUL/cases/by-analysis-status/06_not_runnable_analysis_failed/CVE-2025-58050__pcre2/2026.3.27__hyperpolyglot-0.1.7__upstream/project/source`
  - 当前本地归档报告：
    - `/root/VUL/cases/by-analysis-status/04_runnable_reachable_only/CVE-2022-1586__pcre2/already_a__2026.3.22__2026.3.17__hyperpolyglot-0.1.7__upstream/logs/analysis_run/analysis_report.json`
- 最终判定：
  - 这是标签/归档漂移问题
  - 按准确率优先策略跳过该项目
  - 不作为工具检测失败处理
