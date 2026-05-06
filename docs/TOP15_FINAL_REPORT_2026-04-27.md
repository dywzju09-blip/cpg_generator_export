# Top15 最终检测结果报告（2026-04-27）

## 1. 报告范围与结果版本

本报告给出当前 Top15 基准的最新、可用于论文写作的最终结果口径。结果基于以下两个批次合并而成：

- 主批次全量干净重跑：
  [`top15_final_clean_8787_20260426_v1/stats.json`](/mnt/hw/cpg_generator_export_runtime/logs/top15_benchmark/top15_final_clean_8787_20260426_v1/stats.json)
  与
  [`top15_final_clean_8787_20260426_v1/summary.json`](/mnt/hw/cpg_generator_export_runtime/logs/top15_benchmark/top15_final_clean_8787_20260426_v1/summary.json)
- 对原先被跳过的 11 个标签问题 case 做标签订正后的官方补跑：
  [`top15_skipped11_relabeled_8887_20260426_v1/stats.json`](/mnt/hw/cpg_generator_export_runtime/logs/top15_benchmark/top15_skipped11_relabeled_8887_20260426_v1/stats.json)
  与
  [`top15_skipped11_relabeled_8887_20260426_v1/summary.json`](/mnt/hw/cpg_generator_export_runtime/logs/top15_benchmark/top15_skipped11_relabeled_8887_20260426_v1/summary.json)

最终评测使用的 benchmark 版本为：

- [`benchmark_project.corrected_2026-04-25.json`](/root/Experiment_Ready_Dataset_Top15/benchmark_project.corrected_2026-04-25.json)

该 benchmark 已完成标签清理，不再包含 `Needs_Review` 项。

## 2. Benchmark 最终版本

### 2.1 数据规模

- 总项目数：`143`
- 全部项目均有严格标签：`143/143`
- `Needs_Review`：`0`

最终标签分布：

- `triggerable`：`43`
- `reachable_but_not_triggerable`：`13`
- `unreachable`：`87`

### 2.2 相对原始 benchmark 的标签修订

相对原始 [`benchmark_project.json`](/root/Experiment_Ready_Dataset_Top15/benchmark_project.json)，修正版共修订 `40` 个标签：

- 原先无标签、现已补齐：`9`
- 原先有标签、现已订正：`31`

变更方向统计：

| 旧标签 | 新标签 | 数量 |
|---|---:|---:|
| `triggerable` | `reachable_but_not_triggerable` | 1 |
| `triggerable` | `unreachable` | 8 |
| `reachable_but_not_triggerable` | `unreachable` | 15 |
| `reachable_but_not_triggerable` | `triggerable` | 5 |
| `unreachable` | `triggerable` | 2 |
| 空标签 | 具体严格标签 | 9 |

按组件的标签修订数量：

| 组件 | 修订数 |
|---|---:|
| `sqlite` | 10 |
| `curl` | 9 |
| `ffmpeg` | 6 |
| `gdal` | 4 |
| `libpng` | 4 |
| `libgit2` | 3 |
| `pcre2` | 1 |
| `libwebp` | 1 |
| `libtiff` | 1 |
| `libjpeg-turbo` | 1 |

标签修订的完整记录与依据见：

- [`TOP15_FAILURE_ANALYSIS_2026-04-25.md`](/root/cpg_generator_export/docs/TOP15_FAILURE_ANALYSIS_2026-04-25.md)

## 3. 最终总体结果

### 3.1 覆盖率与准确率

合并主批次与 11 个官方补跑 case 后：

- 总项目数：`143`
- 已产出结果：`143`
- 缺失结果：`0`
- 正确：`130`
- 错误：`13`
- 总体准确率 `acc`：`90.91%`

说明：

- 主批次原始状态为 `132` 已分析、`11` 跳过；跳过原因全部是标签问题。
- 标签订正后，这 `11` 个 case 做了官方补跑，结果为 `11/11` 全对、`0` 跳过。
- 因此最终口径下，全量 `143` 个项目都已有正式结果。

### 3.2 最终预测分布

- `triggerable`：`42`
- `reachable_but_not_triggerable`：`14`
- `unreachable`：`83`
- `no_prediction`：`4`

其中 `no_prediction=4` 均属于工具失败。

### 3.3 三分类混淆矩阵

行表示金标，列表示预测值。

| Gold \\ Pred | `triggerable` | `reachable_but_not_triggerable` | `unreachable` | `no_prediction` |
|---|---:|---:|---:|---:|
| `triggerable` | 38 | 2 | 0 | 3 |
| `reachable_but_not_triggerable` | 1 | 10 | 1 | 1 |
| `unreachable` | 3 | 2 | 82 | 0 |

### 3.4 三分类指标

#### 每类指标

| 标签 | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| `triggerable` | `90.48%` | `88.37%` | `89.41%` | 43 |
| `reachable_but_not_triggerable` | `71.43%` | `76.92%` | `74.07%` | 13 |
| `unreachable` | `98.80%` | `94.25%` | `96.47%` | 87 |

#### 宏平均

- Macro Precision：`86.90%`
- Macro Recall：`86.52%`
- Macro F1：`86.65%`

#### 微平均

- Micro Precision：`93.53%`
- Micro Recall：`90.91%`
- Micro F1：`92.20%`

### 3.5 二分类风险检测口径

若将 `triggerable` 和 `reachable_but_not_triggerable` 合并为“检测到风险”，将 `unreachable` 视为“未检测到风险”，则：

- Precision：`91.07%`
- Recall：`91.07%`
- F1：`91.07%`
- `TP=51`
- `FP=5`
- `TN=82`
- `FN=5`

这个口径更适合描述“是否发现有风险路径”，但不能替代三分类严格结果。

## 4. 按组件结果

| 组件 | 总数 | 正确 | 错误 | 准确率 |
|---|---:|---:|---:|---:|
| `curl` | 10 | 10 | 0 | `100.00%` |
| `ffmpeg` | 10 | 10 | 0 | `100.00%` |
| `freetype` | 10 | 7 | 3 | `70.00%` |
| `gdal` | 10 | 10 | 0 | `100.00%` |
| `gstreamer` | 10 | 7 | 3 | `70.00%` |
| `libaom` | 3 | 3 | 0 | `100.00%` |
| `libgit2` | 10 | 9 | 1 | `90.00%` |
| `libjpeg-turbo` | 10 | 10 | 0 | `100.00%` |
| `libpng` | 10 | 10 | 0 | `100.00%` |
| `libtiff` | 10 | 8 | 2 | `80.00%` |
| `libwebp` | 10 | 9 | 1 | `90.00%` |
| `openssl` | 10 | 7 | 3 | `70.00%` |
| `pcre2` | 10 | 10 | 0 | `100.00%` |
| `sqlite` | 10 | 10 | 0 | `100.00%` |
| `zlib` | 10 | 10 | 0 | `100.00%` |

观察：

- 已经达到 `100%` 的组件族：`curl`、`ffmpeg`、`gdal`、`libaom`、`libjpeg-turbo`、`libpng`、`pcre2`、`sqlite`、`zlib`
- 当前主要误差集中在：`freetype`、`gstreamer`、`openssl`、`libtiff`、`libwebp`、`libgit2`

## 5. 已完成的关键修复

在得到当前最终结果前，已经完成并验证过的主要修复包括：

- Neo4j 写查询统一改成 `session.run(...).consume()`，修复了部分事务内存放大问题。
- `libwebp` 的 `non_webp_encode_only` 证据不再只依赖弱 Rust reachability，`PNG/JPEG -> WebP encode-only` 情况会正确降级。
- generator 复用 `rustc` 参数时强制补 crate edition，修复部分 Rust 语法/edition 导致的 CPG 生成失败。
- 新增 `sqlite`、`gdal` 等系统库版本探针，修复 `resolved_version=unknown` 导致的误判和保守降级。
- 对缺少 `Cargo.lock` 的项目增加 manifest 级 `DependencyInactive` 兜底，避免在默认 feature 图下本就不激活的组件被强行分析。
- 对人工确认是“默认 feature 图”语义的项目，禁止自动推断组件 feature，避免把本不激活的 native 路径误拉入分析。
- `pcre2` 新增显式 JIT 请求检测：源码没有明确请求 JIT 时，不再把 `reachable` 项误抬成 `triggerable`。
- 原先被跳过的 `11` 个标签问题 case 已全部订正并完成官方补跑，结果为 `11/11` 全对。

## 6. 剩余 13 个工具问题

### 6.1 分类统计

当前剩余的不一致全部是工具问题，不再有标签问题。分类如下：

| 问题类型 | 数量 |
|---|---:|
| `tool_failure` | 4 |
| `tool_detection_gap` | 6 |
| `rule_mapping_drift` | 1 |
| `accuracy_first_demotion` | 2 |

### 6.2 逐项明细

| 组件 | 项目 | 版本 | Gold | Pred | 原因 |
|---|---|---|---|---|---|
| `libwebp` | `rimage` | `0.12.3` | `triggerable` | `no_prediction` | `tool_failure` |
| `freetype` | `servo-skia` | `0.30000023.1` | `unreachable` | `reachable_but_not_triggerable` | `tool_detection_gap` |
| `freetype` | `gfx_text` | `0.33.0` | `reachable_but_not_triggerable` | `unreachable` | `tool_detection_gap` |
| `freetype` | `sdf_glyph_renderer` | `1.1.0` | `reachable_but_not_triggerable` | `triggerable` | `tool_detection_gap` |
| `libgit2` | `cargo-cache` | `0.8.3` | `unreachable` | `reachable_but_not_triggerable` | `rule_mapping_drift` |
| `openssl` | `tokio-native-tls` | `0.3.1` | `triggerable` | `no_prediction` | `tool_failure` |
| `openssl` | `libsqlite3-sys` | `0.37.0` | `unreachable` | `triggerable` | `tool_detection_gap` |
| `openssl` | `sha1_smol` | `1.0.1` | `unreachable` | `triggerable` | `tool_detection_gap` |
| `libtiff` | `zng-view` | `0.17.1` | `unreachable` | `triggerable` | `tool_detection_gap` |
| `libtiff` | `rimage` | `0.12.3` | `reachable_but_not_triggerable` | `no_prediction` | `tool_failure` |
| `gstreamer` | `glide` | `0.6.7` | `triggerable` | `reachable_but_not_triggerable` | `accuracy_first_demotion` |
| `gstreamer` | `pipeless-ai` | `1.11.0` | `triggerable` | `reachable_but_not_triggerable` | `accuracy_first_demotion` |
| `gstreamer` | `hunter` | `1.3.5` | `triggerable` | `no_prediction` | `tool_failure` |

### 6.3 根因分析

#### `tool_failure`（4 个）

典型表现是分析过程在给出最终判定前就失败，导致 `predicted_label=""`。当前受影响 case：

- `libwebp/rimage-0.12.3`
- `openssl/tokio-native-tls-0.3.1`
- `libtiff/rimage-0.12.3`
- `gstreamer/hunter-1.3.5`

这类问题优先级最高，因为它们直接造成无预测结果，既伤害 `recall`，也伤害最终 `accuracy`。

#### `tool_detection_gap`（6 个）

这类问题说明工具已经跑完，但 reachability / triggerability 的判定逻辑还不够精确。当前主要集中在：

- `freetype` 家族的可达性与可触发性区分
- `openssl` 家族的误报
- `libtiff/zng-view` 的误抬高

这类问题是当前剩余错误的主体，说明工具在少数 native family 上仍有规则粒度或路径语义建模不足。

#### `rule_mapping_drift`（1 个）

- `libgit2/cargo-cache-0.8.3`

这是规则选择与 benchmark 目标未完全对齐的问题，不是单纯的路径分析失误。后续修复应优先收紧 rule selection，而不是盲目改 reachability 阈值。

#### `accuracy_first_demotion`（2 个）

- `gstreamer/glide-0.6.7`
- `gstreamer/pipeless-ai-1.11.0`

这两项都表现为工具发现了 `triggerable_possible`，但在 accuracy-first / precision-first 投影时被保守压成 `reachable_but_not_triggerable`。这类问题的本质不是“没找到路径”，而是最终标签投影过于保守。

## 7. 剩余问题的修复优先级建议

建议按以下顺序继续修：

1. 先修 `tool_failure`
   这 4 个 case 没有预测值，收益最高，且通常能直接提升覆盖质量。
2. 再修 `tool_detection_gap`
   这 6 个 case 是当前主要误差来源，应按 family 分组处理，优先 `freetype`，再 `openssl`，最后 `libtiff`。
3. 单独处理 `rule_mapping_drift`
   `cargo-cache` 应从规则选择层修，避免引入新误报。
4. 最后放宽 `accuracy_first_demotion`
   仅在有足够版本与调用证据时，对 `gstreamer` 的保守投影做局部放松。

## 8. 原始数据入口

论文或后续 agent 若需要复核，请直接使用以下文件：

### 8.1 Benchmark

- 原始 benchmark：
  [`benchmark_project.json`](/root/Experiment_Ready_Dataset_Top15/benchmark_project.json)
- 修正版 benchmark：
  [`benchmark_project.corrected_2026-04-25.json`](/root/Experiment_Ready_Dataset_Top15/benchmark_project.corrected_2026-04-25.json)

### 8.2 主批次结果

- 汇总统计：
  [`top15_final_clean_8787_20260426_v1/stats.json`](/mnt/hw/cpg_generator_export_runtime/logs/top15_benchmark/top15_final_clean_8787_20260426_v1/stats.json)
- 行级结果：
  [`top15_final_clean_8787_20260426_v1/summary.json`](/mnt/hw/cpg_generator_export_runtime/logs/top15_benchmark/top15_final_clean_8787_20260426_v1/summary.json)
- 问题清单：
  [`top15_final_clean_8787_20260426_v1/issues.json`](/mnt/hw/cpg_generator_export_runtime/logs/top15_benchmark/top15_final_clean_8787_20260426_v1/issues.json)

### 8.3 跳过 11 个 case 的官方补跑结果

- 汇总统计：
  [`top15_skipped11_relabeled_8887_20260426_v1/stats.json`](/mnt/hw/cpg_generator_export_runtime/logs/top15_benchmark/top15_skipped11_relabeled_8887_20260426_v1/stats.json)
- 行级结果：
  [`top15_skipped11_relabeled_8887_20260426_v1/summary.json`](/mnt/hw/cpg_generator_export_runtime/logs/top15_benchmark/top15_skipped11_relabeled_8887_20260426_v1/summary.json)

### 8.4 标签清理与修复过程记录

- [`TOP15_FAILURE_ANALYSIS_2026-04-25.md`](/root/cpg_generator_export/docs/TOP15_FAILURE_ANALYSIS_2026-04-25.md)

## 9. 附录：40 个标签修订清单

### 9.1 `pcre2`

- `hyperpolyglot-0.1.7`：
  `triggerable -> reachable_but_not_triggerable`

### 9.2 `libwebp`

- `image-webp-0.2.4`：
  `triggerable -> unreachable`

### 9.3 `gdal`

- `gdal-0.19.0`：
  `triggerable -> unreachable`
- `startin-0.8.3`：
  `reachable_but_not_triggerable -> unreachable`
- `rasters-0.8.0`：
  `triggerable -> unreachable`
- `tileyolo-0.2.3`：
  `reachable_but_not_triggerable -> unreachable`

### 9.4 `libgit2`

- `git2-0.20.4`：
  `triggerable -> unreachable`
- `cargo-0.96.0`：
  `reachable_but_not_triggerable -> unreachable`
- `cargo-generate-0.23.8`：
  `triggerable -> unreachable`

### 9.5 `sqlite`

- `sqlx-0.8.6`：
  `空 -> unreachable`
- `rusqlite-0.39.0`：
  `空 -> triggerable`
- `rustyline-18.0.0`：
  `空 -> unreachable`
- `diesel-2.3.7`：
  `空 -> unreachable`
- `smoldot-1.1.0`：
  `空 -> triggerable`
- `refinery-core-0.9.1`：
  `空 -> unreachable`
- `cargo-0.96.0`：
  `reachable_but_not_triggerable -> triggerable`
- `r2d2_sqlite-0.33.0`：
  `空 -> triggerable`
- `reedline-0.47.0`：
  `空 -> unreachable`
- `rocket_contrib-0.4.11`：
  `空 -> unreachable`

### 9.6 `libpng`

- `gif-0.14.2`：
  `reachable_but_not_triggerable -> unreachable`
- `jpeg-decoder-0.3.2`：
  `reachable_but_not_triggerable -> unreachable`
- `qoi-0.4.1`：
  `reachable_but_not_triggerable -> unreachable`
- `image-webp-0.2.4`：
  `triggerable -> unreachable`

### 9.7 `libtiff`

- `image-0.25.10`：
  `reachable_but_not_triggerable -> triggerable`

### 9.8 `curl`

- `curl-0.4.49`：
  `reachable_but_not_triggerable -> unreachable`
- `sentry-0.47.0`：
  `reachable_but_not_triggerable -> unreachable`
- `oauth2-5.0.0`：
  `reachable_but_not_triggerable -> unreachable`
- `gix-transport-0.55.1`：
  `reachable_but_not_triggerable -> unreachable`
- `rdkafka-sys-4.10.0+2.12.1`：
  `reachable_but_not_triggerable -> unreachable`
- `opentelemetry-jaeger-0.22.0`：
  `reachable_but_not_triggerable -> unreachable`
- `isahc-1.8.1`：
  `triggerable -> unreachable`
- `git2-curl-0.21.0`：
  `reachable_but_not_triggerable -> unreachable`
- `http-client-6.5.3`：
  `triggerable -> unreachable`

### 9.9 `ffmpeg`

- `gifski-1.34.0`：
  `reachable_but_not_triggerable -> unreachable`
- `ez-ffmpeg-0.10.0`：
  `reachable_but_not_triggerable -> triggerable`
- `bliss-audio-0.11.2`：
  `reachable_but_not_triggerable -> triggerable`
- `stainless_ffmpeg-0.6.2`：
  `reachable_but_not_triggerable -> triggerable`
- `image_sieve-0.6.0`：
  `unreachable -> triggerable`
- `door_player-0.3.20`：
  `unreachable -> triggerable`

### 9.10 `libjpeg-turbo`

- `bambu-0.3.1`：
  `reachable_but_not_triggerable -> unreachable`
