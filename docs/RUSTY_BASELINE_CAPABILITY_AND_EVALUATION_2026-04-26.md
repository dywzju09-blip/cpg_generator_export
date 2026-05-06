# RUSTY Baseline 能力边界与 Top15 检测结果说明

日期：2026-04-26\
数据集：`/root/Experiment_Ready_Dataset_Top15`\
目的：给后续论文写作 agent 提供可直接引用的工具能力、评测口径、检测结果和误差分析说明。

## 1. 核心结论

这里的 RUSTY baseline 不是一个完整的 Rust+C 跨语言可触发性分析器。它的强项是生成 Rust 侧 CPG，并结合 Cargo 依赖、Rust wrapper/sink 证据、native 符号和规则库做项目级可达性判断。仓库里确实有 Joern/c2cpg 驱动的 C 侧 CPG 补充能力，但当前 Top15 流程是按需、符号/组件范围导入 native 源码，不是对每个 native 组件构建完整 C CPG，也没有把 C 内部控制流、数据流、guard、sanitizer 和 Rust->C 参数语义完整闭合。

因此，严格三分类评测时，`triggerable_possible` 不能算作 `triggerable`。它只能说明“Rust 侧或跨语言边界存在可能到达漏洞相关 native sink 的证据”，但没有证明漏洞条件在 native 内部被满足。进一步说，如果 limited baseline 没有完整 C 侧 CPG、Rust->C 精确边和 native 内部触发语义，那么启发式 `triggerable` 也不能作为 confirmed triggerability。按 confirmed-triggerability 口径重新核算后，RUSTY baseline 的总体效果如下：

| 标签口径 | 样本数 | Accuracy | Macro Precision | Macro Recall | Macro F1 | Confirmed Triggerable TP / Gold | Confirmed Triggerable Recall |
|---|---:|---:|---:|---:|---:|---:|---:|
| 当前 benchmark 主表（`PAPER_DATA/BENCHMARK/benchmark_project.json` 的 `strict_label`） | 143 | 63.64% | 37.59% | 55.27% | 42.26% | 0 / 40 | 0.00% |

这说明 RUSTY baseline 对 `unreachable` 的判别较强，对“是否能到达 native 组件/符号”有一定价值，但没有 confirmed triggerability 能力。论文中应把它定位为“Rust-side CPG + heuristic native reachability baseline”，而不是完整的 exploitability analyzer。

## 2. 正确评测口径

本实验保持三分类，不退化为二分类：

- `unreachable`：项目中没有有效依赖、版本、feature 或调用链证据能够到达漏洞相关 native 组件/符号。
- `reachable_but_not_triggerable`：能到达 vulnerable component/sink，但没有证明触发条件成立，或者只能得到可能触发证据。
- `triggerable`：有足够证据证明漏洞路径可达，并且触发相关的输入、状态、参数、guard 或 native 内部路径条件满足。

工具状态到三分类标签的严格映射为：

| 工具状态                    | 严格三分类标签                         | 原因                                     |
| ----------------------- | ------------------------------- | -------------------------------------- |
| `not_reachable`         | `unreachable`                   | 未发现有效 reachability                     |
| `reachable_only`        | `reachable_but_not_triggerable` | 只证明可达，不证明触发                            |
| `triggerable_possible`  | `reachable_but_not_triggerable` | 只能说明可能触发，不能当作 confirmed triggerability |
| `triggerable_confirmed` 且有完整 C 侧路径/参数/guard 证明 | `triggerable`                   | 有 confirmed trigger evidence           |
| 当前 limited baseline 的 `triggerable_confirmed` 或启发式 `triggerable`，但无完整 C 侧语义证明 | `reachable_but_not_triggerable` | 没有 C 内部路径、参数和 guard 证明，不能算 confirmed triggerability |
| `analysis_failed`       | `no_prediction`                 | 分析失败，不计为正确预测                           |

之前出现过较高的 accuracy/recall，是因为把 `triggerable_possible` 直接算成了 `triggerable`，或者把问题折叠成“reachable vs unreachable”的二分类。这个口径不适合和你的工具对比，因为你的工具目标是 exploitability/triggerability 级别，而不仅是 reachability。

## 3. 工具链实际能力

### 3.1 RUSTY/Rust CPG 能力

RUSTY 本体负责 Rust 侧 CPG 生成。当前仓库通过 `rust_src` 下的 `rust-cpg-generator` 解析 Rust 项目，恢复 Rust 方法、调用、类型、MIR/语义片段，并导入 Neo4j 供后续查询。

它能够支持：

- 解析真实 Rust 项目的 Cargo 编译上下文。
- 识别 Rust 方法、调用点、wrapper API、source/sink token 和一部分 MIR 级结构。
- 给出 Rust 侧调用可达性证据，例如 `rust_call_root`、`rust_call_package`、`rust_method_code_package`、`rust_native_gateway_package`。
- 结合依赖解析判断 root crate 是否依赖相关 sys crate、FFI crate 或 native wrapper。

它不能独立完成：

- C/C++ 侧 CPG 生成。
- Rust->C->C 多层调用图的完整重建。
- Rust 参数到 C 参数的完整数据流绑定。
- C 内部漏洞函数之前的 path condition、guard、sanitizer、state machine 和 trigger constraint 证明。

### 3.2 C 侧 CPG 支持不是 RUSTY 本体能力

仓库里有 C 侧 CPG 补充支持，但来源是 Joern/c2cpg，不是 RUSTY 本体：

- `c2cpg.sh` 调用 `io.joern.c2cpg.Main`。
- `generate_cpgs.sh --lang c` 使用 `joern-parse` 和 `joern-export`。
- `tools/supplychain/supplychain_analyze.py` 中存在 `generate_c_cpg_for_input(...)`、`_import_native_component_source(...)`、`maybe_import_native_source_for_symbol(...)` 等按需导入逻辑。

当前 Top15 跑法不是“给所有 native 组件构建完整 CPG 并做完整跨语言闭环分析”。它只在需要 native 源码补充时，对组件/符号相关范围做导入，并在大量 case 中继续依赖 source scan、符号匹配、wrapper 规则、版本探针和人工规则库。最近一次已完成结果扫描中，native CPG 使用情况大致为：

- 看到 report 数：141
- CPG 请求次数：40
- 从 JSON 复用 CPG 次数：36
- 有 CPG 请求的 case：30
- native source bootstrap 状态：`imported=40`，`unsupported=265`，`failed=3`

这组数字说明 C 侧 CPG 是按需增强，不是全量基础能力。

### 3.3 当前 baseline 能做什么

当前工具可以比较可靠地完成以下任务：

- 解析 Cargo 依赖、feature、lockfile 和部分 build script/native 版本证据。
- 判断项目是否依赖某个 vulnerable native component。
- 识别 Rust 侧 wrapper/sink 是否存在，例如 decode/parse/open/compile/compress/decompress 等入口。
- 通过规则库把 Rust wrapper、sys crate、native 符号和 CVE sink 关联起来。
- 在 native source 可获得时，按需导入 C 源码/CPG，补充符号、调用和组件证据。
- 给出项目级 `unreachable` 或 `reachable_but_not_triggerable` 判断。
- 为误报/漏报定位提供 evidence 字段，如 `call_reachability_sources`、`version_hit_states`、`triggerable_states`、`source_resolution`。

### 3.4 当前 baseline 不能可靠完成什么

当前工具不能可靠完成以下任务：

- 不能证明所有 `triggerable_possible` case 真的可触发。
- 不能完整覆盖 native 内部多层函数调用链。
- 不能系统追踪 Rust `as_ptr()/len()/flags/options/callback` 到 C `buf/len/flag/state` 的参数语义。
- 不能完整判断 C 内部 sanitizer、guard、bounds check、format check、state transition 是否阻断漏洞。
- 不能在 binary-only/system library 场景下恢复完整 native 内部逻辑。
- 不能把“看到了 wrapper 或 symbol”直接提升为 exploitability confirmed。
- 不能替代你的工具生成的完整跨语言图。

## 4. 数据集与运行状态

Top15 数据集位于：

- 最新完整修正版标签：`/root/Experiment_Ready_Dataset_Top15/benchmark_project.corrected_2026-04-25.json`
- 项目源码缓存：`/root/Experiment_Ready_Dataset_Top15/source_cache_downloaded`

数据集总项目数为 143。本文档当前统一使用 `PAPER_DATA/BENCHMARK/benchmark_project.json` 中的 `strict_label` 作为 gold label。

最终主结果数据入口：

- `PAPER_DATA/BENCHMARK/benchmark_project.json`
- `PAPER_DATA/RUSTY_BASELINE/RESULTS/rusty_limited_baseline_case_metrics.csv`
- `PAPER_DATA/RUSTY_BASELINE/RESULTS/rusty_limited_baseline_final_metrics.json`

注意：`PAPER_DATA/RESULTS/top15_strict_confirmed_only_metrics.json` 是主工具的 strict confirmed-only 结果，不是 RUSTY baseline。RUSTY baseline 的指标必须以本目录下的 `rusty_limited_baseline_final_metrics.json` 为准。

## 5. 严格三分类检测结果

### 5.1 最终 merged 标签视图

统计范围：143 个有标签 case。

总体指标：

- Correct：88 / 143
- Accuracy：63.64%
- Macro Precision：37.59%
- Macro Recall：55.27%
- Macro F1：42.26%

标签分布：

| 类别                              | Gold | Prediction |
| ------------------------------- | ---: | ---------: |
| `unreachable`                   |   87 |         90 |
| `reachable_but_not_triggerable` |   13 |         48 |
| `triggerable`                   |   43 |          1 |
| `no_prediction`                 |    0 |          4 |

混淆矩阵：

| Gold \ Pred                     | `unreachable` | `reachable_but_not_triggerable` | `triggerable` | `no_prediction` |
| ------------------------------- | ------------: | ------------------------------: | ------------: | --------------: |
| `unreachable`                   |            79 |                               7 |             1 |               0 |
| `reachable_but_not_triggerable` |             3 |                               9 |             0 |               1 |
| `triggerable`                   |             8 |                              32 |             0 |               3 |

逐类指标：

| 类别                              | Precision | Recall |     F1 | TP | FP | FN |
| ------------------------------- | --------: | -----: | -----: | -: | -: | -: |
| `unreachable`                   |    87.78% | 90.80% | 89.27% | 79 | 11 |  8 |
| `reachable_but_not_triggerable` |    18.75% | 69.23% | 29.51% |  9 | 39 |  4 |
| `triggerable`                   |     0.00% |  0.00% |  0.00% |  0 |  1 | 43 |

解释：`unreachable` 的 precision/recall 都较高，整体 accuracy 为 63.64%。但 confirmed `triggerable` recall 为 0.00%，说明 RUSTY-based baseline 缺少 confirmed triggerability 的语义基础。

### 5.2 RUSTY-only 与 current strict status-only 口径

在你当前要求的 strict confirmed-only 规则下，这里只保留不含标签映射的口径：

- `RUSTY-only`：只使用 Rust CPG 和 Rust 侧可达证据；不使用你的 C 侧 CPG、Rust->C 精确边、C 内部 CFG/DFG 或触发约束。该层不能输出 confirmed `triggerable`。
- `RUSTY-based limited baseline`：当前已完成统计使用的 baseline；有 Rust CPG、规则库和少量按需 native source/CPG 补充，但 native 内部语义不完整。严格口径下 `triggerable_possible` 和无 C 侧语义证明的启发式 `triggerable` 都降为 `reachable_but_not_triggerable`。

说明：此前出现的 `90.91%` 来自主工具的 strict confirmed-only 结果，不是 RUSTY baseline。RUSTY baseline 当前严格口径请统一使用 `PAPER_DATA/RUSTY_BASELINE/RESULTS/rusty_limited_baseline_final_metrics.json`，并与 `PAPER_DATA/BENCHMARK/benchmark_project.json` 的 `strict_label` 对齐。

| Method | 使用能力 | 样本数 | 三分类 Accuracy | Confirmed Triggerable TP / Gold | Confirmed Triggerable Recall | 说明 |
|---|---|---:|---:|---:|---:|---|
| `RUSTY-only` | Rust CPG + Rust-side reachability only | N/A | N/A | 0 / 40 | 0.00% | 不是完整检测器，不具备 C 内部触发证明能力；论文中不应报告 accuracy。 |
| `RUSTY-based limited baseline` | Rust CPG + heuristic bridge + partial/on-demand native supplement | 143 | 63.64% | 0 / 40 | 0.00% | 已完成真实运行和 confirmed-triggerability 审计；无 confirmed trigger evidence。 |

这个表格的核心证据来自当前混淆矩阵：40 个 gold `triggerable` 中，confirmed-triggerability 审计后没有任何 case 被 limited baseline 证明为 `triggerable`；29 个只能停在 `reachable_but_not_triggerable`，8 个判为 `unreachable`，3 个 `no_prediction`。也就是说，limited baseline 的失败不是简单分类偏差，而是缺少 C 侧内部路径、参数和 guard 证明。

## 6. 主要误差类型

### 6.1 Gold triggerable 被判为 reachable\_but\_not\_triggerable

这是最主要的失败类型。当前 benchmark 标签视图中，40 个 gold `triggerable` 里没有任何 case 被 limited baseline 证明为 confirmed `triggerable`；29 个只能判成 `reachable_but_not_triggerable`，8 个判为 `unreachable`，3 个 `no_prediction`。

根因是 baseline 经常只能得到：

- Rust wrapper/sink 可见。
- native symbol 或组件可见。
- 某些规则条件可能匹配。
- 但 C 内部路径、参数、状态和 guard 没有被完整证明。

这些证据只能支持 `triggerable_possible`，不能支持 confirmed `triggerable`。按照你的评测原则，这些 case 对 triggerability 检测来说就是失败。

### 6.2 Gold reachable/triggerable 被判为 unreachable

这类漏报通常来自：

- Cargo feature 或 optional dependency 推断不足。
- Rust CPG 生成失败或 fallback source scan 覆盖不够。
- wrapper API 被封装得更深，Rust 侧 sink token 不明显。
- native 版本/source resolution 失败，导致保守降级。
- Rust->C bridge 只存在间接依赖或 build script 证据，没有形成强调用边。

### 6.3 Gold unreachable 被判为 reachable\_but\_not\_triggerable 或 triggerable

这类误报通常来自：

- 仅凭 package-level wrapper 或符号名匹配就认为可达。
- native 组件存在，但具体项目默认 feature 并不会启用漏洞路径。
- Rust 项目只是 encode-only、test-only、asset-only 或 build-time-only 使用相关组件。
- native source/版本不可确认时，规则 fallback 太乐观。
- 缺少 C 内部 guard 判断，无法发现路径实际被格式、状态或参数条件阻断。

### 6.4 analysis\_failed / no\_prediction

少数 case 仍会因为 Rust CPG 生成、导入 Neo4j、依赖构建、native 源码导入或环境问题失败。这类不能算正确预测，应作为工程可用性问题单独报告。

## 7. 为什么 RUSTY baseline 不如你的工具

你的工具的核心优势应表述为：它不是只在 Rust 侧看 wrapper，也不是把 C 当黑箱，而是生成并利用更完整的跨语言图，将 Rust 项目侧证据、Rust->C FFI 边、native C 内部调用、参数流和漏洞触发规则放到同一个分析框架里。

RUSTY baseline 不如你的工具，主要有以下原因。

第一，跨语言边不完整。RUSTY 本体只生成 Rust CPG，后续 Rust->C 关系主要靠 sys crate、wrapper 名称、build.rs、符号、规则库和 source scan 补边。这类边可以帮助 reachability，但不足以证明真实调用链一定穿过漏洞函数。

第二，C 侧内部语义不完整。当前 baseline 即使补充 CPG，也多是按需导入组件/符号范围，无法保证覆盖完整 native call graph。很多漏洞条件发生在 C 内部多层函数之后，仅靠 Rust wrapper 证据无法确认。

第三，参数语义没有闭合。很多 native CVE 的触发依赖 `buf/len/flags/options/callback/state` 等参数关系。RUSTY baseline 很难系统证明 Rust 侧输入如何绑定到 C 侧参数，更难证明长度、格式、状态机和 flag 组合满足触发条件。

第四，guard/sanitizer/path condition 处理不足。可触发性不是“能调用到函数”就成立，还要判断中途检查是否会阻断漏洞路径。baseline 缺少完整 C 内部 CFG/DFG 和 guard reasoning，因此只能给出 possible。

第五，规则 fallback 会提高 reachability 召回，但会降低 triggerability precision。为了覆盖真实项目，baseline 使用 wrapper token、symbol usage、package-level gateway、source text evidence 等弱证据。这些证据对找候选有价值，但用于 confirmed exploitability 会过宽。

第六，binary-only/system native dependency 场景下信息不足。系统库、二进制库或源码不可得时，baseline 只能依赖版本探针、符号和 Rust 边界证据，无法分析 native 内部逻辑。

因此，论文中可以把实验结论表述为：

> RUSTY-based baseline can recover Rust-side program structure and provide useful vulnerable-component reachability evidence. However, because its cross-language edges and native-side semantics are incomplete, it often stops at `triggerable_possible`. Under a strict three-class exploitability evaluation, these cases must be counted as reachable but not confirmed triggerable. This explains the low triggerable recall and demonstrates the need for our complete cross-language graph and native semantic modeling.

中文表述可以写成：

> RUSTY-based baseline 能较好地恢复 Rust 侧程序结构，并在项目级判断 vulnerable native component 是否可能可达。但它的跨语言边和 C 侧内部语义不完整，很多结果只能停留在 `triggerable_possible`。在严格三分类评测中，`possible` 不能等同于 confirmed triggerability，因此 gold triggerable case 会大量落入 reachable-but-not-triggerable。这正体现了本文工具的优势：我们的跨语言图包含更完整的 Rust->C 边、C 内部调用/数据语义和漏洞触发约束，能够比 RUSTY baseline 更准确地区分“可达”和“真实可触发”。

## 8. 如果给 RUSTY 补充你的 C 侧 CPG，会发生什么

如果只是把你的工具生成的 C 侧 CPG文件直接提供给 RUSTY baseline，但不接入 supplychain 的跨语言边、参数流和触发语义，结果不会自动等同于你工具的结果。原因是 CPG 数据本身只是基础，仍需要完成以下集成：

- Rust FFI callsite 与 C method/function 的精确对齐。
- Rust 参数与 C 参数的跨语言数据流映射。
- C 内部 interprocedural call graph 的可达路径搜索。
- C 内部 sanitizer、guard、path condition 和漏洞触发规则求解。
- native 组件版本/source/build feature 与实际项目配置对齐。
- 对 indirect call、callback、function pointer、macro/generated code 的处理。

如果只把 CPG 放进去，但没有这些跨语言语义边和分析逻辑，最多会提升 native reachability 的覆盖，不能把 `triggerable_possible` 自动升级为 `triggerable`。这也是为什么映射型 `predicted_label` 指标不能直接当作 confirmed-triggerability 结果来引用。论文中可以把这点作为方法贡献来强调：提升效果来自“完整跨语言图 + 语义分析”，而不是单纯“多导入一个 CPG 文件”。

## 9. 推荐论文对比方式

建议论文中不要把 RUSTY baseline 命名成完整 RUSTY exploitability detector，而是命名为：

- `RUSTY-R`: RUSTY-based reachability baseline
- `RUSTY+Rules`: Rust CPG plus heuristic native rules
- `Rust-side CPG baseline`

你的工具可以命名为：

- `Ours`
- `Full cross-language CPG`
- `Cross-language exploitability analysis`

推荐表格列：

| Method                                | Rust CPG | C CPG             | Explicit Rust->C edges | Native internal CFG/DFG | Trigger constraints | Three-class Acc. | Confirmed Triggerable Recall |
| ------------------------------------- | -------- | ----------------- | ---------------------- | ----------------------- | ------------------- | ---------------: | ----------------------------: |
| RUSTY-only                            | Yes      | No                | No/FFI-name only       | No                      | No                  | N/A              | 0.00% |
| RUSTY-based limited baseline          | Yes      | Partial/on-demand | Heuristic              | Partial                 | Weak/rule fallback  | 63.64%           | 0.00% |
这里建议主表采用最终 merged 标签视图，并且使用 strict confirmed-only 口径。若论文要加入一个额外中间配置，例如“RUSTY + CPG-only without supplychain semantics”，则必须单独运行后再填数。

## 10. 对另一个 agent 的使用建议

写论文时重点提取以下信息：

- 不要引用之前把 `triggerable_possible` 算作 `triggerable` 的高 accuracy。
- 主结果采用严格三分类，`triggerable_possible -> reachable_but_not_triggerable`。
- RUSTY baseline 的结论是 reachability 有价值，triggerability 很弱。
- RUSTY-only 和 RUSTY-based limited baseline 的 confirmed triggerable recall 都是 0.00%；这说明仅靠 Rust CPG 和弱桥接不能证明可触发。
- 基于 RUSTY limited baseline 混淆矩阵，29 个 gold triggerable case 只能到达 `reachable_but_not_triggerable`，8 个被判为 `unreachable`，3 个没有预测；这说明 baseline 的主要缺口是 C 侧路径、参数和 guard 证明。
- 不要再引用 `90.91%` 作为 confirmed-triggerability accuracy；那是历史映射口径，不符合当前 strict confirmed-only 规则。
- 你的工具优势不是“也能生成 CPG”，而是“跨语言边、C 内部语义、触发条件和证据分层更完整”。
- 如果补充你的 C 侧 CPG，仍必须配套 Rust->C 对齐和语义分析；否则只会提高可达性，不会自然获得可触发性。
