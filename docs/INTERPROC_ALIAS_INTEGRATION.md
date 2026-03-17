# INTERPROC + Alias 集成设计（interproc_v2）

## 1. 背景与目标

当前 `tools/verification` 已具备：
- 基于 `chain/control` 的路径约束提取；
- 参数语义判定（`flags/len/nonnull/callback`）；
- 局部跨过程 flags 追踪（`interproc_flags.py`）。

但在以下场景仍有明显盲区：
- 多层 wrapper 参数重命名后无法稳定回溯；
- `x = x | EXPR`、`x = x & ~EXPR` 在跨函数时精度不足；
- 指针/引用别名导致 `nonnull/callback` 判断偏保守；
- 证据链跨函数断裂，`unknown` 占比高。

目标：引入可工程落地的 `must/may alias + interprocedural valueflow` 统一框架，统一评估 `flags/len/nullability/callback`，在**仅可证明矛盾时输出 `unsat`**，否则保守 `unknown`，并保持 `analysis_report.json` 兼容。

## 2. 设计原则

1. 保守性：信息缺失、签名不全、别名冲突时不输出 `unsat`，仅输出 `unknown` + reason。
2. 兼容性：保留现有字段；只增量扩展（如 `interproc_context`、`interproc_eval`）。
3. 可复现性：所有结论附带 `FlowTrace`/evidence，包含 `call_id/method/code/guard/depth/provenance`。
4. 可控复杂度：深度限制（`--interproc-depth`），环检测，工作列表去重。

## 3. 模块与职责

### 3.1 新增 `tools/verification/alias_analysis.py`

接口：
- `analyze_aliases(method_calls, method_signatures, max_depth) -> AliasResult`

输出结构（建议）：
- `must_alias_sets`: Union-Find 归并后的别名组（变量槽位层面）。
- `may_alias_map`: `var -> set(var)`。
- `points_to`: `ptr -> set(base_var)`（轻量地址传播，非堆对象建模）。
- `evidence`: 每条别名边的来源语句、函数、深度。
- `unresolved`: 无法解析或冲突节点（用于上层降级到 unknown）。

支持语句：
- 赋值：`a = b`
- 取址：`p = &x`
- 解引用赋值：`*p = ...`、`*p |= ...`
- 参数传递：caller `arg_i` -> callee `param_i`

不做：
- 堆对象 field-sensitive 分析；
- 数组/结构体深层别名精确建模。

### 3.2 新增 `tools/verification/interproc_valueflow.py`

接口：
- `build_interproc_index(calls, method_signatures) -> Index`
- `propagate_from_sink(index, sink_call, arg_index, controls, value_env, max_depth) -> FlowResult`

核心数据结构：
- `ValueState`
  - `constants`: `set/int-equalities`
  - `intervals`: `var -> [lo, hi]`
  - `flags_must/may/forbid`
  - `nullability`: `nonnull/null/unknown`（可按 must/may 表示）
  - `callback_targets`: `set(symbol)`
- `FlowTrace`
  - `call_id`, `method`, `code`, `guard`, `depth`, `provenance`

统一 transfer：
- 赋值与别名更新；
- 位运算更新（含 `x = x | EXPR`、`x = x & ~EXPR` 归一化）；
- guard certainty（`true/may/false`）与分支极性传播；
- 调用边参数映射（含重命名）。

## 4. 数据流总览

```text
constraint_extractor.build_path_constraint_bundle
  -> interproc_context {method_calls, call_graph_edges, method_signatures}
  -> combined_constraints (保持)

alias_analysis.analyze_aliases(interproc_context)
  -> AliasResult

interproc_valueflow.propagate_from_sink(index, sink,arg,max_depth,...)
  -> FlowResult(ValueState + FlowTrace + unresolved)

interproc_flags / param_semantics
  -> 消费 FlowResult + AliasResult
  -> 生成 flags/len/nonnull/callback 结论 + interproc_eval

supplychain_analyze
  -> 写入 constraint_result.param_semantics.interproc_eval
  -> 若 interproc 可证 unsat => triggerable=false_positive
```

## 5. 规则求值语义（统一）

### 5.1 Flags

- 数据源：`ValueState.flags_must/may/forbid`。
- 规则：`requires_all/requires_any/forbids/allowed`。
- 判定：
  - `unsat`：存在必然冲突（required∩forbid、forbidden must-set、required 被 must-forbid 等）。
  - `sat`：所有 required 必然满足、forbid 不可能满足、且无 unresolved。
  - 否则 `unknown`。

### 5.2 Len

- 数据源：`ValueState.intervals` + `combined_constraints`。
- 支持跨函数参数重命名：sink arg -> callee param -> wrapper param 链。
- 判定：
  - 仅当区间/约束可证明冲突时 `unsat`；
  - 无法绑定 `len_var` 或约束不闭合 -> `unknown`。

### 5.3 Nonnull

- 数据源：`ValueState.nullability` + alias 合并（must/may）。
- 规则：`must_be=nonnull|null`。
- 判定：
  - 若 must-null 与 must-nonnull 冲突可证 -> `unsat`；
  - may-null/may-nonnull 混合 -> `unknown`。

### 5.4 Callback

- 数据源：`callback_targets` + 跨过程 invoke 证据。
- 支持“设置 + 调用”跨函数分离证据。
- 判定：
  - `must_be_set=true` 且可证为 null -> `unsat`；
  - `must_be_called=true` 且可证不会被调用（在已解析路径内）-> `unsat`；
  - 其余信息不足 -> `unknown`。

## 6. unknown / unsat 边界

统一策略：
- `unsat` 仅在可构造矛盾证据链时给出（带 trace/reason）。
- 以下情况强制降级 `unknown`：
  - method signature 缺失；
  - alias graph 冲突或递归截断；
  - 指针表达式超出当前轻量模型；
  - guard 无法判定确定性；
  - 深度达上限后仍存在关键未解析依赖。

## 7. 复杂度与性能控制

记：
- `N` 调用节点数，
- `E` 调用边数，
- `A` 别名边数，
- `D` 深度上限（默认 2）。

近似复杂度：
- alias 构建：`O(N + A * α(N))`（Union-Find）
- valueflow：`O((N + E) * D * K)`（`K` 为 transfer 常数，受 domain 数量影响）
- 空间：`O(N + A + trace)`

工程控制：
- 工作列表 key 去重：`(method,target,domain,depth,guard_state)`
- 环检测：递归栈截断并记录 unresolved
- trace 截断：最多保留前 `M` 条（可配置，默认 200）

## 8. 字段兼容与增量输出

### 8.1 `constraint_extractor` 返回

保留：
- `combined_constraints` 等原字段不变。

新增：
- `interproc_context`:
  - `method_calls`
  - `call_graph_edges`
  - `method_signatures`

### 8.2 `param_semantics` 返回

保留：
- `flags_eval/len_eval/nonnull_eval/enum_eval/callback_eval/abi_contract_eval`。

新增：
- `interproc_eval`:
  - `engine_version`（`interproc_v2`）
  - `status`
  - `trace`
  - `unresolved`
  - `alias_summary`（must/may/points_to 统计）

### 8.3 `interproc_flags` 返回

- `evaluate_flags_interproc` API 不变；
- `engine` 改为 `interproc_v2`；
- evidence 增加 provenance（跨过程调用路径）。

### 8.4 `analysis_report.json`

- 不删除、不改名、不重定义已有字段；
- 仅在 `constraint_result.param_semantics.interproc_eval` 增量写入。

## 9. 回退策略

1. `interproc_context` 不完整：自动降级到现有 intra/轻量 interproc。
2. alias 分析异常：记录 `interproc_eval.reason`，结果 `unknown`。
3. solver/Apron 不可用：继续 interval fallback；不影响 interproc 证据输出。
4. 若 interproc 明确 `unsat`：维持主流程 `triggerable=false_positive` 逻辑。

## 10. 计划修改文件

1. `tools/verification/interproc_valueflow.py`（新增）
2. `tools/verification/alias_analysis.py`（新增）
3. `tools/verification/interproc_flags.py`（改造到 v2 引擎）
4. `tools/verification/param_semantics.py`（len/nonnull/callback 复用 interproc+alias，并新增 `interproc_eval`）
5. `tools/verification/constraint_extractor.py`（新增 `interproc_context`）
6. `tools/supplychain/supplychain_analyze.py`（新增 `--interproc-depth`，接入写回）
7. `tools/verification/test_interproc_valueflow.py`（新增）
8. `tools/verification/test_alias_analysis.py`（新增）
9. `tools/verification/test_param_semantics.py`（更新回归）

## 11. 验证计划

单测：

```bash
cd /Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export
python3 -m unittest \
  tools.verification.test_alias_analysis \
  tools.verification.test_interproc_valueflow \
  tools.verification.test_param_semantics
```

集成：

```bash
```

历史 `vulnerabilities/` 示例目录已清理，不再使用这两条命令作为当前仓库的集成入口。

验收点：
- 旧报告字段可读；
- `interproc_eval.engine_version == interproc_v2`；
- 多层 wrapper + alias 场景下 `unknown` 降低；
- 仅可证矛盾时输出 `unsat`。
