# CLAMS 风格跨语言参数语义约束强化设计（CLAMS-lite）

## 1. 背景与目标
当前分析流程已经具备：
- 调用链可达性判定（`reachable`）
- 规则命中判定（`trigger_model` + 轻量 `param_semantics`）
- 数值路径可满足性（`path_solver`）

但在 Rust -> C/FFI 边界上，`ptr/len/flags/callback/nullability` 语义仍存在“局部判断、跨边界弱绑定”问题，容易出现：
- 可达但不可触发（误报）
- 触发结论证据链不足（解释性弱）

本设计目标是引入 **CLAMS-lite 契约层**：
1. 在边界处提取参数契约（ABI contracts）
2. 与现有路径约束统一求解（能数值化则进入 solver）
3. 对不可数值化契约保留符号判定（仅可证冲突才 `unsat`）
4. 输出 `sat/unsat/unknown` 与冲突证据，保持 `analysis_report.json` 向后兼容

---

## 2. 设计原则
1. **保守性优先**：信息不足返回 `unknown`，仅可证明冲突时返回 `unsat`
2. **兼容性优先**：不改变现有核心字段语义，仅新增可选字段
3. **分层解耦**：
   - 提取层：`abi_contracts.py`
   - 约束汇总层：`constraint_extractor.py`
   - 语义评估层：`param_semantics.py`
   - 流程接入层：`supplychain_analyze.py`
4. **可追溯性**：所有结论附带 `call_id/method/code/rule_id` 证据

---

## 3. 当前流程基线（As-Is）
### 3.1 主流程
`tools/supplychain/supplychain_analyze.py`
- 构建 `path_bundle`（路径约束、seed、sink_vars/value_env）
- 调用 `evaluate_param_semantics(...)`
- 若 `param_semantics.status == unsat`，降级 `triggerable=false_positive`

### 3.2 约束提取
`tools/verification/constraint_extractor.py`
- `build_path_constraint_bundle(...)` 当前输出：
  - `path_constraints`
  - `seed_constraints`
  - `combined_constraints`
  - `sink_calls/sink_args/sink_vars`
  - `const_map/value_env/method_signatures`

### 3.3 参数语义
`tools/verification/param_semantics.py`
- 支持 `flags/len/nonnull/enum/callback` 基础评估
- callback 当前以“是否设置/弱可达证据”为主
- 尚未引入统一 ABI 契约输入对象

---

## 4. 目标架构（To-Be）

```text
trigger_model.param_semantics.abi_contracts
                |
                v
      build_abi_contracts(...)      (NEW: abi_contracts.py)
                |
                v
build_path_constraint_bundle(...)   (extended)
  - path + seed + abi_numeric -> combined_constraints
  - abi symbolic contracts kept with evidence
                |
                v
evaluate_param_semantics(..., abi_contracts=...)
  - flags/len/null/callback/enum + abi_contract_eval
                |
                v
supplychain_analyze.py
  - write to constraint_result.param_semantics
  - unsat => false_positive + downgrade_reason
```

---

## 5. 规则 Schema 扩展（向后兼容）

在现有 `trigger_model.param_semantics` 下新增可选字段 `abi_contracts`：

```json
{
  "trigger_model": {
    "param_semantics": {
      "abi_contracts": {
        "ptr_len_pairs": [
          {
            "call": "foo",
            "ptr_arg": 1,
            "len_arg": 2,
            "len_constraints": [{"op": ">=", "value": 0}],
            "null_ptr_requires_len_zero": true
          }
        ],
        "nullability": [
          {"call": "foo", "arg_index": 1, "must_be": "nonnull"}
        ],
        "flag_domain": [
          {
            "call": "xmlReadMemory",
            "arg_index": 5,
            "allowed": ["XML_PARSE_DTDLOAD", "XML_PARSE_NOENT", "XML_PARSE_NONET"],
            "requires_all": ["XML_PARSE_DTDLOAD", "XML_PARSE_NOENT"],
            "forbids": ["XML_PARSE_NONET"]
          }
        ],
        "callback_contracts": [
          {
            "call": "c_entry_libcurl",
            "arg_index": 3,
            "must_be_set": true,
            "must_be_invocable": true
          }
        ]
      }
    }
  }
}
```

兼容策略：
- 若 `abi_contracts` 缺失，走现有逻辑，结果不变
- 若字段存在但解析失败，不抛异常，返回 `unknown + reason`

---

## 6. 新增模块：`abi_contracts.py`

### 6.1 接口
```python
build_abi_contracts(trigger_model, evidence_calls, path_bundle) -> dict
```

### 6.2 输出结构（统一契约对象）
```json
{
  "status": "sat|unsat|unknown",
  "ptr_len_pairs": [...],
  "nullability": [...],
  "flag_domain": [...],
  "callback_contracts": [...],
  "constraints": [
    {
      "variable": "host_len",
      "operator": ">",
      "value": 255,
      "source": "abi_contract",
      "evidence_ref": "rule:ptr_len_pairs[0]"
    }
  ],
  "arg_bindings": [
    {
      "call": "c_entry_libcurl",
      "call_id": 1000271,
      "arg_index": 9,
      "arg_expr": "host_len",
      "bound_var": "host_len",
      "binding_confidence": "high|medium|low"
    }
  ],
  "boundary_assumptions": [
    {
      "kind": "missing_sink_args_fallback_signature",
      "call": "c_entry_libcurl",
      "detail": "arg text absent, use method_signatures index mapping"
    }
  ],
  "evidence": [...],
  "reason": null
}
```

### 6.3 提取逻辑
1. 读取规则 `trigger_model.param_semantics.abi_contracts`
2. 结合 `path_bundle.sink_calls/sink_args/method_signatures/value_env` 建立参数绑定
3. 生成两类契约：
   - **numeric-contracts**：可转成 `{var,op,value}`（进入 solver）
   - **symbolic-contracts**：不可数值化（保留证据，交给语义层）
4. 可证明冲突（如同一变量被约束 `x<=255` 与 `x>255`）标 `unsat`
5. 否则 `sat/unknown`

---

## 7. `constraint_extractor.py` 改造

### 7.1 `build_path_constraint_bundle` 返回新增字段
- `abi_contracts`（来自 `build_abi_contracts` 的结构）
- `arg_bindings`
- `boundary_assumptions`

### 7.2 `combined_constraints` 合并策略
`combined_constraints = dedupe(path_constraints + seed_constraints + abi_numeric_constraints)`

### 7.3 冲突解释来源
- 保留 `source = abi_contract`
- `evidence_ref` 指向契约 rule id / index

---

## 8. `param_semantics.py` 改造

### 8.1 接口变更
```python
evaluate_param_semantics(..., path_bundle, solver=None, abi_contracts=None)
```
- `abi_contracts` 为空时自动回退为 `path_bundle.get("abi_contracts")`

### 8.2 `flags` 强化
- 运算支持：`=, |=, &=, ^=, x=x|EXPR, x=x&~EXPR`
- 双域跟踪：
  - token-domain（宏名）
  - numeric-domain（若 const_map 可还原）
- 结合 `flag_domain`：
  - `allowed/requires/forbids` 做一致性检查
- 判定原则：
  - 可证冲突才 `unsat`
  - 条件不明进入 `may/unknown`

### 8.3 `len` 强化
- 约束源统一：
  1) path constraints
  2) seed constraints
  3) abi ptr_len numeric constraints
  4) vuln rule len constraints
- 统一调用 solver
- 输出：
  - `constraints_used`
  - `range_estimate`
  - `conflict_reason`

### 8.4 `callback` 强化
- 两阶段：
  1) set/unset 判定（nullability）
  2) invocable 证据判定（调用证据扫描）
- 无法证明可调用时，若未可证不可调用 => `unknown`
- 新增 `reachability` 字段：`may_called|forbid_called|unknown`

### 8.5 新增统一字段
在 `param_semantics` 结果里新增：
```json
"abi_contract_eval": {
  "status": "sat|unsat|unknown",
  "constraints_used": [...],
  "conflict_reason": ...,
  "evidence": [...],
  "boundary_assumptions": [...]
}
```

并保持原字段不变：`flags_eval/len_eval/nonnull_eval/enum_eval/callback_eval`

---

## 9. `supplychain_analyze.py` 接入

### 9.1 执行顺序
1. 生成 `path_bundle`
2. 调用 `build_abi_contracts(trigger_model, evidence_calls, path_bundle)`
3. 把 `abi_contracts` 注入 `path_bundle`
4. 调用 `evaluate_param_semantics(..., abi_contracts=abi_contracts)`
5. 结果写入 `constraint_result.param_semantics`

### 9.2 触发降级规则
保持现有语义：
- `reachable == true` 且 `param_semantics.status == unsat`
  - `triggerable = false_positive`
  - `downgrade_reason += param_semantics_unsat`

---

## 10. 报告输出变更（兼容）

仅新增可选字段，不删除/重命名既有字段。

新增建议路径：
- `constraint_result.param_semantics.abi_contract_eval`
- `conditions.abi_contracts`
- `conditions.arg_bindings`
- `conditions.boundary_assumptions`

兼容保证：
- 旧读取端忽略新增字段即可
- 若新增字段缺失，语义按当前版本回退

---

## 11. 失败回退策略
1. `abi_contracts` 解析异常：
   - 不中断主流程
   - `abi_contract_eval.status=unknown`
   - `reason=abi_contract_parse_error:<msg>`
2. 参数绑定失败（如 sink 参数文本缺失）：
   - 使用 `method_signatures` 做索引回退
   - 仍失败则 `boundary_assumptions += missing_sink_args`
3. solver 不可用：
   - 使用 interval fallback
   - 仍不可判定则 `unknown`
4. 任何异常不直接输出 `unsat`（除非存在可证明冲突证据）

---

## 12. 测试矩阵

### 12.1 新增 `test_abi_contracts.py`
1. `ptr+len` sat：`ptr!=NULL && len>0`
2. `flags` unsat：`requires_all` 与 `forbids` 冲突
3. callback unknown：set 证据不足且无调用证据

### 12.2 更新 `test_param_semantics.py`
1. flags 正例 sat（含 `x=x|EXPR`）
2. flags 反例 unsat（含 `x=x&~EXPR`）
3. len 冲突 unsat（输出 `conflict_reason`）
4. callback：
   - 可调用 -> `may_called`
   - 无可调用证据 -> `unknown`

### 12.3 端到端回归
- `CVE-2024-40896`：验证 flags 域与必备位
- `CVE-2023-38545_46218`：验证 ptr/len + callback 契约

---

## 13. 性能影响与控制

潜在开销点：
1. 参数绑定与证据扫描（新增）
2. flags 双域求值（token + numeric）

控制手段：
- 仅对 `trigger_model` 声明了 `param_semantics/abi_contracts` 的 sink 执行
- 限制 callback/flags 跨过程深度（默认 2）
- 约束 dedupe 与早停冲突检测

预期影响：
- 单案例增加轻微 CPU 开销（可控）
- 不显著增加 Neo4j 交互次数（优先复用已有 `evidence_calls/path_bundle`）

---

## 14. 实施步骤（确认后执行）
1. 新增 `tools/verification/abi_contracts.py`
2. 扩展 `constraint_extractor.build_path_constraint_bundle`
3. 扩展 `param_semantics.evaluate_param_semantics` + 子评估器
4. 在 `supplychain_analyze.py` 接入 ABI 契约构建与写回
5. 更新两份规则 JSON（libxml2/libcurl）
6. 新增/更新单测并跑回归命令

---

## 15. 验证命令（确认后执行）
```bash
cd /Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export
python3 -m unittest tools.verification.test_param_semantics tools.verification.test_abi_contracts
```

历史 `vulnerabilities/` 示例目录已在仓库清理时移除；当前应改为对外部项目或 `output/vulnerability_runs/new_projects_sweep` 中保留的 run 做验证。

---

## 16. 待确认项
1. `callback_contracts.must_be_invocable` 的严格度：
   - `may_called` 即满足（推荐，保守）
   - 还是需要更强证据（可能引入更多 unknown）
2. `ptr_len_pairs.null_ptr_requires_len_zero` 是否默认启用
3. `flag_domain.allowed` 缺失时是否只校验 `requires/forbids`

> 当前建议：全部采取保守策略，优先减少误判 `unsat`。
