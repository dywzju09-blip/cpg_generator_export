# 跨语言触发语义图（TTSG）与约束可满足证明：技术方案文档

> 目标：以“跨语言触发语义图（TTSG）+ 约束可满足证明”作为论文核心创新，支持 n‑day 供应链漏洞的可达与可触发检测（非 0day）。

---

## 1. 核心创新点概述

### 1.1 跨语言触发语义图（TTSG, Translingual Trigger Semantics Graph）

**定义**：
在传统 CPG 的基础上，把“触发条件、参数语义、FFI 边界、证据链”作为一等图元素，形成跨语言的触发语义图。

**与传统 CPG 的区别**：
- 传统 CPG：函数/语句/调用为主
- TTSG：补充“触发条件节点 + 参数语义节点 + 证据节点”

**解决的问题**：
- 函数可达 ≠ 可触发
- 无法解释“为什么触发”

---

### 1.2 约束可满足证明（Constraint Satisfiability Proof）

**定义**：
在触发条件模型之上，把关键条件转成数学约束（len/flags/路径条件），用 Apron/SMT 判断“是否存在满足条件的输入”。

**解决的问题**：
- 触发条件仅用字符串匹配会误报
- 约束可满足证明可减少误判、提升可信度

---

## 2. TTSG 详细技术讲解

### 2.1 图模型构成

TTSG 扩展了传统 CPG，新增以下图元素：

- `FFI_BRIDGE`：跨语言边界节点（Rust → C）
- `PARAM_ROLE`：参数角色节点（buf/len/flags/callback）
- `TRIGGER_CONDITION`：触发条件节点
- `CONSTRAINT`：约束节点（len > 0, flags contains X）
- `EVIDENCE`：证据节点（依赖链来源、二进制分析来源）

### 2.2 关键关系（边）

- `FFI_CALL`：Rust 调用 C
- `ABI_MAPS`：参数语义对齐
- `REQUIRES`：触发条件依赖的参数/约束
- `SAT_BY`：约束可满足证明链接
- `EVIDENCE_OF_DEP`：依赖关系的证据

### 2.3 参数语义对齐（FFI 语义层）

在跨语言调用链中识别参数语义：

- `buf`：输入缓冲区指针
- `len`：缓冲区长度
- `flags`：开关/选项
- `callback`：回调函数

示例：
```
XML_Parse(parser, xml_buf, xml_len, XML_TRUE)
```
语义标注：
- `arg2 = buf`
- `arg3 = len`
- `arg4 = flags`

**意义**：
触发条件往往依赖 `len` 和 `flags`，必须对齐语义才能做准确触发判定。

---

## 3. 约束可满足证明：技术细节

### 3.1 约束来源

- **参数约束**：buf/len 关系，如 `len = |input|`
- **路径约束**：if/while 条件，如 `len > 0`
- **flag 约束**：`flags` 包含危险位
- **sanitizer 约束**：禁用外部实体、限制长度

### 3.2 约束表达方式

统一表达成：

- 数值约束：`len > 0`, `len > 500000`
- 位约束：`flags & XML_PARSE_NOENT != 0`
- 逻辑组合：`A and (B or C)`

### 3.3 可满足性判定

求解结果分三类：

- `satisfiable` → 可触发（confirmed）
- `unsatisfiable` → 不可触发（unreachable）
- `unknown` → 可能触发（possible）

---

## 4. 系统架构（文本版）

**输入层**
- Rust + C 源码 / 二进制库
- n‑day CVE 规则库（JSON）

**中间层（图构建）**
- CPG → Neo4j
- 跨语言补链
- TTSG 扩展节点与边

**分析层**
- 可达性：调用链 + 依赖链
- 触发性：触发条件模型 + 约束求解

**输出层**
- 可达/可触发报告
- 触发条件证据链
- 约束可满足证明结果

---

## 5. 应用于 n‑day 供应链漏洞的价值

- **可解释性**：不仅告诉“能到达”，还能解释“为什么能触发”。
- **跨语言准确性**：Rust→C→C→第三方库的链路清晰可追踪。
- **适用 n‑day**：只需漏洞规则库（JSON）即可检测，不依赖 0day。

---

## 6. 在 PoC 中的体现（CVE‑2024‑28757）

触发条件：
- 回调注册 (`XML_SetExternalEntityRefHandler`)
- 创建外部实体解析器 (`XML_ExternalEntityParserCreate`)
- 实际解析 (`XML_Parse`)

约束示例：
- `xml_len > 0`
- `flags` 未禁用外部实体

可满足性：
- 存在输入使 `xml_len > 0`，且 flags 允许解析 → `confirmed`

---

## 7. 输出示例（结构设计）

```json
{
  "reachable": true,
  "triggerable": "confirmed",
  "tts_graph": {
    "ffi_semantics": [{"arg2":"buf","arg3":"len","arg4":"flags"}],
    "trigger_conditions": ["XML_SetExternalEntityRefHandler", "XML_Parse"],
    "evidence_chain": ["cargo metadata", "binary deps", "manual"]
  },
  "constraint_result": {
    "status": "satisfiable",
    "constraints": ["len > 0", "flags contains XML_TRUE"],
    "solver": "apron|smt"
  }
}
```

---

## 8. 论文贡献点可写成

1. **跨语言触发语义图（TTSG）**：把触发条件、参数语义、依赖证据统一建模为图对象，支持跨语言、跨组件的触发性解释。
2. **约束可满足证明**：将触发条件抽象为数学约束，用求解器判断“是否存在触发输入”，显著降低误报。
3. **供应链场景适配**：针对 n‑day CVE 规则库实现自动化检测，而非 0day 漏洞发现。

---

## 9. 后续落地路线

- **阶段 1**：TTSG 在现有 Neo4j 中落地，输出触发语义节点与证据链
- **阶段 2**：轻量约束求解（规则级）
- **阶段 3**：Apron/SMT 引入，完成可满足证明

---

## 10. 你可以用在汇报中的一句话

> 我们提出跨语言触发语义图（TTSG），把触发条件、参数语义与供应链证据纳入同一属性图，再用约束可满足性证明判断触发是否真实可能，从而实现面向 n‑day 的跨语言供应链漏洞可达与可触发检测。

