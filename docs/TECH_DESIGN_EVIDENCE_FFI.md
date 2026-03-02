# 证据链建模 + FFI 语义对齐 技术设计文档（待确认后实施）

## 目标

在现有跨语言供应链分析基础上，补齐两个关键能力：

1. **二进制/间接依赖证据链建模**：每条 `DEPENDS_ON` 不只是“存在关系”，还要有“证据来源 + 可信度”。
2. **跨语言 ABI/FFI 语义对齐**：识别参数语义（buf/len/flags/callback）与触发条件，从“函数可达”提升到“参数条件满足”。

## 一、证据链建模（Binary / Indirect Dependency Evidence）

### 1.1 核心问题

- 二进制-only 组件没有源码，依赖链不透明。
- 现有工具只能手工补充 C 组件依赖，缺少证据与可信度描述。
- 供应链场景必须支持“自动推断 + 可解释链路”。

### 1.2 设计思路

在图中构建“证据化的依赖链”，让每条依赖边具有：

- `evidence_type`: 证据类型（build/metadata/binary/symbol/manual）
- `confidence`: 可信度（high/medium/low）
- `source`: 证据来源路径或命令（可选）
- `evidence`: 关键证据摘要（可选）

### 1.3 数据来源与优先级

1. **Cargo metadata**（高可信）
2. **build.rs / cargo:rustc-link-lib**（中高可信）
3. **二进制依赖**（otool/ldd/readelf）（中可信）
4. **符号推断**（nm/objdump）（低可信）
5. **手工补充 JSON**（可解释、低~中可信）

### 1.4 方案落地

**扩展依赖导入逻辑**：

- 在 `import_dependencies` 时支持 `depends` 中的 `evidence` 字段。
- `DEPENDS_ON` 关系附带属性：
  - `evidence_type`, `confidence`, `source`, `evidence`

**新增证据链输出**：

- 在报告中增加 `dependency_chain_evidence`：
  - 每一条依赖边包含证据信息

**新增二进制依赖推断（后续可扩展）**：

- 初版可以仅支持 macOS `otool -L`：
  - 自动解析 `.dylib` 的依赖库名 → 形成 `depends` 边

### 1.5 输出示例（报告新增字段）

```json
"dependency_chain_evidence": [
  {"from":"crate_b","to":"compa","evidence_type":"manual","confidence":"low"},
  {"from":"compa","to":"compb","evidence_type":"manual","confidence":"low"},
  {"from":"compb","to":"compc","evidence_type":"manual","confidence":"low"},
  {"from":"compc","to":"expat","evidence_type":"binary","confidence":"medium","evidence":"otool -L"}
]
```

---

## 二、FFI 语义对齐（ABI/Parameter Semantics Alignment）

### 2.1 核心问题

- 仅函数名可达无法说明漏洞触发。
- 许多漏洞要求特定参数/flag/回调配置。
- Rust ↔ C 的参数语义没有对齐，导致触发判断过粗。

### 2.2 设计目标

在分析中建立以下能力：

1. **参数角色标注**：识别 `buf/len/flags/callback` 等语义。
2. **条件匹配**：在触发模型中引入“参数/flag条件”。
3. **证据输出**：报告中给出参数语义与 flag 证据。

### 2.3 方案落地

**规则扩展**：

- 在 `trigger_model` 增加可选 `param_roles` / `flag_required` / `flag_forbidden`。

**参数语义识别（启发式）**：

- Rust：
  - `as_ptr()` → `buf`
  - `len()` / `as_bytes().len()` → `len`
- C：
  - `strlen()` / `sizeof` → `len`
  - 常见 `options` / `flags` 参数名 → `flags`

**条件匹配增强**：

- 通过 `call_code_contains` 识别 flags（如 `XML_PARSE_NOENT`）
- 通过 `param_roles` 约束参数位置/语义

### 2.4 输出示例（报告新增字段）

```json
"ffi_semantics": {
  "ffi_signature": "XML_Parse(parser, xml_buf, xml_len, XML_TRUE)",
  "param_roles": {"arg2":"buf","arg3":"len"},
  "flags_evidence": ["XML_TRUE"],
  "notes": ["buf/len pattern matched"]
}
```

---

## 三、与 PoC 的结合方式

基于 CVE-2024-28757 PoC：

- 触发条件：
  - `XML_SetExternalEntityRefHandler`
  - `XML_ExternalEntityParserCreate`
  - `XML_Parse`
- 证据链：
  - Rust → C 多层 → expat
- FFI 语义对齐：
  - 验证 XML buffer 与长度参数的传递关系

---

## 四、实施顺序与改动范围

1. 扩展依赖导入：支持 `depends` 边证据字段
2. 报告输出：增加 `dependency_chain_evidence`
3. 触发模型扩展：支持参数语义 / flags 输出
4. PoC 检测验证与输出增强

---

## 五、确认点

请确认是否按上述设计实施：

- 证据链建模：增加 `evidence_type/confidence/source` 的依赖边建模与报告输出
- FFI 语义对齐：启发式识别 `buf/len/flags`，并输出到报告

确认后我将开始修改代码。

