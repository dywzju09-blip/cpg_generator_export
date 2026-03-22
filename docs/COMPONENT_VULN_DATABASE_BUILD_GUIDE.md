# Rust Native 组件漏洞数据库构建说明

## 1. 目标

本说明文档定义一套可长期维护的“Rust 主流依赖 C 组件漏洞数据库”构建方案，目标是：

- 不再为每个项目临时手写新的 `vulns.json`
- 数据库能直接满足当前 [`supplychain_analyze.py`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/supplychain_analyze.py) 的输入要求
- 数据库不仅保存 `CVE + 版本范围 + 漏洞符号`，还要保存“触发条件、参数语义、环境 guard、组件来源、间接依赖证据”
- 能覆盖 Rust 直接调用 native 组件，以及 `Rust crate -> sys crate -> C wrapper -> 下游 C 组件` 这类间接调用场景

这份数据库的定位不是通用情报库，而是“为当前检测器服务的可执行规则数据库”。

## 2. 当前检测器真正需要什么

当前检测器不是只吃一个“CVE 列表”，而是吃一组可执行规则。核心入口见：

- [`tools/supplychain/supplychain_analyze.py#L4809`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/supplychain_analyze.py#L4809)
- [`tools/supplychain/supplychain_analyze.py#L4811`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/supplychain_analyze.py#L4811)

分析器对每条漏洞规则会做三件事：

1. 从 `--vulns` 读取原始规则
2. 从组件级知识库补齐默认 sink / guard / input predicate
3. 把高层字段编译成 `trigger_model`

对应实现：

- 组件级合并：[`tools/supplychain/supplychain_analyze.py#L1014`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/supplychain_analyze.py#L1014)
- 规则标准化：[`tools/supplychain/supplychain_analyze.py#L1601`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/supplychain_analyze.py#L1601)
- 报告输出字段：[`tools/supplychain/supplychain_analyze.py#L5370`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/supplychain_analyze.py#L5370)

所以数据库不能只保存“漏洞是否存在”，必须保存“如何判断可达、如何判断可触发”。

## 3. 推荐采用三层数据库，而不是一个大 JSON

建议在 [`tools/supplychain/`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain) 下新增专用目录：

```text
tools/supplychain/vuln_db/
├── components/
│   └── <component>.json
├── vulns/
│   └── <component>/
│       └── <CVE>.json
├── evidence/
│   └── <component>/
│       └── <CVE>.json
├── indexes/
│   ├── runtime_rules.full.json
│   ├── components_by_crate.json
│   ├── cves_by_component.json
│   └── component_alias_index.json
└── README.md
```

三层含义如下：

- `components/`: 组件级静态知识，解决“这是什么组件、Rust 怎么碰到它、间接依赖链怎么表达”
- `vulns/`: 单个 CVE 的运行时规则，必须能直接投喂当前分析器
- `evidence/`: 补丁、PoC、advisory、人工分析摘要，解决规则可追溯和后续扩充问题

这样做的原因是：

- 组件级信息会被多个 CVE 复用
- CVE 规则要保持当前检测器兼容
- 证据材料不应塞进运行时 JSON，否则会越来越难维护

## 4. 组件层应该保存什么

组件层不是“漏洞规则”，而是“组件知识底座”。它主要解决间接调用、别名、sys crate 映射、native 来源、FFI 语义复用的问题。

建议每个组件文件至少包含以下信息：

```json
{
  "component": "libxml2",
  "aliases": ["xml2", "libxml"],
  "ecosystem": "native-c",
  "homepage": "https://xmlsoft.org/",
  "package_aliases": ["libxml", "libxml2-sys", "libxslt", "xmlsec"],
  "sys_crates": ["libxml", "libxml2-sys"],
  "high_level_crates": ["libxml", "libxslt"],
  "provider_hints": {
    "default_source": "system",
    "source_markers": ["vendored", "pkg-config", "system"]
  },
  "native_symbols": [
    "xmlReadMemory",
    "xmlParseMemory",
    "xmlCtxtReadMemory"
  ],
  "rust_entrypoints": [
    "Parser::parse_string",
    "Parser::parse_file"
  ],
  "indirect_dependency_patterns": [
    {
      "from_crate": "xmlsec",
      "through": ["libxslt", "libxml2"],
      "evidence_type": "manual",
      "confidence": "medium"
    }
  ],
  "ffi_summary_ref": {
    "registry": "tools/ffi_semantics/ffi_semantics_registry.json",
    "component": "libxml2"
  }
}
```

组件层必须覆盖 6 类信息：

1. 组件标识
2. Rust crate / sys crate / native 组件别名
3. 常见 sink 符号与 Rust 入口
4. 组件来源信息
5. 间接依赖模式
6. 可复用的 FFI/ABI 语义

现有项目中，下面几个文件都可以作为组件层初始种子：

- [`tools/supplychain/sink_knowledge_base.json`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/sink_knowledge_base.json)
- [`tools/ffi_semantics/ffi_semantics_registry.json`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/ffi_semantics/ffi_semantics_registry.json)
- [`tools/fetch/native_source_providers.py`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/fetch/native_source_providers.py)

## 5. 漏洞层必须保存什么

漏洞层是数据库最关键的部分。每个 `CVE` 文件必须是“当前分析器可直接消费的规则对象”，也就是最终能被聚合成一个 `runtime_rules.full.json`。

### 5.1 最低可运行字段

最低要求不是只有 4 个字段，但至少必须有：

- `cve`
- `package`
- `version_range`
- `symbols`

### 5.2 面向当前检测器的必备增强字段

为了满足当前“可达 + 可触发 + 间接调用”的要求，建议每条漏洞规则至少覆盖下列字段：

- `match.crates`
- `symbols`
- `rust_sinks`
- `native_sinks`
- `trigger_conditions`
- `trigger_model.conditions`
- `trigger_model.mitigations`
- `input_predicate`
- `env_guards`
- `source_patterns`
- `sanitizer_patterns`
- `must_flow`
- `source_status`

如果漏洞依赖参数、flag、结构体字段或跨语言状态，还要补：

- `trigger_model.param_semantics`
- `trigger_model.state_rules`
- `trigger_model.existential_inputs`
- `trigger_model.ffi_summaries`

### 5.3 推荐的单条 CVE 结构

下面这个结构是建议作为数据库中的“标准漏洞条目”：

```json
{
  "cve": "CVE-2024-40896",
  "package": "libxml2",
  "version_range": "<2.13.0",
  "description": "XXE in libxml2 parser path.",
  "severity": "high",
  "references": {
    "advisory": ["..."],
    "patch": ["..."],
    "poc": ["..."]
  },
  "match": {
    "crates": ["libxml", "libxml2-sys", "xmlsec"]
  },
  "symbols": [
    "xmlReadMemory",
    "xmlCtxtReadMemory",
    "xmlParseMemory"
  ],
  "rust_sinks": [
    {"path": "Parser::parse_string"},
    {"path": "xmlReadMemory"}
  ],
  "native_sinks": [
    "xmlReadMemory",
    "xmlParseMemory"
  ],
  "source_status": "system",
  "component_metadata_ref": "tools/supplychain/vuln_db/components/libxml2.json",
  "trigger_conditions": [
    "untrusted XML reaches parser",
    "dangerous parser flags enable entity expansion"
  ],
  "input_predicate": {
    "class": "crafted_xml_or_html_input",
    "strategy": "assume_if_not_explicit"
  },
  "env_guards": {
    "all": [
      {"type": "component_version", "package": "libxml2", "op": "<", "version": "2.13.0"}
    ]
  },
  "must_flow": [
    "request.body -> Parser::parse_string.arg1"
  ],
  "source_patterns": ["request", "payload", "xml_body"],
  "sanitizer_patterns": ["escape", "validate", "XML_PARSE_NONET"],
  "trigger_model": {
    "conditions": [
      {
        "id": "xml_parser_call",
        "type": "call",
        "name": "xmlReadMemory",
        "lang": "Rust"
      },
      {
        "id": "dangerous_flags",
        "type": "call_code_contains",
        "name": "xmlReadMemory",
        "lang": "Rust",
        "contains": ["XML_PARSE_NOENT", "XML_PARSE_DTDLOAD"],
        "contains_all": true
      }
    ],
    "mitigations": [
      {
        "id": "nonet_enabled",
        "type": "call_code_contains",
        "name": "xmlReadMemory",
        "lang": "Rust",
        "contains": ["XML_PARSE_NONET"],
        "contains_all": true
      }
    ],
    "param_semantics": {
      "flags": [
        {
          "call": "xmlReadMemory",
          "arg_index": 5,
          "requires_all": ["XML_PARSE_DTDLOAD", "XML_PARSE_NOENT"],
          "forbids": ["XML_PARSE_NONET"]
        }
      ]
    }
  }
}
```

这个结构和当前已有规则完全同类，可直接参考：

- [`tools/supplychain/real_apps/rules/post_maker_cve_2023_4863.json`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/real_apps/rules/post_maker_cve_2023_4863.json)
- [`tools/supplychain/supplychain_vulns_cve_2024_40896.json`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/supplychain_vulns_cve_2024_40896.json)

## 6. 间接调用信息应该如何入库

你特别强调了“间接调用时漏洞触发的情况”，这部分必须显式设计，不能只靠 `symbols`。

数据库里至少要保存 3 类间接信息。

### 6.1 依赖间接性

要回答“Rust 为什么会碰到这个 native 组件”，需要组件层或证据层保存：

- `high_level_crates`
- `sys_crates`
- `through_components`
- `dependency_edges`
- `evidence_type`
- `confidence`

建议用统一结构保存：

```json
{
  "dependency_chain_templates": [
    {
      "from": "high_level_crate",
      "to": "sys_crate",
      "through": ["wrapper_c_component", "target_component"],
      "evidence_type": "manual",
      "confidence": "medium",
      "notes": "Observed in xmlsec -> libxslt -> libxml2 style chain."
    }
  ]
}
```

如果一个漏洞通常通过“别的 C 组件间接进入”，这一层必须记录；否则后续分析只能命中直接绑定的 case。

### 6.2 调用间接性

要回答“虽然 Rust 没直接调用漏洞符号，但路径上其实会到漏洞函数”，要用规则字段表达。

当前检测器可利用的字段主要是：

- `rust_sinks`
- `native_sinks`
- `must_flow`
- `trigger_model.conditions` 里的 `api_sequence`
- `trigger_model.conditions` 里的 `call_order`
- `trigger_model.conditions` 里的 `field_to_call_arg`
- `trigger_model.conditions` 里的 `io_to_call_arg`

当前分析器支持的主要条件类型见：

- [`tools/supplychain/supplychain_analyze.py#L4319`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/supplychain_analyze.py#L4319)

这意味着数据库里的规则不能只写：

```json
{"symbols":["XML_ExternalEntityParserCreate"]}
```

而要写成：

```json
{
  "rust_sinks": [{"path": "Parser::parse"}],
  "native_sinks": ["XML_Parse", "XML_ExternalEntityParserCreate"],
  "trigger_model": {
    "conditions": [
      {
        "id": "expat_sequence",
        "type": "api_sequence",
        "steps": [
          {"name": "XML_Parse", "lang": "C"},
          {"name": "XML_ExternalEntityParserCreate", "lang": "C"}
        ],
        "scope": "any",
        "same_method": false
      }
    ]
  }
}
```

### 6.3 状态间接性

有些漏洞不是“调用到某个函数就触发”，而是“先设置某个结构体字段，再进入后续函数才成立”。这类信息必须放到：

- `trigger_model.param_semantics`
- `trigger_model.state_rules`
- `trigger_model.existential_inputs`

现有状态语义能力见：

- [`tools/verification/state_semantics.py`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/verification/state_semantics.py)
- [`tools/verification/param_semantics.py`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/verification/param_semantics.py)

这对于 zlib、libxml2、image decoder、parser flags 这类漏洞非常重要。

## 7. 组件层、漏洞层、证据层的职责边界

为了避免数据库继续演化成“一个什么都往里塞的大 JSON”，建议严格按下面边界维护。

### 7.1 组件层负责复用信息

组件层负责：

- 组件别名
- sys crate / high-level crate 映射
- 默认 `rust_sinks`
- 默认 `native_sinks`
- 常见 `input_predicate`
- 常见 `env_guards`
- FFI summary 引用
- 常见间接依赖链模板

这部分和今天的 [`tools/supplychain/sink_knowledge_base.json`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/sink_knowledge_base.json) 定位接近，但建议做得更完整。

### 7.2 漏洞层负责 CVE 特异性

漏洞层负责：

- CVE 编号
- 受影响版本范围
- 漏洞本体符号
- 漏洞特异的触发条件
- 漏洞特异的 mitigations
- 漏洞需要的特定 flags / fields / guards

### 7.3 证据层负责可追溯性

证据层负责：

- advisory 链接
- patch 链接和 patch 摘要
- PoC 链接
- 人工分析摘要
- 为什么得出当前 `trigger_model`

证据层不直接参与运行，但决定数据库是否能长期维护。

## 8. 数据库如何与当前工具对接

为了“不用每次新生成 JSON”，建议分成两个阶段。

### 8.1 第一阶段：先构建运行时总表

先产出一个汇总后的：

- `tools/supplychain/vuln_db/indexes/runtime_rules.full.json`

这个文件内部就是当前分析器能直接读的“规则数组”。也就是说，格式和今天传给 `--vulns` 的 JSON 一样。

这样立即能落地：

```bash
python tools/supplychain/supplychain_analyze.py \
  --cargo-dir <project> \
  --vulns tools/supplychain/vuln_db/indexes/runtime_rules.full.json \
  --report output/analysis_report.json
```

优点：

- 不改分析器主流程也能用
- 先把数据库沉淀起来
- 原有 rule 文件都可以并入

缺点：

- 每次分析会扫描全量规则，后面规模上来会慢

### 8.2 第二阶段：增加数据库选择器

数据库稳定后，再补一个轻量脚本，例如：

- `tools/supplychain/vuln_db/build_runtime_rules.py`
- `tools/supplychain/vuln_db/select_rules_for_project.py`

作用是：

1. 从全量数据库按 `crate/component/version/source` 过滤出相关规则
2. 输出一个项目级精简运行时规则
3. 可选地把组件层信息合并进漏洞层

这一步不是数据库建设的前置条件，但会让后续批量分析更高效。

## 9. 数据采集和建库流程

建议按下面顺序做，而不是先大量堆 CVE。

### 9.1 先确定组件集合

先做“Rust 生态主流 native 组件清单”，优先级建议：

1. 当前项目已覆盖的组件
2. 常见 sys crate 绑定的组件
3. 图像、压缩、XML、数据库、音视频、TLS、正则、git 类组件

初始种子可以从下面位置提取：

- [`tools/supplychain/sink_knowledge_base.json`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/sink_knowledge_base.json)
- [`tools/supplychain/real_apps/manifest.json`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/real_apps/manifest.json)
- [`tools/supplychain/auto_vuln_inputs.py`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/auto_vuln_inputs.py)

### 9.2 再做组件画像

每个组件先补齐：

- aliases
- Rust crate 映射
- 常见 symbols
- provider/source 模式
- 是否常见间接依赖
- 是否已有 FFI summary

只有组件画像完成后，后面的 CVE 规则才不会重复劳动。

### 9.3 再做 CVE 级规则

每个 CVE 至少做下面工作：

1. 确认版本范围
2. 确认漏洞核心 symbol 或 path
3. 从 patch / advisory / PoC 提取真实触发条件
4. 判断是直接调用、间接调用、还是状态驱动
5. 编码成当前规则格式

### 9.4 最后做运行时聚合

把 `components/ + vulns/` 聚合成：

- `runtime_rules.full.json`
- `components_by_crate.json`
- `cves_by_component.json`

供分析器和后续自动化脚本使用。

## 10. 触发条件抽取规范

数据库质量高低，主要取决于触发条件是否足够细，而不是 CVE 数量。

建议每条漏洞都按下面 5 个问题抽取。

1. 入口 API 是什么
2. 漏洞真正发生在哪个 native 函数或状态点
3. 必须满足哪些 flag / 参数 / 顺序 / 分支
4. 哪些防护条件会让漏洞不成立
5. 间接调用时，中间经过哪些 wrapper / parser / decoder

建议把触发条件拆成四类来编码。

### 10.1 路径类条件

适合用：

- `call`
- `call_code_contains`
- `api_sequence`
- `call_order`

### 10.2 数据流类条件

适合用：

- `must_flow`
- `field_to_call_arg`
- `io_to_call_arg`
- `len_to_call_arg`
- `option_to_call_arg`

### 10.3 控制流类条件

适合用：

- `control_code_contains`
- `branch_code_contains`
- `env_guards`

### 10.4 语义类条件

适合用：

- `input_predicate`
- `param_semantics`
- `state_rules`
- `existential_inputs`

只有把触发条件拆成这四类，数据库才适合长期扩充。

## 11. 数据质量门槛

建议给数据库设一个“可入库门槛”，否则后面会堆很多只能做 reachability、不能做 triggerability 的弱规则。

每条正式入库的漏洞规则建议至少满足：

- 有明确 `package`
- 有明确 `version_range`
- 有明确 `symbols`
- 有至少一条 `rust_sinks` 或 `native_sinks`
- 有至少一个触发条件表达
- 有至少一个参考证据来源

如果是“间接调用常见”的漏洞，再额外要求：

- 有 `dependency_chain_templates` 或间接依赖说明
- 有 `api_sequence` / `must_flow` / `state_rules` 至少一种

建议把规则分成 3 个成熟度等级：

- `seed`: 只有基础版本和符号，还不能精确判断触发
- `curated`: 已有完整触发条件，可参与正式分析
- `verified`: 已经被真实项目或 PoC 验证过

## 12. 现有仓库内容如何迁移到数据库

可以按下面顺序迁移，不要一次性重写。

### 12.1 先迁移组件知识

把下面文件的公共信息迁入 `components/`：

- [`tools/supplychain/sink_knowledge_base.json`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/sink_knowledge_base.json)
- [`tools/ffi_semantics/ffi_semantics_registry.json`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/ffi_semantics/ffi_semantics_registry.json)

### 12.2 再迁移手工规则

把下面规则文件迁成 `vulns/<component>/<CVE>.json`：

- [`tools/supplychain/supplychain_vulns_libxml2.json`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/supplychain_vulns_libxml2.json)
- [`tools/supplychain/supplychain_vulns_expat.json`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/supplychain_vulns_expat.json)
- [`tools/supplychain/supplychain_vulns_cve_2024_40896.json`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/supplychain_vulns_cve_2024_40896.json)
- [`tools/supplychain/real_apps/rules/`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/real_apps/rules)

### 12.3 再迁移间接依赖补充

把下面 extras 中的依赖边抽取成“组件链模板”或“证据层案例”：

- [`tools/supplychain/supplychain_extras_libxml2.json`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/supplychain_extras_libxml2.json)
- [`tools/supplychain/supplychain_extras_expat.json`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/supplychain_extras_expat.json)
- [`tools/supplychain/real_apps/extras/`](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/real_apps/extras)

extras 不应继续作为“唯一的间接依赖知识来源”，而应沉淀回数据库。

## 13. 建库时不要犯的几个错误

### 13.1 不要只保存 CVE 和版本

那样只能做“依赖命中”，不能做“触发判断”。

### 13.2 不要把组件共性全写进每个 CVE

会导致规则重复、字段漂移、后期难统一。

### 13.3 不要把项目特异 case 误写成组件通用规则

例如某个真实项目里的 `must_flow` 路径可能高度依赖这个项目，不一定适合作为组件级默认规则。项目特异逻辑应该保留在证据层，通用部分再抽回组件层或 CVE 层。

### 13.4 不要忽略“间接到达但直接 symbol 不可见”的情况

这正是你这个工具的关键卖点之一。数据库如果不保存 wrapper、state、sequence、dependency evidence，后面检测能力会退化成普通 reachability。

## 14. 推荐的实施顺序

按投入产出比，建议这样做。

1. 先定目录结构和 schema
2. 先迁移已有规则，不新增新组件
3. 把 `sink_knowledge_base.json` 和 `ffi_semantics_registry.json` 抽成组件层
4. 生成第一个 `runtime_rules.full.json`
5. 用现有 real-app cases 回归验证
6. 再逐步扩新组件和新 CVE
7. 最后再做规则选择器和自动建库脚本

## 15. 最终交付物应该长什么样

数据库建设完成后，至少应该稳定产出下面 4 类结果：

- 组件画像库
- 单 CVE 可执行规则库
- 证据归档
- 运行时总规则表

其中最关键的运行时文件是：

- `tools/supplychain/vuln_db/indexes/runtime_rules.full.json`

它应该直接替代今天那些零散的 `supplychain_vulns_*.json`，成为默认规则来源。

## 16. 结论

要满足你当前工具的要求，这个数据库不能设计成普通“漏洞清单”，必须设计成：

- 组件知识层
- CVE 规则层
- 证据层
- 运行时投影层

其中：

- 组件层解决“Rust 如何碰到这个 native 组件”
- CVE 层解决“这个漏洞什么条件下成立”
- 证据层解决“为什么这样建规则”
- 运行时层解决“当前分析器如何直接消费”

如果按这个思路建设，后续你新增项目时不需要再手工从零写 `vulns.json`；你只需要从数据库中筛选并投影出适合该项目的一组规则，甚至在第一阶段可以直接把全量规则表传给分析器。
