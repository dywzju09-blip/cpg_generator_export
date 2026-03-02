# CPG 生成工具包（供应链可达/可触发分析）

本项目包含 Rust/C Code Property Graph (CPG) 生成器，以及基于 Neo4j 的跨语言供应链漏洞可达/可触发分析工具。

## 核心功能

本工具旨在解决**跨语言供应链漏洞**的检测问题，特别是当 Rust 项目通过 FFI 调用 C 库时的风险。

- **通用性**: 支持检测任意 C 组件的漏洞，只要能定义其危险函数。
- **自动化**: 对于动态链接库 (.so)，工具可自动提取符号依赖；对于静态库，支持手动补充元数据。
- **精确性**: 基于代码属性图 (CPG) 的全路径分析，不仅检测“是否依赖”，还检测“是否调用”和“是否可触发”。

## 目录结构

- `vulnerabilities/`: 漏洞 PoC 案例库（包含源码、构建脚本和运行说明）。
  - `CVE-2024-28757_expat/`: libexpat XML 实体膨胀漏洞（动态链接示例）。
  - `CVE-2023-50472_cjson/`: cJSON 堆溢出漏洞（静态编译/手动依赖示例）。
  - `CVE-2024-28757_Chain/`: libexpat 多跳调用链变体。
  - `Indirect_Libxml2/`: libxml2 间接调用示例。
- `output/vulnerabilities/`: 分析输出结果（构建产物、CPG、报告）。
- `tools/`: 核心工具脚本。
  - `supplychain/`: 漏洞库定义与分析逻辑。
  - `neo4j/`: 图数据库导入与链接脚本。
- `rust_src/`: Rust CPG 生成器源码。
- `c_tools/`: C CPG 生成器工具。

## 快速开始

请进入 `vulnerabilities/` 目录下的对应漏洞文件夹，运行演示脚本。

### 1. 动态链接场景 (libexpat)
工具自动识别 .so 依赖并分析。
```bash
./vulnerabilities/CVE-2024-28757_expat/run_analysis.sh
```

### 2. 静态编译场景 (cJSON)
演示如何通过手动指定 `extras.json` 来检测源码集成的 C 库漏洞。
```bash
./vulnerabilities/CVE-2023-50472_cjson/run_analysis.sh
```

## 如何检测新组件漏洞（通用方法）

如果您想检测一个新的 C 组件漏洞（例如 zlib），请遵循以下步骤：

### 第一步：定义漏洞
在 `tools/supplychain/` 下创建一个新的漏洞定义文件（如 `vulns_zlib.json`），描述 CVE 编号、受影响版本和**危险函数名**。

```json
[
  {
    "cve": "CVE-XXXX-XXXX",
    "package": "zlib",
    "symbols": ["inflate"],
    "trigger_conditions": ["untrusted input"]
  }
]
```

### 第二步：处理依赖
**情况 A：Rust 项目动态链接了系统库 (如 libz.so)**
无需额外操作。在运行分析时，使用 `auto_extras.py` 扫描 .so 目录即可自动生成依赖关系。

**情况 B：Rust 项目静态编译了 C 源码 (如 cJSON)**
需要手动创建一个依赖描述文件（如 `extras_zlib.json`），告诉工具该项目包含 zlib。

```json
{
  "packages": [{"name": "zlib", "version": "1.2.11"}],
  "depends": [{"from": "your-rust-package", "to": "zlib"}]
}
```

### 第三步：运行分析
使用 `supplychain_analyze.py` 加载上述配置进行检测。

## 环境要求
- Rust (Nightly)
- Java 11+ (Joern)
- Python 3
- Neo4j (运行在 localhost:7687, user=neo4j, pass=password)
- C 编译工具链
