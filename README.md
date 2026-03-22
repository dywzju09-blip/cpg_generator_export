# CPG 生成与供应链漏洞分析工具

本仓库保留两类内容：

- 工具源码与文档
- 默认漏洞数据库
- 最近一次 `NEW/projects` 批量检测的 20 个项目分析报告

历史 CVE PoC 样例、旧分析输出、编译残留和无关资料已清理。

## 当前目录结构

- `tools/`: 供应链分析、Neo4j 导入、参数语义和验证逻辑
- `Data/`: 默认 Rust-native 组件漏洞数据库
- `rust_src/`: Rust CPG 生成器源码
- `c_tools/`: C 侧辅助工具
- `docs/`: 设计说明、规则说明和任务模板
- `skills/`: 可复用的 Codex skills，包括 `find-proj` 等流程模板
- `tools/deploy/`: Linux 迁移、打包和批量运行脚本
- `output/vulnerability_runs/new_projects_sweep/`: 最近一次批量检测结果
- `PROJECT_RULES.md`: 仓库级约束
- `generate_cpgs.sh`: CPG 生成入口脚本

## 保留的检测结果

本次保留的是对外部项目目录 `/Users/dingyanwen/Desktop/VUL/NEW/projects` 的批量检测结果。

结果根目录：

- `output/vulnerability_runs/new_projects_sweep/`

其中包含：

- `README.md`: 本轮检测摘要
- `summary.json`
- `summary_projects.json`
- `confirmed_projects.json`
- `failed_projects.json`
- `timed_out_projects.json`
- `status_counts.json`
- `manifest.json`
- 每个项目各自的运行目录、输入文件、日志、CPG 和分析报告

## 使用方式

1. 在 `tools/supplychain/` 中准备漏洞规则和 extras。
2. 或直接使用 `Data/vuln_db/indexes/runtime_rules.full.json` 作为默认漏洞规则库。
3. 对目标 Rust 项目生成或加载 CPG。
4. 运行 `tools/supplychain/supplychain_analyze.py` 输出可达/可触发结论。

如果要把工具和项目迁移到 Linux 服务器，直接看：

- `docs/DEPLOY_TO_LINUX.md`

如果要看最近一次 20 个项目的检测有效性，直接查看：

- `output/vulnerability_runs/new_projects_sweep/README.md`

## 环境要求

- Rust
- Python 3
- Java / Joern
- Neo4j
- 可用的 native 构建工具链
