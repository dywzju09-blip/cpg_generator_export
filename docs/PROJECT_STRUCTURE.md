# 项目结构说明

本文档描述清理后的仓库结构。当前仓库只保留工具源码、文档，以及最近一次 `NEW/projects` 批量检测的分析结果。

## 当前目录结构

```text
/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export
├── README.md
├── generate_cpgs.sh
├── PROJECT_RULES.md
├── c_tools/
├── docs/
├── rust_src/
│   ├── Cargo.toml
│   └── src/
├── tools/
│   ├── fetch/
│   ├── neo4j/
│   ├── deploy/
│   ├── supplychain/
│   ├── verification/
│   └── ffi_semantics/
└── output/
    └── vulnerability_runs/
        └── new_projects_sweep/
```

## 目录职责

- `c_tools/`: C 侧辅助工具。
- `rust_src/`: Rust CPG 生成器源码。
- `tools/fetch`: native 组件源码或二进制获取脚本。
- `tools/neo4j`: 图导入、链接和查询相关工具。
- `tools/deploy`: Linux 迁移、打包和批量运行脚本。
- `tools/supplychain`: 漏洞规则、依赖解析、可达/可触发分析主逻辑。
- `tools/verification`: 参数语义和补充验证逻辑。
- `docs/`: 设计说明、结构说明、任务模板和分析文档。
- `output/vulnerability_runs/new_projects_sweep/`: 最近一次保留的 20 项目检测报告。

## 已清理内容

以下历史内容已从仓库中移除：

- 历史 `vulnerabilities/` CVE 样例目录
- 旧的 `output/vulnerabilities/` 和旧批量检测结果
- 根目录 `.rlib`、类型推导文本等编译残留
- `rust_src/target/`
- 无关资料目录和旧第三方源码缓存

## 产物管理约定

以下内容应视为可再生产物，默认不长期保留：

- `**/target/`
- `**/target_cpg/`
- `*.rlib`
- `*.log` 的临时调试副本
- 临时脚本和一次性 debug 文件

仓库中若新增批量检测结果，建议统一放在 `output/vulnerability_runs/<run_name>/`，并及时删除过期 run。
