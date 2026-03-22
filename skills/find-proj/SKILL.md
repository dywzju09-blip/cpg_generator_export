---
name: find-proj
description: Use when the user wants new Rust project plus native CVE candidates for static analysis, and the projects must be absent from the current workspace or prior analysis set. Applies to tasks that search, filter, download, and summarize previously untested project-vulnerability combinations.
---

# Find Proj

## 何时使用

在下面这些场景触发本 skill：

- 用户要找一批适合静态分析的 Rust + native CVE 项目。
- 用户明确要求“必须是新项目”“当前目录里没有”“之前从未检测过”。
- 用户要把候选项目源码直接下载到工作区，供后续 `cargo metadata`、CPG 或静态规则分析使用。
- 用户要复用“寻找可用漏洞项目”的筛选模板，但不想每次重新解释规则。

## 工作流

1. 先建立排除集。
   - 扫描当前工作区已有的 `cases/`、`docs/`、已下载源码目录、旧候选汇总、分析状态目录。
   - 提取已检测项目名、版本、漏洞线。
   - 任何已出现的项目默认排除；同一项目的邻近版本也默认排除，除非用户明确允许重测。

2. 再读规则模板。
   - 如果当前仓库里有 `寻找可用漏洞项目的Agent任务模板.md`，优先读它。
   - 如果没有，读取 `references/selection-template.md`。

3. 搜索新候选时，只保留真实项目。
   - 需要真实 Rust 项目、明确的 native 依赖链、可解释的 sink/guard。
   - 优先文件解析、解码、解压、parser、builder、CLI、小型服务。
   - 避开只证明“依赖存在”、但无法解释路径和触发条件的项目。

4. 对每个候选做强制核对。
   - 依赖链：`root -> crate -> sys/ffi -> native`
   - 版本证据：`Cargo.toml`、`Cargo.lock`、build.rs、vendor、发布说明
   - 构建条件：默认 feature、可选 feature、platform guard、vendored/system
   - Rust 侧证据：source、sink、输入对象、builder flag、API 序列
   - 排除集比对：确认该项目此前未被检测

5. 每次都下载精确版本源码。
   - 保存根目录固定带当天日期目录，日期格式用本机当天的 `YYYY.M.D`，例如 `2026.3.17`
   - 如果用户没有额外指定目录，保存路径用 `当前日期目录/<project-name-version>/upstream`
   - 如果用户明确指定了目标目录，则把它视为父目录，实际保存路径用 `目标目录/当前日期目录/<project-name-version>/upstream`
   - 附带简短清单文件，记录项目名、版本、来源 URL
   - 临时脚本和调试文件在任务结束前删除

## 交付要求

- 必须显式说明排除集来自哪里。
- 必须把“为何它是新项目、不是旧项目重复项”写清楚。
- 必须给出版本证据、关键 Rust 路径、触发条件、推荐结论。
- 必须显式说明当天日期目录名，以及它是如何映射到最终保存根目录的。
- 必须把每个候选项目的源码下载到带当天日期的结果目录，且结果目录不能堆在根目录。
- 每个项目统一保存为 `当前日期目录/<project-name-version>/upstream`，或在用户给定父目录时保存为 `目标目录/当前日期目录/<project-name-version>/upstream`。

## 参考文件

- `references/selection-template.md`
  - 需要完整筛选规则、输出结构、硬性要求时读取。
