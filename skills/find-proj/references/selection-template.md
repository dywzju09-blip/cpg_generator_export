# 找新项目漏洞候选模板

这份参考是从“寻找可用漏洞项目的 Agent 任务模板”抽出的可复用规则，专门给 `find-proj` skill 用。

## 1. 核心目标

寻找适合接入静态分析工具的：

- Rust 真实项目
- 已知 CVE
- native 组件依赖链

输出重点不是“找最多”，而是：

- 更容易形成静态规则
- 更容易解释为什么可达/可触发
- 更适合后续人工补最小复现

## 2. 最高优先级硬规则

### 2.1 必须是新项目

- 候选项目必须是当前工作目录里还不存在的项目。
- 只要当前目录中已经出现过：
  - 项目源码目录
  - `cases/` 归档
  - `docs/` 候选记录
  - 分析状态目录
  - 其他能证明“这个项目以前已经跑过”的文档
  就视为“已检测过”。
- 同一项目换一个相近版本，默认仍算重复，不推荐。

### 2.2 必须能进入当前工具工作流

- 能明确依赖链：`root -> crate -> sys/ffi -> native`
- 最好能运行 `cargo metadata`
- 最好能恢复 CPG 所需入口
- 必须指出至少一个 Rust 侧高价值 sink/wrapper/entry
- 必须能描述触发条件

### 2.3 每次都必须落源码

- 只要推荐为候选，就必须下载该项目的精确版本源码。
- 保存根目录必须带本机当天日期目录，格式 `YYYY.M.D`，例如 `2026.3.17`
- 如果用户没有额外指定目录，源码保存路径固定为：`当前日期目录/<project-name-version>/upstream`
- 如果用户明确指定了目标目录，则实际保存路径固定为：`目标目录/当前日期目录/<project-name-version>/upstream`
- 不允许只给链接、不落本地源码。
- 如果源码无法下载或版本无法精确定位，该候选默认降级或淘汰。

## 3. 项目偏好

优先：

- `*-sys`、FFI、bundled、vendored
- 文件解析、图片/视频解码、解压、parser、builder、数据库、revision parser
- CLI、小型服务、单功能处理器
- 输入对象简单：文件字节流、pattern、XML、SQL、archive、image、NAL、revspec

降级或过滤：

- 只有系统库，版本拿不到
- feature 是否启用确认不了
- 只有 README 说依赖，但源码找不到调用
- 只能靠远端环境、竞态、外设、在线协商才能成立
- Rust 侧看不到任何前置条件

## 4. 搜索顺序

### 第零步：建立排除集

先扫描当前工作区已有内容：

- `cases/`
- `docs/`
- 已下载源码目录
- 历史候选汇总
- 分析状态目录

整理出：

- 已检测项目名
- 已检测项目版本
- 已检测漏洞线

### 第一步：先找漏洞组件

优先找：

- 有明确 CVE
- 有明确受影响版本和修复版本
- 有可解释触发条件

常见方向：

- `zlib`
- `libwebp`
- `libgit2`
- `pcre2`
- `sqlite`
- `openssl`
- `libxml2`
- `expat`
- `libarchive`
- 图像/解码/压缩/解析器类 native 组件

### 第二步：再找真实 Rust 项目

优先找：

- crates.io / GitHub 上有真实发布版本
- 存在 `Cargo.toml`，最好有 `Cargo.lock`
- 不是只含最小 PoC 的实验仓库
- 路径里能看到文件/字节流/字符串进入 native wrapper

### 第三步：核对是否适合工具

至少确认：

- 依赖链是否明确
- Rust CPG 是否大概率可生成
- Rust 侧是否存在清晰 sink
- 触发条件是否至少有一部分能在 Rust 侧看见
- 能否解释成“版本 + 路径 + 守卫”

### 第四步：强制核对构建条件

必须确认：

- 默认构建是否真的启用漏洞路径
- 是否需要额外 feature / target / profile
- 是否有 JIT / 64 位 / vendored / system 之类 guard

### 第五步：评估是否适合后续复现

优先保留：

- 容易补 harness
- 容易给 benign 输入回放
- 容易解释输入对象和 sink 关系

## 5. 每个候选至少要交付什么

- 项目名称
- 仓库地址
- 具体版本 / tag / commit
- 本地源码目录：`当前日期目录/<project-name-version>/upstream`，或在用户给定父目录时为 `目标目录/当前日期目录/<project-name-version>/upstream`
- 组件名称
- CVE
- 漏洞后果
- Rust 依赖链
- bundled / vendored / system 判断
- 实际锁定版本
- 默认构建是否启用
- 关键 Rust 函数 / sink / wrapper
- 触发条件拆解
- 守卫分类：
  - `version guard`
  - `feature/build guard`
  - `API sequence guard`
  - `mode/flag guard`
  - `input-shape guard`
  - `environment/runtime guard`
- 适配结论：
  - **强烈推荐**
  - **可做但需要补能力**
  - **不推荐**

## 6. 输出格式

先给总表，再给详情。

总表至少包含：

- 项目
- CVE
- native 组件
- 漏洞后果
- 版本是否可确认
- Rust sink 是否清晰
- CPG 是否大概率可生成
- 触发条件是否适合静态规则
- 推荐等级

详情至少包含：

1. 项目简介
2. 漏洞简介
3. 依赖链与版本证据
4. 本地源码保存位置
5. Rust 侧关键路径
6. 触发条件
7. 守卫分类
8. 适配性判断
9. 最终结论
