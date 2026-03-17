# Linux 迁移与运行

## 目标

把本地采集的项目和 `cpg_generator_export` 工具一起打包，迁移到 Linux 服务器后直接运行检测和归档，不依赖 macOS 绝对路径。

## 推荐方案

推荐用“两段式”：

1. 本地打包一个 bundle  
2. Linux 服务器执行初始化，再跑批量分析

这样比手工复制目录更稳，主要原因是：

- 当前工具依赖 Rust、Python、Java、Joern、Neo4j 和 native 构建链
- 服务器路径通常和本机不同
- 归档脚本和批跑脚本需要统一的 `VUL` 根目录

## 现在已经便携化的点

- `generate_cpgs.sh` 改成了 `bash`，可直接在 Linux 跑
- Neo4j 连接可通过环境变量配置：
  - `CPG_NEO4J_URI`
  - `CPG_NEO4J_USER`
  - `CPG_NEO4J_PASSWORD`
- 归档根目录可通过环境变量配置：
  - `SUPPLYCHAIN_VUL_ROOT`
  - `SUPPLYCHAIN_ARCHIVE_ROOT`

## 本地打包

示例：把工具和 `VUL/316`、`VUL/2026.3.17` 一起打包。

```bash
cd /Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export

python3 tools/deploy/package_for_linux.py \
  --bundle-root /tmp/cpg_linux_bundle \
  --archive /tmp/cpg_linux_bundle.tar.gz \
  --include /Users/dingyanwen/Desktop/VUL/316 \
  --include /Users/dingyanwen/Desktop/VUL/2026.3.17
```

产物：

- `/tmp/cpg_linux_bundle/`
- `/tmp/cpg_linux_bundle.tar.gz`

bundle 结构：

```text
cpg_linux_bundle/
├── BUNDLE_MANIFEST.json
├── cpg_generator_export/
└── VUL/
```

## Linux 服务器初始化

先上传 bundle：

```bash
scp /tmp/cpg_linux_bundle.tar.gz user@server:/data/
ssh user@server
cd /data
tar -xzf cpg_linux_bundle.tar.gz
```

执行初始化：

```bash
cd /data/cpg_linux_bundle/cpg_generator_export
bash tools/deploy/bootstrap_linux.sh /data/cpg_linux_bundle
```

这个脚本会安装：

- Python 3 / pip
- Rust / nightly
- Java 17
- clang / cmake / pkg-config / zlib / OpenSSL 头文件
- `neo4j` Python 驱动

如果服务器用 Docker 跑 Neo4j，建议单独启动一个 `neo4j:5` 容器，然后设置环境变量。

## 运行分析

假设你已经在 bundle 里的 `VUL` 目录准备好了 manifest：

```bash
export CPG_NEO4J_URI=bolt://127.0.0.1:7687
export CPG_NEO4J_USER=neo4j
export CPG_NEO4J_PASSWORD=password

cd /data/cpg_linux_bundle/cpg_generator_export

bash tools/deploy/run_analysis_bundle.sh \
  /data/cpg_linux_bundle \
  /data/cpg_linux_bundle/VUL/2026.3.17/analysis-manifest.json \
  2026_03_17_linux
```

分析结束后，结果会直接归档到：

- `/data/cpg_linux_bundle/VUL/cases/by-analysis-status`

不会要求你再去 `output/vulnerability_runs` 手动搬运。

## 最适合搬到 Linux 的场景

这些场景在 Linux 上通常比 macOS 更容易复现：

- 依赖 Linux 头文件或系统库
- 需要 `asan` / sanitizer
- 需要真实 native 构建链
- 需要更贴近目标发行版的系统组件版本

## 建议的迁移策略

优先把下面几类项目打包到 Linux：

- 你已经静态判成 `confirmed` 或 `possible` 的项目
- macOS 上因为系统库缺失、头文件缺失、feature/build 差异失败的项目
- 需要人工复现 native 崩溃或控制台触发的项目

不建议一开始就把全部历史样本一次性搬过去。更稳的是：

1. 先搬一个批次
2. 在 Linux 验证环境和归档流程
3. 再扩大规模

## 结论

最方便的方式不是“直接 rsync 整个桌面目录”，而是：

1. 用 `package_for_linux.py` 做干净 bundle
2. 用 `bootstrap_linux.sh` 补服务器环境
3. 用 `run_analysis_bundle.sh` 直接跑 manifest

这样你的工具、项目、归档目录和结果路径在 Linux 上都是可重复的。
