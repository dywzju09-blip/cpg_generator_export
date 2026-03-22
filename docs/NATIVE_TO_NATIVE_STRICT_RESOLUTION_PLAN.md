# Native-to-Native 严格解析实现计划

## 1. 目标

当前系统已经支持：

- Rust 到 native 组件的 reachability / triggerability 分析
- provider-based native 自动补源
- 基于源码证据的递归 native dependency expansion

但还没有做到“严格 native-to-native 调用解析”。

本计划的目标是把当前：

- `源码 token / header / build script / pkg-config` 级别的间接依赖推断

升级为：

- `真实外部调用点 -> 外部符号 -> 导出组件 -> 导出函数`

的严格解析链。

本计划明确限定：

- **先支持 Linux**
- 优先支持 **shared library / system library / pkg-config** 路径
- 组件优先级：
  - `openssl`
  - `libxml2`
  - `zlib`
  - `expat`
  - `libwebp`

## 2. 当前状态

当前代码里已经有 3 个相关基础：

1. provider-based 自动补源  
   见 [native_source_providers.py](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/fetch/native_source_providers.py)

2. 导入目标 native 组件 C CPG，并建立 `NATIVE_DEPENDS_ON / NATIVE_CALL`  
   见 [supplychain_analyze.py](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/supplychain_analyze.py#L515)

3. 基于源码扫描的递归 native 扩展  
   见 [supplychain_analyze.py](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/supplychain_analyze.py#L660)

当前问题是：

- `NATIVE_DEPENDS_ON` 主要还是由源码 token/source scan 产生
- `NATIVE_CALL` 依赖已导入 C 图中按名字连出的边
- 没有统一的“外部符号解析层”

所以现在还不能称为严格的 native-to-native 调用解析。

## 3. 严格版本应达到什么标准

一个 `native A -> native B` 调用边要成立，至少要满足下面 4 步中的 3 步，且第 2 步必须成立：

1. 在 A 的源码或构建环境中观测到对外部库的链接证据
2. 在 A 的调用点或二进制导入符号中，观测到外部符号 `sym`
3. 在 B 的导出符号集中，确认 `sym` 由 B 提供
4. 在 B 的源码图中，能把 `sym` 对应到某个 `METHOD:C`

最终图上应出现：

- `CALL:C(A) -[:RESOLVES_EXTERN_TO]-> EXPORTED_SYMBOL(sym)`
- `EXPORTED_SYMBOL(sym) -[:PROVIDED_BY]-> PACKAGE(B)`
- 若源码方法可见：
  - `EXPORTED_SYMBOL(sym) -[:RESOLVES_TO]-> METHOD:C(B::sym)`
- `PACKAGE(A) -[:NATIVE_CALL]-> PACKAGE(B)`

## 4. 三阶段实施方案

### 阶段一：符号级严格解析

目标：

- 先把“外部符号是谁提供的”做严格
- 不要求一开始就做到方法级解析

#### 4.1 新增模块

新增文件：

- [tools/fetch/native_symbol_resolver.py](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/fetch/native_symbol_resolver.py)

建议职责：

- `find_component_binaries(...)`
- `collect_binary_exports(...)`
- `collect_binary_imports(...)`
- `build_symbol_provider_index(...)`
- `resolve_imported_symbol(...)`

#### 4.2 Linux 下的命令来源

优先使用：

- `pkg-config --libs --static <name>`
- `pkg-config --variable=libdir <name>`
- `ldconfig -p`
- `readelf -Ws`
- `nm -D --defined-only`
- `objdump -T`
- `ldd`

规则：

- `exports` 以 `readelf -Ws` 和 `nm -D` 为主
- `imports` 以 `objdump -T` / `readelf -Ws` 中 `UND` 为主
- 动态链接关系以 `ldd` 和 `pkg-config` 辅助

#### 4.3 图模型扩展

建议新增节点：

- `:BINARY`
- `:EXPORTED_SYMBOL`
- `:IMPORTED_SYMBOL`

建议新增关系：

- `PACKAGE -[:OWNS_BINARY]-> BINARY`
- `BINARY -[:EXPORTS]-> EXPORTED_SYMBOL`
- `BINARY -[:IMPORTS]-> IMPORTED_SYMBOL`
- `EXPORTED_SYMBOL -[:PROVIDED_BY]-> PACKAGE`
- `IMPORTED_SYMBOL -[:NEEDS_PROVIDER]-> PACKAGE`

#### 4.4 报告字段

建议新增：

- `binary_resolution`
- `strict_native_dep_edges`
- `ambiguous_symbol_resolutions`
- `binary_artifacts_used`

#### 4.5 验收标准

对 `openssl/libxml2/zlib/expat/libwebp` 中任一项目，能够输出：

- A 导入了哪些外部符号
- 这些符号由哪个组件提供
- 哪些符号解析唯一、哪些不唯一

此阶段做完后：

- `NATIVE_DEPENDS_ON` 不再主要靠 token/source scan
- token/source scan 退为 fallback 证据

### 阶段二：调用点到导出函数的精确映射

目标：

- 把“组件级严格依赖”推进到“调用点级解析”

#### 4.6 新增模块

建议新增文件：

- [tools/neo4j/link_native_externals.py](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/neo4j/link_native_externals.py)

职责：

- 从导入的 C 图里找 `CALL:C`
- 判定哪些 call 没有本地 `METHOD:C` 提供
- 用符号提供者索引解析到 `EXPORTED_SYMBOL`
- 如目标组件源码已导入，再尝试解析到 `METHOD:C`

#### 4.7 关键逻辑

对每个 `CALL:C`：

1. 先检查当前 package 内是否已有同名 `METHOD:C`
2. 若无，则视为外部候选调用
3. 使用“组件链接上下文 + imported symbol + exported symbol”做解析
4. 若唯一命中：
   - 建 `CALL:C -[:RESOLVES_EXTERN_TO]-> EXPORTED_SYMBOL`
   - 建 `PACKAGE(A) -[:NATIVE_CALL]-> PACKAGE(B)`
5. 若多命中：
   - 标记 `ambiguous_external_resolution`
   - 不作为强证据

#### 4.8 必须解决的歧义

重点处理：

- 同名函数在多个库同时出现
- 本地静态函数与外部导出函数同名
- `inline/static inline` 导致源码有声明无导出
- 宏包装函数

#### 4.9 验收标准

至少在一个带间接依赖的验证样例上实现：

- `compA -> imported symbol`
- `imported symbol -> provider package`
- `provider package -> METHOD:C`

最终形成真实的 `NATIVE_CALL`

### 阶段三：链接上下文约束与严格结论门槛

目标：

- 让严格解析真正进入最终 exploitability 结论

#### 4.10 链接上下文建模

需要统一收集：

- `build.rs` 中的 `cargo:rustc-link-lib`
- `cargo:rustc-link-search`
- `pkg-config --libs`
- `pkg-config --cflags`
- 构建产物的 `ldd`
- 若存在 `.pc` 文件，也要解析 `Requires` / `Libs`

建议新增字段：

- `linked_libraries`
- `search_paths`
- `link_mode`
- `binary_resolution_confidence`

#### 4.11 结论门槛收紧

引入 `strict_native_resolution_status`：

- `none`
- `component_level`
- `symbol_level`
- `callsite_level`

结论规则建议：

- 若漏洞家族依赖 native 内部语义，且 `strict_native_resolution_status < symbol_level`
  - 最高只能到 `possible`
- 若能达到 `callsite_level`
  - 才允许给高置信 `confirmed`

#### 4.12 验收标准

至少对 3 个 family 做对照实验：

- `libxml2`
- `zlib`
- `expat` 或 `openssl`

需要报告：

- 严格解析前后的结论变化
- 误报是否下降
- 运行时间增加多少

## 5. 路径迁移与根目录硬编码整改

为了保证迁移到 Linux 服务器后不出现“文件不存在”，实现这三阶段时必须同步整改路径问题。

### 5.1 原则

- 代码逻辑中禁止依赖固定根目录，如：
  - `/Users/...`
  - `/home/...`
  - `Desktop/VUL`
- 所有项目路径、缓存路径、归档路径都必须：
  - 从参数传入
  - 或从环境变量推导
  - 或相对 `REPO_ROOT` 解析

### 5.2 当前需要优先改的地方

1. [tools/deploy/package_for_linux.py](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/deploy/package_for_linux.py)  
   当前 `DEFAULT_VUL_ROOT` 仍是固定路径，必须改成：
   - 环境变量优先
   - 当前工作区相对路径回退

2. [tools/supplychain/archive_analysis_run.py](/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/archive_analysis_run.py)  
   虽然已经支持环境变量，但默认值仍保留本机路径；要进一步统一到“无环境变量时相对 `cwd` 或 `SUPPLYCHAIN_VUL_ROOT` 推导”。

3. 文档中的旧绝对路径  
   例如一些 `docs/*.md` 里的 `examples/...`、`/Users/...` 路径，不能再作为运行说明依据。

### 5.3 实现约束

在三阶段实现中，新增代码必须遵守：

- 缓存目录：
  - 从 `--native-source-cache-dir` 或 `report_dir` 推导
- 二进制缓存：
  - 放到 `cache_root/binary_index/`
- 运行输出：
  - 仅放在 `report_dir` 或 `VUL` 归档目录
- provider 不得写死本机路径

## 6. 具体文件改造建议

### 阶段一涉及

- 新增：
  - `tools/fetch/native_symbol_resolver.py`
- 修改：
  - `tools/fetch/native_source_providers.py`
  - `tools/fetch/native_source_resolver.py`
  - `tools/supplychain/supplychain_analyze.py`
  - `tools/supplychain/auto_extras.py`

### 阶段二涉及

- 新增：
  - `tools/neo4j/link_native_externals.py`
- 修改：
  - `tools/neo4j/import_cpg.py`
  - `tools/supplychain/supplychain_analyze.py`

### 阶段三涉及

- 修改：
  - `tools/supplychain/supplychain_analyze.py`
  - `tools/supplychain/run_manifest_analysis.py`
  - `tools/supplychain/archive_analysis_run.py`
  - `tools/deploy/package_for_linux.py`

## 7. 风险评估

### 7.1 技术风险

- 大型 native 组件导出的 symbol 数量很多，索引构建和 Neo4j 导入会膨胀
- 同名导出符号可能导致歧义解析
- 某些系统库在不同 Linux 发行版下的包名、`.pc` 名、SO 名并不完全一致

### 7.2 工程风险

- 如果一开始就同时支持 Linux/macOS，会明显拖慢进度
- 如果一开始就试图覆盖所有 native 组件，会导致 provider 设计过早复杂化

## 8. 推荐落地顺序

### 第一周

- 完成 Linux symbol resolver
- 支持 `readelf/nm/objdump/ldd/pkg-config`
- 把 `EXPORTED_SYMBOL / IMPORTED_SYMBOL / BINARY` 基础索引做出来

### 第二周

- 接入 `supplychain_analyze.py`
- 让 `NATIVE_DEPENDS_ON` 优先来源于 strict symbol resolution
- 保留 token/source scan 作为 fallback

### 第三周到第四周

- 做调用点级 `RESOLVES_EXTERN_TO`
- 建立 callsite-level `NATIVE_CALL`
- 加入严格结论门槛

### 第五周

- 跑 `libxml2 / zlib / expat / openssl`
- 输出补源前后与严格解析前后的对照实验

## 9. 最终目标

三阶段做完后，系统应能较有底气地声称：

> 对 Linux 下的 Rust-native 项目，工具不仅能自动补源码，还能基于真实外部符号解析，将目标 native 组件及其关键 native 间接依赖纳入同一调用与依赖图中，并据此更谨慎地判断漏洞 exploitability。

这时，“native-to-native 严格解析”才真正从工程雏形变成论文级创新点。
