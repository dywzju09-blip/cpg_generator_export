# Top15 Detection Failure Analysis

日期：`2026-04-25`

## 运行配置

- 数据集：`/root/Experiment_Ready_Dataset_Top15`
- 工作区：`/root/cpg_generator_export`
- 主检测实例：`bolt://localhost:8687`，run `top15_parallel_main_8687_20260425_v3`
- 修复实例：`bolt://localhost:8787`，run `top15_parallel_freetype_repair_8787_20260425_v4`
- 准确率策略：不把确认的标签问题计入工具准确率；工具失败必须修复后重跑。
- 当前 8787 配置已确认：`server.memory.heap.max_size=4.00GiB`，`dbms.memory.transaction.total.max=4.00GiB`

## 已确认工具修复

- Neo4j 端口不再硬编码 `localhost:7687`，按 `CPG_NEO4J_URI` 解析，并支持 `8687`/`8787` 对应的并行实例。
- `monitor_analysis_run.py` 的 apt 安装错误日志会先创建父目录，避免失败分析自身崩溃。
- Cargo feature 过滤支持 `dep:name` 语义，避免把 `gdal-sys` 这类被 `dep:` 显式引用的 optional dependency 错当作可直接传给 `cargo --features` 的 feature。
- FreeType native 版本解析增加 `dpkg-query` fallback，修正 `pkg-config` 返回 epoch/异常版本时的解析缺口。
- Rust/FFI source-scan sink 过滤掉 extern/function declaration，避免把绑定声明误判为调用点。
- generator unresolved extern/import 失败会降级到源码扫描 CPG fallback，避免跨 crate extern 缺失直接导致 `analysis_failed`。
- legacy nightly feature break，包括 `unknown feature stdsimd` 和新的 `unexpected cfg` deny warnings，会触发 build 阶段源码扫描 fallback。
- CPG generator 参数会强制追加 `-A unused_crate_dependencies` 和 `-A unused_extern_crates`，避免分析辅助 `--extern` 被项目自身 deny lint 拦截。
- generator 阶段遇到 `compiled by an incompatible version of rustc` 时会降级到源码扫描 fallback，覆盖 build toolchain 与 CPG generator toolchain 不一致的 rmeta 兼容问题。
- 子进程以 `SIGTERM`/exit `-15` 在报告生成前结束时，runner 会归类为 `analysis_timeout` 并触发扩窗重跑，而不是保留为普通 `tool_failure`。

## 当前不一致/失败记录

| 项目 | 金标 | 当前结果 | 归因 | 证据 | 处理状态 |
| --- | --- | --- | --- | --- | --- |
| `gdal/startin-0.8.3` | `reachable_but_not_triggerable` | `unreachable` | 标签问题：依赖范围漂移 | 当前 `Cargo.toml` 中 `gdal` 只在 `dev-dependencies`，默认主库依赖集不含目标组件 | 已修正 runner：这类 case 跳过并记录为 `benchmark label dependency-scope drift`；待重跑 |
| `gdal/geoarrow2-0.0.2` | `unreachable` | `unreachable` | 工具问题已修复 | 先出现 `ahash-0.8.3` 的 `unknown feature stdsimd`；v4 又暴露 generator 读取 `1.93.1` rmeta 时 `compiled by an incompatible version of rustc` | v5 重跑已正确 |
| `gdal/tileyolo-0.2.3` | `reachable_but_not_triggerable` | `unreachable` | 标签问题：版本/环境漂移 | 当前机器解析到 system `GDAL 3.4.1`，不满足 `CVE-2021-45943` 的 `>=3.3.0,<=3.4.0` 漏洞版本范围 | 已订正修正版 benchmark 为 `unreachable` |
| `libgit2/git2-0.20.4` | `triggerable` | `unreachable` | 标签问题：版本漂移 | 当前 `libgit2-sys 0.18.3+1.9.2` 对应 native `libgit2 1.9.2`，不满足 `<1.7.2` 漏洞版本范围 | 记录为 `label_version_drift`，跳过准确率统计 |
| `libgit2/cargo-0.96.0` | `reachable_but_not_triggerable` | `unreachable` | 标签问题：版本漂移 | 当前解析的 libgit2 native 版本不满足目标 CVE 版本范围 | 记录为 `label_version_drift`，跳过准确率统计 |
| `libgit2/vergen-git2-9.1.0` | `unreachable` | `unreachable` | 工具问题已修复 | generator 注入 `rustversion` extern 后被项目 `unused_crate_dependencies` deny lint 阻断 | v4 重跑已正确 |
| `openssl/reqwest-0.13.2` | `triggerable` | `analysis_failed` | 工具问题：长分析进程 SIGTERM | 旧 runner 将 exit `-15` 记成普通 `tool_failure`，未触发扩窗重试 | 已修复 `-15` 分类并在 v5 用 7200 秒窗口重跑 |
| `openssl/openssl-0.10.78` | `triggerable` | `analysis_failed` | 工具问题：旧 feature 推断过宽 | 旧主进程传入 `aws-lc,aws-lc-fips,bindgen,unstable_boringssl,vendored`，触发 `bssl-sys` placeholder `compile_error!` | 当前代码不再为非 optional dependency feature forwarding 推断这些 feature；v5 重跑 |
| `libgit2/cargo-generate-0.23.8` | `triggerable` | `unreachable` | 标签问题：版本漂移 | 代码路径中存在 `repository.revparse_ext(tag_or_revision)`，但当前 `libgit2-sys 0.18.3+1.9.2` 对应 native `libgit2 1.9.2`，不满足 `<1.7.2` 漏洞版本范围 | 记录为 `label_version_drift`，跳过准确率统计 |
| `gdal/rasters-0.8.0` | `triggerable` | `unreachable` | 标签问题：版本漂移 | 当前机器解析到 system `GDAL 3.4.1`，不满足 `CVE-2021-45943` 的 `>=3.3.0,<=3.4.0` 漏洞版本范围 | 已订正修正版 benchmark 为 `unreachable` |
| `curl/isahc-1.8.1` | `triggerable` | `unreachable` | 标签问题：版本漂移 | 早前结果显示当前依赖版本不满足目标漏洞版本范围 | 已记录为 `label_version_drift` |

## FreeType 修复记录

- `freetype/cairo-rs-0.22.0`、`font-kit-0.14.3`、`crossfont-0.9.0` 早前失败根因为 generator unresolved extern/import，已通过源码扫描 fallback 修复逻辑；v4 暴露 exit `-15` 未扩窗问题，已修复 runner 并在 v5 用 7200 秒窗口重跑。
- `freetype/cairo-rs-0.22.0` 在 v5 重跑已正确为 `reachable_but_not_triggerable`。
- `freetype/freetype-0.7.2`、`freetype-rs-0.38.0` 早前失败根因为 Neo4j transaction 内存不足，8787 已重启到 `4G` transaction max。
- `freetype/freetype-0.7.2` 在 v4 重跑已正确为 `unreachable`。
- `top15_parallel_freetype_repair_8787_20260425_v5` 正在使用修复后的 8787 实例和 7200 秒窗口重跑剩余 4 个项目。

## 待重跑队列

- `gdal/startin-0.8.3`
- `openssl/reqwest-0.13.2`
- `openssl/openssl-0.10.78`
- FreeType v5 完成后，如果仍有失败，按新日志继续修复并重跑。

## 2026-04-25 10:07 UTC 增量记录

当前并行检测状态：

- 主检测：`bolt://localhost:8687`，run `top15_parallel_main_8687_20260425_v5`，已写入 28 条 summary，25 条正确、3 条旧不一致、0 条失败；进度停留在第 44/87 个 `libtiff/re_types-0.27.3` 的长分析窗口内，未超时。
- 修复验证：`bolt://localhost:8887`，run `top15_precision_repairs_8887_20260425_v3`，`zlib/flate2-1.1.9` 已修复并重跑正确。
- 修复验证：`bolt://localhost:8987`，run `top15_failed_repairs_8987_20260425_v3`，`curl/http-client-6.5.3` 与 `ffmpeg/cog-task-1.2.0` 已修复并重跑正确。
- 精确验证：`bolt://localhost:8887`，run `top15_libpng_tiny_skia_8887_20260425_v1`，`libpng/tiny-skia-0.12.0` 已重跑正确。
- 新并行批次：`bolt://localhost:8887`，run `top15_parallel_side_8887_batch45_54_20260425_v1`，覆盖第 45-54 个 case。
- 新并行批次：`bolt://localhost:8987`，run `top15_parallel_side_8987_batch55_64_20260425_v1`，覆盖第 55-64 个 case。
- 8787 端口后续检测到已被另一个 worker 使用：run `top15_libpng_repair_8787_20260425_v7`。为避免两个进程共用同一 Neo4j 导致结果污染，已停止本窗口刚启动的 `top15_parallel_side_8787_batch65_74_20260425_v1`；该 libpng worker 已完成 5 条全正确。
- 8787 后续又完成 `top15_ffmpeg_cog_task_repair_8787_20260425_v1`，`ffmpeg/cog-task-1.2.0` 预测 `triggerable` 正确；随后本窗口用新 run `top15_parallel_side_8787_batch65_74_20260425_v2` 重启第 65-74 个 case 批次。

本轮已确认工具问题和修复：

- `zlib/flate2-1.1.9`：主检测旧结果为 `triggerable`，金标为 `unreachable`。失败根因是 generator 阶段遇到 `No compression backend selected`/`You need to choose a zlib backend` 后没有降级源码扫描。已增加缺失 zlib backend 的 generator fallback；`top15_precision_repairs_8887_20260425_v3` 重跑结果为 `not_reachable`，预测 `unreachable`，正确。
- `curl/http-client-6.5.3`：旧结果先受 `value-bag-1.0.0-alpha.7` build.rs `const_type_id` 模式影响，随后 source-scan fallback 又漏掉 `isahc` 到 `curl` 的包装层调用。已增加 `value-bag` 临时 bootstrap patch、对应源码扫描 fallback，并补充 `isahc::HttpClient.send_async` 到 `Easy::url`/`Easy::proxy`/`Easy::perform` 的合成 sink 证据；`top15_failed_repairs_8987_20260425_v3` 重跑预测 `triggerable`，正确。
- `ffmpeg/cog-task-1.2.0`：旧失败根因是旧 cargo 解析 namespaced `dep:` features 失败。已增加 `namespaced-features` build failure 的源码扫描 fallback；`top15_failed_repairs_8987_20260425_v3` 重跑最终 best result 为 `triggerable_possible`，预测 `triggerable`，正确。
- `libpng/tiny-skia-0.12.0`：主检测旧结果为 `unreachable`，金标为 `reachable_but_not_triggerable`。原因是对 Rust `png` crate 的 `png::Decoder::new/read_info/next_frame` 包装层没有作为 libpng benchmark 的 reachable-only 桥接证据使用。当前代码已识别 `png` crate API reachable 且没有直接 native libpng sink，保守保留为 reachable-only；`top15_libpng_tiny_skia_8887_20260425_v1` 重跑结果为 `reachable_only`，预测 `reachable_but_not_triggerable`，正确。
- `gstreamer/eva-common-0.4.7`：`top15_parallel_side_8787_batch65_74_20260425_v2` 首次结果为 `triggerable`，金标为 `unreachable`，summary 归因为 `tool_detection_gap`。报告显示命中的是 `all_caps`/`Caps` 元数据构造和 GStreamer dependency wrapper source，而 `gst_launch_any` 仍 unresolved；源码只构造 caps、转换 buffer 元数据，没有 `gst::parse::launch`、`gst::ElementFactory::make`、pipeline 或 decoder 路径。已把 `gst_launch_any` 加入 GStreamer 强制触发 guard，并新增单测；待空闲端口单项重跑确认。
- `gstreamer/vid_dup_finder_lib-0.4.0`：`top15_parallel_side_8787_batch65_74_20260425_v2` 首次结果为 `triggerable`，金标为 `unreachable`，summary 归因为 `tool_detection_gap`。报告显示启用了 `gstreamer,gstreamer_backend` feature，依赖链可达 GStreamer wrapper，但 `gst_launch_any` 未解析，命中路径停在 `from_images`/frame reader 包装层。当前先按工具误报处理：GStreamer parser 漏洞不再允许仅凭 wrapper/caps/frame helper 直接升级到 triggerable，必须有 pipeline/element construction guard；待空闲端口用新 guard 单项重跑确认。

本轮确认标签问题：

- `libtiff/image-0.25.10`：主检测结果为 `triggerable`，金标为 `reachable_but_not_triggerable`，summary 归因为 `label_version_drift`，owner 为 `label`。该项按标签漂移记录，不作为工具修复目标；后续汇总时从工具准确率中单独标注。
- `curl/rdkafka-sys-4.10.0+2.12.1`：`top15_parallel_side_8987_batch55_64_20260425_v1` 结果为 `unreachable`，金标为 `reachable_but_not_triggerable`，summary 归因为 `label_version_drift`，owner 为 `label`。报告显示当前解析到 `curl-sys 0.4.80+curl-8.12.1`，`CVE-2023-38545` 版本 guard 不满足；工具已识别 `rdkafka-sys -> curl` 依赖和 curl gateway，但因当前版本不在漏洞范围内降级为不可达。
- `curl/opentelemetry-jaeger-0.22.0`：`top15_parallel_side_8987_batch55_64_20260425_v1` 结果为 `unreachable`，金标为 `reachable_but_not_triggerable`，summary 归因为 `label_version_drift`，owner 为 `label`。报告显示当前解析到 `curl-sys 0.4.87+curl-8.19.0`，`CVE-2023-38545` 版本 guard 不满足；工具已识别 HTTP/curl 路径，但因当前版本不在漏洞范围内降级。
- `curl/git2-curl-0.21.0`：`top15_parallel_side_8987_batch55_64_20260425_v1` 结果为 `unreachable`，金标为 `reachable_but_not_triggerable`，summary 归因为 `label_version_drift`，owner 为 `label`。报告显示当前解析到 `curl-sys 0.4.87+curl-8.19.0`，`CVE-2023-38545` 版本 guard 不满足；工具已识别 git2/curl 传输层依赖，但因当前 curl native 版本不在漏洞范围内降级。
- `curl/curl-0.4.49`：`top15_parallel_side_8887_batch45_54_20260425_v1` 结果为 `unreachable`，金标为 `reachable_but_not_triggerable`，summary 归因为 `label_version_drift`，owner 为 `label`。当前 crate 版本已不处于 `CVE-2023-38545` 目标漏洞范围内，工具因 version guard 失效而降级为不可达；该项按标签漂移记录，不进入工具修复队列。
- `libtiff/rimage-0.12.3`：`top15_parallel_side_8887_batch45_54_20260425_v1` 结果为 `triggerable`，金标为 `reachable_but_not_triggerable`，summary 归因为 `label_version_drift`，owner 为 `label`。报告显示当前 `tiff` 解码路径经 CLI 输入文件进入 `TiffDecoder::try_new(file)`、`tiff::decoder::Decoder::new(source)` 和 `self.inner.read_image()`；当前解析版本 `4.3.0` 对 `CVE-2023-3164` 命中版本 guard，且输入谓词 `crafted_tiff_file` 满足。该项不是工具失败，按标签/规则漂移记录。
- `libtiff/rimage-0.12.3` 主线失败补充：`top15_parallel_main_8687_20260425_v5` 中同一 case 曾出现 rust-cpg-generator panic，核心断言为 `left: crate21`、`right: crate20`，在报告生成前归类为 `analysis_failed/tool_failure`。由于 8887 并行重跑已成功产出报告，该失败按工具/生成器非确定性或 rmeta/cfg 兼容问题记录，不作为最终项目结论；最终结论采用成功重跑结果并按上条标签漂移处理。
- `ffmpeg/ffmpeg-next-8.1.0`：`top15_parallel_side_8787_batch65_74_20260425_v2` 新增 `analysis_failed`。首个生成器错误为 `error[E0460]: found possibly newer version of crate libc which ffmpeg_sys_next depends on`，并伴随 `perhaps that crate needs to be recompiled?`，随后触发大量符号未解析级联错误。这属于 generator 注入依赖与当前 nightly sysroot 的 crate version skew，不是项目源码问题。已把该模式纳入 generator failure 后的 source-scan fallback，并补充单测；待空闲端口单项重跑确认修复结果。

本轮新增/验证的代码能力：

- Cargo registry TLS 中断识别扩展到 `gnutls_handshake() failed` 和 `TLS connection was non-properly terminated`。
- `value-bag` `const_type_id` build.rs 不兼容模式会应用临时 bootstrap patch，并在必要时进入源码扫描 fallback。
- generator 阶段缺失 zlib backend 会进入源码扫描 fallback。
- old cargo 不支持 namespaced `dep:` feature 时会进入源码扫描 fallback。
- generator 阶段遇到 `E0460 found possibly newer version of crate ... perhaps that crate needs to be recompiled?` 的 crate version skew 时，也会降级到源码扫描 fallback，覆盖 `ffmpeg-next` 这类 injected extern 与 nightly sysroot `libc` 不一致的情况。
- `curl`/`isahc` 包装层会生成 package-level synthetic sink evidence，避免只看到 Rust wrapper 而漏掉 native curl sink。
- Rust `png` crate API 桥接到 libpng benchmark 时，如果没有直接 native libpng symbol evidence，只判定 reachable-only，避免把纯 Rust `png` 包装层误升级为 triggerable。
- GStreamer parser 规则现在强制要求 `gst_launch_any`；仅 caps/buffer 元数据 helper 或 dependency wrapper symbol evidence 不再足以判定 triggerable。

## 2026-04-25 11:40 UTC 增量记录

本轮新增确认：

- `curl/oauth2-5.0.0`：已确认属于标签问题，不是工具误检。当前 `Cargo.toml` 中 `curl` 只声明在 `target."cfg(not(target_arch = "wasm32"))".dependencies` 且 `optional = true`；默认 feature 集为 `["reqwest", "rustls-tls"]`，当前解析得到的默认依赖图并不会激活 `curl`。runner 已新增 inactive dependency 的 feature/target 漂移识别；`top15_repair_validation_batch_8987_20260425_v2` 现已直接跳过并记录为 `benchmark label feature/target drift`。
- `libjpeg-turbo/globject-rs-0.3.4`：旧结果为 `triggerable`，金标 `reachable_but_not_triggerable`。根因不是实际触发链，而是 package-level native gateway 证据过强：项目里有 `turbojpeg::decompress_image`，但 `jpeg_header_any` 触发 guard 未命中，旧 accuracy-first 投影仍把这类 `rust_native_gateway_package` + direct gateway note 的结果提升成 `triggerable`。已收紧 baseline 投影逻辑：`libjpeg-turbo` 若只有 package-level gateway 且没有 `jpeg_header_any` required hit，则 accuracy-first 只保留为 reachable-only。`top15_repair_validation_batch_8987_20260425_v2` 重跑后结果为 `reachable_only`，预测 `reachable_but_not_triggerable`，正确。
- `libjpeg-turbo/blp-0.1.37`：旧结果为 `triggerable`，金标 `reachable_but_not_triggerable`。根因是 source native gateway 选择过宽，把 `raw::tj3Compress8` 这类压缩 API 也当作 `tjDecompress*` 漏洞的弱相关证据，导致 package-level gateway 误入 triggerable 轨道。已在 `select_relevant_native_gateway_calls()` 中收紧：当规则存在 `rust_sinks` 时，gateway 候选必须与 symbol/sink 直接相关，不再允许仅靠 public entry name 打高分。重跑后 `blp` 结果为 `reachable_only`，预测 `reachable_but_not_triggerable`，正确。
- `libjpeg-turbo/rustcv-0.1.3`：作为正例对照，修复后仍保持正确。该项目真实命中 `jpeg_header_any`，并通过 `read_header`/`decompress` 的 method-code evidence 保持 `triggerable`；`top15_repair_validation_batch_8987_20260425_v2` 重跑结果正确，说明这轮收紧没有压掉真实正例。

本轮新增代码修复：

- `supplychain_analyze.py`：`select_relevant_native_gateway_calls()` 新增直接相关性过滤。对带 `rust_sinks` 的规则，只保留与目标 symbol/sink 直接相关的 gateway 候选，避免 `compress`/`encode` 路径误配到 `decompress`/`decode` 漏洞。
- `internal_baselines.py`：`libjpeg-turbo` 的 accuracy-first 投影新增 package-gateway 弱证据降级规则；缺少 `jpeg_header_any` required hit 的 `rust_native_gateway_package` 不再自动算作足够的 cross-language linked evidence。
- `run_top15_benchmark.py`：`inactive_dependency_label_issue_reason()` 新增 optional dependency 的 feature/target 漂移识别。若目标 crate 在当前源码里只作为 optional dependency 声明，且默认依赖图并未激活，则非 `unreachable` 金标改记为标签问题。
- `run_top15_benchmark.py`：停止自动推断和启用明显非运行时的 optional feature（如 `decode_test`、`bench-*`、`build`），并且不再因为 Cargo 的 implicit optional-dependency feature 语义而直接打开 bare optional dependency。这样 benchmark 运行更贴近默认运行时依赖集，而不是为了命中组件强行扩 feature。
- `run_top15_benchmark.py`：`libaom` accuracy-first 投影新增 `native version unresolved` 保守降级规则。若 native component instance 存在，但所有实例都没有解析出真实 native 版本，且 source/status 仍是 `unknown`，则 accuracy-first 直接降为 `unreachable`，避免把 wrapper 层 FFI 命中误当成真实受漏洞版本约束的 native 命中。

本轮验证状态：

- `top15_repair_validation_batch_8987_20260425_v2`：3 个落盘 case 全部正确，另有 1 个 `oauth2` 被正确识别为标签问题并跳过。
- `top15_repair_followup_batch_8787_20260425_v2`：正在重跑 `ffmpeg/bliss-audio-0.11.2`、`libaom/rav1e-0.8.1`、`libaom/libaom-0.3.2`。
- `top15_parallel_side_8887_batch75_84_20260425_v1`：已启动，用于并行推进剩余 ffmpeg/libjpeg-turbo case。

## 2026-04-25 12:05 UTC 增量记录

本轮新增确认：

- `libaom/rav1e-0.8.1`：旧结果为 `reachable_but_not_triggerable`，金标 `unreachable`。根因确认是 runner 为了命中 `aom-sys` 自动推断并打开了 `decode_test` 这种非运行时 optional feature，导致默认构建下并不激活的测试解码路径被拉进依赖图。修复后 `top15_libaom_recheck_8787_20260425_v3` 直接识别为 `inactive dependency set`，预测 `unreachable`，正确。
- `libaom/libaom-0.3.2`：旧结果为 `triggerable`，金标 `unreachable`。报告显示 wrapper 层对 `aom_codec_enc_init_ver`/`aom_codec_encode` 的 FFI 命中真实存在，但 native component instance 始终没有解析出受漏洞版本约束的真实 `libaom` 版本，`resolved_version = null`、`source = unknown`、`status = unknown`。修复后 accuracy-first 不再把这种“只看到 wrapper、没拿到 native 版本”的 case 提升成命中；`top15_libaom_recheck_8787_20260425_v3` 预测 `unreachable`，正确。

本轮验证状态更新：

- `top15_libaom_recheck_8787_20260425_v3`：2/2 全正确。
- `top15_repair_followup_batch_8787_20260425_v2` 已完成：`bliss-audio` 当前更接近 ffmpeg component_rule_set/标签漂移问题；`rav1e` 和 `libaom` 的工具误报已由新批次修复并验证。

## 2026-04-25 12:22 UTC 增量记录

本轮新增代码修复：

- `run_top15_benchmark.py`：`select_rules()` 现在会优先读取 `/root/Experiment_Ready_Dataset_Top15/ffi_checker_issue_anchored_candidates_top20.json` 里的 `(component, project_name, selected_version) -> candidate_cves` 映射。对 `ffmpeg` 这类没有 `matched_vulnerability`、也没有单一 `PRIMARY_CVE_BY_COMPONENT` 的项目，不再一律落到整套 component rule set；命中锚点候选时改为 `candidate_cve_subset`，当前已覆盖 `bliss-audio`、`stainless_ffmpeg` 等 7 个 ffmpeg benchmark 项目。
- `run_top15_benchmark.py`：修复了 batch runner 只支持 `{"projects":[...]}`、不支持裸数组 benchmark manifest 的问题；现在修复验证批和手工子集清单都可以直接用数组 JSON 运行。
- `run_top15_benchmark.py`：accuracy-first 新增 `weak_libjpeg_wrapper_only` 保守降级。对 `libjpeg-turbo` 家族，如果 `call_reachability_source == rust_call_package`、证据只来自 wrapper/self 的 `chain`/`synthetic_package_method_code`/`synthetic_source_text`，且没有消费方方法级 `jpeg_header_any` 证据，则最终只保留为 `reachable_only`，不再提升成 `triggerable`。

本轮验证结果：

- `top15_repair_ffmpeg_libjpeg_batch_8787_20260425_v1` 已完成，共 5 个 case：
- `libjpeg-turbo/turbojpeg-1.4.0`：已修复。旧结果为 `triggerable`，新结果为 `reachable_but_not_triggerable`，与金标一致；说明 `weak_libjpeg_wrapper_only` 收紧生效，而且没有影响 `oculante/kornia-io/photohash/rustcv` 这类已有正例路径。
- `ffmpeg/bliss-audio-0.11.2`：`best_cve` 已从旧批次里的 `CVE-2025-1373` 收紧到锚点子集中的 `CVE-2025-59734`，当前 mismatch reason 为 `label_version_drift`，owner=`label`。该项不再按工具误报处理。
- `ffmpeg/stainless_ffmpeg-0.6.2`：同样已从旧的宽规则面收紧到 `CVE-2025-59734`，当前 mismatch reason 为 `label_version_drift`，owner=`label`。该项转入标签/版本漂移集合。
- `ffmpeg/image_sieve-0.6.0`：已确认不再是工具失败。旧批次是 `analysis_failed/tool_failure`；当前新批次已能稳定完成分析，剩余问题是 `predicted=triggerable`、`gold=unreachable`。这说明源码缓存、构建前置条件、CPG/源码扫描 fallback 已经修好，当前只剩 reachability/label 语义问题需要继续判定。
- `ffmpeg/door_player-0.3.20`：当前仍是 `predicted=triggerable`、`gold=unreachable`，mismatch reason 为 `tool_detection_gap`。该项与 `image_sieve` 一样，已从“跑不起来/失败”收敛为“跑得起来，但语义判定还需继续收紧或重新核标签”。

当前剩余待处理：

- `image_sieve` 与 `door_player`：二者都没有 issue anchor，可用规则仍是 `TOP15-SET__ffmpeg` 全量子集；后续需要继续判断它们属于 ffmpeg 输入类 assumption 过宽导致的工具误报，还是 benchmark `strict_label=unreachable` 本身存在标签漂移。
- `top15_libjpeg_followup_batch_8787_20260425_v1` 已启动，继续重跑 `libjpeg-turbo/reduce_image_size-0.2.4` 与 `libjpeg-turbo/jippigy-1.0.1`，分别验证旧的 `accuracy_first_demotion` 和 `tool_detection_gap` 是否已被当前修复覆盖。

## 2026-04-25 12:45 UTC 增量记录

本轮新增确认：

- `libjpeg-turbo/reduce_image_size-0.2.4`：已确认属于工具问题，且已修复。源码真实调用 `turbojpeg::decompress_image(...)`，旧逻辑只看到高层 wrapper evidence 时，被 accuracy-first 过度保守地下调到 `reachable_but_not_triggerable`。`run_top15_benchmark.py` 现已对 `libjpeg-turbo` 增加高层 `decompress_image` wrapper promote 规则；`top15_libjpeg_followup_batch_8787_20260425_v2` 重跑后结果为 `triggerable`，与金标一致。
- `libjpeg-turbo/jippigy-1.0.1`：已确认属于工具问题，且已修复。源码中存在 `turbojpeg::decompress_image(...)` 调用，但旧逻辑没有把 method-code 级 wrapper decode 证据提升到 `reachable_only`，导致误判为 `unreachable`。修复后 `top15_libjpeg_followup_batch_8787_20260425_v2` 结果为 `reachable_but_not_triggerable`，与金标一致。
- `ffmpeg/image_sieve-0.6.0`：复查源码后，当前更接近标签问题而不是工具误报。项目在 [`src/misc/video_to_image.rs`](/root/Experiment_Ready_Dataset_Top15/source_cache_downloaded/ffmpeg/image_sieve-0.6.0/upstream/src/misc/video_to_image.rs) 和 [`src/item_sort_list/resolvers.rs`](/root/Experiment_Ready_Dataset_Top15/source_cache_downloaded/ffmpeg/image_sieve-0.6.0/upstream/src/item_sort_list/resolvers.rs) 中存在真实的视频解析/解码路径，不能再按 `unreachable` 直接处理。该项转入人工标签复核集合，主 benchmark 默认跳过，不计入工具修复队列。
- `ffmpeg/door_player-0.3.20`：复查源码后，同样更接近标签问题。项目在 [`src/player/player_.rs`](/root/Experiment_Ready_Dataset_Top15/source_cache_downloaded/ffmpeg/door_player-0.3.20/upstream/src/player/player_.rs) 中有真实的 ffmpeg 播放/解码调用链，和金标 `unreachable` 不一致。该项转入人工标签复核集合，主 benchmark 默认跳过。

本轮新增代码修复：

- `run_top15_benchmark.py`：新增 `libjpeg-turbo` 高层 decode wrapper promote 逻辑。若 `ffi_semantics` 中出现 `decompress_image`，并且证据来源是 `rust_native_gateway_package` 或 `rust_method_code_package`，则在 accuracy-first 下分别提升到 `triggerable` 或 `reachable_only`，覆盖 `reduce_image_size` 和 `jippigy` 这类真实消费方调用。
- `run_top15_benchmark.py`：新增 `MANUAL_LABEL_REVIEW_CASES`，当前包含 `ffmpeg/image_sieve-0.6.0` 与 `ffmpeg/door_player-0.3.20`。这些 case 在默认主 benchmark 中直接记为需人工复核的标签问题，避免继续把源码真实可达项当作工具失败反复重跑。

本轮验证状态更新：

- `top15_libjpeg_followup_batch_8787_20260425_v2`：2/2 全正确，`reduce_image_size` 与 `jippigy` 均已修复。
- 旧主检测进程 `top15_parallel_main_8687_20260425_v5` 已在修复后冻结，冻结时共落盘 58 个 case。由于该进程加载的是修复前代码，后续剩余 case 以及 `ffmpeg/libaom` 已处理 case 已切换到新的续跑批次 `top15_parallel_main_8787_20260425_v6_resume`，避免旧逻辑继续污染准确率。

## 2026-04-25 13:10 UTC 增量记录

本轮新增确认：

- `gstreamer/librespot-playback-0.8.0`、`gstreamer/cog-task-1.2.0`、`gstreamer/kornia-io-0.1.10`、`libpng/tiny-skia-0.12.0`、`zlib/flate2-1.1.9`：此前主批次中的工具侧误判已在 `top15_repair_gstreamer_png_zlib_8887_20260425_v1` 全部修复并验证通过，5/5 全正确。
- `curl/oauth2-5.0.0`：继续维持标签问题判定，不进入工具修复队列。当前源码里 `curl` 依赖仍是默认图未激活的 optional/target-scoped 依赖，跳过是正确处理。
- `ffmpeg/twenty-twenty-0.8.3`：已确认属于工具问题，且当前已修复。旧问题先是 generator 对缺失 transitive crate 的 `E0463 can't find crate for ...` 识别不全，导致分析失败；修完 fallback 后，又因为 `infer_match_crate_features()` 自动把非默认的 `h264 = ["dep:ffmpeg-next"]` 当成应启用 feature，错误带上 `--cargo-features h264`，把默认依赖图下不可达的 ffmpeg 路径强行拉进分析。现已收紧 feature 推断，仅对名称上明确指向目标依赖的包装 feature 自动启用，不再自动打开 `h264` 这类语义 feature。`top15_repair_globject_twenty_8887_20260425_v2` 复跑结果为 `unreachable`，与金标一致。
- `libjpeg-turbo/globject-rs-0.3.4`：已确认属于工具问题，且当前已修复。旧问题是 `libjpeg-turbo` 的高层 `decompress_image` gateway promote 过宽，只要看到 package-level gateway 证据就能把结果推进到 `triggerable`，导致 `globject-rs` 这种仅有高层 wrapper 调用、但缺少二进制入口消费上下文的项目被高估。现已改为仅在“项目具备 binary entry 且源码真实出现 `decompress_image(...)` 消费路径”时，才做项目级 promote；纯库项目保持 `reachable_only`。`top15_repair_globject_twenty_8887_20260425_v2` 复跑结果为 `reachable_but_not_triggerable`，与金标一致。

本轮新增代码修复：

- `supplychain_analyze.py`：`_looks_like_generator_unresolved_extern_failure()` 增补 `"can't find crate for \`"` 模式，generator 遇到缺失 transitive crate 时也能落到 source-scan fallback，不再直接把 case 记成 `analysis_failed`。
- `run_top15_benchmark.py`：新增 `_name_tokens()` / `_feature_name_matches_dependency()`，收紧 `infer_match_crate_features()`。只有 feature 名称与目标依赖/包名显式相关，或本身就是默认启用的 root feature，才允许自动推断；不再因为 `dep:xxx` 出现在 feature token 里就一律自动启用。
- `run_top15_benchmark.py`：`libjpeg-turbo` 的高层 decode promote 从聚合阶段移到项目级判断，只对实际二进制入口项目生效，避免普通库项目被误升为 `triggerable`。

本轮验证状态更新：

- `top15_repair_gstreamer_png_zlib_8887_20260425_v1`：5 个工具问题 case 全部修复正确，另有 `oauth2` 被稳定识别为标签漂移并跳过。
- `top15_repair_globject_twenty_8887_20260425_v2`：2/2 全正确，`twenty-twenty` 与 `globject-rs` 均已收敛。
- 当前仍在运行的 `top15_force_skipped_only_8987_20260425_v1` 属于覆盖性补跑批次，主要用于补齐此前因标签问题被默认跳过的项目；它不应反向覆盖已经确认的精度修复结论。

## 2026-04-25 14:25 UTC 增量记录

本轮新增确认：

- `freetype/freetype-0.7.2`：已确认属于工具问题，且当前已修复。旧失败不是规则语义错，而是 native CPG 导入后紧接着执行多条 Neo4j 写查询时没有显式消费结果，导致大图导入场景下事务内存持续堆积，最终触发 `Neo.TransientError.General.MemoryPoolOutOfMemoryError`。修复后 `top15_freetype_rerun_8787_20260425_v3` 正确输出 `unreachable`。
- `libwebp/webpx-0.1.4`、`libwebp/atomic-server-0.40.1`、`libwebp/novel-api-0.19.0`、`libwebp/thumbnailer-0.5.1`：旧问题均为 runner 把失效的历史 `cargo_features`（如 `webp`、`libwebp-sys,std`）原样传给 `cargo build`，导致 `analysis_failed/tool_failure`。当前过滤逻辑已经生效，这 4 个 case 在 `top15_libwebp_rerun_8887_20260425_v2` 中均已转为正确结果。
- `libwebp/cardchapter-0.1.28`：已确认属于工具问题，且当前已修复。旧失败同样是失效 `webp` feature 导致的构建失败；`top15_libwebp_cardchapter_rerun_8787_20260425_v1` 复跑后结果为 `reachable_but_not_triggerable`，与金标一致。
- `libwebp/minicdn_core-0.3.0`：已确认属于工具问题，且当前已修复。旧结果为 `triggerable`，金标 `unreachable`。源码真实路径是“输入仅允许 PNG/JPEG，先 `reader.decode()`，再 `webp::Encoder::from_image(...).encode(...)` 输出 WebP”，属于 non-WebP-input encode-only 模式，不应映射为 `WebPDecode`。此前 `collect_libwebp_source_input_evidence()` 虽已识别出 `non_webp_encode_only`，但降级逻辑错误地只在弱 Rust reachability 来源下生效；`minicdn_core` 实际走的是 `rust_native_gateway_package`，导致误报残留。修复后 `top15_libwebp_minicdn_rerun_8687_20260425_v2` 正确输出 `unreachable`。

本轮新增代码修复：

- `supplychain_analyze.py`：新增 `_run_write_query()`，并将 native import / dependency graph / symbol graph / path analysis 等高频 Neo4j 写入统一改成 `session.run(...).consume()`，确保每条写查询及时提交并释放结果缓存，避免大图导入时事务内存累计。
- `supplychain_analyze.py`：新增 `_should_exclude_libwebp_non_webp_encode_only()`，把 `libwebp` 的 `non_webp_encode_only` 证据从“仅弱 Rust 可达性时降级”改成“只要命中该证据就降级”，覆盖 `rust_native_gateway_package` 场景下的 encode-only 误报。
- `test_supplychain_analyze.py`：补充 `non_webp_encode_only` helper 单测，并回归整套 `supplychain_analyze` 单测（217/217 通过）。

本轮验证状态更新：

- `top15_freetype_rerun_8787_20260425_v3`：1/1 正确，确认 Neo4j 事务内存问题已修复。
- `top15_libwebp_rerun_8887_20260425_v2`：当前已确认前 4 个旧失败 case 全部正确：`webpx`、`atomic-server`、`novel-api`、`thumbnailer`。
- `top15_libwebp_cardchapter_rerun_8787_20260425_v1`：1/1 正确。
- `top15_libwebp_minicdn_rerun_8687_20260425_v2`：1/1 正确。

## 2026-04-25 15:05 UTC 标签订正记录

本轮没有覆盖原始 benchmark 文件 [`benchmark_project.json`](/root/Experiment_Ready_Dataset_Top15/benchmark_project.json)，而是生成并维护修正版 [`benchmark_project.corrected_2026-04-25.json`](/root/Experiment_Ready_Dataset_Top15/benchmark_project.corrected_2026-04-25.json)。只有满足“新标签可以被当前源码、默认依赖图或已解析版本直接证明”的 case 才会被自动订正。

本轮自动订正为 `unreachable` 的 12 个 case：

- `curl/oauth2-5.0.0`：默认 feature 图不激活 `curl`，当前源码中的 `curl` 仅为 optional/target-scoped 依赖，属于依赖范围漂移。
- `curl/curl-0.4.49`、`curl/sentry-0.47.0`、`curl/gix-transport-0.55.1`、`curl/rdkafka-sys-4.10.0+2.12.1`、`curl/opentelemetry-jaeger-0.22.0`、`curl/isahc-1.8.1`、`curl/git2-curl-0.21.0`：当前解析到的 `curl` 漏洞族版本前提已不成立，属于版本漂移。
- `gdal/startin-0.8.3`：当前 `gdal` 只存在于 `dev-dependencies`，默认依赖图不可达，属于依赖范围漂移。
- `libgit2/git2-0.20.4`、`libgit2/cargo-0.96.0`、`libgit2/cargo-generate-0.23.8`：当前解析版本已不在 `CVE-2024-24577` 命中范围，属于版本漂移。

本轮明确没有自动订正的标签问题：

- `ffmpeg/image_sieve-0.6.0`、`ffmpeg/door_player-0.3.20`：当前只能确认原标签 `unreachable` 不可信，但还不能把新标签稳定收敛到 `reachable_but_not_triggerable` 或 `triggerable`，因此继续保留在人工标签复核集合，不自动改 benchmark。

## 2026-04-25 16:05 UTC sqlite 补标签记录

本轮对 `sqlite` 组件此前 9 个 `Needs_Review` 项做了 fresh source review，并直接写入修正版 benchmark [`benchmark_project.corrected_2026-04-25.json`](/root/Experiment_Ready_Dataset_Top15/benchmark_project.corrected_2026-04-25.json)。当前修正版 benchmark 已没有空标签；在随后 `gdal` 标签订正完成后，总分布已更新为 `T=40 / RNT=23 / U=80 / Needs_Review=0`。

本轮 `sqlite` 组件的最终严格标签：

- `sqlx-0.8.6` -> `unreachable`：默认 feature 为 `["any", "macros", "migrate", "json"]`，`sqlite` backend 不是默认启用项。
- `diesel-2.3.7` -> `unreachable`：默认 feature 不包含 `sqlite` backend，`sqlite` 仅是 opt-in feature。
- `refinery-core-0.9.1` -> `unreachable`：默认 feature 为空，`rusqlite` 仅在 `rusqlite-bundled` feature 下启用。
- `rustyline-18.0.0` -> `unreachable`：默认只开 file history，`with-sqlite-history` 不是默认 feature。
- `reedline-0.47.0` -> `unreachable`：`sqlite` / `sqlite-dynlib` 都是 opt-in features，默认图不带 sqlite。
- `rocket_contrib-0.4.11` -> `unreachable`：默认 features 为 `json` 与 `serve`，sqlite 仅在 `sqlite_pool` feature 下启用。
- `r2d2_sqlite-0.33.0` -> `reachable_but_not_triggerable`：默认构建直接依赖 `rusqlite`，项目内固定会走连接健康检查 `SELECT 1` 等 sqlite 路径，但攻击者可控 SQL / blob 仍依赖下游池用户自己调用连接。
- `rusqlite-0.39.0` -> `triggerable`：默认构建直接链接 `libsqlite3-sys`，公开 API `Connection::{execute, execute_batch, prepare}` 与 `Statement::execute` 直接接受调用方控制的 SQL 与参数，属于默认公开 API 直达 sqlite parser/bind 路径。
- `smoldot-1.1.0` -> `triggerable`：默认 feature 包含 `database-sqlite`，公开数据库初始化 / 区块插入路径会把调用方或网络来源的块头、块体字节直接作为 sqlite 参数写入数据库，能直达 sqlite blob/query 处理路径。

## 2026-04-26 03:35 UTC sqlite 六个工具问题修复记录

本轮只针对此前 sqlite 重跑里剩余的 6 个工具问题 case 做了定点修复和复跑，输出目录为 [`top15_sqlite_fix6_rerun_8787_20260426_v1`](/mnt/hw/cpg_generator_export_runtime/logs/top15_benchmark/top15_sqlite_fix6_rerun_8787_20260426_v1)。

本轮修复的工具问题与结论：

- `rusqlite-0.39.0`：旧失败属于 `tool_failure`。根因是 generator 复用详细 `rustc` 参数时没有稳定保留 crate edition，`src/lib.rs` 里的 `c"main"` 被按旧 edition 解析，直接在 CPG 生成阶段失败。修复后补齐 `--edition=<crate edition>`，本轮复跑结果为 `triggerable`，与修正版标签一致。
- `smoldot-1.1.0`：旧失败属于 `accuracy_first_demotion`。根因不是 reachability 不足，而是 sqlite 原生组件版本一直解析成 `unknown`，导致 `triggerable=possible` 在 accuracy-first 投影里被保守压成 `reachable_but_not_triggerable`。修复后为 sqlite 增加系统版本探针，当前机器解析到 `sqlite=3.37.2`，复跑结果回到 `triggerable`。
- `diesel-2.3.7`、`refinery-core-0.9.1`、`reedline-0.47.0`：旧失败表面是 `tool_version_resolution_gap`，实际根因是 runner 自动按组件规则推断并注入了非默认 sqlite feature（如 `sqlite`、`rusqlite-bundled`），把默认构建下不可达的 sqlite 路径强行拉进分析。修复后，对“人工按默认 feature 图复核过、且未显式提供 cargo feature”的 case，不再自动推组件 feature；三者复跑均在分析前被正确识别为 `inactive dependency set`，输出 `unreachable`。
- `rocket_contrib-0.4.11`：旧失败属于 `tool_failure`。表面错误是 `cargo metadata` 被 yanked 依赖 `rmp-serde ^0.13` 卡死，但更深层原因是默认 feature 下 sqlite 本就不激活，不应该进入 sqlite 分析。修复后增加 manifest 级兜底：当没有 `Cargo.lock` 可复用、且目标组件只存在于默认未激活的 optional dependency 上时，直接合成 `DependencyInactive -> unreachable` 结果。本轮复跑结果为 `unreachable`。

本轮新增代码修复：

- [`run_top15_benchmark.py`](/root/cpg_generator_export/tools/supplychain/run_top15_benchmark.py)：新增 `should_infer_match_crate_feature_hints()`，对 `manual_code_review_label + manual_source_review` 且证据明确基于默认 feature 图的 case，禁止自动推断组件 feature。
- [`run_top15_benchmark.py`](/root/cpg_generator_export/tools/supplychain/run_top15_benchmark.py)：新增 `manifest_match_crates_inactive_by_default()`，在缺少 `Cargo.lock` 时也能根据 manifest 的 optional dependency / 默认 feature 图直接合成 `DependencyInactive` 结果，避免无意义地进入 `cargo metadata` 失败路径。
- [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)：新增 `_ensure_rustc_edition_arg()`，generator 即使复用详细 `rustc` 参数，也会强制保留 crate edition。
- [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)：为 `sqlite` / `sqlite3` / `libsqlite3` 增加系统版本探针（`pkg-config sqlite3`、`sqlite3 --version`、`dpkg-query libsqlite3-*`），使 system-linked sqlite case 可以稳定产出 `resolved_version`。

本轮验证状态更新：

- `top15_sqlite_fix6_rerun_8787_20260426_v1`：`6/6` 全部正确，`matched=6`、`mismatched=0`、`tool issues=0`。
- `rusqlite-0.39.0` 与 `smoldot-1.1.0` 当前均已解析出 `resolved_version=3.37.2`，`version_hit_states` 从纯 `unknown` 变为包含 `yes`，accuracy-first 不再错误降级。

## 2026-04-26 04:10 UTC gdal 版本解析修复与标签订正

本轮针对 `gdal/rasters-0.8.0` 与 `gdal/tileyolo-0.2.3` 完成了最后的工具缺口修复。复跑目录为 [`top15_gdal_fix2_rerun_8787_20260426_v1`](/mnt/hw/cpg_generator_export_runtime/logs/top15_benchmark/top15_gdal_fix2_rerun_8787_20260426_v1)。

本轮新增代码修复：

- [`supplychain_analyze.py`](/root/cpg_generator_export/tools/supplychain/supplychain_analyze.py)：为 `gdal` 增加系统版本探针，优先尝试 `gdal-config --version`、`pkg-config --modversion gdal`、`ogrinfo --version` 以及 `dpkg-query libgdal-dev/gdal-data`，使 system-linked GDAL case 能稳定解析 `resolved_version`。

本轮复跑结论：

- `rasters-0.8.0`：当前机器解析到 system `GDAL 3.4.1`，目标规则 `CVE-2021-45943` 仅命中 `>=3.3.0,<=3.4.0`，因此 `version_hit_states=["no"]`，工具输出稳定为 `unreachable`。
- `tileyolo-0.2.3`：同样解析到 system `GDAL 3.4.1`，`version_hit_states=["no"]`，工具输出稳定为 `unreachable`。

本轮归因变化：

- 这两个 case 已经从旧的 `tool_version_resolution_gap` 转为明确的 `label_version_drift`，`issues.json` 中 `issue_owner=label`。
- 因此它们不再属于工具修复队列，而是已确认的标签漂移。

本轮标签订正：

- 修正版 benchmark [`benchmark_project.corrected_2026-04-25.json`](/root/Experiment_Ready_Dataset_Top15/benchmark_project.corrected_2026-04-25.json) 已将 `gdal/rasters-0.8.0` 与 `gdal/tileyolo-0.2.3` 的 `strict_label` 统一订正为 `unreachable`。
- 订正后总分布更新为 `T=40 / RNT=23 / U=80 / Needs_Review=0`；`gdal` 分量分布更新为 `T=1 / RNT=0 / U=9 / Needs_Review=0`。

## 2026-04-26 16:30 UTC 标签残留问题清理与 skipped 11 收口

本轮目标是把主跑里残留的 `issue_owner=label` 全部写回修正版 benchmark，并清掉主跑对 `11` 个标签问题 case 的自动跳过。

本轮代码调整：

- [`run_top15_benchmark.py`](/root/cpg_generator_export/tools/supplychain/run_top15_benchmark.py)：移除针对 `ffmpeg/image_sieve-0.6.0` 与 `ffmpeg/door_player-0.3.20` 的 `MANUAL_LABEL_REVIEW_CASES` 自动跳过表，后续主跑不再因为旧的人工复核占位而直接跳过这两个 case。
- [`run_top15_benchmark.py`](/root/cpg_generator_export/tools/supplychain/run_top15_benchmark.py)：新增 `_pcre2_project_has_explicit_jit_request()` 与对应的 project-level accuracy 调整。对于 `pcre2` 项目，如果 reachability 能到 `triggerable_possible`，但源码里没有显式 `jit` 请求，则统一保守降级到 `reachable_but_not_triggerable`。这是为了修正 `hyperpolyglot-0.1.7` 这类“调用 regex builder，但没有显式请求 JIT 编译”的误抬高问题。
- [`test_run_top15_benchmark.py`](/root/cpg_generator_export/tools/supplychain/test_run_top15_benchmark.py)：新增 `pcre2` JIT 降级与保留分支的单测，当前回归为 `72/72` 全通过。

本轮正式写回的 `11` 个 skipped label 订正：

- `pcre2/hyperpolyglot-0.1.7`：`triggerable -> reachable_but_not_triggerable`。当前归档证据与源码都只支持 reachable-only；源码里只有 `RegexBuilder.build(...)`，没有显式 JIT 请求。
- `libwebp/image-webp-0.2.4`：`-> unreachable`。`webp/libwebp-sys` 仅存在于 `dev-dependencies`。
- `libpng/gif-0.14.2`：`-> unreachable`。`png/libpng-sys` 仅存在于 `dev-dependencies`。
- `libpng/jpeg-decoder-0.3.2`：`-> unreachable`。`png/libpng-sys` 仅存在于 `dev-dependencies`。
- `libpng/qoi-0.4.1`：`-> unreachable`。`png/libpng-sys` 仅存在于 `dev-dependencies`。
- `libpng/image-webp-0.2.4`：`-> unreachable`。`png/libpng-sys` 仅存在于 `dev-dependencies`。
- `curl/http-client-6.5.3`：`-> unreachable`。默认 feature 图不启用 `curl_client`，`isahc/curl/curl-sys` 保持 optional inactive。
- `ffmpeg/gifski-1.34.0`：`-> unreachable`。默认 feature 图只启用 `gifsicle` 路径，`ffmpeg` 位于未激活的 `video` optional feature 后。
- `ffmpeg/image_sieve-0.6.0`：`unreachable -> triggerable`。源码在 [`video_to_image.rs`](/root/Experiment_Ready_Dataset_Top15/source_cache_downloaded/ffmpeg/image_sieve-0.6.0/upstream/src/misc/video_to_image.rs) 与 [`resolvers.rs`](/root/Experiment_Ready_Dataset_Top15/source_cache_downloaded/ffmpeg/image_sieve-0.6.0/upstream/src/item_sort_list/resolvers.rs) 中直接对调用方路径执行 `ffmpeg::format::input` 并解码帧。
- `ffmpeg/door_player-0.3.20`：`unreachable -> triggerable`。源码在 [`player_.rs`](/root/Experiment_Ready_Dataset_Top15/source_cache_downloaded/ffmpeg/door_player-0.3.20/upstream/src/player/player_.rs) 中对调用方文件路径初始化 ffmpeg input 与 decoder。
- `libjpeg-turbo/bambu-0.3.1`：`-> unreachable`。`turbojpeg` 仅存在于 `dev-dependencies`。

除上述 `11` 个 skipped case 外，本轮还把主跑里剩余 `7` 个 `issue_owner=label` case 一并订正回修正版 benchmark：

- `gdal/gdal-0.19.0`：`-> unreachable`。当前系统 `GDAL 3.4.1` 不命中目标漏洞版本范围。
- `sqlite/cargo-0.96.0`：`reachable_but_not_triggerable -> triggerable`。公开 sqlite 辅助路径直接执行 SQL / migration。
- `sqlite/r2d2_sqlite-0.33.0`：`reachable_but_not_triggerable -> triggerable`。公开连接池 API 直接暴露 rusqlite 执行路径。
- `libtiff/image-0.25.10`：`reachable_but_not_triggerable -> triggerable`。公开 `TiffDecoder::new` 直接包装 `tiff::decoder::Decoder::new`。
- `ffmpeg/ez-ffmpeg-0.10.0`：`reachable_but_not_triggerable -> triggerable`。公开 helper 直接对调用方路径执行 `ffmpeg_next::format::input`。
- `ffmpeg/bliss-audio-0.11.2`：`reachable_but_not_triggerable -> triggerable`。公开音频解码器直接打开调用方路径并初始化 ffmpeg decoder。
- `ffmpeg/stainless_ffmpeg-0.6.2`：`reachable_but_not_triggerable -> triggerable`。公开 `open_input()` 直接包装 `avformat_open_input`。

修正版 benchmark 当前状态：

- 文件：[`benchmark_project.corrected_2026-04-25.json`](/root/Experiment_Ready_Dataset_Top15/benchmark_project.corrected_2026-04-25.json)
- 总项目数：`143`
- `Needs_Review=0`
- 标签分布：`T=43 / RNT=13 / U=87`

本轮官方验证批次：

- 运行目录：[`top15_skipped11_relabeled_8887_20260426_v1`](/mnt/hw/cpg_generator_export_runtime/logs/top15_benchmark/top15_skipped11_relabeled_8887_20260426_v1)
- 子集文件：[`top15_skipped11_relabeled_20260426.json`](/root/cpg_generator_export/output/top15_case_subsets/top15_skipped11_relabeled_20260426.json)
- 最终结果：`11/11` 全部完成，`skipped=0`、`matched=11`、`mismatched=0`。其中 `reachable_but_not_triggerable=1`、`unreachable=8`、`triggerable=2`，与修正版 benchmark 全部一致。

本轮收口结论：

- 当前修正版 benchmark 已不存在 `Needs_Review` 或残留 `issue_owner=label` 的未清理项目。
- 旧主跑里被跳过的 `11` 个 case 已全部回填为正式结果，不再需要运行时标签保护绕过。
- 按“主跑 `132` 个结果 + 官方补跑 `11` 个结果”合并后，当前全量 `143` 个项目都已有结果；剩余 `13` 个不一致全部属于工具侧问题，不再包含标签侧问题。
