---
name: ANALYSIS
description: Use when the user gives one or more Rust project paths and wants the supply-chain vulnerability tool to analyze them, auto-repair missing native build prerequisites when possible, rerun after fixing the environment, classify the results into /Users/dingyanwen/Desktop/VUL/cases/by-analysis-status, generate per-case README.md and case.json, and record concrete failure reasons under the corresponding project directory when analysis still fails.
---

# ANALYSIS

Use this skill when the user provides a project path or a directory of projects and wants the full workflow completed:

1. determine the target vulnerability rule for each project
2. run the supply-chain analysis tool
3. classify the results into `VUL/cases/by-analysis-status`
4. write `README.md` and `case.json` for every project
5. keep final results in `VUL`, not in `cpg_generator_export`
6. if a curated rule mapping is missing, generate a family-level `vulns.json` first, then run analysis

## Read first

Before running, read:

- `/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/docs/寻找可用漏洞项目的Agent任务模板.md`
- `/Users/dingyanwen/Desktop/VUL/cases/by-analysis-status/README.md`

These define project selection expectations and the target directory structure.

## Required behavior

When the user gives a path, do not stop at static inspection. Complete the workflow end-to-end:

- analyze the project or all projects under that path
- archive the result into `VUL/cases/by-analysis-status`
- ensure the corresponding project directory contains a concrete failure reason if analysis fails
- when the first run fails because native system libraries, headers, `pkg-config`, `cmake`, `clang`, or similar build prerequisites are missing, repair the environment and rerun instead of stopping on the first failure
- use an explicitly relaxed per-project timeout; do not rely on the batch runner default of 900 seconds
- do not classify a project as `analysis_failed` or `analysis_timeout` until you have completed at least one concrete remediation or timeout-expansion retry when that retry is applicable

Do not leave final run results under:

- `/Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/output/vulnerability_runs`

Temporary run data may exist there during execution, but must be archived out at the end.

## Native prerequisite repair policy

Dependency failures caused by missing native prerequisites are part of the workflow, not a stopping condition.

When analysis fails with signals such as:

- `header file not found`
- `library not found`
- `pkg-config` cannot find a package
- `cmake` missing
- `bindgen` / `clang-sys` / `libclang` errors
- `openssl-sys`, `libxml`, `gdal-sys`, `libheif-sys`, `libwebp-sys` build failures caused by missing system packages

you must:

1. inspect `run.log`, Cargo stderr, and if needed the failing crate `build.rs`
2. identify the missing system dependency or header
3. install or expose the missing dependency in the current machine environment
4. rerun the same project analysis
5. only keep `analysis_failed` if the rerun still fails for a non-remediable reason

On this machine, prefer Homebrew-based repair. Start with targeted installs, not blind bulk installs.

Common mappings:

- `openssl-sys`, `native-tls`, `tokio-openssl` -> `brew install openssl@3`
- `libxml/tree.h`, `xml2-config`, `pkg-config --modversion libxml-2.0` -> `brew install libxml2`
- `gdal.h`, `gdal-config`, `gdal-sys` -> `brew install gdal`
- `libheif/heif.h`, `heif.pc`, `libheif-sys` -> `brew install libheif`
- `webp/decode.h`, `libwebp.pc`, `libwebp-sys` -> `brew install webp`
- `bindgen`, `clang-sys`, missing `libclang` -> `brew install llvm`
- missing `pkg-config` or `cmake` -> `brew install pkg-config cmake`

After installing packages, repair the environment before rerunning. Typical exports on this machine are:

```bash
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
export LIBCLANG_PATH="/opt/homebrew/opt/llvm/lib"
export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
export OPENSSL_DIR="/opt/homebrew/opt/openssl@3"
export OPENSSL_ROOT_DIR="/opt/homebrew/opt/openssl@3"
export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig:/opt/homebrew/opt/libxml2/lib/pkgconfig:/opt/homebrew/opt/gdal/lib/pkgconfig:/opt/homebrew/opt/libheif/lib/pkgconfig:/opt/homebrew/opt/webp/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include -I/opt/homebrew/opt/libxml2/include -I/opt/homebrew/opt/gdal/include -I/opt/homebrew/opt/libheif/include -I/opt/homebrew/opt/webp/include ${CPPFLAGS:-}"
export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/opt/libxml2/lib -L/opt/homebrew/opt/gdal/lib -L/opt/homebrew/opt/libheif/lib -L/opt/homebrew/opt/webp/lib ${LDFLAGS:-}"
export CMAKE_PREFIX_PATH="/opt/homebrew/opt/openssl@3:/opt/homebrew/opt/libxml2:/opt/homebrew/opt/gdal:/opt/homebrew/opt/libheif:/opt/homebrew/opt/webp:${CMAKE_PREFIX_PATH:-}"
```

If the package is already installed but still not found, treat that as an environment-resolution issue and fix the relevant variables before rerunning.

If the failure is clearly unrelated to missing system prerequisites, record the concrete failure reason and classify normally.

## Step 1: build the manifest

Create a manifest JSON describing each project to analyze. The manifest can be a list or `{"items": [...]}`.

Minimum fields per item:

```json
{
  "rel": "NEW/projects/bevy_video-0.9.1/upstream",
  "project_dir": "/absolute/path/to/project",
  "cve_dir": "CVE-2025-27091__openh264",
  "vulns": "/absolute/path/to/vulns.json"
}
```

Common optional fields:

```json
{
  "extras": "/absolute/path/to/extras.json",
  "root": "crate_name",
  "root_method": "main",
  "cpg_input": "/absolute/path/to/main.rs",
  "cargo_features": "pcre2",
  "cargo_all_features": false,
  "cargo_no_default_features": false
}
```

## Step 2: choose rules correctly

When the path itself does not encode the vulnerability mapping, derive it before running analysis. Preferred sources:

1. the project’s enclosing `CVE-*` directory
2. an existing manifest or rule file already in the repo
3. the user’s explicit vulnerability assignment
4. the task template document

If you cannot determine which CVE/rule applies to a project, say that the mapping is missing instead of guessing.

If the CVE/family is known but there is no curated `vulns.json` yet, do not stop there. Generate a family-level `vulns.json` in the same schema used by existing cases, then run the analysis with that generated rule. The current workflow supports auto-generation for family-level templates such as `libxml2`, `libheif`, `libwebp`, `openssl`, `gdal`, `openh264`, and `freetype`.

Important constraints:

- if the manifest already tells you the target `family`, `component`, or `CVE-*__component` directory, prefer an explicit family/project rule file over database auto-selection
- do not silently fall back to the full vulnerability database when project rule selection fails or produces no target-component rules
- if no valid target-component rule can be prepared, record that as a concrete rule-mapping failure instead of continuing with unrelated rules
- before trusting the final status, verify that the primary vulnerability reported by analysis matches the intended target component/CVE family; if the report is for a different component, treat that run as invalid and rerun with the correct explicit rule file
- when doing compare reruns from previously archived cases, preserve the original analysis hints whenever they are available in the archived `run.log` or `analysis_report.json`, especially `cpg_input`, `root`, `root_method`, `cargo_features`, `cargo_all_features`, and `cargo_no_default_features`
- do not rebuild a compare manifest only from project inventory metadata when archived analysis hints exist; otherwise projects like example-driven or feature-gated targets may be rerun under different entrypoints and produce misleading diffs

## Step 3: run batch analysis

Use the batch runner:

```bash
python3 /Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/tools/supplychain/run_manifest_analysis.py \
  --manifest /absolute/path/to/manifest.json \
  --run-name <run_name> \
  --timeout-seconds 43200 \
  --archive-dest-root /Users/dingyanwen/Desktop/VUL/cases/by-analysis-status
```

This script will:

- create a temporary run under `cpg_generator_export/output/vulnerability_runs/<run_name>`
- run `tools/supplychain/supplychain_analyze.py` per project
- auto-generate `analysis_inputs/vulns.json` and `analysis_inputs/extras.json` when the manifest omits them but the family template is supported
- write run-level summaries
- archive the results into `VUL/cases/by-analysis-status`
- remove the source run from `cpg_generator_export/output/vulnerability_runs`

Timeout policy:

- never use the default `900` seconds for real analysis work
- start with `--timeout-seconds 43200`
- if a project still times out but is otherwise making progress, rerun that project alone with a larger timeout such as `86400`
- do not add outer shell time limits like `timeout 15m ...`
- only keep `analysis_timeout` after at least one timeout expansion retry for projects where a longer run is reasonable

## Classification rules

If only static analysis exists, classify as:

- `triggerable_confirmed` -> `03_runnable_static_triggerable_confirmed`
- `triggerable_possible` -> `03_runnable_static_triggerable_possible`
- `reachable_only` or `reachable=true + triggerable=false_positive` -> `04_runnable_reachable_only`
- `not_reachable` or `triggerable=unreachable` -> `05_runnable_not_reachable`
- `analysis_failed` -> `06_not_runnable_analysis_failed`
- `analysis_timeout` -> `07_not_runnable_timeout`

Apply `analysis_failed` and `analysis_timeout` conservatively:

- if the issue is fixable missing native prerequisites, repair first
- if the issue is long runtime, expand timeout first
- only classify after the repair or retry path is exhausted

Only use these categories when manual work has already proved them:

- `01_runnable_and_observable_triggered`
- `02_runnable_and_path_triggered`
- `03_runnable_but_not_observed`

## Failure reason requirement

If analysis fails, the corresponding case directory must still be created under `VUL/cases/by-analysis-status/...`, and its:

- `README.md`
- `case.json`

must contain a concrete failure reason derived from `run.log` when possible, not just a generic “analysis failed”.

For missing dependency failures, the recorded reason must distinguish:

- first-run failure symptom
- what you installed or exported to repair the environment
- whether the rerun succeeded or the post-repair failure reason

Do not write a final failure record that only says “missing library” unless you also record the attempted remediation and rerun result.

Examples:

- missing native system library
- missing platform headers
- cargo build failure
- dependency resolution/type mismatch
- timeout before report generation

## Output layout

Each case directory must follow:

- `分类 / CVE 编号 / 项目名 / README.md`
- `分类 / CVE 编号 / 项目名 / case.json`
- `分类 / CVE 编号 / 项目名 / project_source/`
- `分类 / CVE 编号 / 项目名 / analysis_run/`

Run-level summaries must be placed under:

- `/Users/dingyanwen/Desktop/VUL/cases/by-analysis-status/_runs/<run_name>/`

## Final verification

After finishing, check:

```bash
find /Users/dingyanwen/Desktop/VUL/cases/by-analysis-status -maxdepth 3 -mindepth 1 | sort | sed -n '1,240p'
find /Users/dingyanwen/Desktop/RUST_IR/cpg_generator_export/output/vulnerability_runs -maxdepth 1 -mindepth 1 | sort
```

If the second command still shows the completed run, the workflow is incomplete.
