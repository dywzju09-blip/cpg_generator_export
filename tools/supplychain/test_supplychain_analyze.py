import unittest
import json
import subprocess
from tempfile import TemporaryDirectory
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from tools.supplychain.supplychain_analyze import (
    _analysis_base_env,
    _allow_conservative_wrapper_reachability,
    _apply_temporary_text_edits,
    _build_target_selector_args,
    _cargo_build_fallback_toolchains,
    _cargo_cmd_with_flag,
    _cargo_home_has_cached_registry,
    _cargo_manifest_has_lockfile,
    _cpg_annotation_node_ids,
    _can_continue_after_root_crate_compile_failure,
    _cpg_dependency_toolchain,
    _ensure_legacy_crates_io_registry_view,
    _ensure_generator_allow_lints,
    _ensure_rustc_edition_arg,
    _extract_build_download_targets,
    _extract_unused_crate_dependency_externs,
    _ensure_writable_temp_env,
    _collect_root_direct_externs,
    _collect_root_fingerprint_externs,
    _collect_root_library_externs,
    _extract_native_version_from_crate_version,
    _filter_manifest_cargo_features_for_cargo_dir,
    _existing_flag_values,
    _extern_names_from_rustc_args,
    _find_generator_out_dir,
    _infer_enabled_features_from_root_pkg,
    _installed_toolchain_names,
    _resolve_generator_workdir,
    _legacy_nightly_allow_features_env,
    _is_freetype_package_only_wrapper_reachability,
    _looks_like_legacy_nightly_feature_break,
    _looks_like_legacy_nightly_language_break,
    _looks_like_proc_macro_span_feature_break,
    _looks_like_source_only_thin_bindings_target,
    _looks_like_ffmpeg_native_api_mismatch_failure,
    _looks_like_offline_registry_cache_miss,
    _looks_like_registry_download_failure,
    _missing_mandatory_trigger_guard_ids,
    _missing_rustc_private_component,
    _parse_cargo_build_script_directives,
    _prune_extern_args,
    _preferred_package_bootstrap_toolchain,
    _prefetch_build_download_targets,
    _preferred_root_rust_version_toolchain,
    _proc_macro_extern_arg,
    _resolve_cpg_generator_toolchain,
    _root_crate_extern_aliases,
    _root_library_extern_aliases,
    _rust_cpg_generator_path,
    _rust_source_scan_files,
    _plan_bootstrap_compatibility_edits,
    _restore_temporary_text_edits,
    _should_source_scan_after_generator_failure,
    _should_source_scan_after_build_failure,
    _sink_spec_matches_text,
    _target_needs_root_library_extern,
    _target_is_proc_macro,
    _set_rustc_crate_type,
    _toolchain_needs_legacy_crates_io_registry,
    _without_proc_macro_allow_features_env,
    _weak_lib_component_short_alias,
    _generate_source_scan_rust_cpg,
    analyze_triggerability,
    apply_manual_evidence,
    annotate_imported_c_nodes,
    build_native_pkg_edges,
    collect_dependency_source_native_gateway_calls,
    collect_package_native_gateway_calls,
    collect_source_native_gateway_calls,
    collect_curl_isahc_wrapper_sink_calls,
    collect_source_synthetic_sink_calls,
    collect_libwebp_source_input_evidence,
    _filter_speculative_source_features,
    _match_call_name,
    _SYSTEM_NATIVE_VERSION_CACHE,
    apply_sink_knowledge,
    collect_rust_sink_candidates,
    collect_assumption_evidence,
    ensure_metadata_for_cpg_generation,
    _resolve_analysis_toolchain_name,
    _resolve_shared_cargo_target_root,
    _should_exclude_libwebp_non_webp_encode_only,
    _ignore_weak_source_text_wrapper_evidence,
    _ignore_weak_wrapper_reachability,
    _filter_libpng_pure_rust_png_gateway_calls,
    _is_gstreamer_caps_only_reachability,
    _is_libpng_pure_rust_png_bridge,
    _native_component_dependency_candidates,
    eval_condition,
    evaluate_env_guards,
    evaluate_input_predicate,
    effective_wrapper_sink_evidence,
    has_cross_language_native_evidence,
    has_actionable_trigger_hits,
    should_mark_possible_as_confirmed,
    has_dependency_source_symbol_bridge,
    has_explicit_native_symbol_bridge,
    _native_symbol_names_match,
    has_transitive_native_symbol_bridge,
    find_best_dep_chain,
    maybe_collect_expanded_feature_deps,
    map_result_kind,
    merge_evidence_calls,
    normalize_vuln_rule,
    select_manual_evidence,
    select_relevant_native_gateway_calls,
    register_binary_symbol_inventory,
    resolve_native_component_instances,
    resolve_external_c_calls_to_binary_symbols,
    synthesize_sink_calls_from_method_code,
    summarize_guard_status,
)
from tools.fetch.native_source_resolver import (
    choose_c_analysis_scope,
    ensure_native_source_tree,
    find_local_native_source_tree,
    find_symbol_source_files,
    infer_native_source_dependencies,
)
from tools.fetch.native_source_providers import get_provider
from tools.fetch.native_symbol_resolver import (
    _parse_ldd_output,
    _parse_pkg_config_flags,
    build_symbol_provider_index,
    collect_component_link_context,
    resolve_strict_native_dependencies,
)
from tools.supplychain.auto_vuln_inputs import can_auto_generate, generate_extras_payload, generate_vulns_payload
from tools.verification.ffi_summaries import resolve_ffi_summary
from tools.verification.field_flow import build_field_flow
from tools.verification.state_semantics import evaluate_state_semantics
from tools.verification.path_solver import PathConstraintSolver


class CpgBootstrapTests(unittest.TestCase):
    def test_build_target_selector_args_uses_package_name_only(self):
        args = _build_target_selector_args(
            {"name": "hunter", "version": "1.3.5"},
            {"kind": ["bin"], "name": "hunter"},
        )
        self.assertEqual(args[:2], ["-p", "hunter"])
        self.assertEqual(args[2:], ["--bin", "hunter"])

    def test_offline_registry_cache_miss_detects_retry_without_offline_hint(self):
        detail = """
error: no matching package named `syn` found
note: offline mode (via `--offline`) can sometimes cause surprising resolution failures
help: if this error is too confusing you may wish to retry without `--offline`
""".strip()
        self.assertTrue(_looks_like_offline_registry_cache_miss(detail))

    def test_registry_download_failure_detects_tls_reset(self):
        detail = """
warning: spurious network error (1 try remaining): [35] SSL connect error (Recv failure: Connection reset by peer)
error: failed to download from `https://static.crates.io/crates/openssl-sys/0.9.112/download`
""".strip()
        self.assertTrue(_looks_like_registry_download_failure(detail))

    def test_registry_download_failure_detects_crates_io_index_disconnect(self):
        detail = """
error: Unable to update registry `crates-io`
Caused by:
  failed to fetch `https://github.com/rust-lang/crates.io-index`
Caused by:
  error: RPC failed; curl 56 GnuTLS recv error (-9): Error decoding the received TLS packet.
  fetch-pack: unexpected disconnect while reading sideband packet
  fatal: early EOF
""".strip()
        self.assertTrue(_looks_like_registry_download_failure(detail))

    def test_registry_download_failure_detects_gnutls_handshake_termination(self):
        detail = """
error: Unable to update registry `crates-io`
Caused by:
  failed to fetch `https://github.com/rust-lang/crates.io-index`
Caused by:
  fatal: unable to access 'https://github.com/rust-lang/crates.io-index/': gnutls_handshake() failed: The TLS connection was non-properly terminated.
""".strip()
        self.assertTrue(_looks_like_registry_download_failure(detail))

    def test_extract_build_download_targets_matches_ort_archive(self):
        detail = """
[ort] strategy: "unknown"
cargo:rerun-if-changed=/tmp/build/out/onnxruntime-linux-x64-gpu-1.16.0.tgz
thread 'main' panicked at build.rs:226:31:
[ort] failed to download https://github.com/microsoft/onnxruntime/releases/download/v1.16.0/onnxruntime-linux-x64-gpu-1.16.0.tgz: Transport(UnexpectedEof)
""".strip()
        pairs = _extract_build_download_targets(detail)
        self.assertEqual(len(pairs), 1)
        self.assertEqual(
            pairs[0][0],
            "https://github.com/microsoft/onnxruntime/releases/download/v1.16.0/onnxruntime-linux-x64-gpu-1.16.0.tgz",
        )
        self.assertEqual(str(pairs[0][1]), "/tmp/build/out/onnxruntime-linux-x64-gpu-1.16.0.tgz")

    def test_prefetch_build_download_targets_retries_all_curl_errors(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp) / "build" / "out" / "onnxruntime-linux-x64-gpu-1.16.0.tgz"
            detail = f"""
cargo:rerun-if-changed={target}
[ort] failed to download https://github.com/microsoft/onnxruntime/releases/download/v1.16.0/onnxruntime-linux-x64-gpu-1.16.0.tgz: Transport(UnexpectedEof)
""".strip()
            seen_cmds = []

            def fake_run(cmd, *args, **kwargs):
                seen_cmds.append(cmd)
                out_path = Path(cmd[cmd.index("-o") + 1])
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(b"ok")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with patch("tools.supplychain.supplychain_analyze.shutil.which") as mock_which, patch(
                "tools.supplychain.supplychain_analyze.subprocess.run",
                side_effect=fake_run,
            ):
                mock_which.side_effect = lambda name: "/usr/bin/curl" if name == "curl" else None
                prefetched = _prefetch_build_download_targets(detail)

            self.assertEqual(prefetched, [str(target)])
            self.assertTrue(target.exists())
            self.assertIn("--retry-all-errors", seen_cmds[0])
            self.assertIn("--retry-delay", seen_cmds[0])

    def test_cargo_home_has_cached_registry_when_cache_present(self):
        with TemporaryDirectory() as tmp:
            cargo_home = Path(tmp)
            crate_cache = cargo_home / "registry" / "cache" / "index.crates.io-test"
            crate_cache.mkdir(parents=True, exist_ok=True)
            (crate_cache / "demo.crate").write_text("", encoding="utf-8")
            self.assertTrue(_cargo_home_has_cached_registry(str(cargo_home)))

    def test_cargo_home_has_cached_registry_uses_default_home_when_unset(self):
        with TemporaryDirectory() as tmp:
            cargo_home = Path(tmp) / ".cargo"
            crate_cache = cargo_home / "registry" / "cache" / "index.crates.io-test"
            crate_cache.mkdir(parents=True, exist_ok=True)
            (crate_cache / "demo.crate").write_text("", encoding="utf-8")
            with patch("tools.supplychain.supplychain_analyze.Path.home", return_value=Path(tmp)):
                self.assertTrue(_cargo_home_has_cached_registry(""))

    def test_cargo_manifest_has_lockfile_when_present(self):
        with TemporaryDirectory() as tmp:
            cargo_dir = Path(tmp)
            (cargo_dir / "Cargo.lock").write_text("", encoding="utf-8")
            self.assertTrue(_cargo_manifest_has_lockfile(str(cargo_dir)))

    def test_cargo_manifest_has_lockfile_when_missing(self):
        with TemporaryDirectory() as tmp:
            self.assertFalse(_cargo_manifest_has_lockfile(tmp))

    def test_toolchain_needs_legacy_crates_io_registry_for_old_nightly(self):
        self.assertTrue(_toolchain_needs_legacy_crates_io_registry("nightly-2021-12-05"))
        self.assertFalse(_toolchain_needs_legacy_crates_io_registry("nightly-2023-07-21"))
        self.assertFalse(_toolchain_needs_legacy_crates_io_registry("1.93.1"))

    def test_ensure_legacy_crates_io_registry_view_materializes_git_index(self):
        with TemporaryDirectory() as tmp:
            cargo_dir = Path(tmp) / "demo"
            cargo_home = Path(tmp) / "cargo-home"
            sparse_index = cargo_home / "registry" / "index" / "index.crates.io-1949cf8c6b5b557f"
            sparse_cache = cargo_home / "registry" / "cache" / "index.crates.io-1949cf8c6b5b557f"
            sparse_src = cargo_home / "registry" / "src" / "index.crates.io-1949cf8c6b5b557f"
            cargo_dir.mkdir(parents=True, exist_ok=True)
            sparse_index.mkdir(parents=True, exist_ok=True)
            sparse_cache.mkdir(parents=True, exist_ok=True)
            sparse_src.mkdir(parents=True, exist_ok=True)
            (cargo_dir / "Cargo.lock").write_text(
                """
[[package]]
name = "alphanumeric-sort"
version = "1.0.11"
""".lstrip(),
                encoding="utf-8",
            )
            (sparse_index / "config.json").write_text('{"dl":"https://crates.io/api/v1/crates"}\n', encoding="utf-8")
            cache_entry = sparse_index / ".cache" / "al" / "ph" / "alphanumeric-sort"
            cache_entry.parent.mkdir(parents=True, exist_ok=True)
            cache_entry.write_bytes(
                b'\x03\x02\x00\x00\x00etag: "demo"\x001.0.11\x00{"name":"alphanumeric-sort","vers":"1.0.11","deps":[],"cksum":"x","features":{},"yanked":false}\x00'
            )

            result = _ensure_legacy_crates_io_registry_view(str(cargo_dir), cargo_home_hint=str(cargo_home))
            self.assertIn(result["status"], {"materialized", "ready"})
            legacy_index = cargo_home / "registry" / "index" / "github.com-1ecc6299db9ec823"
            legacy_entry = legacy_index / "al" / "ph" / "alphanumeric-sort"
            self.assertTrue(legacy_entry.exists())
            self.assertIn('"vers":"1.0.11"', legacy_entry.read_text(encoding="utf-8"))
            self.assertTrue((cargo_home / "registry" / "cache" / "github.com-1ecc6299db9ec823").exists())
            self.assertTrue((cargo_home / "registry" / "src" / "github.com-1ecc6299db9ec823").exists())
            refs = subprocess.run(
                ["git", "-C", str(legacy_index), "show-ref"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            self.assertIn("refs/remotes/origin/HEAD", refs)

    def test_ensure_writable_temp_env_sets_repo_tmp_when_missing(self):
        with TemporaryDirectory() as tmp:
            env = _ensure_writable_temp_env({"SUPPLYCHAIN_TMPDIR": tmp})
        self.assertEqual(env["TMPDIR"], tmp)
        self.assertEqual(env["TMP"], tmp)
        self.assertEqual(env["TEMP"], tmp)

    def test_weak_lib_component_short_alias_detects_pure_short_name(self):
        self.assertTrue(_weak_lib_component_short_alias("libtiff", "tiff"))
        self.assertFalse(_weak_lib_component_short_alias("libtiff", "libtiff-sys"))
        self.assertFalse(_weak_lib_component_short_alias("openssl", "openssl"))

    def test_resolve_native_component_instances_ignores_weak_lib_short_alias(self):
        instances = resolve_native_component_instances(
            {"package": "libtiff", "match": {"crates": ["tiff", "libtiff-sys"]}},
            {
                "tiff": {
                    "versions": ["0.11.3"],
                    "features": [],
                    "sources": ["cargo_lock"],
                    "manifest_paths": [],
                }
            },
            "",
        )
        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0]["status"], "unknown")
        self.assertEqual(instances[0]["matched_crates"], [])
        self.assertEqual(instances[0]["reachability_crates"][0]["crate"], "tiff")

    def test_resolve_generator_workdir_falls_back_for_read_only_source_dir(self):
        with TemporaryDirectory() as cargo_tmp, TemporaryDirectory() as output_tmp:
            cargo_dir = Path(cargo_tmp)
            cargo_dir.chmod(0o555)
            try:
                workdir = _resolve_generator_workdir(str(cargo_dir), output_tmp)
            finally:
                cargo_dir.chmod(0o755)
        self.assertTrue(workdir.startswith(str(Path(output_tmp).resolve())))

    def test_plan_bootstrap_compatibility_edits_for_glide(self):
        with TemporaryDirectory() as tmp:
            cargo_dir = Path(tmp)
            (cargo_dir / "src").mkdir(parents=True, exist_ok=True)
            (cargo_dir / "Cargo.toml").write_text(
                """
[dependencies.adw]
version = "0.8"
features = ["v1_5"]
package = "libadwaita"

[dependencies.gst-plugin-gtk4]
version = "0.14"
features = ["gtk_v4_14"]

[dependencies.gtk4]
version = "0.10"
features = ["v4_14"]
""".lstrip(),
                encoding="utf-8",
            )
            (cargo_dir / "src" / "ui_context.rs").write_text(
                """
use adw::prelude::MessageDialogExt;

fn demo() {
            css_provider.load_from_string(include_str!("../data/custom-style.css"));
        let dialog = adw::AboutWindow::builder()
            .application_name("Glide")
            .developer_name("Philippe Normand")
            .artists(["Jakub Steiner"])
            .website("http://github.com/philn/glide")
            .issue_url("https://github.com/philn/glide/issues/new")
            .version(version)
            .debug_info(debug_info.to_json().unwrap())
            .application(&self.app)
            .transient_for(&self.window)
            .build();
        let dialog = adw::MessageDialog::builder()
            .title("An error occurred")
            .body(format!("Glide failed to play this media file. {body}"))
            .decorated(true)
            .transient_for(&self.window)
            .build();

        if let Some(path_str) = report_path {
            let path = path::PathBuf::from(path_str);
            let dir_name = path.parent().unwrap().display();
            let label = path.file_name().unwrap().to_str().unwrap();
            let link_button = gtk4::LinkButton::builder()
                .label(label)
                .uri(format!("file://{dir_name}"))
                .build();
            dialog.set_extra_child(Some(&link_button));
        }
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("report", "Report");
        dialog.connect_response(Some("report"), move |_dialog, _response| {
            let _ = open::that_detached("https://github.com/philn/glide/issues/new");
        });
}
""".lstrip(),
                encoding="utf-8",
            )

            plan = _plan_bootstrap_compatibility_edits(
                "glide",
                str(cargo_dir),
                "pkg-config --libs --cflags gtk4 'gtk4 >= 4.14'",
            )
            self.assertEqual(plan["patches"], ["glide_gtk_libadwaita_bootstrap_compat"])
            self.assertEqual(len(plan["edits"]), 2)

            backups = _apply_temporary_text_edits(plan["edits"])
            try:
                patched_manifest = (cargo_dir / "Cargo.toml").read_text(encoding="utf-8")
                patched_ui = (cargo_dir / "src" / "ui_context.rs").read_text(encoding="utf-8")
                self.assertIn('features = ["v1_1"]', patched_manifest)
                self.assertIn("default-features = false", patched_manifest)
                self.assertIn('features = ["v4_6"]', patched_manifest)
                self.assertIn("css_provider.load_from_data", patched_ui)
                self.assertIn("gtk::AboutDialog::builder()", patched_ui)
                self.assertIn("gtk::MessageDialog::builder()", patched_ui)
            finally:
                _restore_temporary_text_edits(backups)

            restored_manifest = (cargo_dir / "Cargo.toml").read_text(encoding="utf-8")
            restored_ui = (cargo_dir / "src" / "ui_context.rs").read_text(encoding="utf-8")
            self.assertIn('features = ["v1_5"]', restored_manifest)
            self.assertIn('features = ["gtk_v4_14"]', restored_manifest)
            self.assertIn("adw::AboutWindow::builder()", restored_ui)

    def test_plan_bootstrap_compatibility_edits_ignores_unrelated_package(self):
        with TemporaryDirectory() as tmp:
            plan = _plan_bootstrap_compatibility_edits(
                "other",
                tmp,
                "pkg-config --libs --cflags gtk4 'gtk4 >= 4.14'",
            )
        self.assertEqual(plan, {"patches": [], "edits": []})

    def test_plan_bootstrap_compatibility_edits_for_value_bag_const_type_id(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            crate = root / "registry" / "src" / "index.crates.io-1949cf8c6b5b557f" / "value-bag-1.0.0-alpha.7"
            crate.mkdir(parents=True, exist_ok=True)
            build_rs = crate / "build.rs"
            original = """
fn main() {
    if rustc::is_feature_flaggable().unwrap_or(false) {
        println!("cargo:rustc-cfg=value_bag_capture_const_type_id");
    } else if target_arch_is_any(&["x86_64"]) {
        println!("cargo:rustc-cfg=value_bag_capture_ctor");
    }
}
""".lstrip()
            build_rs.write_text(original, encoding="utf-8")

            detail = f"""
error: function pointers and raw pointers not derived from integers in patterns behave unpredictably and should not be relied upon
  --> {crate}/src/internal/cast/primitive.rs:56:21
error: could not compile `value-bag` (lib) due to 34 previous errors
""".strip()
            plan = _plan_bootstrap_compatibility_edits("http-client", str(root), detail)
            self.assertEqual(plan["patches"], ["value_bag_const_type_id_bootstrap_compat"])
            self.assertEqual(len(plan["edits"]), 1)

            backups = _apply_temporary_text_edits(plan["edits"])
            try:
                patched = build_rs.read_text(encoding="utf-8")
                self.assertIn("if false && rustc::is_feature_flaggable().unwrap_or(false)", patched)
            finally:
                _restore_temporary_text_edits(backups)
            self.assertEqual(build_rs.read_text(encoding="utf-8"), original)

    def test_can_continue_after_root_crate_compile_failure_when_deps_exist(self):
        with TemporaryDirectory() as tmp:
            deps_dir = Path(tmp) / "target" / "debug" / "deps"
            deps_dir.mkdir(parents=True, exist_ok=True)
            (deps_dir / "libffmpeg_next-abc.rlib").write_text("", encoding="utf-8")
            log = "error: could not compile `ez-ffmpeg` (lib) due to 170 previous errors"
            self.assertTrue(_can_continue_after_root_crate_compile_failure(log, "ez-ffmpeg", str(deps_dir)))

            build_script_log = (
                "error: failed to run custom build command for `ez-ffmpeg v0.10.0`\n"
                "error: could not compile `ez-ffmpeg` (lib)"
            )
            self.assertFalse(
                _can_continue_after_root_crate_compile_failure(build_script_log, "ez-ffmpeg", str(deps_dir))
            )

    def test_plan_bootstrap_compatibility_edits_for_photohash_libheif(self):
        with TemporaryDirectory() as tmp:
            cargo_dir = Path(tmp)
            (cargo_dir / "src" / "hash").mkdir(parents=True, exist_ok=True)
            (cargo_dir / "Cargo.toml").write_text(
                """
[dependencies.anyhow]
version = "1"

[dependencies.libheif-rs]
version = "2.2.0"
features = ["v1_17"]
default-features = false

[dependencies.turbojpeg]
version = "1.1.1"
""".lstrip(),
                encoding="utf-8",
            )
            (cargo_dir / "Cargo.lock").write_text(
                """
# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "cfg-expr"
version = "0.15.8"
dependencies = [
 "target-lexicon 0.12.16",
]

[[package]]
name = "cfg-expr"
version = "0.20.3"
dependencies = [
 "target-lexicon 0.13.2",
]

[[package]]
name = "libheif-rs"
version = "2.5.1"
dependencies = [
 "cfg-if",
 "enumn",
 "four-cc",
 "libheif-sys",
]

[[package]]
name = "libheif-sys"
version = "5.0.0+1.20.2"
dependencies = [
 "system-deps 7.0.6",
]

[[package]]
name = "photohash"
version = "0.1.8"
dependencies = [
 "anyhow",
 "libheif-rs",
 "system-deps 6.2.2",
 "turbojpeg",
]

[[package]]
name = "system-deps"
version = "6.2.2"
dependencies = [
 "cfg-expr 0.15.8",
]

[[package]]
name = "system-deps"
version = "7.0.6"
dependencies = [
 "cfg-expr 0.20.3",
]

[[package]]
name = "target-lexicon"
version = "0.12.16"

[[package]]
name = "target-lexicon"
version = "0.13.2"
""".lstrip(),
                encoding="utf-8",
            )
            heic_rs = cargo_dir / "src" / "hash" / "heic.rs"
            heic_rs.write_text(
                """
use libheif_rs::LibHeif;

pub async fn compute_image_hashes(path: &Path) {
    let libheif = LibHeif::new();
}
""".lstrip(),
                encoding="utf-8",
            )

            plan = _plan_bootstrap_compatibility_edits(
                "photohash",
                str(cargo_dir),
                "The system library `libheif` required by crate `libheif-sys` was not found",
            )
            self.assertEqual(plan["patches"], ["photohash_disable_heic_bootstrap_compat"])
            self.assertEqual(len(plan["edits"]), 3)

            backups = _apply_temporary_text_edits(plan["edits"])
            try:
                patched_manifest = (cargo_dir / "Cargo.toml").read_text(encoding="utf-8")
                patched_lock = (cargo_dir / "Cargo.lock").read_text(encoding="utf-8")
                patched_heic = heic_rs.read_text(encoding="utf-8")
                self.assertNotIn("[dependencies.libheif-rs]", patched_manifest)
                self.assertIn("[dependencies.turbojpeg]", patched_manifest)
                self.assertNotIn('name = "libheif-rs"', patched_lock)
                self.assertNotIn('name = "libheif-sys"', patched_lock)
                self.assertNotIn('"libheif-rs"', patched_lock)
                self.assertNotIn('"system-deps 7.0.6"', patched_lock)
                self.assertIn('"system-deps"', patched_lock)
                self.assertIn('"target-lexicon"', patched_lock)
                self.assertNotIn("libheif_rs", patched_heic)
                self.assertIn("HEIC support disabled for CPG bootstrap", patched_heic)
            finally:
                _restore_temporary_text_edits(backups)

            restored_manifest = (cargo_dir / "Cargo.toml").read_text(encoding="utf-8")
            restored_lock = (cargo_dir / "Cargo.lock").read_text(encoding="utf-8")
            restored_heic = heic_rs.read_text(encoding="utf-8")
            self.assertIn("[dependencies.libheif-rs]", restored_manifest)
            self.assertIn('name = "libheif-rs"', restored_lock)
            self.assertIn("libheif_rs::LibHeif", restored_heic)

    def test_plan_bootstrap_compatibility_edits_for_pipeless_ai_ort_download(self):
        with TemporaryDirectory() as tmp:
            cargo_dir = Path(tmp)
            (cargo_dir / "Cargo.toml").write_text(
                """
[package]
name = "pipeless-ai"
version = "1.11.0"

[target."cfg(all(not(target_os = \\"macos\\"), not(target_os = \\"ios\\")))".dependencies.ort]
version = "1.16.2"
features = [
    "cuda",
    "tensorrt",
    "openvino",
]

[target."cfg(any(target_os = \\"macos\\", target_os = \\"ios\\"))".dependencies.ort]
version = "1.16.2"
features = [
    "coreml",
    "openvino",
]
""".lstrip(),
                encoding="utf-8",
            )

            plan = _plan_bootstrap_compatibility_edits(
                "pipeless-ai",
                str(cargo_dir),
                "failed to run custom build command for `ort v1.16.2`: "
                "failed to download https://github.com/microsoft/onnxruntime/releases/download/"
                "v1.16.0/onnxruntime-linux-x64-gpu-1.16.0.tgz",
            )
            self.assertEqual(plan["patches"], ["pipeless_ai_ort_load_dynamic_bootstrap_compat"])
            self.assertEqual(len(plan["edits"]), 1)

            backups = _apply_temporary_text_edits(plan["edits"])
            try:
                patched_manifest = (cargo_dir / "Cargo.toml").read_text(encoding="utf-8")
                self.assertEqual(patched_manifest.count("default-features = false"), 2)
                self.assertEqual(patched_manifest.count('"load-dynamic"'), 2)
                self.assertIn('"cuda"', patched_manifest)
                self.assertIn('"tensorrt"', patched_manifest)
                self.assertIn('"openvino"', patched_manifest)
                self.assertIn('"coreml"', patched_manifest)
            finally:
                _restore_temporary_text_edits(backups)

            restored_manifest = (cargo_dir / "Cargo.toml").read_text(encoding="utf-8")
            self.assertNotIn("default-features = false", restored_manifest)
            self.assertNotIn('"load-dynamic"', restored_manifest)

    def test_plan_bootstrap_compatibility_edits_for_hunter(self):
        with TemporaryDirectory() as tmp:
            cargo_dir = Path(tmp)
            (cargo_dir / "src").mkdir(parents=True, exist_ok=True)
            fail_rs = cargo_dir / "src" / "fail.rs"
            files_rs = cargo_dir / "src" / "files.rs"
            fail_rs.write_text(
                """
pub trait ErrorLog where Self: Sized {
    fn log(self);
    fn log_and(self) -> Self;
}

impl<T, E> ErrorLog for Result<T, E>
where E: Into<HError> + Clone {
    fn log(self) {}
    fn log_and(self) -> Self { self }
}

impl<E> ErrorLog for E
where E: Into<HError> + Clone {
    fn log(self) {
        let err: HError = self.into();
        put_log(&err).ok();

    }
    fn log_and(self) -> Self {
        let err: HError = self.clone().into();
        put_log(&err).ok();
        self
    }
}

impl From<std::option::NoneError> for HError {
    fn from(_error: std::option::NoneError) -> Self {
        let err = HError::NoneError(Backtrace::new_arced());
        err
    }
}
""".lstrip(),
                encoding="utf-8",
            )
            files_rs.write_text(
                """
impl Files {
    fn remove_placeholder(&mut self) {
        let dirpath = self.directory.path.clone();
        self.find_file_with_path(&dirpath).cloned()
            .map(|placeholder| self.files.remove_item(&placeholder));
    }

    fn set_tag(&mut self) -> HResult<()> {
        match true {
            true => TAGS.write()?.1.push(self.path.clone()),
            false => { TAGS.write()?.1.remove_item(&self.path); },
        }
        Ok(())
    }
}
""".lstrip(),
                encoding="utf-8",
            )

            plan = _plan_bootstrap_compatibility_edits(
                "hunter",
                str(cargo_dir),
                "error[E0412]: cannot find type `NoneError` in module `std::option`",
            )
            self.assertEqual(plan["patches"], ["hunter_legacy_fail_bootstrap_compat"])
            backups = _apply_temporary_text_edits(plan["edits"])
            try:
                patched = fail_rs.read_text(encoding="utf-8")
                self.assertIn("impl ErrorLog for HError", patched)
                self.assertNotIn("impl<E> ErrorLog for E", patched)
                self.assertNotIn("std::option::NoneError", patched)
            finally:
                _restore_temporary_text_edits(backups)

    def test_plan_bootstrap_compatibility_edits_for_hunter_remove_item_failure(self):
        with TemporaryDirectory() as tmp:
            cargo_dir = Path(tmp)
            (cargo_dir / "src").mkdir(parents=True, exist_ok=True)
            files_rs = cargo_dir / "src" / "files.rs"
            files_rs.write_text(
                """
impl Files {
    fn remove_placeholder(&mut self) {
        let dirpath = self.directory.path.clone();
        self.find_file_with_path(&dirpath).cloned()
            .map(|placeholder| self.files.remove_item(&placeholder));
    }

    fn set_tag(&mut self) -> HResult<()> {
        match true {
            true => TAGS.write()?.1.push(self.path.clone()),
            false => { TAGS.write()?.1.remove_item(&self.path); },
        }
        Ok(())
    }
}
""".lstrip(),
                encoding="utf-8",
            )
            plan = _plan_bootstrap_compatibility_edits(
                "hunter",
                str(cargo_dir),
                "error[E0599]: no method named `remove_item` found for struct `Vec<files::File>` in the current scope",
            )
            self.assertEqual(plan["patches"], ["hunter_legacy_fail_bootstrap_compat"])
            backups = _apply_temporary_text_edits(plan["edits"])
            try:
                patched_files = files_rs.read_text(encoding="utf-8")
                self.assertNotIn("remove_item", patched_files)
                self.assertIn("self.files.iter().position", patched_files)
                self.assertIn("tags.1.iter().position", patched_files)
            finally:
                _restore_temporary_text_edits(backups)

    def test_cargo_cmd_with_flag_inserts_after_subcommand(self):
        cmd = _cargo_cmd_with_flag(["cargo", "build", "-vv", "--locked"], "--offline")
        self.assertEqual(cmd, ["cargo", "build", "--offline", "-vv", "--locked"])

    def test_find_generator_out_dir_prefers_root_package_build_output(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            cargo_dir = root / "demo-crate"
            input_file = cargo_dir / "src" / "lib.rs"
            input_file.parent.mkdir(parents=True, exist_ok=True)
            input_file.write_text('include!(concat!(env!("OUT_DIR"), "/generated.rs"));\n', encoding="utf-8")
            (cargo_dir / "Cargo.toml").write_text(
                """
[package]
name = "demo-crate"
version = "0.1.0"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            build_root = root / "target" / "debug" / "build"
            wrong_out = build_root / "dep-crate-aaaa" / "out"
            right_out = build_root / "demo-crate-bbbb" / "out"
            wrong_out.mkdir(parents=True, exist_ok=True)
            right_out.mkdir(parents=True, exist_ok=True)
            (wrong_out / "generated.rs").write_text("// dep\n", encoding="utf-8")
            (right_out / "generated.rs").write_text("// root\n", encoding="utf-8")

            resolved = _find_generator_out_dir(str(input_file), str(root / "target"), cargo_dir=str(cargo_dir))
            self.assertEqual(resolved, str(right_out))

    def test_resolve_analysis_toolchain_falls_back_to_active_when_requested_toolchain_lacks_cargo(self):
        with patch("tools.supplychain.supplychain_analyze._toolchain_has_cargo") as mock_has_cargo, patch(
            "tools.supplychain.supplychain_analyze._active_rustup_toolchain_name",
            return_value="nightly-x86_64-unknown-linux-gnu",
        ):
            mock_has_cargo.side_effect = lambda value: value == "nightly-x86_64-unknown-linux-gnu"
            resolved = _resolve_analysis_toolchain_name({"RUSTUP_TOOLCHAIN": "stable"})

        self.assertEqual(resolved, "nightly-x86_64-unknown-linux-gnu")

    def test_analysis_base_env_uses_resolved_toolchain(self):
        with patch(
            "tools.supplychain.supplychain_analyze._resolve_analysis_toolchain_name",
            return_value="nightly-x86_64-unknown-linux-gnu",
        ), patch(
            "tools.supplychain.supplychain_analyze._toolchain_lib_dirs",
            return_value=["/usr/lib"],
        ), patch(
            "tools.supplychain.supplychain_analyze.os.cpu_count",
            return_value=32,
        ):
            env = _analysis_base_env({})
        self.assertEqual(env["RUSTUP_TOOLCHAIN"], "nightly-x86_64-unknown-linux-gnu")
        self.assertIn("/usr/lib", env["LIBRARY_PATH"])
        self.assertEqual(env["CARGO_BUILD_JOBS"], "4")
        self.assertEqual(env["CMAKE_BUILD_PARALLEL_LEVEL"], "4")
        self.assertEqual(env["CARGO_INCREMENTAL"], "0")

    def test_analysis_base_env_applies_dedicated_cargo_home(self):
        with TemporaryDirectory() as tmp, patch(
            "tools.supplychain.supplychain_analyze._resolve_analysis_toolchain_name",
            return_value="nightly-x86_64-unknown-linux-gnu",
        ), patch(
            "tools.supplychain.supplychain_analyze._toolchain_lib_dirs",
            return_value=[],
        ), patch(
            "tools.supplychain.supplychain_analyze.subprocess.run",
            return_value=SimpleNamespace(stdout="x86_64-unknown-linux-gnu\n", stderr="", returncode=0),
        ), patch(
            "tools.supplychain.supplychain_analyze.os.cpu_count",
            return_value=16,
        ):
            env = _analysis_base_env({"SUPPLYCHAIN_CARGO_HOME": tmp})
        self.assertEqual(env["CARGO_HOME"], tmp)
        self.assertEqual(env["RUST_HOST_TARGET"], "x86_64-unknown-linux-gnu")
        self.assertEqual(env["CARGO_BUILD_JOBS"], "4")

    def test_analysis_base_env_respects_explicit_cargo_build_jobs_override(self):
        with patch(
            "tools.supplychain.supplychain_analyze._resolve_analysis_toolchain_name",
            return_value="nightly-x86_64-unknown-linux-gnu",
        ), patch(
            "tools.supplychain.supplychain_analyze._toolchain_lib_dirs",
            return_value=[],
        ), patch(
            "tools.supplychain.supplychain_analyze.os.cpu_count",
            return_value=32,
        ):
            env = _analysis_base_env({"SUPPLYCHAIN_CARGO_BUILD_JOBS": "2"})
        self.assertEqual(env["CARGO_BUILD_JOBS"], "2")
        self.assertEqual(env["CMAKE_BUILD_PARALLEL_LEVEL"], "2")

    def test_target_is_proc_macro_detects_target_kind(self):
        self.assertTrue(_target_is_proc_macro({"kind": ["proc-macro"]}))
        self.assertFalse(_target_is_proc_macro({"kind": ["lib"]}))

    def test_root_crate_extern_aliases_include_target_name_for_renamed_lib(self):
        aliases = _root_crate_extern_aliases(
            {"name": "servo-fontconfig-sys"},
            {"name": "fontconfig_sys"},
        )
        self.assertEqual(aliases, ["servo_fontconfig_sys", "fontconfig_sys"])

    def test_root_library_extern_aliases_only_include_library_targets(self):
        aliases = _root_library_extern_aliases(
            {
                "name": "pdf_oxide",
                "targets": [
                    {"name": "pdf_oxide", "kind": ["lib"]},
                    {"name": "analyze_gaps", "kind": ["bin"]},
                ],
            }
        )
        self.assertEqual(aliases, ["pdf_oxide"])

    def test_target_needs_root_library_extern_for_binary_target(self):
        self.assertTrue(_target_needs_root_library_extern({"kind": ["bin"]}))
        self.assertTrue(_target_needs_root_library_extern({"kind": ["example"]}))
        self.assertFalse(_target_needs_root_library_extern({"kind": ["lib"]}))

    def test_prune_extern_args_removes_self_crate_entries(self):
        args = [
            "--crate-name",
            "cargo",
            "--extern",
            "cargo=/tmp/libcargo.rlib",
            "--extern",
            "git2=/tmp/libgit2.rlib",
            "--extern=fontconfig_sys=/tmp/libfontconfig_sys.rlib",
        ]
        pruned = _prune_extern_args(args, {"cargo", "fontconfig_sys"})
        self.assertEqual(
            pruned,
            [
                "--crate-name",
                "cargo",
                "--extern",
                "git2=/tmp/libgit2.rlib",
            ],
        )

    def test_extract_unused_crate_dependency_externs(self):
        detail = """
error: extern crate `rustversion` is unused in crate `vergen_git2`
error: extern crate `proc_macro2` is unused
""".strip()
        self.assertEqual(_extract_unused_crate_dependency_externs(detail), ["rustversion", "proc_macro2"])

    def test_collect_root_library_externs_picks_root_library_artifact_for_bin_targets(self):
        externs = _collect_root_library_externs(
            {
                "name": "pdf_oxide",
                "targets": [
                    {"name": "pdf_oxide", "kind": ["lib"]},
                    {"name": "analyze_gaps", "kind": ["bin"]},
                ],
            },
            {
                "pdf_oxide": "/tmp/libpdf_oxide.rlib",
                "analyze_gaps": "/tmp/libanalyze_gaps.rlib",
            },
        )
        self.assertEqual(externs, {"pdf_oxide": "/tmp/libpdf_oxide.rlib"})

    def test_resolve_shared_cargo_target_root_falls_back_when_dev_shm_is_low(self):
        with TemporaryDirectory() as tmp, patch(
            "tools.supplychain.supplychain_analyze.shutil.disk_usage",
            return_value=SimpleNamespace(free=1024),
        ), patch.dict(
            "tools.supplychain.supplychain_analyze.os.environ",
            {
                "SUPPLYCHAIN_SHARED_CARGO_TARGET_MIN_FREE_BYTES": "2048",
                "SUPPLYCHAIN_SHARED_CARGO_TARGET_FALLBACK_ROOT": tmp,
            },
            clear=False,
        ):
            resolved = _resolve_shared_cargo_target_root("/dev/shm/cpg_generator_export/shared_cargo_target")
        self.assertEqual(resolved, tmp)

    def test_resolve_shared_cargo_target_root_keeps_non_dev_shm_root(self):
        self.assertEqual(
            _resolve_shared_cargo_target_root("/mnt/hw/cpg_generator_export_runtime/shared_cargo_target"),
            "/mnt/hw/cpg_generator_export_runtime/shared_cargo_target",
        )

    def test_ignore_weak_source_text_wrapper_evidence_for_code_root_only(self):
        self.assertTrue(
            _ignore_weak_source_text_wrapper_evidence(
                "rust_method_code_root",
                [],
                [],
                [{"id": "srcsynthetic:1"}],
                external_input_evidence={"status": "not_applicable"},
                gateway_bridge_evidence=False,
            )
        )

    def test_keep_source_text_wrapper_evidence_when_external_input_exists(self):
        self.assertFalse(
            _ignore_weak_source_text_wrapper_evidence(
                "rust_method_code_root",
                [],
                [],
                [{"id": "srcsynthetic:1"}],
                external_input_evidence={"status": "external_controlled"},
                gateway_bridge_evidence=False,
            )
        )

    def test_ignore_weak_wrapper_reachability_without_bridge(self):
        self.assertTrue(
            _ignore_weak_wrapper_reachability(
                "system",
                "rust_method_code_root",
                False,
                False,
                gateway_bridge_evidence=False,
            )
        )

    def test_ignore_weak_wrapper_reachability_with_dependency_source_bridge_only(self):
        self.assertTrue(
            _ignore_weak_wrapper_reachability(
                "system",
                "rust_method_code_root",
                False,
                True,
                dependency_source_symbol_bridge=True,
                explicit_native_symbol_bridge=False,
                transitive_native_symbol_bridge=False,
                native_analysis_coverage="none",
                strict_callsite_edges=0,
                gateway_bridge_evidence=False,
            )
        )

    def test_keep_wrapper_reachability_when_native_bridge_exists(self):
        self.assertFalse(
            _ignore_weak_wrapper_reachability(
                "system",
                "rust_method_code_root",
                False,
                True,
                explicit_native_symbol_bridge=True,
                gateway_bridge_evidence=False,
            )
        )

    def test_preferred_root_rust_version_toolchain_prefers_installed_cpg_ready_numeric_toolchain(self):
        with patch(
            "tools.supplychain.supplychain_analyze._toolchain_has_cargo",
            return_value=True,
        ), patch(
            "tools.supplychain.supplychain_analyze._toolchain_has_rustc_private_components",
        ) as mock_has_components, patch(
            "tools.supplychain.supplychain_analyze._installed_toolchain_names",
            return_value=["1.90.0", "1.93.1", "nightly"],
        ):
            mock_has_components.side_effect = lambda value, base_env=None: value == "1.90.0"
            selected = _preferred_root_rust_version_toolchain(
                {"rust-version": "1.93"},
                {"RUSTUP_TOOLCHAIN": "nightly-x86_64-unknown-linux-gnu"},
            )
        self.assertEqual(selected, "1.90.0")

    def test_preferred_root_rust_version_toolchain_falls_back_to_cpg_ready_dated_nightly(self):
        with patch(
            "tools.supplychain.supplychain_analyze._toolchain_has_cargo",
            return_value=True,
        ), patch(
            "tools.supplychain.supplychain_analyze._toolchain_has_rustc_private_components",
        ) as mock_has_components, patch(
            "tools.supplychain.supplychain_analyze._installed_toolchain_names",
            return_value=["nightly-2021-12-05", "1.93.1", "nightly"],
        ):
            mock_has_components.side_effect = (
                lambda value, base_env=None: value == "nightly-2021-12-05"
            )
            selected = _preferred_root_rust_version_toolchain(
                {"rust-version": "1.93"},
                {"RUSTUP_TOOLCHAIN": "nightly-x86_64-unknown-linux-gnu"},
            )
        self.assertEqual(selected, "nightly-2021-12-05")

    def test_preferred_package_bootstrap_toolchain_pins_hunter_to_legacy_nightly(self):
        with patch(
            "tools.supplychain.supplychain_analyze._toolchain_has_cargo",
            return_value=True,
        ), patch(
            "tools.supplychain.supplychain_analyze._toolchain_has_rustc_private_components",
            return_value=True,
        ):
            selected = _preferred_package_bootstrap_toolchain("hunter", {})
        self.assertEqual(selected, "nightly-2020-10-05-x86_64-unknown-linux-gnu")

    def test_cargo_build_fallback_toolchains_prefers_declared_rust_version(self):
        root_pkg = {"rust-version": "1.93"}
        build_logs = "error[E0635]: unknown feature `proc_macro_span_shrink`"
        with patch("tools.supplychain.supplychain_analyze._installed_toolchain_names", return_value=["1.93.1", "1.92", "nightly"]), patch(
            "tools.supplychain.supplychain_analyze._toolchain_has_cargo",
            return_value=True,
        ):
            candidates = _cargo_build_fallback_toolchains(root_pkg, build_logs, {"RUSTUP_TOOLCHAIN": "nightly"})
        self.assertEqual(candidates[:2], ["1.93", "1.93.1"])

    def test_looks_like_legacy_nightly_feature_break_detects_removed_try_trait(self):
        build_logs = """
error[E0635]: feature `try_trait` has been renamed to `try_trait_v2`
error[E0635]: unknown feature `vec_remove_item`
""".strip()
        self.assertTrue(_looks_like_legacy_nightly_feature_break(build_logs))
        self.assertTrue(_looks_like_legacy_nightly_language_break(build_logs))

    def test_looks_like_legacy_nightly_feature_break_detects_removed_stdsimd(self):
        build_logs = "error[E0635]: unknown feature `stdsimd`"
        self.assertTrue(_looks_like_legacy_nightly_feature_break(build_logs))
        self.assertFalse(_looks_like_legacy_nightly_language_break(build_logs))

    def test_looks_like_legacy_nightly_feature_break_detects_unexpected_cfg_deny_warnings(self):
        build_logs = """
warning: unexpected `cfg` condition name: `assert_no_panic`
note: `#[warn(unexpected_cfgs)]` implied by `#[warn(warnings)]`
""".strip()
        self.assertTrue(_looks_like_legacy_nightly_feature_break(build_logs))
        self.assertFalse(_looks_like_legacy_nightly_language_break(build_logs))

    def test_cargo_build_fallback_toolchains_prefers_dated_nightly_for_legacy_language_break(self):
        build_logs = """
error[E0635]: feature `try_trait` has been renamed to `try_trait_v2`
error[E0635]: unknown feature `vec_remove_item`
""".strip()
        with patch(
            "tools.supplychain.supplychain_analyze._installed_toolchain_names",
            return_value=["1.90.0", "nightly-2021-12-05", "nightly-2023-07-21", "nightly"],
        ), patch(
            "tools.supplychain.supplychain_analyze._toolchain_has_cargo",
            return_value=True,
        ), patch(
            "tools.supplychain.supplychain_analyze._toolchain_has_rustc_private_components",
        ) as mock_has_components:
            mock_has_components.side_effect = (
                lambda value, base_env=None: value in {"1.90.0", "nightly-2021-12-05", "nightly-2023-07-21"}
            )
            candidates = _cargo_build_fallback_toolchains({}, build_logs, {"RUSTUP_TOOLCHAIN": "nightly"})
        self.assertEqual(candidates, ["nightly-2021-12-05", "nightly-2023-07-21"])

    def test_looks_like_source_only_thin_bindings_target_accepts_extern_crate_only_sys_lib(self):
        with TemporaryDirectory() as tmp:
            input_file = Path(tmp) / "lib.rs"
            input_file.write_text(
                "extern crate expat_sys;\nextern crate freetype_sys;\n",
                encoding="utf-8",
            )
            self.assertTrue(
                _looks_like_source_only_thin_bindings_target(
                    str(input_file),
                    {"name": "servo-fontconfig-sys"},
                    {"name": "fontconfig_sys"},
                )
            )

    def test_looks_like_source_only_thin_bindings_target_rejects_real_code(self):
        with TemporaryDirectory() as tmp:
            input_file = Path(tmp) / "lib.rs"
            input_file.write_text(
                "extern crate expat_sys;\nfn decode() {}\n",
                encoding="utf-8",
            )
            self.assertFalse(
                _looks_like_source_only_thin_bindings_target(
                    str(input_file),
                    {"name": "servo-fontconfig-sys"},
                    {"name": "fontconfig_sys"},
                )
            )

    def test_looks_like_ffmpeg_native_api_mismatch_failure_detects_root_header_drift(self):
        detail = """
error[E0609]: no field `time_base` on type `AVPacket`
    --> src/core/scheduler/enc_task.rs:1186:28
error: could not compile `ez-ffmpeg` (lib) due to 170 previous errors
""".strip()
        self.assertTrue(_looks_like_ffmpeg_native_api_mismatch_failure(detail, "ez-ffmpeg"))
        self.assertFalse(_looks_like_ffmpeg_native_api_mismatch_failure(detail, "other-crate"))

    def test_looks_like_ffmpeg_native_api_mismatch_failure_detects_missing_generated_constants(self):
        detail = """
error: could not compile `ffmpeg-sys-next` (lib)
error[E0425]: cannot find value `AV_PIX_FMT_SAND128` in this scope
error[E0425]: cannot find value `AV_PIX_FMT_SAND64_10` in this scope
error: could not compile `bliss-audio` (lib) due to previous errors
""".strip()
        self.assertTrue(_looks_like_ffmpeg_native_api_mismatch_failure(detail, "bliss-audio"))

    def test_should_source_scan_after_generator_failure_for_ffmpeg_header_drift(self):
        detail = """
RuntimeError: rust-cpg-generator failed (exit=1)
error[E0609]: no field `nb_stream_groups` on type `&ffmpeg_sys_next::AVFormatContext`
error: aborting due to 170 previous errors
""".strip()
        self.assertTrue(_should_source_scan_after_generator_failure(detail, "ez-ffmpeg"))

    def test_should_source_scan_after_generator_failure_for_unresolved_externs(self):
        detail = """
RuntimeError: rust-cpg-generator failed
error[E0432]: unresolved import `fontconfig_sys`
error[E0433]: use of unresolved module or unlinked crate `freetype`
""".strip()
        self.assertTrue(_should_source_scan_after_generator_failure(detail, "crossfont"))

    def test_should_source_scan_after_generator_failure_for_incompatible_rustc_artifacts(self):
        detail = """
RuntimeError: rust-cpg-generator failed
error[E0514]: found crate `arrow_array` compiled by an incompatible version of rustc
""".strip()
        self.assertTrue(_should_source_scan_after_generator_failure(detail, "geoarrow2"))

    def test_should_source_scan_after_generator_failure_for_crate_version_skew(self):
        detail = """
RuntimeError: rust-cpg-generator failed
error[E0460]: found possibly newer version of crate `libc` which `ffmpeg_sys_next` depends on
= note: perhaps that crate needs to be recompiled?
""".strip()
        self.assertTrue(_should_source_scan_after_generator_failure(detail, "ffmpeg-next"))

    def test_should_source_scan_after_generator_failure_for_missing_transitive_crate(self):
        detail = """
RuntimeError: rust-cpg-generator failed
error[E0463]: can't find crate for `num_traits` which `image` depends on
error[E0463]: can't find crate for `image` which `image_compare` depends on
""".strip()
        self.assertTrue(_should_source_scan_after_generator_failure(detail, "twenty-twenty"))

    def test_should_source_scan_after_generator_failure_for_missing_zlib_backend(self):
        detail = """
RuntimeError: rust-cpg-generator failed
error: You need to choose a zlib backend
error: No compression backend selected; enable one of `zlib`, `zlib-ng`, `zlib-rs`, or the default `rust_backend` feature.
""".strip()
        self.assertTrue(_should_source_scan_after_generator_failure(detail, "flate2"))

    def test_should_source_scan_after_build_failure_for_legacy_nightly_feature_break(self):
        detail = """
RuntimeError: cargo build for CPG deps failed
error[E0635]: unknown feature `stdsimd`
""".strip()
        self.assertTrue(_should_source_scan_after_build_failure(detail, "geoarrow2"))

    def test_should_source_scan_after_build_failure_for_value_bag_const_type_id(self):
        detail = """
RuntimeError: cargo build for CPG deps failed
error: function pointers and raw pointers not derived from integers in patterns behave unpredictably and should not be relied upon
  --> /cache/value-bag-1.0.0-alpha.7/src/internal/cast/primitive.rs:56:21
error: could not compile `value-bag` (lib) due to 34 previous errors
""".strip()
        self.assertTrue(_should_source_scan_after_build_failure(detail, "http-client"))

    def test_should_source_scan_after_build_failure_for_registry_tls_termination(self):
        detail = """
RuntimeError: cargo build for CPG deps failed
error: Unable to update registry `crates-io`
Caused by:
  failed to fetch `https://github.com/rust-lang/crates.io-index`
Caused by:
  fatal: unable to access 'https://github.com/rust-lang/crates.io-index/': gnutls_handshake() failed: The TLS connection was non-properly terminated.
""".strip()
        self.assertTrue(_should_source_scan_after_build_failure(detail, "cog-task"))

    def test_should_source_scan_after_build_failure_for_namespaced_features_unsupported(self):
        detail = """
RuntimeError: cargo build for CPG deps failed
error: failed to parse manifest at `/tmp/Cargo.toml`
Caused by:
  namespaced features with the `dep:` prefix are only allowed on the nightly channel and requires the `-Z namespaced-features` flag on the command-line
""".strip()
        self.assertTrue(_should_source_scan_after_build_failure(detail, "cog-task"))

    def test_should_source_scan_after_build_failure_for_pkg_config_system_library_failure(self):
        detail = """
RuntimeError: cargo build for CPG deps failed
error: failed to run custom build command for `libheif-sys v5.0.0+1.20.2`
Caused by:
  pkg-config exited with status code 1
  The system library `libheif` required by crate `libheif-sys` was not found.
  > pkg-config --libs --cflags libheif 'libheif >= 1.17'
""".strip()
        self.assertTrue(_should_source_scan_after_build_failure(detail, "image_sieve"))

    def test_collect_curl_isahc_wrapper_sink_calls(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            src.mkdir(parents=True, exist_ok=True)
            (src / "isahc.rs").write_text(
                """
use isahc::{http, ResponseExt};

pub struct IsahcClient {
    client: isahc::HttpClient,
}

impl IsahcClient {
    pub async fn send(&self, req: Request) -> Result<Response, Error> {
        let request = http::Request::builder().uri(req.url().as_str()).body(())?;
        let res = self.client.send_async(request).await?;
        Ok(res)
    }
}
""".lstrip(),
                encoding="utf-8",
            )
            calls = collect_curl_isahc_wrapper_sink_calls(
                str(root),
                native_component_instances=[
                    {
                        "matched_crates": [
                            {"crate": "isahc"},
                            {"crate": "curl-sys"},
                        ]
                    }
                ],
            )
        names = {call.get("name") for call in calls}
        self.assertEqual({"Easy::url", "Easy::proxy", "Easy::perform"}, names)

    def test_ensure_generator_allow_lints_adds_unused_extern_suppression(self):
        args = ["--edition=2024", "-A", "dead_code"]
        patched = _ensure_generator_allow_lints(args)
        self.assertIn("-A", patched)
        self.assertIn("unused_crate_dependencies", patched)
        self.assertIn("unused_extern_crates", patched)
        self.assertEqual(patched.count("dead_code"), 1)

    def test_generate_source_scan_rust_cpg_emits_methods_calls_and_local_call_edges(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_dir = root / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            (src_dir / "lib.rs").write_text(
                "\n".join(
                    [
                        "pub fn open(path: &str) {",
                        "    helper(path);",
                        "    unsafe { ffmpeg_sys_next::avformat_open_input(); }",
                        "}",
                        "fn helper(path: &str) {",
                        "    let _ = path.len();",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            out = root / "cpg.json"
            stats = _generate_source_scan_rust_cpg(str(root), str(out), root_pkg_name="ez-ffmpeg")
            graph = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(stats["method_count"], 2)
        self.assertGreaterEqual(stats["call_count"], 2)
        methods = [node for node in graph["nodes"] if node["label"] == "METHOD"]
        calls = [node for node in graph["nodes"] if node["label"] == "CALL"]
        self.assertTrue(any(node["name"] == "open" and node["package"] == "ez-ffmpeg" for node in methods))
        self.assertTrue(any(node["name"] == "ffmpeg_sys_next::avformat_open_input" and node["is_ffi"] for node in calls))
        helper_method = next(node for node in methods if node["name"] == "helper")
        helper_call = next(node for node in calls if node["name"] == "helper")
        self.assertTrue(
            any(edge["label"] == "CALL" and edge["src"] == helper_call["id"] and edge["dst"] == helper_method["id"] for edge in graph["edges"])
        )

    def test_rust_source_scan_files_skips_non_runtime_sources_by_default(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in [
                "src/lib.rs",
                "examples/demo.rs",
                "tests/integration.rs",
                "benches/bench.rs",
                "fuzz/fuzz_targets/input.rs",
                "build.rs",
            ]:
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fn main() {}\n", encoding="utf-8")

            files = {path.relative_to(root).as_posix() for path in _rust_source_scan_files(str(root))}

        self.assertEqual(files, {"src/lib.rs"})

    def test_build_target_selector_args_uses_package_name_spec(self):
        args = _build_target_selector_args(
            {"name": "http-client", "version": "6.5.3"},
            {"kind": ["lib"], "name": "http_client"},
        )
        self.assertEqual(args, ["-p", "http-client", "--lib"])

    def test_build_native_pkg_edges_avoids_deep_ast_global_scan(self):
        session = MagicMock()
        build_native_pkg_edges(session)
        query = session.run.call_args.args[0]
        self.assertIn("MATCH (call:CALL:C)-[:CALL]->(callee:METHOD:C)", query)
        self.assertNotIn("AST*0..40", query)

    def test_filter_manifest_cargo_features_for_cargo_dir_drops_plain_dependency(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                """
[package]
name = "webpx"
version = "0.1.4"

[features]
default = ["std"]
std = ["libwebp-sys/std"]

[dependencies.libwebp-sys]
version = "0.14.1"
""".lstrip(),
                encoding="utf-8",
            )
            kept, dropped = _filter_manifest_cargo_features_for_cargo_dir(
                str(root),
                "libwebp-sys,std",
            )
        self.assertEqual(kept, "std")
        self.assertEqual(dropped, ["libwebp-sys"])

    def test_preferred_root_rust_version_toolchain_uses_project_declared_version_under_nightly(self):
        with patch("tools.supplychain.supplychain_analyze._toolchain_has_cargo") as mock_has_cargo:
            mock_has_cargo.side_effect = lambda value: value == "1.93.1"
            selected = _preferred_root_rust_version_toolchain(
                {"rust-version": "1.93"},
                {"RUSTUP_TOOLCHAIN": "nightly-x86_64-unknown-linux-gnu"},
            )
        self.assertEqual(selected, "1.93.1")

    def test_resolve_cpg_generator_toolchain_prefers_cpg_ready_active_toolchain(self):
        with patch(
            "tools.supplychain.supplychain_analyze._toolchain_has_cargo",
            return_value=True,
        ), patch(
            "tools.supplychain.supplychain_analyze._toolchain_has_rustc_private_components",
        ) as mock_has_components, patch(
            "tools.supplychain.supplychain_analyze._toolchain_supports_manifest_edition",
            return_value=True,
        ), patch(
            "tools.supplychain.supplychain_analyze._active_rustup_toolchain_name",
            return_value="nightly-x86_64-unknown-linux-gnu",
        ), patch(
            "tools.supplychain.supplychain_analyze._installed_toolchain_names",
            return_value=["1.93.1", "nightly-x86_64-unknown-linux-gnu", "stable-x86_64-unknown-linux-gnu"],
        ):
            mock_has_components.side_effect = (
                lambda value, base_env=None: value in {"nightly-x86_64-unknown-linux-gnu", "stable-x86_64-unknown-linux-gnu"}
            )
            selected = _resolve_cpg_generator_toolchain(
                "1.93.1",
                {"RUSTUP_TOOLCHAIN": "1.93.1"},
            )
        self.assertEqual(selected, "nightly-x86_64-unknown-linux-gnu")

    def test_resolve_cpg_generator_toolchain_keeps_active_nightly_ahead_of_pinned_candidates(self):
        with patch(
            "tools.supplychain.supplychain_analyze._toolchain_has_cargo",
            return_value=True,
        ), patch(
            "tools.supplychain.supplychain_analyze._toolchain_has_rustc_private_components",
        ) as mock_has_components, patch(
            "tools.supplychain.supplychain_analyze._toolchain_supports_manifest_edition",
            return_value=True,
        ), patch(
            "tools.supplychain.supplychain_analyze._active_rustup_toolchain_name",
            return_value="nightly-x86_64-unknown-linux-gnu",
        ), patch(
            "tools.supplychain.supplychain_analyze._installed_toolchain_names",
            return_value=[
                "1.93.1",
                "nightly-x86_64-unknown-linux-gnu",
                "nightly-2021-12-05-x86_64-unknown-linux-gnu",
                "nightly-2023-07-21-x86_64-unknown-linux-gnu",
            ],
        ):
            mock_has_components.side_effect = (
                lambda value, base_env=None: value in {
                    "nightly-x86_64-unknown-linux-gnu",
                    "nightly-2021-12-05-x86_64-unknown-linux-gnu",
                    "nightly-2023-07-21-x86_64-unknown-linux-gnu",
                }
            )
            selected = _resolve_cpg_generator_toolchain(
                "1.93.1",
                {"RUSTUP_TOOLCHAIN": "1.93.1"},
            )
        self.assertEqual(selected, "nightly-x86_64-unknown-linux-gnu")

    def test_resolve_cpg_generator_toolchain_skips_legacy_cargo_that_cannot_parse_generator_manifest(self):
        with patch(
            "tools.supplychain.supplychain_analyze._toolchain_has_cargo",
            return_value=True,
        ), patch(
            "tools.supplychain.supplychain_analyze._toolchain_has_rustc_private_components",
            return_value=True,
        ), patch(
            "tools.supplychain.supplychain_analyze._toolchain_supports_manifest_edition",
        ) as mock_supports_manifest, patch(
            "tools.supplychain.supplychain_analyze._active_rustup_toolchain_name",
            return_value="nightly-x86_64-unknown-linux-gnu",
        ), patch(
            "tools.supplychain.supplychain_analyze._installed_toolchain_names",
            return_value=[
                "nightly-2020-10-05-x86_64-unknown-linux-gnu",
                "nightly-x86_64-unknown-linux-gnu",
            ],
        ):
            mock_supports_manifest.side_effect = (
                lambda toolchain, edition, base_env=None: toolchain != "nightly-2020-10-05-x86_64-unknown-linux-gnu"
            )
            selected = _resolve_cpg_generator_toolchain(
                "nightly-2020-10-05-x86_64-unknown-linux-gnu",
                {"RUSTUP_TOOLCHAIN": "nightly-2020-10-05-x86_64-unknown-linux-gnu"},
            )
        self.assertEqual(selected, "nightly-x86_64-unknown-linux-gnu")

    def test_legacy_nightly_allow_features_env_appends_proc_macro_span(self):
        env, adjusted = _legacy_nightly_allow_features_env({"CARGO_ENCODED_RUSTFLAGS": "-Clink-arg=-fuse-ld=lld"})
        self.assertTrue(adjusted)
        self.assertEqual(
            env["CARGO_ENCODED_RUSTFLAGS"],
            "-Clink-arg=-fuse-ld=lld\x1f-Zallow-features=proc_macro_span",
        )

    def test_legacy_nightly_allow_features_env_respects_existing_allow_features(self):
        env, adjusted = _legacy_nightly_allow_features_env({"CARGO_ENCODED_RUSTFLAGS": "-Zallow-features=foo,bar"})
        self.assertFalse(adjusted)
        self.assertEqual(env["CARGO_ENCODED_RUSTFLAGS"], "-Zallow-features=foo,bar")

    def test_without_proc_macro_allow_features_env_strips_only_bootstrap_flag(self):
        env = _without_proc_macro_allow_features_env(
            {"CARGO_ENCODED_RUSTFLAGS": "-Clink-arg=-fuse-ld=lld\x1f-Zallow-features=proc_macro_span"}
        )
        self.assertEqual(env["CARGO_ENCODED_RUSTFLAGS"], "-Clink-arg=-fuse-ld=lld")

    def test_looks_like_proc_macro_span_feature_break_only_matches_proc_macro_case(self):
        self.assertTrue(
            _looks_like_proc_macro_span_feature_break("error[E0635]: unknown feature `proc_macro_span_shrink`")
        )
        self.assertFalse(
            _looks_like_proc_macro_span_feature_break("error[E0635]: feature `try_trait` has been renamed to `try_trait_v2`")
        )

    def test_cpg_dependency_toolchain_prefers_generator_when_toolchains_differ(self):
        self.assertEqual(
            _cpg_dependency_toolchain("1.93.1", "nightly-x86_64-unknown-linux-gnu"),
            "nightly-x86_64-unknown-linux-gnu",
        )

    def test_cpg_dependency_toolchain_keeps_build_toolchain_when_generator_matches(self):
        self.assertEqual(_cpg_dependency_toolchain("1.93.1", "1.93.1"), "1.93.1")

    def test_rust_cpg_generator_path_is_toolchain_scoped(self):
        path = _rust_cpg_generator_path("/repo", "1.93.1")
        self.assertEqual(path, "/repo/rust_src/target/toolchains/1.93.1/release/rust-cpg-generator")

    def test_set_rustc_crate_type_replaces_existing_flags(self):
        args = ["--crate-name", "demo", "--crate-type", "lib", "--edition=2021", "--crate-type=rlib"]
        out = _set_rustc_crate_type(args, "proc-macro")
        self.assertEqual(out, ["--crate-name", "demo", "--edition=2021", "--crate-type", "proc-macro"])

    def test_proc_macro_extern_arg_prefers_sysroot_candidate(self):
        with TemporaryDirectory() as tmp, patch(
            "tools.supplychain.supplychain_analyze.subprocess.run",
            return_value=SimpleNamespace(stdout=f"{tmp}\n", stderr="", returncode=0),
        ):
            libdir = Path(tmp)
            (libdir / "libproc_macro-abc.rlib").write_text("", encoding="utf-8")
            arg = _proc_macro_extern_arg({})
        self.assertTrue(arg.startswith("proc_macro="))
        self.assertIn("libproc_macro-abc.rlib", arg)

    def test_ensure_metadata_for_cpg_generation_prefers_offline_metadata_with_external_deps(self):
        args = SimpleNamespace(
            cargo_dir="/tmp/demo",
            deps="/tmp/demo/deps.json",
            skip_cpg_generation=False,
            cpg_json="",
            regen_cpg=False,
            cargo_features="pcre2",
            cargo_all_features=False,
            cargo_no_default_features=True,
        )
        fake_meta = {"packages": [{"name": "demo"}]}
        with patch("tools.supplychain.supplychain_analyze.run_metadata", return_value=fake_meta) as mock_run_metadata:
            resolved = ensure_metadata_for_cpg_generation(args, None)

        self.assertEqual(resolved, fake_meta)
        mock_run_metadata.assert_called_once_with(
            "/tmp/demo",
            cargo_features="pcre2",
            cargo_all_features=False,
            cargo_no_default_features=True,
            offline=True,
            no_deps=True,
        )

    def test_infer_enabled_features_from_root_pkg_uses_default_features_when_resolve_missing(self):
        root_pkg = {
            "features": {
                "default": ["decode", "encode", "std"],
                "decode": [],
                "encode": [],
                "std": ["dep:libwebp-sys"],
            }
        }
        enabled = _infer_enabled_features_from_root_pkg(root_pkg)
        self.assertEqual(enabled, ["decode", "encode", "std"])

    def test_extern_names_from_rustc_args_supports_split_and_inline_forms(self):
        names = _extern_names_from_rustc_args(
            [
                "--crate-name",
                "demo",
                "--extern",
                "serde=/tmp/libserde.rmeta",
                "--extern=string_cache=/tmp/libstring_cache.rmeta",
            ]
        )
        self.assertEqual(names, {"serde", "string_cache"})

    def test_existing_flag_values_support_split_and_inline_forms(self):
        values = _existing_flag_values(
            [
                "--cfg",
                'feature="std"',
                '--cfg=feature="alloc"',
                "--check-cfg",
                "cfg(wasm)",
            ],
            "--cfg",
        )
        self.assertEqual(values, {'feature="std"', 'feature="alloc"'})

    def test_parse_cargo_build_script_directives_collects_env_cfg_and_check_cfg(self):
        with TemporaryDirectory() as tmp:
            output_file = Path(tmp) / "debug" / "build" / "demo-abc" / "output"
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(
                "\n".join(
                    [
                        "cargo:rustc-env=ISAHC_FEATURES=default,http2",
                        'cargo::rustc-cfg=feature="generated"',
                        "cargo:rustc-check-cfg=cfg(wasm)",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            directives = _parse_cargo_build_script_directives(str(Path(tmp)))
        self.assertEqual(directives["env"], {"ISAHC_FEATURES": "default,http2"})
        self.assertEqual(directives["cfg"], ['feature="generated"'])
        self.assertEqual(directives["check_cfg"], ["cfg(wasm)"])

    def test_collect_root_direct_externs_uses_only_direct_dependencies(self):
        meta = {
            "packages": [
                {
                    "name": "demo",
                    "dependencies": [
                        {"name": "native-tls", "rename": ""},
                        {"name": "openssl-macros", "rename": "openssl_macros_alias"},
                    ],
                },
                {
                    "name": "native-tls",
                    "targets": [{"name": "native_tls", "kind": ["lib"]}],
                },
                {
                    "name": "openssl-macros",
                    "targets": [{"name": "openssl_macros", "kind": ["proc-macro"]}],
                },
            ]
        }
        extern_artifacts = {
            "native_tls": "/tmp/libnative_tls.rmeta",
            "openssl_macros": "/tmp/libopenssl_macros.so",
            "tokio": "/tmp/libtokio.rmeta",
        }
        direct = _collect_root_direct_externs(meta, meta["packages"][0], extern_artifacts)
        self.assertEqual(
            direct,
            {
                "native_tls": "/tmp/libnative_tls.rmeta",
                "openssl_macros_alias": "/tmp/libopenssl_macros.so",
            },
        )

    def test_collect_root_direct_externs_falls_back_to_rust_prefix_stripped_artifact(self):
        meta = {
            "packages": [
                {
                    "name": "demo",
                    "dependencies": [
                        {"name": "rust-ini", "rename": None},
                    ],
                }
            ]
        }
        extern_artifacts = {
            "ini": "/tmp/libini.rmeta",
            "maybe_uninit": "/tmp/libmaybe_uninit.rmeta",
        }
        direct = _collect_root_direct_externs(meta, meta["packages"][0], extern_artifacts)
        self.assertEqual(direct, {"ini": "/tmp/libini.rmeta"})

    def test_collect_root_direct_externs_falls_back_to_compact_artifact_name(self):
        meta = {
            "packages": [
                {
                    "name": "demo",
                    "dependencies": [
                        {"name": "md-5", "rename": None},
                    ],
                }
            ]
        }
        extern_artifacts = {
            "md5": "/tmp/libmd5.rmeta",
        }
        direct = _collect_root_direct_externs(meta, meta["packages"][0], extern_artifacts)
        self.assertEqual(direct, {"md5": "/tmp/libmd5.rmeta"})

    def test_collect_root_fingerprint_externs_selects_matching_duplicate_artifact(self):
        with TemporaryDirectory() as tmp:
            target_dir = Path(tmp) / "target"
            deps_dir = target_dir / "debug" / "deps"
            fingerprint_root = target_dir / "debug" / ".fingerprint"
            deps_dir.mkdir(parents=True)
            fingerprint_root.mkdir(parents=True)

            chosen_marker = "aaeb6473a0748fe6"
            other_marker = "9116e6ad759dce87"
            chosen_hash = int.from_bytes(bytes.fromhex(chosen_marker), byteorder="little")

            root_dir = fingerprint_root / "cargo-1111111111111111"
            root_dir.mkdir()
            (root_dir / "lib-cargo.json").write_text(
                json.dumps(
                    {
                        "features": json.dumps(["default", "vendored-libgit2"]),
                        "deps": [[1, "filetime", False, chosen_hash]],
                    }
                ),
                encoding="utf-8",
            )

            for suffix, marker in [
                ("b3e362f4eec845bc", other_marker),
                ("da0db7b6ca559847", chosen_marker),
            ]:
                fp_dir = fingerprint_root / f"filetime-{suffix}"
                fp_dir.mkdir()
                (fp_dir / "lib-filetime").write_text(marker, encoding="utf-8")
                (deps_dir / f"libfiletime-{suffix}.rlib").write_text("", encoding="utf-8")

            externs = _collect_root_fingerprint_externs(
                str(target_dir),
                str(deps_dir),
                "cargo",
                ["default", "vendored-libgit2"],
            )
            self.assertEqual(
                externs,
                {"filetime": str(deps_dir / "libfiletime-da0db7b6ca559847.rlib")},
            )

    def test_missing_rustc_private_component_detects_rustc_dev_hint(self):
        detail = """
error[E0463]: can't find crate for `rustc_driver`
= help: maybe you need to install the missing components with: `rustup component add rust-src rustc-dev llvm-tools-preview`
""".strip()
        self.assertTrue(_missing_rustc_private_component(detail))


class ExistentialInputTests(unittest.TestCase):
    def test_ffi_summary_resolves_header_fields(self):
        summary = resolve_ffi_summary("inflateGetHeader")
        self.assertIsNotNone(summary)
        param2 = summary["params"]["2"]
        self.assertEqual(param2["role"], "gzip_header")
        self.assertEqual(param2["fields"]["extra_max"]["state"], "pre")
        self.assertEqual(param2["fields"]["extra_len"]["state"], "post")

    def test_field_flow_extracts_header_object_and_fields(self):
        summary = resolve_ffi_summary("inflateGetHeader")
        flow = build_field_flow(
            chain_nodes=[
                {
                    "id": 1,
                    "labels": ["METHOD", "Rust"],
                    "name": "main",
                    "code": "fn main(){ let mut header = gz_header { extra_len: 0, extra_max: EXTRA_CAPTURE_BUF as c_uint }; inflateGetHeader(&mut stream, &mut header); }",
                }
            ],
            evidence_calls=[
                {
                    "id": 2,
                    "name": "inflateGetHeader",
                    "code": "inflateGetHeader",
                    "lang": "Rust",
                    "method": "main",
                }
            ],
            ffi_summaries={"inflateGetHeader": summary},
            value_env={"EXTRA_CAPTURE_BUF": 4},
            const_map={"EXTRA_CAPTURE_BUF": 4},
        )
        self.assertEqual(len(flow["objects"]), 1)
        self.assertIn("header", flow["objects"][0]["aliases"])
        facts = {fact["field"]: fact for fact in flow["field_facts"]}
        self.assertEqual(facts["extra_max"]["resolved_value"], 4)
        self.assertEqual(facts["extra_len"]["resolved_value"], 0)

    def test_assumed_large_input_can_exceed_resolved_max(self):
        trigger_model = {
            "state_rules": [
                {
                    "id": "large_extra_len",
                    "lhs": {
                        "field": "extra_len",
                        "state": "post",
                        "source": "symbolic",
                        "symbolic_var": "attacker_extra_len",
                    },
                    "op": ">",
                    "rhs": {
                        "field": "extra_max",
                        "state": "pre",
                        "source": "observed",
                    },
                    "lhs_constraints": [{"op": ">=", "value": 32}],
                }
            ]
        }
        chain_nodes = [
            {
                "id": 1,
                "labels": ["METHOD", "Rust"],
                "name": "main",
                "code": "fn main(){ let mut header = gz_header { extra_len: 0, extra_max: EXTRA_CAPTURE_BUF as c_uint }; inflateGetHeader(&mut stream, &mut header); }",
            }
        ]
        path_bundle = {
            "combined_constraints": [],
            "value_env": {"EXTRA_CAPTURE_BUF": 4},
            "const_map": {"EXTRA_CAPTURE_BUF": 4},
        }

        result = evaluate_state_semantics(
            trigger_model=trigger_model,
            chain_nodes=chain_nodes,
            evidence_calls=[
                {
                    "id": 2,
                    "name": "inflateGetHeader",
                    "code": "inflateGetHeader",
                    "lang": "Rust",
                    "method": "main",
                }
            ],
            path_bundle=path_bundle,
            solver=PathConstraintSolver(domain="octagon"),
        )

        self.assertEqual(result["status"], "sat")
        self.assertTrue(result["rules"][0]["used_assumption"])
        self.assertTrue(
            any(c.get("variable") == "attacker_extra_len" and c.get("operator") == ">" and c.get("value") == 4
                for c in result["rules"][0]["constraints_used"])
        )

    def test_observed_length_uses_solver_and_can_fail(self):
        trigger_model = {
            "state_rules": [
                {
                    "id": "bounded_len",
                    "lhs": {
                        "field": "extra_len",
                        "state": "post",
                        "source": "observed",
                        "symbolic_var": "observed_extra_len",
                    },
                    "op": ">",
                    "rhs": {
                        "field": "extra_max",
                        "state": "pre",
                        "source": "observed",
                    },
                }
            ]
        }
        chain_nodes = [
            {
                "id": 1,
                "labels": ["METHOD", "Rust"],
                "name": "main",
                "code": "fn main(){ let mut header = gz_header { extra_len: 4, extra_max: 8 }; inflateGetHeader(&mut stream, &mut header); }",
            }
        ]
        path_bundle = {
            "combined_constraints": [],
            "value_env": {},
            "const_map": {},
        }

        result = evaluate_state_semantics(
            trigger_model=trigger_model,
            chain_nodes=chain_nodes,
            evidence_calls=[
                {
                    "id": 2,
                    "name": "inflateGetHeader",
                    "code": "inflateGetHeader",
                    "lang": "Rust",
                    "method": "main",
                }
            ],
            path_bundle=path_bundle,
            solver=PathConstraintSolver(domain="octagon"),
        )

        self.assertEqual(result["status"], "unsat")
        self.assertFalse(result["rules"][0]["used_assumption"])

    def test_legacy_existential_inputs_still_compatible(self):
        trigger_model = {
            "existential_inputs": [
                {
                    "name": "legacy_large_extra_len",
                    "field": "extra_len",
                    "symbolic_var": "legacy_extra_len",
                    "use_observed_value": False,
                    "greater_than_field": "extra_max",
                    "target_operator": ">",
                    "min_value": 16,
                    "min_operator": ">=",
                }
            ]
        }
        chain_nodes = [
            {
                "id": 1,
                "labels": ["METHOD", "Rust"],
                "name": "main",
                "code": "fn main(){ let mut header = gz_header { extra_len: 0, extra_max: 8 }; inflateGetHeader(&mut stream, &mut header); }",
            }
        ]
        result = evaluate_state_semantics(
            trigger_model=trigger_model,
            chain_nodes=chain_nodes,
            evidence_calls=[
                {
                    "id": 2,
                    "name": "inflateGetHeader",
                    "code": "inflateGetHeader",
                    "lang": "Rust",
                    "method": "main",
                }
            ],
            path_bundle={"combined_constraints": [], "value_env": {}, "const_map": {}},
            solver=PathConstraintSolver(domain="octagon"),
        )
        self.assertEqual(result["status"], "sat")


class TriggerConditionRuleTests(unittest.TestCase):
    def setUp(self):
        self.chain_nodes = [
            {
                "id": 100,
                "labels": ["METHOD", "Rust"],
                "name": "decode_image",
                "code": (
                    "fn decode_image(info: ImageInfo) { "
                    "if info.kind == ImageKind::WebP { "
                    "let mut file = File::open(info.path.clone()).unwrap(); "
                    "let mut bytes = Vec::new(); "
                    "file.read_to_end(&mut bytes).unwrap(); "
                    "let decoder = Decoder::new(&bytes); "
                    "decoder.decode(); "
                    "} "
                    "}"
                ),
            }
        ]
        self.calls = [
            {
                "id": 1,
                "name": "File::open",
                "code": "File::open(info.path.clone())",
                "lang": "Rust",
                "method": "decode_image",
            },
            {
                "id": 2,
                "name": "read_to_end",
                "code": "file.read_to_end(&mut bytes)",
                "lang": "Rust",
                "method": "decode_image",
            },
            {
                "id": 3,
                "name": "Decoder::new",
                "code": "Decoder::new(&bytes)",
                "lang": "Rust",
                "method": "decode_image",
            },
            {
                "id": 4,
                "name": "decode",
                "code": "decoder.decode()",
                "lang": "Rust",
                "method": "decode_image",
            },
        ]

    def test_control_code_contains_hits_webp_branch(self):
        cond = {
            "type": "control_code_contains",
            "contains": ["WebP"],
        }
        control_nodes = [
            {
                "id": 11,
                "code": "if info.kind == ImageKind::WebP",
                "child_codes": ["Decoder::new(&bytes)"],
            }
        ]
        result = eval_condition(cond, self.calls, self.calls, chain_nodes=self.chain_nodes, control_nodes=control_nodes)
        self.assertTrue(result["ok"])

    def test_field_to_call_arg_tracks_struct_field_path(self):
        cond = {
            "type": "field_to_call_arg",
            "sink": {"name": "File::open", "lang": "Rust", "arg_index": 1},
            "source_field": "path",
        }
        result = eval_condition(cond, self.calls, self.calls, chain_nodes=self.chain_nodes, control_nodes=[])
        self.assertTrue(result["ok"])
        self.assertEqual(result["evidence"][0]["call_name"], "File::open")

    def test_io_to_call_arg_tracks_open_read_decoder_new(self):
        cond = {
            "type": "io_to_call_arg",
            "sink": {"name": "Decoder::new", "lang": "Rust", "arg_index": 1},
            "open_call": {"name": "File::open", "lang": "Rust"},
            "read_call": {"name_regex": "(^|::)read_to_end$", "lang": "Rust"},
            "sink_arg_index": 1,
            "read_buf_arg_index": 1,
            "same_method": True,
        }
        result = eval_condition(cond, self.calls, self.calls, chain_nodes=self.chain_nodes, control_nodes=[])
        self.assertTrue(result["ok"])
        self.assertEqual(result["evidence"][0]["sink_call_name"], "Decoder::new")

    def test_call_order_can_require_same_receiver(self):
        cond = {
            "type": "call_order",
            "first": {"name": "Decoder::new", "lang": "Rust"},
            "second": {"name_regex": "(^|::)decode$", "lang": "Rust"},
            "same_method": True,
            "require_same_receiver": True,
        }
        result = eval_condition(cond, self.calls, self.calls, chain_nodes=self.chain_nodes, control_nodes=[])
        self.assertTrue(result["ok"])
        self.assertEqual(result["evidence"][0]["first_call_name"], "Decoder::new")

    def test_api_sequence_matches_ordered_calls(self):
        cond = {
            "type": "api_sequence",
            "steps": [
                {"name": "File::open"},
                {"name": "read_to_end"},
                {"name": "Decoder::new"},
                {"name": "decode"},
            ],
            "same_method": True,
        }
        result = eval_condition(cond, self.calls, self.calls, chain_nodes=self.chain_nodes, control_nodes=[])
        self.assertTrue(result["ok"])

    def test_len_to_call_arg_matches_len_expression(self):
        chain_nodes = [
            {
                "id": 200,
                "labels": ["METHOD", "Rust"],
                "name": "send_buf",
                "code": "fn send_buf(buf: Vec<u8>) { native_send(buf.as_ptr(), buf.len()); }",
            }
        ]
        calls = [
            {
                "id": 10,
                "name": "native_send",
                "code": "native_send(buf.as_ptr(), buf.len())",
                "lang": "Rust",
                "method": "send_buf",
            }
        ]
        cond = {
            "type": "len_to_call_arg",
            "sink": {"name": "native_send", "lang": "Rust", "arg_index": 2},
            "source_var": "buf",
        }
        result = eval_condition(cond, calls, calls, chain_nodes=chain_nodes, control_nodes=[])
        self.assertTrue(result["ok"])

    def test_option_to_call_arg_matches_option_unwrap_flow(self):
        chain_nodes = [
            {
                "id": 300,
                "labels": ["METHOD", "Rust"],
                "name": "revparse_entry",
                "code": (
                    "fn revparse_entry(args: Args, repo: Repo) { "
                    "let base = args.base.as_deref(); "
                    "repo.revparse_single(base.unwrap()); "
                    "}"
                ),
            }
        ]
        calls = [
            {
                "id": 20,
                "name": "revparse_single",
                "code": "repo.revparse_single(base.unwrap())",
                "lang": "Rust",
                "method": "revparse_entry",
            }
        ]
        cond = {
            "type": "option_to_call_arg",
            "sink": {"name": "revparse_single", "lang": "Rust", "arg_index": 1},
        }
        result = eval_condition(cond, calls, calls, chain_nodes=chain_nodes, control_nodes=[])
        self.assertTrue(result["ok"])

    def test_option_to_call_arg_can_use_assumption_when_enabled(self):
        chain_nodes = [
            {
                "id": 301,
                "labels": ["METHOD", "Rust"],
                "name": "revparse_entry",
                "code": "fn revparse_entry(repo: Repo, arg:&str) { repo.revparse_single(arg); }",
            }
        ]
        calls = [
            {
                "id": 21,
                "name": "revparse_single",
                "code": "repo.revparse_single(arg)",
                "lang": "Rust",
                "method": "revparse_entry",
            }
        ]
        cond = {
            "type": "option_to_call_arg",
            "sink": {"name": "revparse_single", "lang": "Rust", "arg_index": 1},
            "allow_assume_if_no_direct": True,
            "assumption_reason": "unit_test_assumption",
        }
        result = eval_condition(cond, calls, calls, chain_nodes=chain_nodes, control_nodes=[])
        self.assertTrue(result["ok"])
        self.assertTrue(result["evidence"][0]["assumed"])

    def test_builder_flag_chain_matches_setter_calls(self):
        calls = [
            {"id": 1, "name": "jit", "code": "builder.jit(true)", "lang": "Rust", "method": "compile"},
            {"id": 2, "name": "utf", "code": "builder.utf(true)", "lang": "Rust", "method": "compile"},
            {"id": 3, "name": "build", "code": "builder.build(pattern)", "lang": "Rust", "method": "compile"},
        ]
        cond = {
            "type": "builder_flag_chain",
            "sink": {"name": "build", "lang": "Rust"},
            "setters": [{"name": "jit"}, {"name": "utf"}],
            "same_method": True,
            "require_same_receiver": True,
        }
        result = eval_condition(cond, calls, calls, chain_nodes=[], control_nodes=[])
        self.assertTrue(result["ok"])


class RuleNormalizationAndResultTests(unittest.TestCase):
    def test_match_call_name_supports_qualified_suffix(self):
        self.assertTrue(
            _match_call_name(
                "git2::Repository::revparse_single",
                ["revparse_single"],
                "",
            )
        )
        self.assertTrue(
            _match_call_name(
                "revparse_single",
                ["git2::Repository::revparse_single"],
                "",
            )
        )

    def test_collect_rust_sink_candidates_includes_symbols_and_conditions(self):
        rule = {
            "symbols": ["git_revparse_single"],
            "rust_sinks": [{"path": "git2::Repository::revparse_ext"}],
            "trigger_model": {
                "conditions": [
                    {"type": "call", "name": "cocogitto::CocoGitto::get_changelog_at_tag", "lang": "Rust"}
                ]
            },
        }
        sinks = collect_rust_sink_candidates(rule)
        tokens = [spec["token"].lower() for spec in sinks]
        raws = [spec["raw"].lower() for spec in sinks]
        self.assertIn("revparse_single", tokens)
        self.assertIn("revparse_ext", tokens)
        self.assertNotIn("get_changelog_at_tag", raws)

    def test_collect_rust_sink_candidates_preserves_name_regex_conditions(self):
        rule = {
            "trigger_model": {
                "conditions": [
                    {
                        "type": "call_code_contains",
                        "name_regex": "(?i)(^|::)decode$",
                        "lang": "Rust",
                        "contains": ["packet"],
                        "contains_all": False,
                    }
                ]
            },
        }
        sinks = collect_rust_sink_candidates(rule)
        self.assertTrue(any(spec.get("name_regex") == "(?i)(^|::)decode$" for spec in sinks))

    def test_synthesize_sink_calls_from_method_code_and_merge(self):
        chain_nodes = [
            {
                "id": 42,
                "labels": ["METHOD", "Rust"],
                "name": "resolve_explicit_base",
                "code": "fn resolve_explicit_base(repo:&Repo, base:&str){ let (obj, r) = repo.raw().revparse_ext(base)?; }",
            }
        ]
        synthetic = synthesize_sink_calls_from_method_code(chain_nodes, ["revparse_ext"])
        self.assertEqual(len(synthetic), 1)
        self.assertEqual(synthetic[0]["name"], "revparse_ext")

        merged = merge_evidence_calls({"chain_calls": [], "all_calls": []}, synthetic)
        self.assertEqual(len(merged["all_calls"]), 1)
        self.assertEqual(merged["all_calls"][0]["name"], "revparse_ext")

    def test_synthesize_sink_calls_from_method_code_supports_name_regex(self):
        chain_nodes = [
            {
                "id": 7,
                "labels": ["METHOD", "Rust"],
                "name": "decode_video",
                "code": "fn decode_video(decoder:&Decoder, packet:&[u8]){ let _ = decoder.decode(packet); }",
            }
        ]
        synthetic = synthesize_sink_calls_from_method_code(
            chain_nodes,
            [
                {
                    "name_regex": "(?i)(^|::)decode$",
                    "contains": ["packet"],
                    "contains_all": False,
                }
            ],
        )
        self.assertEqual(len(synthetic), 1)
        self.assertIn("decode", synthetic[0]["code"])

    def test_has_actionable_trigger_hits(self):
        trigger_hits = {
            "required_hits": [
                {
                    "id": "rust_sink_revparse_single",
                    "evidence": [{"name": "revparse_single", "lang": "Rust"}],
                }
            ]
        }
        self.assertTrue(has_actionable_trigger_hits(trigger_hits))

    def test_missing_mandatory_trigger_guard_ids_flags_zlib_api_sequence(self):
        trigger_hits = {
            "required_hits": [{"id": "zlib_gzip_input"}],
            "required_miss": [{"id": "zlib_api_sequence"}],
        }
        self.assertEqual(
            _missing_mandatory_trigger_guard_ids("zlib", trigger_hits),
            ["zlib_api_sequence"],
        )
        self.assertEqual(_missing_mandatory_trigger_guard_ids("libwebp", trigger_hits), [])

    def test_is_freetype_package_only_wrapper_reachability(self):
        self.assertTrue(_is_freetype_package_only_wrapper_reachability("freetype", "rust_call_package"))
        self.assertFalse(_is_freetype_package_only_wrapper_reachability("freetype2", "rust_call_package"))
        self.assertFalse(_is_freetype_package_only_wrapper_reachability("freetype", "rust_method_code_package"))

    def test_collect_source_synthetic_sink_calls(self):
        with TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            (src_dir / "lib.rs").write_text(
                "pub fn run(repo:&Repo,arg:&str){ let _ = repo.revparse_single(arg); }",
                encoding="utf-8",
            )
            calls = collect_source_synthetic_sink_calls(tmp, ["git2::Repository::revparse_single"])
            self.assertTrue(calls)
            self.assertEqual(calls[0]["name"], "revparse_single")

    def test_collect_source_synthetic_sink_calls_ignores_extern_declarations(self):
        with TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            (src_dir / "bindings.rs").write_text(
                'extern "C" {\n    pub fn FT_New_Face(library: FT_Library) -> FT_Error;\n}\n',
                encoding="utf-8",
            )
            calls = collect_source_synthetic_sink_calls(tmp, ["FT_New_Face"])
            self.assertEqual(calls, [])

    def test_collect_source_synthetic_sink_calls_skips_non_runtime_sources_by_default(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "examples").mkdir(parents=True, exist_ok=True)
            (root / "tests").mkdir(parents=True, exist_ok=True)
            (root / "src" / "lib.rs").write_text("pub fn api() {}\n", encoding="utf-8")
            (root / "examples" / "demo.rs").write_text(
                "fn main(){ unsafe { FT_Load_Glyph(face, glyph, flags); } }\n",
                encoding="utf-8",
            )
            (root / "tests" / "integration.rs").write_text(
                "fn test_case(){ unsafe { FT_Load_Glyph(face, glyph, flags); } }\n",
                encoding="utf-8",
            )
            (root / "build.rs").write_text(
                "fn main(){ unsafe { FT_Load_Glyph(face, glyph, flags); } }\n",
                encoding="utf-8",
            )

            calls = collect_source_synthetic_sink_calls(tmp, ["FT_Load_Glyph"])

        self.assertEqual(calls, [])

    def test_synthesize_sink_calls_from_method_code_ignores_binding_declarations(self):
        chain_nodes = [
            {
                "id": 11,
                "labels": ["METHOD", "Rust"],
                "name": "FT_New_Face",
                "code": "pub fn FT_New_Face(library: FT_Library, face: *mut FT_Face) -> FT_Error;",
            },
            {
                "id": 12,
                "labels": ["METHOD", "Rust"],
                "name": "load",
                "code": "pub fn load(face: FT_Face){ unsafe { FT_Load_Glyph(face, 0, 0); } }",
            },
        ]
        synthetic = synthesize_sink_calls_from_method_code(chain_nodes, ["FT_New_Face", "FT_Load_Glyph"])
        self.assertEqual(len(synthetic), 1)
        self.assertEqual(synthetic[0]["name"], "FT_Load_Glyph")

    def test_collect_source_synthetic_sink_calls_respects_context_tokens_for_strings(self):
        with TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            (src_dir / "lib.rs").write_text(
                "\n".join(
                    [
                        "pub fn benign() { let _ = Path::new(\"/tmp/demo\"); }",
                        "pub fn dangerous(decoder: &Decoder, bytes: &[u8]) { let _ = Decoder::new(bytes).decode(); }",
                    ]
                ),
                encoding="utf-8",
            )
            calls = collect_source_synthetic_sink_calls(tmp, ["Decoder::new"])
            self.assertEqual(len(calls), 1)
            self.assertIn("Decoder::new", calls[0]["code"])

    def test_sink_spec_matches_jpeg_decoder_as_decompressor_wrapper(self):
        spec = collect_rust_sink_candidates({"rust_sinks": [{"path": "Decompressor::read_header"}]})[0]
        self.assertTrue(_sink_spec_matches_text(spec, "jpegturbo::JpegTurboDecoder::read_header"))

    def test_collect_libwebp_source_input_evidence_distinguishes_external_and_local_inputs(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_dir = root / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            (src_dir / "upload.rs").write_text(
                "\n".join(
                    [
                        "use actix_multipart::Multipart;",
                        "async fn upload_handler(mut body: Multipart) {",
                        "    while let Some(chunk) = field.next().await {",
                        "        let data = chunk.unwrap();",
                        "    }",
                        "    let img = ImageReader::open(path)?.decode()?;",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (src_dir / "assets.rs").write_text(
                "\n".join(
                    [
                        "fn render(asset_path: PathBuf, webp_path: PathBuf) {",
                        "    if !Path::new(&webp_path).exists() {",
                        "        let img = ImageReader::open(asset_path)?.decode()?;",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            evidence = collect_libwebp_source_input_evidence(str(root))
            self.assertEqual(evidence["status"], "external_controlled")
            statuses = {site["status"] for site in evidence["sites"]}
            self.assertIn("external_controlled", statuses)
            self.assertIn("local_asset_only", statuses)

    def test_collect_libwebp_source_input_evidence_marks_png_jpeg_to_webp_encode_only(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_dir = root / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            (src_dir / "lib.rs").write_text(
                "\n".join(
                    [
                        "fn webp(contents: &[u8], mime_essence: &str) -> Option<Vec<u8>> {",
                        "    let cursor = Cursor::new(contents);",
                        "    let mut reader = image::ImageReader::new(cursor);",
                        "    reader.set_format(match mime_essence {",
                        "        \"image/png\" => ImageFormat::Png,",
                        "        \"image/jpeg\" => ImageFormat::Jpeg,",
                        "        _ => return None,",
                        "    });",
                        "    let image = reader.decode().ok()?;",
                        "    let encoder = webp::Encoder::from_image(&image).ok()?;",
                        "    Some(encoder.encode_lossless().to_vec())",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            evidence = collect_libwebp_source_input_evidence(str(root))
        self.assertEqual(evidence["status"], "non_webp_encode_only")
        self.assertEqual(evidence["sites"][0]["status"], "non_webp_encode_only")

    def test_effective_wrapper_sink_evidence_requires_external_control_for_libwebp(self):
        self.assertTrue(
            effective_wrapper_sink_evidence(
                "libwebp",
                True,
                {"status": "external_controlled"},
            )
        )
        self.assertFalse(
            effective_wrapper_sink_evidence(
                "libwebp",
                True,
                {"status": "local_asset_only"},
            )
        )
        self.assertFalse(
            effective_wrapper_sink_evidence(
                "libwebp",
                True,
                {"status": "sink_only"},
            )
        )
        self.assertTrue(
            effective_wrapper_sink_evidence(
                "openssl",
                True,
                {"status": "local_asset_only"},
            )
        )

    def test_should_exclude_libwebp_non_webp_encode_only(self):
        self.assertTrue(
            _should_exclude_libwebp_non_webp_encode_only(
                "libwebp",
                {"status": "non_webp_encode_only"},
            )
        )
        self.assertFalse(
            _should_exclude_libwebp_non_webp_encode_only(
                "libwebp",
                {"status": "external_controlled"},
            )
        )
        self.assertFalse(
            _should_exclude_libwebp_non_webp_encode_only(
                "openssl",
                {"status": "non_webp_encode_only"},
            )
        )

    def test_normalize_vuln_rule_compiles_high_level_fields(self):
        vuln = {
            "cve": "CVE-TEST-0001",
            "package": "libwebp",
            "version_range": "<1.3.2",
            "must_flow": [
                {"source": "ImageInfo.path", "sink": "File::open.arg1"},
                {"source": "File::open.bytes", "sink": "Decoder::new.arg1"},
            ],
            "rust_guards": {"all": ["ImageType::from_mime(mime) == Webp"]},
            "prune": {"any": ["image_type constrained to Jpeg|Png"]},
        }
        normalized = normalize_vuln_rule(vuln)
        cond_types = [c.get("type") for c in normalized["trigger_model"]["conditions"]]
        self.assertIn("field_to_call_arg", cond_types)
        self.assertIn("io_to_call_arg", cond_types)
        self.assertIn("all_of", cond_types)
        miti_types = [m.get("type") for m in normalized["trigger_model"]["mitigations"]]
        self.assertIn("any_of", miti_types)

    def test_normalize_must_flow_option_prefers_option_condition(self):
        vuln = {
            "cve": "CVE-TEST-OP",
            "package": "libgit2",
            "must_flow": ["Option<String>.as_deref -> revparse_ext.arg1"],
        }
        normalized = normalize_vuln_rule(vuln)
        cond_types = [c.get("type") for c in normalized["trigger_model"]["conditions"]]
        self.assertIn("option_to_call_arg", cond_types)

    def test_normalize_vuln_rule_does_not_force_rust_sinks_when_trigger_exists(self):
        vuln = {
            "cve": "CVE-TEST-NORM",
            "package": "pcre2-sys",
            "rust_sinks": [{"path": "grep_pcre2::RegexMatcherBuilder::build"}],
            "trigger_model": {
                "conditions": [
                    {"id": "engine_selected", "type": "call", "name": "matcher_pcre2", "lang": "Rust"}
                ]
            },
        }
        normalized = normalize_vuln_rule(vuln)
        ids = [c.get("id") for c in normalized["trigger_model"]["conditions"]]
        self.assertIn("engine_selected", ids)
        self.assertNotIn("rust_sink_build", ids)
        self.assertEqual(normalized["rule_compile_meta"]["compiled_rust_sink_conditions"], 0)

    def test_auto_generated_pcre2_rule_tracks_scan_substring_match_path(self):
        rule = generate_vulns_payload({"family": "pcre2", "project": "pomsky-bin"})[0]
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("pcre2::bytes::Regex::captures", sink_paths)
        self.assertEqual(rule["cve"], "CVE-2025-58050")
        self.assertEqual(rule["version_range"], ">=10.45,<10.46")
        condition_ids = {cond["id"] for cond in rule["trigger_model"]["conditions"]}
        self.assertIn("pcre2_pattern_build", condition_ids)
        self.assertIn("pcre2_match_use", condition_ids)
        self.assertIn("pcre2_scan_substring_pattern", condition_ids)
        any_of = next(cond for cond in rule["trigger_model"]["conditions"] if cond["id"] == "pcre2_match_use")
        inner_ids = {cond["id"] for cond in any_of["conditions"]}
        self.assertIn("pcre2_regex_captures", inner_ids)

    def test_auto_generated_libjpeg_rule_includes_wrapper_decode_sink(self):
        rule = generate_vulns_payload({"family": "libjpeg-turbo", "project": "reduce_image_size"})[0]
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("turbojpeg::decompress_image", sink_paths)
        inner_names = {cond["name"] for cond in rule["trigger_model"]["conditions"][0]["conditions"]}
        self.assertIn("decompress_image", inner_names)

    def test_auto_generated_openh264_rule_filters_gstreamer_context(self):
        rule = generate_vulns_payload({"family": "openh264", "project": "jetkvm_client"})[0]
        generic_sink = next(sink for sink in rule["rust_sinks"] if sink["path"] == "Decoder::decode")
        self.assertEqual(generic_sink["context_tokens"], ["openh264"])
        self.assertIn("gstreamer", rule["input_predicate"]["negative_tokens"])

    def test_auto_generated_sqlite_rule_tracks_query_and_prepare_paths(self):
        rule = generate_vulns_payload({"family": "sqlite", "project": "reef"})[0]
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("rusqlite::Connection::query_row", sink_paths)
        self.assertIn("rusqlite::Connection::prepare", sink_paths)

    def test_auto_generated_libxml2_rule_tracks_parser_wrapper_and_input(self):
        rule = generate_vulns_payload({"family": "libxml2", "project": "fatoora-core"})[0]
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("Parser::parse_string", sink_paths)
        cond_ids = {cond["id"] for cond in rule["trigger_model"]["conditions"]}
        self.assertIn("libxml2_parse_entry", cond_ids)
        self.assertIn("libxml2_input", cond_ids)

    def test_auto_generated_libwebp_rule_tracks_direct_and_wrapper_decode(self):
        rule = generate_vulns_payload({"family": "libwebp", "project": "libwebp-image"})[0]
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("WebPDecodeRGBA", sink_paths)
        self.assertIn("webp_load_rgba_from_memory", sink_paths)
        cond_ids = {cond["id"] for cond in rule["trigger_model"]["conditions"]}
        self.assertIn("libwebp_decode_entry", cond_ids)
        self.assertIn("libwebp_input", cond_ids)

    def test_auto_generated_gdal_rule_tracks_dataset_open_and_input(self):
        rule = generate_vulns_payload({"family": "gdal", "project": "gdal"})[0]
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("Dataset::open", sink_paths)
        cond_ids = {cond["id"] for cond in rule["trigger_model"]["conditions"]}
        self.assertIn("gdal_dataset_entry", cond_ids)
        self.assertIn("gdal_input", cond_ids)

    def test_auto_generated_libarchive_rule_tracks_archive_iteration_and_input(self):
        rule = generate_vulns_payload({"family": "libarchive", "project": "pacfiles"})[0]
        self.assertEqual(rule["package"], "libarchive")
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("compress_tools::ArchiveIterator::from_read", sink_paths)
        self.assertIn("compress_tools::uncompress_archive_file", sink_paths)
        cond_ids = {cond["id"] for cond in rule["trigger_model"]["conditions"]}
        self.assertIn("libarchive_entry", cond_ids)
        self.assertIn("libarchive_input", cond_ids)

    def test_generic_auto_generated_family_rule_supports_curl(self):
        self.assertTrue(can_auto_generate({"family": "curl"}))
        rule = generate_vulns_payload({"family": "curl", "project": "downloader"})[0]
        self.assertEqual(rule["package"], "curl")
        self.assertEqual(rule["version_range"], ">=0")
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("Easy::perform", sink_paths)
        cond_ids = {cond["id"] for cond in rule["trigger_model"]["conditions"]}
        self.assertIn("curl_entry_any", cond_ids)
        self.assertIn("curl_input", cond_ids)

    def test_generic_auto_generated_family_rule_supports_libpng(self):
        self.assertTrue(can_auto_generate({"family": "libpng"}))
        rule = generate_vulns_payload({"family": "libpng", "project": "png-reader"})[0]
        self.assertEqual(rule["package"], "libpng")
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("png_image_begin_read_from_memory", sink_paths)
        self.assertIn("png_image_finish_read", sink_paths)
        self.assertEqual(rule["input_predicate"]["class"], "crafted_interlaced_16bit_png")

    def test_analyze_triggerability_can_use_synthetic_evidence_without_chain_nodes(self):
        trigger_model = {
            "conditions": [
                {"id": "caseless_enabled", "type": "call", "name": "caseless", "lang": "Rust"}
            ]
        }
        evidence = {
            "chain_calls": [],
            "all_calls": [
                {
                    "id": "srcsynthetic:a.rs:12:caseless",
                    "name": "caseless",
                    "code": "builder.caseless(true)",
                    "lang": "Rust",
                    "method": "a.rs:12",
                    "scope": "synthetic_source_text",
                }
            ],
        }
        out = analyze_triggerability(
            session=None,
            chain_nodes=[],
            trigger_model=trigger_model,
            source_patterns=[],
            sanitizer_patterns=[],
            context_keywords=[],
            control_nodes=[],
            evidence_calls_override=evidence,
        )
        self.assertEqual(out["triggerable"], "possible")
        self.assertTrue(
            any("No explicit call-chain path" in note for note in out["evidence_notes"])
        )

    def test_evaluate_env_guards_supports_version_source_feature(self):
        vuln = {
            "package": "libwebp",
            "version_range": "<1.3.2",
            "env_guards": {
                "all": [
                    {"type": "component_source", "expected": "bundled"},
                    {"type": "feature_enabled", "feature": "simd"},
                ]
            },
        }
        package_metadata = {
            "libwebp": {
                "versions": ["1.3.1"],
                "sources": ["bundled"],
                "features": ["simd", "decoder"],
                "langs": ["C"],
            }
        }
        package_versions = {"libwebp": ["1.3.1"]}
        eval_res = evaluate_env_guards(vuln, package_metadata, package_versions)
        self.assertEqual(eval_res["status"], "satisfied")
        self.assertTrue(eval_res["satisfied"])
        self.assertFalse(eval_res["failed"])

    def test_evaluate_env_guards_does_not_fallback_to_wrapper_crate_version_for_native_component(self):
        vuln = {"package": "libaom", "version_range": "<3.7.1"}
        package_metadata = {
            "libaom": {
                "versions": ["0.3.2"],
                "sources": ["cargo_lock"],
                "features": [],
                "langs": ["Rust"],
            }
        }
        package_versions = {"libaom": ["0.3.2"]}
        component_instances = [
            {
                "component": "libaom",
                "status": "unknown",
                "resolved_version": None,
                "source": "unknown",
                "matched_crates": [{"crate": "libaom", "versions": ["0.3.2"]}],
            }
        ]

        eval_res = evaluate_env_guards(
            vuln,
            package_metadata,
            package_versions,
            component_instances=component_instances,
        )

        self.assertEqual(eval_res["status"], "unknown")
        version_items = [item for item in eval_res["unresolved"] if item.get("kind") == "version_range"]
        self.assertEqual(version_items[0]["detail"]["reason"], "missing_component_version")

    def test_map_result_kind_and_assumption_evidence(self):
        vuln = {
            "input_predicate": {
                "class": "crafted_webp_lossless",
                "strategy": "assume_if_not_explicit",
            }
        }
        assumptions = collect_assumption_evidence(
            vuln_rule=vuln,
            existential_input_result={"rules": []},
            path_bundle={"boundary_assumptions": []},
        )
        self.assertTrue(assumptions)
        kind = map_result_kind("confirmed", True, assumptions)
        self.assertEqual(kind, "TriggerableWithInputAssumption")

    def test_explicit_input_evidence_is_not_treated_as_assumption(self):
        vuln = {
            "input_predicate": {
                "class": "crafted_x509_certificate",
                "strategy": "assume_if_not_explicit",
            }
        }
        assumptions = collect_assumption_evidence(
            vuln_rule=vuln,
            existential_input_result={"rules": []},
            path_bundle={"boundary_assumptions": []},
            input_predicate_eval={
                "status": "satisfied",
                "positive_hits": ["tls", "x509"],
                "evidence_strength": "explicit_token",
            },
        )
        self.assertEqual(assumptions, [])

    def test_strict_confirmed_gate_requires_full_trigger_and_explicit_input(self):
        trigger_hits = {
            "required_hits": [{"id": "openssl_handshake_any"}, {"id": "openssl_x509_input"}],
            "required_miss": [],
            "mitigations_hit": [],
        }
        self.assertTrue(
            should_mark_possible_as_confirmed(
                package_name="openssl",
                cargo_dir="",
                reachable=True,
                triggerable="possible",
                trigger_hits=trigger_hits,
                input_predicate_eval={
                    "status": "satisfied",
                    "positive_hits": ["tls", "x509"],
                    "evidence_strength": "explicit_token",
                },
                call_reachability_source="rust_call_package",
                explicit_native_symbol_bridge=False,
                transitive_native_symbol_bridge=False,
                gateway_bridge_evidence=True,
                strict_callsite_edges=0,
                native_analysis_coverage="target_only_incomplete",
            )
        )
        self.assertFalse(
            should_mark_possible_as_confirmed(
                package_name="openssl",
                cargo_dir="",
                reachable=True,
                triggerable="possible",
                trigger_hits={**trigger_hits, "required_miss": [{"id": "openssl_x509_input"}]},
                input_predicate_eval={
                    "status": "satisfied",
                    "positive_hits": ["tls", "x509"],
                    "evidence_strength": "explicit_token",
                },
                call_reachability_source="rust_call_package",
                explicit_native_symbol_bridge=False,
                transitive_native_symbol_bridge=False,
                gateway_bridge_evidence=True,
                strict_callsite_edges=0,
                native_analysis_coverage="target_only_incomplete",
            )
        )

    def test_strict_confirmed_gate_confirms_ffmpeg_direct_media_input(self):
        trigger_hits = {
            "required_hits": [{"id": "ffmpeg_input"}],
            "required_miss": [],
            "mitigations_hit": [],
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text(
                """
pub fn open_media(path: &str) {
    let _ = std::fs::File::open(path);
    let _ctx = ffmpeg::format::input(path);
}
""".strip(),
                encoding="utf-8",
            )
            self.assertTrue(
                should_mark_possible_as_confirmed(
                    package_name="ffmpeg",
                    cargo_dir=str(root),
                    reachable=True,
                    triggerable="possible",
                    trigger_hits=trigger_hits,
                    input_predicate_eval={
                        "status": "satisfied",
                        "positive_hits": ["ffmpeg", "stream", "avformat"],
                        "evidence_strength": "explicit_token",
                    },
                    call_reachability_source="rust_call_package",
                    explicit_native_symbol_bridge=True,
                    transitive_native_symbol_bridge=False,
                    gateway_bridge_evidence=False,
                    strict_callsite_edges=0,
                    native_analysis_coverage="target_only_incomplete",
                )
            )

    def test_strict_confirmed_gate_rejects_ffmpeg_without_explicit_media_input_path(self):
        trigger_hits = {
            "required_hits": [{"id": "ffmpeg_input"}],
            "required_miss": [],
            "mitigations_hit": [],
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text(
                """
pub fn transcode_frame() {
    let _ctx = ffmpeg::format::output("out.mp4");
}
""".strip(),
                encoding="utf-8",
            )
            self.assertFalse(
                should_mark_possible_as_confirmed(
                    package_name="ffmpeg",
                    cargo_dir=str(root),
                    reachable=True,
                    triggerable="possible",
                    trigger_hits=trigger_hits,
                    input_predicate_eval={
                        "status": "satisfied",
                        "positive_hits": ["ffmpeg", "stream", "avformat"],
                        "evidence_strength": "explicit_token",
                    },
                    call_reachability_source="rust_call_package",
                    explicit_native_symbol_bridge=True,
                    transitive_native_symbol_bridge=False,
                    gateway_bridge_evidence=False,
                    strict_callsite_edges=0,
                    native_analysis_coverage="target_only_incomplete",
                )
            )

    def test_strict_confirmed_gate_confirms_ffmpeg_imported_input_call_with_path(self):
        trigger_hits = {
            "required_hits": [{"id": "ffmpeg_input"}],
            "required_miss": [],
            "mitigations_hit": [],
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text(
                """
use ffmpeg::format::{context::Input, input};
use std::path::Path;

pub fn open_media(path: &Path) {
    let _ctx = input(&path);
}
""".strip(),
                encoding="utf-8",
            )
            self.assertTrue(
                should_mark_possible_as_confirmed(
                    package_name="ffmpeg",
                    cargo_dir=str(root),
                    reachable=True,
                    triggerable="possible",
                    trigger_hits=trigger_hits,
                    input_predicate_eval={
                        "status": "satisfied",
                        "positive_hits": ["ffmpeg", "stream"],
                        "evidence_strength": "explicit_token",
                    },
                    call_reachability_source="rust_call_package",
                    explicit_native_symbol_bridge=True,
                    transitive_native_symbol_bridge=False,
                    gateway_bridge_evidence=False,
                    strict_callsite_edges=0,
                    native_analysis_coverage="target_only_incomplete",
                )
            )

    def test_strict_confirmed_gate_confirms_libtiff_decode_path(self):
        trigger_hits = {
            "required_hits": [{"id": "libtiff_input"}],
            "required_miss": [],
            "mitigations_hit": [],
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text(
                """
use image::ImageReader;

pub fn read_tiff() {
    let _img = ImageReader::open("sample.tiff").unwrap().decode().unwrap();
}
""".strip(),
                encoding="utf-8",
            )
            self.assertTrue(
                should_mark_possible_as_confirmed(
                    package_name="libtiff",
                    cargo_dir=str(root),
                    reachable=True,
                    triggerable="possible",
                    trigger_hits=trigger_hits,
                    input_predicate_eval={
                        "status": "satisfied",
                        "positive_hits": ["tiff", "image", "decode"],
                        "evidence_strength": "explicit_token",
                    },
                    call_reachability_source="rust_call_package",
                    explicit_native_symbol_bridge=True,
                    transitive_native_symbol_bridge=False,
                    gateway_bridge_evidence=False,
                    strict_callsite_edges=0,
                    native_analysis_coverage="target_only_incomplete",
                )
            )

    def test_strict_confirmed_gate_confirms_libjpeg_runtime_decode_library(self):
        trigger_hits = {
            "required_hits": [{"id": "jpeg_header_any"}, {"id": "jpeg_input"}],
            "required_miss": [],
            "mitigations_hit": [],
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text(
                """
pub fn decode_jpeg(jpeg_data: &[u8]) {
    let mut decompressor = turbojpeg::Decompressor::new().unwrap();
    let _ = decompressor.read_header(&jpeg_data).unwrap();
    let _ = decompressor.decompress(&jpeg_data, &mut []);
}
""".strip(),
                encoding="utf-8",
            )
            self.assertTrue(
                should_mark_possible_as_confirmed(
                    package_name="libjpeg-turbo",
                    cargo_dir=str(root),
                    reachable=True,
                    triggerable="possible",
                    trigger_hits=trigger_hits,
                    input_predicate_eval={
                        "status": "satisfied",
                        "positive_hits": ["jpeg", "turbojpeg", "image", "decompress"],
                        "evidence_strength": "explicit_token",
                    },
                    call_reachability_source="rust_call_package",
                    explicit_native_symbol_bridge=True,
                    transitive_native_symbol_bridge=False,
                    gateway_bridge_evidence=False,
                    strict_callsite_edges=0,
                    native_analysis_coverage="target_only_incomplete",
                )
            )

    def test_strict_confirmed_gate_confirms_pcre2_jit_builder_when_named_guard_is_missing(self):
        trigger_hits = {
            "required_hits": [{"id": "pcre2_pattern_input"}],
            "required_miss": [{"id": "pcre2_build"}],
            "mitigations_hit": [],
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text(
                """
pub fn build_matcher(pat: &str) {
    let mut builder = Pcre2MatcherBuilder::new();
    builder.jit_if_available(true);
    let _ = builder.build(pat);
}
""".strip(),
                encoding="utf-8",
            )
            self.assertTrue(
                should_mark_possible_as_confirmed(
                    package_name="pcre2",
                    cargo_dir=str(root),
                    reachable=True,
                    triggerable="possible",
                    trigger_hits=trigger_hits,
                    input_predicate_eval={
                        "status": "satisfied",
                        "positive_hits": ["match", "compile"],
                        "evidence_strength": "explicit_token",
                    },
                    call_reachability_source="rust_method_code_root",
                    explicit_native_symbol_bridge=False,
                    transitive_native_symbol_bridge=False,
                    gateway_bridge_evidence=True,
                    strict_callsite_edges=0,
                    native_analysis_coverage="target_only_incomplete",
                )
            )

    def test_strict_confirmed_gate_confirms_libwebp_runtime_decode_wrapper(self):
        trigger_hits = {
            "required_hits": [],
            "required_miss": [
                {"id": "webp_decode_sequence"},
                {"id": "webp_branch_guard"},
                {"id": "must_flow_field_0"},
                {"id": "must_flow_io_1"},
            ],
            "mitigations_hit": [],
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text(
                """
pub struct Decoder<'a> { data: &'a [u8] }

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self { Self { data } }
    pub fn decode(&self) {
        unsafe {
            WebPDecodeRGBA(self.data.as_ptr(), self.data.len(), std::ptr::null_mut(), std::ptr::null_mut());
        }
    }
}

pub fn run(webp: &[u8]) {
    Decoder::new(&webp).decode();
}
""".strip(),
                encoding="utf-8",
            )
            self.assertTrue(
                should_mark_possible_as_confirmed(
                    package_name="libwebp",
                    cargo_dir=str(root),
                    reachable=True,
                    triggerable="possible",
                    trigger_hits=trigger_hits,
                    input_predicate_eval={
                        "status": "satisfied",
                        "positive_hits": ["webp", "image", "decode", "frame"],
                        "evidence_strength": "explicit_token",
                    },
                    call_reachability_source="rust_call_package",
                    explicit_native_symbol_bridge=True,
                    transitive_native_symbol_bridge=False,
                    gateway_bridge_evidence=False,
                    strict_callsite_edges=0,
                    native_analysis_coverage="target_only_incomplete",
                )
            )

    def test_strict_confirmed_gate_accepts_gstreamer_runtime_uri_input_without_token_evidence(self):
        trigger_hits = {
            "required_hits": [{"id": "gst_launch_any"}, {"id": "gst_media_input"}],
            "required_miss": [],
            "mitigations_hit": [],
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text(
                """
use gstreamer::ElementFactory;

pub fn load(input_uri: &str) {
    let player = ElementFactory::make("playbin", None).unwrap();
    player.set_property("uri", &input_uri).unwrap();
}
""".strip(),
                encoding="utf-8",
            )
            self.assertTrue(
                should_mark_possible_as_confirmed(
                    package_name="gstreamer",
                    cargo_dir=str(root),
                    reachable=True,
                    triggerable="possible",
                    trigger_hits=trigger_hits,
                    input_predicate_eval={
                        "status": "satisfied",
                        "positive_hits": ["video", "stream"],
                        "evidence_strength": "assumption_required",
                    },
                    call_reachability_source="rust_native_gateway_package",
                    explicit_native_symbol_bridge=False,
                    transitive_native_symbol_bridge=False,
                    gateway_bridge_evidence=True,
                    strict_callsite_edges=0,
                    native_analysis_coverage="none",
                )
            )

    def test_strict_confirmed_gate_accepts_openssl_runtime_handshake_without_token_evidence(self):
        trigger_hits = {
            "required_hits": [{"id": "openssl_handshake_any"}, {"id": "openssl_x509_input"}],
            "required_miss": [],
            "mitigations_hit": [],
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text(
                """
pub struct TlsConnector(native_tls::TlsConnector);

impl TlsConnector {
    pub async fn connect<S>(&self, domain: &str, stream: S) -> Result<(), native_tls::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        handshake(move |s| self.0.connect(domain, s), stream).await
    }
}
""".strip(),
                encoding="utf-8",
            )
            self.assertTrue(
                should_mark_possible_as_confirmed(
                    package_name="openssl",
                    cargo_dir=str(root),
                    reachable=True,
                    triggerable="possible",
                    trigger_hits=trigger_hits,
                    input_predicate_eval={
                        "status": "satisfied",
                        "positive_hits": ["tls", "x509"],
                        "evidence_strength": "assumption_required",
                    },
                    call_reachability_source="rust_native_gateway_package",
                    explicit_native_symbol_bridge=False,
                    transitive_native_symbol_bridge=False,
                    gateway_bridge_evidence=True,
                    strict_callsite_edges=0,
                    native_analysis_coverage="target_only_incomplete",
                )
            )

    def test_collect_assumption_evidence_ignores_cli_decode_input_for_libwebp(self):
        vuln = {
            "input_predicate": {
                "class": "crafted_webp_lossless",
                "strategy": "assume_if_not_explicit",
            }
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "lib.rs").write_text(
                """
use std::fs::File;
use std::io::Read;
use std::path::Path;
use clap::ArgMatches;

pub fn decode<P: AsRef<Path>>(f: P) {
    let mut file = File::open(f.as_ref()).unwrap();
    let mut buf = vec![];
    file.read_to_end(&mut buf).unwrap();
    let decoder = AnimDecoder::new(&buf);
    let _ = decoder.decode();
}
""".strip(),
                encoding="utf-8",
            )
            assumptions = collect_assumption_evidence(
                vuln_rule=vuln,
                existential_input_result={"rules": []},
                path_bundle={"boundary_assumptions": []},
                input_predicate_eval={
                    "status": "satisfied",
                    "positive_hits": ["webp", "image", "decode"],
                    "evidence_strength": "assumption_required",
                },
                package_name="libwebp",
                cargo_dir=str(root),
                external_input_evidence={"status": "not_observed", "sites": []},
            )
            self.assertEqual(assumptions, [])

    def test_map_result_kind_prefers_manual_trigger_status(self):
        self.assertEqual(
            map_result_kind("confirmed", True, [], manual_status="observable_triggered"),
            "ObservableTriggered",
        )
        self.assertEqual(
            map_result_kind("confirmed", True, [], manual_status="path_triggered"),
            "PathTriggered",
        )

    def test_manual_evidence_selection_and_application(self):
        entries = [
            {
                "cve": "CVE-2023-4863",
                "package": "libwebp",
                "symbol": "WebPDecodeRGBA",
                "status": "observable_triggered",
                "summary": "ASan heap-buffer-overflow in VP8LBuildHuffmanTable",
            }
        ]
        matched = select_manual_evidence(
            entries,
            cve="CVE-2023-4863",
            package="libwebp-sys2",
            symbol="WebPDecodeRGBA",
        )
        self.assertIsNotNone(matched)
        entry = {
            "reachable": True,
            "triggerable": "possible",
            "triggerable_internal": "possible",
            "trigger_confidence": "medium",
            "assumptions_used": [],
            "evidence_notes": [],
            "result_kind": "Reachable",
        }
        applied = apply_manual_evidence(entry, matched)
        self.assertEqual(applied["manual_trigger_status"], "observable_triggered")
        self.assertEqual(applied["triggerable"], "confirmed")
        self.assertEqual(applied["result_kind"], "ObservableTriggered")
        self.assertIn("Manual reproduction", applied["evidence_notes"][0])

    def test_summarize_guard_status_merges_trigger_and_env(self):
        trigger_hits = {
            "required_hits": [{"id": "a"}],
            "required_miss": [{"id": "b"}],
            "mitigations_hit": [{"id": "m"}],
        }
        env_eval = {
            "satisfied": [{"kind": "env_guard"}],
            "unresolved": [{"kind": "env_guard"}],
            "failed": [{"kind": "version_range"}],
        }
        summary = summarize_guard_status(trigger_hits, env_eval)
        self.assertIn("trigger:a", summary["satisfied_guards"])
        self.assertIn("trigger:b", summary["unresolved_guards"])
        self.assertIn("mitigation:m", summary["failed_guards"])

    def test_cross_language_native_evidence_requires_native_side_signal_for_system_sources(self):
        self.assertFalse(
            has_cross_language_native_evidence(
                source_status="system",
                call_reachability_source="rust_call_package",
                has_method=False,
                strict_callsite_edges=0,
                native_analysis_coverage="target_only",
                native_dependency_imports=[],
                strict_dependency_resolution={},
            )
        )
        self.assertTrue(
            has_cross_language_native_evidence(
                source_status="system",
                call_reachability_source="c_method",
                has_method=True,
                strict_callsite_edges=0,
                native_analysis_coverage="target_only",
                native_dependency_imports=[],
                strict_dependency_resolution={},
            )
        )

    def test_explicit_native_symbol_bridge_accepts_wrapper_symbol_mentions(self):
        calls = [
            {
                "name": "parse_string",
                "code": "let docptr = xmlReadMemory(input_ptr, input_len, url_ptr, encoding_ptr, options);",
                "scope": "synthetic_package_method_code",
            },
            {
                "name": "WebPDecodeRGBA",
                "code": "let result = unsafe { sys::WebPDecodeRGBA(data.as_ptr(), data.len(), &mut width, &mut height) };",
                "scope": "synthetic_package_method_code",
            },
        ]
        self.assertTrue(has_explicit_native_symbol_bridge("xmlReadMemory", calls))
        self.assertTrue(has_explicit_native_symbol_bridge("WebPDecodeRGBA", calls))
        self.assertTrue(has_explicit_native_symbol_bridge("WebPDecode", calls))
        self.assertFalse(has_explicit_native_symbol_bridge("pcre2_jit_compile_8", calls))

    def test_explicit_native_symbol_bridge_accepts_libjpeg_wrapper_calls(self):
        calls = [
            {
                "name": "read_header",
                "code": "let header = decompressor.read_header(&jpeg_data).map_err(|e| anyhow!(\"Failed to read JPEG header: {}\", e))?;",
                "scope": "synthetic_package_method_code",
            },
            {
                "name": "decompress",
                "code": "decompressor.decompress(&jpeg_data, image).map_err(|e| anyhow!(\"TurboJPEG decompress failed: {}\", e))?;",
                "scope": "synthetic_method_code",
            },
        ]
        self.assertTrue(has_explicit_native_symbol_bridge("tjDecompressHeader3", calls))
        self.assertTrue(has_explicit_native_symbol_bridge("tjDecompress2", calls))

    def test_explicit_native_symbol_bridge_accepts_gstreamer_wrapper_calls(self):
        calls = [
            {
                "name": "make",
                "code": 'let sink = gst::ElementFactory::make("appsink").build()?;',
                "scope": "synthetic_package_method_code",
            },
            {
                "name": "launch",
                "code": 'let pipeline = gst::parse::launch("filesrc location=input ! decodebin")?;',
                "scope": "synthetic_package_method_code",
            },
        ]
        self.assertTrue(has_explicit_native_symbol_bridge("gst_element_factory_make", calls))
        self.assertTrue(has_explicit_native_symbol_bridge("gst_parse_launch", calls))

    def test_explicit_native_symbol_bridge_rejects_generic_read_header_without_jpeg_context(self):
        calls = [
            {
                "name": "read_header",
                "code": "let header = parser.read_header(&blob)?;",
                "scope": "synthetic_package_method_code",
            }
        ]
        self.assertFalse(has_explicit_native_symbol_bridge("tjDecompressHeader3", calls))

    def test_native_symbol_name_match_allows_api_family_prefix(self):
        self.assertTrue(_native_symbol_names_match("WebPDecode", "WebPDecodeRGBA"))
        self.assertTrue(_native_symbol_names_match("WebPDecode", "WebPDecodeRGB"))
        self.assertFalse(_native_symbol_names_match("WebPDecode", "WebPAnimDecoderGetNext"))

    def test_explicit_native_symbol_bridge_rejects_generated_bindings_only(self):
        calls = [
            {
                "name": "xmlReadMemory",
                "code": "pub fn xmlReadMemory(",
                "scope": "synthetic_source_text",
                "file": "target_cpg_analysis/debug/build/libxml/out/bindings.rs",
            }
        ]
        self.assertFalse(has_explicit_native_symbol_bridge("xmlReadMemory", calls))

    def test_dependency_source_symbol_bridge_accepts_real_wrapper_source(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            crate_dir = root / "libxml-0.3.8"
            src_dir = crate_dir / "src"
            src_dir.mkdir(parents=True)
            (crate_dir / "Cargo.toml").write_text('[package]\nname="libxml"\nversion="0.3.8"\n', encoding="utf-8")
            (src_dir / "parser.rs").write_text(
                "use crate::bindings::*;\nfn parse_string() { let _ = unsafe { xmlReadMemory(buf, len, url, enc, 0) }; }\n",
                encoding="utf-8",
            )
            deps = {"packages": [{"name": "libxml", "manifest_path": str(crate_dir / 'Cargo.toml')}]}
            self.assertTrue(has_dependency_source_symbol_bridge("xmlReadMemory", deps, ["libxml"]))

    def test_dependency_source_symbol_bridge_falls_back_to_registry_source(self):
        with TemporaryDirectory() as tmp:
            cargo_home = Path(tmp) / "cargo"
            crate_dir = cargo_home / "registry" / "src" / "index.crates.io-test" / "curl-0.4.38"
            src_dir = crate_dir / "src"
            src_dir.mkdir(parents=True)
            (src_dir / "easy.rs").write_text(
                "fn perform(handle: *mut u8) { unsafe { curl_sys::curl_easy_perform(handle.cast()); } }\n",
                encoding="utf-8",
            )
            deps = {"packages": [{"name": "curl", "version": "0.4.38"}]}
            env = {"SUPPLYCHAIN_CARGO_HOME": str(cargo_home), "CARGO_HOME": str(cargo_home), "HOME": str(Path(tmp) / "home")}
            with patch.dict("os.environ", env, clear=False):
                self.assertTrue(has_dependency_source_symbol_bridge("curl_easy_perform", deps, ["curl"]))

    def test_collect_dependency_source_native_gateway_calls_uses_registry_source_as_bridge_only(self):
        with TemporaryDirectory() as tmp:
            cargo_home = Path(tmp) / "cargo"
            crate_dir = cargo_home / "registry" / "src" / "index.crates.io-test" / "curl-0.4.38"
            src_dir = crate_dir / "src"
            src_dir.mkdir(parents=True)
            (src_dir / "easy.rs").write_text(
                "fn perform(handle: *mut u8) { unsafe { curl_sys::curl_easy_perform(handle.cast()); } }\n",
                encoding="utf-8",
            )
            deps = {"packages": [{"name": "curl", "version": "0.4.38"}]}
            env = {"SUPPLYCHAIN_CARGO_HOME": str(cargo_home), "CARGO_HOME": str(cargo_home), "HOME": str(Path(tmp) / "home")}
            with patch.dict("os.environ", env, clear=False):
                calls = collect_dependency_source_native_gateway_calls(
                    deps,
                    ["curl_sys"],
                    crate_hints=["curl"],
                )

            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["scope"], "synthetic_native_gateway_dependency")
            self.assertEqual(calls[0]["dependency_crate"], "curl")
            selected = select_relevant_native_gateway_calls(calls, symbol="curl_easy_perform", limit=1)
            self.assertEqual(selected[0]["name"], "curl_easy_perform")

    def test_collect_source_native_gateway_calls_skips_doc_comments(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_dir = root / "src"
            src_dir.mkdir(parents=True)
            (src_dir / "lib.rs").write_text(
                "/// webp::WebPAnimDecoderGetNext(decoder, out, ts)\n"
                "fn run(decoder: *mut u8) { unsafe { webp::WebPAnimDecoderGetNext(decoder.cast(), std::ptr::null_mut(), std::ptr::null_mut()); } }\n",
                encoding="utf-8",
            )
            calls = collect_source_native_gateway_calls(str(root), ["webp"])
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["name"], "WebPAnimDecoderGetNext")

    def test_collect_source_native_gateway_calls_skips_non_runtime_sources_by_default(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "examples").mkdir(parents=True, exist_ok=True)
            (root / "examples" / "demo.rs").write_text(
                "fn main(){ let _ = freetype::FT_Load_Glyph(face, glyph, flags); }\n",
                encoding="utf-8",
            )
            (root / "build.rs").write_text(
                "fn main(){ let _ = freetype::FT_Load_Glyph(face, glyph, flags); }\n",
                encoding="utf-8",
            )
            (root / "src" / "lib.rs").write_text("pub fn api() {}\n", encoding="utf-8")

            calls = collect_source_native_gateway_calls(str(root), ["freetype"])

        self.assertEqual(calls, [])

    def test_generator_core_resolution_failure_uses_source_scan_fallback(self):
        detail = "error[E0433]: cannot find `core` in the crate root"
        self.assertTrue(_should_source_scan_after_generator_failure(detail))

    def test_collect_source_native_gateway_calls_handles_glob_imported_native_calls(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_dir = root / "src"
            src_dir.mkdir(parents=True)
            (src_dir / "lib.rs").write_text(
                "use libwebp_sys::*;\n"
                "fn decode(data: &[u8]) {\n"
                "    unsafe { WebPDecodeRGBA(data.as_ptr(), data.len(), &mut 0, &mut 0); }\n"
                "}\n",
                encoding="utf-8",
            )
            calls = collect_source_native_gateway_calls(str(root), ["libwebp_sys"])
            self.assertTrue(any(call["name"] == "WebPDecodeRGBA" for call in calls))
            self.assertTrue(any(call["scope"] == "synthetic_native_gateway_source" for call in calls))

    def test_collect_source_native_gateway_calls_handles_nested_module_import_alias(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_dir = root / "src"
            src_dir.mkdir(parents=True)
            (src_dir / "lib.rs").write_text(
                "use turbojpeg::{libc, raw};\n"
                "fn encode(handle: raw::tjhandle, out: *mut *mut libc::c_uchar) {\n"
                "    unsafe { raw::tj3Compress8(handle, std::ptr::null(), 1, 1, 1, 0, out, std::ptr::null_mut()); }\n"
                "}\n",
                encoding="utf-8",
            )
            calls = collect_source_native_gateway_calls(str(root), ["turbojpeg"])
            self.assertTrue(any(call["name"] == "tj3Compress8" for call in calls))
            selected = select_relevant_native_gateway_calls(calls, symbol="", sink_candidates=[], limit=1, min_score=-5)
            self.assertTrue(selected)

    def test_select_relevant_native_gateway_calls_requires_direct_sink_or_symbol_match(self):
        calls = [
            {
                "id": "nativegwsrc:src/lib.rs:2:raw:tj3Compress8",
                "name": "tj3Compress8",
                "code": "unsafe { raw::tj3Compress8(handle, src, 1, 1, 1, 0, out, size); }",
                "context_code": "unsafe { raw::tj3Compress8(handle, src, 1, 1, 1, 0, out, size); }",
                "lang": "Rust",
                "method": "src/lib.rs:2",
                "enclosing_method": "encode",
                "scope": "synthetic_native_gateway_source",
                "gateway_alias": "raw",
            }
        ]
        selected = select_relevant_native_gateway_calls(
            calls,
            symbol="tjDecompress2",
            sink_candidates=[{"path": "Decompressor::decompress"}],
            limit=1,
            min_score=80,
        )
        self.assertEqual(selected, [])

    def test_collect_source_native_gateway_calls_handles_nested_crate_paths(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_dir = root / "src"
            src_dir.mkdir(parents=True)
            (src_dir / "lib.rs").write_text(
                "pub fn encode_png(data: &[u8]) {\n"
                "    let mut out = Vec::new();\n"
                "    let mut encoder = png::Encoder::new(&mut out, 1, 1);\n"
                "    let mut writer = encoder.write_header().unwrap();\n"
                "    writer.write_image_data(data).unwrap();\n"
                "}\n",
                encoding="utf-8",
            )
            calls = collect_source_native_gateway_calls(str(root), ["png"])

            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["name"], "Encoder::new")
            self.assertEqual(calls[0]["enclosing_method"], "encode_png")
            selected = select_relevant_native_gateway_calls(calls, symbol="", sink_candidates=[], limit=1, min_score=-5)
            self.assertEqual(selected[0]["name"], "Encoder::new")

    def test_collect_source_native_gateway_calls_ignores_imported_uppercase_types(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_dir = root / "src"
            src_dir.mkdir(parents=True)
            (src_dir / "lib.rs").write_text(
                "use png::{DeflateCompression, raw};\n"
                "pub fn encode_level() {\n"
                "    let _ = DeflateCompression::Level(1);\n"
                "    unsafe { raw::png_write_info(std::ptr::null_mut(), std::ptr::null_mut()); }\n"
                "}\n",
                encoding="utf-8",
            )
            calls = collect_source_native_gateway_calls(str(root), ["png"])

            self.assertFalse(any(call["name"] == "Level" for call in calls))
            self.assertTrue(any(call["name"] == "png_write_info" for call in calls))

    def test_libpng_pure_rust_png_gateway_is_reachability_only(self):
        calls = [
            {
                "name": "Encoder::new",
                "code": "let mut encoder = png::Encoder::new(&mut out, 1, 1);",
                "gateway_alias": "png",
            }
        ]
        self.assertTrue(_is_libpng_pure_rust_png_bridge("libpng", "png", calls))
        native_calls = [
            {
                "name": "png_image_finish_read",
                "code": "unsafe { png::png_image_finish_read(image, bg, buf, row_stride, colormap) }",
                "gateway_alias": "png",
            }
        ]
        self.assertFalse(_is_libpng_pure_rust_png_bridge("libpng", "png", native_calls))

    def test_libpng_pure_rust_png_filter_keeps_public_decode_api_only(self):
        calls = [
            {
                "name": "Decoder::new",
                "enclosing_method": "decode_png",
                "code": "let decoder = png::Decoder::new(Cursor::new(data));",
                "context_code": "pub fn decode_png(data: &[u8]) { let decoder = png::Decoder::new(Cursor::new(data)); }",
                "file": "src/pixmap.rs",
                "gateway_alias": "png",
            },
            {
                "name": "Encoder::new",
                "enclosing_method": "to_png",
                "code": "let encoder = png::Encoder::new(Cursor::new(&mut png), width, height);",
                "context_code": "pub fn to_png(&self) -> Vec<u8> { let encoder = png::Encoder::new(Cursor::new(&mut png), width, height); }",
                "file": "src/platform_impl/macos/icon.rs",
                "gateway_alias": "png",
            },
            {
                "name": "Decoder::new",
                "enclosing_method": "new_png",
                "code": "let decoder = png::Decoder::new(Cursor::new(&buf));",
                "context_code": "pub fn new_png(root: &TokenStream, icon: &Path) { let buf = Self::open(icon); let decoder = png::Decoder::new(Cursor::new(&buf)); }",
                "file": "src/image.rs",
                "gateway_alias": "png",
            },
        ]

        filtered = _filter_libpng_pure_rust_png_gateway_calls("libpng", "png", calls)
        self.assertEqual([call["file"] for call in filtered], ["src/pixmap.rs"])

    def test_gstreamer_caps_only_reachability_requires_pipeline(self):
        self.assertTrue(
            _is_gstreamer_caps_only_reachability(
                "gstreamer",
                "rust_method_code_package",
                ["all_caps"],
            )
        )
        self.assertFalse(
            _is_gstreamer_caps_only_reachability(
                "gstreamer",
                "rust_method_code_package",
                ["parse_launch", "all_caps"],
            )
        )
        self.assertFalse(
            _is_gstreamer_caps_only_reachability(
                "gstreamer",
                "rust_native_gateway_package",
                ["all_caps"],
            )
        )

    def test_missing_mandatory_trigger_guard_for_gstreamer_launch_path(self):
        hits = {
            "required_miss": [
                {"id": "gst_launch_any"},
                {"id": "gst_media_input"},
            ]
        }

        self.assertEqual(
            ["gst_launch_any"],
            _missing_mandatory_trigger_guard_ids("gstreamer", hits),
        )

    def test_collect_package_native_gateway_calls_extracts_code_window(self):
        session = MagicMock()
        session.run.return_value = [
            {
                "id": 7,
                "name": "decode_image",
                "code": (
                    "fn decode_image(data: &[u8]) { let prefix = 1; let prefix2 = 2; "
                    "let result = unsafe { webp::WebPDecodeRGBA(data.as_ptr(), data.len(), &mut w, &mut h) }; "
                    "let suffix = prefix + prefix2; println!(\"{}\", suffix); }"
                ),
            }
        ]
        calls = collect_package_native_gateway_calls(session, "demo", ["webp"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["name"], "WebPDecodeRGBA")
        self.assertIn("WebPDecodeRGBA", calls[0]["code"])
        self.assertIsInstance(calls[0]["code"], str)

    def test_has_transitive_native_symbol_bridge_uses_native_call_path(self):
        session = MagicMock()
        session.run.return_value.single.return_value = {"ok": 1}
        self.assertTrue(
            has_transitive_native_symbol_bridge(
                session,
                "libwebp",
                ["WebPAnimDecoderGetNext"],
                "WebPDecode",
            )
        )

    def test_find_best_dep_chain_can_fall_back_to_matched_native_crate(self):
        session = MagicMock()
        session.run.return_value = [
            {
                "target": "libwebp-sys2",
                "chain": ["ril", "image-rs", "libwebp-sys2"],
                "edges": [
                    {"from": "ril", "to": "image-rs", "type": "DEPENDS_ON"},
                    {"from": "image-rs", "to": "libwebp-sys2", "type": "DEPENDS_ON"},
                ],
            }
        ]
        match = find_best_dep_chain(
            session,
            "ril",
            "libwebp",
            native_component_instances=[
                {
                    "matched_crates": [
                        {"crate": "libwebp-sys2"},
                    ]
                }
            ],
        )
        self.assertEqual(match["target"], "libwebp-sys2")
        self.assertEqual(match["chain"][-1], "libwebp-sys2")
        kwargs = session.run.call_args.kwargs
        self.assertIn("libwebp", kwargs["pkg_names"])
        self.assertIn("libwebp-sys2", kwargs["pkg_names"])

    def test_select_relevant_native_gateway_calls_prefers_real_decode_over_cleanup(self):
        calls = [
            {
                "id": "clear",
                "name": "WebPDataClear",
                "code": "unsafe { libwebp::WebPDataClear(&mut data) }",
                "method": "cleanup",
                "scope": "synthetic_native_gateway_source",
                "line": 10,
            },
            {
                "id": "decode",
                "name": "WebPDecodeRGBA",
                "code": "unsafe { libwebp::WebPDecodeRGBA(ptr, len, &mut w, &mut h) }",
                "method": "decode_frame",
                "scope": "synthetic_native_gateway_source",
                "line": 200,
            },
            {
                "id": "delete",
                "name": "WebPMuxDelete",
                "code": "unsafe { libwebp::WebPMuxDelete(mux) }",
                "method": "cleanup",
                "scope": "synthetic_native_gateway_source",
                "line": 20,
            },
        ]
        selected = select_relevant_native_gateway_calls(
            calls,
            symbol="WebPDecode",
            sink_candidates=[{"path": "webp::Decoder::decode"}],
            limit=1,
        )
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["name"], "WebPDecodeRGBA")

    def test_select_relevant_native_gateway_calls_beats_generic_next_over_new(self):
        calls = [
            {
                "id": "new",
                "name": "WebPAnimDecoderNew",
                "code": "unsafe { webp::WebPAnimDecoderNew(data, &opts) }",
                "method": "run_decoder",
                "scope": "synthetic_native_gateway_source",
                "line": 193,
            },
            {
                "id": "next",
                "name": "WebPAnimDecoderGetNext",
                "code": "unsafe { webp::WebPAnimDecoderGetNext(decoder, &mut buf, &mut ts) }",
                "method": "run_decoder",
                "scope": "synthetic_native_gateway_source",
                "line": 245,
            },
        ]
        selected = select_relevant_native_gateway_calls(calls, symbol="VP8LBuildHuffmanTable", limit=1)
        self.assertEqual(selected[0]["name"], "WebPAnimDecoderGetNext")

    def test_select_relevant_native_gateway_calls_filters_weak_constructor_only_hits(self):
        calls = [
            {
                "id": "new",
                "name": "Regex::new",
                "code": "let re = pcre2::bytes::Regex::new(pattern)?;",
                "method": "compile_pattern",
                "scope": "synthetic_native_gateway_source",
                "line": 12,
            }
        ]
        selected = select_relevant_native_gateway_calls(
            calls,
            symbol="pcre2_jit_compile_8",
            sink_candidates=[{"path": "RegexBuilder::build"}],
            limit=1,
        )
        self.assertEqual(selected, [])

    def test_maybe_collect_expanded_feature_deps_uses_all_features_when_root_has_optional_deps(self):
        meta = {
            "packages": [
                {
                    "id": "pkg",
                    "name": "demo",
                    "features": {"webp": ["dep:libwebp-sys2"]},
                    "dependencies": [{"name": "libwebp-sys2", "optional": True}],
                }
            ],
            "workspace_default_members": ["pkg"],
            "resolve": {"nodes": [{"id": "pkg", "features": []}]},
        }
        expanded_meta = {
            "packages": [
                {
                    "id": "pkg",
                    "name": "demo",
                    "version": "0.1.0",
                    "manifest_path": "/tmp/demo/Cargo.toml",
                },
                {
                    "id": "dep",
                    "name": "libwebp-sys2",
                    "version": "0.1.11",
                    "manifest_path": "/tmp/libwebp-sys2/Cargo.toml",
                },
            ],
            "workspace_default_members": ["pkg"],
            "resolve": {
                "nodes": [
                    {"id": "pkg", "features": ["webp"], "deps": [{"pkg": "dep"}]},
                    {"id": "dep", "features": ["1_2"], "deps": []},
                ]
            },
        }
        with patch("tools.supplychain.supplychain_analyze.run_metadata", return_value=expanded_meta):
            result = maybe_collect_expanded_feature_deps("/tmp/demo", meta)
        self.assertIsNotNone(result)
        dep_names = {pkg["name"] for pkg in result["deps"]["packages"]}
        self.assertIn("libwebp-sys2", dep_names)

    def test_filter_speculative_source_features_keeps_functional_features_only(self):
        deps = {
            "packages": [
                {"name": "libwebp-sys2", "features": ["demux", "mux", "static"]},
            ]
        }
        _filter_speculative_source_features(deps, {"libwebp-sys2": []})
        self.assertEqual(deps["packages"][0]["features"], ["demux", "mux"])

    def test_resolve_native_component_instances_matches_sys_suffix_variants_and_probes_system(self):
        with TemporaryDirectory() as tmp:
            crate_dir = Path(tmp) / "libwebp-sys2"
            crate_dir.mkdir(parents=True, exist_ok=True)
            manifest = crate_dir / "Cargo.toml"
            manifest.write_text("[package]\nname='libwebp-sys2'\nversion='0.1.11'\n", encoding="utf-8")
            (crate_dir / "build.rs").write_text(
                "fn main(){ let _ = pkg_config::probe_library(\"libwebp\"); }",
                encoding="utf-8",
            )
            metadata = {
                "libwebp-sys2": {
                    "versions": ["0.1.11"],
                    "sources": ["cargo"],
                    "features": ["demux"],
                    "langs": ["Rust"],
                    "crate_sources": [],
                    "manifest_paths": [str(manifest)],
                }
            }
            vuln = {"package": "libwebp", "match": {"crates": ["webp", "libwebp-sys"]}}
            _SYSTEM_NATIVE_VERSION_CACHE.clear()
            with patch("tools.supplychain.supplychain_analyze.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                mock_run.return_value.stdout = "1.2.4\n"
                mock_run.return_value.stderr = ""
                instances = resolve_native_component_instances(vuln, metadata, cargo_dir=tmp)
            self.assertTrue(instances)
            self.assertEqual(instances[0]["source"], "system")
            self.assertEqual(instances[0]["resolved_version"], "1.2.4")
            crates = [row["crate"] for row in instances[0]["matched_crates"]]
            self.assertIn("libwebp-sys2", crates)

    def test_apply_sink_knowledge_fills_missing_sinks(self):
        vuln = {"package": "libwebp", "cve": "CVE-T"}
        sink_kb = {
            "libwebp": {
                "match": {"crates": ["webp", "libwebp-sys"]},
                "rust_sinks": [{"path": "webp::Decoder::decode"}],
                "symbols": ["WebPDecode"],
            }
        }
        out = apply_sink_knowledge(vuln, sink_kb)
        self.assertEqual(out["match"]["crates"][0], "webp")
        self.assertEqual(out["symbols"][0], "WebPDecode")

    def test_resolve_native_component_instances_uses_feature_and_build_signals(self):
        with TemporaryDirectory() as tmp:
            crate_dir = Path(tmp) / "libgit2-sys"
            crate_dir.mkdir(parents=True, exist_ok=True)
            manifest = crate_dir / "Cargo.toml"
            manifest.write_text("[package]\nname='libgit2-sys'\nversion='0.17.0'\n", encoding="utf-8")
            (crate_dir / "build.rs").write_text(
                "fn main(){ println!(\"cargo:rerun-if-changed=build.rs\"); cc::Build::new().compile(\"libgit2\"); }",
                encoding="utf-8",
            )
            metadata = {
                "libgit2-sys": {
                    "versions": ["0.17.0"],
                    "sources": ["cargo"],
                    "features": ["vendored-libgit2"],
                    "langs": ["Rust"],
                    "crate_sources": [],
                    "manifest_paths": [str(manifest)],
                }
            }
            vuln = {"package": "libgit2", "match": {"crates": ["libgit2-sys"]}}
            instances = resolve_native_component_instances(vuln, metadata, cargo_dir=tmp)
            self.assertTrue(instances)
            self.assertEqual(instances[0]["source"], "bundled")
            self.assertIn("vendored-libgit2", instances[0]["enabled_features"])

    def test_resolve_native_component_instances_falls_back_to_build_version_when_system_probe_missing(self):
        with TemporaryDirectory() as tmp:
            crate_dir = Path(tmp) / "gdal-sys"
            crate_dir.mkdir(parents=True, exist_ok=True)
            manifest = crate_dir / "Cargo.toml"
            manifest.write_text("[package]\nname='gdal-sys'\nversion='0.12.0'\n", encoding="utf-8")
            (crate_dir / "build.rs").write_text(
                "\n".join(
                    [
                        "fn main() {",
                        "    let native = \"3.4.0\";",
                        "    println!(\"cargo:warning={}\", native);",
                        "    let _ = pkg_config::probe_library(\"gdal\");",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            metadata = {
                "gdal": {
                    "versions": ["0.19.0"],
                    "sources": ["cargo"],
                    "features": ["default"],
                    "langs": ["Rust"],
                    "crate_sources": [],
                    "manifest_paths": [str(Path(tmp) / "gdal" / "Cargo.toml")],
                },
                "gdal-sys": {
                    "versions": ["0.12.0"],
                    "sources": ["cargo"],
                    "features": ["default"],
                    "langs": ["Rust"],
                    "crate_sources": [],
                    "manifest_paths": [str(manifest)],
                },
            }
            vuln = {"package": "gdal", "match": {"crates": ["gdal-sys"]}}
            with patch("tools.supplychain.supplychain_analyze._probe_system_native_version", return_value=None):
                instances = resolve_native_component_instances(vuln, metadata, cargo_dir=tmp)
            self.assertTrue(instances)
            self.assertEqual(instances[0]["source"], "system")
            self.assertEqual(instances[0]["resolved_version"], "3.4.0")

    def test_resolve_native_component_instances_prefers_system_openssl_version_probe(self):
        with TemporaryDirectory() as tmp:
            crate_dir = Path(tmp) / "openssl-sys"
            crate_dir.mkdir(parents=True, exist_ok=True)
            manifest = crate_dir / "Cargo.toml"
            manifest.write_text("[package]\nname='openssl-sys'\nversion='0.9.104'\n", encoding="utf-8")
            (crate_dir / "build.rs").write_text(
                "fn main(){ let _ = pkg_config::probe_library(\"openssl\"); }",
                encoding="utf-8",
            )
            metadata = {
                "openssl-sys": {
                    "versions": ["0.9.104"],
                    "sources": ["cargo"],
                    "features": [],
                    "langs": ["Rust"],
                    "crate_sources": [],
                    "manifest_paths": [str(manifest)],
                },
                "openssl": {
                    "versions": ["0.10.76"],
                    "sources": ["cargo"],
                    "features": [],
                    "langs": ["Rust"],
                    "crate_sources": [],
                    "manifest_paths": [],
                },
            }
            vuln = {
                "package": "openssl",
                "source_status": "system",
                "match": {"crates": ["openssl", "openssl-sys"]},
            }
            _SYSTEM_NATIVE_VERSION_CACHE.clear()
            with patch("tools.supplychain.supplychain_analyze.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                mock_run.return_value.stdout = "3.6.1\n"
                mock_run.return_value.stderr = ""
                instances = resolve_native_component_instances(vuln, metadata, cargo_dir=tmp)
            self.assertTrue(instances)
            self.assertEqual(instances[0]["source"], "system")
            self.assertEqual(instances[0]["resolved_version"], "3.6.1")
            evidence_kinds = [item.get("kind") for item in instances[0]["resolution_evidence"]]
            self.assertIn("system_probe", evidence_kinds)

    def test_extract_native_version_from_sys_crate_version_suffix(self):
        self.assertEqual(
            _extract_native_version_from_crate_version("curl-sys", "0.4.87+curl-8.19.0", "curl"),
            "8.19.0",
        )

    def test_ensure_rustc_edition_arg_adds_or_replaces_edition(self):
        self.assertEqual(
            _ensure_rustc_edition_arg(["--crate-name", "demo"], "2024"),
            ["--edition=2024", "--crate-name", "demo"],
        )
        self.assertEqual(
            _ensure_rustc_edition_arg(["--edition=2021", "--crate-name", "demo"], "2024"),
            ["--edition=2024", "--crate-name", "demo"],
        )

    def test_resolve_native_component_instances_prefers_sys_suffix_native_version(self):
        metadata = {
            "curl": {
                "versions": ["0.4.49"],
                "sources": ["cargo_lock"],
                "features": [],
                "langs": ["Rust"],
                "crate_sources": [],
                "manifest_paths": [],
            },
            "curl-sys": {
                "versions": ["0.4.87+curl-8.19.0"],
                "sources": ["cargo_lock"],
                "features": [],
                "langs": ["Rust"],
                "crate_sources": [],
                "manifest_paths": [],
            },
        }
        vuln = {"package": "curl", "match": {"crates": ["curl", "curl-sys"]}}
        with patch("tools.supplychain.supplychain_analyze._probe_system_native_version", return_value=None):
            instances = resolve_native_component_instances(vuln, metadata, cargo_dir="")
        self.assertEqual(instances[0]["resolved_version"], "8.19.0")
        evidence_kinds = [item.get("kind") for item in instances[0]["resolution_evidence"]]
        self.assertIn("crate_native_versions", evidence_kinds)

    def test_resolve_native_component_instances_probes_system_sqlite_version(self):
        metadata = {
            "libsqlite3-sys": {
                "versions": ["0.37.0"],
                "sources": ["cargo_lock"],
                "features": [],
                "langs": ["Rust"],
                "crate_sources": [],
                "manifest_paths": [],
            },
        }
        vuln = {"package": "sqlite", "match": {"crates": ["rusqlite", "libsqlite3-sys"]}}
        _SYSTEM_NATIVE_VERSION_CACHE.clear()
        with patch("tools.supplychain.supplychain_analyze.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "3.37.2\n"
            mock_run.return_value.stderr = ""
            instances = resolve_native_component_instances(vuln, metadata, cargo_dir="")
        self.assertEqual(instances[0]["source"], "system")
        self.assertEqual(instances[0]["resolved_version"], "3.37.2")
        evidence_kinds = [item.get("kind") for item in instances[0]["resolution_evidence"]]
        self.assertIn("system_probe", evidence_kinds)

    def test_resolve_native_component_instances_probes_system_gdal_version(self):
        metadata = {
            "gdal": {
                "versions": ["0.18.0"],
                "sources": ["cargo_lock"],
                "features": [],
                "langs": ["Rust"],
                "crate_sources": [],
                "manifest_paths": [],
            },
            "gdal-sys": {
                "versions": ["0.11.0"],
                "sources": ["cargo_lock"],
                "features": [],
                "langs": ["Rust"],
                "crate_sources": [],
                "manifest_paths": [],
            },
        }
        vuln = {
            "package": "gdal",
            "source_status": "system",
            "match": {"crates": ["gdal", "gdal-sys"]},
        }
        _SYSTEM_NATIVE_VERSION_CACHE.clear()
        with patch("tools.supplychain.supplychain_analyze.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "3.4.1\n"
            mock_run.return_value.stderr = ""
            instances = resolve_native_component_instances(vuln, metadata, cargo_dir="")
        self.assertEqual(instances[0]["source"], "system")
        self.assertEqual(instances[0]["resolved_version"], "3.4.1")
        evidence_kinds = [item.get("kind") for item in instances[0]["resolution_evidence"]]
        self.assertIn("system_probe", evidence_kinds)

    def test_resolve_native_component_instances_does_not_use_wrapper_crate_version_as_native_version(self):
        metadata = {
            "tiff": {
                "versions": ["0.11.3"],
                "sources": ["cargo_lock"],
                "features": [],
                "langs": ["Rust"],
                "crate_sources": [],
                "manifest_paths": [],
            }
        }
        vuln = {"package": "libtiff", "match": {"crates": ["libtiff-sys", "tiff"]}}
        with patch("tools.supplychain.supplychain_analyze._probe_system_native_version", return_value=None):
            instances = resolve_native_component_instances(vuln, metadata, cargo_dir="")
        self.assertIsNone(instances[0]["resolved_version"])
        self.assertEqual(instances[0]["status"], "unknown")
        self.assertEqual(instances[0]["matched_crates"], [])
        self.assertEqual(instances[0]["reachability_crates"][0]["crate"], "tiff")

    def test_native_component_dependency_candidates_include_reachability_crates(self):
        candidates = _native_component_dependency_candidates(
            "libtiff",
            [{"matched_crates": [], "reachability_crates": [{"crate": "tiff"}]}],
        )
        self.assertIn("libtiff", candidates)
        self.assertIn("tiff", candidates)

    def test_resolve_native_component_instances_can_use_system_probe_without_matched_crates(self):
        vuln = {
            "package": "openssl",
            "source_status": "system",
            "match": {"crates": ["openssl", "openssl-sys", "native-tls"]},
        }
        _SYSTEM_NATIVE_VERSION_CACHE.clear()
        with patch("tools.supplychain.supplychain_analyze.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "3.6.1\n"
            mock_run.return_value.stderr = ""
            instances = resolve_native_component_instances(vuln, {}, cargo_dir="")
        self.assertTrue(instances)
        self.assertEqual(instances[0]["status"], "resolved")
        self.assertEqual(instances[0]["source"], "system")
        self.assertEqual(instances[0]["resolved_version"], "3.6.1")
        evidence_kinds = [item.get("kind") for item in instances[0]["resolution_evidence"]]
        self.assertIn("missing_candidate_crates", evidence_kinds)
        self.assertIn("system_probe", evidence_kinds)

    def test_resolve_native_component_instances_honors_env_override_for_system_version(self):
        vuln = {
            "package": "openssl",
            "source_status": "system",
            "match": {"crates": ["openssl", "openssl-sys", "native-tls"]},
        }
        _SYSTEM_NATIVE_VERSION_CACHE.clear()
        with patch.dict("os.environ", {"SUPPLYCHAIN_NATIVE_VERSION_OPENSSL": "3.0.6"}, clear=False):
            instances = resolve_native_component_instances(vuln, {}, cargo_dir="")
        self.assertTrue(instances)
        self.assertEqual(instances[0]["resolved_version"], "3.0.6")
        evidence = instances[0]["resolution_evidence"]
        probe = next(item for item in evidence if item.get("kind") == "system_probe")
        self.assertEqual(probe["probe"]["tool"], "env_override")

    def test_resolve_native_component_instances_can_probe_freetype_system_version(self):
        vuln = {
            "package": "freetype",
            "source_status": "system",
            "match": {"crates": ["freetype-rs", "freetype-sys", "servo-freetype-sys"]},
        }
        _SYSTEM_NATIVE_VERSION_CACHE.clear()
        with patch("tools.supplychain.supplychain_analyze.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "2.14.2\n"
            mock_run.return_value.stderr = ""
            instances = resolve_native_component_instances(vuln, {}, cargo_dir="")
        self.assertTrue(instances)
        self.assertEqual(instances[0]["source"], "system")
        self.assertEqual(instances[0]["resolved_version"], "2.14.2")
        evidence_kinds = [item.get("kind") for item in instances[0]["resolution_evidence"]]
        self.assertIn("system_probe", evidence_kinds)

    def test_resolve_native_component_instances_prefers_freetype_config_over_pkg_config_epoch(self):
        vuln = {
            "package": "freetype",
            "source_status": "system",
            "match": {"crates": ["freetype-rs", "freetype-sys", "servo-freetype-sys"]},
        }
        _SYSTEM_NATIVE_VERSION_CACHE.clear()

        def fake_run(cmd, *args, **kwargs):
            class Result:
                def __init__(self, returncode, stdout, stderr=""):
                    self.returncode = returncode
                    self.stdout = stdout
                    self.stderr = stderr

            if cmd[:2] == ["freetype-config", "--ftversion"]:
                return Result(0, "2.14.2\n")
            if cmd[:3] == ["pkg-config", "--modversion", "freetype2"]:
                return Result(0, "26.5.20\n")
            return Result(1, "", "unsupported")

        with patch("tools.supplychain.supplychain_analyze.subprocess.run", side_effect=fake_run):
            instances = resolve_native_component_instances(vuln, {}, cargo_dir="")
        self.assertTrue(instances)
        self.assertEqual(instances[0]["resolved_version"], "2.14.2")

    def test_resolve_native_component_instances_uses_dpkg_when_freetype_pkg_config_is_epoch(self):
        vuln = {
            "package": "freetype",
            "source_status": "system",
            "match": {"crates": ["freetype-rs", "freetype-sys", "servo-freetype-sys"]},
        }
        _SYSTEM_NATIVE_VERSION_CACHE.clear()

        def fake_run(cmd, *args, **kwargs):
            class Result:
                def __init__(self, returncode, stdout, stderr=""):
                    self.returncode = returncode
                    self.stdout = stdout
                    self.stderr = stderr

            if cmd[:2] == ["freetype-config", "--ftversion"]:
                return Result(1, "", "missing")
            if cmd[:3] == ["pkg-config", "--modversion", "freetype2"]:
                return Result(0, "24.3.18\n")
            if cmd[:2] == ["dpkg-query", "-W"]:
                return Result(0, "2.11.1+dfsg-1ubuntu0.3\n")
            return Result(1, "", "unsupported")

        with patch("tools.supplychain.supplychain_analyze.subprocess.run", side_effect=fake_run):
            instances = resolve_native_component_instances(vuln, {}, cargo_dir="")
        self.assertTrue(instances)
        self.assertEqual(instances[0]["source"], "system")
        self.assertEqual(instances[0]["resolved_version"], "2.11.1")

    def test_resolve_native_component_instances_can_probe_zlib_system_version(self):
        vuln = {
            "package": "zlib",
            "source_status": "system",
            "match": {"crates": ["libz-sys", "flate2"]},
        }
        _SYSTEM_NATIVE_VERSION_CACHE.clear()
        with patch("tools.supplychain.supplychain_analyze.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "1.2.12\n"
            mock_run.return_value.stderr = ""
            instances = resolve_native_component_instances(vuln, {}, cargo_dir="")
        self.assertTrue(instances)
        self.assertEqual(instances[0]["source"], "system")
        self.assertEqual(instances[0]["resolved_version"], "1.2.12")
        evidence_kinds = [item.get("kind") for item in instances[0]["resolution_evidence"]]
        self.assertIn("system_probe", evidence_kinds)

    def test_resolve_native_component_instances_can_probe_libtiff_system_version(self):
        vuln = {
            "package": "libtiff",
            "source_status": "system",
            "match": {"crates": ["tiff", "libtiff-sys"]},
        }
        _SYSTEM_NATIVE_VERSION_CACHE.clear()
        with patch("tools.supplychain.supplychain_analyze.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "4.3.0\n"
            mock_run.return_value.stderr = ""
            instances = resolve_native_component_instances(vuln, {}, cargo_dir="")
        self.assertTrue(instances)
        self.assertEqual(instances[0]["source"], "system")
        self.assertEqual(instances[0]["resolved_version"], "4.3.0")
        evidence_kinds = [item.get("kind") for item in instances[0]["resolution_evidence"]]
        self.assertIn("system_probe", evidence_kinds)

    def test_resolve_native_component_instances_can_probe_libjpeg_turbo_system_version(self):
        metadata = {
            "turbojpeg": {
                "versions": ["1.3.3"],
                "sources": ["cargo_lock"],
                "features": [],
                "langs": ["Rust"],
                "crate_sources": [],
                "manifest_paths": [],
            },
            "turbojpeg-sys": {
                "versions": ["1.1.1"],
                "sources": ["cargo_lock"],
                "features": [],
                "langs": ["Rust"],
                "crate_sources": [],
                "manifest_paths": [],
            },
        }
        vuln = {
            "package": "libjpeg-turbo",
            "source_status": "system",
            "match": {"crates": ["turbojpeg", "turbojpeg-sys", "libjpeg-turbo"]},
        }
        _SYSTEM_NATIVE_VERSION_CACHE.clear()

        def fake_run(cmd, *args, **kwargs):
            class Result:
                def __init__(self, returncode, stdout, stderr=""):
                    self.returncode = returncode
                    self.stdout = stdout
                    self.stderr = stderr

            if cmd[:3] == ["pkg-config", "--modversion", "libturbojpeg"]:
                return Result(1, "", "missing")
            if cmd[:3] == ["pkg-config", "--modversion", "libjpeg"]:
                return Result(0, "2.1.2\n")
            return Result(1, "", "unsupported")

        with patch("tools.supplychain.supplychain_analyze.subprocess.run", side_effect=fake_run):
            instances = resolve_native_component_instances(vuln, metadata, cargo_dir="")
        self.assertTrue(instances)
        self.assertEqual(instances[0]["source"], "system")
        self.assertEqual(instances[0]["resolved_version"], "2.1.2")
        evidence_kinds = [item.get("kind") for item in instances[0]["resolution_evidence"]]
        self.assertIn("system_probe", evidence_kinds)

    def test_resolve_native_component_instances_can_probe_ffmpeg_cli_version(self):
        metadata = {
            "ffmpeg-next": {
                "versions": ["5.1.1"],
                "sources": ["cargo_lock"],
                "features": [],
                "langs": ["Rust"],
                "crate_sources": [],
                "manifest_paths": [],
            }
        }
        vuln = {
            "package": "ffmpeg",
            "source_status": "system",
            "match": {"crates": ["ffmpeg-next", "ffmpeg-sys-next"]},
        }
        _SYSTEM_NATIVE_VERSION_CACHE.clear()

        def fake_run(cmd, *args, **kwargs):
            class Result:
                def __init__(self, returncode, stdout, stderr=""):
                    self.returncode = returncode
                    self.stdout = stdout
                    self.stderr = stderr

            if cmd[:2] == ["ffmpeg", "-version"]:
                return Result(0, "ffmpeg version 4.4.2-0ubuntu0.22.04.1 Copyright ...\n")
            return Result(1, "", "unsupported")

        with patch("tools.supplychain.supplychain_analyze.subprocess.run", side_effect=fake_run):
            instances = resolve_native_component_instances(vuln, metadata, cargo_dir="")
        self.assertTrue(instances)
        self.assertEqual(instances[0]["source"], "system")
        self.assertEqual(instances[0]["resolved_version"], "4.4.2")
        evidence_kinds = [item.get("kind") for item in instances[0]["resolution_evidence"]]
        self.assertIn("system_probe", evidence_kinds)

    def test_resolve_native_component_instances_can_probe_ffmpeg_dpkg_version(self):
        vuln = {
            "package": "ffmpeg",
            "source_status": "system",
            "match": {"crates": ["ffmpeg-next", "ffmpeg-sys-next"]},
        }
        _SYSTEM_NATIVE_VERSION_CACHE.clear()

        def fake_run(cmd, *args, **kwargs):
            class Result:
                def __init__(self, returncode, stdout, stderr=""):
                    self.returncode = returncode
                    self.stdout = stdout
                    self.stderr = stderr

            if cmd[:2] == ["ffmpeg", "-version"]:
                return Result(1, "", "missing")
            if cmd[:4] == ["dpkg-query", "-W", "-f=${Version}\n", "libavformat-dev"]:
                return Result(0, "7:4.4.2-0ubuntu0.22.04.1\n")
            return Result(1, "", "unsupported")

        with patch("tools.supplychain.supplychain_analyze.subprocess.run", side_effect=fake_run):
            instances = resolve_native_component_instances(vuln, {}, cargo_dir="")
        self.assertTrue(instances)
        self.assertEqual(instances[0]["source"], "system")
        self.assertEqual(instances[0]["resolved_version"], "4.4.2")

    def test_resolve_native_component_instances_ignores_c_placeholder_packages(self):
        vuln = {
            "package": "libtiff",
            "match": {"crates": ["tiff", "libtiff-sys"]},
        }
        package_metadata = {
            "libtiff": {
                "langs": ["C"],
                "versions": [],
                "features": [],
                "sources": [],
                "manifest_paths": [],
            },
            "tiff": {
                "langs": ["Rust"],
                "versions": ["0.11.3"],
                "features": [],
                "sources": ["cargo_lock"],
                "manifest_paths": [""],
            },
        }
        instances = resolve_native_component_instances(vuln, package_metadata, cargo_dir="")
        self.assertTrue(instances)
        self.assertEqual(instances[0]["matched_crates"], [])
        self.assertEqual(instances[0]["reachability_crates"][0]["crate"], "tiff")
        evidence_kinds = [item.get("kind") for item in instances[0]["resolution_evidence"]]
        self.assertIn("missing_candidate_crates", evidence_kinds)
        self.assertIn("rust_reachability_crates", evidence_kinds)

    def test_resolve_native_component_instances_does_not_treat_unrelated_build_rs_as_wrapper(self):
        vuln = {
            "package": "libtiff",
            "match": {"crates": ["tiff", "libtiff-sys"]},
        }
        with TemporaryDirectory() as tmp:
            cargo_dir = Path(tmp)
            (cargo_dir / "Cargo.toml").write_text(
                '[package]\nname = "zng-view"\nversion = "0.17.1"\n',
                encoding="utf-8",
            )
            (cargo_dir / "build.rs").write_text(
                'fn main() { println!("cargo:rerun-if-changed=build.rs"); println!("version=1.3.0"); }\n',
                encoding="utf-8",
            )
            (cargo_dir / "src").mkdir()
            (cargo_dir / "src" / "lib.rs").write_text("pub fn decode() {}\n", encoding="utf-8")
            instances = resolve_native_component_instances(vuln, {}, cargo_dir=str(cargo_dir))
        self.assertTrue(instances)
        self.assertEqual(instances[0]["matched_crates"], [])
        evidence_kinds = [item.get("kind") for item in instances[0]["resolution_evidence"]]
        self.assertIn("missing_candidate_crates", evidence_kinds)

    def test_auto_vuln_inputs_support_openh264_freetype_zlib_and_libarchive(self):
        openh264_item = {
            "family": "openh264",
            "project": "demo-video",
            "cve": "CVE-2025-27091",
            "dependency_evidence": [{"crate": "openh264"}],
        }
        freetype_item = {
            "family": "freetype",
            "project": "demo-font",
            "cve": "CVE-2025-27363",
            "dependency_evidence": [{"crate": "freetype-rs"}],
        }
        zlib_item = {
            "family": "zlib",
            "project": "demo-gzip",
            "cve": "CVE-2022-37434",
            "dependency_evidence": [{"crate": "libz-sys"}],
        }
        libarchive_item = {
            "family": "libarchive",
            "project": "demo-archive",
            "cve": "LIBARCHIVE-2025-FAMILY",
            "dependency_evidence": [{"crate": "compress-tools"}],
        }
        self.assertTrue(can_auto_generate(openh264_item))
        self.assertTrue(can_auto_generate(freetype_item))
        self.assertTrue(can_auto_generate(zlib_item))
        self.assertTrue(can_auto_generate(libarchive_item))
        openh264_rule = generate_vulns_payload(openh264_item)[0]
        freetype_rule = generate_vulns_payload(freetype_item)[0]
        zlib_rule = generate_vulns_payload(zlib_item)[0]
        libarchive_rule = generate_vulns_payload(libarchive_item)[0]
        self.assertEqual(openh264_rule["package"], "openh264-sys2")
        self.assertEqual(openh264_rule["symbols"], ["WelsDecodeBs"])
        self.assertEqual(freetype_rule["package"], "freetype")
        self.assertEqual(freetype_rule["version_range"], "<2.13.1")
        self.assertIn("FT_Load_Glyph", freetype_rule["symbols"])
        self.assertEqual(zlib_rule["package"], "zlib")
        self.assertEqual(zlib_rule["version_range"], "<1.2.13")
        self.assertIn("inflateGetHeader", zlib_rule["symbols"])
        self.assertEqual(libarchive_rule["package"], "libarchive")
        self.assertIn("archive_read_next_header", libarchive_rule["symbols"])

    def test_generate_extras_payload_skips_manual_dep_for_weak_libtiff_wrapper(self):
        with TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            (project_dir / "Cargo.lock").write_text(
                '[[package]]\nname = "zng-view"\nversion = "0.17.1"\n\n'
                '[[package]]\nname = "tiff"\nversion = "0.11.3"\n',
                encoding="utf-8",
            )
            payload = generate_extras_payload(
                {
                    "family": "libtiff",
                    "project": "zng-view",
                    "project_dir": str(project_dir),
                    "source_label": "top15_benchmark",
                }
            )
        self.assertEqual(payload["packages"], [{"name": "libtiff", "lang": "C"}])
        self.assertEqual(payload["depends"], [])

    def test_generate_extras_payload_keeps_manual_dep_for_sys_crate_evidence(self):
        with TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            (project_dir / "Cargo.lock").write_text(
                '[[package]]\nname = "tokio-native-tls"\nversion = "0.3.1"\n\n'
                '[[package]]\nname = "openssl-sys"\nversion = "0.9.112"\n',
                encoding="utf-8",
            )
            payload = generate_extras_payload(
                {
                    "family": "openssl",
                    "project": "tokio-native-tls",
                    "project_dir": str(project_dir),
                    "source_label": "top15_benchmark",
                }
            )
        self.assertEqual(payload["packages"], [{"name": "openssl", "lang": "C"}])
        self.assertEqual(len(payload["depends"]), 1)
        self.assertEqual(payload["depends"][0]["from"], "tokio-native-tls")
        self.assertEqual(payload["depends"][0]["to"], "openssl")
        self.assertEqual(payload["depends"][0]["evidence_type"], "manual")

    def test_allow_conservative_wrapper_reachability_requires_strong_bridge(self):
        self.assertFalse(
            _allow_conservative_wrapper_reachability(
                reachable=False,
                call_reachable=True,
                native_component_instances=[{"component": "libtiff"}],
                preserve_binary_decision=True,
                source_status="system",
                call_reachability_source="rust_method_code_package",
                strong_native_bridge_evidence=False,
            )
        )
        self.assertTrue(
            _allow_conservative_wrapper_reachability(
                reachable=False,
                call_reachable=True,
                native_component_instances=[{"component": "openssl"}],
                preserve_binary_decision=True,
                source_status="system",
                call_reachability_source="rust_method_code_package",
                strong_native_bridge_evidence=True,
            )
        )

    def test_evaluate_input_predicate_can_prune_non_target_type(self):
        rule = {
            "input_predicate": {
                "class": "crafted_webp_lossless",
                "strategy": "assume_if_not_explicit",
            }
        }
        chain_nodes = [
            {
                "id": 9,
                "labels": ["METHOD", "Rust"],
                "name": "decode_jpeg",
                "code": "if ty == ImageType::Jpeg { decoder.decode() }",
            }
        ]
        result = evaluate_input_predicate(rule, chain_nodes, [], [])
        self.assertEqual(result["status"], "failed")

    def test_synthesize_sink_calls_respects_contextual_rust_sink_specs(self):
        sinks = [
            {
                "path": "Decoder::decode",
                "contains": ["packet", "as_slice"],
                "contains_all": False,
            }
        ]
        benign = synthesize_sink_calls_from_method_code(
            [
                {
                    "id": 1,
                    "labels": ["METHOD", "Rust"],
                    "name": "connect",
                    "code": "let decoded_answer = base64::engine::general_purpose::STANDARD.decode(sd)?;",
                }
            ],
            sinks,
        )
        dangerous = synthesize_sink_calls_from_method_code(
            [
                {
                    "id": 2,
                    "labels": ["METHOD", "Rust"],
                    "name": "decode_video",
                    "code": "let decoded = decoder.decode(video_packet.as_slice());",
                }
            ],
            sinks,
        )
        self.assertEqual(benign, [])
        self.assertEqual(len(dangerous), 1)


class NativeSourceResolverTests(unittest.TestCase):
    def test_annotate_imported_c_nodes_batches_large_ranges(self):
        session = MagicMock()
        with patch.dict("os.environ", {"SUPPLYCHAIN_NEO4J_ANNOTATE_BATCH_SIZE": "3"}):
            annotate_imported_c_nodes(
                session,
                10,
                17,
                component="freetype",
                resolved_version="2.11.1",
                source_status="resolved",
                source_root="/tmp/freetype",
                provenance="native-source",
            )

        batches = [call.kwargs["ids"] for call in session.run.call_args_list]
        self.assertEqual(batches, [[10, 11, 12], [13, 14, 15], [16, 17]])

    def test_cpg_annotation_node_ids_keeps_only_method_and_call_nodes(self):
        with TemporaryDirectory() as tmp:
            cpg = Path(tmp) / "cpg.json"
            cpg.write_text(
                json.dumps(
                    {
                        "nodes": [
                            {"id": 1, "label": "METHOD"},
                            {"id": 2, "label": "LOCAL"},
                            {"id": 3, "labels": ["CALL", "C"]},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(_cpg_annotation_node_ids(str(cpg), 100), [101, 103])

    def test_provider_supports_official_download_for_common_components(self):
        for component in ["libxml2", "zlib", "expat", "openssl", "libwebp"]:
            provider = get_provider(component)
            self.assertIsNotNone(provider)
            self.assertTrue(provider.official_candidates("1.2.3"))

    def test_find_local_native_source_tree_prefers_bundled_source_dir(self):
        with TemporaryDirectory() as tmp:
            crate_dir = Path(tmp) / "openh264-sys2-0.4.4"
            upstream_dir = crate_dir / "upstream" / "codec" / "decoder"
            upstream_dir.mkdir(parents=True, exist_ok=True)
            manifest = crate_dir / "Cargo.toml"
            manifest.write_text("[package]\nname='openh264-sys2'\nversion='0.4.4'\n", encoding="utf-8")
            (upstream_dir / "welsDecoderExt.cpp").write_text(
                "int WelsDecodeBs() { return 0; }\n",
                encoding="utf-8",
            )
            result = find_local_native_source_tree("openh264-sys2", [str(manifest)])
            self.assertIsNotNone(result)
            self.assertEqual(result["status"], "local")
            self.assertEqual(result["provenance"], "bundled-local")
            self.assertTrue(result["source_root"].endswith("upstream"))

    def test_ensure_native_source_tree_returns_unsupported_for_unknown_component(self):
        result = ensure_native_source_tree(
            "unknown-component",
            "1.2.3",
            [],
            cache_root="/tmp/native-source-cache",
            allow_download=True,
        )
        self.assertEqual(result["status"], "unsupported")

    def test_find_symbol_source_files_and_scope(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "vendor"
            dec_dir = root / "src" / "dec"
            dec_dir.mkdir(parents=True, exist_ok=True)
            (dec_dir / "webp_dec.c").write_text("int WebPDecode(void) { return 0; }\n", encoding="utf-8")
            (dec_dir / "vp8l_dec.c").write_text("int VP8LDecodeImage(void) { return 0; }\n", encoding="utf-8")
            files = find_symbol_source_files(str(root), ["WebPDecode", "VP8LDecodeImage"])
            self.assertEqual(len(files), 2)
            scope = choose_c_analysis_scope(str(root), files)
            self.assertEqual(scope, str(dec_dir))

    def test_infer_native_source_dependencies_from_source_tree(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "libxml2-src"
            root.mkdir(parents=True, exist_ok=True)
            (root / "parser.c").write_text(
                '#include <zlib.h>\n#include <openssl/ssl.h>\nint parse(){ return 0; }\n',
                encoding="utf-8",
            )
            (root / "CMakeLists.txt").write_text(
                "find_package(OpenSSL REQUIRED)\npkg_check_modules(ZLIB REQUIRED zlib)\n",
                encoding="utf-8",
            )
            deps = infer_native_source_dependencies("libxml2", str(root))
            names = {item["component"] for item in deps}
            self.assertIn("zlib", names)
            self.assertIn("openssl", names)

    def test_parse_pkg_config_flags(self):
        lib_dirs, libs = _parse_pkg_config_flags("-L/usr/lib -L/opt/lib -lssl -lcrypto")
        self.assertEqual(lib_dirs, ["/usr/lib", "/opt/lib"])
        self.assertEqual(libs, ["ssl", "crypto"])

    def test_parse_ldd_output(self):
        rows = _parse_ldd_output(
            """
            libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007f)
            libssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3 (0x00007f)
            """
        )
        self.assertEqual(rows[0]["soname"], "libz.so.1")
        self.assertEqual(rows[1]["path"], "/lib/x86_64-linux-gnu/libssl.so.3")

    @patch("tools.fetch.native_symbol_resolver.collect_binary_linked_libraries")
    @patch("tools.fetch.native_symbol_resolver._pkg_config_probe")
    def test_collect_component_link_context(self, mock_pkg, mock_ldd):
        mock_pkg.return_value = {"name": "libxml-2.0", "ok": True, "libs": ["xml2"], "lib_dirs": ["/usr/lib"], "version": "2.9.14"}
        mock_ldd.return_value = [{"soname": "libz.so.1", "path": "/lib/libz.so.1"}]
        context = collect_component_link_context("libxml2", ["/tmp/libxml2.so"])
        self.assertIn("xml2", context["linked_tokens"])
        self.assertIn("z", context["linked_tokens"])

    @patch("tools.fetch.native_symbol_resolver.find_component_binaries")
    @patch("tools.fetch.native_symbol_resolver.collect_binary_exports")
    def test_build_symbol_provider_index_uses_binary_exports(self, mock_exports, mock_binaries):
        mock_binaries.side_effect = lambda component: [f"/tmp/{component}.so"] if component in {"zlib", "openssl"} else []
        mock_exports.side_effect = lambda path: {"inflate"} if "zlib" in path else {"SSL_read"}
        index = build_symbol_provider_index(["zlib", "openssl"])
        self.assertIn("zlib", index)
        self.assertIn("inflate", index["zlib"]["exports"])
        self.assertIn("openssl", index)
        self.assertIn("SSL_read", index["openssl"]["exports"])

    @patch("tools.fetch.native_symbol_resolver.collect_binary_linked_libraries")
    @patch("tools.fetch.native_symbol_resolver._pkg_config_probe")
    @patch("tools.fetch.native_symbol_resolver.build_symbol_provider_index")
    @patch("tools.fetch.native_symbol_resolver.collect_binary_imports")
    @patch("tools.fetch.native_symbol_resolver.find_component_binaries")
    def test_resolve_strict_native_dependencies_from_binary_symbols(self, mock_binaries, mock_imports, mock_index, mock_pkg, mock_ldd):
        mock_binaries.return_value = ["/tmp/libxml2.so"]
        mock_imports.return_value = {"inflate", "SSL_read", "unresolved_only"}
        mock_pkg.return_value = {"name": "libxml-2.0", "ok": True, "libs": ["z"], "lib_dirs": ["/usr/lib"], "version": "2.9.14"}
        mock_ldd.return_value = [{"soname": "libz.so.1", "path": "/lib/libz.so.1"}]
        mock_index.return_value = {
            "zlib": {"component": "zlib", "binaries": ["/tmp/libz.so"], "exports": {"inflate"}},
            "openssl": {"component": "openssl", "binaries": ["/tmp/libssl.so"], "exports": {"SSL_read"}},
            "libxml2": {"component": "libxml2", "binaries": ["/tmp/libxml2.so"], "exports": {"xmlParseDoc"}},
        }
        result = resolve_strict_native_dependencies("libxml2", resolved_version="2.9.14")
        self.assertEqual(result["status"], "resolved")
        names = {item["component"] for item in result["dependencies"]}
        self.assertEqual(names, {"zlib"})
        self.assertEqual(result["unresolved_symbol_count"], 2)
        self.assertIn("imports_by_binary", result)
        self.assertIn("link_context", result)

    def test_register_binary_symbol_inventory_creates_import_and_export_rows(self):
        session = MagicMock()
        strict = {
            "binaries": ["/tmp/libxml2.so"],
            "imports_by_binary": {"/tmp/libxml2.so": ["inflate"]},
            "dependencies": [
                {
                    "component": "zlib",
                    "provider_binaries": ["/tmp/libz.so"],
                    "provider_export_sample": ["inflate"],
                    "evidence": [{"binary": "/tmp/libxml2.so", "symbol": "inflate"}],
                }
            ],
        }
        stats = register_binary_symbol_inventory(session, "libxml2", strict)
        self.assertEqual(stats["binaries"], 1)
        self.assertEqual(stats["imports"], 1)
        self.assertGreaterEqual(stats["exports"], 1)
        self.assertGreaterEqual(session.run.call_count, 4)

    def test_resolve_external_c_calls_to_binary_symbols_emits_queries(self):
        session = MagicMock()
        strict = {
            "dependencies": [
                {
                    "component": "zlib",
                    "provider_binaries": ["/tmp/libz.so"],
                    "evidence": [{"binary": "/tmp/libxml2.so", "symbol": "inflate"}],
                }
            ]
        }
        edges = resolve_external_c_calls_to_binary_symbols(session, "libxml2", strict)
        self.assertEqual(edges, 1)
        self.assertEqual(session.run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
