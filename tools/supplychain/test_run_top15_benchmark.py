import json
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from tools.supplychain.run_top15_benchmark import (
    _apply_project_accuracy_adjustment,
    _accuracy_first_override_reason,
    _vuln_field_or_nested,
    aggregate_report,
    apply_match_crate_feature_hints,
    benchmark_label_issue_reason,
    build_archived_report_entry,
    build_fresh_cpg_rerun_manifest_item,
    build_issue_records,
    build_lockfile_deps,
    configure_analysis_env,
    deps_package_names,
    failure_reason_for_entry,
    filter_manifest_cargo_features,
    inactive_dependency_label_issue_reason,
    infer_match_crate_features,
    infer_packages_from_log,
    manifest_match_crates_inactive_by_default,
    manifest_dependency_sections,
    mismatch_reason,
    issue_owner_for_skip,
    prefetch_cargo_dependencies,
    preferred_shared_cache_root,
    preferred_tmp_root,
    pick_inventory_row,
    preferred_cargo_seed_home,
    seed_run_cargo_home,
    select_rules,
    should_infer_match_crate_feature_hints,
    should_isolate_benchmark_cargo_home,
    should_prefer_fresh_result,
    should_retry_with_fresh_cpg,
    target_vuln_id_for_item,
    validate_runtime_quick,
)


class RunTop15BenchmarkTests(unittest.TestCase):
    def test_validate_runtime_quick_detects_neo4j_socket_block(self):
        with patch("tools.supplychain.run_top15_benchmark.subprocess.run") as mock_run:
            mock_run.side_effect = [
                SimpleNamespace(returncode=1, stdout="", stderr="PermissionError: [Errno 1] Operation not permitted"),
            ]
            detail = validate_runtime_quick("/usr/bin/python3")
        self.assertIn("Neo4j connectivity probe failed", detail)
        self.assertIn("Operation not permitted", detail)

    def test_validate_runtime_quick_accepts_successful_socket_probe(self):
        with patch("tools.supplychain.run_top15_benchmark.subprocess.run") as mock_run:
            mock_run.side_effect = [
                SimpleNamespace(returncode=0, stdout="0\n", stderr=""),
                SimpleNamespace(returncode=0, stdout="ok\n", stderr=""),
            ]
            detail = validate_runtime_quick("/usr/bin/python3")
        self.assertIsNone(detail)

    def test_validate_runtime_quick_reports_neo4j_bolt_timeout_after_socket_success(self):
        with patch("tools.supplychain.run_top15_benchmark.subprocess.run") as mock_run:
            mock_run.side_effect = [
                SimpleNamespace(returncode=0, stdout="0\n", stderr=""),
                subprocess.TimeoutExpired(cmd=["python3", "-c", "from neo4j import GraphDatabase"], timeout=60),
            ]
            detail = validate_runtime_quick("/usr/bin/python3")
        self.assertIn("timed out while executing `RETURN 1` through Neo4j Bolt", detail)

    def test_validate_runtime_quick_restarts_local_neo4j_after_socket_refused(self):
        with patch("tools.supplychain.run_top15_benchmark.subprocess.run") as mock_run, patch(
            "tools.supplychain.run_top15_benchmark.shutil.which",
            return_value="/bin/systemctl",
        ), patch("tools.supplychain.run_top15_benchmark.time.sleep"):
            mock_run.side_effect = [
                SimpleNamespace(returncode=0, stdout="111\n", stderr=""),
                SimpleNamespace(returncode=0, stdout="", stderr=""),
                SimpleNamespace(returncode=0, stdout="0\n", stderr=""),
                SimpleNamespace(returncode=0, stdout="ok\n", stderr=""),
            ]
            detail = validate_runtime_quick("/usr/bin/python3")
        self.assertIsNone(detail)

    def test_configure_analysis_env_overrides_stale_shared_cache_env(self):
        with TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            (repo_root / "output" / "shared_native_cache").mkdir(parents=True, exist_ok=True)
            shm_root = repo_root / "runtime_shm"
            with patch("tools.supplychain.run_top15_benchmark.REPO_ROOT", repo_root), patch(
                "tools.supplychain.run_top15_benchmark.preferred_shared_cache_root",
                return_value=shm_root,
            ), patch.dict(
                "tools.supplychain.run_top15_benchmark.os.environ",
                {
                    "SUPPLYCHAIN_CARGO_HOME": "/mnt/hw/old_cargo_home",
                    "SUPPLYCHAIN_SHARED_CARGO_TARGET_ROOT": "/mnt/hw/old_target",
                    "SUPPLYCHAIN_SHARED_NATIVE_SOURCE_CACHE": "/mnt/hw/old_native",
                },
                clear=False,
            ):
                configure_analysis_env()
                self.assertEqual(os.environ["SUPPLYCHAIN_CARGO_HOME"], str((shm_root / "shared_cargo_home").resolve()))
                self.assertEqual(
                    os.environ["SUPPLYCHAIN_SHARED_CARGO_TARGET_ROOT"],
                    str((shm_root / "shared_cargo_target").resolve()),
                )
                self.assertEqual(
                    os.environ["SUPPLYCHAIN_SHARED_NATIVE_SOURCE_CACHE"],
                    str((shm_root / "shared_native_cache").resolve()),
                )

    def test_configure_analysis_env_prefers_local_home_cargo_seed(self):
        with TemporaryDirectory() as tmp:
            repo_root = Path(tmp) / "repo"
            repo_output = repo_root / "output"
            repo_output.mkdir(parents=True, exist_ok=True)
            remote_seed = Path(tmp) / "mnt_hw" / "shared_cargo_home"
            (remote_seed / "registry" / "cache" / "example").mkdir(parents=True, exist_ok=True)
            (remote_seed / "registry" / "cache" / "example" / "remote.crate").write_text("remote\n", encoding="utf-8")
            (repo_output / "shared_cargo_home").symlink_to(remote_seed)
            home_dir = Path(tmp) / "home"
            local_seed = home_dir / ".cargo"
            (local_seed / "registry" / "cache" / "example").mkdir(parents=True, exist_ok=True)
            (local_seed / "registry" / "cache" / "example" / "local.crate").write_text("local\n", encoding="utf-8")
            shm_root = Path(tmp) / "runtime_shm"
            with patch("tools.supplychain.run_top15_benchmark.REPO_ROOT", repo_root), patch(
                "tools.supplychain.run_top15_benchmark.preferred_shared_cache_root",
                return_value=shm_root,
            ), patch(
                "tools.supplychain.run_top15_benchmark.is_slow_cache_path",
                side_effect=lambda path, env=None: "mnt_hw" in str(Path(path).resolve()),
            ), patch.dict(
                "tools.supplychain.run_top15_benchmark.os.environ",
                {"HOME": str(home_dir)},
                clear=False,
            ):
                configure_analysis_env()
                seeded_file = shm_root / "shared_cargo_home" / "registry" / "cache" / "example" / "local.crate"
                self.assertTrue(seeded_file.exists())
                self.assertFalse(
                    (shm_root / "shared_cargo_home" / "registry" / "cache" / "example" / "remote.crate").exists()
                )

    def test_configure_analysis_env_skips_seed_for_populated_shared_cargo_home(self):
        with TemporaryDirectory() as tmp:
            repo_root = Path(tmp) / "repo"
            (repo_root / "output" / "shared_native_cache").mkdir(parents=True, exist_ok=True)
            shm_root = Path(tmp) / "runtime_shm"
            existing_cache = shm_root / "shared_cargo_home" / "registry" / "cache" / "example"
            existing_cache.mkdir(parents=True, exist_ok=True)
            (existing_cache / "existing.crate").write_text("cached\n", encoding="utf-8")
            seed_home = Path(tmp) / "seed_home"
            (seed_home / "registry" / "cache" / "example").mkdir(parents=True, exist_ok=True)
            (seed_home / "registry" / "cache" / "example" / "seed.crate").write_text("seed\n", encoding="utf-8")
            with patch("tools.supplychain.run_top15_benchmark.REPO_ROOT", repo_root), patch(
                "tools.supplychain.run_top15_benchmark.preferred_shared_cache_root",
                return_value=shm_root,
            ), patch(
                "tools.supplychain.run_top15_benchmark.preferred_cargo_seed_home",
                return_value=seed_home,
            ), patch("tools.supplychain.run_top15_benchmark.seed_run_cargo_home") as mock_seed:
                configure_analysis_env()
            mock_seed.assert_not_called()

    def test_infer_packages_from_log_picks_freetype_and_glu(self):
        log_text = """
The system library `freetype2` required by crate `freetype-sys` was not found.
fatal error: GL/glu.h: No such file or directory
"""
        packages = infer_packages_from_log(log_text)
        self.assertIn("libfreetype-dev", packages)
        self.assertIn("libglu1-mesa-dev", packages)
        self.assertIn("libgl1-mesa-dev", packages)

    def test_infer_packages_from_log_picks_gtk4_stack(self):
        log_text = """
The system library `gtk4` required by crate `gdk4-sys` was not found.
The file `gtk4.pc` needs to be installed.
"""
        packages = infer_packages_from_log(log_text)
        self.assertIn("libgtk-4-dev", packages)
        self.assertIn("libadwaita-1-dev", packages)
        self.assertIn("libgstreamer1.0-dev", packages)
        self.assertIn("libgstreamer-plugins-base1.0-dev", packages)
        self.assertIn("pkg-config", packages)

    def test_preferred_shared_cache_root_uses_dev_shm_when_repo_output_is_tight(self):
        with patch("tools.supplychain.run_top15_benchmark.shutil.disk_usage") as mock_disk_usage:
            def fake_disk_usage(path):
                path_text = str(path)
                if path_text == "/dev/shm":
                    return SimpleNamespace(free=32 * 1024 * 1024 * 1024)
                return SimpleNamespace(free=256 * 1024 * 1024)

            mock_disk_usage.side_effect = fake_disk_usage
            resolved = preferred_shared_cache_root(env={})
        self.assertEqual(resolved, Path("/dev/shm/cpg_generator_export"))

    def test_preferred_shared_cache_root_uses_dev_shm_when_repo_output_cache_is_slow(self):
        with TemporaryDirectory() as tmp:
            repo_root = Path(tmp) / "repo"
            repo_output = repo_root / "output"
            repo_output.mkdir(parents=True, exist_ok=True)
            slow_seed = Path(tmp) / "mnt_hw" / "shared_cargo_home"
            slow_native = Path(tmp) / "mnt_hw" / "shared_native_cache"
            slow_seed.mkdir(parents=True, exist_ok=True)
            slow_native.mkdir(parents=True, exist_ok=True)
            (repo_output / "shared_cargo_home").symlink_to(slow_seed)
            (repo_output / "shared_native_cache").symlink_to(slow_native)
            with patch("tools.supplychain.run_top15_benchmark.REPO_ROOT", repo_root), patch(
                "tools.supplychain.run_top15_benchmark.is_slow_cache_path",
                side_effect=lambda path, env=None: "mnt_hw" in str(Path(path).resolve()),
            ), patch("tools.supplychain.run_top15_benchmark.shutil.disk_usage") as mock_disk_usage:
                mock_disk_usage.return_value = SimpleNamespace(free=64 * 1024 * 1024 * 1024)
                resolved = preferred_shared_cache_root(env={})
            self.assertEqual(resolved, Path("/dev/shm/cpg_generator_export"))

    def test_preferred_tmp_root_uses_dev_shm_when_available(self):
        with patch("tools.supplychain.run_top15_benchmark.shutil.disk_usage") as mock_disk_usage:
            def fake_disk_usage(path):
                path_text = str(path)
                if path_text == "/dev/shm":
                    return SimpleNamespace(free=4 * 1024 * 1024 * 1024)
                return SimpleNamespace(free=0)

            mock_disk_usage.side_effect = fake_disk_usage
            resolved = preferred_tmp_root(env={})
        self.assertEqual(resolved, Path("/dev/shm/cpg_generator_export/tmp"))

    def test_should_isolate_benchmark_cargo_home_uses_shared_mode_under_low_free_space(self):
        with patch("tools.supplychain.run_top15_benchmark.shutil.disk_usage") as mock_disk_usage:
            mock_disk_usage.return_value = SimpleNamespace(free=512 * 1024 * 1024)
            self.assertFalse(
                should_isolate_benchmark_cargo_home(
                    workspace_root=Path("/tmp/work"),
                    env={},
                )
            )

    def test_should_isolate_benchmark_cargo_home_honors_explicit_isolated_mode(self):
        self.assertTrue(
            should_isolate_benchmark_cargo_home(
                workspace_root=Path("/tmp/work"),
                env={"SUPPLYCHAIN_BENCHMARK_CARGO_HOME_MODE": "isolated"},
            )
        )

    def test_should_isolate_benchmark_cargo_home_prefers_shared_mode_for_dev_shm_cache(self):
        self.assertFalse(
            should_isolate_benchmark_cargo_home(
                workspace_root=Path("/tmp/work"),
                env={"SUPPLYCHAIN_CARGO_HOME": "/dev/shm/cpg_generator_export/shared_cargo_home"},
            )
        )

    def test_preferred_cargo_seed_home_skips_slow_output_cache(self):
        with TemporaryDirectory() as tmp:
            repo_output = Path(tmp) / "repo_output"
            repo_output.mkdir(parents=True, exist_ok=True)
            slow_seed = Path(tmp) / "mnt_hw" / "shared_cargo_home"
            (slow_seed / "registry").mkdir(parents=True, exist_ok=True)
            (repo_output / "shared_cargo_home").symlink_to(slow_seed)
            home_dir = Path(tmp) / "home"
            local_seed = home_dir / ".cargo"
            (local_seed / "registry" / "cache").mkdir(parents=True, exist_ok=True)
            with patch("tools.supplychain.run_top15_benchmark.is_slow_cache_path") as mock_slow, patch.dict(
                "tools.supplychain.run_top15_benchmark.os.environ",
                {"HOME": str(home_dir)},
                clear=False,
            ):
                mock_slow.side_effect = lambda path, env=None: "mnt_hw" in str(Path(path).resolve())
                resolved = preferred_cargo_seed_home(repo_output_root=repo_output, env=os.environ)
            self.assertEqual(resolved, local_seed.resolve())

    def test_seed_run_cargo_home_skips_registry_src(self):
        with TemporaryDirectory() as tmp:
            seed = Path(tmp) / "seed"
            dest = Path(tmp) / "dest"
            (seed / "registry" / "index" / "example").mkdir(parents=True, exist_ok=True)
            (seed / "registry" / "cache" / "example").mkdir(parents=True, exist_ok=True)
            (seed / "registry" / "src" / "example").mkdir(parents=True, exist_ok=True)
            (seed / "git" / "checkouts").mkdir(parents=True, exist_ok=True)
            (seed / "registry" / "index" / "example" / "index.json").write_text("{}", encoding="utf-8")
            (seed / "registry" / "cache" / "example" / "crate.crate").write_text("crate", encoding="utf-8")
            (seed / "registry" / "src" / "example" / "README.md").write_text("src", encoding="utf-8")
            (seed / "git" / "checkouts" / "HEAD").write_text("head", encoding="utf-8")
            seed_run_cargo_home(dest, seed)
            self.assertTrue((dest / "registry" / "index" / "example" / "index.json").exists())
            self.assertTrue((dest / "registry" / "cache" / "example" / "crate.crate").exists())
            self.assertTrue((dest / "git" / "checkouts" / "HEAD").exists())
            self.assertFalse((dest / "registry" / "src").exists())

    def test_seed_run_cargo_home_supplements_existing_cache_without_overwrite(self):
        with TemporaryDirectory() as tmp:
            seed = Path(tmp) / "seed"
            dest = Path(tmp) / "dest"
            (seed / "registry" / "cache" / "example").mkdir(parents=True, exist_ok=True)
            (seed / "registry" / "cache" / "example" / "new.crate").write_text("new", encoding="utf-8")
            (seed / "registry" / "index" / "example").mkdir(parents=True, exist_ok=True)
            (seed / "registry" / "index" / "example" / "index.json").write_text("{}", encoding="utf-8")
            (dest / "registry" / "cache" / "example").mkdir(parents=True, exist_ok=True)
            (dest / "registry" / "cache" / "example" / "keep.crate").write_text("keep", encoding="utf-8")
            seed_run_cargo_home(dest, seed)
            self.assertTrue((dest / "registry" / "cache" / "example" / "keep.crate").exists())
            self.assertEqual(
                (dest / "registry" / "cache" / "example" / "keep.crate").read_text(encoding="utf-8"),
                "keep",
            )
            self.assertTrue((dest / "registry" / "cache" / "example" / "new.crate").exists())
            self.assertTrue((dest / "registry" / "index" / "example" / "index.json").exists())

    def test_target_vuln_id_normalizes_component_suffix(self):
        item = {
            "component": "pcre2",
            "matched_vulnerability": "CVE-2022-1586",
        }
        self.assertEqual(target_vuln_id_for_item(item), "CVE-2022-1586__pcre2")

    def test_pick_inventory_row_prefers_matching_vuln_and_non_failed_status(self):
        rows = [
            {
                "vuln_id": "CVE-2025-58050__pcre2",
                "case_status": "analysis_failed",
                "resolved_project_source": "/tmp/source",
                "analysis_report": "/tmp/report_failed.json",
                "evidence_record_count": "10",
            },
            {
                "vuln_id": "CVE-2022-1586__pcre2",
                "case_status": "not_reachable",
                "resolved_project_source": "/tmp/source",
                "analysis_report": "/tmp/report_ok.json",
                "evidence_record_count": "2",
            },
        ]
        picked = pick_inventory_row(rows, target_vuln_id="CVE-2022-1586__pcre2")
        self.assertEqual(picked["vuln_id"], "CVE-2022-1586__pcre2")
        self.assertEqual(picked["case_status"], "not_reachable")

    def test_build_lockfile_deps_prunes_inactive_optional_dependency(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                """
[package]
name = "demo"
version = "0.1.0"

[dependencies]
glob = "0.3"
onig = "6"
pcre2 = { version = "0.2", optional = true }

[features]
default = []
pcre2 = ["dep:pcre2"]
""".strip()
                + "\n",
                encoding="utf-8",
            )
            (root / "Cargo.lock").write_text(
                """
version = 3

[[package]]
name = "demo"
version = "0.1.0"
dependencies = ["glob", "onig", "pcre2"]

[[package]]
name = "glob"
version = "0.3.0"

[[package]]
name = "onig"
version = "6.0.0"

[[package]]
name = "pcre2"
version = "0.2.11"
dependencies = ["pcre2-sys"]

[[package]]
name = "pcre2-sys"
version = "0.2.10"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            deps_path = build_lockfile_deps(
                project_dir=root,
                deps_cache_dir=root / "deps",
                root_name_hint="demo",
                enabled_features=[],
            )
            names = deps_package_names(deps_path)
            self.assertIn("glob", names)
            self.assertIn("onig", names)
            self.assertNotIn("pcre2", names)
            self.assertNotIn("pcre2-sys", names)

    def test_build_lockfile_deps_keeps_active_optional_dependency(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                """
[package]
name = "demo"
version = "0.1.0"

[dependencies]
glob = "0.3"
pcre2 = { version = "0.2", optional = true }

[features]
default = []
pcre2 = ["dep:pcre2"]
""".strip()
                + "\n",
                encoding="utf-8",
            )
            (root / "Cargo.lock").write_text(
                """
version = 3

[[package]]
name = "demo"
version = "0.1.0"
dependencies = ["glob", "pcre2"]

[[package]]
name = "glob"
version = "0.3.0"

[[package]]
name = "pcre2"
version = "0.2.11"
dependencies = ["pcre2-sys"]

[[package]]
name = "pcre2-sys"
version = "0.2.10"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            deps_path = build_lockfile_deps(
                project_dir=root,
                deps_cache_dir=root / "deps",
                root_name_hint="demo",
                enabled_features=["pcre2"],
            )
            names = deps_package_names(deps_path)
            self.assertIn("pcre2", names)
            self.assertIn("pcre2-sys", names)

    def test_infer_match_crate_features_enables_feature_wrapping_optional_dependency(self):
        manifest = {
            "dependencies": {
                "png": "0.17",
                "turbojpeg": {"version": "1.2", "optional": True},
            },
            "features": {
                "default": [],
                "turbojpeg": ["dep:turbojpeg"],
            },
        }
        self.assertEqual(infer_match_crate_features(manifest, ["libjpeg-turbo", "turbojpeg"]), ["turbojpeg"])

    def test_infer_match_crate_features_does_not_emit_plain_dependency_as_feature(self):
        manifest = {
            "dependencies": {
                "turbojpeg": {"version": "1.3"},
            },
            "features": {
                "default": [],
            },
        }
        self.assertEqual(infer_match_crate_features(manifest, ["turbojpeg"]), [])

    def test_infer_match_crate_features_uses_dep_wrapping_feature_only(self):
        manifest = {
            "dependencies": {
                "ffmpeg-next": {"version": "5.1", "optional": True},
            },
            "features": {
                "default": [],
                "ffmpeg": ["dep:ffmpeg-next", "stream"],
                "stream": [],
            },
        }
        self.assertEqual(infer_match_crate_features(manifest, ["ffmpeg-next"]), ["ffmpeg"])

    def test_infer_match_crate_features_skips_semantic_feature_alias_for_optional_dependency(self):
        manifest = {
            "dependencies": {
                "ffmpeg-next": {"version": "7.0.2", "optional": True},
            },
            "features": {
                "default": [],
                "h264": ["dep:ffmpeg-next"],
            },
        }
        self.assertEqual(infer_match_crate_features(manifest, ["ffmpeg-next"]), [])

    def test_infer_match_crate_features_skips_non_runtime_optional_features(self):
        manifest = {
            "dependencies": {
                "aom-sys": {"version": "0.3.3", "optional": True},
            },
            "features": {
                "default": [],
                "decode_test": ["aom-sys"],
                "bench-aom": ["dep:aom-sys"],
            },
        }
        self.assertEqual(infer_match_crate_features(manifest, ["aom-sys", "libaom"]), [])

    def test_infer_match_crate_features_does_not_enable_non_optional_dependency_subfeatures(self):
        manifest = {
            "dependencies": {
                "ffi": {"version": "0.9", "package": "openssl-sys"},
            },
            "features": {
                "default": [],
                "unstable_boringssl": ["ffi/unstable_boringssl"],
                "vendored": ["ffi/vendored"],
            },
        }
        self.assertEqual(infer_match_crate_features(manifest, ["openssl-sys"]), [])

    def test_infer_match_crate_features_keeps_default_dependency_subfeatures(self):
        manifest = {
            "dependencies": {
                "libwebp-sys": {"version": "0.14.1"},
            },
            "features": {
                "default": ["std"],
                "std": ["libwebp-sys/std"],
            },
        }
        self.assertEqual(infer_match_crate_features(manifest, ["libwebp-sys"]), ["std"])

    def test_filter_manifest_cargo_features_drops_plain_non_optional_dependency_names(self):
        manifest = {
            "dependencies": {
                "libwebp-sys": {"version": "0.14.1"},
            },
            "features": {
                "default": ["std"],
                "std": ["libwebp-sys/std"],
            },
        }
        kept, dropped = filter_manifest_cargo_features(manifest, "libwebp-sys,std")
        self.assertEqual(kept, ["std"])
        self.assertEqual(dropped, ["libwebp-sys"])

    def test_filter_manifest_cargo_features_drops_dep_colon_optional_dependency_names(self):
        manifest = {
            "dependencies": {
                "gdal-sys": {"version": "0.11", "optional": True},
            },
            "features": {
                "default": [],
                "with-gdal": ["dep:gdal-sys"],
            },
        }
        kept, dropped = filter_manifest_cargo_features(manifest, "gdal-sys,with-gdal")
        self.assertEqual(kept, ["with-gdal"])
        self.assertEqual(dropped, ["gdal-sys"])

    def test_apply_match_crate_feature_hints_filters_stale_archived_features(self):
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
            hints = {"cargo_features": "libwebp-sys", "enabled_features": []}
            apply_match_crate_feature_hints(
                project_dir=root,
                hints=hints,
                match_crates=["libwebp-sys"],
            )
        self.assertEqual(hints["cargo_features"], "std")
        self.assertEqual(hints["dropped_cargo_features"], ["libwebp-sys"])

    def test_should_infer_match_crate_feature_hints_preserves_manual_default_graph_review(self):
        item = {
            "label_status": "manual_code_review_label",
            "matched_case_status": "manual_source_review",
            "evidence_basis": "Fresh source review of default Cargo feature graph.",
            "note": "Default features do not include the sqlite backend.",
        }
        self.assertFalse(
            should_infer_match_crate_feature_hints(
                item=item,
                hints={
                    "cargo_features": "",
                    "cargo_all_features": False,
                    "cargo_no_default_features": False,
                },
            )
        )
        self.assertTrue(
            should_infer_match_crate_feature_hints(
                item=item,
                hints={
                    "cargo_features": "sqlite",
                    "cargo_all_features": False,
                    "cargo_no_default_features": False,
                },
            )
        )

    def test_manifest_match_crates_inactive_by_default_detects_optional_sqlite_dependency(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                """
[package]
name = "demo"
version = "0.1.0"

[dependencies]
rusqlite = { version = "0.39", optional = true }

[features]
default = []
sqlite = ["dep:rusqlite"]
""".lstrip(),
                encoding="utf-8",
            )
            self.assertTrue(
                manifest_match_crates_inactive_by_default(
                    project_dir=root,
                    enabled_features=[],
                    match_crates=["rusqlite", "libsqlite3-sys"],
                )
            )
            self.assertFalse(
                manifest_match_crates_inactive_by_default(
                    project_dir=root,
                    enabled_features=["sqlite"],
                    match_crates=["rusqlite", "libsqlite3-sys"],
                )
            )

    def test_build_lockfile_deps_uses_stable_unique_filename_for_upstream_dirs(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            first = base / "libwebp" / "atomic-server-0.40.1" / "upstream"
            second = base / "libwebp" / "novel-api-0.19.0" / "upstream"
            for root, name in ((first, "atomic-server"), (second, "novel-api")):
                root.mkdir(parents=True, exist_ok=True)
                (root / "Cargo.toml").write_text(
                    f"[package]\nname = '{name}'\nversion = '0.1.0'\n",
                    encoding="utf-8",
                )
                (root / "Cargo.lock").write_text(
                    f"version = 3\n\n[[package]]\nname = '{name}'\nversion = '0.1.0'\n",
                    encoding="utf-8",
                )
            first_path = build_lockfile_deps(
                project_dir=first,
                deps_cache_dir=base / "deps",
                root_name_hint="atomic-server",
                enabled_features=[],
            )
            second_path = build_lockfile_deps(
                project_dir=second,
                deps_cache_dir=base / "deps",
                root_name_hint="novel-api",
                enabled_features=[],
            )
            self.assertNotEqual(first_path.name, second_path.name)
            self.assertIn("atomic-server", first_path.name)
            self.assertIn("novel-api", second_path.name)

    def test_manifest_dependency_sections_tracks_dev_dependencies(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                """
[package]
name = "demo"
version = "0.1.0"

[dependencies]
quick-error = "2"

[dev-dependencies.webp]
version = "0.3"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            sections = manifest_dependency_sections(root)
        self.assertEqual(sections["webp"], {"dev-dependencies"})
        self.assertEqual(sections["quick-error"], {"dependencies"})

    def test_inactive_dependency_label_issue_reason_detects_dev_only_label_drift(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                """
[package]
name = "image-webp"
version = "0.2.4"

[dependencies]
quick-error = "2"

[dev-dependencies.webp]
version = "0.3"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            reason = inactive_dependency_label_issue_reason(
                {
                    "label_status": "manual_archived_label",
                    "strict_label": "triggerable",
                    "matched_case_status": "triggerable_confirmed",
                    "entry_crate": "webp",
                },
                project_dir=root,
                selection={"match_crates": ["webp", "libwebp-sys"]},
            )
        self.assertIn("benchmark label dependency-scope drift", reason)
        self.assertIn("dev-dependencies", reason)

    def test_inactive_dependency_label_issue_reason_detects_dev_only_manual_review_drift(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                """
[package]
name = "startin"
version = "0.8.3"

[dependencies]
serde = "1"

[dev-dependencies.gdal]
version = "0.16"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            reason = inactive_dependency_label_issue_reason(
                {
                    "label_status": "manual_code_review_label",
                    "strict_label": "reachable_but_not_triggerable",
                    "matched_case_status": "analysis_failed",
                    "entry_crate": "gdal",
                },
                project_dir=root,
                selection={"match_crates": ["gdal", "gdal-sys"]},
            )
        self.assertIn("benchmark label dependency-scope drift", reason)
        self.assertIn("dev-dependencies", reason)

    def test_inactive_dependency_label_issue_reason_detects_optional_dependency_drift(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                """
[package]
name = "oauth2"
version = "5.0.0"

[features]
default = ["reqwest", "rustls-tls"]
rustls-tls = ["reqwest/rustls-tls"]

[dependencies.reqwest]
version = "0.12"
optional = true
default-features = false

[target.'cfg(not(target_arch = "wasm32"))'.dependencies.curl]
version = "0.4"
optional = true
""".strip()
                + "\n",
                encoding="utf-8",
            )
            reason = inactive_dependency_label_issue_reason(
                {
                    "label_status": "manual_code_review_label",
                    "strict_label": "reachable_but_not_triggerable",
                    "entry_crate": "oauth2",
                },
                project_dir=root,
                selection={"match_crates": ["curl", "curl-sys", "isahc"]},
            )
        self.assertIn("benchmark label feature/target drift", reason)
        self.assertIn("optional dependencies", reason)

    def test_project_adjustment_keeps_gstreamer_parse_launch_as_possible_only(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                """
[package]
name = "kornia-io"
version = "0.1.10"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "lib.rs").write_text(
                """
pub fn open_video(path: &str) {
    let _ = gstreamer::parse::launch(
        &format!("filesrc location={path} ! decodebin ! videoconvert ! appsink name=sink")
    );
}
""".strip()
                + "\n",
                encoding="utf-8",
            )
            adjusted = _apply_project_accuracy_adjustment(
                "gstreamer",
                root,
                {
                    "predicted_label": "reachable_but_not_triggerable",
                    "research_label": "triggerable",
                    "best_run_status": "reachable_only",
                    "call_reachability_sources": ["rust_call_package"],
                },
            )
        self.assertEqual(adjusted["predicted_label"], "reachable_but_not_triggerable")
        self.assertEqual(adjusted["best_run_status"], "triggerable_possible")
        self.assertEqual(adjusted["project_adjustment_reason"], "gstreamer_direct_pipeline_parse_possible_only")

    def test_project_adjustment_demotes_gstreamer_backend_only_sink_to_unreachable(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                """
[package]
name = "librespot-playback"
version = "0.8.0"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "lib.rs").write_text(
                """
pub fn open(device: Option<String>) {
    let _ = gst::ElementFactory::make("appsrc");
    let _ = match device {
        None => gst::parse::bin_from_description(
            "audioconvert ! audioresample ! autoaudiosink",
            true,
        ),
        Some(x) => gst::parse::bin_from_description(&x, true),
    };
}
""".strip()
                + "\n",
                encoding="utf-8",
            )
            adjusted = _apply_project_accuracy_adjustment(
                "gstreamer",
                root,
                {
                    "predicted_label": "reachable_but_not_triggerable",
                    "research_label": "triggerable",
                    "best_run_status": "reachable_only",
                    "call_reachability_sources": ["rust_call_package"],
                },
            )
        self.assertEqual(adjusted["predicted_label"], "unreachable")
        self.assertEqual(adjusted["best_run_status"], "not_reachable")

    def test_project_adjustment_promotes_default_pure_rust_png_decoder(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                """
[package]
name = "tiny-skia"
version = "0.12.0"

[features]
default = ["png-format"]
png-format = ["dep:png"]

[dependencies.png]
version = "0.18"
optional = true
""".strip()
                + "\n",
                encoding="utf-8",
            )
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "lib.rs").write_text(
                """
pub fn decode_png(data: &[u8]) -> Result<(), png::DecodingError> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(data));
    let mut reader = decoder.read_info()?;
    let mut buf = vec![0; reader.output_buffer_size().unwrap_or(0)];
    let _ = reader.next_frame(&mut buf)?;
    Ok(())
}
""".strip()
                + "\n",
                encoding="utf-8",
            )
            adjusted = _apply_project_accuracy_adjustment(
                "libpng",
                root,
                {
                    "predicted_label": "unreachable",
                    "research_label": "unreachable",
                    "best_run_status": "not_reachable",
                    "call_reachability_sources": [],
                },
            )
        self.assertEqual(adjusted["predicted_label"], "reachable_but_not_triggerable")
        self.assertEqual(adjusted["best_run_status"], "reachable_only")

    def test_project_adjustment_demotes_zlib_wrapper_library_only(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                """
[package]
name = "flate2"
version = "1.1.9"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            (root / "src" / "ffi").mkdir(parents=True, exist_ok=True)
            (root / "src" / "ffi" / "c.rs").write_text(
                """
pub unsafe fn mz_inflateInit2() {
    let _ = libz_sys::inflateInit2_(std::ptr::null_mut(), 0, std::ptr::null(), 0);
}
""".strip()
                + "\n",
                encoding="utf-8",
            )
            adjusted = _apply_project_accuracy_adjustment(
                "zlib",
                root,
                {
                    "predicted_label": "triggerable",
                    "research_label": "triggerable",
                    "best_run_status": "triggerable_possible",
                    "call_reachability_sources": ["rust_call_package"],
                },
            )
        self.assertEqual(adjusted["predicted_label"], "unreachable")
        self.assertEqual(adjusted["best_run_status"], "not_reachable")

    def test_project_adjustment_keeps_libjpeg_binary_decode_gateway_as_possible_only(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                """
[package]
name = "reduce-image-size"
version = "0.1.0"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "main.rs").write_text(
                """
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let image_data = std::fs::read("input.jpg")?;
    let _ = turbojpeg::decompress_image(&image_data)?;
    Ok(())
}
""".strip()
                + "\n",
                encoding="utf-8",
            )
            adjusted = _apply_project_accuracy_adjustment(
                "libjpeg-turbo",
                root,
                {
                    "predicted_label": "reachable_but_not_triggerable",
                    "research_label": "triggerable",
                    "best_run_status": "reachable_only",
                    "call_reachability_sources": ["rust_native_gateway_package"],
                },
            )
        self.assertEqual(adjusted["predicted_label"], "reachable_but_not_triggerable")
        self.assertEqual(adjusted["best_run_status"], "triggerable_possible")
        self.assertEqual(adjusted["project_adjustment_reason"], "libjpeg_binary_decode_gateway_possible_only")

    def test_project_adjustment_demotes_pcre2_without_explicit_jit_request(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                """
[package]
name = "hyperpolyglot"
version = "0.1.7"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "lib.rs").write_text(
                """
pub fn matches(pattern: &str, content: &str) -> bool {
    let regex = pcre2::bytes::RegexBuilder::new()
        .multi_line(true)
        .build(pattern)
        .unwrap();
    regex.is_match(content.as_bytes()).unwrap_or(false)
}
""".strip()
                + "\n",
                encoding="utf-8",
            )
            adjusted = _apply_project_accuracy_adjustment(
                "pcre2",
                root,
                {
                    "predicted_label": "triggerable",
                    "research_label": "triggerable",
                    "best_run_status": "triggerable_possible",
                    "call_reachability_sources": ["rust_native_gateway_package"],
                },
            )
        self.assertEqual(adjusted["predicted_label"], "reachable_but_not_triggerable")
        self.assertEqual(adjusted["best_run_status"], "reachable_only")
        self.assertEqual(adjusted["project_adjustment_reason"], "pcre2_no_explicit_jit_request")

    def test_project_adjustment_keeps_pcre2_with_explicit_jit_request(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                """
[package]
name = "fastokens"
version = "0.1.1"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "lib.rs").write_text(
                """
pub fn matches(pattern: &str, content: &str) -> bool {
    let regex = pcre2::bytes::RegexBuilder::new()
        .jit_if_available(true)
        .build(pattern)
        .unwrap();
    regex.is_match(content.as_bytes()).unwrap_or(false)
}
""".strip()
                + "\n",
                encoding="utf-8",
            )
            adjusted = _apply_project_accuracy_adjustment(
                "pcre2",
                root,
                {
                    "predicted_label": "triggerable",
                    "research_label": "triggerable",
                    "best_run_status": "triggerable_possible",
                    "call_reachability_sources": ["rust_native_gateway_package"],
                },
            )
        self.assertEqual(adjusted["predicted_label"], "triggerable")
        self.assertEqual(adjusted["best_run_status"], "triggerable_possible")
        self.assertNotIn("project_adjustment_reason", adjusted)

    def test_accuracy_first_override_marks_weak_pcre2_gateway_as_unreachable(self):
        vuln = {
            "call_reachability_source": "rust_native_gateway_package",
            "unresolved_guards": ["env_guard:0"],
            "trigger_model_eval": None,
            "evidence_calls": None,
            "input_predicate_eval": None,
            "param_semantics": None,
            "state_semantics": None,
        }
        self.assertEqual(
            _accuracy_first_override_reason("pcre2", vuln),
            "weak_pcre2_gateway_only",
        )

    def test_accuracy_first_override_marks_libaom_without_native_version_as_unreachable(self):
        vuln = {
            "package": "libaom",
            "resolved_version": "",
            "native_component_instances": [
                {
                    "component": "libaom",
                    "resolved_version": None,
                    "status": "unknown",
                    "source": "unknown",
                }
            ],
        }
        self.assertEqual(
            _accuracy_first_override_reason("libaom", vuln),
            "libaom_native_version_unresolved",
        )

    def test_accuracy_first_override_marks_missing_jit_trigger_as_unreachable(self):
        vuln = {
            "call_reachability_source": "rust_method_code_package",
            "unresolved_guards": ["trigger:pcre2_build", "trigger:pcre2_pattern_input", "env_guard:0"],
            "trigger_model_eval": None,
            "evidence_calls": None,
            "input_predicate_eval": None,
            "param_semantics": None,
            "state_semantics": None,
        }
        self.assertEqual(
            _accuracy_first_override_reason("pcre2", vuln),
            "weak_pcre2_method_without_jit_trigger",
        )

    def test_accuracy_first_override_marks_source_text_only_pcre2_build_as_unreachable(self):
        vuln = {
            "call_reachability_source": "rust_native_gateway_package",
            "conditions": {
                "trigger_model_hits": {
                    "required_hits": [
                        {
                            "id": "pcre2_build",
                            "evidence": [
                                {
                                    "scope": "synthetic_source_text",
                                    "method": "src/quick.rs:216",
                                    "file": "src/quick.rs",
                                    "code": "RegexBuilder::new(...).build().unwrap()",
                                }
                            ],
                        }
                    ]
                },
                "input_predicate_eval": {
                    "status": "satisfied",
                    "strategy": "assume_if_not_explicit",
                },
                "external_input_evidence": {
                    "status": "not_applicable",
                    "external_hits": [],
                    "local_hits": [],
                },
            },
        }
        self.assertEqual(
            _accuracy_first_override_reason("pcre2", vuln),
            "pcre2_source_text_only_jit_path",
        )

    def test_accuracy_first_override_marks_weak_libjpeg_wrapper_only_as_reachable_only(self):
        vuln = {
            "call_reachability_source": "rust_call_package",
            "downgrade_reason": "source_status=system;preserved_by_wrapper_sink_evidence;native_dependency_graph_incomplete",
            "conditions": {
                "trigger_model_hits": {
                    "required_hits": [
                        {
                            "id": "jpeg_header_any",
                            "evidence": [
                                {
                                    "scope": "chain",
                                    "name": "read_header",
                                },
                                {
                                    "scope": "synthetic_package_method_code",
                                    "method": "decompress",
                                    "code": "let header = decompressor.read_header(jpeg_data)?;",
                                },
                                {
                                    "scope": "synthetic_source_text",
                                    "method": "src/decompress.rs:433",
                                    "file": "src/decompress.rs",
                                    "code": "let header = decompressor.read_header(jpeg_data)?;",
                                },
                            ],
                        }
                    ]
                },
                "input_predicate_eval": {
                    "status": "satisfied",
                    "strategy": "assume_if_not_explicit",
                },
                "external_input_evidence": {
                    "status": "not_applicable",
                    "external_hits": [],
                    "local_hits": [],
                },
            },
        }
        self.assertEqual(
            _accuracy_first_override_reason("libjpeg-turbo", vuln),
            "weak_libjpeg_wrapper_only",
        )

    def test_select_rules_prefers_project_candidate_cve_subset(self):
        with TemporaryDirectory() as tmp:
            rule_path, selection = select_rules(
                {
                    "component": "ffmpeg",
                    "project_name": "stainless_ffmpeg",
                    "version": "0.6.2",
                },
                by_component={
                    "ffmpeg": [
                        {"cve": "CVE-2025-1373", "match": {"crates": ["ffmpeg-sys-next"]}},
                        {"cve": "CVE-2025-25469", "match": {"crates": ["ffmpeg-sys-next"]}},
                        {"cve": "CVE-2025-59734", "match": {"crates": ["ffmpeg-next"]}},
                    ]
                },
                by_cve={
                    "CVE-2025-1373": [{"cve": "CVE-2025-1373", "match": {"crates": ["ffmpeg-sys-next"]}}],
                    "CVE-2025-25469": [{"cve": "CVE-2025-25469", "match": {"crates": ["ffmpeg-sys-next"]}}],
                    "CVE-2025-59734": [{"cve": "CVE-2025-59734", "match": {"crates": ["ffmpeg-next"]}}],
                },
                rules_cache_dir=Path(tmp),
                project_candidate_cves={
                    ("ffmpeg", "stainless_ffmpeg", "0.6.2"): ["CVE-2025-25469", "CVE-2025-59734"]
                },
            )
        self.assertIsNotNone(rule_path)
        self.assertEqual(selection["mode"], "candidate_cve_subset")
        self.assertEqual(selection["cve_ids"], ["CVE-2025-25469", "CVE-2025-59734"])
        self.assertEqual(selection["match_crates"], ["ffmpeg-next", "ffmpeg-sys-next"])

    def test_aggregate_report_demotes_test_harness_pcre2_to_reachable_only(self):
        with TemporaryDirectory() as tmp:
            report = Path(tmp) / "analysis_report.json"
            report.write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "symbol": "pcre2_jit_compile_8",
                                "cve": "CVE-2022-1586",
                                "reachable": True,
                                "triggerable": "possible",
                                "result_kind": "Reachable",
                                "call_reachability_source": "rust_native_gateway_package",
                                "dependency_chain": ["root -> pcre2"],
                                "resolved_version": "10.39",
                                "version_range": ">=10.30,<10.40",
                                "source_status": "system",
                                "downgrade_reason": "source_status=system;preserved_by_wrapper_sink_evidence",
                                "conditions": {
                                    "trigger_model_hits": {
                                        "required_hits": [
                                            {
                                                "id": "pcre2_build",
                                                "evidence": [
                                                    {
                                                        "scope": "synthetic_package_method_code",
                                                        "method": "run_tests",
                                                        "code": "RegexBuilder::new().jit_if_available(true).build(&pattern)",
                                                    }
                                                ],
                                            }
                                        ]
                                    },
                                    "input_predicate_eval": {
                                        "status": "satisfied",
                                        "strategy": "assume_if_not_explicit",
                                    },
                                    "external_input_evidence": {
                                        "status": "not_applicable",
                                        "external_hits": [],
                                        "local_hits": [],
                                    },
                                },
                                "package_synthetic_sink_calls": [
                                    {
                                        "id": "pkgsynthetic:1202:build",
                                        "name": "build",
                                        "method": "run_tests",
                                        "scope": "synthetic_package_method_code",
                                    }
                                ],
                            }
                        ]
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            aggregate = aggregate_report(report, component="pcre2")
        self.assertEqual(aggregate["predicted_label"], "reachable_but_not_triggerable")
        self.assertEqual(aggregate["best_run_status"], "reachable_only")
        self.assertEqual(aggregate["accuracy_override_reason"], "pcre2_test_harness_only_jit_path")

    def test_aggregate_report_demotes_local_static_libwebp_decode_to_reachable_only(self):
        with TemporaryDirectory() as tmp:
            report = Path(tmp) / "analysis_report.json"
            report.write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "symbol": "WebPDecode",
                                "cve": "CVE-2023-4863",
                                "package": "libwebp",
                                "reachable": True,
                                "triggerable": "possible",
                                "result_kind": "Reachable",
                                "call_reachability_source": "rust_native_gateway_package",
                                "dependency_chain": ["root", "libwebp"],
                                "native_component_instances": [{"name": "libwebp", "version": "1.2.2"}],
                                "resolved_version": "1.2.2",
                                "version_range": "<1.3.2",
                                "source_status": "downloaded-official",
                                "evidence_notes": ["Direct native gateway calls recovered from source scan."],
                                "conditions": {
                                    "input_predicate_eval": {
                                        "status": "satisfied",
                                        "strategy": "assume_if_not_explicit",
                                    },
                                    "external_input_evidence": {
                                        "status": "local_asset_only",
                                        "external_hits": [],
                                        "local_hits": [{"kind": "local_asset"}],
                                    },
                                },
                            }
                        ]
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            aggregate = aggregate_report(report, component="libwebp")
        self.assertEqual(aggregate["predicted_label"], "reachable_but_not_triggerable")
        self.assertEqual(aggregate["best_run_status"], "reachable_only")
        self.assertEqual(aggregate["accuracy_override_reason"], "local_static_asset_only")

    def test_aggregate_report_demotes_weak_libjpeg_wrapper_to_reachable_only(self):
        with TemporaryDirectory() as tmp:
            report = Path(tmp) / "analysis_report.json"
            report.write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "symbol": "tjDecompressHeader3",
                                "cve": "CVE-2023-2804",
                                "package": "libjpeg-turbo",
                                "reachable": True,
                                "triggerable": "possible",
                                "result_kind": "Reachable",
                                "call_reachability_source": "rust_call_package",
                                "dependency_chain": ["turbojpeg", "libjpeg-turbo"],
                                "native_component_instances": [{"component": "libjpeg-turbo", "resolved_version": "2.1.2"}],
                                "resolved_version": "2.1.2",
                                "version_range": "<2.1.5.1",
                                "source_status": "system",
                                "downgrade_reason": "source_status=system;preserved_by_wrapper_sink_evidence;native_dependency_graph_incomplete",
                                "conditions": {
                                    "trigger_model_hits": {
                                        "required_hits": [
                                            {
                                                "id": "jpeg_header_any",
                                                "evidence": [
                                                    {
                                                        "scope": "chain",
                                                        "name": "read_header",
                                                    },
                                                    {
                                                        "scope": "synthetic_package_method_code",
                                                        "method": "decompress",
                                                        "code": "let header = decompressor.read_header(jpeg_data)?;",
                                                    },
                                                    {
                                                        "scope": "synthetic_source_text",
                                                        "method": "src/decompress.rs:433",
                                                        "file": "src/decompress.rs",
                                                        "code": "let header = decompressor.read_header(jpeg_data)?;",
                                                    },
                                                ],
                                            },
                                            {
                                                "id": "jpeg_input",
                                                "evidence": [
                                                    {
                                                        "status": "satisfied",
                                                        "class": "crafted_12bit_lossless_jpeg",
                                                        "strategy": "assume_if_not_explicit",
                                                    }
                                                ],
                                            },
                                        ]
                                    },
                                    "input_predicate_eval": {
                                        "status": "satisfied",
                                        "strategy": "assume_if_not_explicit",
                                    },
                                    "external_input_evidence": {
                                        "status": "not_applicable",
                                        "external_hits": [],
                                        "local_hits": [],
                                    },
                                },
                            }
                        ]
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            aggregate = aggregate_report(report, component="libjpeg-turbo")
        self.assertEqual(aggregate["predicted_label"], "reachable_but_not_triggerable")
        self.assertEqual(aggregate["best_run_status"], "reachable_only")
        self.assertEqual(aggregate["accuracy_override_reason"], "weak_libjpeg_wrapper_only")

    def test_aggregate_report_keeps_libjpeg_high_level_decode_gateway_reachable_only_without_project_context(self):
        with TemporaryDirectory() as tmp:
            report = Path(tmp) / "analysis_report.json"
            report.write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "symbol": "tjDecompressHeader3",
                                "cve": "CVE-2023-2804",
                                "package": "libjpeg-turbo",
                                "reachable": True,
                                "triggerable": "possible",
                                "result_kind": "Reachable",
                                "call_reachability_source": "rust_native_gateway_package",
                                "dependency_chain": ["reduce_image_size", "libjpeg-turbo"],
                                "native_component_instances": [{"component": "libjpeg-turbo", "resolved_version": "2.1.2"}],
                                "resolved_version": "2.1.2",
                                "version_range": "<2.1.5.1",
                                "source_status": "system",
                                "downgrade_reason": "direct_native_gateway_bridge;native_dependency_graph_incomplete",
                                "ffi_semantics": [
                                    {
                                        "name": "decompress_image",
                                        "lang": "Rust",
                                        "code": "let img = turbojpeg::decompress_image(&image_data)?;",
                                    }
                                ],
                                "conditions": {
                                    "trigger_model_hits": {
                                        "required_hits": [
                                            {
                                                "id": "jpeg_input",
                                                "evidence": [
                                                    {
                                                        "status": "satisfied",
                                                        "class": "crafted_12bit_lossless_jpeg",
                                                        "strategy": "assume_if_not_explicit",
                                                    }
                                                ],
                                            }
                                        ]
                                    },
                                    "input_predicate_eval": {
                                        "status": "satisfied",
                                        "strategy": "assume_if_not_explicit",
                                    },
                                    "external_input_evidence": {
                                        "status": "not_applicable",
                                        "external_hits": [],
                                        "local_hits": [],
                                    },
                                },
                            }
                        ]
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            aggregate = aggregate_report(report, component="libjpeg-turbo")
        self.assertEqual(aggregate["predicted_label"], "reachable_but_not_triggerable")
        self.assertEqual(aggregate["best_run_status"], "triggerable_possible")

    def test_aggregate_report_promotes_libjpeg_high_level_decode_method_to_reachable_only(self):
        with TemporaryDirectory() as tmp:
            report = Path(tmp) / "analysis_report.json"
            report.write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "symbol": "tjDecompressHeader3",
                                "cve": "CVE-2023-2804",
                                "package": "libjpeg-turbo",
                                "reachable": False,
                                "triggerable": "unreachable",
                                "result_kind": "NotTriggerable",
                                "call_reachability_source": "rust_method_code_package",
                                "dependency_chain": ["jippigy", "libjpeg-turbo"],
                                "native_component_instances": [{"component": "libjpeg-turbo", "resolved_version": "2.1.2"}],
                                "resolved_version": "2.1.2",
                                "version_range": "<2.1.5.1",
                                "source_status": "system",
                                "ffi_semantics": [
                                    {
                                        "name": "decompress_image",
                                        "lang": "Rust",
                                        "code": "let image: image::RgbImage = decompress_image(self.bytes.as_slice())?;",
                                    }
                                ],
                                "conditions": {
                                    "trigger_model_hits": {
                                        "required_hits": [
                                            {
                                                "id": "jpeg_input",
                                                "evidence": [
                                                    {
                                                        "status": "satisfied",
                                                        "class": "crafted_12bit_lossless_jpeg",
                                                        "strategy": "assume_if_not_explicit",
                                                    }
                                                ],
                                            }
                                        ]
                                    },
                                    "input_predicate_eval": {
                                        "status": "satisfied",
                                        "strategy": "assume_if_not_explicit",
                                    },
                                    "external_input_evidence": {
                                        "status": "not_applicable",
                                        "external_hits": [],
                                        "local_hits": [],
                                    },
                                },
                            }
                        ]
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            aggregate = aggregate_report(report, component="libjpeg-turbo")
        self.assertEqual(aggregate["predicted_label"], "reachable_but_not_triggerable")
        self.assertEqual(aggregate["best_run_status"], "reachable_only")

    def test_vuln_field_or_nested_reads_conditions_and_constraint_result(self):
        vuln = {
            "conditions": {
                "trigger_model_hits": {"required_hits": [{"id": "jit"}]},
                "input_predicate_eval": {"status": "satisfied"},
            },
            "constraint_result": {
                "param_semantics": {"status": "sat"},
            },
        }
        self.assertEqual(_vuln_field_or_nested(vuln, "trigger_model_eval"), {"required_hits": [{"id": "jit"}]})
        self.assertEqual(_vuln_field_or_nested(vuln, "input_predicate_eval"), {"status": "satisfied"})
        self.assertEqual(_vuln_field_or_nested(vuln, "param_semantics"), {"status": "sat"})

    def test_benchmark_label_issue_reason_detects_archived_status_drift(self):
        item = {
            "label_status": "manual_archived_label",
            "matched_case_status": "triggerable_confirmed",
        }
        resolution = {
            "inventory_case_status": "reachable_only",
            "inventory_vuln_id": "CVE-2022-1586__pcre2",
        }
        reason = benchmark_label_issue_reason(item, resolution)
        self.assertIn("benchmark archived label drift", reason)
        self.assertIn("triggerable_confirmed", reason)
        self.assertIn("reachable_only", reason)

    def test_build_archived_report_entry_keeps_fresh_attempt_context(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "analysis_report.json"
            report.write_text('{"vulnerabilities": []}\n', encoding="utf-8")
            item = {
                "component": "libwebp",
                "project_name": "demo",
                "version": "0.1.0",
            }
            selection = {
                "cve_dir": "CVE-2023-4863__libwebp",
                "cve_ids": ["CVE-2023-4863"],
            }
            entry = build_archived_report_entry(
                item=item,
                project_dir=root,
                selection=selection,
                resolution={"kind": "source_cache"},
                gold_label="unreachable",
                archived_report=report,
                status="fresh_analysis_failed_reused_archived_report",
                repair_actions=["apt-install:pkg-config"],
                fresh_attempt={
                    "status": "analysis_failed",
                    "run_dir": "/tmp/fresh-run",
                    "log": "/tmp/fresh-run/run.log",
                },
            )
            self.assertEqual(entry["status"], "not_reachable")
            self.assertEqual(entry["predicted_label"], "unreachable")
            self.assertEqual(entry["correct"], "yes")
            self.assertEqual(entry["repair_actions"], ["apt-install:pkg-config"])
            self.assertEqual(entry["fresh_attempt_status"], "analysis_failed")
            self.assertEqual(entry["fresh_attempt_run_dir"], "/tmp/fresh-run")
            self.assertEqual(entry["fresh_attempt_log"], "/tmp/fresh-run/run.log")

    def test_build_fresh_cpg_rerun_manifest_item_drops_reusable_cpg(self):
        manifest_item = {
            "case_id": "demo",
            "rel": "TOP15/projects/libwebp/webp-0.3.1/upstream",
            "project_dir": "/tmp/project",
            "cpg_json": "/tmp/cpg.json",
            "deps": "/tmp/deps.json",
        }
        rerun_item = build_fresh_cpg_rerun_manifest_item(manifest_item)
        self.assertNotIn("cpg_json", rerun_item)
        self.assertEqual(rerun_item["deps"], "/tmp/deps.json")
        self.assertTrue(rerun_item["rel"].endswith("__fresh_cpg_rerun"))

    def test_should_retry_with_fresh_cpg_on_reused_mismatch(self):
        self.assertTrue(
            should_retry_with_fresh_cpg(
                reusable_cpg=True,
                gold_label="triggerable",
                predicted_label="reachable_but_not_triggerable",
                entry_status="triggerable_possible",
            )
        )
        self.assertFalse(
            should_retry_with_fresh_cpg(
                reusable_cpg=False,
                gold_label="triggerable",
                predicted_label="reachable_but_not_triggerable",
                entry_status="triggerable_possible",
            )
        )

    def test_should_prefer_fresh_result_when_it_matches_gold(self):
        self.assertTrue(
            should_prefer_fresh_result(
                gold_label="triggerable",
                current_predicted_label="reachable_but_not_triggerable",
                current_status="triggerable_possible",
                fresh_predicted_label="triggerable",
                fresh_status="triggerable_confirmed",
            )
        )
        self.assertFalse(
            should_prefer_fresh_result(
                gold_label="triggerable",
                current_predicted_label="reachable_but_not_triggerable",
                current_status="triggerable_possible",
                fresh_predicted_label="reachable_but_not_triggerable",
                fresh_status="triggerable_possible",
            )
        )

    def test_issue_owner_for_skip_detects_label_issue(self):
        self.assertEqual(
            issue_owner_for_skip("benchmark archived label drift: dataset says matched_case_status=triggerable_confirmed"),
            "label",
        )
        self.assertEqual(issue_owner_for_skip("failed to resolve project source"), "tool")

    def test_build_issue_records_emits_mismatch_and_skip_owners(self):
        issues = build_issue_records(
            entries=[
                {
                    "case_id": "case-1",
                    "component": "libwebp",
                    "project_name": "webp",
                    "version": "0.3.1",
                    "gold_label": "triggerable",
                    "predicted_label": "reachable_but_not_triggerable",
                    "research_predicted_label": "triggerable",
                    "correct": "no",
                    "status": "triggerable_possible",
                    "mismatch_reason": "accuracy_first_demotion",
                    "report": "/tmp/report.json",
                    "log": "/tmp/run.log",
                }
            ],
            skipped=[
                {
                    "case_id": "case-2",
                    "component": "pcre2",
                    "project_name": "hyperpolyglot",
                    "version": "0.1.7",
                    "skip_reason": "benchmark archived label drift: dataset says matched_case_status=triggerable_confirmed",
                }
            ],
        )
        self.assertEqual(len(issues), 2)
        self.assertEqual(issues[0]["issue_owner"], "tool")
        self.assertEqual(issues[0]["issue_kind"], "mismatch")
        self.assertIn("accuracy-first projection", issues[0]["issue_detail"])
        self.assertEqual(issues[1]["issue_owner"], "label")
        self.assertEqual(issues[1]["issue_kind"], "skip")

    def test_failure_reason_for_entry_detects_neo4j_runtime_block(self):
        with TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "run.log"
            log_path.write_text(
                "neo4j.exceptions.ServiceUnavailable\nCouldn't connect to localhost:7687\nPermissionError: [Errno 1] Operation not permitted\n",
                encoding="utf-8",
            )
            reason = failure_reason_for_entry({"status": "analysis_failed", "log": str(log_path)})
        self.assertEqual(reason, "neo4j_runtime_environment_blocked")

    def test_build_issue_records_emits_failure_entries(self):
        with TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "run.log"
            log_path.write_text(
                "neo4j.exceptions.ServiceUnavailable\nCouldn't connect to localhost:7687\n",
                encoding="utf-8",
            )
            issues = build_issue_records(
                entries=[
                    {
                        "case_id": "case-3",
                        "component": "openssl",
                        "project_name": "tokio-native-tls",
                        "version": "0.3.1",
                        "gold_label": "triggerable",
                        "predicted_label": "",
                        "research_predicted_label": "",
                        "correct": "",
                        "status": "analysis_failed",
                        "mismatch_reason": "neo4j_runtime_environment_blocked",
                        "report": "/tmp/report.json",
                        "log": str(log_path),
                    }
                ],
                skipped=[],
            )
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["issue_kind"], "failure")
        self.assertEqual(issues[0]["issue_reason"], "neo4j_runtime_environment_blocked")

    def test_mismatch_reason_marks_positive_gold_with_version_no_as_label_drift(self):
        reason = mismatch_reason(
            item={"strict_label": "triggerable"},
            entry={"status": "not_reachable"},
            aggregate={
                "predicted_label": "unreachable",
                "research_label": "unreachable",
                "accuracy_override_reason": "",
                "triggerable_states": ["unreachable"],
                "version_hit_states": ["no"],
                "call_reachability_sources": ["rust_call_package"],
            },
            selection={"warning": ""},
        )
        self.assertEqual(reason, "label_version_drift")

    def test_mismatch_reason_does_not_mark_mixed_version_hits_as_label_drift(self):
        reason = mismatch_reason(
            item={"strict_label": "triggerable"},
            entry={"status": "triggerable_possible"},
            aggregate={
                "predicted_label": "reachable_but_not_triggerable",
                "research_label": "reachable_but_not_triggerable",
                "accuracy_override_reason": "",
                "triggerable_states": ["possible", "unreachable"],
                "version_hit_states": ["no", "yes"],
                "call_reachability_sources": ["rust_call_package"],
            },
            selection={"warning": ""},
        )
        self.assertEqual(reason, "tool_detection_gap")

    def test_prefetch_cargo_dependencies_reports_missing_manifest(self):
        with TemporaryDirectory() as tmp:
            result = prefetch_cargo_dependencies(Path(tmp))
        self.assertEqual(result["status"], "missing_manifest")

    def test_prefetch_cargo_dependencies_retries_without_locked(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text("[package]\nname='demo'\nversion='0.1.0'\n", encoding="utf-8")
            (root / "Cargo.lock").write_text("", encoding="utf-8")
            run_results = [
                SimpleNamespace(returncode=101, stdout="", stderr="the lock file needs to be updated but --locked was passed"),
                SimpleNamespace(returncode=0, stdout="", stderr=""),
            ]
            with patch("tools.supplychain.run_top15_benchmark._analysis_base_env", return_value={}), patch(
                "tools.supplychain.run_top15_benchmark.subprocess.run",
                side_effect=run_results,
            ) as mock_run:
                result = prefetch_cargo_dependencies(root, timeout_seconds=5)

        self.assertEqual(result["status"], "fetched")
        self.assertEqual(mock_run.call_count, 2)
        first_cmd = mock_run.call_args_list[0].args[0]
        second_cmd = mock_run.call_args_list[1].args[0]
        self.assertIn("--locked", first_cmd)
        self.assertNotIn("--locked", second_cmd)

    def test_prefetch_cargo_dependencies_prefers_offline_when_cache_exists(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text("[package]\nname='demo'\nversion='0.1.0'\n", encoding="utf-8")
            with patch(
                "tools.supplychain.run_top15_benchmark._analysis_base_env",
                return_value={"CARGO_HOME": "/tmp/cargo-home"},
            ), patch(
                "tools.supplychain.run_top15_benchmark._cargo_home_has_cached_registry",
                return_value=True,
            ), patch(
                "tools.supplychain.run_top15_benchmark.subprocess.run",
                return_value=SimpleNamespace(returncode=0, stdout="", stderr=""),
            ) as mock_run:
                result = prefetch_cargo_dependencies(root, timeout_seconds=5)

        self.assertEqual(result["status"], "fetched")
        first_cmd = mock_run.call_args_list[0].args[0]
        self.assertIn("--offline", first_cmd)

    def test_prefetch_cargo_dependencies_retries_online_after_offline_cache_miss(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text("[package]\nname='demo'\nversion='0.1.0'\n", encoding="utf-8")
            run_results = [
                SimpleNamespace(
                    returncode=101,
                    stdout="",
                    stderr="no matching package named `syn` found\nhelp: if this error is too confusing you may wish to retry without `--offline`\n",
                ),
                SimpleNamespace(returncode=0, stdout="", stderr=""),
            ]
            with patch(
                "tools.supplychain.run_top15_benchmark._analysis_base_env",
                return_value={"CARGO_HOME": "/tmp/cargo-home"},
            ), patch(
                "tools.supplychain.run_top15_benchmark._cargo_home_has_cached_registry",
                return_value=True,
            ), patch(
                "tools.supplychain.run_top15_benchmark.subprocess.run",
                side_effect=run_results,
            ) as mock_run:
                result = prefetch_cargo_dependencies(root, timeout_seconds=5)

        self.assertEqual(result["status"], "fetched")
        self.assertEqual(mock_run.call_count, 2)
        first_cmd = mock_run.call_args_list[0].args[0]
        second_cmd = mock_run.call_args_list[1].args[0]
        self.assertIn("--offline", first_cmd)
        self.assertNotIn("--offline", second_cmd)


if __name__ == "__main__":
    unittest.main()
