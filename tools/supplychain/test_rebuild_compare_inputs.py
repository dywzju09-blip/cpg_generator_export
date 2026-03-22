import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.supplychain.rebuild_compare_inputs import (
    build_outputs,
    extract_cli_hints,
    manifest_item_from_case,
)


class RebuildCompareInputsTests(unittest.TestCase):
    def test_extract_cli_hints_from_run_log(self):
        with TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "run.log"
            log_path.write_text(
                "$ python3 tools/supplychain/supplychain_analyze.py "
                "--cargo-dir /tmp/demo "
                "--root demo "
                "--root-method main "
                "--cpg-input /tmp/demo/examples/app.rs "
                "--cargo-features video-display "
                "--cargo-no-default-features "
                "--cargo-all-features\n",
                encoding="utf-8",
            )
            hints = extract_cli_hints(log_path)
            self.assertEqual(hints["root"], "demo")
            self.assertEqual(hints["root_method"], "main")
            self.assertEqual(hints["cpg_input"], "/tmp/demo/examples/app.rs")
            self.assertEqual(hints["cargo_features"], "video-display")
            self.assertTrue(hints["cargo_all_features"])
            self.assertTrue(hints["cargo_no_default_features"])

    def test_manifest_item_preserves_analysis_hints(self):
        with TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "316" / "projects" / "xphone-0.4.0" / "upstream"
            analysis_run = Path(tmp) / "case" / "analysis_run"
            project_dir.mkdir(parents=True, exist_ok=True)
            analysis_run.mkdir(parents=True, exist_ok=True)
            (analysis_run / "run.log").write_text(
                "$ python3 tools/supplychain/supplychain_analyze.py "
                f"--cargo-dir {project_dir} "
                f"--cpg-input {project_dir / 'examples/sipcli.rs'} "
                "--root xphone --root-method main --cargo-features video-display\n",
                encoding="utf-8",
            )
            (analysis_run / "analysis_report.json").write_text(
                json.dumps({"root": "xphone", "cpg_bootstrap": {"input_file": str(project_dir / "examples/sipcli.rs")}}),
                encoding="utf-8",
            )
            case = {
                "rel": "316/projects/xphone-0.4.0/upstream",
                "vulnerability": "CVE-2025-27091__openh264",
                "project_source": str(project_dir),
                "analysis_run": str(analysis_run),
            }
            item = manifest_item_from_case(case)
            self.assertEqual(item["project"], "xphone")
            self.assertEqual(item["version"], "0.4.0")
            self.assertEqual(item["family"], "openh264")
            self.assertEqual(item["component"], "openh264-sys2")
            self.assertEqual(item["root"], "xphone")
            self.assertEqual(item["cpg_input"], str((project_dir / "examples/sipcli.rs").resolve()))
            self.assertEqual(item["cargo_features"], "video-display")
            self.assertEqual(item["code_hit_file"], "examples/sipcli.rs")

    def test_build_outputs_filters_by_rel_prefix(self):
        with TemporaryDirectory() as tmp:
            cases_root = Path(tmp) / "cases"
            keep_dir = cases_root / "03_runnable_static_triggerable_confirmed" / "CVE-2025-27091__openh264" / "xphone-0.4.0__upstream"
            skip_dir = cases_root / "03_runnable_static_triggerable_confirmed" / "CVE-2025-68431__libpng" / "png-1.0.0__upstream"
            for case_dir, rel, vuln in [
                (keep_dir, "316/projects/xphone-0.4.0/upstream", "CVE-2025-27091__openh264"),
                (skip_dir, "OTHER/projects/png-1.0.0/upstream", "CVE-2025-68431__libpng"),
            ]:
                analysis_run = case_dir / "analysis_run"
                analysis_run.mkdir(parents=True, exist_ok=True)
                project_dir = Path(tmp) / rel
                project_dir.mkdir(parents=True, exist_ok=True)
                (analysis_run / "run.log").write_text(
                    f"$ python3 tools/supplychain/supplychain_analyze.py --cargo-dir {project_dir}\n",
                    encoding="utf-8",
                )
                (analysis_run / "analysis_report.json").write_text(json.dumps({}), encoding="utf-8")
                (case_dir / "case.json").write_text(
                    json.dumps(
                        {
                            "rel": rel,
                            "vulnerability": vuln,
                            "project_name": case_dir.name,
                            "status": "triggerable_confirmed",
                            "category": case_dir.parent.parent.name,
                            "label": "runnable_static_triggerable_confirmed",
                            "project_source": str(project_dir),
                            "analysis_run": str(analysis_run),
                        }
                    ),
                    encoding="utf-8",
                )
            output_dir = Path(tmp) / "out"
            baseline, grouped = build_outputs(cases_root, output_dir, rel_prefix="316/projects")
            self.assertEqual(len(baseline), 1)
            self.assertEqual(sorted(grouped), ["openh264"])
            all_manifest = json.loads((output_dir / "inputs" / "all.manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(len(all_manifest), 1)


if __name__ == "__main__":
    unittest.main()
