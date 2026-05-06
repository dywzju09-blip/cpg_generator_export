import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tools.supplychain.run_manifest_analysis import (
    extract_summary_fields,
    prepare_vulns_input,
    run_one,
    validate_analysis_runtime,
)


class RunManifestAnalysisTests(unittest.TestCase):
    def test_extract_summary_prefers_expected_component_match(self):
        with TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "analysis_report.json"
            report_path.write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "package": "brotli",
                                "symbol": "BrotliDecoderDecompressStream",
                                "reachable": False,
                                "triggerable": "unreachable",
                                "result_kind": "NotTriggerable",
                            },
                            {
                                "package": "freetype",
                                "symbol": "FT_New_Face",
                                "reachable": True,
                                "triggerable": "false_positive",
                                "result_kind": "NotTriggerable",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            summary = extract_summary_fields(
                report_path,
                {"family": "freetype", "cve_dir": "CVE-2025-27363__freetype"},
            )
            self.assertEqual(summary["component"], "freetype")
            self.assertEqual(summary["status"], "reachable_only")
            self.assertIsNone(summary["validation_error"])

    def test_extract_summary_rejects_component_mismatch(self):
        with TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "analysis_report.json"
            report_path.write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "package": "brotli",
                                "symbol": "BrotliDecoderDecompressStream",
                                "reachable": False,
                                "triggerable": "unreachable",
                                "result_kind": "NotTriggerable",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            summary = extract_summary_fields(
                report_path,
                {"family": "openh264", "cve_dir": "CVE-2025-27091__openh264"},
            )
            self.assertEqual(summary["status"], "analysis_failed")
            self.assertFalse(summary["reachable"])
            self.assertIn("report component mismatch", summary["validation_error"])

    def test_prepare_vulns_input_prefers_auto_family_rule(self):
        with TemporaryDirectory() as tmp:
            case_dir = Path(tmp)
            (case_dir / "analysis_inputs").mkdir(parents=True, exist_ok=True)
            item = {
                "project_dir": tmp,
                "project": "demo",
                "family": "openh264",
                "cve": "CVE-2025-27091",
                "cve_dir": "CVE-2025-27091__openh264",
                "dependency_evidence": [],
            }
            vulns_path, error = prepare_vulns_input(item, case_dir)
            self.assertIsNone(error)
            self.assertIsNotNone(vulns_path)
            rules = json.loads(Path(vulns_path).read_text(encoding="utf-8"))
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0]["package"], "openh264-sys2")

    def test_prepare_vulns_input_does_not_fallback_to_full_db_on_empty_selection(self):
        with TemporaryDirectory() as tmp:
            case_dir = Path(tmp)
            (case_dir / "analysis_inputs").mkdir(parents=True, exist_ok=True)
            item = {
                "project_dir": tmp,
                "project": "demo",
                "family": "",
                "cve_dir": "CVE-2025-0000__mysterylib",
                "dependency_evidence": [],
                "cargo_features": "",
                "cargo_all_features": False,
                "cargo_no_default_features": False,
            }
            rules_path = Path(tmp) / "runtime_rules.json"
            rules_path.write_text("[]\n", encoding="utf-8")
            with patch("tools.supplychain.run_manifest_analysis.default_runtime_rules_path", return_value=rules_path):
                with patch(
                    "tools.supplychain.run_manifest_analysis.write_selected_rules_for_project",
                    return_value={"selected_rules": 0, "fallback": "no_match"},
                ):
                    vulns_path, error = prepare_vulns_input(item, case_dir)
            self.assertIsNone(vulns_path)
            self.assertIn("no project-specific vulnerability rules matched", error)

    def test_validate_analysis_runtime_accepts_available_dependency(self):
        with patch(
            "tools.supplychain.run_manifest_analysis.subprocess.run",
            return_value=subprocess.CompletedProcess(args=["python3"], returncode=0, stdout="", stderr=""),
        ):
            self.assertIsNone(validate_analysis_runtime("/tmp/python3"))

    def test_validate_analysis_runtime_reports_missing_neo4j(self):
        with patch(
            "tools.supplychain.run_manifest_analysis.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["python3"],
                returncode=1,
                stdout="",
                stderr="ModuleNotFoundError: No module named 'neo4j'",
            ),
        ):
            error = validate_analysis_runtime("/usr/bin/python3")
        self.assertIn("analysis runtime check failed", error)
        self.assertIn("neo4j", error)
        self.assertIn("/usr/bin/python3", error)

    def test_run_one_treats_sigterm_before_report_as_timeout(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            vulns = root / "vulns.json"
            vulns.write_text(
                json.dumps(
                    [
                        {
                            "cve": "CVE-2099-0001",
                            "package": "demo",
                            "symbol": "demo_sink",
                            "version_range": "*",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            item = {
                "rel": "cases/demo",
                "project_dir": str(project),
                "project": "demo",
                "version": "0.1.0",
                "family": "demo",
                "component": "demo",
                "cve_dir": "CVE-2099-0001__demo",
                "vulns": str(vulns),
                "root_method": "main",
            }
            with patch(
                "tools.supplychain.run_manifest_analysis.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=["supplychain_analyze.py"],
                    returncode=-15,
                    stdout="",
                    stderr="",
                ),
            ):
                entry = run_one(item, root / "run", timeout_seconds=3600)
            log_text = Path(entry["log"]).read_text(encoding="utf-8")
            self.assertEqual(entry["exit_code"], -15)
            self.assertEqual(entry["status"], "analysis_timeout")
            self.assertIn("terminated by SIGTERM", log_text)


if __name__ == "__main__":
    unittest.main()
