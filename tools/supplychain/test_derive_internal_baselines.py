import csv
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tools.supplychain.derive_internal_baselines import main


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


class DeriveInternalBaselinesTests(unittest.TestCase):
    def test_main_updates_existing_benchmark_tables_in_place(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "benchmark_db" / "v1"
            index = root / "index"
            report_path = Path(tmp) / "analysis_report.json"
            report_path.write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "package": "libwebp",
                                "symbol": "WebPDecodeRGBA",
                                "dependency_chain": ["demo", "libwebp"],
                                "native_component_instances": [{"component": "libwebp", "resolved_version": "1.3.0"}],
                                "resolved_version": "1.3.0",
                                "version_range": "<1.3.2",
                                "reachable": True,
                                "triggerable": "possible",
                                "result_kind": "Reachable",
                                "source_status": "system",
                                "call_reachability_source": "rust_native_gateway_package",
                                "strict_callsite_edges": 0,
                                "native_analysis_coverage": "target_only",
                                "native_dependency_imports": [],
                                "strict_dependency_resolution": {},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            write_csv(
                index / "inventory_cases.csv",
                [
                    "case_id",
                    "vuln_id",
                    "component_family",
                    "analysis_report",
                    "source_visibility",
                    "resolved_project_source",
                    "original_project_source",
                ],
                [
                    {
                        "case_id": "case__demo",
                        "vuln_id": "CVE-2023-4863__libwebp",
                        "component_family": "libwebp",
                        "analysis_report": str(report_path),
                        "source_visibility": "available",
                        "resolved_project_source": str(Path(tmp) / "project"),
                        "original_project_source": str(Path(tmp) / "project"),
                    }
                ],
            )
            write_csv(
                index / "cases.csv",
                [
                    "case_id",
                    "project_id",
                    "component_id",
                    "vuln_id",
                    "label",
                    "family",
                    "dependency_mode",
                    "source_visibility",
                    "confirmed_case_subset",
                ],
                [
                    {
                        "case_id": "case__demo",
                        "project_id": "proj__demo",
                        "component_id": "component__libwebp",
                        "vuln_id": "CVE-2023-4863__libwebp",
                        "label": "triggerable",
                        "family": "libwebp",
                        "dependency_mode": "cargo",
                        "source_visibility": "available",
                        "confirmed_case_subset": "no",
                    }
                ],
            )
            write_csv(
                index / "experiment_case_subsets.csv",
                ["subset_id", "case_id", "include_reason", "notes"],
                [
                    {
                        "subset_id": "S_eval",
                        "case_id": "case__demo",
                        "include_reason": "unit_test",
                        "notes": "",
                    }
                ],
            )
            write_csv(index / "run_manifest.csv", ["run_id", "case_id", "method"], [])
            write_csv(index / "resource_usage.csv", ["run_id", "case_id", "method"], [])
            write_csv(index / "results.csv", ["run_id", "case_id", "method"], [])
            write_csv(index / "failures.csv", ["run_id", "case_id", "method", "stage", "error_type"], [])

            with patch.object(sys, "argv", ["derive_internal_baselines.py", "--benchmark-db-root", str(root)]):
                rc = main()
            self.assertEqual(rc, 0)

            result_rows = read_csv(index / "results.csv")
            self.assertEqual({row["method"] for row in result_rows}, {"Ours-Full", "BL-Dep", "BL-Dep+Reach", "BL-NoNativeInternal"})
            by_method = {row["method"]: row for row in result_rows}
            self.assertEqual(by_method["Ours-Full"]["predicted_label"], "reachable_but_not_triggerable")
            self.assertEqual(by_method["BL-Dep"]["predicted_label"], "reachable_but_not_triggerable")
            self.assertEqual(by_method["BL-Dep+Reach"]["predicted_label"], "reachable_but_not_triggerable")
            self.assertEqual(by_method["BL-NoNativeInternal"]["predicted_label"], "triggerable")

            run_rows = read_csv(index / "run_manifest.csv")
            self.assertEqual(len(run_rows), 4)
            resource_rows = read_csv(index / "resource_usage.csv")
            self.assertEqual(len(resource_rows), 4)
            self.assertTrue((index / "run_manifest.csv").exists())
            self.assertTrue((index / "resource_usage.csv").exists())
            self.assertTrue((index / "results.csv").exists())
            self.assertTrue((index / "failures.csv").exists())
            table11_rows = read_csv(root / "reports" / "table11_hard_negative_analysis.csv")
            self.assertEqual(len(table11_rows), 28)
            by_key = {(row["method"], row["error_bucket"]): row for row in table11_rows}
            self.assertEqual(by_key[("BL-NoNativeInternal", "reachable_but_not_triggerable_to_triggerable")]["case_count"], "0")
            self.assertEqual(by_key[("BL-NoNativeInternal", "unreachable_to_positive")]["case_count"], "0")
            self.assertEqual(by_key[("BL-Dep", "triggerable_to_reachable_but_not_triggerable")]["case_count"], "1")
            self.assertEqual(by_key[("BL-Dep", "triggerable_to_reachable_but_not_triggerable")]["case_ids"], "case__demo")


if __name__ == "__main__":
    unittest.main()
