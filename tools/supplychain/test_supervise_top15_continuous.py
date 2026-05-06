import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.supplychain.supervise_top15_continuous import analyze_entries, discover_session_batch_index


class SuperviseTop15ContinuousTests(unittest.TestCase):
    def test_analyze_entries_counts_statuses_without_crashing(self):
        analysis = analyze_entries(
            [
                {"case_id": "a", "status": "analysis_failed", "correct": "", "project": "p1"},
                {"case_id": "b", "status": "not_reachable", "correct": "yes", "project": "p2"},
                {"case_id": "c", "status": "reachable_only", "correct": "no", "project": "p3"},
            ]
        )
        self.assertEqual(analysis["processed_count"], 3)
        self.assertEqual(
            analysis["status_counts"],
            {
                "analysis_failed": 1,
                "not_reachable": 1,
                "reachable_only": 1,
            },
        )
        self.assertEqual(analysis["correct_yes"], 1)
        self.assertEqual(analysis["correct_no"], 1)
        self.assertEqual(len(analysis["failed"]), 1)
        self.assertEqual(len(analysis["mismatches"]), 1)

    def test_discover_session_batch_index_uses_existing_artifacts(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            process_root = root / "process"
            run_output_root = root / "runs"
            (process_root / "subsets").mkdir(parents=True)
            (process_root / "logs").mkdir(parents=True)
            run_output_root.mkdir(parents=True)

            (process_root / "subsets" / "demo__b002.benchmark.json").write_text("{}", encoding="utf-8")
            (process_root / "logs" / "demo__b003.log").write_text("", encoding="utf-8")
            (run_output_root / "demo__b004").mkdir()
            (run_output_root / "demo__b004__retry_case__a1").mkdir()

            self.assertEqual(discover_session_batch_index("demo", process_root, run_output_root), 4)


if __name__ == "__main__":
    unittest.main()
