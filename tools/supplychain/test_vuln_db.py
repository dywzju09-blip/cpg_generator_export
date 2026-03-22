import json
import unittest

from tools.supplychain.vuln_db import default_component_kb_path, default_manifest_path, default_runtime_rules_path
from tools.supplychain.select_vuln_rules import select_rules_from_crates


class VulnDbTests(unittest.TestCase):
    def test_default_database_indexes_exist(self):
        self.assertTrue(default_runtime_rules_path().exists())
        self.assertTrue(default_component_kb_path().exists())
        self.assertTrue(default_manifest_path().exists())

    def test_runtime_rules_manifest_counts_match(self):
        manifest = json.loads(default_manifest_path().read_text(encoding="utf-8"))
        rules = json.loads(default_runtime_rules_path().read_text(encoding="utf-8"))
        self.assertEqual(manifest["component_count"], 30)
        self.assertGreaterEqual(manifest["vulnerability_count"], 200)
        self.assertEqual(len(rules), manifest["vulnerability_count"])
        self.assertEqual(manifest["curated_vulnerability_count"], manifest["vulnerability_count"])
        self.assertEqual(manifest["manual_vulnerability_count"], 30)
        self.assertTrue(all(rule.get("maturity") == "curated" for rule in rules))

    def test_rules_include_structured_version_info(self):
        rules = json.loads(default_runtime_rules_path().read_text(encoding="utf-8"))
        for rule in rules:
            affected = rule.get("affected_versions") or {}
            self.assertIn("range_expr", affected)
            self.assertIn("lower_bounds", affected)
            self.assertIn("upper_bounds", affected)
            self.assertIn("fixed_versions", affected)
            self.assertIn("disjunctive_groups", affected)

    def test_selector_can_reduce_rules_by_crate(self):
        rules = json.loads(default_runtime_rules_path().read_text(encoding="utf-8"))
        kb = json.loads((default_runtime_rules_path().parent / "components_by_crate.json").read_text(encoding="utf-8"))
        selected, summary = select_rules_from_crates({"curl", "curl-sys"}, rules, kb)
        self.assertTrue(any(rule["package"] == "curl" for rule in selected))
        self.assertIn("curl", summary["matched_components"])


if __name__ == "__main__":
    unittest.main()
