import unittest

from tools.verification.alias_analysis import analyze_aliases


class TestAliasAnalysis(unittest.TestCase):
    def test_must_alias_and_points_to(self):
        calls = [
            {"id": 1, "method": "main", "name": "<operator>.assignment", "code": "y = x;"},
            {"id": 2, "method": "main", "name": "<operator>.assignment", "code": "p = &x;"},
            {"id": 3, "method": "main", "name": "wrap", "code": "wrap(&x);"},
            {"id": 10, "method": "wrap", "name": "<operator>.assignment", "code": "local = p;"},
        ]
        method_signatures = {"wrap": ["p"]}

        result = analyze_aliases(calls, method_signatures, max_depth=2)

        must_sets = [set(group) for group in result["must_alias_sets"]]
        self.assertTrue(any({"main::x", "main::y"}.issubset(group) for group in must_sets))
        self.assertIn("main::p", result["points_to"])
        self.assertIn("main::x", result["points_to"]["main::p"])
        self.assertIn("wrap::p", result["may_alias_map"])
        self.assertIn("main::x", result["may_alias_map"]["wrap::p"])

    def test_transitive_wrapper_alias_depth(self):
        calls = [
            {"id": 1, "method": "main", "name": "a", "code": "a(&buf);"},
            {"id": 10, "method": "a", "name": "b", "code": "b(p);"},
            {"id": 20, "method": "b", "name": "<operator>.assignment", "code": "*q = data;"},
        ]
        method_signatures = {"a": ["p"], "b": ["q"]}

        result = analyze_aliases(calls, method_signatures, max_depth=2)
        self.assertIn("b::q", result["may_alias_map"])
        self.assertIn("main::buf", result["may_alias_map"]["b::q"])


if __name__ == "__main__":
    unittest.main()
