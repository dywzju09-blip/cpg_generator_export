import unittest

from tools.verification.constraint_extractor import build_path_constraint_bundle
from tools.verification.path_solver import PathConstraintSolver, extract_numeric_constraints


class TestConstraintExtractor(unittest.TestCase):
    def test_safe_mode_bundle_conflict(self):
        chain_nodes = [
            {
                "id": 1,
                "labels": ["METHOD", "C"],
                "name": "parse_xml",
                "code": "int parse_xml(int safe_mode, const char *xml_input) { return 0; }",
            },
            {
                "id": 2,
                "labels": ["METHOD", "Rust"],
                "name": "main",
                "code": "#define SAFE_MODE 1\nparse_xml(SAFE_MODE, payload);",
            },
            {
                "id": 3,
                "labels": ["CALL", "Rust"],
                "name": "parse_xml",
                "code": "parse_xml(SAFE_MODE, payload);",
            },
        ]
        control_nodes = [
            {
                "id": 11,
                "control_type": "IF",
                "code": "if (!safe_mode) { xmlReadMemory(xml_input); }",
                "child_codes": ["!safe_mode"],
            }
        ]

        bundle = build_path_constraint_bundle(chain_nodes, control_nodes, symbol="parse_xml")
        solver = PathConstraintSolver()

        self.assertIn("safe_mode", bundle["value_env"])
        self.assertEqual(bundle["value_env"]["safe_mode"], 1)
        self.assertIn("interproc_context", bundle)
        self.assertIn("method_calls", bundle["interproc_context"])
        self.assertIn("call_graph_edges", bundle["interproc_context"])
        self.assertIn("method_signatures", bundle["interproc_context"])
        self.assertFalse(solver.is_path_feasible(bundle["combined_constraints"]))

    def test_mutually_exclusive_controls_are_unsat(self):
        control_nodes = [
            {"id": 1, "code": "if (x > 0) { sink(); }"},
            {"id": 2, "code": "if (x < 0) { sink(); }"},
        ]
        solver = PathConstraintSolver()
        constraints = extract_numeric_constraints(control_nodes)
        self.assertFalse(solver.is_path_feasible(constraints))


if __name__ == "__main__":
    unittest.main()
