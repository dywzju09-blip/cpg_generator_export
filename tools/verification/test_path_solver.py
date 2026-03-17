import unittest

from tools.verification.path_solver import (
    PathConstraintSolver,
    extract_assignment_constraints,
    extract_numeric_constraints,
)


class TestPathConstraintSolver(unittest.TestCase):
    def test_mutually_exclusive_numeric_constraints(self):
        solver = PathConstraintSolver()
        feasible = solver.is_path_feasible(
            [
                {"variable": "x", "operator": ">", "value": 0},
                {"variable": "x", "operator": "<", "value": 0},
            ]
        )
        self.assertFalse(feasible)

    def test_unknown_constraint_is_conservative(self):
        solver = PathConstraintSolver()
        feasible = solver.is_path_feasible(
            [
                {"variable": "mode", "operator": "contains", "value": 1},
                {"variable": "name", "operator": "==", "value": "non_numeric"},
            ]
        )
        self.assertTrue(feasible)

    def test_safe_mode_conflict_from_control_condition(self):
        solver = PathConstraintSolver()
        control_nodes = [{"code": "if (!safe_mode) { dangerous_call(); }"}]
        path_constraints = extract_numeric_constraints(control_nodes)
        feasible = solver.is_path_feasible(
            path_constraints
            + [
                {"variable": "safe_mode", "operator": "==", "value": 1},
            ]
        )
        self.assertFalse(feasible)

    def test_assignment_extraction(self):
        constraints = extract_assignment_constraints("safe_mode = 1; if (safe_mode) { run(); }")
        self.assertEqual(
            constraints,
            [
                {
                    "variable": "safe_mode",
                    "operator": "==",
                    "value": 1,
                    "raw": "safe_mode = 1",
                }
            ],
        )

    def test_else_keyword_is_not_treated_as_constraint(self):
        control_nodes = [
            {
                "code": "if (!safe_mode) { dangerous_call(); } else { safe_call(); }",
                "child_codes": ["!safe_mode", "else"],
            }
        ]
        constraints = extract_numeric_constraints(control_nodes)
        self.assertEqual(
            constraints,
            [
                {
                    "variable": "safe_mode",
                    "operator": "==",
                    "value": 0,
                    "raw": "!safe_mode",
                    "source": "control_structure",
                    "source_id": None,
                }
            ],
        )

    def test_interval_explain_bottom_reason(self):
        solver = PathConstraintSolver()
        solved = solver.solve_with_explain(
            [
                {"variable": "x", "operator": ">", "value": 10},
                {"variable": "x", "operator": "<", "value": 5},
            ]
        )
        self.assertFalse(solved["feasible"])
        self.assertIsNotNone(solved["bottom_reason"])
        self.assertEqual(solved["bottom_reason"]["variable"], "x")


if __name__ == "__main__":
    unittest.main()
