import unittest

from tools.verification.abi_contracts import build_abi_contracts
from tools.verification.param_semantics import evaluate_param_semantics


class TestParamSemantics(unittest.TestCase):
    def test_flags_guarded_assignment_unsat(self):
        trigger_model = {
            "param_semantics": {
                "flags": [
                    {
                        "call": "xmlReadMemory",
                        "arg_index": 5,
                        "requires_all": ["XML_PARSE_DTDLOAD", "XML_PARSE_NOENT"],
                        "forbids": [],
                    }
                ]
            }
        }
        calls = [
            {"id": 1, "name": "<operator>.assignment", "code": "options = XML_PARSE_DTDLOAD;"},
            {"id": 2, "name": "<operator>.assignmentOr", "code": "options |= XML_PARSE_NOENT;"},
            {
                "id": 3,
                "name": "xmlReadMemory",
                "code": 'xmlReadMemory(xml, strlen(xml), "noname.xml", NULL, options);',
            },
        ]
        controls = [
            {
                "id": 11,
                "code": "if (!safe_mode) { options |= XML_PARSE_NOENT; }",
                "child_codes": ["!safe_mode", "options |= XML_PARSE_NOENT;"],
                "depth": 1,
            }
        ]
        path_bundle = {
            "const_map": {"XML_PARSE_DTDLOAD": 4, "XML_PARSE_NOENT": 2},
            "value_env": {"safe_mode": 1},
            "combined_constraints": [{"variable": "safe_mode", "operator": "==", "value": 1}],
        }

        result = evaluate_param_semantics(trigger_model, calls, controls, path_bundle, solver=None)
        self.assertEqual(result["status"], "unsat")
        self.assertEqual(result["flags_eval"][0]["status"], "unsat")

    def test_len_constraint_conflict_unsat(self):
        trigger_model = {
            "param_semantics": {
                "len": [
                    {
                        "call": "c_entry_libcurl",
                        "arg_index": 9,
                        "constraints": [{"op": ">", "value": 255}],
                    }
                ]
            }
        }
        calls = [
            {
                "id": 3,
                "name": "c_entry_libcurl",
                "code": "c_entry_libcurl(url, proxy, cb, rs, sm, ic, rk, pe, host_len, rh, cm, mc);",
            }
        ]
        path_bundle = {
            "value_env": {},
            "combined_constraints": [
                {"variable": "host_len", "operator": "<=", "value": 255, "source": "control_structure"}
            ],
        }

        result = evaluate_param_semantics(trigger_model, calls, [], path_bundle, solver=None)
        self.assertEqual(result["status"], "unsat")
        self.assertEqual(result["len_eval"][0]["status"], "unsat")
        self.assertTrue(result["len_eval"][0]["conflict_reason"])

    def test_nonnull_and_callback_sat(self):
        trigger_model = {
            "param_semantics": {
                "nonnull": [{"call": "xmlReadMemory", "arg_index": 1, "must_be": "nonnull"}],
                "callback": [{"call": "c_entry_libcurl", "arg_index": 3, "must_be_set": True}],
            }
        }
        calls = [
            {
                "id": 10,
                "name": "xmlReadMemory",
                "code": 'xmlReadMemory(1, len, "x.xml", NULL, options);',
            },
            {
                "id": 11,
                "name": "c_entry_libcurl",
                "code": "c_entry_libcurl(url, proxy, Some(runtime_policy_callback), rs, sm, ic, rk, pe, hl, rh, cm, mc);",
            },
        ]
        result = evaluate_param_semantics(trigger_model, calls, [], {"combined_constraints": [], "value_env": {}}, solver=None)
        self.assertEqual(result["status"], "sat")

    def test_flags_interproc_alias_propagation(self):
        trigger_model = {
            "param_semantics": {
                "flags": [
                    {
                        "call": "sink",
                        "arg_index": 1,
                        "requires_all": ["FLAG_A", "FLAG_B"],
                        "forbids": [],
                    }
                ]
            }
        }
        calls = [
            {"id": 1, "method": "main", "name": "<operator>.assignment", "code": "options = FLAG_A;"},
            {"id": 2, "method": "main", "name": "configure", "code": "configure(&options);"},
            {"id": 3, "method": "main", "name": "sink", "code": "sink(options);"},
            {"id": 10, "method": "configure", "name": "<operator>.assignmentOr", "code": "*opt |= FLAG_B;"},
        ]
        path_bundle = {
            "const_map": {"FLAG_A": 1, "FLAG_B": 2},
            "value_env": {},
            "combined_constraints": [],
            "method_signatures": {"configure": ["opt"], "sink": ["options"]},
        }
        result = evaluate_param_semantics(trigger_model, calls, [], path_bundle, solver=None)
        self.assertEqual(result["status"], "sat")
        self.assertEqual(result["flags_eval"][0]["status"], "sat")
        self.assertIn("FLAG_B", result["flags_eval"][0]["state"]["must_set"])

    def test_callback_may_called_interproc(self):
        trigger_model = {
            "param_semantics": {
                "callback": [
                    {
                        "call": "c_entry_libcurl",
                        "arg_index": 3,
                        "must_be_set": True,
                        "must_be_called": True,
                    }
                ]
            }
        }
        calls = [
            {
                "id": 1,
                "method": "main",
                "name": "c_entry_libcurl",
                "code": "c_entry_libcurl(url, proxy, runtime_policy_callback, rs, sm);",
            },
            {
                "id": 10,
                "method": "c_entry_libcurl",
                "name": "run_policy",
                "code": "run_policy(policy_cb, policy_score);",
            },
            {
                "id": 20,
                "method": "run_policy",
                "name": "cb",
                "code": "cb(policy_score, 1, 2);",
            },
        ]
        path_bundle = {
            "combined_constraints": [],
            "value_env": {},
            "method_signatures": {
                "c_entry_libcurl": ["url", "proxy", "policy_cb", "rs", "sm"],
                "run_policy": ["cb", "score"],
            },
        }
        result = evaluate_param_semantics(trigger_model, calls, [], path_bundle, solver=None)
        self.assertEqual(result["status"], "sat")
        self.assertEqual(result["callback_eval"][0]["status"], "sat")
        evidence = result["callback_eval"][0]["evidence"][0]
        self.assertEqual(evidence["reachability"], "may_called")

    def test_abi_flag_domain_sat(self):
        trigger_model = {
            "param_semantics": {
                "abi_contracts": {
                    "flag_domain": [
                        {
                            "call": "sink",
                            "arg_index": 1,
                            "allowed": ["FLAG_A", "FLAG_B"],
                            "requires_all": ["FLAG_A"],
                            "forbids": ["FLAG_C"],
                        }
                    ]
                }
            }
        }
        calls = [{"id": 1, "name": "sink", "code": "sink(FLAG_A);"}]
        path_bundle = {"combined_constraints": [], "value_env": {}, "const_map": {"FLAG_A": 1, "FLAG_B": 2}}
        abi_contracts = build_abi_contracts(trigger_model, calls, path_bundle)
        path_bundle["abi_contracts"] = abi_contracts
        result = evaluate_param_semantics(
            trigger_model,
            calls,
            [],
            path_bundle,
            solver=None,
            abi_contracts=abi_contracts,
        )
        self.assertEqual(result["status"], "sat")
        self.assertEqual(result["abi_contract_eval"]["status"], "sat")
        self.assertEqual(result["flags_eval"][0]["status"], "sat")

    def test_callback_not_called_branch_unknown(self):
        trigger_model = {
            "param_semantics": {
                "abi_contracts": {
                    "callback_contracts": [
                        {
                            "call": "c_entry_libcurl",
                            "arg_index": 3,
                            "must_be_set": True,
                            "must_be_invocable": True,
                        }
                    ]
                }
            }
        }
        calls = [
            {
                "id": 1,
                "method": "main",
                "name": "c_entry_libcurl",
                "code": "c_entry_libcurl(url, proxy, runtime_policy_callback, rs, sm);",
            },
            {
                "id": 2,
                "method": "c_entry_libcurl",
                "name": "assign_only",
                "code": "policy_cb = runtime_policy_callback;",
            },
        ]
        path_bundle = {
            "combined_constraints": [],
            "value_env": {},
            "method_signatures": {"c_entry_libcurl": ["url", "proxy", "policy_cb", "rs", "sm"]},
        }
        abi_contracts = build_abi_contracts(trigger_model, calls, path_bundle)
        path_bundle["abi_contracts"] = abi_contracts
        result = evaluate_param_semantics(
            trigger_model,
            calls,
            [],
            path_bundle,
            solver=None,
            abi_contracts=abi_contracts,
        )
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["abi_contract_eval"]["status"], "unknown")
        self.assertEqual(result["callback_eval"][0]["status"], "unknown")

    def test_len_interproc_param_rename_sat(self):
        trigger_model = {
            "param_semantics": {
                "len": [
                    {
                        "call": "sink",
                        "arg_index": 1,
                        "constraints": [{"op": ">", "value": 255}],
                    }
                ]
            }
        }
        calls = [
            {"id": 1, "method": "main", "name": "wrapper", "code": "wrapper(host_len);"},
            {"id": 10, "method": "wrapper", "name": "sink", "code": "sink(n);"},
        ]
        path_bundle = {
            "combined_constraints": [{"variable": "host_len", "operator": "==", "value": 300}],
            "value_env": {},
            "method_signatures": {"wrapper": ["n"], "sink": ["len"]},
            "interproc_context": {
                "method_calls": calls,
                "call_graph_edges": [{"caller": "main", "callee": "wrapper", "call_id": 1}],
                "method_signatures": {"wrapper": ["n"], "sink": ["len"]},
            },
        }
        result = evaluate_param_semantics(trigger_model, calls, [], path_bundle, solver=None, interproc_depth=2)
        self.assertEqual(result["len_eval"][0]["status"], "sat")
        self.assertEqual(result["interproc_eval"]["engine_version"], "interproc_v2")

    def test_nonnull_alias_merge_sat(self):
        trigger_model = {
            "param_semantics": {
                "nonnull": [{"call": "sink", "arg_index": 1, "must_be": "nonnull"}],
            }
        }
        calls = [
            {"id": 1, "method": "main", "name": "<operator>.assignment", "code": "p = ptr;"},
            {"id": 2, "method": "main", "name": "sink", "code": "sink(p);"},
        ]
        path_bundle = {
            "combined_constraints": [{"variable": "ptr", "operator": "!=", "value": 0}],
            "value_env": {},
            "method_signatures": {"sink": ["arg"]},
            "interproc_context": {
                "method_calls": calls,
                "call_graph_edges": [],
                "method_signatures": {"sink": ["arg"]},
            },
        }
        result = evaluate_param_semantics(trigger_model, calls, [], path_bundle, solver=None, interproc_depth=2)
        self.assertEqual(result["status"], "sat")
        self.assertEqual(result["nonnull_eval"][0]["status"], "sat")


if __name__ == "__main__":
    unittest.main()
