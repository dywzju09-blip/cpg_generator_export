import unittest

from tools.verification.abi_contracts import build_abi_contracts


class TestAbiContracts(unittest.TestCase):
    def test_ptr_len_constraints_sat(self):
        trigger_model = {
            "param_semantics": {
                "abi_contracts": {
                    "ptr_len_pairs": [
                        {
                            "call": "c_entry_libcurl",
                            "ptr_arg": 1,
                            "len_arg": 2,
                            "len_constraints": [{"op": ">", "value": 0}, {"op": "<=", "value": 1024}],
                        }
                    ]
                }
            }
        }
        calls = [{"id": 100, "name": "c_entry_libcurl", "code": "c_entry_libcurl(host_ptr, host_len);"}]
        result = build_abi_contracts(trigger_model, calls, {"method_signatures": {}, "const_map": {}})
        self.assertEqual(result["status"], "sat")
        self.assertTrue(any(c.get("variable") == "host_len" for c in result["constraints"]))

    def test_flag_domain_conflict_unsat(self):
        trigger_model = {
            "param_semantics": {
                "abi_contracts": {
                    "flag_domain": [
                        {
                            "call": "sink",
                            "arg_index": 1,
                            "allowed": ["FLAG_A", "FLAG_B"],
                            "requires_all": ["FLAG_A"],
                            "forbids": ["FLAG_B"],
                        }
                    ]
                }
            }
        }
        calls = [{"id": 200, "name": "sink", "code": "sink(FLAG_A | FLAG_B);"}]
        result = build_abi_contracts(trigger_model, calls, {"method_signatures": {}, "const_map": {"FLAG_A": 1, "FLAG_B": 2}})
        self.assertEqual(result["status"], "unsat")
        self.assertTrue(result["conflict_reason"])

    def test_callback_invocable_unknown(self):
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
        calls = [{"id": 300, "name": "c_entry_libcurl", "code": "c_entry_libcurl(url, proxy, policy_cb);"}]
        result = build_abi_contracts(trigger_model, calls, {"method_signatures": {}, "const_map": {}})
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(any(a.get("kind") == "invocability_deferred" for a in result["boundary_assumptions"]))


if __name__ == "__main__":
    unittest.main()
