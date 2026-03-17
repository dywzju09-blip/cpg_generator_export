import unittest

from tools.verification.interproc_valueflow import build_interproc_index, propagate_from_sink


class TestInterprocValueFlow(unittest.TestCase):
    def test_flags_or_update_across_wrapper(self):
        calls = [
            {"id": 1, "method": "main", "name": "<operator>.assignment", "code": "options = FLAG_A;"},
            {"id": 2, "method": "main", "name": "configure", "code": "configure(&options);"},
            {"id": 3, "method": "main", "name": "sink", "code": "sink(options);"},
            {"id": 10, "method": "configure", "name": "<operator>.assignment", "code": "*opt = *opt | FLAG_B;"},
        ]
        signatures = {"configure": ["opt"], "sink": ["options"]}
        index = build_interproc_index(calls, signatures)
        index["const_map"] = {"FLAG_A": 1, "FLAG_B": 2}

        sink = [c for c in calls if c.get("name") == "sink"][0]
        flow = propagate_from_sink(index, sink_call=sink, arg_index=1, controls=[], value_env={}, max_depth=2)

        state = flow["state"]
        self.assertIn("FLAG_A", state["flags_must"])
        self.assertIn("FLAG_B", state["flags_must"])
        self.assertEqual(flow["engine_version"], "interproc_v2")

    def test_flags_and_not_update(self):
        calls = [
            {"id": 1, "method": "main", "name": "<operator>.assignment", "code": "options = FLAG_A;"},
            {"id": 2, "method": "main", "name": "configure", "code": "configure(&options);"},
            {"id": 3, "method": "main", "name": "sink", "code": "sink(options);"},
            {"id": 10, "method": "configure", "name": "<operator>.assignment", "code": "*opt = *opt | FLAG_B;"},
            {"id": 11, "method": "configure", "name": "<operator>.assignment", "code": "*opt = *opt & ~FLAG_B;"},
        ]
        signatures = {"configure": ["opt"], "sink": ["options"]}
        index = build_interproc_index(calls, signatures)
        index["const_map"] = {"FLAG_A": 1, "FLAG_B": 2}

        sink = [c for c in calls if c.get("name") == "sink"][0]
        flow = propagate_from_sink(index, sink_call=sink, arg_index=1, controls=[], value_env={}, max_depth=2)

        state = flow["state"]
        self.assertIn("FLAG_A", state["flags_must"])
        self.assertNotIn("FLAG_B", state["flags_must"])
        self.assertIn("FLAG_B", state["flags_forbid"])

    def test_callback_set_and_invoke_trace(self):
        calls = [
            {"id": 1, "method": "main", "name": "entry", "code": "entry(runtime_policy_callback);"},
            {"id": 10, "method": "entry", "name": "run", "code": "run(cb);"},
            {"id": 20, "method": "run", "name": "<operator>.assignment", "code": "local = h;"},
            {"id": 21, "method": "run", "name": "local", "code": "local(score);"},
        ]
        signatures = {"entry": ["cb"], "run": ["h"]}
        index = build_interproc_index(calls, signatures)

        sink = [c for c in calls if c.get("name") == "entry"][0]
        flow = propagate_from_sink(index, sink_call=sink, arg_index=1, controls=[], value_env={}, max_depth=3)
        state = flow["state"]

        self.assertTrue(state["callback_invoked"]["must"])
        self.assertTrue(any(t.get("kind") == "callback_invoke" for t in flow["trace"]))


if __name__ == "__main__":
    unittest.main()
