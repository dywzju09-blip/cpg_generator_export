import unittest

from tools.supplychain.internal_baselines import (
    BL_DEP,
    BL_DEP_REACH,
    BL_NO_NATIVE_INTERNAL,
    project_internal_baseline,
    project_ours_full_from_support,
    support_from_vulnerability,
)


class InternalBaselinesTests(unittest.TestCase):
    def test_support_from_vulnerability_marks_out_of_range_version_as_no(self):
        support = support_from_vulnerability(
            {
                "dependency_chain": ["demo", "libgit2"],
                "native_component_instances": [{"component": "libgit2"}],
                "resolved_version": "1.9.0",
                "version_range": "<1.7.2",
                "reachable": False,
                "triggerable": "unreachable",
                "source_status": "bundled",
            }
        )
        self.assertEqual(support.dependency_hit, "yes")
        self.assertEqual(support.version_hit, "no")
        self.assertEqual(support.rust_reachable, "no")

    def test_bl_dep_requires_dependency_and_version_hit(self):
        support = support_from_vulnerability(
            {
                "dependency_chain": ["demo", "libgit2"],
                "native_component_instances": [{"component": "libgit2"}],
                "resolved_version": "1.9.0",
                "version_range": "<1.7.2",
                "reachable": True,
                "call_reachability_source": "rust_native_gateway_package",
                "triggerable": "possible",
                "source_status": "system",
            }
        )
        projected = project_internal_baseline(BL_DEP, support, gold_label="reachable_but_not_triggerable")
        self.assertEqual(projected["predicted_label"], "unreachable")
        self.assertEqual(projected["correct"], "no")

    def test_bl_dep_reach_requires_rust_reachability(self):
        support = support_from_vulnerability(
            {
                "dependency_chain": ["demo", "libwebp"],
                "native_component_instances": [{"component": "libwebp"}],
                "resolved_version": "1.3.0",
                "version_range": "<1.3.2",
                "reachable": False,
                "triggerable": "unreachable",
                "source_status": "bundled",
            }
        )
        projected = project_internal_baseline(BL_DEP_REACH, support)
        self.assertEqual(projected["predicted_label"], "unreachable")

    def test_bl_no_native_internal_promotes_when_native_instance_exists(self):
        support = support_from_vulnerability(
            {
                "dependency_chain": ["demo", "libwebp"],
                "native_component_instances": [{"component": "libwebp"}],
                "resolved_version": "1.3.0",
                "version_range": "<1.3.2",
                "reachable": True,
                "call_reachability_source": "rust_native_gateway_package",
                "triggerable": "possible",
                "source_status": "system",
            }
        )
        self.assertEqual(support.cross_language_linked, "no")
        projected = project_internal_baseline(BL_NO_NATIVE_INTERNAL, support)
        self.assertEqual(projected["predicted_label"], "triggerable")

    def test_bl_no_native_internal_uses_cross_language_evidence_without_native_instance(self):
        support = support_from_vulnerability(
            {
                "dependency_chain": ["demo", "gstreamer"],
                "native_component_instances": [],
                "resolved_version": "0.24.4",
                "version_range": "<1.22.9",
                "reachable": True,
                "call_reachability_source": "rust_native_gateway_package",
                "triggerable": "possible",
                "source_status": "bundled",
            }
        )
        self.assertEqual(support.cross_language_linked, "yes")
        projected = project_internal_baseline(BL_NO_NATIVE_INTERNAL, support)
        self.assertEqual(projected["predicted_label"], "triggerable")

    def test_ours_full_maps_possible_to_triggerable(self):
        support = support_from_vulnerability(
            {
                "dependency_chain": ["demo", "gstreamer"],
                "native_component_instances": [{"component": "gstreamer"}],
                "resolved_version": "0.24.4",
                "version_range": "<1.22.9",
                "reachable": True,
                "call_reachability_source": "rust_native_gateway_package",
                "triggerable": "possible",
                "source_status": "system",
            }
        )
        projected = project_ours_full_from_support(support, gold_label="triggerable")
        self.assertEqual(projected["predicted_label"], "triggerable")
        self.assertEqual(projected["run_status"], "triggerable_possible")
        self.assertEqual(projected["correct"], "yes")

    def test_ours_full_maps_false_positive_to_reachable_only(self):
        support = support_from_vulnerability(
            {
                "dependency_chain": ["demo", "libxml2"],
                "native_component_instances": [{"component": "libxml2"}],
                "resolved_version": "2.9.1",
                "version_range": "<2.9.4",
                "reachable": True,
                "call_reachability_source": "rust_method_code_package",
                "triggerable": "false_positive",
                "result_kind": "NotTriggerable",
                "source_status": "system",
            }
        )
        projected = project_ours_full_from_support(support, gold_label="reachable_but_not_triggerable")
        self.assertEqual(projected["predicted_label"], "reachable_but_not_triggerable")
        self.assertEqual(projected["native_internal_satisfied"], "no")
        self.assertEqual(projected["correct"], "yes")


if __name__ == "__main__":
    unittest.main()
