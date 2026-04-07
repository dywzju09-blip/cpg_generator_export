import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
from unittest.mock import MagicMock, patch

from tools.supplychain.supplychain_analyze import (
    analyze_triggerability,
    apply_manual_evidence,
    collect_package_native_gateway_calls,
    collect_source_native_gateway_calls,
    collect_source_synthetic_sink_calls,
    _filter_speculative_source_features,
    _match_call_name,
    _SYSTEM_NATIVE_VERSION_CACHE,
    apply_sink_knowledge,
    collect_rust_sink_candidates,
    collect_assumption_evidence,
    eval_condition,
    evaluate_env_guards,
    evaluate_input_predicate,
    has_cross_language_native_evidence,
    has_actionable_trigger_hits,
    has_dependency_source_symbol_bridge,
    has_explicit_native_symbol_bridge,
    _native_symbol_names_match,
    has_transitive_native_symbol_bridge,
    find_best_dep_chain,
    maybe_collect_expanded_feature_deps,
    map_result_kind,
    merge_evidence_calls,
    normalize_vuln_rule,
    select_manual_evidence,
    select_relevant_native_gateway_calls,
    register_binary_symbol_inventory,
    resolve_native_component_instances,
    resolve_external_c_calls_to_binary_symbols,
    synthesize_sink_calls_from_method_code,
    summarize_guard_status,
)
from tools.fetch.native_source_resolver import (
    choose_c_analysis_scope,
    ensure_native_source_tree,
    find_local_native_source_tree,
    find_symbol_source_files,
    infer_native_source_dependencies,
)
from tools.fetch.native_source_providers import get_provider
from tools.fetch.native_symbol_resolver import (
    _parse_ldd_output,
    _parse_pkg_config_flags,
    build_symbol_provider_index,
    collect_component_link_context,
    resolve_strict_native_dependencies,
)
from tools.supplychain.auto_vuln_inputs import can_auto_generate, generate_vulns_payload
from tools.verification.ffi_summaries import resolve_ffi_summary
from tools.verification.field_flow import build_field_flow
from tools.verification.state_semantics import evaluate_state_semantics
from tools.verification.path_solver import PathConstraintSolver


class ExistentialInputTests(unittest.TestCase):
    def test_ffi_summary_resolves_header_fields(self):
        summary = resolve_ffi_summary("inflateGetHeader")
        self.assertIsNotNone(summary)
        param2 = summary["params"]["2"]
        self.assertEqual(param2["role"], "gzip_header")
        self.assertEqual(param2["fields"]["extra_max"]["state"], "pre")
        self.assertEqual(param2["fields"]["extra_len"]["state"], "post")

    def test_field_flow_extracts_header_object_and_fields(self):
        summary = resolve_ffi_summary("inflateGetHeader")
        flow = build_field_flow(
            chain_nodes=[
                {
                    "id": 1,
                    "labels": ["METHOD", "Rust"],
                    "name": "main",
                    "code": "fn main(){ let mut header = gz_header { extra_len: 0, extra_max: EXTRA_CAPTURE_BUF as c_uint }; inflateGetHeader(&mut stream, &mut header); }",
                }
            ],
            evidence_calls=[
                {
                    "id": 2,
                    "name": "inflateGetHeader",
                    "code": "inflateGetHeader",
                    "lang": "Rust",
                    "method": "main",
                }
            ],
            ffi_summaries={"inflateGetHeader": summary},
            value_env={"EXTRA_CAPTURE_BUF": 4},
            const_map={"EXTRA_CAPTURE_BUF": 4},
        )
        self.assertEqual(len(flow["objects"]), 1)
        self.assertIn("header", flow["objects"][0]["aliases"])
        facts = {fact["field"]: fact for fact in flow["field_facts"]}
        self.assertEqual(facts["extra_max"]["resolved_value"], 4)
        self.assertEqual(facts["extra_len"]["resolved_value"], 0)

    def test_assumed_large_input_can_exceed_resolved_max(self):
        trigger_model = {
            "state_rules": [
                {
                    "id": "large_extra_len",
                    "lhs": {
                        "field": "extra_len",
                        "state": "post",
                        "source": "symbolic",
                        "symbolic_var": "attacker_extra_len",
                    },
                    "op": ">",
                    "rhs": {
                        "field": "extra_max",
                        "state": "pre",
                        "source": "observed",
                    },
                    "lhs_constraints": [{"op": ">=", "value": 32}],
                }
            ]
        }
        chain_nodes = [
            {
                "id": 1,
                "labels": ["METHOD", "Rust"],
                "name": "main",
                "code": "fn main(){ let mut header = gz_header { extra_len: 0, extra_max: EXTRA_CAPTURE_BUF as c_uint }; inflateGetHeader(&mut stream, &mut header); }",
            }
        ]
        path_bundle = {
            "combined_constraints": [],
            "value_env": {"EXTRA_CAPTURE_BUF": 4},
            "const_map": {"EXTRA_CAPTURE_BUF": 4},
        }

        result = evaluate_state_semantics(
            trigger_model=trigger_model,
            chain_nodes=chain_nodes,
            evidence_calls=[
                {
                    "id": 2,
                    "name": "inflateGetHeader",
                    "code": "inflateGetHeader",
                    "lang": "Rust",
                    "method": "main",
                }
            ],
            path_bundle=path_bundle,
            solver=PathConstraintSolver(domain="octagon"),
        )

        self.assertEqual(result["status"], "sat")
        self.assertTrue(result["rules"][0]["used_assumption"])
        self.assertTrue(
            any(c.get("variable") == "attacker_extra_len" and c.get("operator") == ">" and c.get("value") == 4
                for c in result["rules"][0]["constraints_used"])
        )

    def test_observed_length_uses_solver_and_can_fail(self):
        trigger_model = {
            "state_rules": [
                {
                    "id": "bounded_len",
                    "lhs": {
                        "field": "extra_len",
                        "state": "post",
                        "source": "observed",
                        "symbolic_var": "observed_extra_len",
                    },
                    "op": ">",
                    "rhs": {
                        "field": "extra_max",
                        "state": "pre",
                        "source": "observed",
                    },
                }
            ]
        }
        chain_nodes = [
            {
                "id": 1,
                "labels": ["METHOD", "Rust"],
                "name": "main",
                "code": "fn main(){ let mut header = gz_header { extra_len: 4, extra_max: 8 }; inflateGetHeader(&mut stream, &mut header); }",
            }
        ]
        path_bundle = {
            "combined_constraints": [],
            "value_env": {},
            "const_map": {},
        }

        result = evaluate_state_semantics(
            trigger_model=trigger_model,
            chain_nodes=chain_nodes,
            evidence_calls=[
                {
                    "id": 2,
                    "name": "inflateGetHeader",
                    "code": "inflateGetHeader",
                    "lang": "Rust",
                    "method": "main",
                }
            ],
            path_bundle=path_bundle,
            solver=PathConstraintSolver(domain="octagon"),
        )

        self.assertEqual(result["status"], "unsat")
        self.assertFalse(result["rules"][0]["used_assumption"])

    def test_legacy_existential_inputs_still_compatible(self):
        trigger_model = {
            "existential_inputs": [
                {
                    "name": "legacy_large_extra_len",
                    "field": "extra_len",
                    "symbolic_var": "legacy_extra_len",
                    "use_observed_value": False,
                    "greater_than_field": "extra_max",
                    "target_operator": ">",
                    "min_value": 16,
                    "min_operator": ">=",
                }
            ]
        }
        chain_nodes = [
            {
                "id": 1,
                "labels": ["METHOD", "Rust"],
                "name": "main",
                "code": "fn main(){ let mut header = gz_header { extra_len: 0, extra_max: 8 }; inflateGetHeader(&mut stream, &mut header); }",
            }
        ]
        result = evaluate_state_semantics(
            trigger_model=trigger_model,
            chain_nodes=chain_nodes,
            evidence_calls=[
                {
                    "id": 2,
                    "name": "inflateGetHeader",
                    "code": "inflateGetHeader",
                    "lang": "Rust",
                    "method": "main",
                }
            ],
            path_bundle={"combined_constraints": [], "value_env": {}, "const_map": {}},
            solver=PathConstraintSolver(domain="octagon"),
        )
        self.assertEqual(result["status"], "sat")


class TriggerConditionRuleTests(unittest.TestCase):
    def setUp(self):
        self.chain_nodes = [
            {
                "id": 100,
                "labels": ["METHOD", "Rust"],
                "name": "decode_image",
                "code": (
                    "fn decode_image(info: ImageInfo) { "
                    "if info.kind == ImageKind::WebP { "
                    "let mut file = File::open(info.path.clone()).unwrap(); "
                    "let mut bytes = Vec::new(); "
                    "file.read_to_end(&mut bytes).unwrap(); "
                    "let decoder = Decoder::new(&bytes); "
                    "decoder.decode(); "
                    "} "
                    "}"
                ),
            }
        ]
        self.calls = [
            {
                "id": 1,
                "name": "File::open",
                "code": "File::open(info.path.clone())",
                "lang": "Rust",
                "method": "decode_image",
            },
            {
                "id": 2,
                "name": "read_to_end",
                "code": "file.read_to_end(&mut bytes)",
                "lang": "Rust",
                "method": "decode_image",
            },
            {
                "id": 3,
                "name": "Decoder::new",
                "code": "Decoder::new(&bytes)",
                "lang": "Rust",
                "method": "decode_image",
            },
            {
                "id": 4,
                "name": "decode",
                "code": "decoder.decode()",
                "lang": "Rust",
                "method": "decode_image",
            },
        ]

    def test_control_code_contains_hits_webp_branch(self):
        cond = {
            "type": "control_code_contains",
            "contains": ["WebP"],
        }
        control_nodes = [
            {
                "id": 11,
                "code": "if info.kind == ImageKind::WebP",
                "child_codes": ["Decoder::new(&bytes)"],
            }
        ]
        result = eval_condition(cond, self.calls, self.calls, chain_nodes=self.chain_nodes, control_nodes=control_nodes)
        self.assertTrue(result["ok"])

    def test_field_to_call_arg_tracks_struct_field_path(self):
        cond = {
            "type": "field_to_call_arg",
            "sink": {"name": "File::open", "lang": "Rust", "arg_index": 1},
            "source_field": "path",
        }
        result = eval_condition(cond, self.calls, self.calls, chain_nodes=self.chain_nodes, control_nodes=[])
        self.assertTrue(result["ok"])
        self.assertEqual(result["evidence"][0]["call_name"], "File::open")

    def test_io_to_call_arg_tracks_open_read_decoder_new(self):
        cond = {
            "type": "io_to_call_arg",
            "sink": {"name": "Decoder::new", "lang": "Rust", "arg_index": 1},
            "open_call": {"name": "File::open", "lang": "Rust"},
            "read_call": {"name_regex": "(^|::)read_to_end$", "lang": "Rust"},
            "sink_arg_index": 1,
            "read_buf_arg_index": 1,
            "same_method": True,
        }
        result = eval_condition(cond, self.calls, self.calls, chain_nodes=self.chain_nodes, control_nodes=[])
        self.assertTrue(result["ok"])
        self.assertEqual(result["evidence"][0]["sink_call_name"], "Decoder::new")

    def test_call_order_can_require_same_receiver(self):
        cond = {
            "type": "call_order",
            "first": {"name": "Decoder::new", "lang": "Rust"},
            "second": {"name_regex": "(^|::)decode$", "lang": "Rust"},
            "same_method": True,
            "require_same_receiver": True,
        }
        result = eval_condition(cond, self.calls, self.calls, chain_nodes=self.chain_nodes, control_nodes=[])
        self.assertTrue(result["ok"])
        self.assertEqual(result["evidence"][0]["first_call_name"], "Decoder::new")

    def test_api_sequence_matches_ordered_calls(self):
        cond = {
            "type": "api_sequence",
            "steps": [
                {"name": "File::open"},
                {"name": "read_to_end"},
                {"name": "Decoder::new"},
                {"name": "decode"},
            ],
            "same_method": True,
        }
        result = eval_condition(cond, self.calls, self.calls, chain_nodes=self.chain_nodes, control_nodes=[])
        self.assertTrue(result["ok"])

    def test_len_to_call_arg_matches_len_expression(self):
        chain_nodes = [
            {
                "id": 200,
                "labels": ["METHOD", "Rust"],
                "name": "send_buf",
                "code": "fn send_buf(buf: Vec<u8>) { native_send(buf.as_ptr(), buf.len()); }",
            }
        ]
        calls = [
            {
                "id": 10,
                "name": "native_send",
                "code": "native_send(buf.as_ptr(), buf.len())",
                "lang": "Rust",
                "method": "send_buf",
            }
        ]
        cond = {
            "type": "len_to_call_arg",
            "sink": {"name": "native_send", "lang": "Rust", "arg_index": 2},
            "source_var": "buf",
        }
        result = eval_condition(cond, calls, calls, chain_nodes=chain_nodes, control_nodes=[])
        self.assertTrue(result["ok"])

    def test_option_to_call_arg_matches_option_unwrap_flow(self):
        chain_nodes = [
            {
                "id": 300,
                "labels": ["METHOD", "Rust"],
                "name": "revparse_entry",
                "code": (
                    "fn revparse_entry(args: Args, repo: Repo) { "
                    "let base = args.base.as_deref(); "
                    "repo.revparse_single(base.unwrap()); "
                    "}"
                ),
            }
        ]
        calls = [
            {
                "id": 20,
                "name": "revparse_single",
                "code": "repo.revparse_single(base.unwrap())",
                "lang": "Rust",
                "method": "revparse_entry",
            }
        ]
        cond = {
            "type": "option_to_call_arg",
            "sink": {"name": "revparse_single", "lang": "Rust", "arg_index": 1},
        }
        result = eval_condition(cond, calls, calls, chain_nodes=chain_nodes, control_nodes=[])
        self.assertTrue(result["ok"])

    def test_option_to_call_arg_can_use_assumption_when_enabled(self):
        chain_nodes = [
            {
                "id": 301,
                "labels": ["METHOD", "Rust"],
                "name": "revparse_entry",
                "code": "fn revparse_entry(repo: Repo, arg:&str) { repo.revparse_single(arg); }",
            }
        ]
        calls = [
            {
                "id": 21,
                "name": "revparse_single",
                "code": "repo.revparse_single(arg)",
                "lang": "Rust",
                "method": "revparse_entry",
            }
        ]
        cond = {
            "type": "option_to_call_arg",
            "sink": {"name": "revparse_single", "lang": "Rust", "arg_index": 1},
            "allow_assume_if_no_direct": True,
            "assumption_reason": "unit_test_assumption",
        }
        result = eval_condition(cond, calls, calls, chain_nodes=chain_nodes, control_nodes=[])
        self.assertTrue(result["ok"])
        self.assertTrue(result["evidence"][0]["assumed"])

    def test_builder_flag_chain_matches_setter_calls(self):
        calls = [
            {"id": 1, "name": "jit", "code": "builder.jit(true)", "lang": "Rust", "method": "compile"},
            {"id": 2, "name": "utf", "code": "builder.utf(true)", "lang": "Rust", "method": "compile"},
            {"id": 3, "name": "build", "code": "builder.build(pattern)", "lang": "Rust", "method": "compile"},
        ]
        cond = {
            "type": "builder_flag_chain",
            "sink": {"name": "build", "lang": "Rust"},
            "setters": [{"name": "jit"}, {"name": "utf"}],
            "same_method": True,
            "require_same_receiver": True,
        }
        result = eval_condition(cond, calls, calls, chain_nodes=[], control_nodes=[])
        self.assertTrue(result["ok"])


class RuleNormalizationAndResultTests(unittest.TestCase):
    def test_match_call_name_supports_qualified_suffix(self):
        self.assertTrue(
            _match_call_name(
                "git2::Repository::revparse_single",
                ["revparse_single"],
                "",
            )
        )
        self.assertTrue(
            _match_call_name(
                "revparse_single",
                ["git2::Repository::revparse_single"],
                "",
            )
        )

    def test_collect_rust_sink_candidates_includes_symbols_and_conditions(self):
        rule = {
            "symbols": ["git_revparse_single"],
            "rust_sinks": [{"path": "git2::Repository::revparse_ext"}],
            "trigger_model": {
                "conditions": [
                    {"type": "call", "name": "cocogitto::CocoGitto::get_changelog_at_tag", "lang": "Rust"}
                ]
            },
        }
        sinks = collect_rust_sink_candidates(rule)
        tokens = [spec["token"].lower() for spec in sinks]
        raws = [spec["raw"].lower() for spec in sinks]
        self.assertIn("revparse_single", tokens)
        self.assertIn("revparse_ext", tokens)
        self.assertNotIn("get_changelog_at_tag", raws)

    def test_collect_rust_sink_candidates_preserves_name_regex_conditions(self):
        rule = {
            "trigger_model": {
                "conditions": [
                    {
                        "type": "call_code_contains",
                        "name_regex": "(?i)(^|::)decode$",
                        "lang": "Rust",
                        "contains": ["packet"],
                        "contains_all": False,
                    }
                ]
            },
        }
        sinks = collect_rust_sink_candidates(rule)
        self.assertTrue(any(spec.get("name_regex") == "(?i)(^|::)decode$" for spec in sinks))

    def test_synthesize_sink_calls_from_method_code_and_merge(self):
        chain_nodes = [
            {
                "id": 42,
                "labels": ["METHOD", "Rust"],
                "name": "resolve_explicit_base",
                "code": "fn resolve_explicit_base(repo:&Repo, base:&str){ let (obj, r) = repo.raw().revparse_ext(base)?; }",
            }
        ]
        synthetic = synthesize_sink_calls_from_method_code(chain_nodes, ["revparse_ext"])
        self.assertEqual(len(synthetic), 1)
        self.assertEqual(synthetic[0]["name"], "revparse_ext")

        merged = merge_evidence_calls({"chain_calls": [], "all_calls": []}, synthetic)
        self.assertEqual(len(merged["all_calls"]), 1)
        self.assertEqual(merged["all_calls"][0]["name"], "revparse_ext")

    def test_synthesize_sink_calls_from_method_code_supports_name_regex(self):
        chain_nodes = [
            {
                "id": 7,
                "labels": ["METHOD", "Rust"],
                "name": "decode_video",
                "code": "fn decode_video(decoder:&Decoder, packet:&[u8]){ let _ = decoder.decode(packet); }",
            }
        ]
        synthetic = synthesize_sink_calls_from_method_code(
            chain_nodes,
            [
                {
                    "name_regex": "(?i)(^|::)decode$",
                    "contains": ["packet"],
                    "contains_all": False,
                }
            ],
        )
        self.assertEqual(len(synthetic), 1)
        self.assertIn("decode", synthetic[0]["code"])

    def test_has_actionable_trigger_hits(self):
        trigger_hits = {
            "required_hits": [
                {
                    "id": "rust_sink_revparse_single",
                    "evidence": [{"name": "revparse_single", "lang": "Rust"}],
                }
            ]
        }
        self.assertTrue(has_actionable_trigger_hits(trigger_hits))

    def test_collect_source_synthetic_sink_calls(self):
        with TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            (src_dir / "lib.rs").write_text(
                "pub fn run(repo:&Repo,arg:&str){ let _ = repo.revparse_single(arg); }",
                encoding="utf-8",
            )
            calls = collect_source_synthetic_sink_calls(tmp, ["git2::Repository::revparse_single"])
            self.assertTrue(calls)
            self.assertEqual(calls[0]["name"], "revparse_single")

    def test_normalize_vuln_rule_compiles_high_level_fields(self):
        vuln = {
            "cve": "CVE-TEST-0001",
            "package": "libwebp",
            "version_range": "<1.3.2",
            "must_flow": [
                {"source": "ImageInfo.path", "sink": "File::open.arg1"},
                {"source": "File::open.bytes", "sink": "Decoder::new.arg1"},
            ],
            "rust_guards": {"all": ["ImageType::from_mime(mime) == Webp"]},
            "prune": {"any": ["image_type constrained to Jpeg|Png"]},
        }
        normalized = normalize_vuln_rule(vuln)
        cond_types = [c.get("type") for c in normalized["trigger_model"]["conditions"]]
        self.assertIn("field_to_call_arg", cond_types)
        self.assertIn("io_to_call_arg", cond_types)
        self.assertIn("all_of", cond_types)
        miti_types = [m.get("type") for m in normalized["trigger_model"]["mitigations"]]
        self.assertIn("any_of", miti_types)

    def test_normalize_must_flow_option_prefers_option_condition(self):
        vuln = {
            "cve": "CVE-TEST-OP",
            "package": "libgit2",
            "must_flow": ["Option<String>.as_deref -> revparse_ext.arg1"],
        }
        normalized = normalize_vuln_rule(vuln)
        cond_types = [c.get("type") for c in normalized["trigger_model"]["conditions"]]
        self.assertIn("option_to_call_arg", cond_types)

    def test_normalize_vuln_rule_does_not_force_rust_sinks_when_trigger_exists(self):
        vuln = {
            "cve": "CVE-TEST-NORM",
            "package": "pcre2-sys",
            "rust_sinks": [{"path": "grep_pcre2::RegexMatcherBuilder::build"}],
            "trigger_model": {
                "conditions": [
                    {"id": "engine_selected", "type": "call", "name": "matcher_pcre2", "lang": "Rust"}
                ]
            },
        }
        normalized = normalize_vuln_rule(vuln)
        ids = [c.get("id") for c in normalized["trigger_model"]["conditions"]]
        self.assertIn("engine_selected", ids)
        self.assertNotIn("rust_sink_build", ids)
        self.assertEqual(normalized["rule_compile_meta"]["compiled_rust_sink_conditions"], 0)

    def test_auto_generated_pcre2_rule_tracks_scan_substring_match_path(self):
        rule = generate_vulns_payload({"family": "pcre2", "project": "pomsky-bin"})[0]
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("pcre2::bytes::Regex::captures", sink_paths)
        self.assertEqual(rule["cve"], "CVE-2025-58050")
        self.assertEqual(rule["version_range"], ">=10.45,<10.46")
        condition_ids = {cond["id"] for cond in rule["trigger_model"]["conditions"]}
        self.assertIn("pcre2_pattern_build", condition_ids)
        self.assertIn("pcre2_match_use", condition_ids)
        self.assertIn("pcre2_scan_substring_pattern", condition_ids)
        any_of = next(cond for cond in rule["trigger_model"]["conditions"] if cond["id"] == "pcre2_match_use")
        inner_ids = {cond["id"] for cond in any_of["conditions"]}
        self.assertIn("pcre2_regex_captures", inner_ids)

    def test_auto_generated_libjpeg_rule_includes_wrapper_decode_sink(self):
        rule = generate_vulns_payload({"family": "libjpeg-turbo", "project": "reduce_image_size"})[0]
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("turbojpeg::decompress_image", sink_paths)
        inner_names = {cond["name"] for cond in rule["trigger_model"]["conditions"][0]["conditions"]}
        self.assertIn("decompress_image", inner_names)

    def test_auto_generated_openh264_rule_filters_gstreamer_context(self):
        rule = generate_vulns_payload({"family": "openh264", "project": "jetkvm_client"})[0]
        generic_sink = next(sink for sink in rule["rust_sinks"] if sink["path"] == "Decoder::decode")
        self.assertEqual(generic_sink["context_tokens"], ["openh264"])
        self.assertIn("gstreamer", rule["input_predicate"]["negative_tokens"])

    def test_auto_generated_sqlite_rule_tracks_query_and_prepare_paths(self):
        rule = generate_vulns_payload({"family": "sqlite", "project": "reef"})[0]
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("rusqlite::Connection::query_row", sink_paths)
        self.assertIn("rusqlite::Connection::prepare", sink_paths)

    def test_auto_generated_libxml2_rule_tracks_parser_wrapper_and_input(self):
        rule = generate_vulns_payload({"family": "libxml2", "project": "fatoora-core"})[0]
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("Parser::parse_string", sink_paths)
        cond_ids = {cond["id"] for cond in rule["trigger_model"]["conditions"]}
        self.assertIn("libxml2_parse_entry", cond_ids)
        self.assertIn("libxml2_input", cond_ids)

    def test_auto_generated_libwebp_rule_tracks_direct_and_wrapper_decode(self):
        rule = generate_vulns_payload({"family": "libwebp", "project": "libwebp-image"})[0]
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("WebPDecodeRGBA", sink_paths)
        self.assertIn("webp_load_rgba_from_memory", sink_paths)
        cond_ids = {cond["id"] for cond in rule["trigger_model"]["conditions"]}
        self.assertIn("libwebp_decode_entry", cond_ids)
        self.assertIn("libwebp_input", cond_ids)

    def test_auto_generated_gdal_rule_tracks_dataset_open_and_input(self):
        rule = generate_vulns_payload({"family": "gdal", "project": "gdal"})[0]
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("Dataset::open", sink_paths)
        cond_ids = {cond["id"] for cond in rule["trigger_model"]["conditions"]}
        self.assertIn("gdal_dataset_entry", cond_ids)
        self.assertIn("gdal_input", cond_ids)

    def test_auto_generated_libarchive_rule_tracks_archive_iteration_and_input(self):
        rule = generate_vulns_payload({"family": "libarchive", "project": "pacfiles"})[0]
        self.assertEqual(rule["package"], "libarchive")
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("compress_tools::ArchiveIterator::from_read", sink_paths)
        self.assertIn("compress_tools::uncompress_archive_file", sink_paths)
        cond_ids = {cond["id"] for cond in rule["trigger_model"]["conditions"]}
        self.assertIn("libarchive_entry", cond_ids)
        self.assertIn("libarchive_input", cond_ids)

    def test_generic_auto_generated_family_rule_supports_curl(self):
        self.assertTrue(can_auto_generate({"family": "curl"}))
        rule = generate_vulns_payload({"family": "curl", "project": "downloader"})[0]
        self.assertEqual(rule["package"], "curl")
        self.assertEqual(rule["version_range"], ">=0")
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("Easy::perform", sink_paths)
        cond_ids = {cond["id"] for cond in rule["trigger_model"]["conditions"]}
        self.assertIn("curl_entry_any", cond_ids)
        self.assertIn("curl_input", cond_ids)

    def test_generic_auto_generated_family_rule_supports_libpng(self):
        self.assertTrue(can_auto_generate({"family": "libpng"}))
        rule = generate_vulns_payload({"family": "libpng", "project": "png-reader"})[0]
        self.assertEqual(rule["package"], "libpng")
        sink_paths = {sink["path"] for sink in rule["rust_sinks"]}
        self.assertIn("png_image_begin_read_from_memory", sink_paths)
        self.assertIn("png_image_finish_read", sink_paths)
        self.assertEqual(rule["input_predicate"]["class"], "crafted_interlaced_16bit_png")

    def test_analyze_triggerability_requires_chain_nodes(self):
        trigger_model = {
            "conditions": [
                {"id": "caseless_enabled", "type": "call", "name": "caseless", "lang": "Rust"}
            ]
        }
        evidence = {
            "chain_calls": [],
            "all_calls": [
                {
                    "id": "srcsynthetic:a.rs:12:caseless",
                    "name": "caseless",
                    "code": "builder.caseless(true)",
                    "lang": "Rust",
                    "method": "a.rs:12",
                    "scope": "synthetic_source_text",
                }
            ],
        }
        out = analyze_triggerability(
            session=None,
            chain_nodes=[],
            trigger_model=trigger_model,
            source_patterns=[],
            sanitizer_patterns=[],
            context_keywords=[],
            control_nodes=[],
            evidence_calls_override=evidence,
        )
        self.assertEqual(out["triggerable"], "unknown")
        self.assertIn("No call path analyzed", out["evidence_notes"][0])

    def test_evaluate_env_guards_supports_version_source_feature(self):
        vuln = {
            "package": "libwebp",
            "version_range": "<1.3.2",
            "env_guards": {
                "all": [
                    {"type": "component_source", "expected": "bundled"},
                    {"type": "feature_enabled", "feature": "simd"},
                ]
            },
        }
        package_metadata = {
            "libwebp": {
                "versions": ["1.3.1"],
                "sources": ["bundled"],
                "features": ["simd", "decoder"],
                "langs": ["C"],
            }
        }
        package_versions = {"libwebp": ["1.3.1"]}
        eval_res = evaluate_env_guards(vuln, package_metadata, package_versions)
        self.assertEqual(eval_res["status"], "satisfied")
        self.assertTrue(eval_res["satisfied"])
        self.assertFalse(eval_res["failed"])

    def test_map_result_kind_and_assumption_evidence(self):
        vuln = {
            "input_predicate": {
                "class": "crafted_webp_lossless",
                "strategy": "assume_if_not_explicit",
            }
        }
        assumptions = collect_assumption_evidence(
            vuln_rule=vuln,
            existential_input_result={"rules": []},
            path_bundle={"boundary_assumptions": []},
        )
        self.assertTrue(assumptions)
        kind = map_result_kind("confirmed", True, assumptions)
        self.assertEqual(kind, "TriggerableWithInputAssumption")

    def test_map_result_kind_prefers_manual_trigger_status(self):
        self.assertEqual(
            map_result_kind("confirmed", True, [], manual_status="observable_triggered"),
            "ObservableTriggered",
        )
        self.assertEqual(
            map_result_kind("confirmed", True, [], manual_status="path_triggered"),
            "PathTriggered",
        )

    def test_manual_evidence_selection_and_application(self):
        entries = [
            {
                "cve": "CVE-2023-4863",
                "package": "libwebp",
                "symbol": "WebPDecodeRGBA",
                "status": "observable_triggered",
                "summary": "ASan heap-buffer-overflow in VP8LBuildHuffmanTable",
            }
        ]
        matched = select_manual_evidence(
            entries,
            cve="CVE-2023-4863",
            package="libwebp-sys2",
            symbol="WebPDecodeRGBA",
        )
        self.assertIsNotNone(matched)
        entry = {
            "reachable": True,
            "triggerable": "possible",
            "triggerable_internal": "possible",
            "trigger_confidence": "medium",
            "assumptions_used": [],
            "evidence_notes": [],
            "result_kind": "Reachable",
        }
        applied = apply_manual_evidence(entry, matched)
        self.assertEqual(applied["manual_trigger_status"], "observable_triggered")
        self.assertEqual(applied["triggerable"], "confirmed")
        self.assertEqual(applied["result_kind"], "ObservableTriggered")
        self.assertIn("Manual reproduction", applied["evidence_notes"][0])

    def test_summarize_guard_status_merges_trigger_and_env(self):
        trigger_hits = {
            "required_hits": [{"id": "a"}],
            "required_miss": [{"id": "b"}],
            "mitigations_hit": [{"id": "m"}],
        }
        env_eval = {
            "satisfied": [{"kind": "env_guard"}],
            "unresolved": [{"kind": "env_guard"}],
            "failed": [{"kind": "version_range"}],
        }
        summary = summarize_guard_status(trigger_hits, env_eval)
        self.assertIn("trigger:a", summary["satisfied_guards"])
        self.assertIn("trigger:b", summary["unresolved_guards"])
        self.assertIn("mitigation:m", summary["failed_guards"])

    def test_cross_language_native_evidence_requires_native_side_signal_for_system_sources(self):
        self.assertFalse(
            has_cross_language_native_evidence(
                source_status="system",
                call_reachability_source="rust_call_package",
                has_method=False,
                strict_callsite_edges=0,
                native_analysis_coverage="target_only",
                native_dependency_imports=[],
                strict_dependency_resolution={},
            )
        )
        self.assertTrue(
            has_cross_language_native_evidence(
                source_status="system",
                call_reachability_source="c_method",
                has_method=True,
                strict_callsite_edges=0,
                native_analysis_coverage="target_only",
                native_dependency_imports=[],
                strict_dependency_resolution={},
            )
        )

    def test_explicit_native_symbol_bridge_accepts_wrapper_symbol_mentions(self):
        calls = [
            {
                "name": "parse_string",
                "code": "let docptr = xmlReadMemory(input_ptr, input_len, url_ptr, encoding_ptr, options);",
                "scope": "synthetic_package_method_code",
            },
            {
                "name": "WebPDecodeRGBA",
                "code": "let result = unsafe { sys::WebPDecodeRGBA(data.as_ptr(), data.len(), &mut width, &mut height) };",
                "scope": "synthetic_package_method_code",
            },
        ]
        self.assertTrue(has_explicit_native_symbol_bridge("xmlReadMemory", calls))
        self.assertTrue(has_explicit_native_symbol_bridge("WebPDecodeRGBA", calls))
        self.assertTrue(has_explicit_native_symbol_bridge("WebPDecode", calls))
        self.assertFalse(has_explicit_native_symbol_bridge("pcre2_jit_compile_8", calls))

    def test_native_symbol_name_match_allows_api_family_prefix(self):
        self.assertTrue(_native_symbol_names_match("WebPDecode", "WebPDecodeRGBA"))
        self.assertTrue(_native_symbol_names_match("WebPDecode", "WebPDecodeRGB"))
        self.assertFalse(_native_symbol_names_match("WebPDecode", "WebPAnimDecoderGetNext"))

    def test_explicit_native_symbol_bridge_rejects_generated_bindings_only(self):
        calls = [
            {
                "name": "xmlReadMemory",
                "code": "pub fn xmlReadMemory(",
                "scope": "synthetic_source_text",
                "file": "target_cpg_analysis/debug/build/libxml/out/bindings.rs",
            }
        ]
        self.assertFalse(has_explicit_native_symbol_bridge("xmlReadMemory", calls))

    def test_dependency_source_symbol_bridge_accepts_real_wrapper_source(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            crate_dir = root / "libxml-0.3.8"
            src_dir = crate_dir / "src"
            src_dir.mkdir(parents=True)
            (crate_dir / "Cargo.toml").write_text('[package]\nname="libxml"\nversion="0.3.8"\n', encoding="utf-8")
            (src_dir / "parser.rs").write_text(
                "use crate::bindings::*;\nfn parse_string() { let _ = unsafe { xmlReadMemory(buf, len, url, enc, 0) }; }\n",
                encoding="utf-8",
            )
            deps = {"packages": [{"name": "libxml", "manifest_path": str(crate_dir / 'Cargo.toml')}]}
            self.assertTrue(has_dependency_source_symbol_bridge("xmlReadMemory", deps, ["libxml"]))

    def test_collect_source_native_gateway_calls_skips_doc_comments(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_dir = root / "src"
            src_dir.mkdir(parents=True)
            (src_dir / "lib.rs").write_text(
                "/// webp::WebPAnimDecoderGetNext(decoder, out, ts)\n"
                "fn run(decoder: *mut u8) { unsafe { webp::WebPAnimDecoderGetNext(decoder.cast(), std::ptr::null_mut(), std::ptr::null_mut()); } }\n",
                encoding="utf-8",
            )
            calls = collect_source_native_gateway_calls(str(root), ["webp"])
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["name"], "WebPAnimDecoderGetNext")

    def test_collect_package_native_gateway_calls_extracts_code_window(self):
        session = MagicMock()
        session.run.return_value = [
            {
                "id": 7,
                "name": "decode_image",
                "code": (
                    "fn decode_image(data: &[u8]) { let prefix = 1; let prefix2 = 2; "
                    "let result = unsafe { webp::WebPDecodeRGBA(data.as_ptr(), data.len(), &mut w, &mut h) }; "
                    "let suffix = prefix + prefix2; println!(\"{}\", suffix); }"
                ),
            }
        ]
        calls = collect_package_native_gateway_calls(session, "demo", ["webp"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["name"], "WebPDecodeRGBA")
        self.assertIn("WebPDecodeRGBA", calls[0]["code"])
        self.assertIsInstance(calls[0]["code"], str)

    def test_has_transitive_native_symbol_bridge_uses_native_call_path(self):
        session = MagicMock()
        session.run.return_value.single.return_value = {"ok": 1}
        self.assertTrue(
            has_transitive_native_symbol_bridge(
                session,
                "libwebp",
                ["WebPAnimDecoderGetNext"],
                "WebPDecode",
            )
        )

    def test_find_best_dep_chain_can_fall_back_to_matched_native_crate(self):
        session = MagicMock()
        session.run.return_value = [
            {
                "target": "libwebp-sys2",
                "chain": ["ril", "image-rs", "libwebp-sys2"],
                "edges": [
                    {"from": "ril", "to": "image-rs", "type": "DEPENDS_ON"},
                    {"from": "image-rs", "to": "libwebp-sys2", "type": "DEPENDS_ON"},
                ],
            }
        ]
        match = find_best_dep_chain(
            session,
            "ril",
            "libwebp",
            native_component_instances=[
                {
                    "matched_crates": [
                        {"crate": "libwebp-sys2"},
                    ]
                }
            ],
        )
        self.assertEqual(match["target"], "libwebp-sys2")
        self.assertEqual(match["chain"][-1], "libwebp-sys2")
        kwargs = session.run.call_args.kwargs
        self.assertIn("libwebp", kwargs["pkg_names"])
        self.assertIn("libwebp-sys2", kwargs["pkg_names"])

    def test_select_relevant_native_gateway_calls_prefers_real_decode_over_cleanup(self):
        calls = [
            {
                "id": "clear",
                "name": "WebPDataClear",
                "code": "unsafe { libwebp::WebPDataClear(&mut data) }",
                "method": "cleanup",
                "scope": "synthetic_native_gateway_source",
                "line": 10,
            },
            {
                "id": "decode",
                "name": "WebPDecodeRGBA",
                "code": "unsafe { libwebp::WebPDecodeRGBA(ptr, len, &mut w, &mut h) }",
                "method": "decode_frame",
                "scope": "synthetic_native_gateway_source",
                "line": 200,
            },
            {
                "id": "delete",
                "name": "WebPMuxDelete",
                "code": "unsafe { libwebp::WebPMuxDelete(mux) }",
                "method": "cleanup",
                "scope": "synthetic_native_gateway_source",
                "line": 20,
            },
        ]
        selected = select_relevant_native_gateway_calls(
            calls,
            symbol="WebPDecode",
            sink_candidates=[{"path": "webp::Decoder::decode"}],
            limit=1,
        )
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["name"], "WebPDecodeRGBA")

    def test_select_relevant_native_gateway_calls_beats_generic_next_over_new(self):
        calls = [
            {
                "id": "new",
                "name": "WebPAnimDecoderNew",
                "code": "unsafe { webp::WebPAnimDecoderNew(data, &opts) }",
                "method": "run_decoder",
                "scope": "synthetic_native_gateway_source",
                "line": 193,
            },
            {
                "id": "next",
                "name": "WebPAnimDecoderGetNext",
                "code": "unsafe { webp::WebPAnimDecoderGetNext(decoder, &mut buf, &mut ts) }",
                "method": "run_decoder",
                "scope": "synthetic_native_gateway_source",
                "line": 245,
            },
        ]
        selected = select_relevant_native_gateway_calls(calls, symbol="VP8LBuildHuffmanTable", limit=1)
        self.assertEqual(selected[0]["name"], "WebPAnimDecoderGetNext")

    def test_maybe_collect_expanded_feature_deps_uses_all_features_when_root_has_optional_deps(self):
        meta = {
            "packages": [
                {
                    "id": "pkg",
                    "name": "demo",
                    "features": {"webp": ["dep:libwebp-sys2"]},
                    "dependencies": [{"name": "libwebp-sys2", "optional": True}],
                }
            ],
            "workspace_default_members": ["pkg"],
            "resolve": {"nodes": [{"id": "pkg", "features": []}]},
        }
        expanded_meta = {
            "packages": [
                {
                    "id": "pkg",
                    "name": "demo",
                    "version": "0.1.0",
                    "manifest_path": "/tmp/demo/Cargo.toml",
                },
                {
                    "id": "dep",
                    "name": "libwebp-sys2",
                    "version": "0.1.11",
                    "manifest_path": "/tmp/libwebp-sys2/Cargo.toml",
                },
            ],
            "workspace_default_members": ["pkg"],
            "resolve": {
                "nodes": [
                    {"id": "pkg", "features": ["webp"], "deps": [{"pkg": "dep"}]},
                    {"id": "dep", "features": ["1_2"], "deps": []},
                ]
            },
        }
        with patch("tools.supplychain.supplychain_analyze.run_metadata", return_value=expanded_meta):
            result = maybe_collect_expanded_feature_deps("/tmp/demo", meta)
        self.assertIsNotNone(result)
        dep_names = {pkg["name"] for pkg in result["deps"]["packages"]}
        self.assertIn("libwebp-sys2", dep_names)

    def test_filter_speculative_source_features_keeps_functional_features_only(self):
        deps = {
            "packages": [
                {"name": "libwebp-sys2", "features": ["demux", "mux", "static"]},
            ]
        }
        _filter_speculative_source_features(deps, {"libwebp-sys2": []})
        self.assertEqual(deps["packages"][0]["features"], ["demux", "mux"])

    def test_resolve_native_component_instances_matches_sys_suffix_variants_and_probes_system(self):
        with TemporaryDirectory() as tmp:
            crate_dir = Path(tmp) / "libwebp-sys2"
            crate_dir.mkdir(parents=True, exist_ok=True)
            manifest = crate_dir / "Cargo.toml"
            manifest.write_text("[package]\nname='libwebp-sys2'\nversion='0.1.11'\n", encoding="utf-8")
            (crate_dir / "build.rs").write_text(
                "fn main(){ let _ = pkg_config::probe_library(\"libwebp\"); }",
                encoding="utf-8",
            )
            metadata = {
                "libwebp-sys2": {
                    "versions": ["0.1.11"],
                    "sources": ["cargo"],
                    "features": ["demux"],
                    "langs": ["Rust"],
                    "crate_sources": [],
                    "manifest_paths": [str(manifest)],
                }
            }
            vuln = {"package": "libwebp", "match": {"crates": ["webp", "libwebp-sys"]}}
            _SYSTEM_NATIVE_VERSION_CACHE.clear()
            with patch("tools.supplychain.supplychain_analyze.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                mock_run.return_value.stdout = "1.2.4\n"
                mock_run.return_value.stderr = ""
                instances = resolve_native_component_instances(vuln, metadata, cargo_dir=tmp)
            self.assertTrue(instances)
            self.assertEqual(instances[0]["source"], "system")
            self.assertEqual(instances[0]["resolved_version"], "1.2.4")
            crates = [row["crate"] for row in instances[0]["matched_crates"]]
            self.assertIn("libwebp-sys2", crates)

    def test_apply_sink_knowledge_fills_missing_sinks(self):
        vuln = {"package": "libwebp", "cve": "CVE-T"}
        sink_kb = {
            "libwebp": {
                "match": {"crates": ["webp", "libwebp-sys"]},
                "rust_sinks": [{"path": "webp::Decoder::decode"}],
                "symbols": ["WebPDecode"],
            }
        }
        out = apply_sink_knowledge(vuln, sink_kb)
        self.assertEqual(out["match"]["crates"][0], "webp")
        self.assertEqual(out["symbols"][0], "WebPDecode")

    def test_resolve_native_component_instances_uses_feature_and_build_signals(self):
        with TemporaryDirectory() as tmp:
            crate_dir = Path(tmp) / "libgit2-sys"
            crate_dir.mkdir(parents=True, exist_ok=True)
            manifest = crate_dir / "Cargo.toml"
            manifest.write_text("[package]\nname='libgit2-sys'\nversion='0.17.0'\n", encoding="utf-8")
            (crate_dir / "build.rs").write_text(
                "fn main(){ println!(\"cargo:rerun-if-changed=build.rs\"); cc::Build::new().compile(\"libgit2\"); }",
                encoding="utf-8",
            )
            metadata = {
                "libgit2-sys": {
                    "versions": ["0.17.0"],
                    "sources": ["cargo"],
                    "features": ["vendored-libgit2"],
                    "langs": ["Rust"],
                    "crate_sources": [],
                    "manifest_paths": [str(manifest)],
                }
            }
            vuln = {"package": "libgit2", "match": {"crates": ["libgit2-sys"]}}
            instances = resolve_native_component_instances(vuln, metadata, cargo_dir=tmp)
            self.assertTrue(instances)
            self.assertEqual(instances[0]["source"], "bundled")
            self.assertIn("vendored-libgit2", instances[0]["enabled_features"])

    def test_resolve_native_component_instances_falls_back_to_build_version_when_system_probe_missing(self):
        with TemporaryDirectory() as tmp:
            crate_dir = Path(tmp) / "gdal-sys"
            crate_dir.mkdir(parents=True, exist_ok=True)
            manifest = crate_dir / "Cargo.toml"
            manifest.write_text("[package]\nname='gdal-sys'\nversion='0.12.0'\n", encoding="utf-8")
            (crate_dir / "build.rs").write_text(
                "\n".join(
                    [
                        "fn main() {",
                        "    let native = \"3.4.0\";",
                        "    println!(\"cargo:warning={}\", native);",
                        "    let _ = pkg_config::probe_library(\"gdal\");",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            metadata = {
                "gdal": {
                    "versions": ["0.19.0"],
                    "sources": ["cargo"],
                    "features": ["default"],
                    "langs": ["Rust"],
                    "crate_sources": [],
                    "manifest_paths": [str(Path(tmp) / "gdal" / "Cargo.toml")],
                },
                "gdal-sys": {
                    "versions": ["0.12.0"],
                    "sources": ["cargo"],
                    "features": ["default"],
                    "langs": ["Rust"],
                    "crate_sources": [],
                    "manifest_paths": [str(manifest)],
                },
            }
            vuln = {"package": "gdal", "match": {"crates": ["gdal-sys"]}}
            with patch("tools.supplychain.supplychain_analyze._probe_system_native_version", return_value=None):
                instances = resolve_native_component_instances(vuln, metadata, cargo_dir=tmp)
            self.assertTrue(instances)
            self.assertEqual(instances[0]["source"], "system")
            self.assertEqual(instances[0]["resolved_version"], "3.4.0")

    def test_resolve_native_component_instances_prefers_system_openssl_version_probe(self):
        with TemporaryDirectory() as tmp:
            crate_dir = Path(tmp) / "openssl-sys"
            crate_dir.mkdir(parents=True, exist_ok=True)
            manifest = crate_dir / "Cargo.toml"
            manifest.write_text("[package]\nname='openssl-sys'\nversion='0.9.104'\n", encoding="utf-8")
            (crate_dir / "build.rs").write_text(
                "fn main(){ let _ = pkg_config::probe_library(\"openssl\"); }",
                encoding="utf-8",
            )
            metadata = {
                "openssl-sys": {
                    "versions": ["0.9.104"],
                    "sources": ["cargo"],
                    "features": [],
                    "langs": ["Rust"],
                    "crate_sources": [],
                    "manifest_paths": [str(manifest)],
                },
                "openssl": {
                    "versions": ["0.10.76"],
                    "sources": ["cargo"],
                    "features": [],
                    "langs": ["Rust"],
                    "crate_sources": [],
                    "manifest_paths": [],
                },
            }
            vuln = {
                "package": "openssl",
                "source_status": "system",
                "match": {"crates": ["openssl", "openssl-sys"]},
            }
            _SYSTEM_NATIVE_VERSION_CACHE.clear()
            with patch("tools.supplychain.supplychain_analyze.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                mock_run.return_value.stdout = "3.6.1\n"
                mock_run.return_value.stderr = ""
                instances = resolve_native_component_instances(vuln, metadata, cargo_dir=tmp)
            self.assertTrue(instances)
            self.assertEqual(instances[0]["source"], "system")
            self.assertEqual(instances[0]["resolved_version"], "3.6.1")
            evidence_kinds = [item.get("kind") for item in instances[0]["resolution_evidence"]]
            self.assertIn("system_probe", evidence_kinds)

    def test_resolve_native_component_instances_can_use_system_probe_without_matched_crates(self):
        vuln = {
            "package": "openssl",
            "source_status": "system",
            "match": {"crates": ["openssl", "openssl-sys", "native-tls"]},
        }
        _SYSTEM_NATIVE_VERSION_CACHE.clear()
        with patch("tools.supplychain.supplychain_analyze.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "3.6.1\n"
            mock_run.return_value.stderr = ""
            instances = resolve_native_component_instances(vuln, {}, cargo_dir="")
        self.assertTrue(instances)
        self.assertEqual(instances[0]["status"], "resolved")
        self.assertEqual(instances[0]["source"], "system")
        self.assertEqual(instances[0]["resolved_version"], "3.6.1")
        evidence_kinds = [item.get("kind") for item in instances[0]["resolution_evidence"]]
        self.assertIn("missing_candidate_crates", evidence_kinds)
        self.assertIn("system_probe", evidence_kinds)

    def test_resolve_native_component_instances_honors_env_override_for_system_version(self):
        vuln = {
            "package": "openssl",
            "source_status": "system",
            "match": {"crates": ["openssl", "openssl-sys", "native-tls"]},
        }
        _SYSTEM_NATIVE_VERSION_CACHE.clear()
        with patch.dict("os.environ", {"SUPPLYCHAIN_NATIVE_VERSION_OPENSSL": "3.0.6"}, clear=False):
            instances = resolve_native_component_instances(vuln, {}, cargo_dir="")
        self.assertTrue(instances)
        self.assertEqual(instances[0]["resolved_version"], "3.0.6")
        evidence = instances[0]["resolution_evidence"]
        probe = next(item for item in evidence if item.get("kind") == "system_probe")
        self.assertEqual(probe["probe"]["tool"], "env_override")

    def test_resolve_native_component_instances_can_probe_freetype_system_version(self):
        vuln = {
            "package": "freetype",
            "source_status": "system",
            "match": {"crates": ["freetype-rs", "freetype-sys", "servo-freetype-sys"]},
        }
        _SYSTEM_NATIVE_VERSION_CACHE.clear()
        with patch("tools.supplychain.supplychain_analyze.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "2.14.2\n"
            mock_run.return_value.stderr = ""
            instances = resolve_native_component_instances(vuln, {}, cargo_dir="")
        self.assertTrue(instances)
        self.assertEqual(instances[0]["source"], "system")
        self.assertEqual(instances[0]["resolved_version"], "2.14.2")
        evidence_kinds = [item.get("kind") for item in instances[0]["resolution_evidence"]]
        self.assertIn("system_probe", evidence_kinds)

    def test_resolve_native_component_instances_prefers_freetype_config_over_pkg_config_epoch(self):
        vuln = {
            "package": "freetype",
            "source_status": "system",
            "match": {"crates": ["freetype-rs", "freetype-sys", "servo-freetype-sys"]},
        }
        _SYSTEM_NATIVE_VERSION_CACHE.clear()

        def fake_run(cmd, *args, **kwargs):
            class Result:
                def __init__(self, returncode, stdout, stderr=""):
                    self.returncode = returncode
                    self.stdout = stdout
                    self.stderr = stderr

            if cmd[:2] == ["freetype-config", "--ftversion"]:
                return Result(0, "2.14.2\n")
            if cmd[:3] == ["pkg-config", "--modversion", "freetype2"]:
                return Result(0, "26.5.20\n")
            return Result(1, "", "unsupported")

        with patch("tools.supplychain.supplychain_analyze.subprocess.run", side_effect=fake_run):
            instances = resolve_native_component_instances(vuln, {}, cargo_dir="")
        self.assertTrue(instances)
        self.assertEqual(instances[0]["resolved_version"], "2.14.2")

    def test_resolve_native_component_instances_can_probe_zlib_system_version(self):
        vuln = {
            "package": "zlib",
            "source_status": "system",
            "match": {"crates": ["libz-sys", "flate2"]},
        }
        _SYSTEM_NATIVE_VERSION_CACHE.clear()
        with patch("tools.supplychain.supplychain_analyze.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "1.2.12\n"
            mock_run.return_value.stderr = ""
            instances = resolve_native_component_instances(vuln, {}, cargo_dir="")
        self.assertTrue(instances)
        self.assertEqual(instances[0]["source"], "system")
        self.assertEqual(instances[0]["resolved_version"], "1.2.12")
        evidence_kinds = [item.get("kind") for item in instances[0]["resolution_evidence"]]
        self.assertIn("system_probe", evidence_kinds)

    def test_auto_vuln_inputs_support_openh264_freetype_zlib_and_libarchive(self):
        openh264_item = {
            "family": "openh264",
            "project": "demo-video",
            "cve": "CVE-2025-27091",
            "dependency_evidence": [{"crate": "openh264"}],
        }
        freetype_item = {
            "family": "freetype",
            "project": "demo-font",
            "cve": "CVE-2025-27363",
            "dependency_evidence": [{"crate": "freetype-rs"}],
        }
        zlib_item = {
            "family": "zlib",
            "project": "demo-gzip",
            "cve": "CVE-2022-37434",
            "dependency_evidence": [{"crate": "libz-sys"}],
        }
        libarchive_item = {
            "family": "libarchive",
            "project": "demo-archive",
            "cve": "LIBARCHIVE-2025-FAMILY",
            "dependency_evidence": [{"crate": "compress-tools"}],
        }
        self.assertTrue(can_auto_generate(openh264_item))
        self.assertTrue(can_auto_generate(freetype_item))
        self.assertTrue(can_auto_generate(zlib_item))
        self.assertTrue(can_auto_generate(libarchive_item))
        openh264_rule = generate_vulns_payload(openh264_item)[0]
        freetype_rule = generate_vulns_payload(freetype_item)[0]
        zlib_rule = generate_vulns_payload(zlib_item)[0]
        libarchive_rule = generate_vulns_payload(libarchive_item)[0]
        self.assertEqual(openh264_rule["package"], "openh264-sys2")
        self.assertEqual(openh264_rule["symbols"], ["WelsDecodeBs"])
        self.assertEqual(freetype_rule["package"], "freetype")
        self.assertEqual(freetype_rule["version_range"], "<2.13.1")
        self.assertIn("FT_Load_Glyph", freetype_rule["symbols"])
        self.assertEqual(zlib_rule["package"], "zlib")
        self.assertEqual(zlib_rule["version_range"], "<1.2.13")
        self.assertIn("inflateGetHeader", zlib_rule["symbols"])
        self.assertEqual(libarchive_rule["package"], "libarchive")
        self.assertIn("archive_read_next_header", libarchive_rule["symbols"])

    def test_evaluate_input_predicate_can_prune_non_target_type(self):
        rule = {
            "input_predicate": {
                "class": "crafted_webp_lossless",
                "strategy": "assume_if_not_explicit",
            }
        }
        chain_nodes = [
            {
                "id": 9,
                "labels": ["METHOD", "Rust"],
                "name": "decode_jpeg",
                "code": "if ty == ImageType::Jpeg { decoder.decode() }",
            }
        ]
        result = evaluate_input_predicate(rule, chain_nodes, [], [])
        self.assertEqual(result["status"], "failed")

    def test_synthesize_sink_calls_respects_contextual_rust_sink_specs(self):
        sinks = [
            {
                "path": "Decoder::decode",
                "contains": ["packet", "as_slice"],
                "contains_all": False,
            }
        ]
        benign = synthesize_sink_calls_from_method_code(
            [
                {
                    "id": 1,
                    "labels": ["METHOD", "Rust"],
                    "name": "connect",
                    "code": "let decoded_answer = base64::engine::general_purpose::STANDARD.decode(sd)?;",
                }
            ],
            sinks,
        )
        dangerous = synthesize_sink_calls_from_method_code(
            [
                {
                    "id": 2,
                    "labels": ["METHOD", "Rust"],
                    "name": "decode_video",
                    "code": "let decoded = decoder.decode(video_packet.as_slice());",
                }
            ],
            sinks,
        )
        self.assertEqual(benign, [])
        self.assertEqual(len(dangerous), 1)


class NativeSourceResolverTests(unittest.TestCase):
    def test_provider_supports_official_download_for_common_components(self):
        for component in ["libxml2", "zlib", "expat", "openssl", "libwebp"]:
            provider = get_provider(component)
            self.assertIsNotNone(provider)
            self.assertTrue(provider.official_candidates("1.2.3"))

    def test_find_local_native_source_tree_prefers_bundled_source_dir(self):
        with TemporaryDirectory() as tmp:
            crate_dir = Path(tmp) / "openh264-sys2-0.4.4"
            upstream_dir = crate_dir / "upstream" / "codec" / "decoder"
            upstream_dir.mkdir(parents=True, exist_ok=True)
            manifest = crate_dir / "Cargo.toml"
            manifest.write_text("[package]\nname='openh264-sys2'\nversion='0.4.4'\n", encoding="utf-8")
            (upstream_dir / "welsDecoderExt.cpp").write_text(
                "int WelsDecodeBs() { return 0; }\n",
                encoding="utf-8",
            )
            result = find_local_native_source_tree("openh264-sys2", [str(manifest)])
            self.assertIsNotNone(result)
            self.assertEqual(result["status"], "local")
            self.assertEqual(result["provenance"], "bundled-local")
            self.assertTrue(result["source_root"].endswith("upstream"))

    def test_ensure_native_source_tree_returns_unsupported_for_unknown_component(self):
        result = ensure_native_source_tree(
            "unknown-component",
            "1.2.3",
            [],
            cache_root="/tmp/native-source-cache",
            allow_download=True,
        )
        self.assertEqual(result["status"], "unsupported")

    def test_find_symbol_source_files_and_scope(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "vendor"
            dec_dir = root / "src" / "dec"
            dec_dir.mkdir(parents=True, exist_ok=True)
            (dec_dir / "webp_dec.c").write_text("int WebPDecode(void) { return 0; }\n", encoding="utf-8")
            (dec_dir / "vp8l_dec.c").write_text("int VP8LDecodeImage(void) { return 0; }\n", encoding="utf-8")
            files = find_symbol_source_files(str(root), ["WebPDecode", "VP8LDecodeImage"])
            self.assertEqual(len(files), 2)
            scope = choose_c_analysis_scope(str(root), files)
            self.assertEqual(scope, str(dec_dir))

    def test_infer_native_source_dependencies_from_source_tree(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "libxml2-src"
            root.mkdir(parents=True, exist_ok=True)
            (root / "parser.c").write_text(
                '#include <zlib.h>\n#include <openssl/ssl.h>\nint parse(){ return 0; }\n',
                encoding="utf-8",
            )
            (root / "CMakeLists.txt").write_text(
                "find_package(OpenSSL REQUIRED)\npkg_check_modules(ZLIB REQUIRED zlib)\n",
                encoding="utf-8",
            )
            deps = infer_native_source_dependencies("libxml2", str(root))
            names = {item["component"] for item in deps}
            self.assertIn("zlib", names)
            self.assertIn("openssl", names)

    def test_parse_pkg_config_flags(self):
        lib_dirs, libs = _parse_pkg_config_flags("-L/usr/lib -L/opt/lib -lssl -lcrypto")
        self.assertEqual(lib_dirs, ["/usr/lib", "/opt/lib"])
        self.assertEqual(libs, ["ssl", "crypto"])

    def test_parse_ldd_output(self):
        rows = _parse_ldd_output(
            """
            libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007f)
            libssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3 (0x00007f)
            """
        )
        self.assertEqual(rows[0]["soname"], "libz.so.1")
        self.assertEqual(rows[1]["path"], "/lib/x86_64-linux-gnu/libssl.so.3")

    @patch("tools.fetch.native_symbol_resolver.collect_binary_linked_libraries")
    @patch("tools.fetch.native_symbol_resolver._pkg_config_probe")
    def test_collect_component_link_context(self, mock_pkg, mock_ldd):
        mock_pkg.return_value = {"name": "libxml-2.0", "ok": True, "libs": ["xml2"], "lib_dirs": ["/usr/lib"], "version": "2.9.14"}
        mock_ldd.return_value = [{"soname": "libz.so.1", "path": "/lib/libz.so.1"}]
        context = collect_component_link_context("libxml2", ["/tmp/libxml2.so"])
        self.assertIn("xml2", context["linked_tokens"])
        self.assertIn("z", context["linked_tokens"])

    @patch("tools.fetch.native_symbol_resolver.find_component_binaries")
    @patch("tools.fetch.native_symbol_resolver.collect_binary_exports")
    def test_build_symbol_provider_index_uses_binary_exports(self, mock_exports, mock_binaries):
        mock_binaries.side_effect = lambda component: [f"/tmp/{component}.so"] if component in {"zlib", "openssl"} else []
        mock_exports.side_effect = lambda path: {"inflate"} if "zlib" in path else {"SSL_read"}
        index = build_symbol_provider_index(["zlib", "openssl"])
        self.assertIn("zlib", index)
        self.assertIn("inflate", index["zlib"]["exports"])
        self.assertIn("openssl", index)
        self.assertIn("SSL_read", index["openssl"]["exports"])

    @patch("tools.fetch.native_symbol_resolver.collect_binary_linked_libraries")
    @patch("tools.fetch.native_symbol_resolver._pkg_config_probe")
    @patch("tools.fetch.native_symbol_resolver.build_symbol_provider_index")
    @patch("tools.fetch.native_symbol_resolver.collect_binary_imports")
    @patch("tools.fetch.native_symbol_resolver.find_component_binaries")
    def test_resolve_strict_native_dependencies_from_binary_symbols(self, mock_binaries, mock_imports, mock_index, mock_pkg, mock_ldd):
        mock_binaries.return_value = ["/tmp/libxml2.so"]
        mock_imports.return_value = {"inflate", "SSL_read", "unresolved_only"}
        mock_pkg.return_value = {"name": "libxml-2.0", "ok": True, "libs": ["z"], "lib_dirs": ["/usr/lib"], "version": "2.9.14"}
        mock_ldd.return_value = [{"soname": "libz.so.1", "path": "/lib/libz.so.1"}]
        mock_index.return_value = {
            "zlib": {"component": "zlib", "binaries": ["/tmp/libz.so"], "exports": {"inflate"}},
            "openssl": {"component": "openssl", "binaries": ["/tmp/libssl.so"], "exports": {"SSL_read"}},
            "libxml2": {"component": "libxml2", "binaries": ["/tmp/libxml2.so"], "exports": {"xmlParseDoc"}},
        }
        result = resolve_strict_native_dependencies("libxml2", resolved_version="2.9.14")
        self.assertEqual(result["status"], "resolved")
        names = {item["component"] for item in result["dependencies"]}
        self.assertEqual(names, {"zlib"})
        self.assertEqual(result["unresolved_symbol_count"], 2)
        self.assertIn("imports_by_binary", result)
        self.assertIn("link_context", result)

    def test_register_binary_symbol_inventory_creates_import_and_export_rows(self):
        session = MagicMock()
        strict = {
            "binaries": ["/tmp/libxml2.so"],
            "imports_by_binary": {"/tmp/libxml2.so": ["inflate"]},
            "dependencies": [
                {
                    "component": "zlib",
                    "provider_binaries": ["/tmp/libz.so"],
                    "provider_export_sample": ["inflate"],
                    "evidence": [{"binary": "/tmp/libxml2.so", "symbol": "inflate"}],
                }
            ],
        }
        stats = register_binary_symbol_inventory(session, "libxml2", strict)
        self.assertEqual(stats["binaries"], 1)
        self.assertEqual(stats["imports"], 1)
        self.assertGreaterEqual(stats["exports"], 1)
        self.assertGreaterEqual(session.run.call_count, 4)

    def test_resolve_external_c_calls_to_binary_symbols_emits_queries(self):
        session = MagicMock()
        strict = {
            "dependencies": [
                {
                    "component": "zlib",
                    "provider_binaries": ["/tmp/libz.so"],
                    "evidence": [{"binary": "/tmp/libxml2.so", "symbol": "inflate"}],
                }
            ]
        }
        edges = resolve_external_c_calls_to_binary_symbols(session, "libxml2", strict)
        self.assertEqual(edges, 1)
        self.assertEqual(session.run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
