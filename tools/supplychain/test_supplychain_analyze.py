import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
from unittest.mock import patch

from tools.supplychain.supplychain_analyze import (
    analyze_triggerability,
    collect_source_synthetic_sink_calls,
    _match_call_name,
    _SYSTEM_NATIVE_VERSION_CACHE,
    apply_sink_knowledge,
    collect_rust_sink_candidates,
    collect_assumption_evidence,
    eval_condition,
    evaluate_env_guards,
    evaluate_input_predicate,
    has_actionable_trigger_hits,
    map_result_kind,
    merge_evidence_calls,
    normalize_vuln_rule,
    resolve_native_component_instances,
    synthesize_sink_calls_from_method_code,
    summarize_guard_status,
)
from tools.fetch.native_source_resolver import (
    choose_c_analysis_scope,
    ensure_native_source_tree,
    find_local_native_source_tree,
    find_symbol_source_files,
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

    def test_auto_vuln_inputs_support_openh264_freetype_and_zlib(self):
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
        self.assertTrue(can_auto_generate(openh264_item))
        self.assertTrue(can_auto_generate(freetype_item))
        self.assertTrue(can_auto_generate(zlib_item))
        openh264_rule = generate_vulns_payload(openh264_item)[0]
        freetype_rule = generate_vulns_payload(freetype_item)[0]
        zlib_rule = generate_vulns_payload(zlib_item)[0]
        self.assertEqual(openh264_rule["package"], "openh264-sys2")
        self.assertEqual(openh264_rule["symbols"], ["WelsDecodeBs"])
        self.assertEqual(freetype_rule["package"], "freetype")
        self.assertEqual(freetype_rule["version_range"], "<2.13.1")
        self.assertIn("FT_Load_Glyph", freetype_rule["symbols"])
        self.assertEqual(zlib_rule["package"], "zlib")
        self.assertEqual(zlib_rule["version_range"], "<1.2.13")
        self.assertIn("inflateGetHeader", zlib_rule["symbols"])

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


if __name__ == "__main__":
    unittest.main()
