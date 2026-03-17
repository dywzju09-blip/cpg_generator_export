import unittest
import json
import os
import tempfile

from tools.ffi_semantics.binding import bind_call_summaries
from tools.ffi_semantics.generate_param_semantics import (
    generate_candidate_summaries_from_c_header,
    generate_candidate_summaries_from_rust_ffi,
    upsert_component_entry,
)
from tools.ffi_semantics.registry import (
    discover_project_components,
    load_component_summaries,
    resolve_component_summary,
)


class RegistryTests(unittest.TestCase):
    def test_registry_resolves_zlib_component_summary(self):
        summary = resolve_component_summary("inflateGetHeader", component_name="zlib", component_version="1.2.12")
        self.assertIsNotNone(summary)
        self.assertEqual(summary["component_name"], "zlib")
        self.assertEqual(summary["params"]["2"]["pointee_type"], "gz_header")

    def test_generate_candidate_summaries_from_rust_ffi(self):
        src = """
        #[repr(C)]
        struct gz_header {
            extra: *mut u8,
            extra_len: c_uint,
            extra_max: c_uint,
        }

        extern "C" {
            fn inflateGetHeader(strm: *mut z_stream, head: *mut gz_header) -> c_int;
        }
        """
        summaries = generate_candidate_summaries_from_rust_ffi(src)
        self.assertIn("inflateGetHeader", summaries)
        param2 = summaries["inflateGetHeader"]["params"]["2"]
        self.assertEqual(param2["abi_kind"], "mut_ptr")
        self.assertEqual(param2["pointee_type"], "gz_header")
        self.assertIn("extra_max", param2["fields"])

    def test_generate_candidate_summaries_from_c_header(self):
        src = """
        typedef unsigned int uInt;
        typedef unsigned char Bytef;

        typedef struct gz_header_s {
            Bytef *extra;
            uInt extra_len;
            uInt extra_max;
            int done;
        } gz_header;

        typedef gz_header *gz_headerp;
        typedef struct z_stream_s *z_streamp;

        int inflateGetHeader(z_streamp strm, gz_headerp head);
        """
        summaries = generate_candidate_summaries_from_c_header(src)
        self.assertIn("inflateGetHeader", summaries)
        param2 = summaries["inflateGetHeader"]["params"]["2"]
        self.assertEqual(param2["abi_kind"], "mut_ptr")
        self.assertEqual(param2["pointee_type"], "gz_header")
        self.assertIn("extra_max", param2["fields"])
        self.assertEqual(param2["fields"]["extra"]["declared_type"], "Bytef*")

    def test_bind_c_header_and_rust_ffi_summary(self):
        c_src = """
        typedef unsigned int uInt;
        typedef unsigned char Bytef;

        typedef struct gz_header_s {
            Bytef *extra;
            uInt extra_len;
            uInt extra_max;
            int done;
        } gz_header;

        typedef gz_header *gz_headerp;
        typedef struct z_stream_s *z_streamp;

        int inflateGetHeader(z_streamp strm, gz_headerp head);
        """
        rust_src = """
        #[repr(C)]
        struct gz_header {
            extra: *mut u8,
            extra_len: c_uint,
            extra_max: c_uint,
            done: c_int,
        }

        extern "C" {
            fn inflateGetHeader(strm: *mut z_stream, head: *mut gz_header) -> c_int;
        }
        """
        c_summary = generate_candidate_summaries_from_c_header(c_src)["inflateGetHeader"]
        rust_summary = generate_candidate_summaries_from_rust_ffi(rust_src)["inflateGetHeader"]
        bound = bind_call_summaries(c_summary, rust_summary)
        self.assertEqual(bound["summary_source"], "bound_c_header_and_rust_ffi")
        self.assertEqual(bound["binding_sources"], ["c", "rust"])
        param2 = bound["params"]["2"]
        self.assertEqual(param2["native_declared_type"], "gz_headerp")
        self.assertEqual(param2["rust_declared_type"], "*mut gz_header")
        self.assertEqual(param2["pointee_type"], "gz_header")
        self.assertIn("extra_max", param2["fields"])

    def test_upsert_component_entry_auto_binds_c_and_rust(self):
        registry = {"schema_version": 1, "components": []}
        c_entry = {
            "name": "zlib",
            "version": "1.2.12",
            "summaries": {
                "inflateGetHeader": {
                    "lang": "C",
                    "summary_source": "generated_from_c_header",
                    "params": {
                        "2": {
                            "role": "head",
                            "declared_type": "gz_headerp",
                            "abi_kind": "mut_ptr",
                            "type": "gz_headerp",
                            "pointee_type": "gz_header",
                        }
                    },
                }
            },
        }
        rust_entry = {
            "name": "zlib",
            "version": "1.2.12",
            "summaries": {
                "inflateGetHeader": {
                    "lang": "Rust",
                    "summary_source": "generated_from_rust_ffi",
                    "params": {
                        "2": {
                            "role": "head",
                            "declared_type": "*mut gz_header",
                            "arg_shape": "rust_mut_ref_or_c_mut_ptr",
                            "abi_kind": "mut_ptr",
                            "type": "*mut gz_header",
                            "pointee_type": "gz_header",
                        }
                    },
                }
            },
        }
        registry = upsert_component_entry(registry, c_entry)
        registry = upsert_component_entry(registry, rust_entry)
        summary = registry["components"][0]["summaries"]["inflateGetHeader"]
        self.assertEqual(summary["summary_source"], "bound_c_header_and_rust_ffi")
        self.assertEqual(summary["params"]["2"]["rust_declared_type"], "*mut gz_header")
        self.assertEqual(summary["params"]["2"]["native_declared_type"], "gz_headerp")

    def test_discover_project_components_with_dep_and_symbols(self):
        discovered = discover_project_components(
            deps={
                "packages": [
                    {"name": "cve-2022-37434-libz-sys-harness", "version": "0.1.0"},
                    {"name": "libz-sys", "version": "1.1.8"},
                ],
                "depends": [{"from": "cve-2022-37434-libz-sys-harness", "to": "libz-sys"}],
            },
            calls=[{"name": "inflateGetHeader"}, {"name": "inflate"}],
        )
        self.assertTrue(discovered)
        self.assertEqual(discovered[0]["name"], "zlib")
        self.assertGreater(discovered[0]["score"], 0)

    def test_call_alias_resolves_to_canonical_summary(self):
        summary = resolve_component_summary(
            call_name="z_inflateGetHeader",
            component_name="libz-sys",
            component_version="1.2.12",
        )
        self.assertIsNotNone(summary)
        self.assertEqual(summary["alias_of"], "inflateGetHeader")
        self.assertEqual(summary["component_name"], "zlib")

    def test_internal_binding_propagates_summary_to_wrapper(self):
        registry = {
            "schema_version": 1,
            "components": [
                {
                    "name": "demo",
                    "version": "1.0.0",
                    "internal_bindings": [
                        {
                            "id": "wrap_to_core",
                            "entry_call": "wrapper_call",
                            "bind_call": "core_call",
                            "param_map": {"1": "1"},
                            "allow_create_entry": True,
                        }
                    ],
                    "summaries": {
                        "core_call": {
                            "lang": "C",
                            "summary_source": "generated_from_c_header",
                            "params": {
                                "1": {
                                    "role": "ctx",
                                    "abi_kind": "mut_ptr",
                                    "type": "ctx_t*",
                                    "pointee_type": "ctx_t",
                                    "fields": {
                                        "len": {"kind": "len", "state": "post"},
                                    },
                                }
                            },
                        }
                    },
                }
            ],
        }
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as handle:
            json.dump(registry, handle)
            tmp_registry = handle.name
        try:
            summaries = load_component_summaries(
                component_name="demo",
                component_version="1.0.0",
                registry_path=tmp_registry,
            )
        finally:
            os.unlink(tmp_registry)
        self.assertIn("wrapper_call", summaries)
        self.assertIn("len", summaries["wrapper_call"]["params"]["1"]["fields"])
        self.assertEqual(summaries["wrapper_call"]["summary_source"], "component_internal_binding")


if __name__ == "__main__":
    unittest.main()
