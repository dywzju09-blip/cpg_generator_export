# Indirect Dependency PoC (libxml2 XXE)

This example demonstrates a real XXE vulnerability in **libxml2 < 2.9.4**
triggered through an indirect C dependency chain:

Rust -> component_a -> component_b -> libxml2 (.so)

Files:
- `component_a.c`: wrapper around component_b
- `component_b.c`: calls libxml2 `xmlReadMemory` with external entity expansion

The PoC input uses a local file to demonstrate external entity expansion.
