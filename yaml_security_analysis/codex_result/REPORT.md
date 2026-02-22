# PyYAML Security Analysis (Local)

Scope: `pyyaml-main/lib` (Python implementation, optional C bindings)
Date: 2026-02-02

This report documents potential exploitation paths in this codebase when
parsing untrusted YAML. These are not necessarily newly discovered CVEs.
They are practical attack surfaces in the current implementation that
applications frequently misuse.

## Findings

### 1) Arbitrary code execution via UnsafeLoader / Loader

**Impact:** Remote code execution if an application parses untrusted YAML
using `yaml.unsafe_load`, `yaml.load(..., Loader=yaml.UnsafeLoader)`,
or `yaml.load(..., Loader=yaml.Loader)`.

**Why it happens:** `UnsafeConstructor` allows arbitrary module import and
`!!python/object/apply` / `!!python/object/new` tags. This lets a YAML
payload invoke any callable (e.g., `os.system`).

**Relevant code:**
- `lib/yaml/constructor.py` (UnsafeConstructor + `construct_python_object_apply`)
- `lib/yaml/loader.py` (UnsafeLoader / Loader)

**Proof of concept:** `security/pocs/poc_unsafe_loader_rce.py`

**Suggested fixes:**
- For consumers: never use `unsafe_load` / `UnsafeLoader` on untrusted input.
- For library hardening: consider gating unsafe tags behind explicit
  allowlists, or requiring a feature flag to enable `UnsafeLoader`.
- Provide a safe default in documentation and examples.

---

### 2) Callable injection via FullLoader and `!!python/name`

**Impact:** If an application assumes parsed data is inert and later calls
objects within it, an attacker can inject callables (e.g., `os.system`),
leading to arbitrary command execution in the application’s logic.

**Why it happens:** `FullLoader` supports `!!python/name` and returns live
Python objects from already-imported modules. This is not a direct RCE by
itself, but becomes exploitable when application code invokes the object
(e.g., `config["hook"](data)` or `callable_from_config()` patterns).

**Relevant code:**
- `lib/yaml/constructor.py` (`construct_python_name` and `find_python_name`)

**Proof of concept:** `security/pocs/poc_full_loader_callable_injection.py`

**Suggested fixes:**
- Use `safe_load` for untrusted input.
- If FullLoader is required, strip or reject `!!python/name` tags before
  parsing, or use a custom constructor that returns a harmless placeholder.

---

### 3) Denial of service via deep nesting (recursion exhaustion)

**Impact:** Untrusted YAML with extreme nesting can raise `RecursionError`
or cause excessive CPU usage during construction, resulting in a crash or
request timeouts.

**Why it happens:** There are no depth/complexity limits in the constructor.
The recursive construction of nodes can exceed Python’s recursion limit.

**Relevant code:**
- `lib/yaml/constructor.py` (`construct_object`, `construct_sequence`,
  `construct_mapping`)

**Proof of concept:** `security/pocs/poc_deep_nesting_dos.py`

**Suggested fixes:**
- Add a configurable maximum depth and/or a node count limit.
- For consumers, enforce size limits and timeouts before parsing.

---

## Notes

- These issues are inherent to common YAML deserialization patterns. The
  library provides safe APIs (`safe_load`), but application misuse is
  common, so the exposure is real.
- The PoCs are intentionally minimal and avoid harmful side effects.

