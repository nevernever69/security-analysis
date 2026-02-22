# PyYAML Security Analysis

This directory contains a comprehensive security analysis of the PyYAML library, including zero-day vulnerability discoveries, proof-of-concept exploits, and suggested fixes.

## Quick Start

```bash
# Run all vulnerability tests
python3 run_all_tests.py

# Run individual tests
python3 test_vuln_001_billion_laughs.py
python3 test_vuln_002_fullloader_rce.py
# ... etc
```

## Discovered Vulnerabilities

| ID | Vulnerability | Severity | Impact |
|----|--------------|----------|--------|
| VULN-001 | Billion Laughs (Alias Expansion) | HIGH | Memory exhaustion DoS |
| VULN-002 | FullLoader RCE via Builtins | CRITICAL | Remote code execution |
| VULN-003 | ReDoS in Type Resolvers | MEDIUM | CPU exhaustion DoS |
| VULN-004 | State Key Blacklist Bypass | MEDIUM | Security bypass |
| VULN-005 | Deep Recursion DoS | HIGH | Stack overflow crash |
| VULN-006 | Integer Parsing DoS | MEDIUM | Memory/CPU exhaustion |
| VULN-008 | Merge Key Recursion | HIGH | Stack overflow crash |

## Files

- `SECURITY_REPORT.md` - Detailed vulnerability analysis
- `SUGGESTED_FIXES.md` - Code patches and recommendations
- `run_all_tests.py` - Test suite runner
- `test_vuln_*.py` - Individual vulnerability tests

## Key Findings

### 1. FullLoader is NOT Safe (VULN-002)

Despite documentation suggesting FullLoader is "safer" than UnsafeLoader, it provides direct access to dangerous Python builtins:

```python
import yaml

# This returns Python's open() function!
payload = "!!python/name:builtins.open"
open_func = yaml.load(payload, Loader=yaml.FullLoader)
# Attacker can now read/write files: open_func('/etc/passwd').read()

# This returns __import__!
payload = "!!python/name:builtins.__import__"
import_func = yaml.load(payload, Loader=yaml.FullLoader)
# Attacker can import any module: import_func('os').system('whoami')
```

**Recommendation:** ALWAYS use `yaml.safe_load()` for untrusted input.

### 2. Billion Laughs Attack (VULN-001)

YAML's alias feature allows exponential memory consumption:

```yaml
a: &a "AAAAAAAAAA"
b: &b [*a, *a]
c: &c [*b, *b]
d: &d [*c, *c]
# ... continuing creates 2^n copies
```

14 levels = 163,840 copies of the base string from ~200 bytes of input.

### 3. No Depth Limits (VULN-005)

PyYAML has no built-in protection against deeply nested structures:

```python
# This will crash with RecursionError
payload = "[" * 1000 + "]" * 1000
yaml.safe_load(payload)  # Crash!
```

### 4. Sexagesimal Integer Explosion (VULN-006)

YAML 1.1's base-60 notation creates massive numbers:

```yaml
num: 59:59:59:59:59  # Creates 777,599,999 from 14 characters!
```

## Recommendations

1. **Use SafeLoader exclusively** for any untrusted input
2. **Implement input size limits** before parsing
3. **Apply depth limits** to prevent recursion attacks
4. **Consider disabling features** like merge keys for untrusted input
5. **Monitor memory usage** when parsing large documents

## Running Tests

Requirements:
- Python 3.8+
- PyYAML (from this repository)

```bash
cd /path/to/pyyaml
export PYTHONPATH=lib:$PYTHONPATH
cd security_analysis
python3 run_all_tests.py
```

## Disclosure

These vulnerabilities should be reported to the PyYAML maintainers through proper security disclosure channels. See `.github/SECURITY.md` in the main repository for the security policy.

## License

This security analysis is provided for educational and defensive purposes only.
