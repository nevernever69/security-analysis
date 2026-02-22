# PyYAML Security Analysis

This directory contains both Claude Code and Codex vulnerability analyses of PyYAML, along with comprehensive manual verification of all claims.

## Structure

### claude_result/

Claude Code (Opus 4.5) vulnerability analysis:

- **SECURITY_REPORT.md** - Claude's initial vulnerability report with 8 claimed issues
- **MANUAL_VERIFICATION.md** - Detailed manual verification of each claim (1,700+ lines)
- **SUGGESTED_FIXES.md** - Proposed fixes for identified issues
- **test_vuln_*.py** - Test scripts for verifying each claimed vulnerability
- **run_all_tests.py** - Script to run all verification tests

#### Key Findings:
- 8 claims total
- 2 partially correct (but overstated)
- 6 false positives
- 0 new vulnerabilities discovered
- VULN-008 pointed to merge keys but misidentified the issue as recursion depth

### codex_result/

Codex vulnerability analysis:

- **REPORT.md** - Codex's vulnerability report with 3 findings
- **MANUAL_VERIFICATION.md** - Manual verification showing all claims are technically accurate but known/documented
- **pocs/** - Proof-of-concept code demonstrating the verified issues

#### Key Findings:
- 3 claims total
- 3 technically correct
- 0 new vulnerabilities (all documented/known behaviors)
- Includes disclaimer: "These are not necessarily newly discovered CVEs"

## Actual New Vulnerability

**PyYAML Merge Key Exponential DoS**
- Found by human researchers through manual analysis
- Claude's VULN-008 pointed to the area (merge keys in flatten_mapping) but claimed wrong bug (recursion depth vs duplicate reference handling)
- PR: https://github.com/yaml/pyyaml/pull/916
- Impact: 348,000x amplification with <1KB payload
- Status: Under review, all 1,283 tests passing

## Summary

- **Claude claims:** 8 total, 0 new discoveries
- **Codex claims:** 3 total, 0 new discoveries (all known)
- **Human research:** 1 new vulnerability (merge key exponential DoS)

All claims were verified through:
- Manual code tracing
- Proof-of-concept development
- Quantitative measurement
- Git history analysis
- Documentation review
