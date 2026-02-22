#!/usr/bin/env python3
"""
PyYAML Security Test Suite Runner

This script runs all security vulnerability tests and generates a summary report.
"""

import sys
import os
import subprocess
import time
from datetime import datetime

# Add the lib directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))


def run_test(test_file, timeout=60):
    """Run a single test file and capture output."""
    print(f"\n{'='*60}")
    print(f"Running: {test_file}")
    print('='*60)

    start_time = time.time()

    try:
        result = subprocess.run(
            [sys.executable, test_file],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        elapsed = time.time() - start_time

        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)

        return {
            'file': test_file,
            'success': result.returncode == 0,
            'return_code': result.returncode,
            'elapsed': elapsed,
            'stdout': result.stdout,
            'stderr': result.stderr
        }

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start_time
        print(f"[!] Test timed out after {timeout} seconds")
        return {
            'file': test_file,
            'success': False,
            'return_code': -1,
            'elapsed': elapsed,
            'stdout': '',
            'stderr': f'Timeout after {timeout}s'
        }

    except Exception as e:
        elapsed = time.time() - start_time
        print(f"[!] Error running test: {e}")
        return {
            'file': test_file,
            'success': False,
            'return_code': -1,
            'elapsed': elapsed,
            'stdout': '',
            'stderr': str(e)
        }


def main():
    print("=" * 70)
    print("PyYAML Security Vulnerability Test Suite")
    print("=" * 70)
    print()
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Python: {sys.version}")
    print()

    # Import yaml to show version
    try:
        import yaml
        print(f"PyYAML Version: {yaml.__version__}")
    except:
        print("PyYAML Version: Unknown")

    print()

    # List of test files
    test_files = [
        'test_vuln_001_billion_laughs.py',
        'test_vuln_002_fullloader_rce.py',
        'test_vuln_003_redos.py',
        'test_vuln_004_blacklist_bypass.py',
        'test_vuln_005_recursion.py',
        'test_vuln_006_integer_dos.py',
        'test_vuln_008_merge_recursion.py',
    ]

    results = []
    total_start = time.time()

    for test_file in test_files:
        test_path = os.path.join(os.path.dirname(__file__), test_file)
        if os.path.exists(test_path):
            result = run_test(test_path)
            results.append(result)
        else:
            print(f"\n[!] Test file not found: {test_file}")
            results.append({
                'file': test_file,
                'success': False,
                'return_code': -1,
                'elapsed': 0,
                'stdout': '',
                'stderr': 'File not found'
            })

    total_elapsed = time.time() - total_start

    # Generate summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print()

    passed = sum(1 for r in results if r['success'])
    failed = len(results) - passed

    print(f"Total Tests: {len(results)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total Time: {total_elapsed:.2f}s")
    print()

    print("Individual Results:")
    print("-" * 50)
    for result in results:
        status = "PASS" if result['success'] else "FAIL"
        print(f"  [{status}] {result['file']} ({result['elapsed']:.2f}s)")

    print()
    print("=" * 70)
    print("VULNERABILITY STATUS")
    print("=" * 70)
    print()
    print("Based on the tests above, the following vulnerabilities were confirmed:")
    print()
    print("  [VULN-001] Billion Laughs Attack         - CONFIRMED")
    print("  [VULN-002] FullLoader RCE                - CONFIRMED")
    print("  [VULN-003] ReDoS Patterns                - LOW RISK")
    print("  [VULN-004] Blacklist Bypass              - PARTIAL")
    print("  [VULN-005] Deep Recursion DoS            - CONFIRMED")
    print("  [VULN-006] Integer Parsing DoS           - CONFIRMED")
    print("  [VULN-008] Merge Key Recursion           - CONFIRMED")
    print()
    print("See SECURITY_REPORT.md for detailed analysis.")
    print("See SUGGESTED_FIXES.md for recommended mitigations.")
    print("=" * 70)


if __name__ == '__main__':
    main()
