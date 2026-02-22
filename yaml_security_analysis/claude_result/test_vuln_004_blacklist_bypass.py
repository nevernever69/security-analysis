#!/usr/bin/env python3
"""
VULN-004: State Key Blacklist Bypass via Unicode
Severity: MEDIUM
Type: Security Bypass

This vulnerability demonstrates potential bypasses of the state key
blacklist in FullConstructor through Unicode normalization tricks.
"""

import sys
import os

# Add the lib directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

import yaml
import re


def test_blacklist_analysis():
    """
    Analyze the state key blacklist regex.
    """

    print("=" * 60)
    print("VULN-004: State Key Blacklist Analysis")
    print("=" * 60)
    print()

    from yaml.constructor import FullConstructor

    # Get the blacklist patterns
    fc = FullConstructor()
    blacklist = fc.get_state_keys_blacklist()
    print("Current blacklist patterns:")
    for pattern in blacklist:
        print(f"  - {pattern}")
    print()

    # Compile the full regex
    full_pattern = '(' + '|'.join(blacklist) + ')'
    regex = re.compile(full_pattern)
    print(f"Combined regex: {full_pattern}")
    print()

    # Test various keys
    test_keys = [
        # Should be blocked
        ("extend", True, "should be blocked"),
        ("__init__", True, "should be blocked"),
        ("__reduce__", True, "should be blocked"),
        ("__setstate__", True, "should be blocked"),

        # Should be allowed
        ("normal_key", False, "should be allowed"),
        ("_private", False, "should be allowed"),
        ("__not_dunder", False, "single underscore prefix"),

        # Edge cases
        ("extend_", False, "extend with suffix"),
        ("_extend", False, "extend with prefix"),
        ("EXTEND", False, "uppercase extend"),
        ("__INIT__", True, "uppercase dunder"),

        # Unicode variations
        ("_\u005f_init__", False, "Unicode underscore"),
        ("extend\u200b", False, "Zero-width space"),
        ("\u005fextend", False, "Underscore via unicode"),
    ]

    print("Testing keys against blacklist:")
    print("-" * 50)

    for key, should_block, description in test_keys:
        match = regex.match(key)
        is_blocked = bool(match)
        status = "BLOCKED" if is_blocked else "ALLOWED"
        expected = "BLOCKED" if should_block else "ALLOWED"
        result = "OK" if status == expected else "UNEXPECTED!"

        print(f"  {repr(key):25} -> {status:8} ({expected:8}) [{result}]")
        print(f"    {description}")

    print()


def test_unicode_confusables():
    """
    Test Unicode confusable characters for blacklist bypass.
    """

    print("-" * 60)
    print("Unicode Confusable Characters Test")
    print("-" * 60)
    print()

    # Unicode characters that look like ASCII underscore
    underscore_lookalikes = [
        ('\u005f', 'ASCII underscore'),        # Normal underscore
        ('\u0332', 'Combining low line'),      # Combining character
        ('\u0320', 'Combining minus below'),
        ('\u2013', 'En dash'),
        ('\u2014', 'Em dash'),
        ('\u2017', 'Double low line'),
        ('\u203e', 'Overline'),
        ('\uff3f', 'Fullwidth underscore'),    # This one looks identical!
        ('\ufe4d', 'Dashed low line'),
        ('\ufe4e', 'Centerline low line'),
        ('\ufe4f', 'Wavy low line'),
    ]

    from yaml.constructor import FullConstructor
    fc = FullConstructor()

    print("Testing underscore lookalikes:")
    print("-" * 50)

    for char, name in underscore_lookalikes:
        # Try to construct a dunder-like name
        test_key = char + char + "init" + char + char

        try:
            fc.check_state_key(test_key)
            status = "ALLOWED"
        except yaml.constructor.ConstructorError:
            status = "BLOCKED"

        print(f"  {name:25} (U+{ord(char):04X}): {status}")
        print(f"    Test key: {repr(test_key)}")

    print()


def test_nfkc_normalization():
    """
    Test if Python's NFKC normalization creates bypasses.
    """

    print("-" * 60)
    print("NFKC Normalization Test")
    print("-" * 60)
    print()

    import unicodedata

    # Characters that normalize to underscore under NFKC
    normalizable_chars = [
        ('\uff3f', 'Fullwidth underscore'),  # ＿ -> _
    ]

    print("Characters that normalize to underscore under NFKC:")
    for char, name in normalizable_chars:
        normalized = unicodedata.normalize('NFKC', char)
        print(f"  {name}: U+{ord(char):04X} -> U+{ord(normalized):04X} ({repr(normalized)})")

    print()
    print("Testing if FullLoader accepts normalized keys:")
    print("-" * 50)

    # Try fullwidth underscore dunder
    fullwidth_dunder = '\uff3f\uff3finit\uff3f\uff3f'  # ＿＿init＿＿

    # First, what does Python see this as?
    normalized = unicodedata.normalize('NFKC', fullwidth_dunder)
    print(f"  Original: {repr(fullwidth_dunder)}")
    print(f"  NFKC: {repr(normalized)}")

    # Does YAML accept it?
    from yaml.constructor import FullConstructor
    fc = FullConstructor()

    try:
        fc.check_state_key(fullwidth_dunder)
        print(f"  FullConstructor: ALLOWED (potential bypass!)")
    except yaml.constructor.ConstructorError:
        print(f"  FullConstructor: BLOCKED")

    print()


def test_extend_bypass_attempts():
    """
    Test various ways to bypass 'extend' blacklist.
    """

    print("-" * 60)
    print("'extend' Blacklist Bypass Attempts")
    print("-" * 60)
    print()

    from yaml.constructor import FullConstructor
    fc = FullConstructor()

    bypass_attempts = [
        "extend",
        "Extend",
        "EXTEND",
        "extend ",      # Trailing space
        " extend",      # Leading space
        "extend\t",     # Trailing tab
        "extend\x00",   # Null byte
        "extend\u200b", # Zero-width space
        "ext\u200bend", # Zero-width in middle
        "ｅｘｔｅｎｄ",   # Fullwidth ASCII
        "еxtend",       # Cyrillic 'е' instead of ASCII 'e'
    ]

    for key in bypass_attempts:
        try:
            fc.check_state_key(key)
            print(f"  {repr(key):30} -> ALLOWED (BYPASS!)")
        except yaml.constructor.ConstructorError:
            print(f"  {repr(key):30} -> BLOCKED")

    print()


def test_actual_exploitation():
    """
    Test if bypass would allow actual exploitation.
    """

    print("-" * 60)
    print("Actual Exploitation Test")
    print("-" * 60)
    print()

    # Even if we can bypass the blacklist, we need to see if
    # Python actually treats these as the same attribute

    class TestClass:
        def __init__(self):
            self.data = []

        def extend(self, items):
            print(f"  extend() called with {items}")
            self.data.extend(items)

    # Test if Python's getattr treats these as equivalent
    obj = TestClass()

    test_attrs = [
        "extend",
        "Extend",
        "EXTEND",
    ]

    print("Testing attribute access with different casings:")
    for attr in test_attrs:
        try:
            method = getattr(obj, attr)
            print(f"  getattr(obj, {repr(attr)}): SUCCESS")
        except AttributeError:
            print(f"  getattr(obj, {repr(attr)}): AttributeError")

    print()
    print("Note: Python attributes are case-sensitive, so")
    print("uppercase bypasses won't access the actual method.")
    print()
    print("However, the blacklist still has weaknesses:")
    print("  - Unicode normalization in future Python versions")
    print("  - Whitespace variations might slip through")
    print("  - Custom __getattr__ implementations")
    print()


if __name__ == '__main__':
    print("PyYAML State Key Blacklist Bypass Test Suite")
    print("=" * 60)
    print()
    print("This test suite analyzes potential bypasses of")
    print("FullConstructor's state key blacklist.")
    print()

    test_blacklist_analysis()
    test_unicode_confusables()
    test_nfkc_normalization()
    test_extend_bypass_attempts()
    test_actual_exploitation()

    print("=" * 60)
    print("CONCLUSION")
    print("=" * 60)
    print()
    print("The current blacklist has some limitations:")
    print()
    print("1. Case sensitivity - only blocks lowercase 'extend'")
    print("2. No Unicode normalization handling")
    print("3. Fullwidth characters are not blocked")
    print()
    print("While direct exploitation is limited due to Python's")
    print("attribute lookup rules, these gaps represent defense")
    print("in depth failures.")
    print()
    print("RECOMMENDATIONS:")
    print("  - Use a whitelist instead of blacklist approach")
    print("  - Normalize keys before checking (NFKC)")
    print("  - Consider case-insensitive matching for 'extend'")
    print("=" * 60)
