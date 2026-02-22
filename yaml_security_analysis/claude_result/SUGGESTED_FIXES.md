# PyYAML Security Fixes

This document provides suggested fixes for the vulnerabilities identified in the security analysis.

---

## VULN-001 Fix: Billion Laughs Protection

### Problem
YAML aliases allow exponential memory expansion similar to XML's Billion Laughs attack.

### Suggested Fix
Add alias expansion tracking and limits to the constructor.

```python
# In constructor.py, modify BaseConstructor.__init__:

class BaseConstructor:
    # Add class-level configuration
    MAX_ALIAS_EXPANSIONS = 1000  # Limit total alias expansions
    MAX_ALIAS_DEPTH = 100        # Limit alias nesting depth

    def __init__(self):
        self.constructed_objects = {}
        self.recursive_objects = {}
        self.state_generators = []
        self.deep_construct = False
        # NEW: Alias tracking
        self.alias_expansion_count = 0
        self.alias_depth = 0

    def construct_object(self, node, deep=False):
        # NEW: Check alias limits
        if node in self.constructed_objects:
            self.alias_expansion_count += 1
            if self.alias_expansion_count > self.MAX_ALIAS_EXPANSIONS:
                raise ConstructorError(None, None,
                    f"too many alias expansions (limit: {self.MAX_ALIAS_EXPANSIONS})",
                    node.start_mark)
            return self.constructed_objects[node]

        # ... rest of existing code ...
```

### Alternative: Composer-Level Protection

```python
# In composer.py, modify Composer.compose_node:

class Composer:
    MAX_ANCHOR_REFERENCES = 100  # Limit references per anchor

    def __init__(self):
        self.anchors = {}
        self.anchor_reference_counts = {}  # NEW

    def compose_node(self, parent, index):
        if self.check_event(AliasEvent):
            event = self.get_event()
            anchor = event.anchor
            if anchor not in self.anchors:
                raise ComposerError(None, None,
                    "found undefined alias %r" % anchor, event.start_mark)

            # NEW: Track and limit alias references
            self.anchor_reference_counts[anchor] = \
                self.anchor_reference_counts.get(anchor, 0) + 1
            if self.anchor_reference_counts[anchor] > self.MAX_ANCHOR_REFERENCES:
                raise ComposerError(None, None,
                    f"anchor '{anchor}' referenced too many times "
                    f"(limit: {self.MAX_ANCHOR_REFERENCES})",
                    event.start_mark)

            return self.anchors[anchor]
        # ... rest of existing code ...
```

---

## VULN-002 Fix: FullLoader Security Hardening

### Problem
FullLoader provides access to dangerous builtins like `open`, `__import__`, and `getattr`.

### Suggested Fix 1: Remove Dangerous Names from builtins Access

```python
# In constructor.py, modify FullConstructor.find_python_name:

class FullConstructor(SafeConstructor):
    # Blocklist of dangerous names even in pre-imported modules
    DANGEROUS_BUILTINS = frozenset([
        'eval', 'exec', 'compile', 'open', '__import__',
        'getattr', 'setattr', 'delattr', 'globals', 'locals',
        'vars', 'dir', 'type', 'object', 'staticmethod',
        'classmethod', 'property', 'super', 'memoryview',
        'input', 'breakpoint', 'help', 'license', 'credits',
    ])

    DANGEROUS_MODULES = frozenset([
        'os', 'sys', 'subprocess', 'socket', 'ctypes',
        'importlib', 'pickle', 'marshal', 'code', 'codeop',
        'pty', 'fcntl', 'resource', 'syslog', 'posix',
    ])

    def find_python_name(self, name, mark, unsafe=False):
        if not name:
            raise ConstructorError(...)

        if '.' in name:
            module_name, object_name = name.rsplit('.', 1)
        else:
            module_name = 'builtins'
            object_name = name

        # NEW: Block dangerous modules entirely
        if module_name in self.DANGEROUS_MODULES and not unsafe:
            raise ConstructorError("while constructing a Python object", mark,
                f"access to module '{module_name}' is not allowed", mark)

        # NEW: Block dangerous builtins
        if module_name == 'builtins' and object_name in self.DANGEROUS_BUILTINS:
            raise ConstructorError("while constructing a Python object", mark,
                f"access to 'builtins.{object_name}' is not allowed", mark)

        # ... rest of existing code ...
```

### Suggested Fix 2: Whitelist Approach (Safer)

```python
# In constructor.py, add whitelist-based FullConstructor:

class FullConstructor(SafeConstructor):
    # Only allow access to these specific types/names
    ALLOWED_NAMES = frozenset([
        # Standard types
        'builtins.int', 'builtins.float', 'builtins.str',
        'builtins.bool', 'builtins.list', 'builtins.dict',
        'builtins.tuple', 'builtins.set', 'builtins.frozenset',
        'builtins.bytes', 'builtins.bytearray',

        # Collections
        'collections.OrderedDict', 'collections.defaultdict',
        'collections.Counter', 'collections.deque',

        # Datetime
        'datetime.date', 'datetime.time', 'datetime.datetime',
        'datetime.timedelta', 'datetime.timezone',
    ])

    def find_python_name(self, name, mark, unsafe=False):
        if unsafe:
            return super().find_python_name(name, mark, unsafe=True)

        # Normalize the name
        if '.' not in name:
            full_name = f'builtins.{name}'
        else:
            full_name = name

        if full_name not in self.ALLOWED_NAMES:
            raise ConstructorError("while constructing a Python object", mark,
                f"access to '{full_name}' is not allowed in safe mode", mark)

        return super().find_python_name(name, mark, unsafe=False)
```

---

## VULN-003 Fix: ReDoS Prevention

### Problem
Complex regex patterns may be vulnerable to catastrophic backtracking.

### Suggested Fix
Add input length limits before regex matching.

```python
# In resolver.py, modify Resolver.resolve:

class Resolver(BaseResolver):
    MAX_SCALAR_LENGTH = 4096  # Limit scalar length for implicit typing

    def resolve(self, kind, value, implicit):
        if kind is ScalarNode and implicit[0]:
            # NEW: Skip implicit typing for very long scalars
            if len(value) > self.MAX_SCALAR_LENGTH:
                return self.DEFAULT_SCALAR_TAG

            # ... existing resolution code ...
```

---

## VULN-005 Fix: Recursion Depth Limits

### Problem
Deeply nested YAML can cause stack overflow.

### Suggested Fix
Add depth tracking and limits.

```python
# In composer.py:

class Composer:
    MAX_NESTING_DEPTH = 100  # Configurable limit

    def __init__(self):
        self.anchors = {}
        self.depth = 0  # NEW

    def compose_node(self, parent, index):
        # NEW: Check depth
        self.depth += 1
        if self.depth > self.MAX_NESTING_DEPTH:
            raise ComposerError(None, None,
                f"document exceeds maximum nesting depth ({self.MAX_NESTING_DEPTH})",
                None)

        try:
            # ... existing node composition code ...
            return node
        finally:
            self.depth -= 1  # NEW: Decrement on exit
```

---

## VULN-006 Fix: Integer Size Limits

### Problem
Extremely large integers or sexagesimal notation can exhaust resources.

### Suggested Fix
Add size limits to integer construction.

```python
# In constructor.py:

class SafeConstructor(BaseConstructor):
    MAX_INT_LENGTH = 1000      # Max digits
    MAX_SEXAGESIMAL_SEGMENTS = 10  # Max base-60 segments

    def construct_yaml_int(self, node):
        value = self.construct_scalar(node)
        value = value.replace('_', '')

        # NEW: Check length limits
        if len(value) > self.MAX_INT_LENGTH:
            raise ConstructorError(None, None,
                f"integer value too long ({len(value)} digits, max: {self.MAX_INT_LENGTH})",
                node.start_mark)

        # ... existing parsing code ...

        # Handle sexagesimal
        if ':' in value:
            parts = value.split(':')
            # NEW: Limit segments
            if len(parts) > self.MAX_SEXAGESIMAL_SEGMENTS:
                raise ConstructorError(None, None,
                    f"too many sexagesimal segments ({len(parts)}, max: {self.MAX_SEXAGESIMAL_SEGMENTS})",
                    node.start_mark)

            digits = [int(part) for part in parts]
            # ... existing calculation ...
```

---

## VULN-008 Fix: Merge Key Depth Limits

### Problem
Nested merge keys can cause recursion issues.

### Suggested Fix
Add depth tracking to flatten_mapping.

```python
# In constructor.py:

class SafeConstructor(BaseConstructor):
    MAX_MERGE_DEPTH = 50  # Limit merge recursion

    def flatten_mapping(self, node, depth=0):  # NEW: depth parameter
        # NEW: Check depth limit
        if depth > self.MAX_MERGE_DEPTH:
            raise ConstructorError("while constructing a mapping", node.start_mark,
                f"merge key recursion too deep (limit: {self.MAX_MERGE_DEPTH})",
                node.start_mark)

        merge = []
        index = 0
        while index < len(node.value):
            key_node, value_node = node.value[index]
            if key_node.tag == 'tag:yaml.org,2002:merge':
                del node.value[index]
                if isinstance(value_node, MappingNode):
                    self.flatten_mapping(value_node, depth + 1)  # NEW: increment depth
                    merge.extend(value_node.value)
                elif isinstance(value_node, SequenceNode):
                    submerge = []
                    for subnode in value_node.value:
                        if not isinstance(subnode, MappingNode):
                            raise ConstructorError(...)
                        self.flatten_mapping(subnode, depth + 1)  # NEW: increment depth
                        submerge.append(subnode.value)
                    # ... rest of existing code ...
```

---

## Global Configuration Object

Create a unified configuration for all security limits:

```python
# New file: yaml/config.py

class YAMLConfig:
    """Security and performance configuration for YAML parsing."""

    def __init__(self):
        # Alias/Reference limits
        self.max_alias_expansions = 1000
        self.max_alias_depth = 100
        self.max_anchor_references = 100

        # Nesting limits
        self.max_nesting_depth = 100
        self.max_merge_depth = 50

        # Size limits
        self.max_scalar_length = 1024 * 1024  # 1MB
        self.max_int_digits = 1000
        self.max_sexagesimal_segments = 10

        # Collection limits
        self.max_sequence_length = 100000
        self.max_mapping_size = 100000

        # String limits
        self.max_key_length = 1024

    @classmethod
    def strict(cls):
        """Return a strict configuration for untrusted input."""
        config = cls()
        config.max_alias_expansions = 100
        config.max_nesting_depth = 20
        config.max_scalar_length = 65536
        config.max_int_digits = 100
        config.max_sequence_length = 10000
        config.max_mapping_size = 1000
        return config

    @classmethod
    def relaxed(cls):
        """Return a relaxed configuration for trusted input."""
        config = cls()
        config.max_alias_expansions = 10000
        config.max_nesting_depth = 1000
        config.max_scalar_length = 100 * 1024 * 1024
        config.max_int_digits = 10000
        return config


# Default configuration
DEFAULT_CONFIG = YAMLConfig()
STRICT_CONFIG = YAMLConfig.strict()


# Usage:
# yaml.safe_load(data, config=yaml.STRICT_CONFIG)
```

---

## Summary of Fixes

| Vulnerability | Fix Type | Complexity | Breaking Changes |
|--------------|----------|------------|------------------|
| VULN-001 | Alias limits | Medium | None if limits are high enough |
| VULN-002 | Name whitelist/blocklist | High | May break existing code |
| VULN-003 | Length limits | Low | None |
| VULN-005 | Depth limits | Medium | None if limits are reasonable |
| VULN-006 | Integer limits | Low | May affect edge cases |
| VULN-008 | Merge depth limit | Low | None |

---

## Testing Recommendations

After implementing fixes:

1. Run existing test suite to ensure no regressions
2. Add security-specific test cases from this analysis
3. Fuzz test with AFL or similar tools
4. Perform memory profiling with large/complex inputs
5. Document new limits in user-facing documentation
6. Consider adding a "strict mode" for security-conscious users
