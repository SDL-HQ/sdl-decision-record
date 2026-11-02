"""Build the OPA example's three policy objects from the Cedar example's store and calls.

    python3 examples/opa/build_inputs.py

The forty calls are examples/cedar/inputs-toolcalls.jsonl, unchanged (same
input shape, same labels). The store is the Cedar example's STORE entities,
re-keyed as data.entities[type][id] -> attrs. Three policy objects:
policy-caller.json, policy-store.json, policy-canonical.json, differing only
in `entities` and `canonicalise`, as the Cedar example's do.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location("cedar_build_inputs", HERE.parent / "cedar" / "build_inputs.py")
cedar_inputs = importlib.util.module_from_spec(_spec)  # the same store, the same calls
_spec.loader.exec_module(cedar_inputs)

BUILTINS = ["contains", "count", "eq", "equal", "gt", "gte", "internal.member_2", "lt", "lte", "neq", "startswith"]


def store() -> dict:
    out: dict = {}
    for e in cedar_inputs.STORE:
        out.setdefault(e["uid"]["type"], {})[e["uid"]["id"]] = e["attrs"]
    return {"entities": out}


def policy(entities: str, canonicalise: str) -> dict:
    return {"engine": "opa", "rego_version": 1, "bundle": {"policies.rego": (HERE / "policies.rego").read_text()}, "data": store(),
            "query": "data.agentic.decision", "builtins": BUILTINS, "strict_builtin_errors": False, "canonicalise": canonicalise, "entities": entities}


def main() -> int:
    for name, ent, canon in (("caller", "caller", "none"), ("store", "store", "none"), ("canonical", "store", "url-v1")):
        (HERE / f"policy-{name}.json").write_text(json.dumps(policy(ent, canon), indent=1, sort_keys=True) + "\n")
    print("wrote policy-caller.json, policy-store.json, policy-canonical.json; inputs are examples/cedar/inputs-toolcalls.jsonl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
