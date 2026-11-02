"""cedar_conformance: Cedar's own conformance corpus as a decision record.

Input: {"test": <path of a test file inside the corpus>, "request": <index>}
Policy: {"corpus": "cedar-integration-tests", "root": <directory>, "files": {<relative path>: "sha256:..."}}

The policy is the corpus: every file a test reads (policies, schema, entities)
is digested into the policy object, so the record's policy_digest identifies
the exact corpus and a replay against a changed corpus is refused. Each input
names one request of one test; the decider loads that test's policies, schema
and entities from the corpus, evaluates the request with the Cedar engine and
reports the decision with the determining policy ids as the reason. Labelled
with the corpus's expected decision, the rows support the benchmark profile
and the verifier recomputes agreement from the rows.

`root` is where the corpus files are; under `vendor/cedar-integration-tests`
for the hand-written tests, and a fetched directory for the generated
corpus (tools/fetch_cedar_drt.py). Only `files` is compared at construction;
`root` is where to look.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

DECIDER_ID = "cedar-conformance"
OUTCOMES = ("ALLOW", "DENY")

try:
    import cedarpy
    from importlib.metadata import version as _version

    DECIDER_VERSION = f"cedarpy-{_version('cedarpy')}"
except ImportError:
    cedarpy = None
    DECIDER_VERSION = "cedarpy-unavailable"


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def corpus_policy(root: Path, tests) -> Dict[str, Any]:
    files: Dict[str, str] = {}
    for t in tests:
        d = json.loads((root / t).read_text())
        for k in ("policies", "schema", "entities"):
            if d.get(k):
                files[d[k]] = digest(root / d[k])
        files[t] = digest(root / t)
    return {"corpus": "cedar-integration-tests", "root": str(root), "files": dict(sorted(files.items()))}


class Decider:
    def __init__(self, policy: Dict[str, Any]) -> None:
        if cedarpy is None:
            raise RuntimeError("cedarpy is not installed; pip install cedarpy")
        if not isinstance(policy, dict) or policy.get("corpus") != "cedar-integration-tests" or not isinstance(policy.get("files"), dict):
            raise ValueError("policy must be {corpus: cedar-integration-tests, root, files}")
        root = policy["root"]
        if root.startswith("$"):  # an environment variable names where the fetched corpus is
            import os

            root = os.environ.get(root[1:], "")
            if not root:
                raise ValueError(f"policy.root is {policy['root']} and that variable is not set")
        self.root = Path(root)
        if not self.root.is_absolute():
            self.root = Path(__file__).resolve().parents[1] / self.root
        differing = [p for p, want in policy["files"].items() if not (self.root / p).exists() or digest(self.root / p) != want]
        if differing:
            raise ValueError(f"the corpus under {self.root} is not the record's policy; {len(differing)} file(s) differ, first {differing[:3]}")
        self._cache: Dict[str, Any] = {}

    def _load(self, test: str):
        if test not in self._cache:
            d = json.loads((self.root / test).read_text())
            ptxt = (self.root / d["policies"]).read_text()
            policies = cedarpy.policies_from_json_str(ptxt) if d["policies"].endswith((".json", ".cedarjson")) else ptxt
            stxt = (self.root / d["schema"]).read_text() if d.get("schema") else None
            schema = json.loads(stxt) if stxt is not None and d["schema"].endswith(".json") else stxt
            entities = json.loads((self.root / d["entities"]).read_text())
            self._cache[test] = (d, policies, schema, entities)
        return self._cache[test]

    def decide(self, item: Any) -> Tuple[str, Optional[str], Optional[Dict[str, Any]]]:
        if not isinstance(item, dict) or not isinstance(item.get("test"), str) or not isinstance(item.get("request"), int):
            raise ValueError("input must be {test, request}")
        d, policies, schema, entities = self._load(item["test"])
        r = d["requests"][item["request"]]
        request = {"principal": r["principal"], "action": r["action"], "resource": r["resource"], "context": r.get("context", {})}
        try:
            res = cedarpy.is_authorized(request, policies, entities, schema)
        except TypeError:  # bindings before cedarpy 4.12 take only the string form of an entity uid
            request = {k: (f'{v["type"]}::{json.dumps(v["id"])}' if k != "context" else v) for k, v in request.items()}
            res = cedarpy.is_authorized(request, policies, entities, schema)
        decision = str(res.decision)
        reasons = sorted(res.diagnostics.reasons)
        errors = [str(e)[:120] for e in res.diagnostics.errors]
        ext = {"expected_reason": sorted(r.get("reason", [])), "expected_errors": len(r.get("errors", [])), "errors": errors, "description": r.get("description", "")[:80]}
        if decision.endswith("Allow"):
            return "ALLOW", "+".join(reasons) if reasons else "allow", ext
        if decision.endswith("Deny"):
            return "DENY", "+".join(reasons) if reasons else "no-policy-permits", ext
        return "DENY", "request-invalid", ext


if __name__ == "__main__":
    from emitters._cli import run_emitter

    sys.exit(run_emitter(sys.modules[__name__]))
