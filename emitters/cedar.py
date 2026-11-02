"""cedar: an execution-time decision over a privileged call, under Cedar.

Input (one decision): {"principal": {"type", "id"}, "action": {"type", "id"},
                       "resource": {"type", "id"}, "context": {...}, "entities": [...]}
Policy: {"engine": "cedar", "schema": <Cedar schema text>, "policies": <Cedar policy text>,
         "canonicalise": "none" | "url-v1", "entities": "caller" | "store", "store": [<entity>, ...]}

The decision point is the call and its arguments, not a prompt. The policy is
a Cedar policy set with a schema (a named grammar with a published formal
semantics, a Lean model and a differential-testing corpus; `vendor/
cedar-integration-tests` carries the hand-written part of that corpus and
`tools/cedar_conformance.py` runs the generated part). The decider validates
the policy set against the schema at construction and refuses an invalid one,
then evaluates every request with the Cedar engine (`cedarpy`, the Rust
engine behind Python bindings) and reports ALLOW or DENY with the determining
policy ids as the reason. The same request under the same policy gives the
same decision, and a third party holding the record re-runs it with
`dr.verify --replay emitters.cedar` and gets the same outcome and reason.

Where the entities come from is the design question this emitter is built
to show. Under `"entities": "caller"` the decision consults the entities the
input carries, attributes included, so a caller who writes
`"allowlisted": true` has decided the call. Under `"entities": "store"` the
decision consults the policy's own `store`, keyed by entity uid, and ignores
any entities the input carries: the gate decides, and a resource the store
does not know is an entity Cedar cannot read attributes from, which denies.
The store is part of the policy, so it is in the record's policy digest and
a replay against a different store is a different decider. Either way the
retained input and the retained policy are the whole of what was decided on.

Canonicalisation. Under `"canonicalise": "url-v1"` the decider, before
resolving entities or building the request, lower-cases and IDNA-encodes host
names, strips a trailing dot, normalises `.` and `..` in paths after
percent-decoding them, and upper-cases currency codes and lower-cases URL schemes, on the context keys
and entity attributes named in `CANONICAL_KEYS` and on the ids of entities
whose type ends in `Host`. Under `"none"` it evaluates the arguments as given. The
example runs both over the same inputs so the difference is in the rows.

Reason. ALLOW: the permit policies that fired, joined with `+`. DENY: the
forbid policies that fired, or `no-policy-permits` when nothing did, or
`request-invalid` when the request could not be built against the schema
(an unknown entity, a type mismatch). Evaluation errors do not change the
decision Cedar reaches and are reported in `ext`, not in the reason.
"""

from __future__ import annotations

import posixpath
import sys
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

DECIDER_ID = "cedar-authorizer"
OUTCOMES = ("ALLOW", "DENY")

try:
    import cedarpy
    from importlib.metadata import version as _version

    DECIDER_VERSION = f"cedarpy-{_version('cedarpy')}"
except ImportError:  # the verifier closure never imports this module unasked
    cedarpy = None
    DECIDER_VERSION = "cedarpy-unavailable"

CANONICAL_KEYS = {"host": "host", "name": "host", "domain": "host", "recipient_domain": "host", "url_path": "path", "path": "path", "currency": "upper", "scheme": "lower"}


def canonical_host(h: str) -> str:
    h = h.strip().rstrip(".").lower()
    try:
        return h.encode("idna").decode("ascii")
    except UnicodeError:
        return h


def canonical_path(p: str) -> str:
    p = urllib.parse.unquote(p)
    out = posixpath.normpath(p)
    return "/" + out.lstrip("/") if p.startswith("/") else out


def canonicalise(obj: Any, mode: str) -> Any:
    if mode == "none":
        return obj
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kind = CANONICAL_KEYS.get(k)
            if isinstance(v, str) and kind == "host":
                out[k] = canonical_host(v)
            elif isinstance(v, str) and kind == "path":
                out[k] = canonical_path(v)
            elif isinstance(v, str) and kind == "upper":
                out[k] = v.upper()
            elif isinstance(v, str) and kind == "lower":
                out[k] = v.lower()
            else:
                out[k] = canonicalise(v, mode)
        return out
    if isinstance(obj, list):
        return [canonicalise(x, mode) for x in obj]
    return obj


class Decider:
    def __init__(self, policy: Dict[str, Any]) -> None:
        if cedarpy is None:
            raise RuntimeError("cedarpy is not installed; pip install cedarpy")
        if not isinstance(policy, dict) or policy.get("engine") != "cedar":
            raise ValueError('policy.engine must be "cedar"')
        for k in ("schema", "policies"):
            if not isinstance(policy.get(k), str) or not policy[k].strip():
                raise ValueError(f"policy.{k} must be Cedar text")
        self.mode = policy.get("canonicalise", "none")
        if self.mode not in ("none", "url-v1"):
            raise ValueError("policy.canonicalise must be none or url-v1")
        self.entity_source = policy.get("entities", "caller")
        if self.entity_source not in ("caller", "store"):
            raise ValueError("policy.entities must be caller or store")
        self.store: List[Dict[str, Any]] = list(policy.get("store") or [])
        if self.entity_source == "store" and not self.store:
            raise ValueError("policy.entities is store but policy.store is empty")
        self.schema = policy["schema"]
        self.policies = policy["policies"]
        v = cedarpy.validate_policies(self.policies, self.schema)
        if not v.validation_passed:
            raise ValueError("the policy set does not validate against its schema: " + "; ".join(str(e) for e in v.errors[:3]))

    def decide(self, item: Any) -> Tuple[str, Optional[str], Optional[Dict[str, Any]]]:
        if not isinstance(item, dict):
            raise ValueError("input must be an object")
        for k in ("principal", "action", "resource"):
            e = item.get(k)
            if not isinstance(e, dict) or not isinstance(e.get("type"), str) or not isinstance(e.get("id"), str):
                raise ValueError(f"input.{k} must be {{type, id}}")
        item = canonicalise(item, self.mode)
        if self.mode != "none":
            for k in ("principal", "resource"):
                if item[k]["type"].endswith("Host"):
                    item[k] = {"type": item[k]["type"], "id": canonical_host(item[k]["id"])}
        request = {"principal": item["principal"], "action": item["action"], "resource": item["resource"], "context": item.get("context") or {}}
        entities: List[Dict[str, Any]] = self.store if self.entity_source == "store" else (item.get("entities") or [])
        try:
            res = cedarpy.is_authorized(request, self.policies, entities, self.schema)
        except Exception as exc:  # the engine refused the request outright
            return "DENY", "request-invalid", {"error": str(exc)[:200]}
        decision = str(res.decision)
        reasons = sorted(res.diagnostics.reasons)
        errors = [str(e)[:200] for e in res.diagnostics.errors]
        if decision.endswith("Allow"):
            return "ALLOW", "+".join(reasons) if reasons else "allow", {"errors": errors} if errors else None
        if decision.endswith("Deny"):
            return "DENY", ("+".join(reasons) if reasons else "no-policy-permits"), {"errors": errors} if errors else None
        return "DENY", "request-invalid", {"errors": errors, "decision": decision}


if __name__ == "__main__":
    from emitters._cli import run_emitter

    sys.exit(run_emitter(sys.modules[__name__]))
