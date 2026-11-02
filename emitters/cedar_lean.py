"""The Cedar deciders under the Lean definitional engine: the proved specification as the decision procedure.

cedar-spec (github.com/cedar-policy/cedar-spec) holds a Lean 4 formalisation of
Cedar — `isAuthorized` as a definition, with theorems proved about it — and a
command-line front end, `cedar-lean-cli`, that parses policies, schema,
entities and a request with the Rust parser and evaluates them with the Lean
definition through Lean's FFI. This module is the Cedar deciders of this
repository (`emitters.cedar` over tool calls, `emitters.cedar_conformance`
over Cedar's corpus) with that engine in place of cedarpy: same policy
objects, same inputs, same outcome and reason vocabulary, so a record made
under one can be replayed under the other wherever the record names the
other as established (SPEC §8).

What the engine is. `CEDAR_LEAN_CLI` names the built binary; the decider
version is `cedar-lean-<cedar-spec commit>`, taken from `CEDAR_LEAN_SPEC_COMMIT`,
because the binary's own `--version` reports the Cedar crate it was built
with (4.4.0 at the pin) and not the specification it evaluates. Both are
required; nothing is guessed from a binary.

How a decision is made. Policies, schema and entities are written to a
temporary directory as the files the CLI reads; the request goes in a JSON
file with the principal, action and resource rendered as `Type::"id"`, the
id escaped as Cedar's `EntityUid` Display does (Rust `str::escape_debug`),
because the CLI requires the normalised form. One process per decision.
The CLI prints three lines at most — the decision with the determining
policies, and the erroring policies if any — and those are parsed; anything
else is `request-invalid`.

What this costs: one process per decision (about 50 ms here, against
cedarpy's tens of microseconds), and a toolchain that this repository does
not vendor. What it buys: a decider whose semantics are the definition the
Cedar theorems are about, so "the decision procedure named in the record"
is, for this engine, the specification.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from emitters import cedar as _cedar
from emitters import cedar_conformance as _conf

DECIDER_ID = _cedar.DECIDER_ID  # the same decision procedure, another engine
_COMMIT = os.environ.get("CEDAR_LEAN_SPEC_COMMIT", "")
DECIDER_VERSION = f"cedar-lean-{_COMMIT[:12]}" if _COMMIT else "cedar-lean-unavailable"
OUTCOMES = _cedar.OUTCOMES if hasattr(_cedar, "OUTCOMES") else ("ALLOW", "DENY")

_ALLOW = re.compile(r"^This request was allowed as it matched the following policies: ?(.*)$", re.M)
_DENY = re.compile(r"^This request was denies as it matched the following policies: ?(.*)$", re.M)
_IMPLICIT = re.compile(r"^This request was implicitly denied", re.M)
_ERRS = re.compile(r"errored during evaluation: ?(.*)$", re.M)


def escape_eid(s: str) -> str:
    """Rust `str::escape_debug`, which is how Cedar prints an entity id and what its parser calls normalised."""
    out: List[str] = []
    simple = {"\t": "\\t", "\n": "\\n", "\r": "\\r", "\\": "\\\\", "'": "\\'", '"': '\\"', "\0": "\\0"}
    for i, ch in enumerate(s):
        if ch in simple:
            out.append(simple[ch])
        elif ch.isprintable() and not (i == 0 and unicodedata.category(ch) in ("Mn", "Me")):
            out.append(ch)
        else:
            out.append("\\u{%x}" % ord(ch))
    return "".join(out)


def uid(e: Dict[str, str]) -> str:
    return f'{e["type"]}::"{escape_eid(e["id"])}"'


class Engine:
    def __init__(self) -> None:
        cli = os.environ.get("CEDAR_LEAN_CLI", "")
        if not cli or not Path(cli).exists():
            raise RuntimeError("CEDAR_LEAN_CLI must name the built cedar-lean-cli binary")
        if not _COMMIT:
            raise RuntimeError("CEDAR_LEAN_SPEC_COMMIT must name the cedar-spec commit the binary was built from")
        self.cli = cli

    def authorize(self, policies: str, schema: Optional[str], schema_is_json: bool, entities: Any, request: Dict[str, Any]) -> Tuple[str, List[str], List[str], str]:
        """→ (decision 'allow'|'deny'|'invalid', determining policy ids, erroring policy ids, raw text)."""
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            (d / "policies.cedar").write_text(policies)
            (d / "entities.json").write_text(json.dumps(entities))
            (d / "request.json").write_text(json.dumps({"principal": uid(request["principal"]), "action": uid(request["action"]), "resource": uid(request["resource"]), "context": request.get("context") or {}}))
            cmd = [self.cli, "evaluate", "authorize", str(d / "policies.cedar"), str(d / "entities.json")]
            if schema is not None:
                sp = d / ("schema.json" if schema_is_json else "schema.cedarschema")
                sp.write_text(schema)
                cmd.append(str(sp))
            cmd += ["--request-file", str(d / "request.json")]
            p = subprocess.run(cmd, capture_output=True, text=True, env={"PATH": os.environ.get("PATH", ""), "LD_LIBRARY_PATH": os.environ.get("LD_LIBRARY_PATH", "")})
        out = p.stdout
        errs = _ERRS.search(out)
        erroring = sorted(errs.group(1).split()) if errs else []
        if _IMPLICIT.search(out):
            return "deny", [], erroring, out
        m = _ALLOW.search(out)
        if m:
            return "allow", sorted(m.group(1).split()), erroring, out
        m = _DENY.search(out)
        if m:
            return "deny", sorted(m.group(1).split()), erroring, out
        return "invalid", [], [], (out + p.stderr)[:300]


class Decider:
    """`emitters.cedar.Decider` with the Lean engine: the same policy object, canonicalisation and entity source."""

    def __init__(self, policy: Dict[str, Any]) -> None:
        # the same shape checks and refusals as the cedarpy decider, then the engine
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
        self.store = list(policy.get("store") or [])
        if self.entity_source == "store" and not self.store:
            raise ValueError("policy.entities is store but policy.store is empty")
        self.schema = policy["schema"]
        self.policies = policy["policies"]
        self.engine = Engine()

    def decide(self, item: Any) -> Tuple[str, Optional[str], Optional[Dict[str, Any]]]:
        if not isinstance(item, dict):
            raise ValueError("input must be an object")
        for k in ("principal", "action", "resource"):
            e = item.get(k)
            if not isinstance(e, dict) or not isinstance(e.get("type"), str) or not isinstance(e.get("id"), str):
                raise ValueError(f"input.{k} must be {{type, id}}")
        item = _cedar.canonicalise(item, self.mode)
        if self.mode != "none":
            for k in ("principal", "resource"):
                if item[k]["type"].endswith("Host"):
                    item[k] = {"type": item[k]["type"], "id": _cedar.canonical_host(item[k]["id"])}
        entities = self.store if self.entity_source == "store" else (item.get("entities") or [])
        decision, reasons, erroring, raw = self.engine.authorize(self.policies, self.schema, False, entities, item)
        if decision == "allow":
            return "ALLOW", "+".join(reasons) if reasons else "allow", {"errors": erroring} if erroring else None
        if decision == "deny":
            return "DENY", ("+".join(reasons) if reasons else "no-policy-permits"), {"errors": erroring} if erroring else None
        return "DENY", "request-invalid", {"errors": [raw[:200]]}


class ConformanceDecider:
    """`emitters.cedar_conformance.Decider` with the Lean engine: the corpus as policy, {test, request} as input."""

    def __init__(self, policy: Dict[str, Any]) -> None:
        if not isinstance(policy, dict) or policy.get("corpus") != "cedar-integration-tests" or not isinstance(policy.get("files"), dict):
            raise ValueError("policy must be {corpus: cedar-integration-tests, root, files}")
        root = policy["root"]
        if root.startswith("$"):
            root = os.environ.get(root[1:], "")
            if not root:
                raise ValueError(f"policy.root is {policy['root']} and that variable is not set")
        self.root = Path(root)
        if not self.root.is_absolute():
            self.root = Path(__file__).resolve().parents[1] / self.root
        differing = [p for p, want in policy["files"].items() if not (self.root / p).exists() or _conf.digest(self.root / p) != want]
        if differing:
            raise ValueError(f"the corpus under {self.root} is not the record's policy; {len(differing)} file(s) differ, first {differing[:3]}")
        self.engine = Engine()
        self._cache: Dict[str, Any] = {}

    def _load(self, test: str):
        if test not in self._cache:
            d = json.loads((self.root / test).read_text())
            policies = (self.root / d["policies"]).read_text()
            if d["policies"].endswith((".json", ".cedarjson")):
                raise ValueError("JSON-format policies are not handled by this engine wrapper")
            schema = (self.root / d["schema"]).read_text() if d.get("schema") else None
            schema_is_json = bool(d.get("schema")) and d["schema"].endswith(".json")
            entities = json.loads((self.root / d["entities"]).read_text())
            self._cache[test] = (d, policies, schema, schema_is_json, entities)
        return self._cache[test]

    def decide(self, item: Any) -> Tuple[str, Optional[str], Optional[Dict[str, Any]]]:
        if not isinstance(item, dict) or not isinstance(item.get("test"), str) or not isinstance(item.get("request"), int):
            raise ValueError("input must be {test, request}")
        d, policies, schema, schema_is_json, entities = self._load(item["test"])
        r = d["requests"][item["request"]]
        request = {"principal": r["principal"], "action": r["action"], "resource": r["resource"], "context": r.get("context", {})}
        decision, reasons, erroring, raw = self.engine.authorize(policies, schema, schema_is_json, entities, request)
        ext = {"expected_reason": sorted(r.get("reason", [])), "expected_errors": len(r.get("errors", [])), "errors": erroring, "description": r.get("description", "")[:80]}
        if decision == "allow":
            return "ALLOW", "+".join(reasons) if reasons else "allow", ext
        if decision == "deny":
            return "DENY", "+".join(reasons) if reasons else "no-policy-permits", ext
        ext["errors"] = [raw[:200]]
        return "DENY", "request-invalid", ext


if __name__ == "__main__":
    from emitters._cli import run_emitter

    sys.exit(run_emitter(sys.modules[__name__]))
