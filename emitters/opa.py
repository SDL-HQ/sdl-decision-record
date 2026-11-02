"""opa: an execution-time decision over a privileged call, under Rego, evaluated by the OPA engine.

Built from the "Other grammars" paragraph of the specification draft (§6.1)
to find out whether that paragraph is enabling; every decision the paragraph
did not make is logged in docs/OPA-REGO-FROM-THE-PARAGRAPH-2026-10-21.md and
numbered G1.. in the comments here.

Input (one decision), the same shape as emitters/cedar.py:
    {"principal": {"type", "id"}, "action": {"type", "id"}, "resource": {"type", "id"},
     "context": {...}, "entities": [{"uid": {"type", "id"}, "attrs": {...}}, ...]}
Policy:
    {"engine": "opa", "rego_version": 0 | 1,                       # G2
     "bundle": {<filename>: <rego text>, ...},                     # the paragraph's "bundle"
     "data": {...},                                                 # the base document, whole
     "query": "data.<package>.<rule>",                              # G4: must evaluate to {allow, permit, forbid}
     "builtins": [<builtin name>, ...],                             # G3: the only builtins the policy may use
     "strict_builtin_errors": bool,                                 # G8
     "canonicalise": "none" | "url-v1",                             # §6.6, reused from emitters.cedar
     "entities": "caller" | "store"}                                # G6

The engine is the `opa` binary named by $OPA_BIN (G1); DECIDER_VERSION is
what `opa version` prints. At construction the decider writes the bundle,
the data and a capabilities file that lists only the policy's `builtins`
(taken from `opa capabilities --current` and filtered), refuses if any named
builtin is in NONDETERMINISTIC, and runs `opa check --strict --capabilities`
over the bundle; a policy that uses an unlisted builtin, or does not compile,
is refused (G3, G7). Each decision runs `opa eval -f json` with the same
capabilities file, the base document (entities from the store, or from the
caller: G6), and the canonicalised input (§6.6).

Reason (G4/G5): the query's value is {"allow": bool, "permit": [ids], "forbid": [ids]};
ALLOW with the permit ids `+`-joined, DENY with the forbid ids, or
`no-policy-permits`; `request-invalid` when the query is undefined, the value
has another shape, or the engine reports an error (the error goes to ext).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from emitters.cedar import canonical_host, canonicalise  # the §6.6 mechanism, not Cedar knowledge (G13)

DECIDER_ID = "opa-authorizer"
OUTCOMES = ("ALLOW", "DENY")

# G3: builtins whose value depends on something other than input, data and policy.
NONDETERMINISTIC = frozenset({
    "time.now_ns", "rand.intn", "uuid.rfc4122", "http.send", "net.lookup_ip_addr", "opa.runtime",
    "io.jwt.decode_verify",  # G3b: checks exp/nbf against the wall clock unless the policy supplies `time`
})


def opa_bin() -> str:
    b = os.environ.get("OPA_BIN") or shutil.which("opa")
    if not b:
        raise RuntimeError("set OPA_BIN to an opa binary, or put opa on PATH")
    return b


def opa_version(b: Optional[str] = None) -> str:
    out = subprocess.run([b or opa_bin(), "version"], capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    raise RuntimeError("opa version printed no Version line")


try:
    DECIDER_VERSION = f"opa-{opa_version()}"
except Exception:  # no engine on this machine: the module imports, the Decider refuses
    DECIDER_VERSION = "opa-unavailable"


def _major(version: str) -> int:
    return int(version.split(".")[0])


def rego_version_flags(rego_version: int, engine_version: str) -> List[str]:
    """G2: OPA 1.x reads v1 by default and v0 with --v0-compatible; OPA 0.x reads v0 by default and v1 with --v1-compatible."""
    if _major(engine_version) >= 1:
        return ["--v0-compatible"] if rego_version == 0 else []
    return ["--v1-compatible"] if rego_version == 1 else []


def capabilities_for(b: str, builtins: List[str]) -> Dict[str, Any]:
    caps = json.loads(subprocess.run([b, "capabilities", "--current"], capture_output=True, text=True, check=True).stdout)
    known = {x["name"] for x in caps["builtins"]}
    unknown = sorted(set(builtins) - known)
    if unknown:
        raise ValueError(f"policy.builtins names builtins this engine does not have: {unknown}")
    caps["builtins"] = [x for x in caps["builtins"] if x["name"] in set(builtins)]
    return caps


class Decider:
    def __init__(self, policy: Dict[str, Any]) -> None:
        if not isinstance(policy, dict) or policy.get("engine") != "opa":
            raise ValueError('policy.engine must be "opa"')
        if policy.get("rego_version") not in (0, 1):
            raise ValueError("policy.rego_version must be 0 or 1")  # G2
        if not isinstance(policy.get("bundle"), dict) or not policy["bundle"] or not all(isinstance(v, str) for v in policy["bundle"].values()):
            raise ValueError("policy.bundle must map filenames to Rego text")
        if not isinstance(policy.get("data"), dict):
            raise ValueError("policy.data must be an object")
        if not isinstance(policy.get("query"), str) or not policy["query"].startswith("data."):
            raise ValueError("policy.query must be a data.<package>.<rule> reference")
        if not isinstance(policy.get("builtins"), list) or any(not isinstance(x, str) for x in policy["builtins"]):
            raise ValueError("policy.builtins must be a list of builtin names")  # G3
        bad = sorted(set(policy["builtins"]) & NONDETERMINISTIC)
        if bad:
            raise ValueError(f"policy.builtins names non-deterministic builtins: {bad}")
        self.mode = policy.get("canonicalise", "none")
        if self.mode not in ("none", "url-v1"):
            raise ValueError("policy.canonicalise must be none or url-v1")
        self.entity_source = policy.get("entities", "store")
        if self.entity_source not in ("caller", "store"):
            raise ValueError("policy.entities must be caller or store")
        self.strict = bool(policy.get("strict_builtin_errors", False))
        self.query = policy["query"]
        self.data = policy["data"]
        self.bin = opa_bin()
        self.version = opa_version(self.bin)
        self.flags = rego_version_flags(policy["rego_version"], self.version)
        self.dir = Path(tempfile.mkdtemp(prefix="opa-decider-"))
        self.bundle_files: List[str] = []
        for name, text in policy["bundle"].items():
            p = self.dir / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
            self.bundle_files.append(str(p))
        self.caps = self.dir / "capabilities.json"
        self.caps.write_text(json.dumps(capabilities_for(self.bin, policy["builtins"]), sort_keys=True))
        chk = subprocess.run([self.bin, "check", "--strict", "--capabilities", str(self.caps), *self.flags, *self.bundle_files], capture_output=True, text=True)
        if chk.returncode != 0:  # G7: an unlisted builtin or a compile error refuses construction
            msg = (chk.stdout + chk.stderr).replace(str(self.dir) + "/", "").strip()
            raise ValueError("the policy does not check against its declared builtins: " + msg[:300])

    @staticmethod
    def _index(entities: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for e in entities:
            uid = e.get("uid") or {}
            out.setdefault(uid.get("type", ""), {})[uid.get("id", "")] = e.get("attrs", {})
        return out

    def _eval(self, data: Dict[str, Any], item: Dict[str, Any]) -> subprocess.CompletedProcess:
        data_file = self.dir / "data.json"
        input_file = self.dir / "input.json"
        data_file.write_text(json.dumps(data, sort_keys=True))
        input_file.write_text(json.dumps(item, sort_keys=True))
        cmd = [self.bin, "eval", "-f", "json", "--capabilities", str(self.caps), *self.flags]
        if self.strict:
            cmd.append("--strict-builtin-errors")
        for f in self.bundle_files:
            cmd += ["-d", f]
        cmd += ["-d", str(data_file), "-i", str(input_file), self.query]
        env: Dict[str, str] = {}  # a clean environment: nothing for opa.runtime() to report
        return subprocess.run(cmd, capture_output=True, text=True, env=env)

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
        data = dict(self.data)
        if self.entity_source == "caller":  # G6: the caller's entities are the store for this decision
            data["entities"] = self._index(item.get("entities") or [])
        request = {k: v for k, v in item.items() if k != "entities"}
        p = self._eval(data, request)
        try:
            out = json.loads(p.stdout) if p.stdout.strip() else {}
        except json.JSONDecodeError:
            return "DENY", "request-invalid", {"error": (p.stdout + p.stderr)[:200]}
        if "errors" in out or p.returncode != 0:
            errs = [f"{e.get('code')}: {e.get('message')}"[:200] for e in out.get("errors", [])] or [p.stderr[:200]]
            return "DENY", "request-invalid", {"errors": errs}
        res = out.get("result") or []
        if not res:
            return "DENY", "no-policy-permits", {"undefined": True}
        val = res[0].get("expressions", [{}])[0].get("value")
        if not isinstance(val, dict) or not isinstance(val.get("allow"), bool) or not isinstance(val.get("permit"), list) or not isinstance(val.get("forbid"), list):
            return "DENY", "request-invalid", {"error": "query value is not {allow, permit, forbid}", "value": val}
        permit, forbid = sorted(map(str, val["permit"])), sorted(map(str, val["forbid"]))
        if val["allow"]:
            return "ALLOW", "+".join(permit) if permit else "allow", None
        return "DENY", "+".join(forbid) if forbid else "no-policy-permits", None


if __name__ == "__main__":
    from emitters._cli import run_emitter

    sys.exit(run_emitter(sys.modules[__name__]))
