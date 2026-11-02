"""opa_conformance: OPA's own test-case corpus as a decision record, the corpus being the policy.

Built to test whether §6.2 ("the grammar's own conformance corpus as a
record") carries over from Cedar to OPA/Rego. It does not carry over as
written, and the differences are the point (gap log G10–G12 in
docs/OPA-REGO-FROM-THE-PARAGRAPH-2026-10-21.md):

- OPA's corpus (`v1/test/cases/testdata/{v0,v1}/**/*.yaml` in
  open-policy-agent/opa, Apache-2.0) expects a *result set* (a set of
  variable bindings), an *error substring* or an *error code* — values, not
  decisions. So the outcome vocabulary here is RESULT | ERROR | UNDEFINED,
  the row's `reason` is a digest of the normalised result set (RESULT), the
  error code (ERROR) or "undefined", and the label is the corpus's expected
  class. Replay compares (outcome, reason), which is value-exact.
- The corpus's comparison rules come from OPA's own runner
  (`v1/topdown/exported_test.go`): bindings compared as a set; `sort_bindings`
  sorts each binding's array value; `ignore_generated_vars` drops `__localq*`
  bindings; `want_error` is a substring of the error text; `want_error_code`
  is exact; `strict_error` evaluates with strict builtin errors.
- `input_term` (a raw Rego term) is carried into the query as
  `<query> with input as <term>` because the CLI takes JSON input only.

Policy: {"corpus": "opa-test-cases", "root": <path or "$ENV">, "files": {relative path: digest, ...}}
Input:  {"file": <relative yaml path>, "case": <index>}
Decider identity: opa-conformance@opa-<version>. The engine is $OPA_BIN (G1).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dr.canonical import canonical_bytes, digest_bytes
from emitters.opa import opa_bin, opa_version, rego_version_flags

DECIDER_ID = "opa-conformance"
OUTCOMES = ("RESULT", "ERROR", "UNDEFINED")

try:
    DECIDER_VERSION = f"opa-{opa_version()}"
except Exception:
    DECIDER_VERSION = "opa-unavailable"


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def corpus_policy(root: Path, files) -> Dict[str, Any]:
    return {"corpus": "opa-test-cases", "root": "$OPA_TESTDATA_ROOT", "files": {f: digest(root / f) for f in sorted(files)}}


def _rego_rank(v: Any) -> int:
    if v is None:
        return 0
    if isinstance(v, bool):
        return 1
    if isinstance(v, (int, float)):
        return 2
    if isinstance(v, str):
        return 3
    if isinstance(v, list):
        return 4
    return 5


def _rego_key(v: Any):
    """A sort key approximating Rego's term ordering: null < bool < number < string < array < object."""
    r = _rego_rank(v)
    if r == 4:
        return (r, [_rego_key(x) for x in v])
    if r == 5:
        return (r, [(k, _rego_key(v[k])) for k in sorted(v)])
    return (r, v)


def jsonify(v: Any) -> Any:
    """YAML to JSON as OPA's loader does it: non-string object keys become strings."""
    if isinstance(v, dict):
        return {("true" if k is True else "false" if k is False else "null" if k is None else str(k)): jsonify(x) for k, x in v.items()}
    if isinstance(v, list):
        return [jsonify(x) for x in v]
    return v


def normalise_result_set(bindings: List[Dict[str, Any]], sort_bindings: bool, ignore_generated: bool) -> List[str]:
    """The result set as OPA's runner compares it: a set of binding objects, rendered canonically and sorted."""
    out = []
    for b in bindings:
        obj = {}
        for k, v in b.items():
            if ignore_generated and k.startswith("__localq"):
                continue
            if sort_bindings and isinstance(v, list):
                v = sorted(v, key=_rego_key)
            obj[k] = v
        out.append(canonical_bytes(obj).decode("utf-8"))
    return sorted(set(out))


def result_digest(normalised: List[str]) -> str:
    return digest_bytes(canonical_bytes(normalised))


class Decider:
    def __init__(self, policy: Dict[str, Any]) -> None:
        if not isinstance(policy, dict) or policy.get("corpus") != "opa-test-cases" or not isinstance(policy.get("files"), dict):
            raise ValueError("policy must be {corpus: opa-test-cases, root, files}")
        root = policy["root"]
        if root.startswith("$"):
            root = os.environ.get(root[1:], "")
            if not root:
                raise ValueError(f"policy.root is {policy['root']} and that variable is not set")
        self.root = Path(root)
        differing = [p for p, want in policy["files"].items() if not (self.root / p).exists() or digest(self.root / p) != want]
        if differing:
            raise ValueError(f"the corpus under {self.root} is not the record's policy; {len(differing)} file(s) differ, first {differing[:3]}")
        self.bin = opa_bin()
        self.version = opa_version(self.bin)
        self.dir = Path(tempfile.mkdtemp(prefix="opa-conformance-"))
        self._cache: Dict[str, List[Dict[str, Any]]] = {}

    def _cases(self, rel: str) -> List[Dict[str, Any]]:
        if rel not in self._cache:
            import yaml  # the corpus is YAML; the record retains inputs as {file, case}

            self._cache[rel] = jsonify(yaml.safe_load((self.root / rel).read_text(encoding="utf-8"))).get("cases", [])
        return self._cache[rel]

    def _run(self, case: Dict[str, Any], rego_version: int) -> subprocess.CompletedProcess:
        for p in self.dir.glob("*"):
            p.unlink()
        cmd = [self.bin, "eval", "-f", "json", *rego_version_flags(rego_version, self.version)]
        if case.get("strict_error"):
            cmd.append("--strict-builtin-errors")
        # Files are named relative to the working directory, as OPA's runner names them (`test-<i>.rego`), so error
        # locations in the retained rows carry no machine path and the rows reproduce byte for byte.
        for i, mod in enumerate(case.get("modules") or []):
            (self.dir / f"test-{i}.rego").write_text(mod, encoding="utf-8")
            cmd += ["-d", f"test-{i}.rego"]
        if case.get("data") is not None:
            (self.dir / "data.json").write_text(json.dumps(case["data"]), encoding="utf-8")
            cmd += ["-d", "data.json"]
        query = case["query"]
        if case.get("input_term") is not None:  # G12
            query = f"{query} with input as {case['input_term']}"
        elif case.get("input") is not None:
            (self.dir / "input.json").write_text(json.dumps(case["input"]), encoding="utf-8")
            cmd += ["-i", "input.json"]
        cmd.append(query)
        # The engine runs in a clean environment: `opa.runtime()` reports the process environment, and an
        # evaluation that could read it is neither deterministic nor fit to retain (G17).
        env = {**(case.get("env") or {})}
        return subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=self.dir)

    def decide(self, item: Any) -> Tuple[str, Optional[str], Optional[Dict[str, Any]]]:
        if not isinstance(item, dict) or not isinstance(item.get("file"), str) or not isinstance(item.get("case"), int):
            raise ValueError("input must be {file, case}")
        rel = item["file"]
        rego_version = 0 if "/v0/" in rel or rel.startswith("v0/") else 1
        case = self._cases(rel)[item["case"]]
        want_class = "ERROR" if ("want_error" in case or "want_error_code" in case) else ("UNDEFINED" if case.get("want_result") == [] else "RESULT")
        ext: Dict[str, Any] = {"note": case.get("note", "")[:120], "expected": want_class, "rego_version": rego_version}
        if "want_error_code" in case:
            ext["want_error_code"] = case["want_error_code"]
        if "want_error" in case:
            ext["want_error"] = case["want_error"][:200]
        p = self._run(case, rego_version)
        try:
            out = json.loads(p.stdout) if p.stdout.strip() else {}
        except json.JSONDecodeError:
            out = {"errors": [{"code": "unparseable-output", "message": (p.stdout + p.stderr)[:200]}]}
        if "errors" in out or p.returncode != 0:
            errs = out.get("errors") or [{"code": "exit", "message": p.stderr[:200]}]
            # G16: the CLI's JSON separates location, code and message; OPA's own runner matches want_error
            # against the Go error's string form, "<file>:<row>: <code>: <message>", so that form is rebuilt here.
            def text(e):
                loc = e.get("location") or {}
                head = f"{loc['file']}:{loc['row']}: " if loc.get("file") and loc.get("row") else ""
                return f"{head}{e.get('code')}: {e.get('message')}"
            ext["errors"] = [{"code": e.get("code"), "message": str(e.get("message"))[:200], "text": text(e)[:300]} for e in errs]
            return "ERROR", str(errs[0].get("code")), ext
        res = out.get("result") or []
        bindings = [r.get("bindings", {}) for r in res]
        norm = normalise_result_set(bindings, bool(case.get("sort_bindings")), bool(case.get("ignore_generated_vars")))
        ext["result"] = [x[:400] for x in norm[:8]]
        if "want_result" in case and case["want_result"] is not None:
            want_norm = normalise_result_set(case["want_result"], bool(case.get("sort_bindings")), bool(case.get("ignore_generated_vars")))
            ext["want"] = [x[:400] for x in want_norm[:8]]
            ext["want_digest"] = result_digest(want_norm)
        if not res:
            return "UNDEFINED", "undefined", ext
        return "RESULT", result_digest(norm), ext


def agrees(outcome: str, reason: str, ext: Dict[str, Any], case: Dict[str, Any]) -> bool:
    """OPA's own runner's rule, over a row: the class, the value (as a set of bindings), the error code or substring."""
    if "want_error" in case or "want_error_code" in case:
        if outcome != "ERROR":
            return False
        errs = ext.get("errors") or []
        if "want_error_code" in case and (not errs or errs[0]["code"] != case["want_error_code"]):
            return False
        if "want_error" in case and not any(case["want_error"] in (e.get("text") or e["message"] or "") for e in errs):
            return False
        return True
    want = case.get("want_result")
    if want == []:
        return outcome == "UNDEFINED"
    if outcome != "RESULT":
        return False
    return reason == ext.get("want_digest")


if __name__ == "__main__":
    from emitters._cli import run_emitter

    sys.exit(run_emitter(sys.modules[__name__]))
