"""What the OPA decider refuses at construction, and what it does not (G3, G3b, G7)."""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from emitters import opa  # noqa: E402

base = json.loads((HERE / "policy-store.json").read_text())


def attempt(label, mutate):
    p = json.loads(json.dumps(base))
    mutate(p)
    try:
        opa.Decider(p)
        print(f"{label}: constructed")
    except ValueError as exc:
        print(f"{label}: refused — {str(exc)[:160]}")


def uses(builtin_call):
    def m(p):
        p["bundle"]["policies.rego"] += f"\n\nclock := {builtin_call}\n"
    return m


attempt("the policy as shipped", lambda p: None)
attempt("policy text uses time.now_ns(), builtins list unchanged", uses("time.now_ns()"))
attempt("policy text uses time.now_ns(), builtins list adds it", lambda p: (uses("time.now_ns()")(p), p["builtins"].append("time.now_ns")))
attempt("policy text uses http.send, builtins list adds it", lambda p: (uses('http.send({"method": "get", "url": "https://example.com"})')(p), p["builtins"].append("http.send")))
attempt("policy text uses sprintf (deterministic), builtins list unchanged", uses('sprintf("%d", [1])'))
attempt("policy text uses sprintf, builtins list adds it", lambda p: (uses('sprintf("%d", [1])')(p), p["builtins"].append("sprintf")))
attempt("builtins list names a builtin this engine does not have", lambda p: p["builtins"].append("no.such_builtin"))
attempt("policy text does not parse", lambda p: p["bundle"].__setitem__("policies.rego", "package agentic\n\nallow if {"))
attempt("rego_version 0 for v1 text", lambda p: p.__setitem__("rego_version", 0))
