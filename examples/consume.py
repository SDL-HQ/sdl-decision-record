#!/usr/bin/env python3
"""A consumer of the verifier's output: a threshold over properties, not a boolean over the verdict.

    python3 -m dr.verify <run> --registry <registry.json> --json | python3 examples/consume.py
    python3 -m dr.verify <run> --registry <registry.json> --json | python3 examples/consume.py --require chain,signature,retained --allow-unknown replay

The verifier reports every property in one of four states and folds them into
a verdict: ESTABLISHED only when nothing is unknown. That fold is deliberately
strict -- unknown is not a pass -- and for a record verified without its
decider, receipts or a witness it is the common result, not the exception.
Most of the committed examples are NOT ESTABLISHED on their own.

A consumer that fails its build on anything but exit 0 has therefore not
adopted the four-state model; it has discarded it at first contact, and will
switch the check off within the week. What a consumer decides is its own
threshold: which properties must be *established* for this use, which may be
*unknown* because this consumer cannot or need not supply what would decide
them, and that nothing *failed*. This script is that decision, made explicit.

It is an application of SPEC section 9 as it stands -- per-property states,
read from `--json` -- and adds no state, no property and no field. The
verifier is unchanged; the policy is the consumer's.

Defaults: require the eight core properties established; allow the six
conditional ones to be unknown or n/a; refuse on any failure. Exit 0 when the
threshold is met, 1 when it is not, 2 if the input is not a verifier report.
"""

from __future__ import annotations

import argparse
import json
import sys

CORE = ("document", "signing_trust", "signature", "chain", "decisions", "profile", "correctness", "retained")
CONDITIONAL = ("replay", "invocation", "stream", "completeness", "receipts", "witness")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--require", default=",".join(CORE), help="properties that must be established (comma-separated)")
    ap.add_argument("--allow-unknown", default=",".join(CONDITIONAL), help="properties that may be unknown or n/a for this use")
    a = ap.parse_args(argv)
    require = [p for p in a.require.split(",") if p]
    allow_unknown = set(p for p in a.allow_unknown.split(",") if p)

    try:
        report = json.load(sys.stdin)
        states = {p["property"]: p["state"] for p in report["properties"]}
        details = {p["property"]: p["detail"] for p in report["properties"]}
    except (ValueError, KeyError, TypeError) as exc:
        print(f"not a verifier report: {exc}", file=sys.stderr)
        return 2

    problems = []
    # Nothing may have failed, whatever this consumer requires: a failure is a
    # claim the record makes that its own contents contradict.
    for name, state in states.items():
        if state == "failed":
            problems.append(f"{name} FAILED: {details[name]}")
    # Required properties must be established -- n/a is not established, and
    # a property the report does not carry at all is unknown (SPEC section 9).
    for name in require:
        state = states.get(name, "unknown")
        if state == "n/a" and name == "correctness":
            continue  # a production record has no correctness property to require
        if state != "established":
            problems.append(f"{name} is {state}, required established: {details.get(name, 'not judged')}")
    # Everything else may be unknown only if this consumer said so.
    for name, state in states.items():
        if name in require or name in allow_unknown:
            continue
        if state in ("unknown", "n/a"):
            problems.append(f"{name} is {state} and this consumer did not allow that")

    verdict = report.get("verdict", "?")
    if problems:
        print(f"REFUSED under this consumer's threshold (verifier verdict: {verdict})")
        for p in problems:
            print(f"  {p}")
        return 1
    unknowns = sorted(n for n, s in states.items() if s in ("unknown", "n/a"))
    print(f"ACCEPTED under this consumer's threshold (verifier verdict: {verdict})")
    print(f"  established: {', '.join(n for n in require if states.get(n) == 'established')}")
    if unknowns:
        print(f"  allowed unknown or n/a: {', '.join(unknowns)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
