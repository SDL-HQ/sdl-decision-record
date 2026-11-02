"""The assurance ladder: a way to read the four-state report, never a replacement for it.

A verification reports every property as established, unknown, failed or n/a
(SPEC §9). The ladder names what a set of those properties, all established,
lets a reader rely on, from A0 to A4:

    A0  the operator's word   nothing beyond what the producer says
    A1  integrity             signed and chained: unchanged since it was signed
    A2  re-evaluable          the retained inputs, re-decided, give the recorded decisions
    A3  invoked               the decider itself signed each decision
    A4  witnessed             a party other than the producer signed each input
                              as it arrived, and the rows account for its log

Three rules, each held by tests/test_assurance.py:

- **A level is a set of properties that must all be established.** Each level
  includes the one below it. One property in a level's set that is unknown,
  or n/a where the level needs it, means the level is not reached, whatever
  else holds. A property allowed to be n/a is named as such and is n/a only
  when it does not apply to the record (`correctness` outside the benchmark
  profile, `stream` outside a stream).
- **A failed property voids the ladder.** A report with any failed property
  reaches no level, A0 included: the operator's word is contradicted by the
  evidence, and a level shown beside a failure would read as a pass.
- **No level is ever shown without the table beneath it.** The level is
  computed from a report's properties and rendered only by the report that
  carries them (`Report.to_text`, `Report.to_json`); the structure returned
  here carries the table itself, so whatever forwards a level forwards the
  states it was computed from.

The levels are numbered A0–A4 and are not the rungs L0–L3 of
`experiments/rederivability/RESULTS.md`, which order the ways a verifier can
re-derive a decision by what each still accepts on trust. The two are
different questions and keep different names.

What no level covers: `completeness` (never established, §13), `receipts` and
`witness` (evidence a party holds about particular rows or about the record's
existence, reported in the table and not ranked here).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

# (level, name, what it adds, properties added, properties that may be n/a)
LEVELS: Tuple[Tuple[str, str, str, Tuple[str, ...], Tuple[str, ...]], ...] = (
    ("A0", "the operator's word", "nothing beyond what the producer says", (), ()),
    ("A1", "integrity", "signed and chained: the record and its rows are unchanged since they were signed, and its counts recompute",
     ("document", "signing_trust", "signature", "chain", "decisions", "profile", "correctness", "stream"), ("correctness", "stream")),
    ("A2", "re-evaluable", "the retained inputs, re-decided under the retained policy, give every recorded outcome and reason",
     ("retained", "replay"), ()),
    ("A3", "invoked", "the decider itself signed each decision, under a key the producer does not hold",
     ("invocation",), ()),
    ("A4", "witnessed", "a party other than the producer signed each input as it arrived, and the rows account for its log",
     ("arrival", "arrivals_accounted"), ()),
)

WHERE_JUDGED = {
    "replay": "pass --replay <decider module>",
    "invocation": "pass --decider-registry",
    "arrival": "judged by tools/verify_arrival.py",
    "arrivals_accounted": "judged by tools/verify_arrival.py",
}


def assess(properties: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """The ladder over a report's properties, with the table it was computed from."""
    table = [{"property": p["property"], "state": p["state"]} for p in properties]
    states = {p["property"]: p["state"] for p in table}
    failed = [p["property"] for p in table if p["state"] == "failed"]
    levels: List[Dict[str, Any]] = []
    reached: Optional[Tuple[str, str]] = None
    missing_below: List[Dict[str, str]] = []
    for level, name, means, adds, may_be_na in LEVELS:
        missing = list(missing_below)
        for prop in adds:
            state = states.get(prop)
            if state == "established" or (state == "n/a" and prop in may_be_na):
                continue
            missing.append({"property": prop, "state": state or "not judged",
                            **({"how": WHERE_JUDGED[prop]} if prop in WHERE_JUDGED and state in (None, "n/a") else {})})
        ok = not failed and not missing
        levels.append({"level": level, "name": name, "means": means, "requires": list(adds),
                       "reached": ok, "missing": missing})
        if ok:
            reached = (level, name)
        missing_below = missing
    return {
        "level": reached[0] if reached else None,
        "name": reached[1] if reached else None,
        "failed": failed,
        "levels": levels,
        "table": table,
        "read_with": "the table: a level is every property it names established, and says nothing the table does not",
    }


def render_text(assessment: Dict[str, Any]) -> List[str]:
    """Lines for the end of a text report. Only Report.to_text calls this, after the table."""
    if assessment["level"] is None:
        why = ", ".join(assessment["failed"]) if assessment["failed"] else "nothing established"
        lines = [f"ASSURANCE: none -- {why} failed, so no level is reached, A0 included"]
        return lines
    lines = [f"ASSURANCE: {assessment['level']} {assessment['name']} -- read with the table above; "
             "a level is every property it names established"]
    for lv in assessment["levels"]:
        if lv["reached"]:
            continue
        gaps = "; ".join(f"{m['property']} {m['state']}" + (f" ({m['how']})" if "how" in m else "") for m in lv["missing"])
        lines.append(f"  {lv['level']} {lv['name']}: not reached -- {gaps}")
    return lines
