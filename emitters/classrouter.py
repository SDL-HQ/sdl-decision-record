"""classrouter: a data-classification router with three outcomes.

Input: {"destination": <name>, "fields": {<field>: <classification level>}}
Policy: {"levels": [lowest, ..., highest],
         "destinations": {<name>: {"max_level": <level>, "redactable": true|false}}}

ROUTE   every field's level is at or below the destination's max_level
REDACT  some field exceeds it and the destination is redactable; the reason
        names the offending fields in sorted order
DENY    some field exceeds it and the destination is not redactable, or the
        destination or a level is unknown to the policy

Three outcomes rather than two, so that the record format is exercised on a
decision vocabulary that is not allow/deny. Decides on declared classification
levels, never on the content of any field.

Policy may also carry `"reason_detail": "fine" | "coarse"` (default fine). Under
coarse the reasons are `redact`, `exceeds` and `level_unknown` with no field
names. The ext block on a REDACT still lists the redacted fields, because ext
is what the decider saw; whether it is written to the row is the emitter's
`retain_ext` choice, not the decider's (experiments/leakage).
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

DECIDER_ID = "classrouter"
DECIDER_VERSION = "1.0.0"
OUTCOMES = ("ROUTE", "REDACT", "DENY")


class Decider:
    def __init__(self, policy: Dict[str, Any]) -> None:
        levels = policy.get("levels")
        dests = policy.get("destinations")
        if not isinstance(levels, list) or not levels or len(set(levels)) != len(levels):
            raise ValueError("policy.levels must be a non-empty list of distinct levels")
        if not isinstance(dests, dict):
            raise ValueError("policy.destinations must be an object")
        self.rank = {lvl: i for i, lvl in enumerate(levels)}
        for name, spec in dests.items():
            if spec.get("max_level") not in self.rank or not isinstance(spec.get("redactable"), bool):
                raise ValueError(f"destination {name!r} needs a known max_level and a boolean redactable")
        self.dests = dests
        detail = policy.get("reason_detail", "fine")
        if detail not in ("fine", "coarse"):
            raise ValueError("policy.reason_detail must be \"fine\" or \"coarse\"")
        self.coarse = detail == "coarse"

    def _why(self, kind: str, fields) -> str:
        return kind if self.coarse else kind + ":" + ",".join(fields)

    def decide(self, item: Any) -> Tuple[str, Optional[str], Optional[Dict[str, Any]]]:
        if not isinstance(item, dict) or not isinstance(item.get("fields"), dict):
            return "DENY", "malformed_request", None
        dest = self.dests.get(item.get("destination"))
        if dest is None:
            return "DENY", "destination_unknown", None
        limit = self.rank[dest["max_level"]]
        offending = []
        for field in sorted(item["fields"]):
            level = item["fields"][field]
            if level not in self.rank:
                return "DENY", self._why("level_unknown", [field]), None
            if self.rank[level] > limit:
                offending.append(field)
        if not offending:
            return "ROUTE", None, None
        if dest["redactable"]:
            return "REDACT", self._why("redact", offending), {"redacted": offending}
        return "DENY", self._why("exceeds", offending), None


def main(argv=None) -> int:
    import sys
    from ._cli import run_emitter

    return run_emitter(sys.modules[__name__], argv)


if __name__ == "__main__":
    raise SystemExit(main())
