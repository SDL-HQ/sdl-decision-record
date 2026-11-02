"""An independent reimplementation of the toolgate decision function, from the policy object alone.

Written before reading `emitters/toolgate.py`'s decide(), from only: the
retained policy object (`{"tools": {name: {"args": {arg: type}}}}`), the
record's declared outcome vocabulary (ALLOW, DENY) and SPEC.md. SPEC.md says
nothing about this decider. Every choice below is therefore a guess, marked
with a G-number; the divergences the measurement finds are attributed to them
in the findings.

This exists to answer one question: for a decider with no published engine and
no published decision function, how far does retaining the policy and the
inputs get a reader?
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

GUESSES = {
    "G1": "arguments are checked in sorted order, so the reported reason is the first failure alphabetically",
    "G2": "an argument the policy does not declare is refused rather than ignored",
    "G3": "the reason is '<kind>:<arg>' naming the failing argument",
    "G4": "'integer' means a JSON integer and rejects a boolean; 'string' rejects non-strings; 'boolean' rejects 0/1",
    "G5": "a missing argument is reported before a wrongly typed one",
    "G6": "an unknown tool is refused with 'tool_not_allowlisted'",
}

_CHECK = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),  # G4
    "boolean": lambda v: isinstance(v, bool),
}


class NaiveDecider:
    def __init__(self, policy: Dict[str, Any]) -> None:
        self.tools = policy["tools"]

    def decide(self, item: Any) -> Tuple[str, Optional[str], None]:
        if not isinstance(item, dict) or not isinstance(item.get("tool"), str):
            return "DENY", "malformed_call", None
        args = item.get("args")
        if not isinstance(args, dict):
            return "DENY", "args_not_object", None
        spec = self.tools.get(item["tool"])
        if spec is None:
            return "DENY", "tool_not_allowlisted", None  # G6
        declared: Dict[str, str] = spec.get("args") or {}
        for arg in sorted(declared):  # G1, G5
            if arg not in args:
                return "DENY", f"missing:{arg}", None  # G3
        for arg in sorted(declared):
            if not _CHECK[declared[arg]](args[arg]):  # G4
                return "DENY", f"type:{arg}", None  # G3
        for arg in sorted(args):  # G2
            if arg not in declared:
                return "DENY", f"undeclared:{arg}", None
        return "ALLOW", None, None
