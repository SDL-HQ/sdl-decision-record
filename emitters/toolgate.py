"""toolgate: a tool-call allowlist with typed argument schemas.

Input: {"tool": <name>, "args": {<name>: <value>, ...}}
Policy: {"tools": {<name>: {"args": {<arg>: "string"|"integer"|"number"|"boolean"}}}}

ALLOW when the tool is allowlisted, every declared argument is present with
the declared JSON type, and no undeclared argument is present. DENY otherwise,
with the first defect found as the reason, in a fixed check order so the reason
is as deterministic as the outcome.

Decides on structure and type only. Never on the content of any string.

Policy may also carry `"reason_detail": "fine" | "coarse"` (default fine). Under
coarse, a DENY reason names the kind of defect and not the argument:
`arg_missing`, `arg_type`, `arg_undeclared`. The decision is the same; the row
says less about the schema (experiments/leakage). Replay matches either way
because the decider reads the setting from the same policy the rows digest.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

DECIDER_ID = "toolgate"
DECIDER_VERSION = "1.0.0"
OUTCOMES = ("ALLOW", "DENY")

_TYPES = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
}


class Decider:
    def __init__(self, policy: Dict[str, Any]) -> None:
        tools = policy.get("tools")
        if not isinstance(tools, dict):
            raise ValueError("policy.tools must be an object")
        for name, spec in tools.items():
            for arg, typ in (spec.get("args") or {}).items():
                if typ not in _TYPES:
                    raise ValueError(f"tool {name!r} arg {arg!r}: unknown type {typ!r}")
        self.tools = tools
        detail = policy.get("reason_detail", "fine")
        if detail not in ("fine", "coarse"):
            raise ValueError("policy.reason_detail must be \"fine\" or \"coarse\"")
        self.coarse = detail == "coarse"

    def _why(self, kind: str, arg: str) -> str:
        return kind if self.coarse else f"{kind}:{arg}"

    def decide(self, item: Any) -> Tuple[str, Optional[str], Optional[Dict[str, Any]]]:
        if not isinstance(item, dict) or not isinstance(item.get("tool"), str):
            return "DENY", "malformed_call", None
        tool = item["tool"]
        args = item.get("args")
        if not isinstance(args, dict):
            return "DENY", "args_not_object", None
        spec = self.tools.get(tool)
        if spec is None:
            return "DENY", "tool_not_allowlisted", None
        declared: Dict[str, str] = spec.get("args") or {}
        for arg in sorted(declared):
            if arg not in args:
                return "DENY", self._why("arg_missing", arg), None
            if not _TYPES[declared[arg]](args[arg]):
                return "DENY", self._why("arg_type", arg), None
        for arg in sorted(args):
            if arg not in declared:
                return "DENY", self._why("arg_undeclared", arg), None
        return "ALLOW", None, None


def main(argv=None) -> int:
    import sys
    from ._cli import run_emitter

    return run_emitter(sys.modules[__name__], argv)


if __name__ == "__main__":
    raise SystemExit(main())
