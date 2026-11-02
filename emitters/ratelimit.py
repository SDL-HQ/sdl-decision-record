"""ratelimit: a sliding-window request limit per principal.

Input: {"principal": <string>, "at": <integer seconds>}
Policy: {"window_seconds": <int>, "max_requests": <int>}

ALLOW when, counting this request, the principal has made at most max_requests
requests whose `at` lies within the last window_seconds (inclusive of the
window's start). DENY otherwise. The reason on a DENY is "window_exceeded";
the ext block carries the count the decision was taken on, so the row says
what the decider saw.

This decider is stateful: the decision for seq n depends on the inputs at seq
1..n-1 for the same principal. That is the point of including it. A stateless
decider can be replayed one row at a time; this one can be replayed only over
the whole ledger in order, from a fresh state. The format handles it because
inputs are retained in sequence and replay re-decides them in sequence, but a
reader should know that a single row of this decider is not independently
re-derivable, and the spec says so.

Requests are not required to arrive in time order; a request with an earlier
`at` than one already seen is still counted against the window it falls in.
The decision depends only on the inputs, in sequence.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

DECIDER_ID = "ratelimit"
DECIDER_VERSION = "1.0.0"
OUTCOMES = ("ALLOW", "DENY")


class Decider:
    def __init__(self, policy: Dict[str, Any]) -> None:
        w, m = policy.get("window_seconds"), policy.get("max_requests")
        if not (isinstance(w, int) and w > 0 and isinstance(m, int) and m >= 0):
            raise ValueError("policy needs positive integer window_seconds and non-negative integer max_requests")
        self.window = w
        self.max = m
        self.seen: Dict[str, List[int]] = defaultdict(list)

    def decide(self, item: Any) -> Tuple[str, Optional[str], Optional[Dict[str, Any]]]:
        if not isinstance(item, dict) or not isinstance(item.get("principal"), str) or not item["principal"]:
            return "DENY", "malformed_request", None
        at = item.get("at")
        if isinstance(at, bool) or not isinstance(at, int):
            return "DENY", "malformed_request", None
        history = self.seen[item["principal"]]
        history.append(at)
        in_window = sum(1 for t in history if at - self.window < t <= at)
        ext = {"window_count": in_window}
        if in_window > self.max:
            return "DENY", "window_exceeded", ext
        return "ALLOW", None, ext


def main(argv=None) -> int:
    import sys
    from ._cli import run_emitter

    return run_emitter(sys.modules[__name__], argv)


if __name__ == "__main__":
    raise SystemExit(main())
