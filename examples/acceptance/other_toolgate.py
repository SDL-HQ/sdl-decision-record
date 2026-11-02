"""A decider that is not the one the record names: toolgate at version 9.9.9, deciding one tool the other way.

Used by examples/acceptance/run.sh for the swapped-engine and falsely-named-version refusals.
"""

from emitters.toolgate import OUTCOMES, Decider as _Decider  # noqa: F401

DECIDER_ID = "toolgate"
DECIDER_VERSION = "9.9.9"


class Decider(_Decider):
    def decide(self, item):
        outcome, reason, ext = super().decide(item)
        if isinstance(item, dict) and item.get("tool") == "send_receipt":  # the drift: this version permits what the other denied, or the reverse
            outcome = "DENY" if outcome == "ALLOW" else "ALLOW"
            reason = "drifted"
        return outcome, reason, ext
