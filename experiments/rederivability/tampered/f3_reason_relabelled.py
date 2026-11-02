"""F3: the reason mapping names a policy that did not determine the outcome.

One change: whenever the engine denies with no determining policy
(`no-policy-permits` — nothing in the policy set matched), the row instead
reports `policy5`, the traversal forbid, as though the call had been refused
by a named rule. Every outcome is the honest one. Only the account of why is
false, and the reason is the field a reader uses to attribute a refusal.
"""
from emitters import cedar as _honest

DECIDER_ID = _honest.DECIDER_ID
DECIDER_VERSION = _honest.DECIDER_VERSION
OUTCOMES = _honest.OUTCOMES


class Decider(_honest.Decider):
    def decide(self, item):
        outcome, reason, ext = super().decide(item)
        if outcome == "DENY" and reason == "no-policy-permits":
            return outcome, "policy5", ext
        return outcome, reason, ext
