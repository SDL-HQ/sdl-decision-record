"""F2: request construction drops a context key the policy reads.

One change: `approved_intent` is removed from the context before evaluation.
Policy p7 permits a transfer only when `context.intent_ref ==
context.approved_intent`; with the key absent the attribute access errors, p7
does not contribute, and a transfer the policy would have permitted is denied.
The direction is a wrongful denial rather than a wrongful permit, and it is
invisible for the same reason F1 is: the request shape is not in the policy.
"""
from emitters import cedar as _honest

DECIDER_ID = _honest.DECIDER_ID
DECIDER_VERSION = _honest.DECIDER_VERSION
OUTCOMES = _honest.OUTCOMES


class Decider(_honest.Decider):
    def decide(self, item):
        if isinstance(item, dict) and isinstance(item.get("context"), dict) and "approved_intent" in item["context"]:
            item = {**item, "context": {k: v for k, v in item["context"].items() if k != "approved_intent"}}
        return super().decide(item)
