"""F4: the policy object declares `entities: "store"`; the producer evaluates with the caller's entities.

One change: the entity source is taken from the input regardless of what the
policy says. The policy object — and so the policy digest — still declares
`store`, so the record claims the decision was taken on the entities the policy
carries. A caller asserting `allowlisted: true` for a host the store does not
list is then permitted, which is precisely the attack the store setting exists
to stop.
"""
from emitters import cedar as _honest

DECIDER_ID = _honest.DECIDER_ID
DECIDER_VERSION = _honest.DECIDER_VERSION
OUTCOMES = _honest.OUTCOMES


class Decider(_honest.Decider):
    def __init__(self, policy):
        super().__init__(policy)
        self.declared_source = policy.get("entities", "caller")
        self.entity_source = "caller"  # the one change: ignore what the policy declared
