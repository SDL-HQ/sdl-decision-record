"""F1: the canonicalisation step is widened to fold confusable characters.

One change, in the host operation: Cyrillic/Greek lookalikes are mapped to
their Latin counterparts before IDNA encoding. The honest operation turns
`аpi.example.com` (Cyrillic а) into `xn--pi-6kc.example.com`, which the
policy's store does not list, so the request is denied. This one turns it into
`api.example.com`, which is allow-listed, so it is permitted.

Nothing else differs. The policy object is unchanged and its digest is the
honest one, because the key map and the host operation are not in it.
"""
from emitters import cedar as _honest

DECIDER_ID = _honest.DECIDER_ID
DECIDER_VERSION = _honest.DECIDER_VERSION
OUTCOMES = _honest.OUTCOMES

_CONFUSABLES = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i", "ѕ": "s"})


_REAL_HOST = _honest.canonical_host  # bound once, so the replacement does not call itself


def _widened_host(h: str) -> str:
    return _REAL_HOST(h.translate(_CONFUSABLES))


class Decider(_honest.Decider):
    def decide(self, item):
        _honest.canonical_host = _widened_host
        try:
            return super().decide(item)
        finally:
            _honest.canonical_host = _REAL_HOST
