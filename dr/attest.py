"""Decider attestations: the decider's own signature over each decision, made when it decides.

A row is the producer's word on what the decider said. Replay re-decides the
retained inputs and checks the rows against the named decider, but a row
whose outcome the decider would also have given is consistent with the
decider having run and with it never having been called. An attestation is
what closes it:
the decider, holding a key the producer does not, signs each decision as it
makes it, and the verifier requires one per row, under a key in a decider
registry whose material is not any producer key.

    {"kind": "decider-attestation", "record_id": ..., "seq": n, "input_digest": ..., "outcome": ...,
     "reason": ..., "policy_digest": ..., "decider": "<id>@<version>", "decider_key_id": ...,
     "payload_hash": ..., "signature": ...}

The body is the decision the decider knows it made, bound to the run and the
sequence number the producer told it; it is not the row hash, which the
producer computes afterwards from fields of its own (timestamp, chain). The
verifier matches every row to its attestation on the fields they share. A
producer that did not call the decider has nothing to attach and no key to
forge one with. What this does not establish: that the decider's key was
not also the producer's; the independence check is on key material, as for
witnesses, and is organisational beyond that.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .registry import resolve
from .signing import SignatureCheckRaised, sign_record, verify_signature
from .witness import _public_key_material
from .canonical import read_jsonl, loads as strict_loads

ATTESTATIONS_FILE = "attestations.jsonl"
KIND = "decider-attestation"
FIELDS = ("record_id", "seq", "input_digest", "outcome", "reason", "policy_digest", "decider")


ARRIVAL_KEY = "arrival"  # the row's ext key naming its arrival (tools/arrive.py EXT_KEY), echoed in the body


def attest(row: Dict[str, Any], *, record_id: str, decider_key_id: str, private_key_pem: bytes, arrival: Optional[int] = None) -> Dict[str, Any]:
    body = {"kind": KIND, "record_id": record_id, "seq": row["seq"], "input_digest": row["input_digest"], "outcome": row["outcome"], "reason": row["reason"],
            "policy_digest": row["policy_digest"], "decider": row["decider"], "decider_key_id": decider_key_id}
    if arrival is not None:
        # The arrival identifier reaches the decider from the attester with the input,
        # not from the producer afterwards, so it may be in the body (SPEC section 15).
        body[ARRIVAL_KEY] = arrival
    return sign_record(body, private_key_pem)


def load(path: Path) -> List[Dict[str, Any]]:
    return [strict_loads(l) for _, l in read_jsonl(path)]


def check(attestations: List[Dict[str, Any]], record: Dict[str, Any], rows: List[Dict[str, Any]], decider_registry: Dict[str, Any], producer_registry: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    """(state, detail) for the invocation property."""
    by_seq: Dict[int, Dict[str, Any]] = {}
    for a in attestations:
        if not isinstance(a, dict) or a.get("kind") != KIND or not isinstance(a.get("seq"), int):
            return "failed", "an attestation is not a decider attestation"
        if a["seq"] in by_seq:
            return "failed", f"two attestations for seq {a['seq']}"
        by_seq[a["seq"]] = a
    missing = [r["seq"] for r in rows if r["seq"] not in by_seq]
    if missing:
        return "failed", f"{len(missing)} of {len(rows)} rows have no decider attestation (seq {missing[:6]}{'…' if len(missing) > 6 else ''}): the producer wrote them and no decider signed them"
    extra = sorted(set(by_seq) - {r["seq"] for r in rows})
    if extra:
        return "failed", f"attestations for seq {extra[:6]} name decisions the record does not have"
    producer_material = set()
    for entry in (producer_registry or {}).get("keys", []):
        m = _public_key_material(entry.get("public_key_pem")) if isinstance(entry, dict) else None
        if m is not None:
            producer_material.add(m)
    keys_seen = set()
    for r in rows:
        a = by_seq[r["seq"]]
        want = {"record_id": record["record_id"], "seq": r["seq"], "input_digest": r["input_digest"], "outcome": r["outcome"], "reason": r["reason"], "policy_digest": r["policy_digest"], "decider": r["decider"]}
        got = {k: a.get(k) for k in FIELDS}
        if got != want:
            diff = sorted(k for k in FIELDS if got[k] != want[k])
            return "failed", f"seq {r['seq']}: the attestation does not match the row on {diff}; the row is not what the decider signed"
        if ARRIVAL_KEY in a:
            # The decider signed which arrival it decided; the row must name the same one.
            named = r.get("ext", {}).get(ARRIVAL_KEY) if isinstance(r.get("ext"), dict) else None
            if named != a[ARRIVAL_KEY]:
                return "failed", f"seq {r['seq']}: the decider signed arrival {a[ARRIVAL_KEY]} and the row names {named!r}; the row was re-pointed after the decision"
        state, detail, pem = resolve(decider_registry, a.get("decider_key_id"), a.get("payload_hash"))
        if state != "honoured":
            return ("unknown" if state == "unknown" else "failed"), f"seq {r['seq']}: {detail}"
        material = _public_key_material(pem)
        if material is None:
            return "unknown", f"seq {r['seq']}: the decider key could not be parsed"
        if material in producer_material:
            return "unknown", f"seq {r['seq']}: the decider key {a.get('decider_key_id')!r} is also a producer key; a producer attesting its own rows establishes nothing"
        try:
            ok, why = verify_signature(a, pem)
        except SignatureCheckRaised as exc:
            return "unknown", f"seq {r['seq']}: the signature check could not be performed: {exc}"
        if not ok:
            return "failed", f"seq {r['seq']}: the attestation's signature does not verify under {a.get('decider_key_id')!r}: {why}"
        keys_seen.add(a.get("decider_key_id"))
    return "established", f"every one of the {len(rows)} rows carries a decision the decider signed under {sorted(keys_seen)} at decision time, bound to this record and sequence; the producer could not have written these rows without the decider"
