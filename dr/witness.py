"""Witness statements: a second party's countersignature over a record's payload hash.

What a witness statement establishes is narrow and should be read narrowly:
that a record with exactly this payload_hash existed when the witness signed,
by a key the reader's witness registry honours. It says nothing about rows the
producer left out before the witness saw the record. Combined with a stream
(SPEC §12), it fixes the sequence from that point: a producer cannot replace a
witnessed record without the next record's prev_record_hash pointing at a
document the witness never saw.

    {
      "kind": "sdl-witness-statement",
      "record_payload_hash": the witnessed record's payload_hash,
      "witnessed_at": UTC time by the witness's clock,
      "witness_key_id", "payload_hash", "signature"
    }

Witnesses have their own registry, in the same format as the producer's. A
producer witnessing its own record proves nothing, so the verifier compares
the witness key's *material* against every key in the producer registry and
reports a match as unknown, whatever identifier either registry gives the key.
A comparison on key identifiers would be a tie-break on names, not an
independence test: a producer key enrolled in the witness registry under a
second name would witness itself.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from cryptography.hazmat.primitives import serialization

from .canonical import is_digest
from .registry import resolve
from .signing import SignatureCheckRaised, payload_hash, sign_record, verify_signature
from .canonical import loads as strict_loads

WITNESS_KIND = "sdl-witness-statement"
WITNESS_KEYS = frozenset({"kind", "record_payload_hash", "witnessed_at", "witness_key_id", "payload_hash", "signature"})
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _public_key_material(pem: Any):
    """The raw public key bytes behind a PEM, or None if it cannot be read.

    Two registries may encode or label one key differently; the bytes of the
    key are what identify the signer.
    """
    if not isinstance(pem, str) or not pem.strip():
        return None
    try:
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
        return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    except Exception:
        return None


def countersign(record_payload_hash: str, *, witness_key_id: str, private_key_pem: bytes, witnessed_at: str) -> Dict[str, Any]:
    return sign_record(
        {"kind": WITNESS_KIND, "record_payload_hash": record_payload_hash, "witnessed_at": witnessed_at, "witness_key_id": witness_key_id},
        private_key_pem,
    )


def statement_defects(statement: Dict[str, Any]) -> List[str]:
    if not isinstance(statement, dict):
        return ["statement is not an object"]
    if set(statement) != WITNESS_KEYS:
        return [f"statement keys are {sorted(statement)}, expected {sorted(WITNESS_KEYS)}"]
    d: List[str] = []
    if statement["kind"] != WITNESS_KIND:
        d.append(f"kind is {statement['kind']!r}")
    if not is_digest(statement["record_payload_hash"]):
        d.append("record_payload_hash is not a digest")
    if not isinstance(statement["witnessed_at"], str) or not TS_RE.match(statement["witnessed_at"]):
        d.append("witnessed_at is not YYYY-MM-DDTHH:MM:SSZ")
    if statement["payload_hash"] != payload_hash(statement):
        d.append("payload_hash does not recompute")
    return d


def check(statement: Dict[str, Any], record: Dict[str, Any], witness_registry: Dict[str, Any], producer_registry: Dict[str, Any]) -> Tuple[str, str]:
    """(state, detail): established / failed / unknown."""
    defects = statement_defects(statement)
    if defects:
        return "failed", "; ".join(defects)
    if statement["record_payload_hash"] != record["payload_hash"]:
        return "failed", f"the statement witnesses {statement['record_payload_hash']}, this record is {record['payload_hash']}"
    key_id = statement["witness_key_id"]
    state, detail, pem = resolve(witness_registry, key_id, statement["payload_hash"])
    if state != "honoured":
        return ("unknown" if state == "unknown" else "failed"), detail
    # Independence is a property of the key, not of its name. Compare the
    # witness key's material against every producer key; the identifiers the
    # two registries use are irrelevant to whether the same party signed both.
    witness_material = _public_key_material(pem)
    if witness_material is None:
        return "unknown", f"witness key {key_id!r} could not be parsed, so its independence from the producer cannot be decided"
    for entry in producer_registry.get("keys", []):
        if not isinstance(entry, dict):
            continue
        producer_material = _public_key_material(entry.get("public_key_pem"))
        if producer_material is None:
            return "unknown", f"producer key {entry.get('key_id')!r} could not be parsed, so the witness key's independence cannot be decided"
        if producer_material == witness_material:
            producer_id = entry.get("key_id")
            named = f"as {producer_id!r}" if producer_id != key_id else "under the same id"
            return "unknown", f"witness key {key_id!r} is also a producer key ({named} in the producer registry); a producer witnessing itself establishes nothing"
    try:
        ok, why = verify_signature(statement, pem)
    except SignatureCheckRaised as exc:
        return "unknown", f"the witness signature check could not be performed: {exc}"
    if not ok:
        return "failed", "the witness signature does not verify"
    return "established", f"witness {key_id!r} signed this record's payload_hash at {statement['witnessed_at']}; it bounds nothing before that"


def main(argv=None) -> int:
    """python3 -m dr.witness <record.json> --key witness.pem --key-id w1 --witnessed-at <UTC> [--out statement.json]"""
    import argparse
    import json
    from pathlib import Path

    ap = argparse.ArgumentParser(description="Countersign a record's payload_hash as a witness.")
    ap.add_argument("record", help="the record.json to witness")
    ap.add_argument("--key", required=True, help="the witness's Ed25519 private key PEM")
    ap.add_argument("--key-id", required=True, help="the witness registry key id")
    ap.add_argument("--witnessed-at", required=True, help="UTC time, YYYY-MM-DDTHH:MM:SSZ, by the witness's clock")
    ap.add_argument("--out", default=None, help="write the statement here; default stdout")
    args = ap.parse_args(argv)
    record = strict_loads(Path(args.record).read_text(encoding="utf-8"))
    if payload_hash(record) != record.get("payload_hash"):
        raise SystemExit("refusing to witness a record whose payload_hash does not recompute")
    st = countersign(record["payload_hash"], witness_key_id=args.key_id, private_key_pem=Path(args.key).read_bytes(), witnessed_at=args.witnessed_at)
    text = json.dumps(st, indent=2, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}: witnessed {record['payload_hash']}")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
