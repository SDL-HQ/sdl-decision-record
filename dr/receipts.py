"""Decision receipts: the producer's signed acknowledgement of one decision,
handed to the party the decision was about, at the time it was made.

A record cannot establish its own completeness (SPEC §11, §13). What it can do
is make omission detectable by someone else. A receipt is the producer saying,
under its key, "decision `seq` of run `record_id` exists and its row hashes to
`row_hash`". The producer cannot later publish a record of that run without
that row and keep the receipt holder from noticing. It can still omit a
decision it never receipted; a receipt is evidence about one decision, not a
bound on all of them.

    {
      "kind": "sdl-decision-receipt",
      "record_id": the run the decision belongs to,
      "seq": the row's seq within the run,
      "decision_no": the stream-wide decision number, or seq when there is no stream,
      "stream_id": the stream, or null,
      "row_hash": the row's row_hash,
      "ts": the row's ts,
      "signing_key_id", "payload_hash", "signature": as for a record
    }

Receipts are not retained in the run directory. A receipt kept beside the
record it attests would be deleted with the row it attests; its value is that
it is held elsewhere.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .canonical import is_digest
from .registry import resolve
from .signing import SignatureCheckRaised, payload_hash, sign_record, verify_signature

RECEIPT_KIND = "sdl-decision-receipt"
RECEIPT_KEYS = frozenset(
    {"kind", "record_id", "seq", "decision_no", "stream_id", "row_hash", "ts", "signing_key_id", "payload_hash", "signature"}
)


def issue(
    row: Dict[str, Any],
    *,
    record_id: str,
    stream_id: Optional[str],
    first_decision: int,
    signing_key_id: str,
    private_key_pem: bytes,
) -> Dict[str, Any]:
    receipt = {
        "kind": RECEIPT_KIND,
        "record_id": record_id,
        "seq": row["seq"],
        "decision_no": first_decision + row["seq"] - 1,
        "stream_id": stream_id,
        "row_hash": row["row_hash"],
        "ts": row["ts"],
        "signing_key_id": signing_key_id,
    }
    return sign_record(receipt, private_key_pem)


def receipt_defects(receipt: Dict[str, Any]) -> List[str]:
    d: List[str] = []
    if not isinstance(receipt, dict):
        return ["receipt is not an object"]
    if set(receipt) != RECEIPT_KEYS:
        d.append(f"receipt keys are {sorted(receipt)}, expected {sorted(RECEIPT_KEYS)}")
        return d
    if receipt["kind"] != RECEIPT_KIND:
        d.append(f"kind is {receipt['kind']!r}")
    for k in ("seq", "decision_no"):
        v = receipt[k]
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            d.append(f"{k} must be a positive integer")
    if not is_digest(receipt["row_hash"]):
        d.append("row_hash is not a digest")
    if receipt["payload_hash"] != payload_hash(receipt):
        d.append("payload_hash does not recompute")
    return d


def check(
    receipt: Dict[str, Any],
    record: Dict[str, Any],
    rows: List[Dict[str, Any]],
    registry: Dict[str, Any],
) -> Tuple[str, str]:
    """One receipt against one verified record and its rows.

    Returns (state, detail) where state is one of:
      "included"   the receipted decision is in the record, unchanged
      "missing"    the receipt names a seq beyond the record's rows: a decision
                   the producer acknowledged and did not publish
      "altered"    the seq is in range and the row there is not the receipted row
      "foreign"    the receipt is for another run; says nothing about this one
      "invalid"    the receipt itself does not verify (shape, signature, trust)
      "unknown"    the receipt's signature could not be checked
    """
    defects = receipt_defects(receipt)
    if defects:
        return "invalid", "; ".join(defects)
    state, detail, pem = resolve(registry, receipt["signing_key_id"], receipt["payload_hash"])
    if state == "unknown":
        return "unknown", detail
    if state == "failed":
        return "invalid", detail
    try:
        ok, why = verify_signature(receipt, pem)
    except SignatureCheckRaised as exc:
        return "unknown", f"the receipt's signature check could not be performed: {exc}"
    if not ok:
        return "invalid", "the receipt's signature does not verify"
    if receipt["record_id"] != record["record_id"]:
        return "foreign", f"receipt is for run {receipt['record_id']!r}, this record is {record['record_id']!r}"
    stream = record.get("stream")
    if stream is not None:
        if receipt["stream_id"] != stream["stream_id"]:
            return "foreign", f"receipt names stream {receipt['stream_id']!r}, this record is in {stream['stream_id']!r}"
        expected_no = stream["first_decision"] + receipt["seq"] - 1
        if receipt["decision_no"] != expected_no:
            return "altered", f"receipt says decision {receipt['decision_no']} is seq {receipt['seq']}; this record's numbering puts seq {receipt['seq']} at decision {expected_no}"
    elif receipt["stream_id"] is not None or receipt["decision_no"] != receipt["seq"]:
        return "foreign", "receipt carries stream numbering and this record has no stream"
    seq = receipt["seq"]
    if seq > len(rows):
        return "missing", f"the producer acknowledged decision seq {seq} of this run at {receipt['ts']}; the record has {len(rows)} rows"
    row = rows[seq - 1]
    if row["row_hash"] != receipt["row_hash"]:
        return "altered", f"seq {seq}: the receipted row_hash {receipt['row_hash']} is not the row in the record ({row['row_hash']})"
    return "included", f"seq {seq} is in the record with the receipted row_hash"
