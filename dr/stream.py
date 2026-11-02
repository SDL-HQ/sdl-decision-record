"""Streams: a sequence of records, each committing to the one before it.

    python3 -m dr.stream record1.json record2.json ...   # check a sequence, report forks

A stream moves the completeness problem; it does not solve it, and the point
of this module is to say exactly how far it moves it:

- A verifier holding only record N learns that N claims a predecessor with a
  given payload_hash. It learns nothing about whether rows were omitted from N
  or from any earlier record.
- A verifier holding records 1..N learns that no record was removed from the
  middle (seq contiguous, each prev_record_hash matches, first_decision
  advances by exactly the previous row_count). It learns nothing about rows
  omitted before signing, and nothing about records N+1.. that were signed
  and then withheld. Tail truncation is undetectable from the records alone.
- A verifier who saw record K at some earlier time, and now sees a different
  record claiming (stream_id, seq K), has caught an equivocation: the producer
  signed two histories. That is the one thing a stream makes detectable that a
  single record cannot, and it needs the second observation to exist.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .signing import payload_hash
from .canonical import NotCanonicalisable, NotJSON
from .canonical import loads as strict_loads


# Why a record's identity could or could not be computed. A reason, not a
# bool: "this document cannot be hashed" is about the document and "the
# verifier's hashing raised" is about the verifier, and a caller that cannot
# tell them apart reports both as the document's defect.
IDENTITY_OK = "ok"
IDENTITY_NOT_A_RECORD = "not-a-record"          # not an object, or lacking the fields hashing reads
IDENTITY_NO_CANONICAL_FORM = "no-canonical-form"  # a value RFC 8785 has no rendering for
# Anything else raised while hashing is the verifier's own fault. It is not
# returned as a reason: it propagates to the command's guard, which exits 3,
# "nothing was judged". Returned as a reason, a caller would report it as the
# document's defect, exit 1, which is a verdict the document did not earn.


def identity(record: Any) -> Tuple[str, str]:
    """A record's payload_hash computed from its own fields, never read from the
    copy it carries: that copy is a second statement of the identity a link is
    meant to check, and an edited body keeps it unchanged.

    Returns (IDENTITY_OK, payload_hash) or (reason, what happened). Any other
    exception is the verifier's and propagates."""
    if not isinstance(record, dict):
        return IDENTITY_NOT_A_RECORD, f"the document is a {type(record).__name__}, not a record object"
    try:
        return IDENTITY_OK, payload_hash(record)
    except NotCanonicalisable as exc:
        return IDENTITY_NO_CANONICAL_FORM, f"the document holds a value with no canonical form: {exc}"


def link_check(record: Dict[str, Any], prior: Optional[Dict[str, Any]]) -> Tuple[str, List[str]]:
    """Does `record` follow `prior`? ("established" | "failed" | "unknown", reasons).

    Failed is a statement about the record: it names a predecessor this prior
    is not. Unknown is a statement about the check: the prior supplied cannot
    be read as a record, or the verifier could not hash it, so nothing about
    the record follows. A prior whose stated payload_hash does not recompute
    but whose fields do hash to what the record names is the predecessor, with
    a corrupted copy of its own identity; the link holds and the reason says so."""
    st = record.get("stream")
    if st is None:
        return "failed", ["the record has no stream block"]
    if st["seq"] == 1:
        return ("established", []) if prior is None else ("failed", ["the record is the first in its stream and a prior was supplied"])
    if prior is None:
        return "unknown", ["no prior record supplied"]
    why, computed = identity(prior)
    if why != IDENTITY_OK:
        return "unknown", [f"the prior supplied cannot be checked against: {computed}"]
    pst = prior.get("stream")
    if not isinstance(pst, dict) or not isinstance(prior.get("ledger"), dict):
        return "unknown", ["the prior supplied has no stream block or no ledger, so it is not a stream record to link to"]
    try:
        p_sid, p_seq, p_first, p_count = pst["stream_id"], pst["seq"], pst["first_decision"], prior["ledger"]["row_count"]
        expected_first = p_first + p_count
    except (KeyError, TypeError) as exc:
        return "unknown", [f"the prior supplied is not shaped as a stream record: {type(exc).__name__}: {exc}"]
    d: List[str] = []
    if p_sid != st["stream_id"]:
        d.append(f"stream_id: prior {p_sid!r}, record {st['stream_id']!r}")
    if p_seq + 1 != st["seq"]:
        d.append(f"seq: prior {p_seq}, record {st['seq']}; expected {p_seq + 1}")
    if computed != st["prev_record_hash"]:
        d.append(f"prev_record_hash {st['prev_record_hash']} is not the prior's payload_hash, computed from its fields: {computed}")
        if prior.get("payload_hash") != computed:
            d.append(f"the prior's stated payload_hash {prior.get('payload_hash')} does not recompute from its own fields; it was altered after it was signed")
    if st["first_decision"] != expected_first:
        d.append(f"first_decision: record says {st['first_decision']}, the prior's numbering continues at {expected_first}")
    if d:
        return "failed", d
    notes = []
    if prior.get("payload_hash") != computed:
        notes.append(f"the prior's own stated payload_hash {prior.get('payload_hash')} does not recompute; its fields do, and they are what this record names")
    return "established", notes


def link_defects(record: Dict[str, Any], prior: Optional[Dict[str, Any]]) -> List[str]:
    """Why `record` does not follow `prior`, or why that could not be checked. Empty means it does."""
    state, reasons = link_check(record, prior)
    if state == "established":
        return []
    return reasons if state == "failed" else [f"cannot check: {r}" for r in reasons]


def check_sequence(records: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    """Order records by (stream_id, seq); report link defects and equivocations.

    Returns (defects, forks). A fork is two distinct records claiming the same
    (stream_id, seq). Distinct means distinct computed payload_hash. A record
    whose identity cannot be computed is reported as a defect with the reason,
    and is grouped by the payload_hash it states, so two such records stating
    different hashes are still a fork and two stating the same one are not
    silently merged: each is named as unhashable.
    """
    by_pos: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
    for r in records:
        st = r.get("stream") if isinstance(r, dict) else None
        if st is None:
            continue
        by_pos.setdefault((st["stream_id"], st["seq"]), []).append(r)
    forks: List[str] = []
    defects: List[str] = []
    for (sid, seq), group in sorted(by_pos.items()):
        keys = set()
        for g in group:
            why, value = identity(g)
            if why == IDENTITY_OK:
                keys.add(value)
            else:
                stated = g.get("payload_hash")
                keys.add(f"stated {stated}")
                defects.append(f"stream {sid!r} seq {seq}: a record here cannot be hashed ({value}); grouped by the payload_hash it states, {stated}, which nothing here checks")
        # a computed hash and the same value stated by an unhashable record are one identity claim
        keys = {k[len("stated "):] if k.startswith("stated ") and k[len("stated "):] in keys else k for k in keys}
        if len(keys) > 1:
            forks.append(f"stream {sid!r} seq {seq}: {len(keys)} distinct records signed for the same position: {sorted(keys)}")
    streams = sorted({k[0] for k in by_pos})
    for sid in streams:
        seqs = sorted(k[1] for k in by_pos if k[0] == sid)
        if seqs[0] != 1:
            defects.append(f"stream {sid!r}: the earliest record held is seq {seqs[0]}; records 1..{seqs[0] - 1} are not here, and nothing here says whether they exist")
        for a, b in zip(seqs, seqs[1:]):
            if b != a + 1:
                defects.append(f"stream {sid!r}: records {a + 1}..{b - 1} are not here")
                continue
            for rec in by_pos[(sid, b)]:
                for prior in by_pos[(sid, a)]:
                    for defect in link_defects(rec, prior):
                        defects.append(f"stream {sid!r} seq {b} after {a}: {defect}")
    return defects, forks


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Check a sequence of stream records for linkage and forks.")
    ap.add_argument("records", nargs="+", help="record.json files")
    args = ap.parse_args(argv)
    try:  # the whole command, reading and output included: exit 1 here means "defects found"
        return _check(args.records)
    except Exception as exc:  # noqa: BLE001 — a fault in the verifier must not exit with a verdict's code
        print(f"VERIFIER ERROR: {type(exc).__name__}: {exc} -- a fault in the verifier, not a verdict about the records; nothing was judged", file=sys.stderr)
        return 3


def _check(paths: List[str]) -> int:
    records = []
    for p in paths:
        try:
            records.append(strict_loads(Path(p).read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:  # NotJSON is a ValueError
            print(f"ERROR: {p} could not be read as a record: {exc}", file=sys.stderr)
            return 3
    outside = [p for p, r in zip(paths, records) if not (isinstance(r, dict) and r.get("stream"))]
    if len(outside) == len(records):
        print("ERROR: none of the records given is part of a stream, so there is no sequence to check; nothing was judged", file=sys.stderr)
        return 3
    for p in outside:
        print(f"NOTE   {p} is not part of a stream and was not checked")
    defects, forks = check_sequence(records)
    for f in forks:
        print(f"FORK   {f}")
    for d in defects:
        print(f"DEFECT {d}")
    if not forks and not defects:
        held = sorted((r["stream"]["stream_id"], r["stream"]["seq"]) for r in records if isinstance(r, dict) and r.get("stream"))
        print(f"OK: {len(held)} records link in sequence: {held[0][1]}..{held[-1][1]}. Nothing here says whether a record after {held[-1][1]} exists.")
    return 2 if forks else (1 if defects else 0)


if __name__ == "__main__":
    raise SystemExit(main())
