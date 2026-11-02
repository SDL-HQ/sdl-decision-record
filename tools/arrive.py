"""Input arrivals: a party in front of the decider signs each input as it arrives.

The mirror of decider attestations (SPEC §15). An attestation establishes that
the producer could not have written a row's *decision* without the decider;
an arrival establishes that it could not have written the row's *input*
without the party that received it. The verifier's existing roof is exactly
this gap: `experiments/rederivability/out/f5-input-fabricated` establishes on
every property while its retained input at seq 24 is a call that never
arrived, honestly decided.

    {"kind": "input-arrival", "arrival_seq": n, "input_digest": "sha256:...",
     "attester_key_id": ..., "payload_hash": ..., "signature": ...}

Two things the attester cannot know, and the design follows from both:

- It signs before any row exists, so it cannot bind to a record id or a row
  sequence as a decider attestation does. It binds to the input's digest and
  to its own sequence number, and the *row* names the arrival (`ext.arrival`),
  which puts the link inside the row hash. A digest alone is not a link,
  because the same bytes arrive more than once (a rate limiter is meant to
  see them twice) and a retried request is two arrivals.
- It does not hold the run's salt, so it signs the plain `digest(input)`. For
  a version 2 row the verifier recomputes the plain digest from the retained
  input; without retained inputs a keyed row's arrival is unknown, not failed.

What makes it worth anything is who holds the key. The check is on key
material, as for witnesses and decider attestations: an attester key that is a
producer key establishes nothing, and an attester key that is the decider's
establishes nothing either, because then one party stands at both ends of the
decision. Beyond that the independence is organisational, and the addendum
says so first.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dr.canonical import canonical_input, digest_obj
from dr.record import INPUTS_FILE
from dr.registry import resolve
from dr.rows import is_keyed_digest
from dr.signing import SignatureCheckRaised, sign_record, verify_signature
from dr.witness import _public_key_material
from dr.canonical import read_jsonl, loads as strict_loads, loads_input

ARRIVALS_FILE = "arrivals.jsonl"
KIND = "input-arrival"
EXT_KEY = "arrival"
FIELDS = ("arrival_seq", "input_digest")


class LogNotContinuable(ValueError):
    """The attester's log is not a contiguous run of its own arrivals from 1,
    so there is no number to continue from that would not read as tampering."""


def resume_from(log_path: Path) -> int:
    """The last arrival_seq in an existing log, so that a restarted attester
    continues its numbering rather than starting again at 1.

    A restart is an ordinary event; numbering from 1 again made it produce
    two arrivals numbered N, which `accounted` fails as tampering. The log is
    read, not trusted: every complete line must be an arrival of this kind,
    numbered 1, 2, 3 … with no gap or repeat, or the attester refuses to open
    it (LogNotContinuable) rather than extend a log it cannot vouch for. One
    case is not refused: a final line with no newline that does not parse is a
    write cut short by a stop, and `arrive` returns only after the line and its
    newline are flushed, so that arrival was never handed to anyone; it is
    removed and the count continues from the last complete line."""
    path = Path(log_path)
    if not path.exists():
        return 0
    data = path.read_bytes()
    if not data:
        return 0
    complete, _, tail = data.rpartition(b"\n")
    if tail:
        try:
            strict_loads(tail.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            with open(path, "r+b") as f:  # the torn write: never returned, so never named by a row
                f.truncate(len(complete) + 1 if complete else 0)
                f.flush()
                os.fsync(f.fileno())
        else:
            raise LogNotContinuable(f"{path}: the last line is complete but has no newline; it was not written by this attester")
    last = 0
    for n, line in enumerate((complete.decode("utf-8").split("\n") if complete else []), start=1):  # LF only (jsonl_lines)
        if not line.strip(" \t\r"):
            raise LogNotContinuable(f"{path}: line {n} is empty")
        try:
            a = strict_loads(line)
        except ValueError:
            raise LogNotContinuable(f"{path}: line {n} is not an arrival")
        if not isinstance(a, dict) or a.get("kind") != KIND or not isinstance(a.get("arrival_seq"), int) or isinstance(a.get("arrival_seq"), bool):
            raise LogNotContinuable(f"{path}: line {n} is not an arrival")
        if a["arrival_seq"] != last + 1:
            raise LogNotContinuable(f"{path}: line {n} is arrival {a['arrival_seq']}, expected {last + 1}; the log is not a contiguous run from 1")
        last = a["arrival_seq"]
    return last


class Attester:
    """The party in front of the decider. Holds a key the producer does not.

    `arrive(input_obj)` signs the input's digest with the attester's own
    sequence number, appends the arrival to the attester's own log (flushed
    before it returns, so an abort cannot lose an arrival already signed), and returns it. The
    producer receives the arrival with the request and names it in the row.

    `arrive_text(text)` is the same for an input still in the form it arrived
    in, text or bytes: it reads it with `dr.canonical.loads_input`, the reader
    the gate's command line uses, and bytes are decoded as UTF-8 only, so a
    byte-order mark is refused as the gate refuses it. An attester and a gate that parse the same bytes with
    different readers can sign one value and decide another under one digest
    (a duplicate member name, a number with more digits than a double holds);
    given the text, both read it the one way or both refuse it (SEAMS.md).
    `arrive(obj)` takes a value someone else parsed, and that parser is theirs.
    """

    def __init__(self, log_path: Path, *, key_id: str, private_key_pem: bytes) -> None:
        self.log_path = Path(log_path)
        self.key_id = key_id
        self._pem = private_key_pem
        self._seq = resume_from(self.log_path)
        self._log = open(self.log_path, "a", encoding="utf-8")

    def arrive(self, input_obj: Any) -> Dict[str, Any]:
        value = canonical_input(input_obj)  # NotAnInput before a number is spent: no gate decides such an input
        self._seq += 1
        body = {"kind": KIND, "arrival_seq": self._seq, "input_digest": digest_obj(value), "attester_key_id": self.key_id}
        arrival = sign_record(body, self._pem)
        self._log.write(json.dumps(arrival, sort_keys=True) + "\n")
        self._log.flush()
        return arrival

    def arrive_text(self, text: str) -> Dict[str, Any]:
        return self.arrive(loads_input(text))  # refused before a number is spent, as arrive refuses

    def close(self) -> None:
        self._log.close()


def load(path: Path) -> List[Dict[str, Any]]:
    return [strict_loads(l) for _, l in read_jsonl(path)]


def _plain_digests(directory: Path, rows: List[Dict[str, Any]]) -> Tuple[Optional[Dict[int, str]], str]:
    """seq -> plain digest(input) for every row, from the row itself (v1) or the
    retained input (v2). (None, why) when a keyed row's input is not retained."""
    out: Dict[int, str] = {}
    keyed = [r for r in rows if is_keyed_digest(r["input_digest"])]
    if not keyed:
        return {r["seq"]: r["input_digest"] for r in rows}, ""
    p = directory / INPUTS_FILE
    if not p.exists():
        return None, "the rows carry keyed digests and no inputs are retained, so the plain digest the attester signed cannot be recomputed"
    lines = [strict_loads(l) for _, l in read_jsonl(p)]
    by_seq = {l["seq"]: l["input"] for l in lines if isinstance(l, dict) and "seq" in l}
    for r in rows:
        if r["seq"] not in by_seq:
            return None, f"seq {r['seq']}: no retained input to recompute the plain digest from"
        out[r["seq"]] = digest_obj(by_seq[r["seq"]])
    return out, ""


def check(
    arrivals: List[Dict[str, Any]],
    rows: List[Dict[str, Any]],
    directory: Path,
    attester_registry: Dict[str, Any],
    producer_registry: Optional[Dict[str, Any]],
    decider_registry: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """(state, detail) for the arrival property."""
    by_seq: Dict[int, Dict[str, Any]] = {}
    for a in arrivals:
        if not isinstance(a, dict) or a.get("kind") != KIND or not isinstance(a.get("arrival_seq"), int):
            return "failed", "an arrival is not an input arrival"
        if a["arrival_seq"] in by_seq:
            return "failed", f"two arrivals numbered {a['arrival_seq']}"
        by_seq[a["arrival_seq"]] = a

    # Every row names an arrival; no two rows name the same one.
    named: Dict[int, int] = {}
    unnamed = []
    for r in rows:
        ext = r.get("ext") if isinstance(r.get("ext"), dict) else {}
        n = ext.get(EXT_KEY)
        if not isinstance(n, int):
            unnamed.append(r["seq"])
            continue
        if n in named:
            return "failed", f"rows {named[n]} and {r['seq']} both name arrival {n}: one input, decided twice by the producer's own account"
        named[n] = r["seq"]
    if unnamed:
        return "failed", f"{len(unnamed)} of {len(rows)} rows name no arrival (seq {unnamed[:6]}{'…' if len(unnamed) > 6 else ''}): the producer wrote them and no one signed their inputs as received"
    absent = sorted(n for n in named if n not in by_seq)
    if absent:
        return "failed", f"rows name arrivals {absent[:6]} that the log does not have"

    plain, why = _plain_digests(directory, rows)
    if plain is None:
        return "unknown", why

    def material_of(reg: Optional[Dict[str, Any]]) -> set:
        out = set()
        for entry in (reg or {}).get("keys", []):
            m = _public_key_material(entry.get("public_key_pem")) if isinstance(entry, dict) else None
            if m is not None:
                out.add(m)
        return out

    producer_material = material_of(producer_registry)
    decider_material = material_of(decider_registry)
    keys_seen = set()
    for r in rows:
        a = by_seq[r["ext"][EXT_KEY]]
        if a["input_digest"] != plain[r["seq"]]:
            return "failed", f"seq {r['seq']}: the retained input is not what arrived; arrival {a['arrival_seq']} was signed over a different input"
        state, detail, pem = resolve(attester_registry, a.get("attester_key_id"), a.get("payload_hash"))
        if state != "honoured":
            return ("unknown" if state == "unknown" else "failed"), f"seq {r['seq']}: {detail}"
        material = _public_key_material(pem)
        if material is None:
            return "unknown", f"seq {r['seq']}: the attester key could not be parsed"
        if material in producer_material:
            return "unknown", f"seq {r['seq']}: the attester key {a.get('attester_key_id')!r} is also a producer key; a producer attesting its own inputs establishes nothing"
        if material in decider_material:
            return "unknown", f"seq {r['seq']}: the attester key {a.get('attester_key_id')!r} is also the decider's key; one party at both ends of the decision establishes nothing about the input"
        try:
            ok, why = verify_signature(a, pem)
        except SignatureCheckRaised as exc:
            return "unknown", f"seq {r['seq']}: the signature check could not be performed: {exc}"
        if not ok:
            return "failed", f"seq {r['seq']}: the arrival's signature does not verify under {a.get('attester_key_id')!r}: {why}"
        keys_seen.add(a.get("attester_key_id"))
    unmatched = len(by_seq) - len(named)
    tail = f"; the log holds {unmatched} arrival(s) no row names, which this property does not judge" if unmatched else ""
    return "established", f"every one of the {len(rows)} rows carries an input that {sorted(keys_seen)} signed as received before it was decided, and the row names which arrival; the producer could not have written these inputs without the attester{tail}"


# --- completeness from the attester's log------------------------------------

def accounted(
    arrivals: List[Dict[str, Any]],
    rows: List[Dict[str, Any]],
    *,
    from_attester: bool,
    prior_rows: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[str, str, Optional[Dict[str, Any]]]:
    """(state, detail, range) for the `arrivals_accounted` property. `range` is
    `{"first", "last", "accounted"}` — the bounds the state is about and how
    many arrivals inside them have a row — reported as a field beside the
    state, because a consumer thresholding over states (SPEC section 9's use)
    never reads the detail, and "established" without its bounds reads as
    complete for the period.

    The arrivals a record's rows name have a first and a last number. Every
    arrival the attester logged between them that no row names is one the
    producer received and recorded no decision for. That is the input-side
    analogue of a receipt for a decision the record lacks (§13), with a
    difference: the attester's own log is complete for its endpoint by
    construction, so from that copy the middle can be established, not only
    refuted. From the copy the record retains it cannot, because that copy is
    the producer's selection, so the state is n/a — not claimed — unless that
    copy itself shows a gap, which refutes whichever copy it came from.

    The copy's own numbering is judged first: the attester numbers without
    holes, so a number missing inside the range means a signed arrival was
    removed from the copy, and that fails from either copy. Without
    this, a producer that dropped a decision and the matching arrival from the
    log it handed over would be accounted for.

    Arrivals before the first named or after the last are not judged; they
    belong to neighbouring records. With the prior record's rows (a stream),
    the gap between its last named arrival and this record's first is judged
    too, which closes the seam.
    """
    numbered = {a["arrival_seq"] for a in arrivals if isinstance(a, dict) and isinstance(a.get("arrival_seq"), int)}
    named = sorted({r["ext"][EXT_KEY] for r in rows if isinstance(r.get("ext"), dict) and isinstance(r["ext"].get(EXT_KEY), int)})
    if not named:
        return "unknown", "no row names an arrival, so there is no range to account for", None
    lo, hi = named[0], named[-1]
    if prior_rows:
        prior_named = sorted({r["ext"][EXT_KEY] for r in prior_rows if isinstance(r.get("ext"), dict) and isinstance(r["ext"].get(EXT_KEY), int)})
        if prior_named:
            lo = prior_named[-1] + 1
    # The attester numbers arrivals 1, 2, 3 ... with no holes, so a copy missing a
    # number inside the judged range is not the attester's complete log: an entry
    # it signed has been taken out, and whatever that entry was, the range cannot
    # be accounted for from this copy. That refutes the copy, whichever it is.
    holes = [n for n in range(lo, hi + 1) if n not in numbered]
    in_range = {n for n in numbered if lo <= n <= hi}
    unaccounted = sorted(in_range - set(named))
    rng = {"first": lo, "last": hi, "accounted": len(in_range) - len(unaccounted)}
    if holes:
        return "failed", f"between {lo} and {hi}: the log has no arrival numbered {holes[:6]}{'…' if len(holes) > 6 else ''}; the attester numbers every arrival, so this copy has had {len(holes)} signed arrival(s) removed and is not its complete log", rng
    if unaccounted:
        return "failed", f"between {lo} and {hi}: {len(unaccounted)} arrival(s) have no row (arrival {unaccounted[:6]}{'…' if len(unaccounted) > 6 else ''}); the attester signed them as received and the record has no decision for them", rng
    if not from_attester:
        return "n/a", f"between {lo} and {hi}: not claimed — every arrival the record retains in that range has a row, but the retained copy is the producer's selection; the attester's own log (--arrival-log) is what can establish this", rng
    return "established", f"between {lo} and {hi}: every one of the {len(in_range)} arrivals the attester logged in that range has a row; the record omitted no decision in that range, and claims nothing outside it" + ("" if prior_rows is None else " (the range begins after the prior record's last arrival)"), rng
