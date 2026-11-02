"""Writing a run: rows as decisions happen, then a record over what was written.

The record is built from the rows re-read from disk, not from the objects in
memory, and the figures in it come from dr.derive, the same functions the
verifier runs. The emitter never writes a count it computed some other way.

Usage, from an emitter:

    run = Run(directory, decider_id="toolgate", decider_version="1.0.0",
              outcomes=("ALLOW", "DENY"), policy=policy_obj)
    for item in inputs:
        outcome, reason, ext = decider.decide(item)
        run.decide(item, outcome, reason, ts=..., label=..., ext=ext)
    run.close(record_id=..., issued_at=..., signing_key_id=..., private_key_pem=...)

Durability. A row is written when the decision is made, and the record is
signed only at close(); a process that stops before close() leaves no record
at all, which is the honest failure (SPEC §11). What a stop takes with it is
decided by `durability`:

    "none"   the row sits in the process's own buffer until it fills; an abort
             that skips cleanup loses every row still buffered, which is on
             the order of twenty decisions at a time;
    "flush"  (default) the row is handed to the kernel before decide()
             returns, so it survives any abort of the process itself;
    "fsync"  the row is on the medium before decide() returns, so it survives
             the machine stopping too. One fsync per retained file per
             decision; the emitter pays for it.

None of this is a claim the record makes. A record cannot say what was lost
before it was signed; it can only make the loss small or zero.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence, Tuple

from . import attest as attest_mod, derive, receipts as receipts_mod
from .canonical import canonical_bytes, canonical_input, digest_file, digest_obj, same_value
from .record import FORMAT, FORMAT_VERSION, FORMAT_VERSION_STREAM, INPUTS_FILE, POLICY_FILE, record_defects
from .rows import GENESIS, ROW_VERSION, ROW_VERSION_KEYED, keyed_input_digest, load_rows, row_hash, verify_chain
from .registry import resolve
from .signing import SignatureCheckRaised, sign_record, verify_signature

LEDGER_FILE = "decisions.jsonl"
RECORD_FILE = "record.json"
DURABILITY = ("none", "flush", "fsync")


class NotCanonicalInput(ValueError):
    """The input handed to the gate is not its own canonical value, so the row's
    digest would stand for an input the decision was not made on."""


class ArrivalRefused(Exception):
    """The gate refused an input: the policy requires an arrival and this input
    had none, or one that does not verify over it. Nothing was written."""


def check_arrival(arrival: Any, input_obj: Any, attester_registry: Dict[str, Any]) -> Tuple[bool, str]:
    """Is `arrival` a signed input-arrival over `input_obj`'s plain digest, under a
    key the attester registry honours? The gate's half of SPEC section 16.8; the
    verifier's half, including that the key is no producer's or decider's, is in
    tools/arrive.py and needs registries the gate does not hold."""
    if not isinstance(arrival, dict) or arrival.get("kind") != "input-arrival" or not isinstance(arrival.get("arrival_seq"), int):
        return False, "what came with the input is not an input arrival"
    if arrival.get("input_digest") != digest_obj(input_obj):
        return False, f"arrival {arrival['arrival_seq']} was signed over a different input"
    state, detail, pem = resolve(attester_registry, arrival.get("attester_key_id"), arrival.get("payload_hash"))
    if state != "honoured":
        return False, f"arrival {arrival['arrival_seq']}: {detail}"
    try:
        ok, why = verify_signature(arrival, pem)
    except SignatureCheckRaised as exc:
        return False, f"arrival {arrival['arrival_seq']}: the signature check could not be performed: {exc}"
    if not ok:
        return False, f"arrival {arrival['arrival_seq']}: {why}"
    return True, ""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Run:
    def __init__(
        self,
        directory: Path,
        *,
        decider_id: str,
        decider_version: str,
        outcomes: Sequence[str],
        policy: Any,
        retain_inputs: bool = True,
        retain_policy: bool = True,
        stream: Optional[Dict[str, Any]] = None,
        record_id: Optional[str] = None,
        signing_key_id: Optional[str] = None,
        private_key_pem: Optional[bytes] = None,
        issue_receipts: bool = False,
        keyed_digests: bool = False,
        salt: Optional[bytes] = None,
        retain_ext: bool = True,
        decider_key_id: Optional[str] = None,
        decider_private_key_pem: Optional[bytes] = None,
        established_versions: Optional[Sequence[Dict[str, str]]] = None,
        durability: str = "flush",
        attester_registry: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        `stream`, if given, is {"stream_id", "seq", "prev_record_hash", "first_decision"}
        and makes this a format_version 2 record (SPEC §12). `issue_receipts`
        makes decide() also sign a receipt for every row, which the caller hands
        to the party the decision was about; it needs record_id, signing_key_id
        and private_key_pem at construction, because a receipt is issued when
        the decision is made, not when the run is closed. `durability` is one
        of "none", "flush" or "fsync" (module docstring).
        """
        if durability not in DURABILITY:
            raise ValueError(f"durability must be one of {DURABILITY}, not {durability!r}")
        self.durability = durability
        self.directory = Path(directory)
        self.stream = dict(stream) if stream is not None else None
        self.record_id = record_id
        self.signing_key_id = signing_key_id
        self._private_key_pem = private_key_pem
        self.issue_receipts = issue_receipts
        if issue_receipts and not (record_id and signing_key_id and private_key_pem):
            raise ValueError("receipts need record_id, signing_key_id and private_key_pem at construction")
        self.receipts: list = []
        # Decider attestations (SPEC §15): the decider signs each decision as it
        # is made, under a key the producer does not hold. Needs record_id at
        # construction for the same reason receipts do.
        self.decider_key_id = decider_key_id
        self._decider_private_key_pem = decider_private_key_pem
        if (decider_key_id is None) != (decider_private_key_pem is None):
            raise ValueError("decider attestations need both decider_key_id and decider_private_key_pem")
        if decider_key_id is not None and not record_id:
            raise ValueError("decider attestations need record_id at construction")
        self._attestations = None
        # Row version 2: input digests keyed with a per-run salt kept in the
        # inputs file, so withholding the inputs withholds the ability to test
        # guesses against the digests. `salt` may be given for reproducible
        # examples; a real run leaves it None and gets 32 random bytes.
        self.keyed = keyed_digests
        self.salt = salt if salt is not None else (os.urandom(32) if keyed_digests else None)
        self.retain_ext = retain_ext
        # The gate's precondition (SPEC section 16.8). A policy carrying
        # {"arrival": "required"} is a decider that decides nothing it was not
        # handed an arrival for; the registry the arrival is checked under is
        # supplied here at runtime, as every registry is, and is not in the policy.
        self.arrival_required = isinstance(policy, dict) and policy.get("arrival") == "required"
        self.attester_registry = attester_registry
        if self.arrival_required and attester_registry is None:
            raise ValueError("the policy requires an arrival for every input and no attester registry was supplied to check them under")
        self.directory.mkdir(parents=True, exist_ok=False)
        self.decider = f"{decider_id}@{decider_version}"
        self.decider_id = decider_id
        self.decider_version = decider_version
        # Other versions of the decider a conformance run has established as
        # agreeing with this one in full, each with the digest of that run's
        # result (SPEC §8). The producer's claim, like the version itself.
        self.established_versions = [dict(e) for e in (established_versions or [])]
        self.outcomes = list(outcomes)
        self.policy_digest = digest_obj(policy)
        self.retain_inputs = retain_inputs
        self._prev = GENESIS
        self._seq = 0
        self._ledger = open(self.directory / LEDGER_FILE, "w", encoding="utf-8")
        self._inputs = open(self.directory / INPUTS_FILE, "w", encoding="utf-8") if retain_inputs else None
        if self._inputs is not None and self.keyed:
            self._inputs.write(json.dumps({"salt": self.salt.hex()}) + "\n")
        if self.decider_key_id is not None:
            self._attestations = open(self.directory / attest_mod.ATTESTATIONS_FILE, "w", encoding="utf-8")
        if retain_policy:
            self._write_whole(self.directory / POLICY_FILE, canonical_bytes(policy))
        self._settle()
        if self.durability == "fsync":
            # The files now exist; make the directory entries durable too, or
            # a stop could leave durable bytes in files that are not there.
            self._fsync_directory()
        self._closed = False

    # -- durability -----------------------------------------------------------

    def _open_handles(self):
        return [h for h in (self._ledger, self._inputs, self._attestations) if h is not None and not h.closed]

    def _settle(self) -> None:
        """Push everything written so far to where `durability` says it must be."""
        if self.durability == "none":
            return
        for h in self._open_handles():
            h.flush()
            if self.durability == "fsync":
                os.fsync(h.fileno())

    def _write_whole(self, path: Path, data: bytes) -> None:
        """Write a whole file, to the medium if the tier says so."""
        with open(path, "wb") as f:
            f.write(data)
            if self.durability != "none":
                f.flush()
                if self.durability == "fsync":
                    os.fsync(f.fileno())

    def _fsync_directory(self) -> None:
        if os.name != "posix":
            return
        fd = os.open(self.directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def decide(
        self,
        input_obj: Any,
        outcome: str,
        reason: Optional[str],
        *,
        ts: Optional[str] = None,
        label: Optional[str] = None,
        ext: Optional[Dict[str, Any]] = None,
        decided_by_decider: bool = True,
        arrival: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Write one row. `decided_by_decider=False` writes a row the decider
        did not decide (a producer forwarding without the gate): no attestation
        is made for it, and a verifier asked for invocation will say so.

        `arrival` is the attester's signed arrival for this input, handed to
        the gate with the input. Under a policy that requires one, the gate
        refuses an input with none, or with one not signed over this input's
        plain digest by a key the attester registry honours (ArrivalRefused);
        nothing is written. The row then names the arrival and, when the
        decider attests, the attestation carries the same identifier."""
        if self._closed:
            raise RuntimeError("run is closed")
        if outcome not in self.outcomes:
            raise ValueError(f"outcome {outcome!r} is not one of the declared outcomes {self.outcomes}")
        if not same_value(canonical_input(input_obj), input_obj):  # NotAnInput for an integer past 2**53 - 1
            raise NotCanonicalInput("the input is not the value its digest covers; decide canonical_input(input) and write that (SPEC §2)")
        arrival_seq: Optional[int] = None
        if self.arrival_required:
            if arrival is None:
                raise ArrivalRefused("the policy requires an arrival for every input and this input came with none")
            ok, why = check_arrival(arrival, input_obj, self.attester_registry)
            if not ok:
                raise ArrivalRefused(why)
            arrival_seq = arrival["arrival_seq"]
            ext = {**(ext or {}), "arrival": arrival_seq}
        self._seq += 1
        row: Dict[str, Any] = {
            "v": ROW_VERSION_KEYED if self.keyed else ROW_VERSION,
            "seq": self._seq,
            "ts": ts or utc_now(),
            "input_digest": keyed_input_digest(self.salt, input_obj) if self.keyed else digest_obj(input_obj),
            "decider": self.decider,
            "policy_digest": self.policy_digest,
            "outcome": outcome,
            "reason": reason,
        }
        if label is not None:
            row["label"] = label
        if ext is not None and self.retain_ext:
            row["ext"] = ext
        row["prev_hash"] = self._prev
        row["row_hash"] = row_hash(self._prev, row)
        self._prev = row["row_hash"]
        self._ledger.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
        if self._inputs is not None:
            self._inputs.write(json.dumps({"seq": self._seq, "input": input_obj}, sort_keys=True, ensure_ascii=False) + "\n")
        if self._attestations is not None and decided_by_decider:
            a = attest_mod.attest(row, record_id=self.record_id, decider_key_id=self.decider_key_id, private_key_pem=self._decider_private_key_pem, arrival=arrival_seq)
            self._attestations.write(json.dumps(a, sort_keys=True) + "\n")
        if self.issue_receipts:
            self.receipts.append(
                receipts_mod.issue(
                    row,
                    record_id=self.record_id,
                    stream_id=self.stream["stream_id"] if self.stream else None,
                    first_decision=self.stream["first_decision"] if self.stream else 1,
                    signing_key_id=self.signing_key_id,
                    private_key_pem=self._private_key_pem,
                )
            )
        self._settle()
        return row

    def close(
        self,
        *,
        record_id: Optional[str] = None,
        signing_key_id: Optional[str] = None,
        private_key_pem: Optional[bytes] = None,
        issued_at: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> Path:
        """Build and sign the record from the rows on disk.

        `profile` may be given to assert what the emitter intended; it is
        checked against what the rows support and a disagreement is an error
        here, before anything is signed. Left None, the rows decide.
        """
        if self._closed:
            raise RuntimeError("run is closed")
        record_id = record_id or self.record_id
        signing_key_id = signing_key_id or self.signing_key_id
        private_key_pem = private_key_pem or self._private_key_pem
        if not (record_id and signing_key_id and private_key_pem):
            raise ValueError("close needs record_id, signing_key_id and private_key_pem, here or at construction")
        if self.record_id is not None and record_id != self.record_id:
            raise ValueError("record_id at close differs from the one receipts were issued under")
        self._ledger.close()
        if self._inputs is not None:
            self._inputs.close()
        if self._attestations is not None:
            self._attestations.close()
        self._closed = True

        rows = load_rows(self.directory / LEDGER_FILE)
        terminal = verify_chain(rows)
        derived = derive.derive_all(rows)
        supported = derived["supported_profile"]
        if supported is None:
            raise ValueError("the rows support no profile: some are labelled and some are not")
        if profile is not None and profile != supported:
            raise ValueError(f"the emitter intended profile {profile!r} but the rows support {supported!r}")

        retained: Dict[str, str] = {}
        for name in sorted(p.name for p in self.directory.iterdir() if p.is_file()):
            if name in (LEDGER_FILE, RECORD_FILE):
                continue
            retained[name] = digest_file(self.directory / name)

        record: Dict[str, Any] = {
            "format": FORMAT,
            "format_version": FORMAT_VERSION_STREAM if self.stream is not None else FORMAT_VERSION,
            "profile": supported,
            "record_id": record_id,
            "issued_at": issued_at or utc_now(),
            "decider": {"id": self.decider_id, "version": self.decider_version, "outcomes": self.outcomes,
                        **({"established_versions": self.established_versions} if self.established_versions else {})},
            "policy_digests": derived["policy_digests"],
            "ledger": {"path": LEDGER_FILE, "row_count": len(rows), "terminal_hash": terminal},
            "counts": derived["counts"],
            "retained": retained,
            "signing_key_id": signing_key_id,
        }
        if "benchmark" in derived:
            record["benchmark"] = derived["benchmark"]
        if self.stream is not None:
            record["stream"] = self.stream
        signed = sign_record(record, private_key_pem)
        defects = record_defects(signed)
        if defects:
            raise ValueError("refusing to write a record that fails its own shape: " + "; ".join(defects))
        self._write_whole(self.directory / RECORD_FILE, (json.dumps(signed, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"))
        if self.durability == "fsync":
            self._fsync_directory()
        return self.directory / RECORD_FILE
