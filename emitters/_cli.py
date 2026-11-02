"""The one command-line wrapper every emitter shares.

An emitter module provides DECIDER_ID, DECIDER_VERSION, OUTCOMES and a
Decider class with decide(input) -> (outcome, reason, ext). This wrapper reads
an inputs file, runs the decider over it in order, writes the ledger through
dr.emit and signs the record. The inputs file holds one JSON object per line:

    {"ts": "2026-10-18T00:00:00Z", "input": {...}, "label": "ALLOW"}

`label` is optional and, if present on any line, must be present on every
line; the rows then support the benchmark profile. `ts` is the time the
decision is recorded as having been made; taking it from the input rather than
the clock is what makes an example run reproduce byte for byte.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from types import ModuleType

from dr.canonical import NotAnInput, canonical_input, read_jsonl, loads, loads_input
from dr.emit import Run
from dr.signing import payload_hash


def run_emitter(mod: ModuleType, argv=None) -> int:
    ap = argparse.ArgumentParser(description=f"Emit a decision record with {mod.DECIDER_ID}@{mod.DECIDER_VERSION}.")
    ap.add_argument("--policy", required=True, help="policy JSON file")
    ap.add_argument("--inputs", required=True, help="inputs JSONL file")
    ap.add_argument("--out", required=True, help="run directory to create")
    ap.add_argument("--key", required=True, help="Ed25519 private key PEM")
    ap.add_argument("--key-id", required=True, help="registry key id the record will name")
    ap.add_argument("--record-id", required=True)
    ap.add_argument("--issued-at", default=None, help="UTC time to sign the record as; default now")
    ap.add_argument("--profile", default=None, choices=["production", "benchmark"], help="assert the intended profile; the rows must support it")
    ap.add_argument("--no-retain-inputs", action="store_true")
    ap.add_argument("--no-ext", action="store_true", help="do not write the decider's ext block to the rows (SPEC §14)")
    ap.add_argument("--keyed", action="store_true", help="row version 2: keyed input digests, salt kept in inputs.jsonl (SPEC §14)")
    ap.add_argument("--salt", default=None, help="hex salt for --keyed; default 32 random bytes. Only for reproducible examples")
    ap.add_argument("--stream", default=None, metavar="ID:SEQ", help="format_version 2: this record's position in a stream (SPEC §12)")
    ap.add_argument("--prior", default=None, help="record.json of the previous record in the stream; required when SEQ > 1")
    ap.add_argument("--receipts", default=None, metavar="DIR", help="also sign a receipt per decision into DIR (SPEC §13)")
    ap.add_argument("--decider-key", default=None, help="Ed25519 private key PEM held by the decider: attest every decision as it is made (SPEC §15)")
    ap.add_argument("--decider-key-id", default=None, help="decider registry key id the attestations will name")
    ap.add_argument("--established-version", action="append", default=[], metavar="VERSION=DIGEST",
                    help="another version of the decider a conformance run established as agreeing in full, with the digest of that run's result (SPEC §8); repeatable")
    args = ap.parse_args(argv)

    try:
        policy = loads(Path(args.policy).read_text(encoding="utf-8"))
    except ValueError as exc:
        raise SystemExit(f"policy {args.policy}: {exc}")
    # The inputs are read as the verifier reads them, and refused as it would
    # refuse them: a duplicate member name decided here under one value would be
    # read under another by a reader that keeps the first (SEAMS.md).
    lines = []
    for n, text in read_jsonl(Path(args.inputs)):
        try:
            lines.append(loads_input(text))
        except ValueError as exc:
            raise SystemExit(f"input {len(lines) + 1} (line {n}): {exc}")
    key_pem = Path(args.key).read_bytes()
    stream = None
    if args.stream:
        sid, _, seq = args.stream.rpartition(":")
        seq = int(seq)
        if seq == 1:
            if args.prior:
                raise SystemExit("--prior given for the first record of a stream")
            stream = {"stream_id": sid, "seq": 1, "prev_record_hash": None, "first_decision": 1}
        else:
            if not args.prior:
                raise SystemExit("--prior is required when the stream seq is greater than 1")
            prior = loads(Path(args.prior).read_text(encoding="utf-8"))
            pst = prior.get("stream")
            if pst is None or pst["stream_id"] != sid or pst["seq"] != seq - 1:
                raise SystemExit(f"the prior record is not seq {seq - 1} of stream {sid!r}")
            if payload_hash(prior) != prior["payload_hash"]:
                raise SystemExit("the prior record's payload_hash does not recompute from its own fields")
            stream = {"stream_id": sid, "seq": seq, "prev_record_hash": payload_hash(prior), "first_decision": pst["first_decision"] + prior["ledger"]["row_count"]}
    decider = mod.Decider(policy)
    run = Run(
        Path(args.out),
        decider_id=mod.DECIDER_ID,
        decider_version=mod.DECIDER_VERSION,
        outcomes=mod.OUTCOMES,
        policy=policy,
        retain_inputs=not args.no_retain_inputs,
        retain_ext=not args.no_ext,
        keyed_digests=args.keyed,
        salt=bytes.fromhex(args.salt) if args.salt else None,
        stream=stream,
        record_id=args.record_id,
        signing_key_id=args.key_id,
        private_key_pem=key_pem,
        issue_receipts=bool(args.receipts),
        established_versions=[{"version": v.split("=", 1)[0], "evidence": v.split("=", 1)[1]} for v in args.established_version],
        decider_key_id=args.decider_key_id,
        decider_private_key_pem=Path(args.decider_key).read_bytes() if args.decider_key else None,
    )
    for n, item in enumerate(lines, start=1):
        try:
            value = canonical_input(item["input"])  # the decider decides the value the digest covers (SPEC §2)
        except NotAnInput as exc:
            raise SystemExit(f"input {n}: {exc}")
        outcome, reason, ext = decider.decide(value)
        run.decide(value, outcome, reason, ts=item.get("ts"), label=item.get("label"), ext=ext)
    record = run.close(issued_at=args.issued_at, profile=args.profile)
    if args.receipts:
        rdir = Path(args.receipts)
        rdir.mkdir(parents=True, exist_ok=True)
        for r in run.receipts:
            (rdir / f"receipt-{r['seq']:06d}.json").write_text(json.dumps(r, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {record} ({len(lines)} decisions" + (f", {len(run.receipts)} receipts in {args.receipts}" if args.receipts else "") + ")")
    return 0
