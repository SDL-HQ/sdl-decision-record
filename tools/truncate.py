"""Delete decisions from a run and re-sign it. The record will verify.

    python3 tools/truncate.py <run dir> <out dir> --drop 3,7,12 --key key.pem

This is not an attack on the format; it is what the format cannot prevent. The
producer holds the key, so the producer chooses what is signed. Drop any rows,
renumber, recompute every hash forward, re-derive the counts from the rows
that remain, sign. Every property the verifier reports holds, because every
property is a statement about the rows that are there.

What this leaves behind is the subject of SPEC.md §13: receipts held by other
parties, witness statements, and stream links, each of which makes a specific
deletion detectable to a specific holder.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Iterable, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dr import derive  # noqa: E402
from dr.canonical import read_jsonl  # noqa: E402
from dr.canonical import digest_file  # noqa: E402
from dr.rows import GENESIS, row_hash  # noqa: E402
from dr.signing import sign_record  # noqa: E402


def truncate(run_dir: Path, out_dir: Path, drop: Iterable[int], private_key_pem: bytes) -> Path:
    drop = set(drop)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    shutil.copytree(run_dir, out_dir)
    record = json.loads((out_dir / "record.json").read_text())
    ledger = out_dir / record["ledger"]["path"]
    rows = [json.loads(l) for _, l in read_jsonl(ledger)]
    kept = [r for r in rows if r["seq"] not in drop]
    if not kept:
        raise SystemExit("refusing to produce an empty ledger")
    prev = GENESIS
    for i, r in enumerate(kept, start=1):
        r["seq"] = i
        r["prev_hash"] = prev
        r["row_hash"] = row_hash(prev, r)
        prev = r["row_hash"]
    ledger.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in kept))
    inputs = out_dir / "inputs.jsonl"
    if inputs.exists():
        lines = [json.loads(l) for _, l in read_jsonl(inputs)]
        head = []  # a v2 (keyed) ledger keeps its salt as the first line; the salt is kept
        if lines and set(lines[0]) == {"salt"}:
            head, lines = lines[:1], lines[1:]
        kept_inputs = [x for x in lines if x["seq"] not in drop]
        for i, x in enumerate(kept_inputs, start=1):
            x["seq"] = i
        inputs.write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in head + kept_inputs))
    for k in ("payload_hash", "signature"):
        record.pop(k, None)
    derived = derive.derive_all(kept)
    record["ledger"]["row_count"] = len(kept)
    record["ledger"]["terminal_hash"] = prev
    record["counts"] = derived["counts"]
    record["policy_digests"] = derived["policy_digests"]
    if "benchmark" in record:
        record["benchmark"] = derived["benchmark"]
    record["retained"] = {name: digest_file(out_dir / name) for name in record["retained"]}
    (out_dir / "record.json").write_text(json.dumps(sign_record(record, private_key_pem), indent=2, sort_keys=True) + "\n")
    return out_dir


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run_dir")
    ap.add_argument("out_dir")
    ap.add_argument("--drop", required=True, help="comma-separated row seqs to delete")
    ap.add_argument("--key", required=True, help="the producer's private key")
    args = ap.parse_args(argv)
    drop = [int(x) for x in args.drop.split(",") if x.strip()]
    out = truncate(Path(args.run_dir), Path(args.out_dir), drop, Path(args.key).read_bytes())
    print(f"wrote {out}: dropped rows {sorted(drop)}, renumbered, re-chained, re-signed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
