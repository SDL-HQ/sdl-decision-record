"""The manipulations an evaluator should try on a record, each one a subcommand.

    forge.py tamper-row  <run> <seq>                      flip one row's outcome on disk (ALLOW <-> DENY)
    forge.py forge-attestation <run> <seq>                flip the decision inside one decider attestation
    forge.py resign <run> <producer key pem>              re-digest the retained files and sign the record again (the producer can)
    forge.py drop-attestations <run> <seq> [<seq> ...]     remove the attestations for those seqs (a producer trimming the tail)
    forge.py evidence <out.json> <engine> <requests> <agree> [excluded ...]
                                                          write a conformance result object; prints its digest
    forge.py digest <file.json>                           the digest a record names for that result

Nothing here is a verifier feature. These are the things a producer, or
someone holding the producer's output, could do, so that the transcript shows
what the verifier says about each.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dr.canonical import digest_file, digest_obj  # noqa: E402
from dr.signing import sign_record  # noqa: E402


def rows_path(run):
    return Path(run) / "decisions.jsonl"


def rewrite_jsonl(path, fn):
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    rows = [fn(r) for r in rows]
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


def flip(outcome):
    return "DENY" if outcome == "ALLOW" else "ALLOW"


def main(argv):
    cmd = argv[0]
    if cmd == "tamper-row":
        run, seq = argv[1], int(argv[2])
        rewrite_jsonl(rows_path(run), lambda r: dict(r, outcome=flip(r["outcome"])) if r["seq"] == seq else r)
        print(f"row {seq} of {run}: outcome flipped on disk, hashes left as they were")
    elif cmd == "forge-attestation":
        run, seq = argv[1], int(argv[2])
        rewrite_jsonl(Path(run) / "attestations.jsonl", lambda a: dict(a, outcome=flip(a["outcome"])) if a["seq"] == seq else a)
        print(f"attestation for seq {seq} of {run}: outcome flipped, signature left as it was")
    elif cmd == "resign":
        run, key = Path(argv[1]), Path(argv[2]).read_bytes()
        record = json.loads((run / "record.json").read_text())
        for k in ("payload_hash", "signature"):
            record.pop(k, None)
        record["retained"] = {name: digest_file(run / name) for name in record["retained"]}
        (run / "record.json").write_text(json.dumps(sign_record(record, key), indent=2, sort_keys=True) + "\n")
        print(f"{run}: retained digests recomputed and the record signed again with the producer's key")
    elif cmd == "drop-attestations":
        run, seqs = Path(argv[1]), {int(x) for x in argv[2:]}
        path = run / "attestations.jsonl"
        kept = [l for l in path.read_text().splitlines() if l.strip() and json.loads(l)["seq"] not in seqs]
        path.write_text("".join(l + "\n" for l in kept))
        print(f"{run}: attestations for seq {sorted(seqs)} removed")
    elif cmd == "evidence":
        out, engine, requests, agree = argv[1], argv[2], int(argv[3]), int(argv[4])
        excluded = [{"note": x, "reason": "named by the producer"} for x in argv[5:]]
        body = {"corpus": "an example corpus", "engine": engine, "requests": requests, "agree_decision_reason_and_error_presence": agree, "excluded": excluded}
        Path(out).write_text(json.dumps({"full_corpus": body}, indent=1) + "\n")
        print(digest_obj(body))
    elif cmd == "digest":
        body = json.loads(Path(argv[1]).read_text())
        print(digest_obj(body.get("full_corpus", body)))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
