#!/usr/bin/env python3
"""Two records for the acceptance procedure, built deterministically (fixed test keys, fixed times).

    python3 examples/acceptance/attested.py fabricated <out>   # the roof, with an attester in front of it
    python3 examples/acceptance/attested.py gated <out>        # the gate refuses an input with no arrival

`fabricated`: the tool gate over examples/data/toolgate-traffic-hour1.jsonl with an attester in
front of it, except that the producer replaced the retained input of row 4 with a benign call it
then decided honestly (the fifth alteration of experiments/rederivability). The row still names
arrival 4, which the attester signed over the input that actually arrived.

`gated`: the same traffic under a policy carrying {"arrival": "required"}; input 4 is sent to the
gate with no arrival. The gate refuses it and writes nothing; the remaining 19 are decided.

Each writes <out>/ (the record), <out>.attester-log.jsonl (the attester's own copy) and the three
registries beside it. Nothing here is composed by hand: run.sh captures what the verifier says.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import tools.arrive as arrive  # noqa: E402
from dr.emit import ArrivalRefused, Run  # noqa: E402
from dr.signing import public_key_pem  # noqa: E402
from emitters import toolgate  # noqa: E402

TRAFFIC = ROOT / "examples" / "data" / "toolgate-traffic-hour1.jsonl"
POLICY = json.loads((ROOT / "examples" / "data" / "toolgate-policy.json").read_text())
TARGET = 4  # delete_all_orders, over an hour of send_receipt traffic


def test_key(label: str) -> bytes:
    seed = hashlib.sha256(f"acceptance-attested-test-key:{label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def registry(path: Path, entries: dict) -> dict:
    reg = {"registry_version": 1, "keys": [{"key_id": k, "status": "active", "public_key_pem": public_key_pem(v)} for k, v in entries.items()]}
    path.write_text(json.dumps(reg, indent=1) + "\n")
    return reg


def main(argv) -> int:
    which, out = argv[0], Path(argv[1])
    keys = {k: test_key(k) for k in ("producer", "decider", "customer")}
    side = out.parent
    registry(side / f"{out.name}.producer.json", {"producer": keys["producer"]})
    registry(side / f"{out.name}.decider.json", {"decider": keys["decider"]})
    areg = registry(side / f"{out.name}.attester.json", {"customer": keys["customer"]})
    items = [json.loads(l) for l in TRAFFIC.read_text().splitlines() if l.strip()]
    policy = dict(POLICY)
    if which == "gated":
        policy["arrival"] = "required"
    decider = toolgate.Decider(policy)
    att = arrive.Attester(side / f"{out.name}.attester-log.jsonl", key_id="customer", private_key_pem=keys["customer"])
    run = Run(out, decider_id=toolgate.DECIDER_ID, decider_version=toolgate.DECIDER_VERSION, outcomes=toolgate.OUTCOMES,
              policy=policy, record_id=f"acceptance-{which}-2026-10-28", signing_key_id="producer", private_key_pem=keys["producer"],
              decider_key_id="decider", decider_private_key_pem=keys["decider"],
              attester_registry=areg if which == "gated" else None)
    for i, it in enumerate(items, start=1):
        real = it["input"]
        if which == "gated" and i == TARGET:
            o, why, ext = decider.decide(real)
            try:
                run.decide(real, o, why, ts=it["ts"], ext=ext, arrival=None)
            except ArrivalRefused as exc:
                msg = f"input {i} refused by the gate: {exc}"
                print(msg)
                (side / f"{out.name}.refused.txt").write_text(msg + "\n")
            continue
        a = att.arrive(real)  # the attester signs what actually arrived
        decided = real
        if which == "fabricated" and i == TARGET:
            decided = {"tool": "send_receipt", "args": {"order_id": 4, "email": "x@example.invalid", "resend": False}}
        o, why, ext = decider.decide(decided)
        ext = dict(ext or {})
        if which == "gated":
            run.decide(decided, o, why, ts=it["ts"], ext=ext, arrival=a)
        else:
            ext[arrive.EXT_KEY] = a["arrival_seq"]
            run.decide(decided, o, why, ts=it["ts"], ext=ext)
    att.close()
    (out / arrive.ARRIVALS_FILE).write_text(att.log_path.read_text())
    run.close(issued_at="2026-10-28T06:00:00Z")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
