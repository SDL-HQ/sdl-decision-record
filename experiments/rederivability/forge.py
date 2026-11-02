"""Build the forged records: each signed, each internally consistent, each exploiting one producer-side step.

    python3 experiments/rederivability/forge.py --out experiments/rederivability/out

Keys. Generated here from fixed labels, so the fixtures reproduce; they are
test keys for this experiment and nothing else. No production key is read.

What "forged" means. Each record is made by a tampered decider
(`experiments/rederivability/tampered/`) whose `DECIDER_ID` and
`DECIDER_VERSION` are identical to the honest module's, because the version
names the engine and not the wrapper. Every row is a real decision the
tampered code really made, the chain is sound, the counts derive, the decider
signed each row at decision time. The record is a true account of what the
tampered producer's code did and a false account of what the policy required.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for p in (str(ROOT), str(Path(__file__).resolve().parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dr.canonical import read_jsonl
from dr.emit import Run
from dr.signing import public_key_pem

FORGERIES = [
    ("f1-canonicalisation-widened", "tampered.f1_canon_widened",
     "the host operation folds confusable characters, so a lookalike host becomes the allow-listed one"),
    ("f2-context-key-dropped", "tampered.f2_context_key_dropped",
     "request construction removes a context key the policy reads"),
    ("f3-reason-relabelled", "tampered.f3_reason_relabelled",
     "the reason names a forbid that did not fire"),
    ("f4-entity-source-swapped", "tampered.f4_entity_source_swapped",
     "the policy declares the store; the producer evaluates with the caller's entities"),
]


def test_key(label: str) -> bytes:
    seed = hashlib.sha256(f"sdl-decision-record re-derivability experiment {label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "out"))
    ap.add_argument("--policy", default=str(ROOT / "examples" / "cedar" / "policy-canonical.json"))
    ap.add_argument("--inputs", default=str(ROOT / "examples" / "cedar" / "inputs-toolcalls.jsonl"))
    a = ap.parse_args(argv)
    out = Path(a.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    producer_pem, decider_pem = test_key("producer"), test_key("decider")
    (out / "registry.json").write_text(json.dumps(
        {"registry_version": 1, "keys": [{"key_id": "rederivability-test-producer", "status": "active",
                                          "public_key_pem": public_key_pem(producer_pem)}]}, indent=1) + "\n")
    (out / "deciders.json").write_text(json.dumps(
        {"registry_version": 1, "keys": [{"key_id": "rederivability-test-decider", "status": "active",
                                          "public_key_pem": public_key_pem(decider_pem)}]}, indent=1) + "\n")

    policy = json.loads(Path(a.policy).read_text())
    items = [json.loads(l) for _, l in read_jsonl(a.inputs)]
    made = []
    for name, module, what in FORGERIES:
        mod = importlib.import_module(module)
        # F4's record must declare the store while the decider ignores it
        pol = dict(policy)
        decider = mod.Decider(pol)
        run = Run(out / name, decider_id=mod.DECIDER_ID, decider_version=mod.DECIDER_VERSION,
                  outcomes=list(mod.OUTCOMES), policy=pol, record_id=f"forged-{name}",
                  signing_key_id="rederivability-test-producer", private_key_pem=producer_pem,
                  decider_key_id="rederivability-test-decider", decider_private_key_pem=decider_pem)
        for i, it in enumerate(items, start=1):
            outcome, reason, ext = decider.decide(it["input"])
            run.decide(it["input"], outcome, reason, ts=f"2026-10-23T04:00:{i % 60:02d}Z", ext=ext)
        run.close(issued_at="2026-10-23T04:01:00Z")
        made.append({"name": name, "module": module, "what": what})
        print(f"wrote {out / name}  ({what})")
    # F5 is a different kind: the decider is the honest one and the code is not touched.
    # One retained input is replaced with a benign call and the decision recomputed honestly.
    # The record is then a flawless account of a call the agent never made. Every check in
    # this repository passes on it, which is the point: re-derivation re-derives the decision,
    # never the fact that the retained input is what the system saw.
    honest = importlib.import_module("emitters.cedar")
    doctored = [json.loads(json.dumps(x)) for x in items]
    target = 24  # the Cyrillic-lookalike host, honestly denied
    doctored[target - 1]["input"]["resource"] = {"type": "Agentic::Host", "id": "api.example.com"}
    for e in doctored[target - 1]["input"]["entities"]:
        if e["uid"]["type"].endswith("Host"):
            e["uid"]["id"] = "api.example.com"
            e["attrs"]["name"] = "api.example.com"
    doctored[target - 1]["input"]["note"] = "allow-listed host over https"
    name = "f5-input-fabricated"
    decider = honest.Decider(dict(policy))
    run = Run(out / name, decider_id=honest.DECIDER_ID, decider_version=honest.DECIDER_VERSION,
              outcomes=list(honest.OUTCOMES), policy=dict(policy), record_id=f"forged-{name}",
              signing_key_id="rederivability-test-producer", private_key_pem=producer_pem,
              decider_key_id="rederivability-test-decider", decider_private_key_pem=decider_pem)
    for i, it in enumerate(doctored, start=1):
        outcome, reason, ext = decider.decide(it["input"])
        run.decide(it["input"], outcome, reason, ts=f"2026-10-23T04:00:{i % 60:02d}Z", ext=ext)
    run.close(issued_at="2026-10-23T04:01:00Z")
    made.append({"name": name, "module": "emitters.cedar (honest)",
                 "what": f"the retained input of seq {target} is a benign call the agent never made; "
                         "the decision is honestly computed from it"})
    print(f"wrote {out / name}  (input fabricated at seq {target}; honest decider)")

    (out / "FORGERIES.json").write_text(json.dumps(made, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
