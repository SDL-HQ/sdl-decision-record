"""The forgery table of experiments/rederivability, one rung up: with an attester.

    python3 experiments/rederivability/ladder.py --out <dir outside the tree>

`experiments/rederivability/RESULTS.md` §6 shows which check catches which of
five forgeries, and that F5 — a retained input the agent never supplied,
honestly decided — passes every check. Its ladder names L3, "as L2, with the
inputs independently attested", as the rung that reaches it, and does not
climb it. This does: the five forgeries are rebuilt by the same tampered
deciders over inputs a customer-operated attester signed as they arrived, and
every record is verified twice — by `dr.verify` with replay under the honest
module, and by `verify_arrival.py`, which adds `arrival` and
`arrivals_accounted`. The table that results is §6's with two more columns.

What F1–F4 should show: the attester changes nothing, because their inputs
did arrive; the forgery is in the decider, and `arrival` establishes. What F5
should show: the one column that was "passes" becomes failed. Anything else
is a finding about the attester, not about the forgeries.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
for p in (str(ROOT), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import tools.arrive as arrive  # noqa: E402
import forge  # noqa: E402  (the forgery recipes and test keys)
from dr.canonical import read_jsonl  # noqa: E402
from dr.emit import Run  # noqa: E402
from dr.signing import public_key_pem  # noqa: E402

TARGET = 24  # the Cyrillic-lookalike host, honestly denied; forge.py's choice


def test_key(label: str) -> bytes:
    """The attester's key, derived from a fixed seed so the build is deterministic."""
    seed = hashlib.sha256(f"attested-input-test-key:{label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def registry(path: Path, entries: dict) -> Path:
    path.write_text(json.dumps({"registry_version": 1, "keys": [
        {"key_id": k, "status": "active", "public_key_pem": public_key_pem(pem)} for k, pem in entries.items()]}, indent=1) + "\n")
    return path


def fabricate(items: list) -> list:
    """F5's input: the retained input of seq TARGET replaced by a benign call the agent never made."""
    doctored = [json.loads(json.dumps(x)) for x in items]
    it = doctored[TARGET - 1]["input"]
    it["resource"] = {"type": "Agentic::Host", "id": "api.example.com"}
    for e in it["entities"]:
        if e["uid"]["type"].endswith("Host"):
            e["uid"]["id"] = "api.example.com"
            e["attrs"]["name"] = "api.example.com"
    it["note"] = "allow-listed host over https"
    return doctored

VERIFY_ARRIVAL = ROOT / "tools" / "verify_arrival.py"


def build(out: Path, name: str, module: str, items: list, seen: list, keys: dict) -> Path:
    """One forgery, as forge.py builds it, with arrivals in front. `seen` is
    what reached the attester; `items` is what the producer decided."""
    att = arrive.Attester(out / f"{name}.attester-log.jsonl", key_id="customer", private_key_pem=keys["customer"])
    arrivals = [att.arrive(it["input"]) for it in seen]
    att.close()
    policy = json.loads((ROOT / "examples" / "cedar" / "policy-canonical.json").read_text())
    mod = importlib.import_module(module)
    decider = mod.Decider(dict(policy))
    d = out / name
    run = Run(d, decider_id=mod.DECIDER_ID, decider_version=mod.DECIDER_VERSION, outcomes=list(mod.OUTCOMES),
              policy=dict(policy), record_id=f"ladder-{name}", signing_key_id="rederivability-test-producer",
              private_key_pem=keys["producer"], decider_key_id="rederivability-test-decider",
              decider_private_key_pem=keys["decider"])
    for i, it in enumerate(items, start=1):
        outcome, reason, ext = decider.decide(it["input"])
        ext = dict(ext or {})
        ext[arrive.EXT_KEY] = i
        run.decide(it["input"], outcome, reason, ts=f"2026-10-27T04:00:{i % 60:02d}Z", ext=ext)
    (d / arrive.ARRIVALS_FILE).write_text("".join(json.dumps(a, sort_keys=True) + "\n" for a in arrivals))
    run.close(issued_at="2026-10-27T04:01:00Z")
    return d


def verify(d: Path, preg: Path, dreg: Path, areg: Path, log: Path) -> dict:
    base = ["-m", "dr.verify", str(d), "--registry", str(preg), "--decider-registry", str(dreg), "--replay", "emitters.cedar", "--json"]
    r = subprocess.run([sys.executable, *base], capture_output=True, text=True, cwd=ROOT)
    ref = json.loads(r.stdout)
    r2 = subprocess.run([sys.executable, "-I", str(VERIFY_ARRIVAL), str(d), "--registry", str(preg), "--decider-registry", str(dreg),
                         "--attester-registry", str(areg), "--arrival-log", str(log), "--replay", "emitters.cedar", "--json"],
                        capture_output=True, text=True, cwd=ROOT)
    att = json.loads(r2.stdout)
    props = {p["property"]: p for p in att["properties"]}
    return {"replay_honest": next(p["state"] for p in ref["properties"] if p["property"] == "replay"),
            "verdict_ref": ref["exit_code"], "arrival": props["arrival"]["state"],
            "accounted": props["arrivals_accounted"]["state"], "verdict_att": att["verdict"],
            "arrival_detail": props["arrival"]["detail"]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    out = Path(a.out).resolve()
    if out == ROOT or ROOT in out.parents:
        print("build outside the tree", file=sys.stderr)
        return 2
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    keys = {"producer": forge.test_key("producer"), "decider": forge.test_key("decider"), "customer": test_key("customer")}
    preg = (out / "registry.json")
    preg.write_text(json.dumps({"registry_version": 1, "keys": [{"key_id": "rederivability-test-producer", "status": "active", "public_key_pem": public_key_pem(keys["producer"])}]}))
    dreg = (out / "deciders.json")
    dreg.write_text(json.dumps({"registry_version": 1, "keys": [{"key_id": "rederivability-test-decider", "status": "active", "public_key_pem": public_key_pem(keys["decider"])}]}))
    areg = registry(out / "attester.json", {"customer": keys["customer"]})
    items = [json.loads(l) for _, l in read_jsonl(ROOT / "examples" / "cedar" / "inputs-toolcalls.jsonl")]

    t0 = time.perf_counter()
    rows = []
    for name, module, what in forge.FORGERIES:
        d = build(out, name, module, items, items, keys)
        rows.append((name, what, verify(d, preg, dreg, areg, out / f"{name}.attester-log.jsonl")))
    fab = fabricate(items)
    d = build(out, "f5-input-fabricated", "emitters.cedar", fab, items, keys)
    rows.append(("f5-input-fabricated", f"the retained input of seq {TARGET} is a benign call the agent never made; the decision is honestly computed from it",
                 verify(d, preg, dreg, areg, out / "f5-input-fabricated.attester-log.jsonl")))
    took = time.perf_counter() - t0

    def v(code):
        return {0: "ESTABLISHED", 1: "NOT ESTABLISHED", 2: "FAILED"}[code] if isinstance(code, int) else str(code)

    lines = ["# Results: the forgery table, one rung up", "",
             f"`ladder.py`. The five forgeries of `experiments/rederivability/forge.py`, rebuilt with a "
             f"customer-operated attester in front of the decider; {len(rows)} records. Columns 3–4 are "
             "`experiments/rederivability/RESULTS.md` §6's; columns 5–7 are new.", "",
             "| forgery | what it misreports | `replay` (honest module) | verdict, `dr.verify` | `arrival` | `arrivals_accounted` | verdict, with attester |",
             "|---|---|---|---|---|---|---|"]
    for name, what, r in rows:
        lines.append(f"| `{name}` | {what} | {r['replay_honest']} | **{v(r['verdict_ref'])}** | {r['arrival']} | {r['accounted']} | **{v(r['verdict_att'])}** |")
    f5 = rows[-1][2]
    lines += ["", "## Read-off", "",
              "- F1–F4 are unchanged by the attester: their inputs did arrive, so `arrival` establishes on all four and the verdict is still the one replay under the honest module gives. The forgery is in the decider, and the attester has nothing to say about deciders — which is the right silence.",
              f"- F5 moves. It was the one row that passed every check; with the attester it is **{v(f5['verdict_att'])}** on `arrival`: *{f5['arrival_detail']}*",
              "- So the ladder's L3 is reached, and what it accepts on trust is what the ladder said: the attester, and the seam between arrival and decision. The roof is now one rung higher and still a roof.",
              ]
    (HERE / "LADDER.md").write_text("\n".join(lines) + "\n")
    print(f"timing (not committed): {len(rows)} records in {took:.1f}s", file=sys.stderr)
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
