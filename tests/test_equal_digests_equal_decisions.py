"""Equal digests, equal decisions.

The format identifies an input by the digest of its canonical bytes, and a
decider has its own type model: `{"order_id": 396}` and `{"order_id": 396.0}`
have one canonical form and one digest, and the tool gate allows the first and
denies the second. A producer could then decide a form the attester never saw,
get a genuine decision and a genuine attestation for it, and every property
including replay would establish.

The invariant this holds: whatever form an input arrives in, every party that
decides it (the gate, replay, re-derivation) and the party that attests it
decide or sign the value its canonical bytes denote, so two inputs with equal
digests are decided identically by any deterministic decider. The generated
test below runs each decider's committed traffic through the emitter twice, once
as committed and once with every integer written as a float, and requires the
two records' rows to agree; a companion check proves the pairs exercise the
class rather than pass vacuously.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dr.canonical import (  # noqa: E402
    MAX_INPUT_INTEGER, NotAnInput, canonical_bytes, canonical_input, digest_obj, same_value)
from dr.emit import NotCanonicalInput, Run  # noqa: E402
from dr.signing import generate_private_key_pem, public_key_pem  # noqa: E402
import tools.arrive as arrive  # noqa: E402

KEY = ["--key", "examples/keys/example-signing-key.pem", "--key-id", "example-2026-10", "--issued-at", "2026-10-28T00:00:00Z"]


def floatify(x):
    if isinstance(x, bool):
        return x
    if isinstance(x, int):
        return float(x)
    if isinstance(x, dict):
        return {k: floatify(v) for k, v in x.items()}
    if isinstance(x, list):
        return [floatify(v) for v in x]
    return x


# (module, policy, traffic, whether the module can run here)
DECIDERS = [
    ("emitters.toolgate", "examples/data/toolgate-policy.json", "examples/data/toolgate-traffic-hour1.jsonl", True),
    ("emitters.toolgate", "examples/data/toolgate-policy.json", "examples/data/toolgate-suite.jsonl", True),
    ("emitters.ratelimit", "examples/data/ratelimit-policy.json", "examples/data/ratelimit-traffic.jsonl", True),
    ("emitters.classrouter", "examples/data/classrouter-policy.json", "examples/data/classrouter-suite.jsonl", True),
    ("emitters.cedar", "examples/cedar/policy-canonical.json", "examples/cedar/inputs-toolcalls.jsonl", True),
    ("emitters.cedar_conformance", "examples/cedar/policy-conformance-handwritten.json", "examples/cedar/inputs-conformance-handwritten.jsonl", True),
]


def _items(traffic):
    return [json.loads(l) for l in (ROOT / traffic).read_text(encoding="utf-8").splitlines() if l.strip()]


def _emit(tmp_path, name, module, policy, items):
    inputs = tmp_path / f"{name}.jsonl"
    inputs.write_text("".join(json.dumps(i) + "\n" for i in items))
    out = tmp_path / name
    p = subprocess.run([sys.executable, "-m", module, "--policy", policy, "--inputs", str(inputs), "--out", str(out),
                        "--record-id", name, *KEY], cwd=ROOT, capture_output=True, text=True)
    return p, out


def _rows(out):
    return [json.loads(l) for l in (out / "decisions.jsonl").read_text().splitlines() if l.strip()]


def _cedar_available():
    try:
        import cedarpy  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.parametrize("module,policy,traffic,_", DECIDERS, ids=[f"{m.split('.')[1]}:{Path(t).stem}" for m, _p, t, _ in DECIDERS])
def test_equal_canonical_bytes_are_decided_identically_through_the_emitter(tmp_path, module, policy, traffic, _):
    if "cedar" in module and not _cedar_available():
        pytest.skip("cedarpy is not installed")
    items = _items(traffic)
    variants = [{**it, "input": floatify(it["input"])} for it in items]
    for a, b in zip(items, variants):
        assert canonical_bytes(a["input"]) == canonical_bytes(b["input"])  # the pair is a pair
    pa, oa = _emit(tmp_path, "as-committed", module, policy, items)
    pb, ob = _emit(tmp_path, "as-floats", module, policy, variants)
    assert pa.returncode == 0, pa.stderr
    assert pb.returncode == 0, pb.stderr
    ra, rb = _rows(oa), _rows(ob)
    assert [(r["input_digest"], r["outcome"], r["reason"]) for r in ra] == [(r["input_digest"], r["outcome"], r["reason"]) for r in rb]
    # and what is retained is the value the digest covers, whichever form arrived
    ia = (oa / "inputs.jsonl").read_text()
    ib = (ob / "inputs.jsonl").read_text()
    assert ia == ib


def test_the_pairs_exercise_the_class():
    """Without the canonical step at least one decider decides a pair differently;
    otherwise the test above would pass whether or not the step is there."""
    import importlib
    differing = 0
    for module, policy, traffic, _ in DECIDERS:
        if "cedar" in module and not _cedar_available():
            continue
        mod = importlib.import_module(module)
        dec = mod.Decider(json.loads((ROOT / policy).read_text()))
        for it in _items(traffic):
            a, b = it["input"], floatify(it["input"])
            if a == b and json.dumps(a) == json.dumps(b):
                continue
            try:
                ra = mod.Decider(json.loads((ROOT / policy).read_text())).decide(a)[:2]
                rb = mod.Decider(json.loads((ROOT / policy).read_text())).decide(b)[:2]
            except Exception:
                differing += 1
                continue
            differing += ra != rb
        del dec
    assert differing > 0


def test_canonical_input_is_a_projection():
    samples = [396, 396.0, -0.0, 1.5, 2**53 - 1, float(2**60), 1e21, 1e-7, [1, 2.0, {"a": 3.0}], {"x": {"y": [0.0, True, None, "s"]}}]
    for x in samples:
        v = canonical_input(x)
        assert canonical_bytes(v) == canonical_bytes(x)          # same digest
        assert same_value(canonical_input(v), v)                  # idempotent
    assert same_value(canonical_input({"order_id": 396.0}), {"order_id": 396})
    assert not same_value(396, 396.0)


def test_an_integer_whose_bytes_stand_for_others_is_not_an_input():
    assert canonical_bytes(9007199254740992) == canonical_bytes(9007199254740993)  # the collision, unchanged in canonical_bytes
    canonical_input(MAX_INPUT_INTEGER)
    for bad in (2**53, -(2**53), 9007199254740993, {"order_id": 2**63 - 1}, [1, -(2**63)]):
        with pytest.raises(NotAnInput):
            canonical_input(bad)
    # canonical_bytes itself is unchanged: no digest anywhere moves
    assert canonical_bytes(2**60) == b"1152921504606847000"  # ECMAScript shortest round-trip, as RFC 8785 says


def _run(tmp_path, **kw):
    return Run(tmp_path / "r", decider_id="t", decider_version="1", outcomes=("ALLOW", "DENY"), policy={"p": 1}, **kw)


def test_the_gate_refuses_an_input_that_is_not_its_own_canonical_value(tmp_path):
    run = _run(tmp_path)
    with pytest.raises(NotCanonicalInput):
        run.decide({"order_id": 396.0}, "DENY", "arg_type:order_id")
    with pytest.raises(NotAnInput):
        run.decide({"order_id": 2**53}, "ALLOW", None)
    run.decide({"order_id": 396}, "ALLOW", None)
    assert len(_rows(tmp_path / "r")) == 1


def test_the_emitter_refuses_an_input_with_no_canonical_value(tmp_path):
    p, out = _emit(tmp_path, "big", "emitters.toolgate", "examples/data/toolgate-policy.json",
                   [{"input": {"tool": "lookup_order", "args": {"order_id": 9007199254740993}}}])
    assert p.returncode != 0
    assert "input 1" in (p.stderr + p.stdout)


def test_the_attester_refuses_before_spending_a_number(tmp_path):
    att = arrive.Attester(tmp_path / "log.jsonl", key_id="c", private_key_pem=generate_private_key_pem())
    with pytest.raises(NotAnInput):
        att.arrive({"order_id": 2**53})
    assert att.arrive({"order_id": 1})["arrival_seq"] == 1
    a = att.arrive({"order_id": 396.0})
    assert a["input_digest"] == digest_obj({"order_id": 396})
    att.close()


def test_replay_fails_the_substitution_the_attester_cannot_see(tmp_path, monkeypatch):
    """The producer decides 396.0 where 396 arrived, with its own writer (the
    honest gate refuses). arrival and invocation establish on equal digests;
    replay decides the value the digest covers and fails the row."""
    import dr.emit as emit_mod
    from emitters import toolgate
    keys = {k: generate_private_key_pem() for k in ("producer", "decider", "customer")}
    regs = {}
    for k, pem in keys.items():
        regs[k] = tmp_path / f"{k}.json"
        regs[k].write_text(json.dumps({"registry_version": 1, "keys": [{"key_id": k, "status": "active", "public_key_pem": public_key_pem(pem)}]}))
    policy = json.loads((ROOT / "examples/data/toolgate-policy.json").read_text())
    dec = toolgate.Decider(policy)
    att = arrive.Attester(tmp_path / "log.jsonl", key_id="customer", private_key_pem=keys["customer"])
    d = tmp_path / "rec"
    run = Run(d, decider_id=toolgate.DECIDER_ID, decider_version=toolgate.DECIDER_VERSION, outcomes=toolgate.OUTCOMES, policy=policy,
              record_id="t", signing_key_id="producer", private_key_pem=keys["producer"],
              decider_key_id="decider", decider_private_key_pem=keys["decider"])
    arrived = {"tool": "lookup_order", "args": {"order_id": 396}}
    a = att.arrive(arrived)
    decided = floatify(arrived)
    o, r, e = dec.decide(decided)
    assert (o, r) == ("DENY", "arg_type:order_id") and dec.decide(arrived)[:2] == ("ALLOW", None)  # the class, for this decider
    monkeypatch.setattr(emit_mod, "same_value", lambda x, y: True)  # the producer's own writer
    run.decide(decided, o, r, ts="2026-10-28T00:00:00Z", ext={**(e or {}), arrive.EXT_KEY: a["arrival_seq"]})
    monkeypatch.undo()
    att.close()
    run.close(issued_at="2026-10-28T00:00:01Z")
    base = [sys.executable, "tools/verify_arrival.py", str(d), "--registry", str(regs["producer"]), "--decider-registry", str(regs["decider"]),
            "--attester-registry", str(regs["customer"]), "--arrival-log", str(tmp_path / "log.jsonl"), "--json"]
    plain = json.loads(subprocess.run(base, cwd=ROOT, capture_output=True, text=True).stdout)
    states = {p["property"]: p["state"] for p in plain["properties"]}
    assert states["arrival"] == "established" and states["invocation"] == "established"
    replayed = json.loads(subprocess.run(base + ["--replay", "emitters.toolgate"], cwd=ROOT, capture_output=True, text=True).stdout)
    rp = next(p for p in replayed["properties"] if p["property"] == "replay")
    assert rp["state"] == "failed"
    assert "not in canonical form" in rp["detail"]
