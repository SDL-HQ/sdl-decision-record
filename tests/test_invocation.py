"""Decider attestations: the invocation property, and the case replay cannot see.

A producer that writes rows without calling the decider produces rows the
decider would also have produced, and replay establishes them. With
attestations, those rows have no decider signature and the verifier says so.
"""

import json
from pathlib import Path

from dr import attest
from dr.emit import Run
from dr.signing import generate_private_key_pem, public_key_pem
from dr.verify import verify_directory
from emitters import toolgate

from conftest import states

POLICY = {"tools": {"echo": {"args": {"text": "string"}}}}


def _registry(path: Path, key_id: str, pem: bytes) -> Path:
    path.write_text(json.dumps({"registry_version": 1, "keys": [{"key_id": key_id, "status": "active", "public_key_pem": public_key_pem(pem)}]}))
    return path


def _run(directory: Path, producer_pem: bytes, decider_pem: bytes, ungated_from: int | None = None):
    decider = toolgate.Decider(POLICY)
    run = Run(directory, decider_id=toolgate.DECIDER_ID, decider_version=toolgate.DECIDER_VERSION, outcomes=toolgate.OUTCOMES, policy=POLICY,
              record_id="attested-run", signing_key_id="producer", private_key_pem=producer_pem, decider_key_id="gate", decider_private_key_pem=decider_pem)
    items = [{"tool": "echo", "args": {"text": f"hello {i}"}} for i in range(6)]
    for i, item in enumerate(items, 1):
        if ungated_from is not None and i >= ungated_from:
            # the producer forwards without the gate and writes the outcome the gate would have given
            run.decide(item, "ALLOW", None, ts="2026-10-20T00:00:00Z", label="ALLOW", decided_by_decider=False)
        else:
            outcome, reason, ext = decider.decide(item)
            run.decide(item, outcome, reason, ts="2026-10-20T00:00:00Z", label="ALLOW", ext=ext)
    run.close(issued_at="2026-10-20T00:01:00Z", profile="benchmark")
    return directory


def test_attested_rows_establish_invocation(tmp_path):
    producer, gate = generate_private_key_pem(), generate_private_key_pem()
    preg, dreg = _registry(tmp_path / "producer.json", "producer", producer), _registry(tmp_path / "decider.json", "gate", gate)
    d = _run(tmp_path / "run", producer, gate)
    assert attest.ATTESTATIONS_FILE in json.loads((d / "record.json").read_text())["retained"]
    s = states(verify_directory(d, preg, replay_module="emitters.toolgate", decider_registry=dreg))
    assert s["replay"] == "established" and s["invocation"] == "established"
    assert states(verify_directory(d, preg, replay_module="emitters.toolgate"))["invocation"] == "unknown"  # no decider registry


def test_rows_the_decider_never_saw_fail_invocation_even_when_replay_agrees(tmp_path):
    producer, gate = generate_private_key_pem(), generate_private_key_pem()
    preg, dreg = _registry(tmp_path / "producer.json", "producer", producer), _registry(tmp_path / "decider.json", "gate", gate)
    d = _run(tmp_path / "run", producer, gate, ungated_from=4)
    rep = verify_directory(d, preg, replay_module="emitters.toolgate", decider_registry=dreg)
    s = states(rep)
    assert s["replay"] == "established", "the forwarded rows carry the outcome the gate would have given, so replay cannot tell"
    assert s["invocation"] == "failed"
    detail = {p["property"]: p["detail"] for p in rep.properties}["invocation"]
    assert "3 of 6 rows have no decider attestation" in detail and "[4, 5, 6]" in detail
    assert rep.verdict == 2


def test_a_producer_key_cannot_attest_its_own_rows(tmp_path):
    producer = generate_private_key_pem()
    preg = _registry(tmp_path / "producer.json", "producer", producer)
    dreg = _registry(tmp_path / "decider.json", "gate", producer)  # the same key under another name
    d = _run(tmp_path / "run", producer, producer)
    s = states(verify_directory(d, preg, decider_registry=dreg))
    assert s["invocation"] == "unknown"


def test_an_attestation_that_does_not_match_its_row_fails(tmp_path):
    producer, gate = generate_private_key_pem(), generate_private_key_pem()
    preg, dreg = _registry(tmp_path / "producer.json", "producer", producer), _registry(tmp_path / "decider.json", "gate", gate)
    d = _run(tmp_path / "run", producer, gate)
    rows = [json.loads(l) for l in (d / "decisions.jsonl").read_text().splitlines()]
    a = attest.load(d / attest.ATTESTATIONS_FILE)
    other = dict(rows[0]); other["outcome"] = "DENY"
    forged = attest.attest(other, record_id="attested-run", decider_key_id="gate", private_key_pem=gate)
    state, detail = attest.check([forged] + a[1:], json.loads((d / "record.json").read_text()), rows, json.loads(dreg.read_text()), json.loads(preg.read_text()))
    assert state == "failed" and "does not match the row on ['outcome']" in detail
