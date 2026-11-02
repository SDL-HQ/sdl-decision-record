"""Under a policy that requires an arrival, the gate decides nothing without one.

SPEC section 16.8. `{"arrival": "required"}` in the policy object is under the
policy digest; the attester registry the arrival is checked under is supplied
to the gate at runtime, as every registry is. The check sits in Run.decide,
ahead of the decider, so Decider.decide(item) and replay are untouched. The
decider's attestation then carries the arrival it decided, and the invocation
property fails a row re-pointed at another arrival.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import tools.arrive as arrive  # noqa: E402
import tools.verify_arrival as verify_arrival  # noqa: E402
from dr.emit import ArrivalRefused, Run  # noqa: E402
from dr.signing import generate_private_key_pem, public_key_pem, sign_record  # noqa: E402
from dr.verify import verify_directory  # noqa: E402
from emitters import toolgate  # noqa: E402

from conftest import TOOL_POLICY  # noqa: E402

POLICY = {**TOOL_POLICY, "arrival": "required"}
INPUTS = [
    {"tool": "get_weather", "args": {"city": "Auckland"}},
    {"tool": "lookup_order", "args": {"order_id": "7"}},
    {"tool": "get_weather", "args": {"city": "Wellington"}},
]


def registry(path: Path, **keys: bytes) -> Path:
    path.write_text(json.dumps({"registry_version": 1, "keys": [
        {"key_id": k, "status": "active", "public_key_pem": public_key_pem(pem)} for k, pem in keys.items()]}))
    return path


@pytest.fixture
def world(tmp_path):
    keys = {k: generate_private_key_pem() for k in ("producer", "decider", "customer")}
    areg = {"registry_version": 1, "keys": [{"key_id": "customer", "status": "active", "public_key_pem": public_key_pem(keys["customer"])}]}
    return {"keys": keys, "areg": areg,
            "producer": registry(tmp_path / "producer.json", producer=keys["producer"]),
            "decider": registry(tmp_path / "decider.json", decider=keys["decider"]),
            "customer": registry(tmp_path / "customer.json", customer=keys["customer"]),
            "tmp": tmp_path}


def run(world, name, *, policy=POLICY, areg="default"):
    return Run(world["tmp"] / name, decider_id=toolgate.DECIDER_ID, decider_version=toolgate.DECIDER_VERSION, outcomes=toolgate.OUTCOMES,
               policy=policy, record_id=f"t-{name}", signing_key_id="producer", private_key_pem=world["keys"]["producer"],
               decider_key_id="decider", decider_private_key_pem=world["keys"]["decider"],
               attester_registry=world["areg"] if areg == "default" else areg)


def attester(world, name):
    return arrive.Attester(world["tmp"] / f"{name}.log.jsonl", key_id="customer", private_key_pem=world["keys"]["customer"])


def states(world, d, log=None):
    report = verify_directory(d, world["producer"], decider_registry=world["decider"])
    verify_arrival.add_arrival(report, d, registry=world["producer"], attester_registry=world["customer"],
                               decider_registry=world["decider"], arrival_log=log)
    return {p["property"]: p for p in report.properties}, report.verdict


def test_the_policy_requires_a_registry_to_check_under(world):
    with pytest.raises(ValueError):
        run(world, "no-registry", areg=None)


def test_an_input_with_no_arrival_is_refused_and_nothing_is_written(world):
    r = run(world, "refused")
    decider = toolgate.Decider(POLICY)
    o, why, ext = decider.decide(INPUTS[0])
    with pytest.raises(ArrivalRefused):
        r.decide(INPUTS[0], o, why, ext=ext)
    assert not (world["tmp"] / "refused" / "decisions.jsonl").read_text().strip()


def test_an_arrival_over_a_different_input_is_refused(world):
    r = run(world, "wrong-input")
    att = attester(world, "wrong-input")
    a = att.arrive(INPUTS[1])  # the attester saw a different call
    decider = toolgate.Decider(POLICY)
    o, why, ext = decider.decide(INPUTS[0])
    with pytest.raises(ArrivalRefused, match="different input"):
        r.decide(INPUTS[0], o, why, ext=ext, arrival=a)


def test_an_arrival_under_a_key_the_gate_does_not_honour_is_refused(world):
    r = run(world, "bad-key")
    body = {"kind": arrive.KIND, "arrival_seq": 1, "input_digest": arrive.digest_obj(INPUTS[0]), "attester_key_id": "producer"}
    a = sign_record(body, world["keys"]["producer"])  # the producer signing its own arrival
    decider = toolgate.Decider(POLICY)
    o, why, ext = decider.decide(INPUTS[0])
    with pytest.raises(ArrivalRefused):
        r.decide(INPUTS[0], o, why, ext=ext, arrival=a)


def test_an_honest_run_names_each_arrival_and_the_decider_signs_it(world):
    r = run(world, "honest")
    att = attester(world, "honest")
    decider = toolgate.Decider(POLICY)
    for x in INPUTS:
        a = att.arrive(x)
        o, why, ext = decider.decide(x)
        r.decide(x, o, why, ext=ext, arrival=a)
    att.close()
    d = world["tmp"] / "honest"
    (d / arrive.ARRIVALS_FILE).write_text(att.log_path.read_text())
    r.close(issued_at="2026-10-28T00:00:00Z")
    rows = [json.loads(l) for l in (d / "decisions.jsonl").read_text().splitlines()]
    assert [row["ext"]["arrival"] for row in rows] == [1, 2, 3]
    atts = [json.loads(l) for l in (d / "attestations.jsonl").read_text().splitlines()]
    assert [a["arrival"] for a in atts] == [1, 2, 3]
    props, verdict = states(world, d, log=att.log_path)
    assert verdict == 0
    assert props["invocation"]["state"] == "established"
    assert props["arrival"]["state"] == "established"
    assert props["arrivals_accounted"]["state"] == "established"
    assert props["arrivals_accounted"]["range"] == {"first": 1, "last": 3, "accounted": 3}
    assert props["arrivals_accounted"]["detail"].startswith("between 1 and 3:")


def test_a_row_re_pointed_at_another_arrival_fails_invocation(world):
    r = run(world, "repointed")
    att = attester(world, "repointed")
    decider = toolgate.Decider(POLICY)
    for x in INPUTS:
        a = att.arrive(x)
        o, why, ext = decider.decide(x)
        r.decide(x, o, why, ext=ext, arrival=a)
    att.close()
    d = world["tmp"] / "repointed"
    (d / arrive.ARRIVALS_FILE).write_text(att.log_path.read_text())
    r.close(issued_at="2026-10-28T00:00:00Z")
    # The producer re-points row 2 at arrival 3 and re-chains and re-signs: the
    # decider's attestation still says 2, so invocation fails on its own.
    from dr.rows import row_hash
    rows = [json.loads(l) for l in (d / "decisions.jsonl").read_text().splitlines()]
    rows[1]["ext"]["arrival"] = 3
    prev = "GENESIS"
    out = []
    for row in rows:
        body = {k: v for k, v in row.items() if k not in ("prev_hash", "row_hash")}
        body["prev_hash"] = prev
        body["row_hash"] = row_hash(prev, body)
        prev = body["row_hash"]
        out.append(body)
    (d / "decisions.jsonl").write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in out))
    rec = json.loads((d / "record.json").read_text())
    rec["ledger"]["terminal_hash"] = prev
    for k in ("payload_hash", "signature"):
        rec.pop(k, None)
    (d / "record.json").write_text(json.dumps(sign_record(rec, world["keys"]["producer"]), sort_keys=True))
    props, verdict = states(world, d, log=att.log_path)
    assert verdict == 2
    assert props["invocation"]["state"] == "failed" and "re-pointed" in props["invocation"]["detail"]


def test_a_row_the_producer_wrote_itself_under_a_requiring_policy_contradicts_the_record(world):
    # The producer bypasses the gate: decided_by_decider=False, no arrival. The policy
    # under the digest says the gate decides nothing without one, so the row contradicts
    # the record from its own contents, with no arrival file or log in hand.
    # Run.decide refuses with no arrival even for a forwarded row, so a producer that
    # bypasses the gate writes the rows with its own tooling. Simulate that by writing
    # under a copy of the policy without the requirement and swapping the policy file.
    decider = toolgate.Decider(POLICY)
    r2 = Run(world["tmp"] / "bypass2", decider_id=toolgate.DECIDER_ID, decider_version=toolgate.DECIDER_VERSION, outcomes=toolgate.OUTCOMES,
             policy=TOOL_POLICY, record_id="t-bypass2", signing_key_id="producer", private_key_pem=world["keys"]["producer"])
    for x in INPUTS[:2]:
        o, why, ext = decider.decide(x)
        r2.decide(x, o, why, ext=ext, decided_by_decider=False)
    r2.close(issued_at="2026-10-28T00:00:00Z")
    d = world["tmp"] / "bypass2"
    (d / "policy.json").write_text(json.dumps(POLICY, sort_keys=True))
    props, _ = states(world, d)
    assert props["arrival"]["state"] == "failed" and "requires an arrival" in props["arrival"]["detail"]


def test_replay_is_untouched_by_the_requirement(world):
    # Replay constructs Decider(policy) and calls decide(item): the requirement lives in
    # the gate, not the decider, so an honest record under the requiring policy replays.
    r = run(world, "replayed")
    att = attester(world, "replayed")
    decider = toolgate.Decider(POLICY)
    for x in INPUTS:
        a = att.arrive(x)
        o, why, ext = decider.decide(x)
        r.decide(x, o, why, ext=ext, arrival=a)
    att.close()
    d = world["tmp"] / "replayed"
    (d / arrive.ARRIVALS_FILE).write_text(att.log_path.read_text())
    r.close(issued_at="2026-10-28T00:00:00Z")
    report = verify_directory(d, world["producer"], decider_registry=world["decider"], replay_module="emitters.toolgate")
    assert report.state("replay") == "established"
