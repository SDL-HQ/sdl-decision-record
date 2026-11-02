"""The arrival property, over toolgate so no engine is needed.

Run with the suite.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tools.arrive as arrive  # noqa: E402
import tools.verify_arrival as verify_arrival  # noqa: E402
from dr.emit import Run  # noqa: E402
from dr.signing import generate_private_key_pem, public_key_pem  # noqa: E402
from dr.verify import verify_directory  # noqa: E402
from emitters import toolgate  # noqa: E402

POLICY = {"tools": {"get_weather": {"args": {"city": "string"}}, "lookup_order": {"args": {"order_id": "integer"}}}}
INPUTS = [
    {"tool": "get_weather", "args": {"city": "Auckland"}},
    {"tool": "lookup_order", "args": {"order_id": 7}},
    {"tool": "delete_everything", "args": {}},
    {"tool": "lookup_order", "args": {"order_id": "7"}},
    {"tool": "get_weather", "args": {"city": "Auckland"}},  # the same bytes twice: two arrivals, two rows
]


def registry(path: Path, **keys: bytes) -> Path:
    path.write_text(json.dumps({"registry_version": 1, "keys": [
        {"key_id": k, "status": "active", "public_key_pem": public_key_pem(pem)} for k, pem in keys.items()]}))
    return path


@pytest.fixture
def world(tmp_path):
    keys = {k: generate_private_key_pem() for k in ("producer", "decider", "customer")}
    return {
        "keys": keys,
        "producer": registry(tmp_path / "producer.json", producer=keys["producer"]),
        "decider": registry(tmp_path / "decider.json", decider=keys["decider"]),
        "customer": registry(tmp_path / "customer.json", customer=keys["customer"]),
        "theatre": registry(tmp_path / "theatre.json", producer=keys["producer"]),
        "tmp": tmp_path,
    }


def build(world, name, *, seen=None, decided=None, attester="customer", link=lambda i: i, retain_arrivals=True, keyed=False, retain_inputs=True,
          decline_at=None, decline_without_decider=False, retain_subset=None):
    seen = INPUTS if seen is None else seen
    decided = INPUTS if decided is None else decided
    d = world["tmp"] / name
    att = arrive.Attester(world["tmp"] / f"{name}.log.jsonl", key_id=attester, private_key_pem=world["keys"][attester])
    arrivals = [att.arrive(x) for x in seen]
    att.close()
    decider = toolgate.Decider(POLICY)
    outcomes = list(toolgate.OUTCOMES) + (["DECLINED"] if decline_at else [])
    run = Run(d, decider_id=toolgate.DECIDER_ID, decider_version=toolgate.DECIDER_VERSION, outcomes=outcomes, policy=POLICY,
              record_id=f"t-{name}", signing_key_id="producer", private_key_pem=world["keys"]["producer"],
              decider_key_id="decider", decider_private_key_pem=world["keys"]["decider"],
              keyed_digests=keyed, salt=b"\x02" * 32 if keyed else None, retain_inputs=retain_inputs)
    for i, x in enumerate(decided, start=1):
        outcome, reason, ext = decider.decide(x)
        ext = dict(ext or {})
        if link(i) is not None:
            ext[arrive.EXT_KEY] = link(i)
        if decline_at == i:
            run.decide(x, "DECLINED", "budget-exhausted", ts=f"2026-10-26T00:00:{i:02d}Z", ext=ext,
                       decided_by_decider=not decline_without_decider)
            continue
        run.decide(x, outcome, reason, ts=f"2026-10-26T00:00:{i:02d}Z", ext=ext)
    if retain_arrivals:
        kept = arrivals if retain_subset is None else [a for a in arrivals if retain_subset(a["arrival_seq"])]
        (d / arrive.ARRIVALS_FILE).write_text("".join(json.dumps(a, sort_keys=True) + "\n" for a in kept))
    run.close(issued_at="2026-10-26T01:00:00Z")
    return d, world["tmp"] / f"{name}.log.jsonl"


def arrival_state(world, d, *, attester_registry="customer", arrival_log=None, prior=None, prop="arrival"):
    report = verify_directory(d, world["producer"], decider_registry=world["decider"])
    verify_arrival.add_arrival(report, d, registry=world["producer"], attester_registry=world[attester_registry] if attester_registry else None,
                               decider_registry=world["decider"], arrival_log=arrival_log, prior=prior)
    return report.state(prop), report.verdict, next(p["detail"] for p in report.properties if p["property"] == prop)


def test_honest_run_establishes_and_the_reference_verifier_is_untouched(world):
    d, _ = build(world, "honest")
    assert verify_directory(d, world["producer"], decider_registry=world["decider"]).verdict == 0
    state, verdict, _ = arrival_state(world, d)
    assert (state, verdict) == ("established", 0)


def test_a_fabricated_input_fails_however_the_producer_copes(world):
    fab = [dict(x) for x in INPUTS]
    fab[2] = {"tool": "get_weather", "args": {"city": "Wellington"}}  # a benign call that never arrived
    d, _ = build(world, "kept-link", decided=fab)
    assert arrival_state(world, d)[0] == "failed"
    d, _ = build(world, "dropped-link", decided=fab, link=lambda i: None if i == 3 else i)
    assert arrival_state(world, d)[0] == "failed"


def test_the_producer_attesting_its_own_inputs_is_unknown_not_established(world):
    d, _ = build(world, "theatre", attester="producer")
    state, verdict, detail = arrival_state(world, d, attester_registry="theatre")
    assert (state, verdict) == ("unknown", 1)
    assert "producer key" in detail


def test_withholding_the_log_is_not_claimed_and_the_attesters_copy_restores_it(world):
    fab = [dict(x) for x in INPUTS]
    fab[2] = {"tool": "get_weather", "args": {"city": "Wellington"}}
    d, log = build(world, "withheld", decided=fab, retain_arrivals=False)
    assert arrival_state(world, d)[0] == "n/a"
    assert arrival_state(world, d, arrival_log=log)[0] == "failed"


def test_two_rows_naming_one_arrival_fail(world):
    d, _ = build(world, "dup", decided=INPUTS + [INPUTS[2]], link=lambda i: 3 if i == 6 else i)
    state, _, detail = arrival_state(world, d)
    assert state == "failed" and "decided twice" in detail


def test_the_same_bytes_arriving_twice_are_two_arrivals_and_establish(world):
    # INPUTS[0] == INPUTS[4]; a digest alone could not tell them apart.
    d, _ = build(world, "twice")
    assert arrival_state(world, d)[0] == "established"


def test_keyed_rows_need_the_retained_inputs(world):
    d, _ = build(world, "keyed", keyed=True)
    assert arrival_state(world, d)[0] == "established"
    d, _ = build(world, "keyed-withheld", keyed=True, retain_inputs=False)
    assert arrival_state(world, d)[0] == "unknown"


def test_the_two_copies_of_the_log_must_be_the_same_bytes(world):
    d, log = build(world, "two-copies")
    other = world["tmp"] / "other.jsonl"
    other.write_text(log.read_text() + "\n")  # one byte of difference
    assert arrival_state(world, d, arrival_log=other)[0] == "failed"
    assert arrival_state(world, d, arrival_log=log)[0] == "established"


def test_the_row_names_the_arrival_inside_the_hash(world):
    d, _ = build(world, "bound")
    rows = [json.loads(l) for l in (d / "decisions.jsonl").read_text().splitlines() if l.strip()]
    assert all(r["ext"][arrive.EXT_KEY] == r["seq"] for r in rows)
    # Re-pointing a row's link without re-hashing is caught by chain, before arrival is reached.
    rows[1]["ext"][arrive.EXT_KEY] = 1
    (d / "decisions.jsonl").write_text("".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in rows))
    report = verify_directory(d, world["producer"], decider_registry=world["decider"])
    assert report.state("chain") == "failed"


# --- arrivals_accounted ---------------------------------------------------------

def test_from_the_record_alone_accounting_is_not_claimed(world):
    d, _ = build(world, "acc-record")
    state, verdict, _ = arrival_state(world, d, prop="arrivals_accounted")
    assert (state, verdict) == ("n/a", 0)


def test_from_the_attesters_log_the_middle_is_established(world):
    d, log = build(world, "acc-attester")
    state, verdict, _ = arrival_state(world, d, arrival_log=log, prop="arrivals_accounted")
    assert (state, verdict) == ("established", 0)


def test_an_omitted_decision_inside_the_range_is_refuted(world):
    # The producer received five arrivals and recorded four: arrival 3 has no row.
    decided = [INPUTS[0], INPUTS[1], INPUTS[3], INPUTS[4]]
    links = {1: 1, 2: 2, 3: 4, 4: 5}
    d, log = build(world, "acc-omitted", decided=decided, link=lambda i: links[i])
    assert arrival_state(world, d, arrival_log=log)[0] == "established"  # every row's input did arrive
    state, verdict, detail = arrival_state(world, d, arrival_log=log, prop="arrivals_accounted")
    assert (state, verdict) == ("failed", 2) and "arrival [3]" in detail
    # The producer's own retained copy shows the same gap: refuted from either copy.
    assert arrival_state(world, d, prop="arrivals_accounted")[0] == "failed"


def test_a_log_with_an_arrival_cut_out_does_not_account_for_the_range(world):
    # The producer drops decision 3 and hands over a copy of the attester's log
    # with arrival 3 removed. Without the hole check this would be established.
    decided = [INPUTS[0], INPUTS[1], INPUTS[3], INPUTS[4]]
    links = {1: 1, 2: 2, 3: 4, 4: 5}
    d, log = build(world, "acc-trimmed-log", decided=decided, link=lambda i: links[i], retain_arrivals=False)
    trimmed = world["tmp"] / "trimmed.log.jsonl"
    trimmed.write_text("".join(l + "\n" for l in log.read_text().splitlines() if json.loads(l)["arrival_seq"] != 3))
    assert arrival_state(world, d, arrival_log=trimmed)[0] == "established"  # every row's own arrival is there
    state, verdict, detail = arrival_state(world, d, arrival_log=trimmed, prop="arrivals_accounted")
    assert (state, verdict) == ("failed", 2) and "no arrival numbered [3]" in detail


def test_a_retained_copy_with_a_hole_refutes_itself(world):
    # The same omission with the trimmed copy retained under the record: from the record
    # alone this was "not claimed"; the hole in the copy's own numbering now refutes it.
    decided = [INPUTS[0], INPUTS[1], INPUTS[3], INPUTS[4]]
    links = {1: 1, 2: 2, 3: 4, 4: 5}
    d, _ = build(world, "acc-trimmed-retained", decided=decided, link=lambda i: links[i], retain_subset=lambda n: n != 3)
    state, verdict, detail = arrival_state(world, d, prop="arrivals_accounted")
    assert (state, verdict) == ("failed", 2) and "no arrival numbered [3]" in detail


def test_a_refusal_to_decide_is_a_decision_about_that_arrival(world):
    # SPEC section 16.4: the input arrived and the procedure declined it. A row naming the
    # arrival with a declared declining outcome leaves no gap in the range.
    d, log = build(world, "acc-declined", decline_at=3)
    state, verdict, _ = arrival_state(world, d, arrival_log=log, prop="arrivals_accounted")
    assert (state, verdict) == ("established", 0)


def test_a_producer_side_refusal_without_the_decider_is_the_invocation_limit(world):
    # The same row written by the producer alone (section 15's decided_by_decider=False):
    # the range is accounted for and `invocation` fails on that row. The limit, not a gap.
    d, log = build(world, "acc-declined-producer", decline_at=3, decline_without_decider=True)
    report = verify_directory(d, world["producer"], decider_registry=world["decider"])
    assert report.state("invocation") == "failed"
    state, verdict, _ = arrival_state(world, d, arrival_log=log, prop="arrivals_accounted")
    assert (state, verdict) == ("established", 2)


def test_arrivals_outside_the_named_range_are_not_judged(world):
    # Arrivals 1 and 5 belong to neighbouring records; this record decided 2-4.
    d, log = build(world, "acc-neighbours", decided=INPUTS[1:4], link=lambda i: i + 1)
    state, _, detail = arrival_state(world, d, arrival_log=log, prop="arrivals_accounted")
    assert state == "established" and "between 2 and 4" in detail


def test_a_prior_record_closes_the_seam(world):
    # Prior record decided arrivals 1-2; this one decided 4-5; arrival 3 fell between.
    att = arrive.Attester(world["tmp"] / "seam.log.jsonl", key_id="customer", private_key_pem=world["keys"]["customer"])
    arrivals = [att.arrive(x) for x in INPUTS]
    att.close()
    def run(name, decided, link):
        d = world["tmp"] / name
        decider = toolgate.Decider(POLICY)
        r = Run(d, decider_id=toolgate.DECIDER_ID, decider_version=toolgate.DECIDER_VERSION, outcomes=toolgate.OUTCOMES, policy=POLICY,
                record_id=f"t-{name}", signing_key_id="producer", private_key_pem=world["keys"]["producer"])
        for i, x in enumerate(decided, start=1):
            o, why, ext = decider.decide(x)
            r.decide(x, o, why, ts=f"2026-10-27T00:00:{i:02d}Z", ext={**(ext or {}), arrive.EXT_KEY: link(i)})
        (d / arrive.ARRIVALS_FILE).write_text("".join(json.dumps(a, sort_keys=True) + "\n" for a in arrivals))
        r.close(issued_at="2026-10-27T01:00:00Z")
        return d
    prior = run("seam-prior", INPUTS[:2], lambda i: i)
    this = run("seam-this", INPUTS[3:], lambda i: i + 3)
    log = world["tmp"] / "seam.log.jsonl"
    assert arrival_state(world, this, arrival_log=log, prop="arrivals_accounted")[0] == "established"  # alone: 4-5, fine
    state, _, detail = arrival_state(world, this, arrival_log=log, prior=prior, prop="arrivals_accounted")
    assert state == "failed" and "arrival [3]" in detail


# --- a restarted attester ------------------------------------------------

def _attester(world, log):
    return arrive.Attester(log, key_id="customer", private_key_pem=world["keys"]["customer"])


def test_a_restarted_attester_continues_its_numbering(world):
    """A restart is an ordinary event. Numbering from 1 again gave [1, 2, 3, 1, 2],
    which `accounted` fails as two arrivals numbered 1: honest operation
    producing the signature of tampering."""
    log = world["tmp"] / "restart.log.jsonl"
    att = _attester(world, log)
    first = [att.arrive(x) for x in INPUTS[:3]]
    att.close()
    att = _attester(world, log)
    second = [att.arrive(x) for x in INPUTS[3:5]]
    att.close()
    assert [a["arrival_seq"] for a in first + second] == [1, 2, 3, 4, 5]
    assert [a["arrival_seq"] for a in arrive.load(log)] == [1, 2, 3, 4, 5]
    rows = [{"seq": i, "ext": {arrive.EXT_KEY: i}} for i in range(1, 6)]
    state, detail, rng = arrive.accounted(arrive.load(log), rows, from_attester=True)
    assert state == "established", detail
    assert rng == {"first": 1, "last": 5, "accounted": 5}


def test_a_log_that_is_not_a_contiguous_run_from_1_is_refused(world):
    log = world["tmp"] / "gap.log.jsonl"
    att = _attester(world, log)
    arrivals = [att.arrive(x) for x in INPUTS[:3]]
    att.close()
    log.write_text("".join(json.dumps(a, sort_keys=True) + "\n" for a in (arrivals[0], arrivals[2])))
    with pytest.raises(arrive.LogNotContinuable):
        _attester(world, log)
    log.write_text("".join(json.dumps(a, sort_keys=True) + "\n" for a in arrivals[1:]))
    with pytest.raises(arrive.LogNotContinuable):
        _attester(world, log)
    log.write_text(json.dumps(arrivals[0], sort_keys=True) + "\n" + json.dumps({"kind": "something-else"}) + "\n")
    with pytest.raises(arrive.LogNotContinuable):
        _attester(world, log)


def test_a_write_cut_short_by_a_stop_is_dropped_and_the_count_continues(world):
    """`arrive` returns only after the line and its newline are flushed, so a
    torn final line was never handed to anyone and no row can name it."""
    log = world["tmp"] / "torn.log.jsonl"
    att = _attester(world, log)
    [att.arrive(x) for x in INPUTS[:2]]
    att.close()
    with open(log, "a", encoding="utf-8") as f:
        f.write('{"arrival_seq": 3, "input_dig')
    att = _attester(world, log)
    assert att.arrive(INPUTS[2])["arrival_seq"] == 3
    att.close()
    assert [a["arrival_seq"] for a in arrive.load(log)] == [1, 2, 3]


def test_a_complete_final_line_without_a_newline_is_refused(world):
    """Not a torn write: `arrive` writes the newline with the line, so a
    complete arrival without one was not written by this attester."""
    log = world["tmp"] / "nonl.log.jsonl"
    att = _attester(world, log)
    arrivals = [att.arrive(x) for x in INPUTS[:2]]
    att.close()
    log.write_text(json.dumps(arrivals[0], sort_keys=True) + "\n" + json.dumps(arrivals[1], sort_keys=True))
    with pytest.raises(arrive.LogNotContinuable):
        _attester(world, log)
