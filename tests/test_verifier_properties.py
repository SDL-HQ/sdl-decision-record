"""Every property the verifier reports, and the tamper that turns it."""

import json

import pytest

from conftest import build_run, read_record, read_rows, resign, states, verify, write_record, write_rows
from dr.canonical import digest_obj
from emitters import ratelimit


def test_an_honest_benchmark_record_is_established(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    rep = verify(d, keys)
    s = states(rep)
    assert rep.verdict == 0
    assert s == {
        "document": "established", "signing_trust": "established", "signature": "established",
        "chain": "established", "decisions": "established", "profile": "established",
        "correctness": "established", "retained": "established", "replay": "n/a", "invocation": "n/a",
        "stream": "n/a", "completeness": "n/a", "receipts": "n/a", "witness": "n/a",
    }


def test_an_honest_production_record_is_established_with_correctness_not_applicable(tmp_path, keys):
    d = build_run(tmp_path / "run", keys, labelled=False)
    rep = verify(d, keys)
    assert rep.verdict == 0
    assert states(rep)["correctness"] == "n/a"
    assert "benchmark" not in read_record(d)


def test_counts_are_recomputed_not_trusted(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    resign(d, keys["pem"], lambda r: r["counts"]["by_outcome"].update(DENY=0))
    s = states(verify(d, keys))
    assert s["signature"] == "established" and s["decisions"] == "failed"


def test_policy_digests_are_recomputed(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    resign(d, keys["pem"], lambda r: r.update(policy_digests=["sha256:" + "a" * 64]))
    assert states(verify(d, keys))["decisions"] == "failed"


def test_decider_identity_is_recomputed(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    resign(d, keys["pem"], lambda r: r["decider"].update(version="9.9.9"))
    assert states(verify(d, keys))["decisions"] == "failed"


def test_an_outcome_outside_the_declared_vocabulary_fails(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    resign(d, keys["pem"], lambda r: r["decider"].update(outcomes=["ALLOW"]))
    s = states(verify(d, keys))
    assert s["decisions"] == "failed"


def test_correctness_is_recomputed_from_labels(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    resign(d, keys["pem"], lambda r: r["benchmark"].update(agree=1, disagree=4))
    s = states(verify(d, keys))
    assert s["decisions"] == "established" and s["correctness"] == "failed"


def test_row_count_is_bound(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    resign(d, keys["pem"], lambda r: r["ledger"].update(row_count=4))
    assert states(verify(d, keys))["chain"] == "failed"


def test_a_missing_ledger_fails_the_chain_and_leaves_the_rest_unknown(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    (d / "decisions.jsonl").unlink()
    rep = verify(d, keys)
    s = states(rep)
    assert s["chain"] == "failed" and s["decisions"] == "unknown" and rep.verdict == 2


def test_a_retained_file_that_changed_fails_custody(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    (d / "policy.json").write_text("{}")
    assert states(verify(d, keys))["retained"] == "failed"


def test_a_retained_file_that_is_absent_is_unknown_and_replay_cannot_run(tmp_path, keys):
    """The record names inputs.jsonl; this copy lacks it. The digest check could
    not run: unknown, not failed. Replay then has nothing to replay, and
    the verdict is NOT ESTABLISHED, never ESTABLISHED."""
    d = build_run(tmp_path / "run", keys)
    (d / "inputs.jsonl").unlink()
    rep = verify(d, keys, replay="emitters.toolgate")
    s = states(rep)
    assert s["retained"] == "unknown" and s["replay"] == "unknown" and rep.verdict == 1
    detail = {p["property"]: p["detail"] for p in rep.properties}["retained"]
    assert "not present in this copy" in detail and "inputs.jsonl" in detail


def test_a_retained_file_that_is_present_and_differs_fails(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    (d / "inputs.jsonl").write_text("")
    assert states(verify(d, keys))["retained"] == "failed"


def test_an_absent_file_does_not_hide_a_differing_one(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    (d / "inputs.jsonl").unlink()
    (d / "policy.json").write_text("{}")
    rep = verify(d, keys)
    assert states(rep)["retained"] == "failed" and rep.verdict == 2


def test_retained_inputs_must_hash_to_the_rows(tmp_path, keys):
    """A retained inputs file whose digest the record carries, but whose entries do not match the rows: a producer substituting inputs after the fact."""
    d = build_run(tmp_path / "run", keys)
    lines = [json.loads(l) for l in (d / "inputs.jsonl").read_text().splitlines()]
    lines[0]["input"] = {"tool": "get_weather", "args": {"city": "Elsewhere"}}
    (d / "inputs.jsonl").write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in lines))
    from dr.canonical import digest_file

    resign(d, keys["pem"], lambda r: r["retained"].update({"inputs.jsonl": digest_file(d / "inputs.jsonl")}))
    s = states(verify(d, keys))
    assert s["signature"] == "established" and s["retained"] == "failed"


def test_retained_policy_must_be_the_policy_the_rows_ran_under(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    (d / "policy.json").write_text(json.dumps({"tools": {}}))
    from dr.canonical import digest_file

    resign(d, keys["pem"], lambda r: r["retained"].update({"policy.json": digest_file(d / "policy.json")}))
    s = states(verify(d, keys))
    assert s["retained"] == "failed"


def test_no_retained_files_is_not_applicable_and_still_establishes(tmp_path, keys):
    d = build_run(tmp_path / "run", keys, retain_inputs=False)
    (d / "policy.json").unlink()
    resign(d, keys["pem"], lambda r: r.update(retained={}))
    rep = verify(d, keys)
    assert states(rep)["retained"] == "n/a" and rep.verdict == 0


def test_an_unnamed_file_in_the_directory_is_noted_not_vouched_for(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    (d / "notes.txt").write_text("hello")
    rep = verify(d, keys)
    assert rep.verdict == 0 and any("notes.txt" in n for n in rep.notes)


def test_replay_establishes_and_fails(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    assert states(verify(d, keys, replay="emitters.toolgate"))["replay"] == "established"
    # a record whose rows say DENY where the decider says ALLOW, re-hashed and re-signed: honest chain, dishonest decision
    rows = read_rows(d)
    rows[0]["outcome"] = "DENY"
    rows[0]["reason"] = "invented"
    from dr.rows import GENESIS, row_hash

    prev = GENESIS
    for r in rows:
        r["prev_hash"] = prev
        r["row_hash"] = row_hash(prev, r)
        prev = r["row_hash"]
    write_rows(d, rows)
    from dr import derive

    def fix(rec):
        rec["ledger"]["terminal_hash"] = prev
        rec["counts"] = derive.counts(rows)
        rec["benchmark"] = derive.benchmark(rows)

    resign(d, keys["pem"], fix)
    s = states(verify(d, keys, replay="emitters.toolgate"))
    assert s["chain"] == "established" and s["decisions"] == "established" and s["replay"] == "failed"


def test_replay_with_the_wrong_decider_is_unknown(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    assert states(verify(d, keys, replay="emitters.ratelimit"))["replay"] == "unknown"


def test_replay_without_retained_inputs_is_unknown(tmp_path, keys):
    d = build_run(tmp_path / "run", keys, retain_inputs=False)
    assert states(verify(d, keys, replay="emitters.toolgate"))["replay"] == "unknown"


def test_unknown_is_never_a_pass(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    rows = read_rows(d)
    for r in rows:
        r["v"] = 3
    write_rows(d, rows)
    rep = verify(d, keys)
    assert states(rep)["chain"] == "unknown" and rep.verdict == 1


def test_unknown_format_version_judges_nothing(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    resign(d, keys["pem"], lambda r: r.update(format_version=3))
    rep = verify(d, keys)
    assert all(p["state"] == "unknown" for p in rep.properties) and rep.verdict == 1


def test_record_shape_rejects_undeclared_keys(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    resign(d, keys["pem"], lambda r: r.update(counters_checked_against_ledger=True))
    s = states(verify(d, keys))
    assert s["document"] == "failed"


def test_stateful_decider_replays_in_order_only(tmp_path, keys):
    items = [{"input": {"principal": "a", "at": t}} for t in (1, 2, 3, 4, 5, 100, 101, 102, 103)]
    d = build_run(tmp_path / "run", keys, module=ratelimit, policy={"window_seconds": 10, "max_requests": 3}, items=items, labelled=False)
    rows = read_rows(d)
    assert [r["outcome"] for r in rows] == ["ALLOW"] * 3 + ["DENY"] * 2 + ["ALLOW"] * 3 + ["DENY"]
    assert states(verify(d, keys, replay="emitters.ratelimit"))["replay"] == "established"
    # the same inputs in a different order give different decisions: a single row is not independently re-derivable
    rev = list(reversed(items))
    d2 = build_run(tmp_path / "run2", keys, module=ratelimit, policy={"window_seconds": 10, "max_requests": 3}, items=rev, labelled=False)
    assert [r["outcome"] for r in read_rows(d2)] != list(reversed([r["outcome"] for r in rows]))


def test_text_and_json_reports_agree(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    rep = verify(d, keys)
    as_json = json.loads(rep.to_json(d))
    assert as_json["verdict"] == "ESTABLISHED" and "VERDICT: ESTABLISHED" in rep.to_text(d)


def test_a_retained_file_of_any_kind_that_is_absent_is_unknown(tmp_path, keys):
    """Not only inputs.jsonl and policy.json: any file the record names is checked, and any absent one leaves custody unknown."""
    from dr.emit import Run
    from emitters import toolgate

    run = Run(tmp_path / "run", decider_id="toolgate", decider_version="1.0.0", outcomes=toolgate.OUTCOMES, policy={"tools": {}})
    (tmp_path / "run" / "operator-notes.txt").write_text("shift notes\n")
    run.decide({"tool": "x"}, "DENY", "tool_not_allowlisted", ts="2026-10-18T00:00:00Z")
    run.close(record_id="r", signing_key_id="k1", private_key_pem=keys["pem"], issued_at="2026-10-18T01:00:00Z")
    assert "operator-notes.txt" in read_record(tmp_path / "run")["retained"]
    assert states(verify(tmp_path / "run", keys))["retained"] == "established"
    (tmp_path / "run" / "operator-notes.txt").unlink()
    assert states(verify(tmp_path / "run", keys))["retained"] == "unknown"


def test_a_benchmark_with_a_disagreement_is_an_honest_established_record(tmp_path, keys):
    from conftest import TOOL_SUITE

    items = [dict(x) for x in TOOL_SUITE]
    items[0]["label"] = "DENY"  # the suite author was wrong, or the gate is: either way the record says so
    d = build_run(tmp_path / "run", keys, items=items)
    r = read_record(d)
    assert r["benchmark"]["agree"] == 4 and r["benchmark"]["disagree"] == 1
    assert r["benchmark"]["by_label"] == {"ALLOW": {"ALLOW": 1}, "DENY": {"ALLOW": 1, "DENY": 3}}
    assert verify(d, keys).verdict == 0


def test_replay_compares_the_reason_as_well_as_the_outcome(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    rows = read_rows(d)
    assert rows[2]["outcome"] == "DENY"
    rows[2]["reason"] = "arg_missing:order_id"  # a different reason for the same outcome
    from dr.rows import GENESIS, row_hash

    prev = GENESIS
    for r in rows:
        r["prev_hash"] = prev
        r["row_hash"] = row_hash(prev, r)
        prev = r["row_hash"]
    write_rows(d, rows)
    resign(d, keys["pem"], lambda rec: rec["ledger"].update(terminal_hash=prev))
    s = states(verify(d, keys, replay="emitters.toolgate"))
    assert s["decisions"] == "established" and s["replay"] == "failed"
