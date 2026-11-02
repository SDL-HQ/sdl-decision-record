"""What a record cannot say about itself, and what makes deletion detectable.

The first test is the limit, made runnable: delete decisions, re-sign, and
every property holds. The rest are the mechanisms that cross the boundary, each
with the exact thing it establishes and the exact thing it does not.
"""

import json
from pathlib import Path

import pytest

from conftest import TOOL_POLICY, TOOL_SUITE, build_run, read_record, read_rows, states, verify
from dr import receipts, witness
from dr.emit import Run
from dr.signing import generate_private_key_pem, public_key_pem
from dr.stream import check_sequence, link_defects
from dr.verify import verify_directory
from emitters import ratelimit, toolgate
from tools.truncate import truncate


def test_the_limit_deleting_decisions_and_resigning_verifies_clean(tmp_path, keys):
    d = build_run(tmp_path / "run", keys, labelled=False)
    t = truncate(d, tmp_path / "truncated", drop=[2, 4], private_key_pem=keys["pem"])
    rep = verify(t, keys, replay="emitters.toolgate")
    assert rep.verdict == 0
    assert read_record(t)["counts"]["decisions"] == 3
    s = states(rep)
    assert s["completeness"] == "n/a" and s["replay"] == "established"


def _run_with_receipts(directory, keys, items, module=toolgate, policy=TOOL_POLICY, stream=None):
    decider = module.Decider(policy)
    run = Run(
        directory, decider_id=module.DECIDER_ID, decider_version=module.DECIDER_VERSION, outcomes=module.OUTCOMES, policy=policy,
        stream=stream, record_id=directory.name, signing_key_id=keys["key_id"], private_key_pem=keys["pem"], issue_receipts=True,
    )
    for i, item in enumerate(items):
        outcome, reason, ext = decider.decide(item["input"])
        run.decide(item["input"], outcome, reason, ts=f"2026-10-18T00:00:{i:02d}Z", ext=ext)
    run.close(issued_at="2026-10-18T01:00:00Z")
    rdir = directory.parent / f"{directory.name}-receipts"
    rdir.mkdir()
    paths = []
    for r in run.receipts:
        p = rdir / f"receipt-{r['seq']}.json"
        p.write_text(json.dumps(r, sort_keys=True))
        paths.append(p)
    return directory, paths


def test_a_receipt_for_a_deleted_decision_refutes_completeness_and_counts_the_gap(tmp_path, keys):
    d, rcpts = _run_with_receipts(tmp_path / "run", keys, TOOL_SUITE)
    t = truncate(d, tmp_path / "truncated", drop=[4, 5], private_key_pem=keys["pem"])
    rep = verify_directory(t, keys["registry"], receipt_paths=rcpts)
    s = {p["property"]: (p["state"], p["detail"]) for p in rep.properties}
    assert s["completeness"][0] == "failed" and "at least 2 acknowledged decision(s) are not in it" in s["completeness"][1]
    assert s["receipts"][0] == "failed"
    assert rep.verdict == 2


def test_receipts_for_decisions_that_are_present_are_included_and_establish_nothing_more(tmp_path, keys):
    d, rcpts = _run_with_receipts(tmp_path / "run", keys, TOOL_SUITE)
    rep = verify_directory(d, keys["registry"], receipt_paths=rcpts)
    s = states(rep)
    assert s["receipts"] == "established" and s["completeness"] == "n/a" and rep.verdict == 0


def test_deleting_an_interior_row_turns_a_later_receipt_into_an_alteration(tmp_path, keys):
    d, rcpts = _run_with_receipts(tmp_path / "run", keys, TOOL_SUITE)
    t = truncate(d, tmp_path / "truncated", drop=[2], private_key_pem=keys["pem"])
    rep = verify_directory(t, keys["registry"], receipt_paths=[rcpts[2]])  # receipt for original seq 3, now at seq 2
    s = {p["property"]: (p["state"], p["detail"]) for p in rep.properties}
    assert s["receipts"][0] == "failed" and "receipted row_hash" in s["receipts"][1]


def test_a_receipt_forged_with_another_key_is_invalid_and_a_foreign_one_is_ignored(tmp_path, keys):
    d, rcpts = _run_with_receipts(tmp_path / "run", keys, TOOL_SUITE)
    rows = read_rows(d)
    forged = receipts.issue(rows[0], record_id=d.name, stream_id=None, first_decision=1, signing_key_id="k1", private_key_pem=generate_private_key_pem())
    fp = tmp_path / "forged.json"
    fp.write_text(json.dumps(forged))
    other = receipts.issue(rows[0], record_id="some-other-run", stream_id=None, first_decision=1, signing_key_id="k1", private_key_pem=keys["pem"])
    op = tmp_path / "other.json"
    op.write_text(json.dumps(other))
    assert states(verify_directory(d, keys["registry"], receipt_paths=[fp]))["receipts"] == "failed"
    assert states(verify_directory(d, keys["registry"], receipt_paths=[op]))["receipts"] == "unknown"


def test_a_stateful_decider_is_partly_self_witnessing(tmp_path, keys):
    """Deleting a row that influenced a later decision breaks replay; deleting one that did not does not."""
    items = [{"input": {"principal": "a", "at": t}} for t in (1, 2, 3, 4)] + [{"input": {"principal": "b", "at": 50}}]
    policy = {"window_seconds": 10, "max_requests": 3}
    d = build_run(tmp_path / "run", keys, module=ratelimit, policy=policy, items=items, labelled=False)
    assert [r["outcome"] for r in read_rows(d)] == ["ALLOW", "ALLOW", "ALLOW", "DENY", "ALLOW"]
    t1 = truncate(d, tmp_path / "t1", drop=[1], private_key_pem=keys["pem"])  # a's first request: row 4's DENY now unexplained
    assert states(verify(t1, keys, replay="emitters.ratelimit"))["replay"] == "failed"
    t2 = truncate(d, tmp_path / "t2", drop=[5], private_key_pem=keys["pem"])  # b's only request: nothing depended on it
    assert states(verify(t2, keys, replay="emitters.ratelimit"))["replay"] == "established"


def _three_linked_runs(tmp_path, keys, stream_id="s"):
    dirs, records = [], []
    prev_hash, first = None, 1
    for n in range(1, 4):
        d = tmp_path / f"run{n}"
        stream = {"stream_id": stream_id, "seq": n, "prev_record_hash": prev_hash, "first_decision": first}
        build = Run(d, decider_id="toolgate", decider_version="1.0.0", outcomes=toolgate.OUTCOMES, policy=TOOL_POLICY, stream=stream)
        dec = toolgate.Decider(TOOL_POLICY)
        for i, item in enumerate(TOOL_SUITE[: n + 1]):
            o, r, e = dec.decide(item["input"])
            build.decide(item["input"], o, r, ts=f"2026-10-18T0{n}:00:{i:02d}Z")
        build.close(record_id=f"run{n}", signing_key_id=keys["key_id"], private_key_pem=keys["pem"], issued_at=f"2026-10-18T0{n}:59:00Z")
        rec = read_record(d)
        dirs.append(d)
        records.append(rec)
        prev_hash, first = rec["payload_hash"], first + rec["ledger"]["row_count"]
    return dirs, records


def test_a_stream_links_and_the_verifier_checks_the_link_only_with_the_prior(tmp_path, keys):
    dirs, records = _three_linked_runs(tmp_path, keys)
    assert records[0]["format_version"] == 2 and records[1]["stream"]["first_decision"] == 3
    assert states(verify_directory(dirs[0], keys["registry"]))["stream"] == "established"
    assert states(verify_directory(dirs[1], keys["registry"]))["stream"] == "unknown"
    assert states(verify_directory(dirs[1], keys["registry"], prior_record=dirs[0] / "record.json"))["stream"] == "established"
    assert states(verify_directory(dirs[2], keys["registry"], prior_record=dirs[0] / "record.json"))["stream"] == "failed"
    defects, forks = check_sequence(records)
    assert defects == [] and forks == []


def test_tail_truncation_of_a_stream_is_undetectable_from_the_records_alone(tmp_path, keys):
    dirs, records = _three_linked_runs(tmp_path, keys)
    defects, forks = check_sequence(records[:2])
    assert defects == [] and forks == []  # the limit: nothing says run3 exists


def test_a_removed_middle_record_and_a_fork_are_detected(tmp_path, keys):
    dirs, records = _three_linked_runs(tmp_path, keys)
    defects, _ = check_sequence([records[0], records[2]])
    assert any("records 2..2 are not here" in d for d in defects)
    # the producer signs a second, different history for seq 2
    alt = tmp_path / "alt2"
    stream = dict(records[1]["stream"])
    build = Run(alt, decider_id="toolgate", decider_version="1.0.0", outcomes=toolgate.OUTCOMES, policy=TOOL_POLICY, stream=stream)
    build.decide({"tool": "nope", "args": {}}, "DENY", "tool_not_allowlisted", ts="2026-10-18T02:00:00Z")
    build.decide({"tool": "nope2", "args": {}}, "DENY", "tool_not_allowlisted", ts="2026-10-18T02:00:01Z")
    build.decide({"tool": "nope3", "args": {}}, "DENY", "tool_not_allowlisted", ts="2026-10-18T02:00:02Z")
    build.close(record_id="run2b", signing_key_id=keys["key_id"], private_key_pem=keys["pem"], issued_at="2026-10-18T02:59:00Z")
    defects, forks = check_sequence(records + [read_record(alt)])
    assert len(forks) == 1 and "seq 2" in forks[0]


def test_a_witness_statement_establishes_existence_at_a_time_and_nothing_before(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    rec = read_record(d)
    wpem = generate_private_key_pem()
    wreg = tmp_path / "witnesses.json"
    wreg.write_text(json.dumps({"registry_version": 1, "keys": [{"key_id": "w1", "status": "active", "public_key_pem": public_key_pem(wpem)}]}))
    st = witness.countersign(rec["payload_hash"], witness_key_id="w1", private_key_pem=wpem, witnessed_at="2026-10-18T05:00:00Z")
    sp = tmp_path / "statement.json"
    sp.write_text(json.dumps(st))
    s = {p["property"]: (p["state"], p["detail"]) for p in verify_directory(d, keys["registry"], witness_statement=sp, witness_registry=wreg).properties}
    assert s["witness"][0] == "established" and "bounds nothing before that" in s["witness"][1]
    # the same statement does not witness a truncated re-signing of the record
    t = truncate(d, tmp_path / "t", drop=[1], private_key_pem=keys["pem"])
    assert states(verify_directory(t, keys["registry"], witness_statement=sp, witness_registry=wreg))["witness"] == "failed"
    # a producer witnessing itself is unknown, whatever the key is called: the
    # producer key enrolled in the witness registry under a *different* id
    # ("k2"; the producer registry calls it "k1") must still be recognised by
    # its key material
    self_reg = tmp_path / "self.json"
    self_reg.write_text(json.dumps({"registry_version": 1, "keys": [{"key_id": "k2", "status": "active", "public_key_pem": public_key_pem(keys["pem"])}]}))
    own = witness.countersign(rec["payload_hash"], witness_key_id="k2", private_key_pem=keys["pem"], witnessed_at="2026-10-18T05:00:00Z")
    op = tmp_path / "own.json"
    op.write_text(json.dumps(own))
    s = {p["property"]: (p["state"], p["detail"]) for p in verify_directory(d, keys["registry"], witness_statement=op, witness_registry=self_reg).properties}
    assert s["witness"][0] == "unknown" and "also a producer key" in s["witness"][1]
    # and under the same id as the producer registry uses (the collision path)
    same_reg = tmp_path / "same.json"
    same_reg.write_text(json.dumps({"registry_version": 1, "keys": [{"key_id": "k1", "status": "active", "public_key_pem": public_key_pem(keys["pem"])}]}))
    own_same = witness.countersign(rec["payload_hash"], witness_key_id="k1", private_key_pem=keys["pem"], witnessed_at="2026-10-18T05:00:00Z")
    osp = tmp_path / "own_same.json"
    osp.write_text(json.dumps(own_same))
    assert states(verify_directory(d, keys["registry"], witness_statement=osp, witness_registry=same_reg))["witness"] == "unknown"
    # a genuinely different key that merely reuses the producer's id is a witness
    reuse_reg = tmp_path / "reuse.json"
    reuse_reg.write_text(json.dumps({"registry_version": 1, "keys": [{"key_id": "k1", "status": "active", "public_key_pem": public_key_pem(wpem)}]}))
    reuse = witness.countersign(rec["payload_hash"], witness_key_id="k1", private_key_pem=wpem, witnessed_at="2026-10-18T05:00:00Z")
    rp = tmp_path / "reuse_statement.json"
    rp.write_text(json.dumps(reuse))
    assert states(verify_directory(d, keys["registry"], witness_statement=rp, witness_registry=reuse_reg))["witness"] == "established"
    # without a witness registry the statement cannot be resolved
    assert states(verify_directory(d, keys["registry"], witness_statement=sp))["witness"] == "unknown"


def test_a_forged_witness_statement_fails(tmp_path, keys):
    """Someone who knows the witness's key id but not its key signs a statement under that id."""
    d = build_run(tmp_path / "run", keys)
    rec = read_record(d)
    wpem = generate_private_key_pem()
    wreg = tmp_path / "witnesses.json"
    wreg.write_text(json.dumps({"registry_version": 1, "keys": [{"key_id": "w1", "status": "active", "public_key_pem": public_key_pem(wpem)}]}))
    forged = witness.countersign(rec["payload_hash"], witness_key_id="w1", private_key_pem=generate_private_key_pem(), witnessed_at="2026-10-18T05:00:00Z")
    fp = tmp_path / "forged.json"
    fp.write_text(json.dumps(forged))
    s = {p["property"]: (p["state"], p["detail"]) for p in verify_directory(d, keys["registry"], witness_statement=fp, witness_registry=wreg).properties}
    assert s["witness"][0] == "failed" and "does not verify" in s["witness"][1]


def test_completeness_is_never_established():
    """No code path in the verifier can report completeness as established."""
    import ast
    import re

    src = Path(__file__).resolve().parents[1].joinpath("dr", "verify.py").read_text()
    calls = re.findall(r'report\.add\(\s*"completeness",\s*"(\w+)"', src)
    assert calls and set(calls) <= {"n/a", "failed", "unknown"}, calls


def test_a_prior_altered_after_signing_does_not_link(tmp_path, keys):
    """The link is checked against the prior's identity computed from its body,
    not against the payload_hash the prior carries: an edited body keeps that
    copy unchanged, and a stream whose purpose is to make a removed record
    visible must not accept a prior that says something it did not sign."""
    dirs, records = _three_linked_runs(tmp_path, keys)
    import json
    prior = json.loads((dirs[0] / "record.json").read_text())
    prior["ledger"]["row_count"] += 1  # a row fewer than the prior signed for, the stored hash and signature left as they were
    altered = tmp_path / "altered-prior.json"
    altered.write_text(json.dumps(prior))
    rep = verify_directory(dirs[1], keys["registry"], prior_record=altered)
    assert states(rep)["stream"] == "failed"
    assert "does not recompute" in next(p["detail"] for p in rep.properties if p["property"] == "stream")
    defects, forks = check_sequence([prior, records[1], records[2]])
    assert any("does not recompute" in d for d in defects)
    # the same prior, unaltered, still links
    assert states(verify_directory(dirs[1], keys["registry"], prior_record=dirs[0] / "record.json"))["stream"] == "established"


def test_two_bodies_under_one_stated_hash_are_a_fork(tmp_path, keys):
    dirs, records = _three_linked_runs(tmp_path, keys)
    import copy
    twin = copy.deepcopy(records[1])
    twin["ledger"]["row_count"] += 1  # a different body carrying the same stated payload_hash
    defects, forks = check_sequence([records[0], records[1], twin, records[2]])
    assert len(forks) == 1


# --- a fork that cannot hide, and a check that cannot run is not a failure ---

def _nan(record):
    import copy
    r = copy.deepcopy(record)
    r["ledger"]["x"] = float("nan")  # a value with no canonical form, as a dict handed to the API
    return r


def test_two_unhashable_records_at_one_position_are_still_a_fork(tmp_path, keys):
    """Grouping by computed identity put every unhashable record in one bucket,
    so a forger who planted a NaN in each half of a fork reported nothing."""
    import copy
    dirs, records = _three_linked_runs(tmp_path, keys)
    other = copy.deepcopy(records[0])
    other["ledger"]["row_count"] += 1
    from dr.signing import payload_hash
    other["payload_hash"] = payload_hash(other)
    defects, forks = check_sequence([records[0], other])
    assert len(forks) == 1  # the baseline
    defects, forks = check_sequence([_nan(records[0]), _nan(other)])
    assert len(forks) == 1, (defects, forks)
    assert sum("cannot be hashed" in d for d in defects) == 2
    # an unhashable copy of a record is not a fork with the record, but it is named
    defects, forks = check_sequence([records[0], _nan(records[0])])
    assert forks == [] and sum("cannot be hashed" in d for d in defects) == 1


def test_a_bare_nan_is_refused_where_a_record_is_read(tmp_path, keys):
    import subprocess, sys, json
    dirs, records = _three_linked_runs(tmp_path, keys)
    bad = tmp_path / "nan.json"
    bad.write_text((dirs[0] / "record.json").read_text().replace('"row_count": ', '"x": NaN, "row_count": ', 1))
    p = subprocess.run([sys.executable, "-m", "dr.stream", str(bad), str(dirs[1] / "record.json")], capture_output=True, text=True)
    assert p.returncode == 3 and "not JSON" in p.stderr


def _stream_state(tmp_path, keys, prior_path):
    dirs, _ = _three_linked_runs(tmp_path, keys)
    rep = verify_directory(dirs[1], keys["registry"], prior_record=prior_path(dirs))
    return next((p["state"], p["detail"]) for p in rep.properties if p["property"] == "stream")


def test_a_prior_that_cannot_be_read_is_unknown_not_the_records_failure(tmp_path, keys):
    def nan_prior(dirs):
        p = tmp_path / "nan-prior.json"
        p.write_text((dirs[0] / "record.json").read_text().replace('"row_count": ', '"x": NaN, "row_count": ', 1))
        return p
    state, detail = _stream_state(tmp_path, keys, nan_prior)
    assert state == "unknown" and "could not be read" in detail


def test_a_prior_that_is_not_a_record_is_unknown(tmp_path, keys):
    def list_prior(dirs):
        p = tmp_path / "list-prior.json"
        p.write_text("[1, 2, 3]")
        return p
    state, detail = _stream_state(tmp_path, keys, list_prior)
    assert state == "unknown" and "not a record" in detail


def test_the_verifiers_own_failure_is_not_a_state_of_the_record(tmp_path, keys, monkeypatch, capsys):
    """The hasher breaking is not the prior being malformed. Reported as
    unknown with the verifier named, it would exit 1, the NOT ESTABLISHED code,
    so a verifier fault would still leave a verdict. It propagates to the
    command's guard instead: exit 3, nothing judged."""
    import dr.stream as stream_mod
    import dr.verify as verify_mod
    def broken(record):
        raise RuntimeError("hasher broke")
    dirs, _ = _three_linked_runs(tmp_path, keys)
    monkeypatch.setattr(stream_mod, "payload_hash", broken)
    with pytest.raises(RuntimeError, match="hasher broke"):
        verify_directory(dirs[1], keys["registry"], prior_record=dirs[0] / "record.json")
    code = verify_mod.main([str(dirs[1]), "--registry", str(keys["registry"]), "--prior", str(dirs[0] / "record.json")])
    err = capsys.readouterr().err
    assert code == 3 and "VERIFIER ERROR" in err and "hasher broke" in err


def test_a_corrupted_stated_hash_over_an_intact_body_still_links(tmp_path, keys):
    """The prior's fields hash to what the record names; only the prior's own copy
    of its identity is wrong. That is the prior's defect, said in the detail, and
    not the record's failure."""
    import json
    def corrupted(dirs):
        prior = json.loads((dirs[0] / "record.json").read_text())
        prior["payload_hash"] = "sha256:" + "0" * 64
        p = tmp_path / "corrupted-prior.json"
        p.write_text(json.dumps(prior))
        return p
    state, detail = _stream_state(tmp_path, keys, corrupted)
    assert state == "established" and "does not recompute" in detail
