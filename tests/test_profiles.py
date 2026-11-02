"""A record must not pick a profile that excuses it from a check its content supports."""

import pytest

from conftest import TOOL_SUITE, build_run, read_rows, resign, states, verify, write_rows
from dr import derive


def test_production_declared_over_labelled_rows_fails_profile_and_correctness(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)

    def lie(r):
        r["profile"] = "production"
        del r["benchmark"]

    resign(d, keys["pem"], lie)
    s = states(verify(d, keys))
    assert s["profile"] == "failed" and s["correctness"] == "failed"


def test_benchmark_declared_over_unlabelled_rows_fails(tmp_path, keys):
    d = build_run(tmp_path / "run", keys, labelled=False)
    resign(d, keys["pem"], lambda r: r.update(profile="benchmark", benchmark={"labelled": 5, "agree": 5, "disagree": 0, "by_label": {}}))
    s = states(verify(d, keys))
    assert s["profile"] == "failed" and s["correctness"] == "failed"


def test_a_mixed_ledger_supports_no_profile(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    rows = read_rows(d)
    del rows[2]["label"]
    from dr.rows import GENESIS, row_hash

    prev = GENESIS
    for r in rows:
        r["prev_hash"] = prev
        r["row_hash"] = row_hash(prev, r)
        prev = r["row_hash"]
    write_rows(d, rows)
    resign(d, keys["pem"], lambda r: r["ledger"].update(terminal_hash=prev))
    s = states(verify(d, keys))
    assert s["chain"] == "established" and s["profile"] == "failed"
    assert derive.supported_profile(rows) is None


def test_the_emitter_refuses_to_sign_a_mixed_ledger(tmp_path, keys):
    items = [dict(x) for x in TOOL_SUITE]
    del items[1]["label"]
    with pytest.raises(ValueError, match="support no profile"):
        build_run(tmp_path / "run", keys, items=items)


def test_the_emitter_refuses_an_intended_profile_the_rows_do_not_support(tmp_path, keys):
    from dr.emit import Run
    from emitters import toolgate

    run = Run(tmp_path / "run", decider_id="toolgate", decider_version="1.0.0", outcomes=toolgate.OUTCOMES, policy={"tools": {}})
    run.decide({"tool": "x"}, "DENY", "tool_not_allowlisted", ts="2026-10-18T00:00:00Z", label="DENY")
    with pytest.raises(ValueError, match="intended profile 'production'"):
        run.close(record_id="r", signing_key_id="k1", private_key_pem=keys["pem"], profile="production")


def test_the_record_shape_ties_the_benchmark_block_to_the_profile(tmp_path, keys):
    d = build_run(tmp_path / "run", keys, labelled=False)
    resign(d, keys["pem"], lambda r: r.update(benchmark={"labelled": 0, "agree": 0, "disagree": 0, "by_label": {}}))
    assert states(verify(d, keys))["document"] == "failed"
