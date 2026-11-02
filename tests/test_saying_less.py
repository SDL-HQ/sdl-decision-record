"""Saying less (SPEC section 14): row version 2 (keyed digests), retain_ext and coarse reasons.

Each leak-reduction option must leave every property established with the
inputs present, and must remove exactly the information it claims to.
"""

import json
import random
from collections import defaultdict

import pytest

from conftest import TOOL_POLICY, TOOL_SUITE, build_run, read_record, read_rows, states, verify, write_rows
from dr.rows import KEYED_DIGEST_PREFIX, RowError, keyed_input_digest, load_rows, verify_chain
from dr.canonical import digest_obj
from emitters import classrouter, ratelimit, toolgate

SALT = bytes(range(32))


def test_keyed_rows_verify_and_replay_exactly_as_v1(tmp_path, keys):
    d = build_run(tmp_path / "run", keys, keyed_digests=True, salt=SALT)
    rows = read_rows(d)
    assert all(r["v"] == 2 and r["input_digest"].startswith(KEYED_DIGEST_PREFIX) for r in rows)
    first = (d / "inputs.jsonl").read_text().splitlines()[0]
    assert json.loads(first) == {"salt": SALT.hex()}
    rep = verify(d, keys, replay="emitters.toolgate")
    assert rep.verdict == 0 and states(rep)["replay"] == "established"
    assert rows[0]["input_digest"] == keyed_input_digest(SALT, TOOL_SUITE[0]["input"])
    assert rows[0]["input_digest"] != KEYED_DIGEST_PREFIX + digest_obj(TOOL_SUITE[0]["input"]).split(":")[1]


def test_keyed_digest_depends_on_the_salt(tmp_path, keys):
    a = keyed_input_digest(SALT, {"x": 1})
    b = keyed_input_digest(bytes(32), {"x": 1})
    assert a != b and a.startswith(KEYED_DIGEST_PREFIX)


def test_a_v2_row_with_a_plain_digest_is_a_row_error(tmp_path, keys):
    d = build_run(tmp_path / "run", keys, keyed_digests=True, salt=SALT)
    rows = read_rows(d)
    rows[0]["input_digest"] = digest_obj(TOOL_SUITE[0]["input"])
    with pytest.raises(RowError, match="keyed digest"):
        verify_chain(rows)


def test_a_wrong_salt_fails_the_retained_inputs(tmp_path, keys):
    d = build_run(tmp_path / "run", keys, keyed_digests=True, salt=SALT)
    lines = (d / "inputs.jsonl").read_text().splitlines()
    lines[0] = json.dumps({"salt": bytes(32).hex()})
    (d / "inputs.jsonl").write_text("\n".join(lines) + "\n")
    from dr.canonical import digest_file
    from conftest import resign
    resign(d, keys["pem"], lambda r: r["retained"].__setitem__("inputs.jsonl", digest_file(d / "inputs.jsonl")))
    s = states(verify(d, keys, replay="emitters.toolgate"))
    assert s["retained"] == "failed" and s["replay"] == "unknown"


def test_a_salt_line_on_v1_rows_is_a_failure(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    text = (d / "inputs.jsonl").read_text()
    (d / "inputs.jsonl").write_text(json.dumps({"salt": SALT.hex()}) + "\n" + text)
    from dr.canonical import digest_file
    from conftest import resign
    resign(d, keys["pem"], lambda r: r["retained"].__setitem__("inputs.jsonl", digest_file(d / "inputs.jsonl")))
    assert states(verify(d, keys))["retained"] == "failed"


def test_retain_ext_false_drops_ext_and_changes_nothing_the_verifier_checks(tmp_path, keys):
    items = [{"input": {"principal": "a", "at": t}} for t in (1, 2, 3, 4)]
    policy = {"window_seconds": 10, "max_requests": 3}
    with_ext = build_run(tmp_path / "with", keys, module=ratelimit, policy=policy, items=items, labelled=False)
    without = build_run(tmp_path / "without", keys, module=ratelimit, policy=policy, items=items, labelled=False, retain_ext=False)
    assert all("ext" in r for r in read_rows(with_ext))
    assert not any("ext" in r for r in read_rows(without))
    for d in (with_ext, without):
        rep = verify(d, keys, replay="emitters.ratelimit")
        assert rep.verdict == 0 and states(rep)["replay"] == "established"
    assert [r["outcome"] for r in read_rows(with_ext)] == [r["outcome"] for r in read_rows(without)]


@pytest.mark.parametrize("module,policy,items,fine,coarse", [
    (toolgate, TOOL_POLICY, TOOL_SUITE, ["arg_type:order_id", "arg_undeclared:extra"], ["arg_type", "arg_undeclared"]),
    (
        classrouter,
        {"levels": ["low", "high"], "destinations": {"a": {"max_level": "low", "redactable": True}, "b": {"max_level": "low", "redactable": False}}},
        [{"input": {"destination": "a", "fields": {"f": "high", "g": "low"}}}, {"input": {"destination": "b", "fields": {"f": "high"}}}, {"input": {"destination": "b", "fields": {"f": "nope"}}}],
        ["redact:f", "exceeds:f", "level_unknown:f"],
        ["redact", "exceeds", "level_unknown"],
    ),
])
def test_coarse_reasons_drop_names_keep_outcomes_and_replay(tmp_path, keys, module, policy, items, fine, coarse):
    f = build_run(tmp_path / "fine", keys, module=module, policy=policy, items=items, labelled=False)
    c = build_run(tmp_path / "coarse", keys, module=module, policy={**policy, "reason_detail": "coarse"}, items=items, labelled=False)
    fr, cr = read_rows(f), read_rows(c)
    assert [r["outcome"] for r in fr] == [r["outcome"] for r in cr]
    assert [r["reason"] for r in fr if r["reason"] and ":" in r["reason"]] == fine
    assert [r["reason"] for r in cr if r["reason"] and r["reason"] in coarse] == coarse
    assert not any(":" in (r["reason"] or "") for r in cr)
    for d in (f, c):
        rep = verify(d, keys, replay=f"emitters.{module.DECIDER_ID}")
        assert rep.verdict == 0 and states(rep)["replay"] == "established"
    # the two runs carry different policy digests: the setting is part of the policy, not a side channel
    assert read_record(f)["policy_digests"] != read_record(c)["policy_digests"]


def test_reason_detail_is_validated():
    with pytest.raises(ValueError, match="reason_detail"):
        toolgate.Decider({**TOOL_POLICY, "reason_detail": "vague"})
    with pytest.raises(ValueError, match="reason_detail"):
        classrouter.Decider({"levels": ["a"], "destinations": {}, "reason_detail": 3})


# --- the attacker computes what it says ------------------------------------


