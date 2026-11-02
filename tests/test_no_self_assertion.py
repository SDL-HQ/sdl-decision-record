"""Nothing in the record tells the verifier whether a check happened.

The defect this guards against, found in another project: a verifier that
established a property because the document carried a flag saying the
property had been checked. The record format here has no boolean fields at all,
and the verifier's source never branches on a record value to decide a state.
"""

import ast
import json
from pathlib import Path

from conftest import TOOL_POLICY, build_run, read_record
from dr.receipts import RECEIPT_KEYS
from dr.record import CONDITIONAL_KEYS, REQUIRED_KEYS, STREAM_KEYS, V2_OPTIONAL_KEYS
from dr.witness import WITNESS_KEYS

ROOT = Path(__file__).resolve().parents[1]


def _walk(obj, path="record"):
    if isinstance(obj, bool):
        yield path
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")


def test_a_record_carries_no_boolean_anywhere(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    assert list(_walk(read_record(d))) == []


def test_the_record_key_set_names_no_checked_or_verified_flag():
    for key in REQUIRED_KEYS | CONDITIONAL_KEYS | V2_OPTIONAL_KEYS | STREAM_KEYS | RECEIPT_KEYS | WITNESS_KEYS:
        assert not any(w in key for w in ("checked", "verified", "matches", "enforced", "trusted", "complete")), key


def test_a_stream_record_and_its_receipts_carry_no_boolean_anywhere(tmp_path, keys):
    from dr.emit import Run
    from emitters import toolgate

    run = Run(tmp_path / "run", decider_id="toolgate", decider_version="1.0.0", outcomes=toolgate.OUTCOMES, policy=TOOL_POLICY,
              stream={"stream_id": "s", "seq": 1, "prev_record_hash": None, "first_decision": 1},
              record_id="r", signing_key_id=keys["key_id"], private_key_pem=keys["pem"], issue_receipts=True)
    run.decide({"tool": "x", "args": {}}, "DENY", "tool_not_allowlisted", ts="2026-10-18T00:00:00Z")
    run.close(issued_at="2026-10-18T01:00:00Z")
    assert list(_walk(read_record(tmp_path / "run"))) == []
    assert all(list(_walk(r, "receipt")) == [] for r in run.receipts)


def test_the_verifier_never_sets_a_state_from_a_record_truth_value():
    """No `record[...] is True`, `record.get(...) is True`, or `if record[...]:` deciding a report.add."""
    src = (ROOT / "dr" / "verify.py").read_text()
    tree = ast.parse(src)
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and any(isinstance(c, ast.Constant) and isinstance(c.value, bool) for c in node.comparators):
            text = ast.unparse(node)
            if "record" in text:
                offenders.append(text)
        if isinstance(node, ast.If):
            test = ast.unparse(node.test)
            if test.startswith(("record[", "record.get(")) and " == " not in test and " != " not in test and " in " not in test:
                offenders.append(test)
    assert offenders == [], offenders


def test_every_record_figure_is_a_claim_the_rows_can_contradict(tmp_path, keys):
    """For each numeric figure in the record, changing it alone makes a property fail."""
    from conftest import resign, states, verify

    for path, mutate in (
        ("counts.decisions", lambda r: r["counts"].update(decisions=99)),
        ("counts.by_outcome", lambda r: r["counts"]["by_outcome"].update(ALLOW=99)),
        ("benchmark.agree", lambda r: r["benchmark"].update(agree=0)),
        ("benchmark.by_label", lambda r: r["benchmark"].update(by_label={})),
        ("ledger.row_count", lambda r: r["ledger"].update(row_count=99)),
        ("ledger.terminal_hash", lambda r: r["ledger"].update(terminal_hash="sha256:" + "f" * 64)),
        ("policy_digests", lambda r: r.update(policy_digests=["sha256:" + "f" * 64])),
        ("retained", lambda r: r["retained"].update({"policy.json": "sha256:" + "f" * 64})),
    ):
        d = build_run(tmp_path / path.replace(".", "_"), keys)
        resign(d, keys["pem"], mutate)
        assert "failed" in states(verify(d, keys)).values(), path
