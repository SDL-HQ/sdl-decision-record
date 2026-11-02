"""The OPA/Rego decider built from the specification's "Other grammars" paragraph.

Skipped without an `opa` binary ($OPA_BIN or on PATH); the verifier closure
never needs one. With it: refusals at construction (an unlisted builtin, a
non-deterministic builtin, a policy that does not check), the forty calls
deciding as the Cedar records do on every outcome, and the mechanism the
conformance decider needs that §6.2 did not have (result-set normalisation
as OPA's own runner does it).
"""

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if not (os.environ.get("OPA_BIN") or shutil.which("opa")):
    pytest.skip("no opa binary (set OPA_BIN)", allow_module_level=True)

from emitters import opa, opa_conformance  # noqa: E402

HERE = ROOT / "examples" / "opa"


def _policy(name):
    return json.loads((HERE / f"policy-{name}.json").read_text())


def test_construction_refuses_unlisted_and_nondeterministic_builtins():
    p = _policy("store")
    p["bundle"]["policies.rego"] += "\n\nclock := time.now_ns()\n"
    with pytest.raises(ValueError, match="does not check"):
        opa.Decider(p)
    p["builtins"].append("time.now_ns")
    with pytest.raises(ValueError, match="non-deterministic"):
        opa.Decider(p)
    p = _policy("store")
    p["builtins"].append("no.such_builtin")
    with pytest.raises(ValueError, match="does not have"):
        opa.Decider(p)


def test_the_forty_calls_decide_as_the_cedar_records_do_on_outcome():
    inputs = [json.loads(l) for l in (ROOT / "examples" / "cedar" / "inputs-toolcalls.jsonl").read_text().splitlines() if l.strip()]
    for name in ("caller", "store", "canonical"):
        d = opa.Decider(_policy(name))
        cedar_rows = [json.loads(l) for l in (ROOT / "examples" / "cedar" / "out" / f"toolcalls-{name}" / "decisions.jsonl").read_text().splitlines() if l.strip()]
        for item, row in zip(inputs, cedar_rows):
            outcome, reason, _ = d.decide(item["input"])
            assert outcome == row["outcome"], (name, row["seq"], reason)


def test_same_call_same_policy_same_decision_and_reason():
    d = opa.Decider(_policy("canonical"))
    item = json.loads((ROOT / "examples" / "cedar" / "inputs-toolcalls.jsonl").read_text().splitlines()[0])["input"]
    first = d.decide(item)[:2]
    assert all(d.decide(item)[:2] == first for _ in range(5))
    assert first == ("ALLOW", "p0")


def test_result_set_normalisation_follows_opa_runner():
    n = opa_conformance.normalise_result_set
    assert n([{"x": [3, 1, 2]}], sort_bindings=True, ignore_generated=False) == n([{"x": [1, 2, 3]}], False, False)
    assert n([{"x": 1, "__localq1__": 9}], False, True) == n([{"x": 1}], False, False)
    assert n([{"x": 1}, {"x": 2}], False, False) == n([{"x": 2}, {"x": 1}], False, False)
    assert n([{"x": 1.0}], False, False) == n([{"x": 1}], False, False)
    assert opa_conformance.jsonify({1: {True: None}}) == {"1": {"true": None}}


def test_committed_opa_records_verify_and_replay():
    from dr import verify as V

    for name in ("toolcalls-canonical",):
        rep = V.verify_directory(HERE / "out" / name, ROOT / "examples" / "keys" / "registry.json", replay_module="emitters.opa")
        detail = next(p for p in rep.properties if p["property"] == "replay")
        if rep.state("replay") == "unknown" and "proves nothing" in detail["detail"]:
            pytest.skip(f"records were made under another opa: {detail['detail'][:80]}")
        assert rep.state("replay") == "established", detail
