"""The Lean definitional engine as a Cedar decider (emitters/cedar_lean.py).

Two parts. Without the engine (every environment): the committed record it
made verifies, and replaying it under cedarpy — which it names as established
by a full-corpus run — fails at the first row on the reason string, which is
the captured finding (the Lean front end reports a policy by its `@id`, cedarpy
by its position; the corpus the name rests on has no `@id`). With the engine
(`CEDAR_LEAN_CLI` and `CEDAR_LEAN_SPEC_COMMIT` set): the forty calls decide
with the same outcomes as the cedarpy record, and the entity-id escaping is
Rust's `escape_debug`.
"""

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from emitters import cedar_lean  # noqa: E402

REG = ROOT / "examples" / "keys" / "registry.json"
EV = ROOT / "examples" / "cedar" / "conformance"
LEAN_RECORD = ROOT / "examples" / "cedar" / "out" / "toolcalls-lean"


def test_escape_eid_is_rust_escape_debug():
    e = cedar_lean.escape_eid
    assert e("abc") == "abc"
    assert e('a"b') == 'a\\"b'
    assert e("a'b") == "a\\'b"
    assert e("a\\b") == "a\\\\b"
    assert e("\0\n\t\r") == "\\0\\n\\t\\r"
    assert e("\x17") == "\\u{17}"
    assert e("é") == "é"
    assert cedar_lean.uid({"type": "A::B", "id": 'x"'}) == 'A::B::"x\\""'


def test_committed_lean_record_verifies_and_names_cedarpy_whose_reasons_differ():
    cedarpy = pytest.importorskip("cedarpy")
    from dr import verify as V

    rec = json.loads((LEAN_RECORD / "record.json").read_text())
    assert rec["decider"]["version"].startswith("cedar-lean-")
    named = {e["version"] for e in rec["decider"]["established_versions"]}
    assert named == {"cedarpy-4.12.2"}
    rep = V.verify_directory(LEAN_RECORD, REG)
    assert rep.verdict == 0 and all(p["state"] in ("established", "n/a") for p in rep.properties), rep.properties
    if __import__("importlib.metadata").metadata.version("cedarpy") != "4.12.2":
        pytest.skip("the replay finding is for cedarpy 4.12.2, the version the record names")
    rep = V.verify_directory(LEAN_RECORD, REG, replay_module="emitters.cedar", conformance_evidence=[EV / "cedarpy-4.12.2.json"])
    detail = next(p["detail"] for p in rep.properties if p["property"] == "replay")
    assert rep.state("replay") == "failed"
    assert "seq 1" in detail and "'policy0'" in detail and "'p0'" in detail, detail


@pytest.mark.skipif(not (os.environ.get("CEDAR_LEAN_CLI") and os.environ.get("CEDAR_LEAN_SPEC_COMMIT")), reason="no Lean engine (set CEDAR_LEAN_CLI and CEDAR_LEAN_SPEC_COMMIT)")
def test_lean_engine_decides_the_forty_calls_with_the_same_outcomes():
    policy = json.loads((ROOT / "examples" / "cedar" / "policy-canonical.json").read_text())
    d = cedar_lean.Decider(policy)
    inputs = [json.loads(l) for l in (ROOT / "examples" / "cedar" / "inputs-toolcalls.jsonl").read_text().splitlines() if l.strip()]
    rows = [json.loads(l) for l in (ROOT / "examples" / "cedar" / "out" / "toolcalls-canonical" / "decisions.jsonl").read_text().splitlines() if l.strip()]
    differing_reasons = 0
    for item, row in zip(inputs, rows):
        outcome, reason, _ = d.decide(item["input"])
        assert outcome == row["outcome"], (row["seq"], reason)
        differing_reasons += reason != row["reason"]
    assert differing_reasons == 17  # 16 by `@id` against position, one by request validation (row 36)
