"""The execution-time example under Cedar: decider refusals, reproduction, and what a changed policy does.

Skipped without cedarpy (the Cedar engine behind Python bindings), which the
verifier closure never imports; the emitter does.
"""

import filecmp
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

cedarpy = pytest.importorskip("cedarpy")

# The scripts call `python3`; run them under the interpreter running this suite, which has
# the dependencies, ahead of a fixed system PATH (on a CI runner /usr/bin/python3 has none).
SCRIPT_PATH = f"{Path(sys.executable).parent}:/usr/bin:/bin:/usr/local/bin"
ROOT = Path(__file__).resolve().parents[1]

from emitters import cedar, cedar_conformance  # noqa: E402


def _tree_equal(a: Path, b: Path) -> bool:
    cmp = filecmp.dircmp(a, b)
    if cmp.left_only or cmp.right_only or cmp.diff_files or cmp.funny_files:
        return False
    return all(_tree_equal(a / d, b / d) for d in cmp.common_dirs)


def _policy(name):
    return json.loads((ROOT / "examples" / "cedar" / f"policy-{name}.json").read_text())


def test_decider_refuses_a_policy_set_that_does_not_validate():
    p = _policy("store")
    p["policies"] = p["policies"].replace("context.amount <= 1000", "context.amount <= \"1000\"")
    with pytest.raises(ValueError, match="does not validate"):
        cedar.Decider(p)
    p = _policy("store")
    p["store"] = []
    with pytest.raises(ValueError, match="store is empty"):
        cedar.Decider(p)


def test_same_call_same_policy_same_decision_and_canonicalisation_is_the_difference():
    rows = [json.loads(l) for l in (ROOT / "examples" / "cedar" / "inputs-toolcalls.jsonl").read_text().splitlines()]
    traversal = next(r["input"] for r in rows if "percent-encoded traversal" in r["input"]["note"])
    store, canonical = cedar.Decider(_policy("store")), cedar.Decider(_policy("canonical"))
    assert store.decide(traversal)[0] == "ALLOW" and canonical.decide(traversal)[0] == "DENY"
    assert [canonical.decide(traversal) for _ in range(3)] == [canonical.decide(traversal)] * 3
    caller_asserted = next(r["input"] for r in rows if "caller-asserted entity" in r["input"]["note"])
    assert cedar.Decider(_policy("caller")).decide(caller_asserted)[0] == "ALLOW"
    assert store.decide(caller_asserted)[0] == "DENY"


def test_conformance_decider_refuses_a_changed_corpus(tmp_path):
    p = json.loads((ROOT / "examples" / "cedar" / "policy-conformance-handwritten.json").read_text())
    k = sorted(p["files"])[0]
    p["files"][k] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="not the record's policy"):
        cedar_conformance.Decider(p)


def test_cedar_example_reproduces_committed_outputs(tmp_path):
    work = tmp_path / "repo"
    for name in ("dr", "emitters", "examples", "vendor", "tools"):
        shutil.copytree(ROOT / name, work / name, ignore=shutil.ignore_patterns("__pycache__", "out", "scratch", "TRANSCRIPT.md"))
    proc = subprocess.run(["bash", "examples/cedar/run.sh"], cwd=work, capture_output=True, text=True, env={"PATH": SCRIPT_PATH, "PYTHONDONTWRITEBYTECODE": "1"})
    assert proc.returncode == 0, proc.stderr
    committed = ROOT / "examples" / "cedar" / "out"
    for sub in ("toolcalls-caller", "toolcalls-store", "toolcalls-canonical", "conformance-handwritten"):
        assert _tree_equal(work / "examples" / "cedar" / "out" / sub, committed / sub), sub
    assert (work / "examples" / "cedar" / "TRANSCRIPT.md").read_bytes() == (ROOT / "examples" / "cedar" / "TRANSCRIPT.md").read_bytes()


def test_engine_version_mismatch_is_unknown_not_established(tmp_path):
    """The record names its engine; a verifier holding another one is told replay proves nothing, and the verdict is NOT ESTABLISHED."""
    from dr import verify as V

    sample = ROOT / "examples" / "cedar" / "out" / "conformance-drt-sample"
    rec = json.loads((sample / "record.json").read_text())
    assert rec["decider"]["version"].startswith("cedarpy-")
    report = V.Report()
    report.add("retained", "established", "")
    other = type("M", (), {"DECIDER_ID": cedar_conformance.DECIDER_ID, "DECIDER_VERSION": "cedarpy-0.0.0"})
    import sys

    sys.modules["_other_engine"] = other
    try:
        V._replay(report, sample, rec, [], "_other_engine", [])
    finally:
        del sys.modules["_other_engine"]
    assert report.state("replay") == "unknown"
    detail = next(p["detail"] for p in report.properties if p["property"] == "replay")
    assert "cedarpy-0.0.0" in detail and "proves nothing" in detail


def test_conformance_decider_falls_back_to_string_uids_for_old_bindings(monkeypatch, tmp_path):
    """Bindings before 4.12 take only `Type::"id"` uids; the decider retries in that form rather than raising."""
    root = tmp_path / "c"
    (root / "corpus-tests").mkdir(parents=True)
    (root / "corpus-tests" / "t.cedar").write_text('permit(principal, action, resource);')
    (root / "corpus-tests" / "t.cedarschema").write_text('entity U; action a appliesTo { principal: U, resource: U };')
    (root / "corpus-tests" / "t.entities.json").write_text("[]")
    (root / "corpus-tests" / "t.json").write_text(json.dumps({"policies": "corpus-tests/t.cedar", "schema": "corpus-tests/t.cedarschema", "entities": "corpus-tests/t.entities.json",
        "requests": [{"principal": {"type": "U", "id": "x"}, "action": {"type": "Action", "id": "a"}, "resource": {"type": "U", "id": "y"}, "context": {}, "decision": "allow", "reason": ["policy0"]}]}))
    policy = cedar_conformance.corpus_policy(root, ["corpus-tests/t.json"])
    d = cedar_conformance.Decider(policy)
    assert d.decide({"test": "corpus-tests/t.json", "request": 0})[:2] == ("ALLOW", "policy0")
    seen = []
    real = cedarpy.is_authorized

    def old_bindings(request, *a, **k):
        seen.append(request)
        if isinstance(request["principal"], dict):
            raise TypeError("argument 'requests': 'dict' object cannot be converted to 'PyString'")
        return real(request, *a, **k)

    monkeypatch.setattr(cedar_conformance.cedarpy, "is_authorized", old_bindings)
    assert d.decide({"test": "corpus-tests/t.json", "request": 0})[:2] == ("ALLOW", "policy0")
    assert seen[-1]["principal"] == 'U::"x"' and seen[-1]["context"] == {}


def test_by_engine_results_say_what_the_report_says():
    """The generated by-engine file: a different engine is refused by version and would have failed recomputation; the same engine is established."""
    f = ROOT / "examples" / "cedar" / "drt-results-by-engine.json"
    if not f.exists():
        pytest.skip("drt-results-by-engine.json not generated")
    d = json.loads(f.read_text())
    rows = {e["engine"]: e for e in d["engines"]}
    own = rows[d["record_names"].split("@")[1]]
    assert own["verifier_replay"] == "established" and own["forced_rows_differ"] == 0 and own["corpus_agree"] == own["corpus_requests"]
    for name, e in rows.items():
        if name == own["engine"]:
            continue
        assert e["verifier_replay"] == "unknown" and e["verifier_verdict"] == "NOT ESTABLISHED" and e["verifier_exit"] == 1
        assert e["allow_where_corpus_expects_deny"] == 0
