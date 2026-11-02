"""decider.established_versions (SPEC §8): other versions a conformance run established, named in the record.

A replay under a named version is accepted; one under an unnamed version is
refused as before; supplied evidence that does not support the name refuses
it; and a falsely named version is caught only where the rows differ, which
is the cost of naming and is measured in tests/test_cedar.py against real
engines. No cedarpy needed here: the deciders are stand-ins.
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dr import verify as V  # noqa: E402
from dr.canonical import digest_obj  # noqa: E402
from dr.emit import Run  # noqa: E402

KEY = (ROOT / "examples" / "keys" / "example-signing-key.pem").read_bytes()
REG = ROOT / "examples" / "keys" / "registry.json"


class _Stub:
    DECIDER_ID = "stub"
    OUTCOMES = ("ALLOW", "DENY")

    def __init__(self, version, flip_at=None):
        self.DECIDER_VERSION = version
        self.flip_at = flip_at
        self.Decider = lambda policy: self

    def decide(self, item):
        if self.flip_at is not None and item["n"] == self.flip_at:
            return "DENY", "drift", None
        return ("ALLOW", "even", None) if item["n"] % 2 == 0 else ("DENY", "odd", None)


def _install(name, stub):
    sys.modules[name] = stub
    return name


def _evidence(version, agree=1000, total=1000):
    body = {"engine": version, "requests": total, "agree_decision_reason_and_error_presence": agree, "corpus": "stub"}
    return body, digest_obj(body)


def _record(tmp_path, established=None, n=6):
    d = tmp_path / "rec"
    stub = _Stub("1.0.0")
    run = Run(d, decider_id="stub", decider_version="1.0.0", outcomes=["ALLOW", "DENY"], policy={"p": 1}, record_id="r1",
              signing_key_id="example-2026-10", private_key_pem=KEY, established_versions=established)
    for i in range(n):
        o, r, e = stub.decide({"n": i})
        run.decide({"n": i}, o, r, ts="2026-10-20T00:00:00Z")
    run.close(issued_at="2026-10-20T00:00:00Z")
    return d


def _replay_state(d, module, evidence=()):
    rep = V.verify_directory(d, REG, replay_module=module, conformance_evidence=list(evidence))
    return rep.state("replay"), next(p["detail"] for p in rep.properties if p["property"] == "replay"), rep.verdict


def test_record_without_the_field_is_unchanged(tmp_path):
    d = _record(tmp_path)
    assert "established_versions" not in json.loads((d / "record.json").read_text())["decider"]
    assert _replay_state(d, _install("_stub_same", _Stub("1.0.0")))[0] == "established"
    state, detail, verdict = _replay_state(d, _install("_stub_other", _Stub("0.9.0")))
    assert state == "unknown" and "proves nothing" in detail and verdict == V.NOT_ESTABLISHED


def test_named_version_is_accepted_and_unnamed_is_not(tmp_path):
    body, dig = _evidence("0.9.0")
    d = _record(tmp_path, established=[{"version": "0.9.0", "evidence": dig}])
    assert json.loads((d / "record.json").read_text())["decider"]["established_versions"] == [{"version": "0.9.0", "evidence": dig}]
    state, detail, verdict = _replay_state(d, _install("_stub_named", _Stub("0.9.0")))
    assert state == "established" and "names as established" in detail and "producer's claim" in detail and verdict == V.ESTABLISHED
    state, detail, _ = _replay_state(d, _install("_stub_unnamed", _Stub("0.8.0")))
    assert state == "unknown" and "proves nothing" in detail


def test_supplied_evidence_is_checked_both_ways(tmp_path):
    body, dig = _evidence("0.9.0")
    d = _record(tmp_path, established=[{"version": "0.9.0", "evidence": dig}])
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"engine": "cedarpy-x", "full_corpus": body}))
    state, detail, _ = _replay_state(d, _install("_stub_ev", _Stub("0.9.0")), [good])
    assert state == "established" and "1000 of 1000" in detail and "digest matches" in detail
    # the digest the record names, but the run did not agree in full: the name is not supported
    partial, pdig = _evidence("0.9.0", agree=999)
    d2 = _record(tmp_path / "two", established=[{"version": "0.9.0", "evidence": pdig}])
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"full_corpus": partial}))
    state, detail, verdict = _replay_state(d2, _install("_stub_ev2", _Stub("0.9.0")), [bad])
    assert state == "unknown" and "999 of 1000" in detail and "not supported" in detail and verdict == V.NOT_ESTABLISHED
    # evidence for a different digest is simply not the evidence named; falls back to the producer's claim
    state, detail, _ = _replay_state(d, _install("_stub_ev3", _Stub("0.9.0")), [bad])
    assert state == "established" and "producer's claim" in detail


def test_a_falsely_named_version_is_caught_only_where_rows_differ(tmp_path):
    """The cost of naming: the name check no longer refuses by version, so a drifted engine is caught by recomputation or not at all."""
    _, dig = _evidence("0.9.0")
    d = _record(tmp_path, established=[{"version": "0.9.0", "evidence": dig}], n=6)
    state, detail, verdict = _replay_state(d, _install("_stub_drift_hit", _Stub("0.9.0", flip_at=3)))
    assert state == "failed" and "seq 4" in detail and verdict == V.FAILED
    state, _, verdict = _replay_state(d, _install("_stub_drift_miss", _Stub("0.9.0", flip_at=99)))
    assert state == "established" and verdict == V.ESTABLISHED


def test_shape_rejects_bad_established_versions(tmp_path):
    from dr.record import record_defects

    d = _record(tmp_path, established=[{"version": "0.9.0", "evidence": _evidence("0.9.0")[1]}])
    rec = json.loads((d / "record.json").read_text())
    assert record_defects(rec) == []
    for bad in ([], [{"version": "1.0.0", "evidence": _evidence("x")[1]}], [{"version": "0.9.0", "evidence": "nope"}],
                [{"version": "0.9.0", "evidence": _evidence("x")[1]}] * 2, [{"version": "0.9.0"}]):
        r = json.loads(json.dumps(rec))
        r["decider"]["established_versions"] = bad
        assert any("established_versions" in x for x in record_defects(r)), bad


def test_supplied_evidence_may_name_exclusions_and_they_are_checked_both_ways(tmp_path):
    """A result that agrees on every request it did not exclude supports the name; the exclusions are inside the digested result and printed."""
    body = {"engine": "0.9.0", "requests": 1000, "agree_decision_reason_and_error_presence": 997, "corpus": "stub",
            "excluded": [{"note": "a", "reason": "a harness-only builtin"}, {"note": "b", "reason": "a harness-only builtin"}, {"note": "c", "reason": "loader refuses what the library evaluates"}]}
    dig = digest_obj(body)
    d = _record(tmp_path, established=[{"version": "0.9.0", "evidence": dig}])
    f = tmp_path / "ev.json"
    f.write_text(json.dumps({"full_corpus": body}))
    state, detail, verdict = _replay_state(d, _install("_stub_exc_ok", _Stub("0.9.0")), [f])
    assert state == "established" and "997 of 1000, 3 excluded and named" in detail and "harness-only builtin" in detail and verdict == V.ESTABLISHED
    # the exclusions do not close the gap: refused, with the count stated
    short = dict(body, agree_decision_reason_and_error_presence=990)
    d2 = _record(tmp_path / "two", established=[{"version": "0.9.0", "evidence": digest_obj(short)}])
    f2 = tmp_path / "ev2.json"
    f2.write_text(json.dumps({"full_corpus": short}))
    state, detail, _ = _replay_state(d2, _install("_stub_exc_short", _Stub("0.9.0")), [f2])
    assert state == "unknown" and "990 of 1000 with 3 excluded" in detail and "not supported" in detail
    # an exclusion without a reason is malformed: refused
    bad = dict(body, excluded=[{"note": "a"}, {"note": "b", "reason": ""}, {"note": "c", "reason": "x"}])
    d3 = _record(tmp_path / "three", established=[{"version": "0.9.0", "evidence": digest_obj(bad)}])
    f3 = tmp_path / "ev3.json"
    f3.write_text(json.dumps({"full_corpus": bad}))
    state, detail, _ = _replay_state(d3, _install("_stub_exc_bad", _Stub("0.9.0")), [f3])
    assert state == "unknown" and "malformed excluded" in detail
