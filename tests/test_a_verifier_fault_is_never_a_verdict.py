"""A fault in the verifier exits 3 and is never a property's state.

Two ways a fault could get past the guard, both held here. A fault while
hashing could be caught inside a check and turned into a state: a stream
DEFECT, exit 1, in `dr.stream`; `retained` failed, exit 2, while hashing
retained inputs in `dr.verify`; `stream` unknown, exit 1, while checking a
link. And a guard that covered the computation but not the reading, rendering
or printing would leave a fault there with Python's exit 1, a verdict's code;
`dr.stream` given a record outside any stream would crash with no fault
injected at all.

Each case below injects a fault at one place a verifier reads, hashes, renders
or prints, and requires exit 3, VERIFIER ERROR on standard error, and no
verdict on standard output.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dr.signing  # noqa: E402
import dr.stream as stream_mod  # noqa: E402
import dr.verify as verify_mod  # noqa: E402
import tools.verify_arrival as va  # noqa: E402

REC = "examples/acceptance/out/record"
VERIFY = [REC, "--registry", "examples/keys/registry.json", "--decider-registry", "examples/keys/deciders.json"]
G = "examples/acceptance/out/gated"
ARRIVAL = [G, "--registry", f"{G}.producer.json", "--decider-registry", f"{G}.decider.json",
           "--attester-registry", f"{G}.attester.json", "--arrival-log", f"{G}.attester-log.jsonl"]
VERDICT_WORDS = ("VERDICT", "ESTABLISHED", "FAILED", "DEFECT", "FORK", "OK:", '"properties"')


def _boom(*a, **k):
    raise RuntimeError("injected verifier fault")


CASES = [
    # (id, module main, argv, object to patch, attribute)
    ("verify: hashing retained inputs", verify_mod.main, VERIFY, verify_mod, "digest_obj"),
    ("verify: hashing the record", verify_mod.main, VERIFY, verify_mod, "payload_hash"),
    ("verify: rendering text", verify_mod.main, VERIFY, verify_mod.Report, "to_text"),
    ("verify: rendering json", verify_mod.main, [*VERIFY, "--json"], verify_mod.Report, "to_json"),
    ("verify: the level", verify_mod.main, [*VERIFY, "--assurance"], verify_mod, "assess"),
    # The attestation check runs outside the guard around any supplied file,
    # so a fault inside it is the verifier's. The witness and receipt checks
    # run inside the guard around their file; a fault there of a supplied
    # file's kind is read as the file's (README row 3, SPEC.md section 9).
    ("verify: the attestation check", verify_mod.main, VERIFY, verify_mod.attest_mod, "check"),
    ("arrival: reading arrivals", va.main, ARRIVAL, va.arrive, "load"),
    ("arrival: rendering text", va.main, ARRIVAL, verify_mod.Report, "to_text"),
    ("arrival: rendering json", va.main, [*ARRIVAL, "--json"], va.json, "dumps"),
    ("stream: hashing", stream_mod.main, [f"{REC}/record.json"], stream_mod, "payload_hash"),
    ("stream: reading", stream_mod.main, [f"{REC}/record.json"], stream_mod, "strict_loads"),
]


@pytest.mark.parametrize("main,argv,target,attr", [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_an_injected_fault_exits_3_and_says_so(monkeypatch, capsys, main, argv, target, attr):
    monkeypatch.chdir(ROOT)
    monkeypatch.setattr(target, attr, _boom)
    code = main(list(argv))
    out, err = capsys.readouterr()
    assert code == 3, (code, out[-300:], err[-300:])
    assert "VERIFIER ERROR" in err and "injected verifier fault" in err
    assert not any(w in out for w in VERDICT_WORDS), out[-300:]


def test_a_stream_hashing_fault_is_not_a_defect(monkeypatch, capsys):
    """Broken, this exits 1 with a DEFECT line: a verifier fault reported as the stream's."""
    monkeypatch.chdir(ROOT)
    monkeypatch.setattr(stream_mod, "payload_hash", _boom)
    assert stream_mod.main([f"{REC}/record.json"]) == 3
    out, err = capsys.readouterr()
    assert "DEFECT" not in out and "VERIFIER ERROR" in err


def test_a_record_outside_any_stream_is_nothing_to_check_not_a_crash(monkeypatch, capsys):
    """Broken, this is an IndexError traceback and exit 1, with no fault injected at all."""
    monkeypatch.chdir(ROOT)
    assert stream_mod.main(["examples/out/classrouter-benchmark/record.json"]) == 3
    out, err = capsys.readouterr()
    assert "Traceback" not in err and "none of the records given is part of a stream" in err


def test_a_record_outside_the_stream_is_named_and_the_stream_is_still_checked(monkeypatch, capsys):
    monkeypatch.chdir(ROOT)
    code = stream_mod.main([f"{REC}/record.json", "examples/out/classrouter-benchmark/record.json"])
    out, _ = capsys.readouterr()
    assert code == 0
    assert "NOTE   examples/out/classrouter-benchmark/record.json is not part of a stream" in out and "OK:" in out


def test_a_malformed_supplied_file_is_still_the_files_state(tmp_path, monkeypatch):
    """The other side of the line: narrowing the handlers must not turn a bad
    supplied file into a crash. A registry that is not JSON is unknown, as before."""
    monkeypatch.chdir(ROOT)
    bad = tmp_path / "registry.json"
    bad.write_text("{not json")
    rep = verify_mod.verify_directory(ROOT / REC, bad)
    assert {p["property"]: p["state"] for p in rep.properties}["signing_trust"] == "unknown"


def _boom_typed(*a, **k):
    raise TypeError("injected verifier fault")


@pytest.mark.parametrize("attr,argv", [
    ("digest_obj", VERIFY),
    ("keyed_input_digest", ["examples/out/ratelimit-production-keyed", "--registry", "examples/keys/registry.json"]),
], ids=["plain inputs", "keyed inputs"])
def test_a_fault_of_a_supplied_files_kind_while_hashing_is_still_a_fault(monkeypatch, capsys, attr, argv):
    """The catch around reading a retained file names the exception kinds a
    malformed file raises, TypeError among them. Hashing what was read sits
    outside that catch, so a TypeError raised by the hash is the verifier's
    fault and exits 3. Broken, this exits 2 with `retained` failed: the
    injected fault read as the file's."""
    monkeypatch.chdir(ROOT)
    monkeypatch.setattr(verify_mod, attr, _boom_typed)
    code = verify_mod.main(list(argv))
    out, err = capsys.readouterr()
    assert code == 3, (code, out[-300:], err[-300:])
    assert "VERIFIER ERROR" in err and not any(w in out for w in VERDICT_WORDS)


def test_a_command_line_the_verifier_cannot_read_exits_3(capsys):
    """argparse exits 2 on a usage error, FAILED's code. Nothing was judged, so
    the verifier exits 3 and says so. Broken, `python3 -m dr.verify` with no
    arguments exits 2."""
    with pytest.raises(SystemExit) as e:
        verify_mod.main([])
    assert e.value.code == 3
    out, err = capsys.readouterr()
    assert "nothing was judged" in err and not out
