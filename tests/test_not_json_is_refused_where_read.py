"""A bare NaN or Infinity is refused where a document is read.

Python's json module accepts NaN, Infinity and -Infinity; RFC 8259 does not,
and the canonical form has no rendering for them. A reader that let them
through would leave the refusal to whichever check hashed the value first,
where it reads as that check's verdict: a ledger row would make the whole
directory unreadable, a key registry carrying one would be accepted, and a
stream prior or fork group carrying one would fall through the link and fork
checks. Each
case below plants one bare NaN in one file of a valid record and states what
the verifier now says, which is what it says for any other text that is not
JSON in that file.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dr.canonical import NotJSON, loads  # noqa: E402

SRC = ROOT / "examples" / "acceptance" / "out" / "record"


def _verify(d, registry="examples/keys/registry.json"):
    p = subprocess.run([sys.executable, "-m", "dr.verify", str(d), "--registry", str(registry),
                        "--decider-registry", "examples/keys/deciders.json", "--json"], capture_output=True, text=True, cwd=ROOT)
    rep = json.loads(p.stdout) if p.stdout.strip().startswith("{") else None
    states = {q["property"]: (q["state"], q["detail"]) for q in rep["properties"]} if rep else {}
    return p.returncode, states, p.stderr


@pytest.mark.parametrize("text", ["NaN", "Infinity", "-Infinity", '{"a": [1, NaN]}',
                                  '{"s": "\\ud800"}', '{"\\udfff": 1}', '["a\\udc00b"]'])
def test_the_reader_refuses_what_is_not_json(text):
    with pytest.raises(NotJSON):
        loads(text)


def test_the_string_nan_is_still_a_string_and_a_surrogate_pair_is_still_a_character():
    assert loads('{"a": "NaN", "b": 1.5}') == {"a": "NaN", "b": 1.5}
    assert loads('{"s": "\\ud83d\\ude00"}') == {"s": "\U0001F600"}


@pytest.mark.parametrize("planted", ["NaN", '"\\ud800"'], ids=["nan", "lone-surrogate"])
def test_a_ledger_row_carrying_what_has_no_canonical_form_fails_chain(tmp_path, planted):
    """The canonicaliser now rejects nothing a format reader accepts."""
    d = _copy(tmp_path)
    lines = (d / "decisions.jsonl").read_text().splitlines()
    lines[0] = lines[0].replace('"input_digest"', '"ext": {"x": ' + planted + '}, "input_digest"', 1)
    (d / "decisions.jsonl").write_text("\n".join(lines) + "\n")
    code, states, _ = _verify(d)
    assert code == 2 and states["chain"][0] == "failed"
    assert "canonical form" in states["chain"][1]


def test_a_registry_carrying_a_lone_surrogate_is_unreadable(tmp_path):
    reg = tmp_path / "registry.json"
    reg.write_text((ROOT / "examples/keys/registry.json").read_text().replace('"registry_version": 1', '"registry_version": 1, "x": "\\ud800"', 1))
    code, states, _ = _verify(SRC, reg)
    assert states["signing_trust"][0] == "unknown" and code == 1


def _copy(tmp_path):
    d = tmp_path / "record"
    shutil.copytree(SRC, d)
    return d


def test_a_record_carrying_nan_is_unreadable_like_any_record_that_is_not_json(tmp_path):
    d = _copy(tmp_path)
    (d / "record.json").write_text((d / "record.json").read_text().replace('"format_version"', '"x": NaN, "format_version"', 1))
    code, _, err = _verify(d)
    assert code == 3 and "not JSON" in err


def test_a_ledger_row_carrying_nan_fails_chain_as_a_row_that_is_not_json(tmp_path):
    d = _copy(tmp_path)
    lines = (d / "decisions.jsonl").read_text().splitlines()
    lines[0] = lines[0].replace('"input_digest"', '"ext": {"x": NaN}, "input_digest"', 1)
    (d / "decisions.jsonl").write_text("\n".join(lines) + "\n")
    code, states, _ = _verify(d)
    assert code == 2
    assert states["chain"][0] == "failed" and "not JSON" in states["chain"][1]


def test_a_registry_carrying_nan_is_unreadable_so_trust_is_unknown(tmp_path):
    reg = tmp_path / "registry.json"
    reg.write_text((ROOT / "examples/keys/registry.json").read_text().replace('"registry_version": 1', '"registry_version": 1, "x": NaN', 1))
    code, states, _ = _verify(SRC, reg)
    assert states["signing_trust"][0] == "unknown"
    assert code == 1


# --- the reader is I-JSON: nothing it accepts is refused by the canonicaliser ---
#
# Three inputs a JSON reader can accept and the canonicaliser cannot render:
# 1e400 (the float parser overflows to infinity without the constant hook), an
# integer written out past a double's range (canonical_bytes would raise a bare
# OverflowError and crash the verifier with Python's exit 1, the code for NOT
# ESTABLISHED), and duplicate member names (accepted, last value wins, so two
# parsers read two values). The reader refuses all three.

BIG = "1" + "0" * 400


@pytest.mark.parametrize("text", [
    '{"n": 1e400}', '{"n": -1e400}', '{"n": 1e309}', '[1E+999]',
    '{"n": %s}' % BIG, '{"n": -%s}' % BIG,
    '{"a": 1, "a": 2}', '{"a": 1, "a": 1}', '{"o": {"x": 1, "x": 2}}', '[{"k": true, "k": false}]',
], ids=["1e400", "-1e400", "1e309", "1E+999", "int-400-digits", "-int-400-digits",
        "dup-differing", "dup-equal", "dup-nested", "dup-in-array"])
def test_the_reader_refuses_numbers_past_a_double_and_duplicate_names(text):
    with pytest.raises(NotJSON):
        loads(text)


@pytest.mark.parametrize("text", [
    '{"n": 1e308}', '{"n": 1.7976931348623157e308}', '{"n": -1.7976931348623157e308}', '{"n": 5e-324}',
    '{"n": 9007199254740993}', '{"n": -0.0}', '{"n": 1E2}', '[{"a": 1}, {"a": 2}]', '{"a": {"a": 1}}',
    '{"%s": 1}' % ("k" * 1000),
], ids=["1e308", "max-double", "min-double", "subnormal", "past-2^53", "neg-zero", "1E2",
        "same-name-different-objects", "same-name-nested", "long-name"])
def test_the_reader_still_accepts_every_edge_that_is_i_json(text):
    loads(text)


def _edge_texts():
    yield from ['{"n": 1e308}', '{"n": 5e-324}', '{"n": -0.0}', '{"n": 9007199254740993}', '{"n": 123456789012345678901234567890}',
                '{"s": "\\ud83d\\ude00"}', '{"s": "\\u0000"}', '[[], {}, null, true, false, ""]', '{"n": 1.0}', '{"n": 0.1}']
    # and the texts a reader once accepted that the canonicaliser could not render:
    # without them this test passes whether or not the reader refuses them
    yield from ['{"n": 1e400}', '{"n": -1e309}', '{"n": %s}' % BIG, '[-%s]' % BIG, '{"s": "\\ud800"}', 'NaN']
    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "*.json", "*.jsonl"], capture_output=True, text=True).stdout.split()
    for f in tracked:
        p = ROOT / f
        if not p.is_file() or p.stat().st_size > 2_000_000:
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        if f.endswith(".jsonl"):
            yield from (l for l in text.splitlines() if l.strip())
        else:
            yield text


def test_the_canonicaliser_rejects_nothing_a_format_reader_accepts():
    """For edge texts and every JSON document and
    JSON Lines row tracked in the repository, whatever the reader accepts the
    canonicaliser renders."""
    from dr.canonical import canonical_bytes
    checked = 0
    for text in _edge_texts():
        try:
            value = loads(text)
        except (NotJSON, ValueError):
            continue
        canonical_bytes(value)  # must not raise
        checked += 1
    assert checked > 100


@pytest.mark.parametrize("planted,reason", [
    ("1e400", "overflows a double"),
    (BIG, "past a double's range"),
    ('{"y": 1, "y": 2}', "appears twice"),
], ids=["1e400", "int-400-digits", "duplicate-name"])
def test_a_ledger_row_carrying_r1s_cases_fails_chain_with_the_readers_reason(tmp_path, planted, reason):
    d = _copy(tmp_path)
    lines = (d / "decisions.jsonl").read_text().splitlines()
    lines[0] = lines[0].replace('"input_digest"', '"ext": {"x": ' + planted + '}, "input_digest"', 1)
    (d / "decisions.jsonl").write_text("\n".join(lines) + "\n")
    code, states, _ = _verify(d)
    assert code == 2 and states["chain"][0] == "failed"
    assert reason in states["chain"][1]


def test_a_record_or_registry_with_a_duplicate_name_is_unreadable(tmp_path):
    d = _copy(tmp_path)
    text = (d / "record.json").read_text()
    assert '"format_version": 2' in text
    (d / "record.json").write_text(text.replace('"format_version": 2', '"format_version": 2, "format_version": 2', 1))
    code, _, err = _verify(d)
    assert code == 3 and "appears twice" in err
    reg = tmp_path / "registry.json"
    reg.write_text((ROOT / "examples/keys/registry.json").read_text().replace('"registry_version": 1', '"registry_version": 1, "registry_version": 1', 1))
    code, states, _ = _verify(SRC, reg)
    assert states["signing_trust"][0] == "unknown" and code == 1


def test_a_fault_in_the_verifier_never_exits_with_a_verdicts_code(monkeypatch, capsys):
    """Python exits 1 on an uncaught exception, and 1 is NOT ESTABLISHED. A crash
    must say it is the verifier's, and exit 3: nothing was judged."""
    import dr.verify as verify_mod
    import dr.stream as stream_mod
    import tools.verify_arrival as va
    def broken(*a, **k):
        raise RuntimeError("deliberately broken for the test")
    monkeypatch.setattr(verify_mod, "verify_directory", broken)
    code = verify_mod.main([str(SRC), "--registry", str(ROOT / "examples/keys/registry.json")])
    assert code == verify_mod.UNREADABLE == 3 and "VERIFIER ERROR" in capsys.readouterr().err
    monkeypatch.setattr(va, "add_arrival", broken)
    code = va.main([str(SRC), "--registry", str(ROOT / "examples/keys/registry.json")])
    assert code == 3 and "VERIFIER ERROR" in capsys.readouterr().err
    monkeypatch.setattr(stream_mod, "check_sequence", broken)
    code = stream_mod.main([str(SRC / "record.json")])
    assert code == 3 and "VERIFIER ERROR" in capsys.readouterr().err
