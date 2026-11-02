"""The seam table (SEAMS.md): one test per row.

A seam is a place where two parties must agree on what a value is and can
silently not. Each row of SEAMS.md is one class of JSON text, probed against
every party that reads or decides an input here — the reader, the
canonicaliser, the attester, the gate's command line, replay — and against the
engines' own parsers where an input crosses into them. Each row is in one of
three states: refused (every party here refuses it, with its reason), pinned
(every party provably reads one value), or open (stated as open, with why).
The tests below hold the state each row claims. Those that need an engine this
machine may not have (cedarpy, Go, OPA) skip without it; CI has all three.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dr.canonical import (  # noqa: E402
    NotAnInput, NotJSON, canonical_bytes, canonical_input, digest_obj, jsonl_lines, loads, loads_input, same_value)
from dr.signing import generate_private_key_pem  # noqa: E402
import tools.arrive as arrive  # noqa: E402

# In CI the engine rows must run: a skip there would leave a row unheld and
# say nothing (.github/workflows/tests.yml sets this).
REQUIRE_ENGINES = os.environ.get("SEAMS_REQUIRE_ENGINES") == "1"


def _require(available, what: str):
    """Skip without the engine, except in CI, where a missing engine fails."""
    if not available:
        if REQUIRE_ENGINES:
            pytest.fail(f"{what} is required here (SEAMS_REQUIRE_ENGINES=1) and missing")
        pytest.skip(f"no {what}")


def _cedarpy():
    try:
        import cedarpy
        return cedarpy
    except ImportError:
        return None


KEY = ["--key", "examples/keys/example-signing-key.pem", "--key-id", "example-2026-10", "--issued-at", "2026-10-28T00:00:00Z"]
POLICY = "examples/data/toolgate-policy.json"


def _line(inp: str) -> str:
    return '{"ts": "2026-10-18T01:00:00Z", "input": ' + inp + '}'


def _emit(tmp_path, *lines, name="run"):
    f = tmp_path / f"{name}.jsonl"
    f.write_text("".join(l + "\n" for l in lines), encoding="utf-8")
    out = tmp_path / name
    p = subprocess.run([sys.executable, "-m", "emitters.toolgate", "--policy", POLICY, "--inputs", str(f), "--out", str(out),
                        "--record-id", name, *KEY], cwd=ROOT, capture_output=True, text=True)
    return p, out


def _verify(out, *extra):
    p = subprocess.run([sys.executable, "-m", "dr.verify", str(out), "--registry", "examples/keys/registry.json",
                        "--replay", "emitters.toolgate", "--json", *extra], cwd=ROOT, capture_output=True, text=True)
    rep = json.loads(p.stdout) if p.stdout.strip().startswith("{") else {"properties": []}
    return p.returncode, {q["property"]: (q["state"], q["detail"]) for q in rep["properties"]}


def _rows(out):
    return [json.loads(l) for l in (out / "decisions.jsonl").read_text(encoding="utf-8").split("\n") if l.strip()]


def _attester(tmp_path):
    return arrive.Attester(tmp_path / "arrivals.jsonl", key_id="customer", private_key_pem=generate_private_key_pem())


def _refused_everywhere_here(tmp_path, inp: str, reason: str, *, input_only=False, line=None):
    """The reader (unless the class is refused only as an input), the input
    reader, the gate's command line (given `line`, or `inp` as a line's input)
    and the attester all refuse `inp`, with `reason`; the attester spends no
    number on it."""
    if not input_only:
        with pytest.raises(ValueError, match=reason):
            loads(inp)
    with pytest.raises(ValueError, match=reason):
        loads_input(inp)
    p, out = _emit(tmp_path, line if line is not None else _line(inp))
    assert p.returncode != 0 and reason in p.stderr, p.stderr
    assert "Traceback" not in p.stderr
    assert not (out / "record.json").exists()
    att = _attester(tmp_path)
    with pytest.raises(ValueError, match=reason):
        att.arrive_text(inp)
    assert att.arrive_text('{"tool": "get_weather", "args": {"city": "a"}}')["arrival_seq"] == 1
    att.close()


# --- 1. duplicate member names: refused ---------------------------------------

DUP = '{"tool": "lookup_order", "args": {"order_id": 1, "order_id": "x"}}'


def test_row_1_duplicate_names_are_refused_by_every_party_here(tmp_path):
    """Before: the gate's command line read this with the last value winning,
    decided DENY on the string, and the record verified with exit 0, while a
    reader that keeps the first value reads an integer the gate allows."""
    _refused_everywhere_here(tmp_path, DUP, "appears twice")


# --- 2. numeric overflow: refused ---------------------------------------------

@pytest.mark.parametrize("n", ["1e400", "-1e309", "1" + "0" * 400])
def test_row_2_overflow_is_refused_by_every_party_here(tmp_path, n):
    _refused_everywhere_here(tmp_path, '{"tool": "lookup_order", "args": {"order_id": %s}}' % n, "double")


# --- 3. integers past 2^53: refused as inputs, rendered as documents -----------

def test_row_3_integers_past_2_53_are_refused_as_inputs_and_rendered_as_documents(tmp_path):
    inp = '{"tool": "lookup_order", "args": {"order_id": 9007199254740993}}'
    assert loads(inp)["args"]["order_id"] == 9007199254740993          # a document may carry it
    assert canonical_bytes(9007199254740993) == b"9007199254740992"     # RFC 8785, unchanged
    with pytest.raises(NotAnInput):
        canonical_input(loads_input(inp))
    p, out = _emit(tmp_path, _line(inp))
    assert p.returncode != 0 and "beyond" in p.stderr and "Traceback" not in p.stderr
    att = _attester(tmp_path)
    with pytest.raises(NotAnInput):
        att.arrive_text(inp)
    att.close()


# --- 4. negative zero: pinned to 0 --------------------------------------------

@pytest.mark.parametrize("spelling", ["-0", "-0.0", "-0e0", "0.0"])
def test_row_4_negative_zero_is_decided_signed_and_replayed_as_0(tmp_path, spelling):
    inp = '{"tool": "lookup_order", "args": {"order_id": %s}}' % spelling
    v = canonical_input(loads_input(inp))
    assert same_value(v, {"tool": "lookup_order", "args": {"order_id": 0}})
    assert digest_obj(v) == digest_obj({"tool": "lookup_order", "args": {"order_id": 0}})
    p, out = _emit(tmp_path, _line(inp))
    assert p.returncode == 0, p.stderr
    assert [(r["outcome"], r["reason"]) for r in _rows(out)] == [("ALLOW", None)]
    code, states = _verify(out)
    assert code == 0 and states["replay"][0] == "established"
    att = _attester(tmp_path)
    assert att.arrive_text(inp)["input_digest"] == _rows(out)[0]["input_digest"]
    att.close()


def test_row_4_cedar_decides_the_value_the_digest_covers():
    cedarpy = _cedarpy()
    _require(cedarpy, "cedarpy")
    pol = "permit(principal, action, resource) when { context.n == 0 };"
    req = lambda n: {"principal": 'User::"a"', "action": 'Action::"view"', "resource": 'Doc::"d"', "context": {"n": n}}
    raw = cedarpy.is_authorized(req(-0.0), pol, [])
    assert raw.decision != cedarpy.Decision.Allow           # Cedar has no floats: the raw -0.0 is refused
    assert cedarpy.is_authorized(req(canonical_input(-0.0)), pol, []).decision == cedarpy.Decision.Allow


# --- 5. Unicode normalisation: pinned by not normalising ----------------------

NFC, NFD = "Zürich", "Zürich"


def test_row_5_no_party_normalises_so_the_digest_tells_the_forms_apart(tmp_path):
    a = {"tool": "get_weather", "args": {"city": NFC}}
    b = {"tool": "get_weather", "args": {"city": NFD}}
    assert canonical_input(a) == a and canonical_input(b) == b
    assert digest_obj(a) != digest_obj(b)
    p, out = _emit(tmp_path, _line(json.dumps(a)), _line(json.dumps(b, ensure_ascii=False)))
    assert p.returncode == 0, p.stderr
    rows = _rows(out)
    assert [r["input_digest"] for r in rows] == [digest_obj(a), digest_obj(b)]
    retained = [loads(l)["input"]["args"]["city"] for _, l in jsonl_lines((out / "inputs.jsonl").read_text(encoding="utf-8"))]
    assert retained == [NFC, NFD]
    code, states = _verify(out)
    assert code == 0 and states["replay"][0] == "established"


def test_row_5_cedar_compares_code_points():
    cedarpy = _cedarpy()
    _require(cedarpy, "cedarpy")
    pol = 'permit(principal, action, resource) when { context.city == "Zürich" };'
    req = lambda c: {"principal": 'User::"a"', "action": 'Action::"view"', "resource": 'Doc::"d"', "context": {"city": c}}
    assert cedarpy.is_authorized(req(NFC), pol, []).decision == cedarpy.Decision.Allow
    assert cedarpy.is_authorized(req(NFD), pol, []).decision == cedarpy.Decision.Deny


# --- 6. byte-order mark: refused ----------------------------------------------

def test_row_6_a_byte_order_mark_is_refused(tmp_path):
    inp = '{"tool": "get_weather", "args": {"city": "a"}}'
    _refused_everywhere_here(tmp_path, "\ufeff" + inp, "BOM", line="\ufeff" + _line(inp))


@pytest.mark.parametrize("raw", [b"\xef\xbb\xbf" + b'{"tool": "get_weather", "args": {"city": "a"}}',
                                 '{"tool": "get_weather", "args": {"city": "a"}}'.encode("utf-16"),
                                 '{"tool": "get_weather", "args": {"city": "a"}}'.encode("utf-32"),
                                 b'{"tool": "get_weather", "args": {"city": "\xff"}}'],
                         ids=["utf-8 with BOM", "utf-16", "utf-32", "not UTF-8"])
def test_row_6_bytes_are_read_as_utf_8_only_so_the_attester_refuses_what_the_gate_refuses(tmp_path, raw):
    """Python's json.loads given bytes drops a BOM and detects UTF-16 and
    UTF-32. Read that way, the reader and the attester given the bytes an input
    arrived as would accept, and sign, what the gate reading the same bytes as
    UTF-8 refuses."""
    with pytest.raises(ValueError):
        loads(raw)
    with pytest.raises(ValueError):
        loads_input(raw)
    att = _attester(tmp_path)
    with pytest.raises(ValueError):
        att.arrive_text(raw)
    good = '{"tool": "get_weather", "args": {"city": "a"}}'
    assert att.arrive_text(good.encode("utf-8"))["arrival_seq"] == 1          # no number was spent on the refusal
    assert att.arrive_text(good)["input_digest"] == att.arrive_text(good.encode("utf-8"))["input_digest"]
    att.close()


def test_the_reader_takes_text_or_utf_8_bytes_and_nothing_else():
    with pytest.raises(TypeError):
        loads(123)


# --- 7. trailing content: refused; trailing whitespace is whitespace -----------

@pytest.mark.parametrize("trailing", [' {"x": 1}', "x"])
def test_row_7_trailing_content_is_refused(tmp_path, trailing):
    inp = '{"tool": "get_weather", "args": {"city": "a"}}'
    _refused_everywhere_here(tmp_path, inp + trailing, "Extra data", line=_line(inp) + trailing)


def test_row_7_trailing_json_whitespace_is_not_content():
    assert loads('{"a": 1} \t\r') == {"a": 1}
    with pytest.raises(ValueError):
        loads('{"a": 1} ')  # not JSON whitespace: content after the value


# --- 8. number spellings: one value, one decision; excess precision refused ----

@pytest.mark.parametrize("spelling", ["100", "1E2", "1e2", "1e+2", "100.0", "1.0e2", "0.1e3", "10000e-2"])
def test_row_8_spellings_of_one_value_are_one_input(tmp_path, spelling):
    inp = '{"tool": "lookup_order", "args": {"order_id": %s}}' % spelling
    assert digest_obj(canonical_input(loads_input(inp))) == digest_obj({"tool": "lookup_order", "args": {"order_id": 100}})
    p, out = _emit(tmp_path, _line(inp))
    assert p.returncode == 0 and [(r["outcome"], r["reason"]) for r in _rows(out)] == [("ALLOW", None)]


@pytest.mark.parametrize("text", ["01", "+1", ".5", "1.", "0x10", "1e", "-"])
def test_row_8_spellings_outside_the_grammar_are_refused(text):
    with pytest.raises(ValueError):
        loads('{"n": %s}' % text)


@pytest.mark.parametrize("n,reads_as", [("1.00000000000000001", "1"), ("1e-400", "0"), ("0.30000000000000001", "0.3"),
                                        ("123456789012345678901234567890.0", "1.2345678901234568e+29")])
def test_row_8_a_number_more_precise_than_its_canonical_bytes_is_refused_as_an_input(tmp_path, n, reads_as):
    """Before: 1.00000000000000001 was decided as the integer 1 and allowed; a
    reader that keeps every digit reads a number with a fraction."""
    inp = '{"tool": "lookup_order", "args": {"order_id": %s}}' % n
    loads(inp)  # a document may carry it: its digest is over the double, as RFC 8785 says
    _refused_everywhere_here(tmp_path, inp, "not the number its canonical bytes spell", input_only=True)
    with pytest.raises(NotAnInput, match=re.escape(f"reads it as {reads_as},")):
        loads_input(inp)


@pytest.mark.parametrize("n", ["0.1", "5e-324", "1.7976931348623157e308", "-2.5", "1e21", "1e-7", "0.000001"])
def test_row_8_a_number_spelled_as_its_canonical_bytes_spell_it_is_an_input(n):
    loads_input('{"n": %s}' % n)


# --- 9. escaped versus literal characters; what ends a line --------------------

def test_row_9_an_escape_and_its_character_are_one_value():
    pairs = [('"\\u0072"', '"r"'), ('"\\/"', '"/"'), ('"\\u00e9"', '"é"'), ('"\\u00E9"', '"é"'), ('"\\ud83d\\ude00"', '"\U0001F600"')]
    for esc, lit in pairs:
        assert canonical_bytes(loads(esc)) == canonical_bytes(loads(lit))


@pytest.mark.parametrize("ch", [" ", " ", "\u0085"], ids=["U+2028", "U+2029", "U+0085"])
@pytest.mark.parametrize("as_written", ["literal", "escaped"])
def test_row_9_a_line_terminator_inside_a_string_does_not_end_the_line(tmp_path, ch, as_written):
    """Before: an input carrying U+2028, escaped or not, was retained with the
    character written literally, as RFC 8785 writes it, and the verifier split
    `inputs.jsonl` with `str.splitlines`, which ends a line there: an honest
    record failed `retained` and exited 2."""
    city = "a" + (ch if as_written == "literal" else "\\u%04x" % ord(ch)) + "b"
    p, out = _emit(tmp_path, _line('{"tool": "get_weather", "args": {"city": "%s"}}' % city))
    assert p.returncode == 0, p.stderr
    code, states = _verify(out)
    assert code == 0, states
    assert states["retained"][0] == "established" and states["replay"][0] == "established"


def test_row_9_a_carriage_return_is_whitespace_not_a_line_end(tmp_path):
    """Before: the ledger reader iterated the file, which ends a line at a lone
    CR; a row with a CR between its tokens (JSON whitespace) was read as two
    lines that are not JSON. A reader splitting on LF reads one row."""
    p, out = _emit(tmp_path, _line('{"tool": "get_weather", "args": {"city": "a"}}'))
    assert p.returncode == 0
    led = out / "decisions.jsonl"
    text = led.read_text(encoding="utf-8")
    led.write_bytes(text.replace("{", "{\r", 1).encode("utf-8"))
    code, states = _verify(out)
    assert states["chain"][0] == "established", states["chain"]


def test_row_9_every_line_reader_here_splits_on_lf_only():
    text = '{"a": "x y"}\n\n {"b": 1}\r\n{"c": "\u0085"}'
    assert [n for n, _ in jsonl_lines(text)] == [1, 3, 4]
    assert [loads(l) for _, l in jsonl_lines(text)] == [{"a": "x y"}, {"b": 1}, {"c": "\u0085"}]
    readers = list((ROOT / "dr").glob("*.py")) + [ROOT / "tools" / f for f in ("arrive.py", "verify_arrival.py", "rederive.py", "corpus_coverage.py")] + [ROOT / "emitters" / "_cli.py"]
    offenders = []
    for f in readers:
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("#")[0]
            split_text = ".splitlines()" in code and "__doc__" not in code and "# not JSON Lines" not in line
            text_mode = "jsonl_lines(" in code and "read_text" in code   # text mode turns a lone CR into LF first
            iterated = re.search(r"for .* in f\b", code) is not None      # iterating a text file: universal newlines
            if split_text or text_mode or iterated:
                offenders.append(f"{f.relative_to(ROOT)}:{n}")
    assert offenders == []


# --- the engines' own parsers, where an input crosses into them --------------

GO_PROBE = r'''
package main

import ("bufio"; "bytes"; "encoding/json"; "fmt"; "os")

func main() {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		d := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		d.UseNumber()
		var v interface{}
		if err := d.Decode(&v); err != nil { fmt.Println("ERR"); continue }
		b, _ := json.Marshal(v)
		fmt.Println(string(b))
	}
}
'''


def test_gos_reader_disagrees_where_the_table_refuses(tmp_path):
    """Go's encoding/json, as OPA reads JSON (a Decoder with UseNumber): it keeps
    the last of two duplicate names, keeps every digit of a number, keeps a
    number past a double's range, and refuses a byte-order mark. Each is a row
    this side refuses, because a reader like this one reads another value."""
    _require(shutil.which("go"), "a go toolchain")
    (tmp_path / "probe.go").write_text(GO_PROBE)
    env = {**os.environ, "GOCACHE": str(tmp_path / "gocache"), "GOFLAGS": "", "GO111MODULE": "off"}
    b = subprocess.run(["go", "build", "-o", str(tmp_path / "probe"), str(tmp_path / "probe.go")], capture_output=True, text=True, env=env)
    assert b.returncode == 0, b.stderr
    lines = ['{"a": 1, "a": 2}', '{"n": 1.00000000000000001}', '{"n": 1e-400}', '{"n": 1e400}', '\ufeff{"a": 1}']
    out = subprocess.run([str(tmp_path / "probe")], input="\n".join(lines) + "\n", capture_output=True, text=True).stdout.splitlines()
    assert out == ['{"a":2}', '{"n":1.00000000000000001}', '{"n":1e-400}', '{"n":1e400}', "ERR"]


OPA_BIN = os.environ.get("OPA_BIN") or shutil.which("opa")


def _opa(query: str, input_text: str):
    p = subprocess.run([OPA_BIN, "eval", "--format", "json", "--stdin-input", query], input=input_text, capture_output=True, text=True)
    if p.returncode != 0:
        return ("error", p.stderr.strip()[:200])
    res = json.loads(p.stdout).get("result")
    return ("value", res[0]["expressions"][0]["value"]) if res else ("undefined", None)


def test_opa_reading_the_text_itself_decides_another_number_under_the_same_digest():
    """Why row 8 refuses: OPA, given the text, keeps every digit. The digest of
    `1.00000000000000001` and of `1` is the same, and OPA decides them
    differently; here the gate decides the canonical value, so OPA in this
    format never sees the text, but a party in front that does would."""
    _require(OPA_BIN, "an opa binary (OPA_BIN or on PATH)")
    assert digest_obj(loads('{"x": 1.00000000000000001}')) == digest_obj({"x": 1})
    assert _opa("input.x == 1", '{"x": 1}') == ("value", True)
    assert _opa("input.x == 1", '{"x": 1.00000000000000001}') == ("value", False)
    assert _opa("input.x > 0", '{"x": 1e-400}') == ("value", True)


def test_opa_on_the_rows_this_side_pins():
    _require(OPA_BIN, "an opa binary (OPA_BIN or on PATH)")
    assert _opa("input.x == 0", '{"x": -0.0}') == ("value", True)                       # row 4
    assert _opa('input.c == "Zürich"', json.dumps({"c": NFD})) == ("value", False)  # row 5: code points
    assert _opa('input.c == "r"', '{"c": "\\u0072"}') == ("value", True)                 # row 9


def test_opa_on_a_duplicate_name_reads_one_of_two_values():
    """Recorded rather than relied on: whichever value OPA keeps, a reader that
    keeps the other exists, and this side refuses the text."""
    _require(OPA_BIN, "an opa binary (OPA_BIN or on PATH)")
    kind, value = _opa("input.a", '{"a": 1, "a": 2}')
    assert (kind, value) in {("value", 1), ("value", 2), ("error", value)}
