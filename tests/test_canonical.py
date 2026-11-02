"""dr.canonical is RFC 8785, and the move to it changed no byte in the examples."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from dr.canonical import NotCanonicalisable, canonical_bytes, legacy_sorted_json_bytes

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "value,expected",
    [
        (0.0, "0"), (-0.0, "0"), (1.0, "1"), (1.5, "1.5"), (0.1, "0.1"),
        (1e21, "1e+21"), (1e20, "100000000000000000000"), (1e-7, "1e-7"), (0.000001, "0.000001"),
        (5e-324, "5e-324"), (1.7976931348623157e308, "1.7976931348623157e+308"),
        (9007199254740992.0, "9007199254740992"), (2**53 + 2, "9007199254740994"), (10**21, "1e+21"),
        (-1.5, "-1.5"), (3.0e-5, "0.00003"), (333333333.33333329, "333333333.3333333"), (1e30, "1e+30"),
    ],
)
def test_numbers_render_as_ecmascript_does(value, expected):
    assert canonical_bytes(value).decode() == expected


def test_member_names_sort_by_utf16_code_units_rfc8785_example():
    obj = {
        "€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One", "\U0001f600": "Emoji: Grinning Face", "\u0080": "Control", "ö": "Latin Small Letter O With Diaeresis",
    }
    keys = list(json.loads(canonical_bytes(obj).decode()).keys())
    # RFC 8785 §3.2.3: the emoji (surrogate pair) sorts before U+FB33, where a code-point sort would put it last
    assert keys == ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"]
    assert list(json.loads(legacy_sorted_json_bytes(obj).decode()).keys())[-1] == "\U0001f600", "the legacy encoding sorted by code point"


def test_rfc8785_appendix_b_sample_reproduces():
    s = "".join(map(chr, [0x20AC, 0x24, 0x0F, 0x0A, 0x41, 0x27, 0x42, 0x22, 0x5C, 0x5C, 0x22, 0x2F]))
    sample = {"numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001], "string": s, "literals": [None, True, False]}
    expected = (
        b'{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"'
        + "€".encode() + b'$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    )
    assert canonical_bytes(sample) == expected


@pytest.mark.parametrize("value", [float("nan"), float("inf"), {1: "x"}, {"a": object()}, "\ud800"])
def test_what_has_no_canonical_form_is_refused(value):
    with pytest.raises(NotCanonicalisable):
        canonical_bytes(value)


def test_no_byte_of_the_examples_changed_under_rfc8785():
    """Every object under examples/ digests identically under RFC 8785 and the legacy encoding."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "check_canonical_identity.py"), str(ROOT / "examples")],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 differ" in result.stdout
