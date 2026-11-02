"""Canonical bytes and digests. Everything hashed or signed goes through here.

One encoding, stated once: RFC 8785 (JSON Canonicalization Scheme), which is
UTF-8 JSON with no whitespace, object members sorted by the UTF-16 code units
of their names, numbers rendered as ECMAScript renders them, and non-ASCII
left as the characters themselves. A verifier rebuilds these bytes from the
parsed object, so reformatting a file on disk changes nothing and changing a
value changes everything.

``legacy_sorted_json_bytes`` is ``json.dumps(sort_keys=True,
separators=(",", ":"), ensure_ascii=False)``, the format's first encoding.
It agrees with RFC 8785 on every document this repository carries (ASCII
member names, integers, strings, booleans, null) and disagrees on two things
none of them contains: member names outside the Basic Multilingual Plane,
which Python sorts by code point and JCS sorts by UTF-16 code unit, and
floating-point numbers, which Python renders as ``repr`` and JCS as ECMAScript
``Number::toString``. It is kept so that the agreement can be re-checked:
every record, row, input and receipt under ``examples/`` digests identically
under both functions, and a test holds it.

What is rejected rather than canonicalised: NaN and infinities (RFC 8785
§3.2.2.3 has no representation for them), non-string member names, and
strings containing lone surrogates (they cannot be encoded as UTF-8).
"""

from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal
from typing import Any

DIGEST_PREFIX = "sha256:"

# The largest integer magnitude an IEEE 754 double represents exactly. RFC 8785
# numbers are doubles; an int beyond this is rendered the way ECMAScript would
# render the double nearest to it.
_MAX_SAFE_INTEGER = 2**53

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class NotCanonicalisable(ValueError):
    """The object has no RFC 8785 serialisation."""


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number_from_decimal_digits(negative: bool, digits: str, point: int) -> str:
    """ECMAScript Number::toString over the shortest round-trip digits.

    ``digits`` are the significant decimal digits with no leading zeros and
    ``point`` is the position of the decimal point relative to them, so the
    value is 0.<digits> * 10**point. Follows ECMA-262 Number::toString steps
    for k (digit count) and n (point).
    """
    k = len(digits)
    n = point
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        sign = "+" if e >= 0 else "-"
        mant = digits[0] if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mant}e{sign}{abs(e)}"
    return ("-" + body) if negative else body


def _float(x: float) -> str:
    if math.isnan(x) or math.isinf(x):
        raise NotCanonicalisable("NaN and infinities have no RFC 8785 representation")
    if x == 0:
        return "0"  # ECMAScript renders -0 as "0"
    d = Decimal(repr(x))  # repr is the shortest round-trip form, as in ECMAScript
    sign, mantissa, exponent = d.as_tuple()
    digits = "".join(str(i) for i in mantissa).lstrip("0") or "0"
    stripped = digits.rstrip("0")
    exponent += len(digits) - len(stripped)
    digits = stripped
    return _number_from_decimal_digits(bool(sign), digits, exponent + len(digits))


def _int(i: int) -> str:
    if -_MAX_SAFE_INTEGER <= i <= _MAX_SAFE_INTEGER:
        return str(i)
    try:
        return _float(float(i))
    except OverflowError:  # an integer past a double's range has no RFC 8785 rendering
        raise NotCanonicalisable(f"the integer {str(i)[:24]}… ({len(str(abs(i)))} digits) is past a double's range and has no RFC 8785 representation") from None


def _serialise(obj: Any, out: list) -> None:
    if obj is None:
        out.append("null")
    elif obj is True:
        out.append("true")
    elif obj is False:
        out.append("false")
    elif isinstance(obj, int):
        out.append(_int(obj))
    elif isinstance(obj, float):
        out.append(_float(obj))
    elif isinstance(obj, str):
        out.append(_string(obj))
    elif isinstance(obj, (list, tuple)):
        out.append("[")
        for i, item in enumerate(obj):
            if i:
                out.append(",")
            _serialise(item, out)
        out.append("]")
    elif isinstance(obj, dict):
        for k in obj:
            if not isinstance(k, str):
                raise NotCanonicalisable(f"object member names must be strings, got {type(k).__name__}")
        out.append("{")
        for i, k in enumerate(sorted(obj, key=lambda s: s.encode("utf-16-be"))):
            if i:
                out.append(",")
            out.append(_string(k))
            out.append(":")
            _serialise(obj[k], out)
        out.append("}")
    else:
        raise NotCanonicalisable(f"no JSON representation for {type(obj).__name__}")


def canonical_bytes(obj: Any) -> bytes:
    out: list = []
    _serialise(obj, out)
    try:
        return "".join(out).encode("utf-8")
    except UnicodeEncodeError as exc:  # lone surrogates
        raise NotCanonicalisable(str(exc)) from exc


class NotJSON(ValueError):
    """Text Python's json module accepts and the canonical form cannot render,
    or that two readers can read differently: the bare constants NaN, Infinity
    and -Infinity, which RFC 8259 does not allow; numbers past a double's range
    (`1e400`, or an integer written out in more digits than a double holds);
    lone surrogates; and duplicate member names — the last three allowed by
    RFC 8259's grammar and forbidden by I-JSON (RFC 7493), the profile RFC 8785
    requires. None has a single canonical meaning, so a
    document carrying one could not be hashed, and a reader that let it through
    deferred the refusal to whichever check hashed it first, where it read as
    that check's failure (a stream link, a fork that vanished, an unreadable
    run). Refused where the document is read, as the reader's error."""


def _refuse_constant(name: str) -> Any:
    raise NotJSON(f"{name} is not JSON (RFC 8259) and has no canonical form")


def _refuse_lone_surrogates(obj: Any) -> None:
    # json.loads joins a valid escaped pair into one character, so a surrogate
    # code point still present after parsing is a lone one.
    if isinstance(obj, str):
        if any("\ud800" <= ch <= "\udfff" for ch in obj):
            raise NotJSON("a lone surrogate is not I-JSON (RFC 7493 §2.1) and has no canonical form (RFC 8785 requires I-JSON)")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _refuse_lone_surrogates(k)
            _refuse_lone_surrogates(v)
    elif isinstance(obj, list):
        for v in obj:
            _refuse_lone_surrogates(v)


def _reader_parse_float(text: str) -> float:
    value = float(text)
    if math.isinf(value):  # 1e400: the float parser overflows to infinity without the constant hook
        raise NotJSON(f"the number {text[:24]} overflows a double and has no canonical form")
    return value


def _reader_parse_int(text: str) -> int:
    value = int(text)
    try:
        float(value)
    except OverflowError:  # integer digits past a double's range: no canonical rendering
        raise NotJSON(f"the integer {text[:24]}… ({len(text.lstrip('-'))} digits) is past a double's range and has no canonical form") from None
    return value


def _refuse_duplicate_names(pairs) -> dict:
    # I-JSON (RFC 7493 §2.3) forbids duplicate member names. Parsers disagree on
    # them (first wins, last wins, refuse), so two readers of the same bytes can
    # see two different values under one digest: a seam, refused where it is read.
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise NotJSON(f"the member name {k!r} appears twice in one object; I-JSON (RFC 7493 §2.3) forbids it and parsers disagree on which value wins")
        out[k] = v
    return out


def _as_text(text: Any) -> str:
    """The document as text. Bytes are decoded as UTF-8 and nothing else, so a
    byte-order mark stays in the text and is refused there. Python's
    `json.loads` given bytes would detect UTF-16 and UTF-32 and drop a leading
    BOM, so the attester given the bytes an input arrived as would accept what
    the gate, reading the same bytes as UTF-8, refuses."""
    if isinstance(text, (bytes, bytearray, memoryview)):
        return bytes(text).decode("utf-8")  # UnicodeDecodeError is a ValueError: not UTF-8, not read
    if not isinstance(text, str):
        raise TypeError(f"a document is text or UTF-8 bytes, not {type(text).__name__}")
    return text


def loads(text: str) -> Any:
    """`json.loads`, refusing what is not I-JSON: the bare constants (not JSON at
    all), numbers past a double's range, lone surrogates and duplicate member
    names. After this, the canonicaliser rejects nothing a format reader
    accepts, and no two conforming readers see different values in a document
    this one accepts. Held by `tests/test_not_json_is_refused_where_read.py`.
    Every format reader uses this."""
    obj = json.loads(_as_text(text), parse_constant=_refuse_constant, parse_float=_reader_parse_float, parse_int=_reader_parse_int, object_pairs_hook=_refuse_duplicate_names)
    _refuse_lone_surrogates(obj)
    return obj


# JSON's own whitespace (RFC 8259 §2). Nothing else is: U+2028, U+2029 and
# U+0085 may stand unescaped inside a JSON string, and RFC 8785 writes them so.
_JSON_WHITESPACE = " \t\r\n"


def jsonl_lines(text: str):
    """The lines of a JSON Lines file, as (line number, text): split on LF
    (U+000A) and on nothing else, skipping lines that are empty or JSON
    whitespace only. A CR before the LF is JSON whitespace and is left for the
    parser. Python's `str.splitlines` also splits on U+2028, U+2029, U+0085 and
    a lone CR, the first three legal unescaped inside a JSON string and
    written literally by this format's own writer, so a reader using it broke
    an honest line in two, and two readers of one file counted different lines
    (SEAMS.md, line terminators). Every format reader splits with this."""
    return [(n, line) for n, line in enumerate(text.split("\n"), start=1) if line.strip(_JSON_WHITESPACE)]


def read_jsonl(path) -> list:
    """`jsonl_lines` over a file, read as bytes and decoded as UTF-8. Not
    `read_text`: Python's text mode turns a lone CR into LF before any splitter
    sees it, which ends a line inside a row that carries a CR as JSON
    whitespace between its tokens."""
    with open(path, "rb") as f:
        return jsonl_lines(f.read().decode("utf-8"))


def _input_parse_float(text: str) -> float:
    value = _reader_parse_float(text)
    if Decimal(text) != Decimal(_float(value)):
        raise NotAnInput(
            f"the number {text[:32]} is not the number its canonical bytes spell: a double reads it as {_float(value)}, "
            f"so its digest also stands for {_float(value)}, and a reader that keeps every digit (OPA, Go's json.Number) "
            "decides a different number; not an input")
    return value


def loads_input(text: str) -> Any:
    """`loads` for text that carries an input, which additionally refuses a
    number whose spelling denotes a different value from the one its canonical
    bytes denote: more digits than a double holds (`1.00000000000000001`
    reads as 1) or a magnitude a double cannot hold (`1e-400` reads as 0). Its
    digest is the digest of the double's value, and a party that reads the
    same text keeping every digit decides another number under that digest:
    equal digests and unequal decisions, for numbers with a fraction or an
    exponent. Other spellings of
    the same value (`1E2`, `100.0`, `1.0e2`) are accepted: they spell exactly
    the value the canonical bytes do. Integers past ±(2**53 - 1), whose
    canonical bytes also spell their neighbours, are refused by
    `canonical_input`, as before. Documents are read with `loads`; this is
    the input's reader, as `canonical_input` is the input's value."""
    obj = json.loads(_as_text(text), parse_constant=_refuse_constant, parse_float=_input_parse_float, parse_int=_reader_parse_int, object_pairs_hook=_refuse_duplicate_names)
    _refuse_lone_surrogates(obj)
    return obj


# The largest integer magnitude whose canonical rendering names it alone: past
# this, two integers render as the same double (2**53 + 1 renders as 2**53).
# Number.MAX_SAFE_INTEGER; RFC 7493 (I-JSON) §2.2.
MAX_INPUT_INTEGER = 2**53 - 1


class NotAnInput(NotCanonicalisable):
    """The object's canonical bytes do not determine it, so a digest over them
    could stand for a different value than the one decided."""


def _refuse_unsafe_integers(obj: Any, where: str = "input") -> None:
    if isinstance(obj, bool) or obj is None:
        return
    if isinstance(obj, int):
        if not -MAX_INPUT_INTEGER <= obj <= MAX_INPUT_INTEGER:
            raise NotAnInput(f"{where} is the integer {obj}, beyond \u00b1(2**53 - 1); its canonical bytes also stand for other integers")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _refuse_unsafe_integers(v, f"{where}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _refuse_unsafe_integers(v, f"{where}[{i}]")


def _parse_int(text: str) -> Any:
    i = int(text)
    # Text this long can only be a double's rendering (integers that long are
    # refused above), so it is read back as the double it renders.
    return i if -MAX_INPUT_INTEGER <= i <= MAX_INPUT_INTEGER else float(text)


def canonical_input(obj: Any) -> Any:
    """The value an input's digest covers: its canonical bytes, read back.

    Equal digests must mean equal decisions, and a decider has its own type
    model: `{"order_id": 396}` and `{"order_id": 396.0}` have one canonical form
    and one digest, and a decider that checks for an integer decides them
    differently. So every party that decides an input decides this value
    instead (the gate before deciding, replay before re-deciding, the attester
    before signing): two inputs with equal canonical bytes become the same
    value, and any deterministic decider then decides them the same way. The
    cost is that a decider cannot tell 396 from 396.0, which for a format that
    identifies inputs by digest is the correct behaviour.

    Refused (NotAnInput): an integer beyond +/-(2**53 - 1), whose canonical
    bytes also stand for its neighbours. `canonical_bytes` itself is unchanged
    and still renders such an integer as RFC 8785 does, so no digest moves and
    the conformance corpora that carry 64-bit values in their own data are
    unaffected; the refusal is of an *input*, not of a document."""
    _refuse_unsafe_integers(obj)
    return json.loads(canonical_bytes(obj).decode("utf-8"), parse_int=_parse_int)


def same_value(a: Any, b: Any) -> bool:
    """Structural equality that also compares number types: 396 is not 396.0."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(same_value(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same_value(x, y) for x, y in zip(a, b))
    return a == b


def legacy_sorted_json_bytes(obj: Any) -> bytes:
    """The pre-19-October encoding, kept so the byte-identity check can be re-run."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest_bytes(data: bytes) -> str:
    return DIGEST_PREFIX + hashlib.sha256(data).hexdigest()


def digest_obj(obj: Any) -> str:
    return digest_bytes(canonical_bytes(obj))


def digest_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return DIGEST_PREFIX + h.hexdigest()


def is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(DIGEST_PREFIX)
        and len(value) == len(DIGEST_PREFIX) + 64
        and all(c in "0123456789abcdef" for c in value[len(DIGEST_PREFIX):])
    )
