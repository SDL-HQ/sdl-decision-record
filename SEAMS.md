# Seams

A **seam** is a place where two parties have to agree on what a value is and
can silently disagree. The format identifies an input by the digest of its
canonical bytes (SPEC §2). That only means something if every party reading
those bytes reads one value: the reader, the canonicaliser, the gate's command
line, the attester, replay and re-derivation, and any engine an input crosses
into. If two parties read two values under one digest, the chain, the
signature and the arrival can all establish over a decision that was made on a
different value from the one the record names.

This table takes the known classes of JSON interoperability trouble, a fixed
list, and records how each party here treats each class. A row is in one of
three states:

- **refused**: every party here refuses it, with its own reason, where the
  text is read;
- **pinned**: every party provably reads one value;
- **open**: neither of those, stated with why.

Each row has tests in `tests/test_seams.py`. The engines' own parsers (Cedar
through `cedarpy`, Go's `encoding/json` as OPA uses it, and OPA 1.21.3 itself)
are probed there too, where they are installed; CI has all three.

| # | class | example | here | an engine reading the text itself | state |
|---|---|---|---|---|---|
| 1 | duplicate member names | `{"a": 1, "a": 2}` | refused by the reader, the gate's command line and `Attester.arrive_text` | Go keeps the last; other parsers keep the first or refuse | **refused** |
| 2 | numeric overflow | `1e400`, a 400-digit integer | refused by the reader, the gate's command line and the attester | Go as `float64` refuses `1e400`; Go with `UseNumber`, as OPA reads, keeps it | **refused** |
| 3 | integers past ±(2^53 − 1) | `9007199254740993` | a document may carry one, rendered as RFC 8785 renders it; as an input, refused by the gate, the attester and replay | OPA and Cedar keep it exactly; its canonical bytes also stand for 9007199254740992 | **refused as an input** |
| 4 | negative zero | `-0`, `-0.0`, `-0e0` | canonical bytes `0`; decided, signed and replayed as the integer 0 | Cedar refuses `-0.0` as a float and decides the canonical 0; OPA: `-0.0 == 0` | **pinned** |
| 5 | Unicode normalisation | `Zürich` precomposed vs decomposed | no party normalises: two forms, two canonical byte strings, two digests, retained as received | Cedar and OPA compare code points | **pinned** |
| 6 | byte-order mark | `EF BB BF` before a document | refused by the reader, the gate's command line and the attester, as text or as bytes: bytes are decoded as UTF-8 only | Go refuses | **refused** |
| 7 | trailing content | `{"a": 1} {"b": 2}`, `{"a": 1}x` | refused; trailing JSON whitespace is whitespace | Go's `Unmarshal` refuses; a streaming `Decoder` reads the first document and stops | **refused** |
| 8 | number spellings | `100`, `1E2`, `100.0`, `1.0e2`, `10000e-2` | one value, one digest, one decision. A spelling of a number its canonical bytes do not spell (`1.00000000000000001`, `1e-400`, `0.30000000000000001`) is refused as an input. Spellings outside the grammar (`01`, `+1`, `.5`, `1.`, `0x10`) are refused by every reader | OPA keeps every digit: `1.00000000000000001 == 1` is false there, and its digest is the digest of `1` | **pinned**; excess precision **refused as an input** |
| 9 | escaped vs literal characters | `"r"` vs `"r"`; U+2028, U+2029, U+0085 inside a string; CR between tokens | an escape and its character are one value. A line of JSON Lines ends at LF and nowhere else, read from bytes, so a character that may stand unescaped in a string never ends a line | Go's line scanner splits on LF | **pinned** |

## The rows, with what was wrong before

**1. Duplicate member names.** The reader already refused them. The gate's
command line did not: it read its inputs file with Python's own parser. It
decided `{"order_id": 1, "order_id": "x"}` as the string (DENY, `arg_type`), and
the record verified with exit 0. A party that keeps the first value reads an
integer that the gate allows. Every input path now uses the reader.

**2. Numeric overflow.** The reader already refused it. The gate's command
line crashed with a traceback (`NotCanonicalisable`), and now refuses with the
reader's reason.

**3. Integers past ±(2^53 − 1).** Unchanged. Recorded here because the
row is on the list.

**4. Negative zero.** RFC 8785 renders −0 as `0`, and `canonical_input` reads
`0` back as the integer 0, so every party decides 0. Cedar shows why this has
to happen before the engine is called: given the raw `-0.0` it refuses the
request, because Cedar has no floats, and given the canonical value it decides.

**5. Unicode normalisation.** Nothing here normalises, and nothing should.
RFC 8785 does not normalise, both engines compare code points, and the two
forms have different digests. A normalisation somewhere between two parties
therefore shows up as an arrival or replay that fails, never as equal digests
over different text. Whether a policy should treat the two forms as one city
is a question for the policy's author, not for the format.

**6, 7. Byte-order marks and trailing content.** Refused by every reader here.
Before, the gate's command line refused them with a traceback. The reader and
the attester's `arrive_text` also take bytes, and they once handed
bytes straight to Python's `json.loads`. That drops a leading BOM from bytes
and detects UTF-16 and UTF-32, so the attester given the bytes an input arrived
as signed what the gate, reading the same bytes as UTF-8, refuses. Bytes are
now decoded as UTF-8 and nothing else, so the BOM stays in the text and is
refused there.

**8. Number spellings.** Spellings of one value already were one input.
What was not: a spelling that denotes a different number from the one its
canonical bytes denote. `1.00000000000000001` was decided as the integer 1 and
allowed. Its digest is the digest of `1`, and OPA, reading the same text, keeps
every digit and decides a different number. This is the same class again, for
numbers with a fraction or an exponent. An input number is now refused unless
the decimal value it spells is the decimal value its canonical bytes spell
(`dr.canonical.loads_input`). Spellings of the same value, such as `1E2` and
`100.0`, still pass. A document may still carry such a number; its digest
covers the double, as RFC 8785 says.

**9. Escaped and literal characters, and what ends a line.** An escape and the
character it names are one value to every reader. The defect was the line.
RFC 8785 writes U+2028, U+2029 and U+0085 unescaped, and so does this format's
writer. Python's `str.splitlines` ends a line at all three, and four of the
format's readers used it. So an honest record whose input carried U+2028,
escaped or not when it arrived, failed `retained` and the verifier exited 2. The
ledger reader iterated the file in text mode, which ends a line at a lone CR,
and a CR between a row's tokens is JSON whitespace. Every reader now splits
JSON Lines on LF and on nothing else, from bytes (`dr.canonical.read_jsonl`).

## What this table does not cover

The list is fixed, and anything outside it goes to a second list. On that
second list, unprobed: numbers inside strings that an
engine parses (Cedar's `decimal`, durations and IP addresses); key ordering
and depth limits in engines; text that is not UTF-8 reaching an engine through
a path other than this format's readers; and any parser an integrator uses
before calling `Attester.arrive`. `arrive(obj)` takes a value someone else
parsed, and that parser is theirs. `arrive_text(text)` reads the bytes the way
the gate does.
