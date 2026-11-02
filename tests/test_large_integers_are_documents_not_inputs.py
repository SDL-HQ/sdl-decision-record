"""Integers beyond +/-(2**53 - 1) are refused as inputs, never as documents.

Such an integer is refused as an *input*, because its canonical bytes also
stand for its neighbours, and leaves `canonical_bytes` exactly as RFC 8785 has
it. The reason given for not refusing inside `canonical_bytes` was measured
by hand against two corpora that are fetched, not vendored: the pinned Cedar
corpus carries 780 such integers in 235 files and OPA's pinned testdata 31 in
15, and `opa_conformance` runs result sets through `canonical_bytes`. This file
holds those claims so they are not checked once and by nothing since:

- without either corpus, the consequence: a result set carrying 2**63 is
  normalised and digested by the OPA conformance decider's own functions;
- with the corpus present (CI fetches both at their pins), the figures
  themselves, and every OPA case carrying one through the decider's own
  comparison path.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dr.canonical import MAX_INPUT_INTEGER, NotAnInput, canonical_bytes, canonical_input  # noqa: E402
from emitters import opa_conformance  # noqa: E402


def _large(x, out):
    if isinstance(x, bool):
        return
    if isinstance(x, int) and abs(x) > MAX_INPUT_INTEGER:
        out.append(x)
    elif isinstance(x, dict):
        for v in x.values():
            _large(v, out)
    elif isinstance(x, list):
        for v in x:
            _large(v, out)


def _count(root: Path, suffixes, load):
    files = values = 0
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix not in suffixes:
            continue
        try:
            docs = load(p)
        except Exception:
            continue
        found = []
        for d in docs:
            _large(d, found)
        if found:
            files += 1
            values += len(found)
    return files, values


def test_a_result_set_carrying_a_64_bit_integer_is_still_compared():
    """The consequence, needing neither corpus nor binary: a document carrying
    2**63 is normalised and digested, while the same value as an input is refused."""
    bindings = [{"x": 2**63, "y": [-(2**63), 1]}, {"x": 1496455200000000000}]
    norm = opa_conformance.normalise_result_set(bindings, sort_bindings=True, ignore_generated=False)
    assert len(norm) == 2
    assert opa_conformance.result_digest(norm).startswith("sha256:")
    assert canonical_bytes(2**63) == b"9223372036854776000"  # RFC 8785's rendering, unchanged
    with pytest.raises(NotAnInput):
        canonical_input({"x": 2**63})


CEDAR = os.environ.get("CEDAR_DRT_ROOT")
OPA = os.environ.get("OPA_TESTDATA_ROOT")


@pytest.mark.skipif(not CEDAR, reason="set CEDAR_DRT_ROOT to the fetched Cedar corpus (tools/fetch_cedar_drt.py)")
def test_the_cedar_corpus_carries_the_integers_d96_says_it_does():
    assert _count(Path(CEDAR), {".json"}, lambda p: [json.loads(p.read_text(encoding="utf-8"))]) == (235, 780)


@pytest.mark.skipif(not OPA, reason="set OPA_TESTDATA_ROOT to the fetched OPA testdata (tools/fetch_opa_testdata.py)")
def test_the_opa_testdata_carries_the_integers_d96_says_it_does_and_each_is_compared():
    import yaml
    root = Path(OPA)
    assert _count(root, {".yaml", ".yml"}, lambda p: list(yaml.safe_load_all(p.read_text(encoding="utf-8")))) == (15, 31)
    compared = 0
    for p in sorted(root.rglob("*.yaml")):
        cases = opa_conformance.jsonify(yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("cases", [])
        for case in cases:
            found = []
            _large(case.get("want_result"), found)
            if found:
                opa_conformance.normalise_result_set(case["want_result"], bool(case.get("sort_bindings")), bool(case.get("ignore_generated_vars")))
                compared += 1
    assert compared > 0
