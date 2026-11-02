"""A generated results file carries no date and no timing (SPEC section 7.1's rule).

The stronger check -- re-run the generator and compare -- is in
tests/test_rederive.py and tests/test_the_ladder_reproduces.py where the inputs
allow it; this is the floor under both: the two things that made a generated file move between runs
-- an ISO date and a wall-clock or per-unit timing -- are absent from every
one. A new generated file joins GENERATED and inherits the rule.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GENERATED = (
    "experiments/rederivability/RESULTS.md",
    "experiments/rederivability/LADDER.md",
)
ISO_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
TIMING = re.compile(r"\b\d+(?:\.\d+)?\s?(?:ms|s|seconds?|milliseconds?)\b(?!-)")


def offending(text: str) -> list[str]:
    hits = []
    for n, line in enumerate(text.splitlines(), start=1):
        for pat, what in ((ISO_DATE, "date"), (TIMING, "timing")):
            for m in pat.finditer(line):
                hits.append(f"line {n}: {what} {m.group(0)!r}")
    return hits


@pytest.mark.parametrize("path", GENERATED)
def test_no_date_and_no_timing_in_a_generated_results_file(path):
    hits = offending((ROOT / path).read_text(encoding="utf-8"))
    assert not hits, f"{path} carries what makes a generated file move between runs: {hits}"


def test_the_rule_catches_a_date_and_a_timing():
    assert offending("built on 2026-10-27") == ["line 1: date '2026-10-27'"]
    assert offending("23 cases in 2.3s; 0.18 ms per arrival") == ["line 1: timing '2.3s'", "line 1: timing '0.18 ms'"]
    assert offending("5,677 cases; sha256:d9c8; 40 of 40; seq 24; 45,416 requests") == []
