"""The header and footer of tests/MUTATIONS.md are what tools/mutate.py writes
for the figures in the table, and the table was generated over the code and
tests in hand.

A full run takes about an hour, so the suite does not regenerate the table.
What is held instead: the prose around the table is the generator's own text
for the figures the table states; the digest in the header is the digest of
the code and tests as they are, so a change to either without regenerating
the table fails here; and the number of tests the header says are left out is
the number those files hold.

Breaking this: edit the header or footer alone, or change code or tests
without regenerating the table.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import mutate  # noqa: E402

TEXT = (ROOT / "tests" / "MUTATIONS.md").read_text(encoding="utf-8")


def _parsed():
    m = re.search(r"whose digest is `(sha256:[0-9a-f]{64})`.*?Baseline: (\d+) tests pass, 0 fail, (\d+) skipped, with .*? \((\d+) tests\)", TEXT, re.S)
    commit, passed, skipped, left = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
    skips = [(int(n), w, why) for n, w, why in re.findall(r"^- (\d+) in `([^`]+)`: (.*)$", TEXT, re.M)]
    rows = [l for l in TEXT.split("\n") if re.match(r"\| M\d+ \|", l)]
    results = []
    for l in rows:
        cells = [c.strip() for c in l.strip("|").split("|")]
        results.append((cells[0], int(cells[3]), mutate.is_control(cells[2])))
    return commit, passed, skipped, left, skips, rows, results


def test_the_prose_is_the_generators_for_these_figures():
    commit, passed, skipped, left, skips, rows, results = _parsed()
    assert TEXT == "\n".join(mutate.head(commit, passed, skipped, left, skips) + rows + mutate.foot(results))


def test_the_skips_listed_add_up_to_the_skips_stated():
    _, _, skipped, _, skips, _, _ = _parsed()
    assert sum(n for n, _, _ in skips) == skipped


def test_the_tests_said_to_be_left_out_are_the_ones_that_file_holds():
    _, _, _, left, _, _, _ = _parsed()
    assert left == mutate.count_left_out()


def test_a_control_is_not_counted_as_caught_or_uncaught():
    line = mutate.foot([("M1", 3, False), ("M2", 0, False), ("M3", 0, True)])[1]
    assert line == "Mutations applied: 3. 1 of 2 caught, 1 uncaught (M2). 1 control: 1 unchanged, as a control must be (M3)."
    loud = mutate.foot([("M1", 3, False), ("M3", 2, True)])[1]
    assert "fault in the harness (M3)" in loud


def test_the_table_was_generated_over_the_code_and_tests_in_hand():
    digest = _parsed()[0]
    assert digest == mutate.measured_digest(), (
        "the code or tests changed since tests/MUTATIONS.md was generated; run python3 tools/mutate.py")
