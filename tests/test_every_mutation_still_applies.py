"""Every mutation in tools/mutate.py still names code that exists.

A mutation is a literal substitution, so when the code it targets is
rewritten the mutation stops applying, and the harness stops at it. Without
this, a stale mutation is found only when the table is next regenerated. This
holds each target to exactly one occurrence.

Breaking this: reword a line a mutation targets without updating the mutation.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import mutate  # noqa: E402


@pytest.mark.parametrize("m", mutate.MUTATIONS, ids=[m.id for m in mutate.MUTATIONS])
def test_the_mutation_target_occurs_exactly_once(m):
    assert (ROOT / m.file).read_text(encoding="utf-8").count(m.old) == 1


def test_the_harness_reads_failures_and_skips_from_pytest():
    """`-rs` alone replaces pytest's default `-rfE`, and the FAILED lines the
    harness counts disappear: every mutation then reads as uncaught."""
    import inspect
    src = inspect.getsource(mutate.run_suite)
    assert '"-rfEs"' in src


def test_the_harness_refuses_a_suite_that_did_not_run(tmp_path, monkeypatch):
    """A collection error exits pytest with 2 and prints ERROR lines, not
    FAILED lines. Read as zero failures, it passed a baseline that ran no test
    and reported a mutation that broke an import as uncaught. The harness now
    refuses to measure anything from such a run."""
    import pytest as _pytest
    (tmp_path / "test_bad.py").write_text("def invalid syntax\n", encoding="utf-8")
    monkeypatch.setattr(mutate, "ROOT", tmp_path)
    monkeypatch.setattr(mutate, "LEFT_OUT", ())
    with _pytest.raises(SystemExit) as e:
        mutate.run_suite()
    assert "did not run to a result" in str(e.value) and "exit 2" in str(e.value)
