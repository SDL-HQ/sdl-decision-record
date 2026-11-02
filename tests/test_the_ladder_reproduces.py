"""The forgery table one rung up reproduces byte for byte (SPEC section 16).

`experiments/rederivability/LADDER.md` is what `ladder.py` writes: the five
forgeries rebuilt with an attester in front. No date and no timing is written
into it, so a reader who runs the script gets a clean tree, and a figure in it
that moved is drift. Same rule as `tests/test_rederive.py` holds for the
rederivability results.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXP = ROOT / "experiments" / "rederivability"

pytest.importorskip("cedarpy")


@pytest.mark.parametrize("script,output", [("ladder.py", "LADDER.md")])
def test_the_committed_results_are_what_the_script_writes(tmp_path, script, output):
    before = (EXP / output).read_text()
    try:
        r = subprocess.run([sys.executable, str(EXP / script), "--out", str(tmp_path / "out")],
                           capture_output=True, text=True, cwd=ROOT)
        assert r.returncode == 0, r.stderr[-2000:]
        after = (EXP / output).read_text()
    finally:
        (EXP / output).write_text(before)
    assert after == before, f"{output} drifted from what {script} writes"
    assert "timing (not committed)" in r.stderr
