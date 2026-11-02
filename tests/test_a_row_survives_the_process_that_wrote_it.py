"""A decision that was made is on disk before decide() returns.

Rows written to a buffered handle, with the record signed only at close(),
would let an abort that skipped cleanup take every row still in the buffer
with it, on the order of twenty decisions, with no key needed to lose them.
The measurement here is the abort itself: a child process
writes rows and leaves by os._exit, which runs no cleanup, and the parent reads
what is on disk afterwards.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dr.emit import DURABILITY, LEDGER_FILE, Run  # noqa: E402
from emitters import toolgate  # noqa: E402

from conftest import TOOL_POLICY  # noqa: E402

CHILD = """
import os, sys
sys.path.insert(0, {root!r})
from dr.emit import Run
from emitters import toolgate
run = Run({d!r}, decider_id="toolgate", decider_version="1.0.0", outcomes=toolgate.OUTCOMES,
          policy={policy!r}, durability={tier!r}, record_id="r1",
          decider_key_id={dk!r}, decider_private_key_pem={dpem!r})
for i in range({n}):
    run.decide({{"tool": "get_weather", "args": {{"city": "Auckland"}}}}, "ALLOW", None, ts="2026-10-26T00:00:00Z")
os._exit(0)
"""


def rows_on_disk(d: Path, name: str = LEDGER_FILE) -> list:
    p = d / name
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def abort_after(d: Path, tier: str, n: int, *, attest: bool = False) -> None:
    dk = dpem = None
    if attest:
        from dr.signing import generate_private_key_pem

        dk, dpem = "dk1", generate_private_key_pem()
    code = CHILD.format(root=str(ROOT), d=str(d), policy=TOOL_POLICY, tier=tier, n=n, dk=dk, dpem=dpem)
    subprocess.run([sys.executable, "-c", code], check=True, capture_output=True)


def test_the_tiers_are_the_three_the_docstring_names(tmp_path):
    assert DURABILITY == ("none", "flush", "fsync")
    with pytest.raises(ValueError):
        Run(tmp_path / "x", decider_id="toolgate", decider_version="1.0.0", outcomes=toolgate.OUTCOMES, policy=TOOL_POLICY, durability="sometimes")


def test_without_the_fix_an_abort_takes_the_buffered_rows(tmp_path):
    """The defect, kept measurable: at the "none" tier a single row never
    reaches the file, and a run of 500 leaves a multiple of the buffer behind."""
    abort_after(tmp_path / "one", "none", 1)
    assert rows_on_disk(tmp_path / "one") == []
    abort_after(tmp_path / "many", "none", 500)
    survived = len(rows_on_disk(tmp_path / "many"))
    assert 0 < survived < 500, survived


@pytest.mark.parametrize("tier", ["flush", "fsync"])
def test_every_decided_row_is_on_disk_after_an_abort(tmp_path, tier):
    d = tmp_path / tier
    abort_after(d, tier, 500, attest=True)
    rows = rows_on_disk(d)
    assert len(rows) == 500
    assert [r["seq"] for r in rows] == list(range(1, 501))
    # The retained files that travel with the ledger are kept in step: an input
    # and an attestation per row, no more and no fewer.
    assert len(rows_on_disk(d, "inputs.jsonl")) == 500
    assert len(rows_on_disk(d, "attestations.jsonl")) == 500


def test_the_default_is_flush(tmp_path):
    run = Run(tmp_path / "r", decider_id="toolgate", decider_version="1.0.0", outcomes=toolgate.OUTCOMES, policy=TOOL_POLICY)
    assert run.durability == "flush"
    run.decide({"tool": "get_weather", "args": {"city": "Auckland"}}, "ALLOW", None)
    # Visible to another reader of the file before close(), in this process.
    assert len(rows_on_disk(tmp_path / "r")) == 1
