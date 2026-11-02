"""The acceptance procedure reproduces byte for byte: every verdict in ACCEPTANCE.md was captured, not composed.

Re-runs examples/acceptance/run.sh in a copy of the repository and compares
ACCEPTANCE.md and every file under examples/acceptance/out/ with the
committed ones; any drift fails.
"""

import filecmp
import shutil
import subprocess
import sys
from pathlib import Path

# The scripts call `python3`; run them under the interpreter running this suite, which has
# the dependencies, ahead of a fixed system PATH (on a CI runner /usr/bin/python3 has none).
SCRIPT_PATH = f"{Path(sys.executable).parent}:/usr/bin:/bin:/usr/local/bin"
ROOT = Path(__file__).resolve().parents[1]


def _tree_equal(a: Path, b: Path) -> bool:
    cmp = filecmp.dircmp(a, b)
    if cmp.left_only or cmp.right_only or cmp.diff_files or cmp.funny_files:
        return False
    return all(_tree_equal(a / d, b / d) for d in cmp.common_dirs)


def test_acceptance_procedure_reproduces_byte_for_byte(tmp_path):
    work = tmp_path / "repo"
    for name in ("dr", "emitters", "examples", "experiments", "tools"):
        shutil.copytree(ROOT / name, work / name, ignore=shutil.ignore_patterns("__pycache__", "scratch"))
    shutil.rmtree(work / "examples" / "acceptance" / "out")
    (work / "examples" / "acceptance" / "ACCEPTANCE.md").unlink()
    proc = subprocess.run(["bash", "examples/acceptance/run.sh"], cwd=work, capture_output=True, text=True, env={"PATH": SCRIPT_PATH, "PYTHONDONTWRITEBYTECODE": "1"})
    assert proc.returncode == 0, proc.stderr
    assert (work / "examples" / "acceptance" / "ACCEPTANCE.md").read_text() == (ROOT / "examples" / "acceptance" / "ACCEPTANCE.md").read_text()
    assert _tree_equal(work / "examples" / "acceptance" / "out", ROOT / "examples" / "acceptance" / "out")


def test_every_step_in_the_procedure_names_its_verdict():
    text = (ROOT / "examples" / "acceptance" / "ACCEPTANCE.md").read_text()
    steps = text.count("\n## ")
    assert steps == text.count("VERDICT: ") == text.count("[exit ")
    assert "VERDICT: ESTABLISHED" in text and "VERDICT: FAILED" in text and "VERDICT: NOT ESTABLISHED" in text
