"""The worked example reproduces the committed outputs byte for byte.

The transcript is captured, not written, and the records under examples/out are
what the committed emitters, data and key produce. If either drifts from the
code, this fails. The run happens in a temporary copy so the test writes
nothing into the repository.
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


def test_example_reproduces_committed_outputs(tmp_path):
    work = tmp_path / "repo"
    for name in ("dr", "emitters", "experiments", "examples", "tools"):
        shutil.copytree(ROOT / name, work / name, ignore=shutil.ignore_patterns("__pycache__", "out", "scratch", "TRANSCRIPT.md"))
    proc = subprocess.run(["bash", "examples/run.sh"], cwd=work, capture_output=True, text=True, env={"PATH": SCRIPT_PATH, "PYTHONDONTWRITEBYTECODE": "1"})
    assert proc.returncode == 0, proc.stderr
    assert _tree_equal(work / "examples" / "out", ROOT / "examples" / "out")
    assert (work / "examples" / "TRANSCRIPT.md").read_bytes() == (ROOT / "examples" / "TRANSCRIPT.md").read_bytes()


def test_the_example_needs_no_network_and_no_credentials():
    src = (ROOT / "examples" / "run.sh").read_text()
    for word in ("curl", "wget", "http://", "https://", "pip install", "TOKEN", "API_KEY"):
        assert word not in src, word
