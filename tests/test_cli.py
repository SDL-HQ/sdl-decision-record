"""The command line returns the documented exit codes, from a subprocess, not from a call."""

import subprocess
import sys
from pathlib import Path

from conftest import build_run, read_rows, write_rows

ROOT = Path(__file__).resolve().parents[1]


def _run(*args):
    return subprocess.run([sys.executable, "-m", "dr.verify", *args], cwd=ROOT, capture_output=True, text=True)


def test_exit_codes(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    assert _run(str(d), "--registry", str(keys["registry"])).returncode == 0
    assert _run(str(d), "--registry", str(keys["registry"]), "--json").stdout.strip().startswith("{")
    rows = read_rows(d)
    for r in rows:
        r["v"] = 3
    write_rows(d, rows)
    assert _run(str(d), "--registry", str(keys["registry"])).returncode == 1
    (d / "decisions.jsonl").unlink()
    assert _run(str(d), "--registry", str(keys["registry"])).returncode == 2
    (d / "record.json").write_text("{not json")
    assert _run(str(d), "--registry", str(keys["registry"])).returncode == 3
    assert _run(str(tmp_path / "nowhere"), "--registry", str(keys["registry"])).returncode == 3
