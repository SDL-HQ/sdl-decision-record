"""Regenerate `reports-without-assurance.json`: what the verifiers printed before
the assurance ladder existed, for the matrix in `MATRIX` below.

Without `--assurance`, every report is meant to be byte-identical to what it
was before the ladder. A test that only checks the flag's absence cannot fail
on an unrequested change to the report. This fixture is the "before": the
verifiers as they were before the ladder, run over the files this repository
carries, recorded as the exit code and the SHA-256 of standard output and
standard error. `tests/test_assurance.py` compares the current verifiers to it.
The source the fixture was generated from predates the ladder and is not part
of this tree; the fixture is kept as the recorded result.

Run from the repository root, given a checkout of the verifiers from before the
ladder:

    python3 tests/fixtures/make_reports_without_assurance.py /path/to/pre-ladder-checkout

The old modules are imported from the given checkout; the files they verify
are this repository's, by relative path, so the reports name the same
directories the test passes. Regenerate only with a decision entry saying
why the reports changed.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = HERE / "reports-without-assurance.json"

REG = ["--registry", "examples/keys/registry.json"]
DEC = ["--decider-registry", "examples/keys/deciders.json"]


def matrix():
    dirs = sorted({str(Path(f).parent) for f in subprocess.run(["git", "-C", str(ROOT), "ls-files", "*record.json"],
                                                               capture_output=True, text=True, check=True).stdout.split()
                   if Path(f).name == "record.json"})
    out = []
    for d in dirs:
        for extra in ([], DEC):
            for fmt in ([], ["--json"]):
                out.append(["dr.verify", d, *REG, *extra, *fmt])
    E = "experiments/rederivability/out"
    for fmt in ([], ["--json"]):
        out.append(["dr.verify", "examples/acceptance/out/record", *REG, *DEC, "--replay", "emitters.toolgate", *fmt])
        out.append(["dr.verify", f"{E}/f5-input-fabricated", "--registry", f"{E}/registry.json", "--decider-registry", f"{E}/deciders.json",
                    "--replay", "emitters.cedar", *fmt])
        for name in ("gated", "fabricated"):
            o = f"examples/acceptance/out/{name}"
            out.append(["tools.verify_arrival", o, "--registry", f"{o}.producer.json", "--decider-registry", f"{o}.decider.json",
                        "--attester-registry", f"{o}.attester.json", "--arrival-log", f"{o}.attester-log.jsonl",
                        "--replay", "emitters.toolgate", *fmt])
    return out


def run(module_name: str, args):
    import importlib
    mod = importlib.import_module(module_name)
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = mod.main(list(args))
    return {"exit": code,
            "stdout_sha256": hashlib.sha256(stdout.getvalue().encode("utf-8")).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr.getvalue().encode("utf-8")).hexdigest()}


def main(argv):
    old = Path(argv[1]).resolve()
    sys.path.insert(0, str(old))  # the old dr/ and tools/ are imported; the files read are this repository's
    import os
    os.chdir(ROOT)
    commit = subprocess.run(["git", "-C", str(old), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    cases = [{"args": m, **run(m[0], m[1:])} for m in matrix()]
    OUT.write_text(json.dumps({"generated_from": commit, "cases": cases}, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(cases)} cases from {commit[:7]} to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main(sys.argv)
