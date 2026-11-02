"""The second-implementer instrument: its exclusions hold, and its figure reproduces.

`experiments/spec_sufficiency/verifier.py` is a verifier written from `SPEC.md` alone,
and the whole value of its result rests on two exclusions. Both are tested by attempting
them rather than asserted in a comment:

  - the reference implementation cannot be imported on that path;
  - the corpus's expected states cannot be opened during a run.

The third test re-runs it over the corpus and compares the output byte for byte with
`results.jsonl` as committed, so the measurement in `RESULTS.md` cannot drift from the
code that produced it. The fourth holds the citation audit: every rule in the
implementation names the sentence of `SPEC.md` that licenses it, and a rule whose licence
has left the specification fails here.

Breaking these: import `dr` from the verifier; read an `expected.json` in it; change a
rule without regenerating `results.jsonl`; reword a cited sentence in `SPEC.md`.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "experiments" / "spec_sufficiency" / "verifier.py"
COMMITTED = ROOT / "experiments" / "spec_sufficiency" / "results.jsonl"
CORPUS = ROOT / "conformance" / "verifier"


def _run(code: str) -> subprocess.CompletedProcess:
    """In a subprocess, because the blocker and the open() guard are process-wide."""
    return subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, cwd=ROOT)


def test_the_reference_implementation_cannot_be_imported_on_this_path():
    r = _run(
        "import importlib.util as u, sys\n"
        f"s = u.spec_from_file_location('v', {str(TOOL)!r}); m = u.module_from_spec(s); s.loader.exec_module(m)\n"
        "for name in ('dr', 'dr.verify', 'emitters.cedar', 'tools.rederive'):\n"
        "    try:\n"
        "        __import__(name)\n"
        "    except m.ReferenceCodeBlocked:\n"
        "        continue\n"
        "    raise SystemExit(f'{name} was importable')\n"
        "print('all blocked')\n"
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "all blocked" in r.stdout


def test_the_expected_states_cannot_be_opened_during_a_run():
    case = next(p for p in sorted((CORPUS / "cases").iterdir()) if (p / "expected.json").exists())
    r = _run(
        "import importlib.util as u\n"
        f"s = u.spec_from_file_location('v', {str(TOOL)!r}); m = u.module_from_spec(s); s.loader.exec_module(m)\n"
        "try:\n"
        f"    open({str(case / 'expected.json')!r})\n"
        "except PermissionError as exc:\n"
        "    assert 'expected states may not be read' in str(exc), str(exc)\n"
        "    print('refused')\n"
        "else:\n"
        "    raise SystemExit('an expected.json was opened')\n"
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "refused" in r.stdout


def _pinned() -> bool:
    """Is SPEC.md still the revision this measurement was taken against?"""
    r = _run(
        "import importlib.util as u, pathlib\n"
        f"s = u.spec_from_file_location('v', {str(TOOL)!r}); m = u.module_from_spec(s); s.loader.exec_module(m)\n"
        f"print(m.spec_digest(pathlib.Path({str(ROOT / 'SPEC.md')!r})) == m.MEASURED_AGAINST)\n"
    )
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout.strip() == "True"


def test_every_rule_cites_a_sentence_that_is_in_the_specification():
    """Scoped to the pinned revision: once SPEC.md moves, the refusal is the guarantee.

    The audit's claim is about the text the rules were written from. It cannot be
    about a later SPEC.md, because nothing re-read it — so after a correction the
    citations are expected to drift and the digest guard is what protects the
    result from being re-run as though they had not.
    """
    if not _pinned():
        return  # covered by test_a_changed_specification_refuses_to_re_run
    r = _run(
        "import importlib.util as u, pathlib\n"
        f"s = u.spec_from_file_location('v', {str(TOOL)!r}); m = u.module_from_spec(s); s.loader.exec_module(m)\n"
        f"missing = m.audit_citations(pathlib.Path({str(ROOT / 'SPEC.md')!r}))\n"
        "print(len(m.CITES), missing)\n"
    )
    assert r.returncode == 0, r.stdout + r.stderr
    count, missing = r.stdout.strip().split(" ", 1)
    assert missing == "[]", f"rules citing text absent from SPEC.md: {missing}"
    assert int(count) > 50


def test_the_committed_result_reproduces_byte_for_byte(tmp_path):
    if not _pinned():
        return  # covered by test_a_changed_specification_refuses_to_re_run
    out = tmp_path / "results.jsonl"
    r = subprocess.run(
        [sys.executable, "-I", str(TOOL), "--corpus", str(CORPUS), "--out", str(out)],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert out.read_bytes() == COMMITTED.read_bytes(), "the run no longer reproduces the committed results.jsonl"


def test_a_changed_specification_refuses_to_re_run(tmp_path):
    """A second-implementer figure is bound to the revision it read.

    The rules were written by a reader who had not seen the reference. That
    reader has since seen it, so re-running them against a corrected SPEC.md
    measures consistent editing and not sufficiency. The run refuses at exit 5
    rather than quietly producing a better-looking number, and the committed
    result stays as the dated finding.

    Breaking this: drop the digest guard, or re-point MEASURED_AGAINST at a
    revision nobody read blind.
    """
    if _pinned():
        return  # nothing to refuse while the specification is unchanged
    out = tmp_path / "results.jsonl"
    r = subprocess.run(
        [sys.executable, "-I", str(TOOL), "--corpus", str(CORPUS), "--out", str(out)],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert r.returncode == 5, f"expected a refusal at exit 5, got {r.returncode}: {r.stderr}"
    assert "not a second measurement" in r.stderr
    assert not out.exists(), "a refused run wrote output"
    assert len(COMMITTED.read_text().strip().splitlines()) == 47


def test_the_committed_result_is_the_figure_RESULTS_states():
    lines = [json.loads(l) for l in COMMITTED.read_text().splitlines() if l.strip()]
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    assert len(lines) == len(manifest["cases"]) == 47
    mine = {l["case"]: l for l in lines}
    agree = verdicts = 0
    for case in manifest["cases"]:
        exp = json.loads((CORPUS / "cases" / case["name"] / "expected.json").read_text())
        got = mine[case["name"]]
        # score.py's own rule: an UNREADABLE case is compared on readability and its
        # properties are not compared at all, there being nothing to compare them to.
        if exp["verdict"] == "UNREADABLE" or got["verdict"] == "UNREADABLE":
            agree += exp["verdict"] == got["verdict"]
        elif all(exp["properties"].get(p) == got["properties"][p] for p in manifest["property_names"]):
            agree += 1
        if exp["verdict"] == got["verdict"]:
            verdicts += 1
    assert (agree, verdicts) == (42, 46), f"RESULTS.md states 42 and 46; this run gives {agree} and {verdicts}"
