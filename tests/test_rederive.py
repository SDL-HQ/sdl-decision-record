"""Re-derivation without the producer's code (tools/rederive.py, experiments/rederivability/).

Every test here drives the tool in a subprocess, deliberately. `tools.rederive`
installs a process-wide meta-path finder that refuses to import `emitters.*`;
importing it inside the suite would block the tests that exercise the emitters.
The isolation is the tool's point, so the tests pay the subprocess cost rather
than weaken it.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXP = ROOT / "experiments" / "rederivability"
cedarpy = pytest.importorskip("cedarpy")
ENV = {"PYTHONPATH": f"{ROOT}:{EXP}", "PATH": "/usr/bin:/bin"}


def run(*args, **kw):
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, cwd=ROOT,
                          env={**ENV, **kw.pop("env", {})}, **kw)


def test_the_producer_emitter_cannot_be_imported_on_this_path():
    """The demonstration, not the assertion: the blocker raises, and a published engine still imports."""
    p = run("-c", """
import sys; sys.path.insert(0, '.')
import tools.rederive as R
blocked = []
for m in ('emitters', 'emitters.cedar', 'emitters.toolgate', 'dr.verify', 'dr.emit'):
    try:
        __import__(m); blocked.append((m, 'IMPORTED'))
    except R.ProducerCodeBlocked:
        blocked.append((m, 'blocked'))
import cedarpy  # published software must still be importable
print(repr(blocked))
""")
    assert p.returncode == 0, p.stderr
    got = eval(p.stdout.strip())
    assert all(state == "blocked" for _, state in got), got
    assert len(got) == 5


def test_the_blocker_survives_an_attempt_to_remove_it():
    """Re-installing is idempotent and the finder is ahead of the default importers."""
    p = run("-c", """
import sys; sys.path.insert(0, '.')
import tools.rederive as R
R.install_blocker(); R.install_blocker()
n = sum(1 for f in sys.meta_path if isinstance(f, R._Blocker))
first = isinstance(sys.meta_path[0], R._Blocker)
print(n, first)
""")
    assert p.returncode == 0, p.stderr
    n, first = p.stdout.split()
    assert n == "1" and first == "True"


@pytest.mark.parametrize("name", ["toolcalls-canonical", "toolcalls-store", "toolcalls-caller"])
def test_committed_cedar_records_rederive_on_outcome_and_reason(name):
    p = run("tools/rederive.py", f"examples/cedar/out/{name}", "--json")
    assert p.returncode == 0, p.stderr
    d = json.loads(p.stdout)
    assert d["rows"] == 40
    assert d["outcome_agree"] == 40, [r for r in d["per_row"] if r.get("outcome") == "differ"]
    assert d["reason_differ"] == 0
    assert d["input_digests_all_match"] is True


def test_a_wrong_assumption_changes_the_result():
    """The instrument check: if the tool agreed regardless of its assumptions it would measure nothing."""
    p = run("-c", """
import sys; sys.path.insert(0, '.')
import tools.rederive as R
from pathlib import Path
R.ASSUMED_KEY_MAP.pop('path'); R.ASSUMED_KEY_MAP.pop('url_path')
d = R.rederive(Path('examples/cedar/out/toolcalls-canonical'))
print(d['outcome_agree'], d['outcome_differ'])
""")
    assert p.returncode == 0, p.stderr
    agree, differ = (int(x) for x in p.stdout.split())
    assert differ > 0 and agree < 40, "dropping a key-map entry must move the result"


def test_step_impact_is_reported_per_step():
    p = run("tools/rederive.py", "examples/cedar/out/toolcalls-canonical", "--steps", "--json")
    assert p.returncode == 0, p.stderr
    d = json.loads(p.stdout)
    c = d["rows_changed_by_step"]
    # unconditional steps touch every row; the canonicalisation steps touch some
    assert c["dropped_keys"] == 40 and c["entity_source_substitution"] == 40
    assert c["host"] > 0 and c["path"] > 0
    none = json.loads(run("tools/rederive.py", "examples/cedar/out/toolcalls-store", "--steps", "--json").stdout)
    assert none["rows_changed_by_step"]["host"] == 0, "mode 'none' must change nothing"


def test_a_decider_with_no_published_engine_rederives_on_outcome_only():
    p = run("-c", """
import json, sys
sys.path[:0] = ['.', 'experiments/rederivability']
from naive_toolgate import NaiveDecider
run = 'examples/out/toolgate-production'
policy = json.load(open(f'{run}/policy.json'))
rows = [json.loads(l) for l in open(f'{run}/decisions.jsonl')]
inputs = {x['seq']: x['input'] for x in (json.loads(l) for l in open(f'{run}/inputs.jsonl')) if 'seq' in x}
d = NaiveDecider(policy); oa = ra = 0
for r in rows:
    o, why, _ = d.decide(inputs[r['seq']])
    oa += o == r['outcome']; ra += why == r.get('reason')
print(len(rows), oa, ra)
""")
    assert p.returncode == 0, p.stderr
    n, oa, ra = (int(x) for x in p.stdout.split())
    assert oa == n, "every outcome must re-derive from the policy object alone"
    assert ra < n, "the reason vocabulary is not published, so it must not all agree"


@pytest.mark.skipif(not (EXP / "out" / "FORGERIES.json").exists(), reason="run experiments/rederivability/forge.py first")
def test_the_catch_table_holds():
    """F1-F4 are caught by re-derivation; F5 is caught by nothing. The second half is the finding."""
    res = json.loads((EXP / "results.json").read_text())
    by = {r["forgery"]: r for r in res["catch_table"]}
    for name in ("f1-canonicalisation-widened", "f2-context-key-dropped", "f4-entity-source-swapped"):
        assert by[name]["rederived"]["outcome_differ"] > 0, f"{name} must be caught on outcome"
        assert by[name]["replay_producer_module"]["verdict"] == "ESTABLISHED", f"{name} must pass replay under its own module"
    assert by["f3-reason-relabelled"]["rederived"]["reason_differ"] > 0
    assert by["f3-reason-relabelled"]["rederived"]["outcome_differ"] == 0
    f5 = by["f5-input-fabricated"]
    assert f5["rederived"]["outcome_differ"] == 0 and f5["rederived"]["reason_differ"] == 0
    assert f5["replay_honest_module"]["verdict"] == "ESTABLISHED", "F5 must pass every check: it is the roof"


@pytest.mark.skipif(not (EXP / "out" / "FORGERIES.json").exists(), reason="run experiments/rederivability/forge.py first")
@pytest.mark.skipif(not os.environ.get("CEDAR_DRT_ROOT"), reason="RESULTS.md carries the conformance figures; set CEDAR_DRT_ROOT to re-capture it")
def test_results_recapture_without_drift():
    """The committed RESULTS.md is what measure.py produces with the conformance corpus in hand.

    Without CEDAR_DRT_ROOT the script omits the conformance section rather than estimating it, so the
    comparison is only meaningful with the corpus present and the test skips otherwise.
    """
    before = (EXP / "RESULTS.md").read_text()
    p = run("experiments/rederivability/measure.py", env={"CEDAR_DRT_ROOT": os.environ["CEDAR_DRT_ROOT"]})
    assert p.returncode == 0, p.stderr
    after = (EXP / "RESULTS.md").read_text()
    if after != before:
        (EXP / "RESULTS.md").write_text(before)
    assert after == before, "RESULTS.md drifted; re-run measure.py and look at git diff"
