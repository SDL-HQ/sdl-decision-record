"""The assurance ladder (dr/assurance.py, SPEC §9.1).

Three rules: a level is a set of properties that must all be established, one
unknown dropping it; a failed property voids the ladder; and no level is ever
shown without the four-state table beneath it. Then the level is computed for
every record in this repository, and for the named records whose level is the
point: F5 reaches A3 — invoked, re-evaluable, signed and chained, and a
fabrication — and only the attester's rung, A4, is closed to it.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dr.assurance import LEVELS, assess  # noqa: E402
from dr.verify import CORE_PROPERTIES, verify_directory  # noqa: E402

ALL = [p for _, _, _, adds, _ in LEVELS for p in adds]


def _table(**states):
    base = {p: "established" for p in ALL}
    base.update(states)
    return [{"property": k, "state": v, "detail": ""} for k, v in base.items()]


def test_every_property_established_reaches_a4():
    a = assess(_table())
    assert a["level"] == "A4" and all(lv["reached"] for lv in a["levels"])


@pytest.mark.parametrize("prop", ALL)
@pytest.mark.parametrize("state", ["unknown", "n/a"])
def test_one_property_not_established_drops_every_level_that_names_it(prop, state):
    a = assess(_table(**{prop: state}))
    first = next(lv for lv, _, _, adds, _ in LEVELS if prop in adds)
    allowed_na = any(prop in na for *_, na in LEVELS)
    if state == "n/a" and allowed_na:
        assert a["level"] == "A4"
        return
    order = [lv for lv, *_ in LEVELS]
    assert a["level"] == order[order.index(first) - 1]
    for lv in a["levels"][order.index(first):]:
        assert not lv["reached"] and {"property": prop, "state": state} in [{k: m[k] for k in ("property", "state")} for m in lv["missing"]]


def test_only_correctness_and_stream_may_be_n_a():
    assert {p for *_, na in LEVELS for p in na} == {"correctness", "stream"}


def test_a_property_never_judged_is_not_established():
    props = [p for p in _table() if p["property"] != "replay"]
    a = assess(props)
    assert a["level"] == "A1"
    assert a["levels"][2]["missing"][0]["state"] == "not judged"


@pytest.mark.parametrize("prop", ALL + ["receipts", "witness", "completeness"])
def test_a_failed_property_anywhere_voids_the_ladder(prop):
    a = assess(_table(**{prop: "failed"}))
    assert a["level"] is None and a["failed"] == [prop]
    assert not any(lv["reached"] for lv in a["levels"])


def test_the_level_carries_the_table_it_was_computed_from():
    props = _table(replay="n/a")
    a = assess(props)
    assert a["table"] == [{"property": p["property"], "state": p["state"]} for p in props]


def test_the_ladder_covers_every_core_property_but_retained_at_a1():
    a1 = next(adds for lv, _, _, adds, _ in LEVELS if lv == "A1")
    assert set(CORE_PROPERTIES) - set(a1) == {"retained"}
    assert "retained" in next(adds for lv, _, _, adds, _ in LEVELS if lv == "A2")


# --- shown only with the table ----------------------------------------------

ACC = ROOT / "examples" / "acceptance" / "out"


def _run(*args):
    return subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True)


VERIFY = ["-m", "dr.verify", "examples/acceptance/out/record", "--registry", "examples/keys/registry.json",
          "--decider-registry", "examples/keys/deciders.json", "--replay", "emitters.toolgate"]


def test_the_text_report_states_the_level_after_every_property_and_the_verdict():
    out = _run(*VERIFY, "--assurance").stdout
    lines = out.splitlines()
    at = next(i for i, l in enumerate(lines) if l.startswith("ASSURANCE:"))
    verdict = next(i for i, l in enumerate(lines) if l.startswith("VERDICT:"))
    props = json.loads(_run(*VERIFY, "--json").stdout)["properties"]
    assert verdict < at
    for p in props:
        assert any(p["property"] in l for l in lines[:verdict]), p["property"]
    assert lines[at] == "ASSURANCE: A3 invoked -- read with the table above; a level is every property it names established"


def test_the_json_report_carries_the_level_beside_and_over_its_properties():
    rep = json.loads(_run(*VERIFY, "--json", "--assurance").stdout)
    assert rep["assurance"]["table"] == [{"property": p["property"], "state": p["state"]} for p in rep["properties"]]
    assert rep["assurance"]["level"] == "A3"


FIXTURE = ROOT / "tests" / "fixtures" / "reports-without-assurance.json"


def _in_process(module_name, args):
    import contextlib, hashlib, importlib, io, os
    mod = importlib.import_module(module_name)
    out, err = io.StringIO(), io.StringIO()
    here = os.getcwd()
    os.chdir(ROOT)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = mod.main(list(args))
    finally:
        os.chdir(here)
    return {"exit": code, "stdout_sha256": hashlib.sha256(out.getvalue().encode("utf-8")).hexdigest(),
            "stderr_sha256": hashlib.sha256(err.getvalue().encode("utf-8")).hexdigest()}, out.getvalue()


def _needs_cedar(case):
    """A case that replays under the Cedar engine needs cedarpy installed."""
    a = case["args"]
    return any(a[i - 1] == "--replay" and a[i].startswith("emitters.cedar") for i in range(1, len(a)))


def _cases(*, cedar):
    cases = json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]
    return [c for c in cases if _needs_cedar(c) == cedar]


def _differ(cases):
    differ = []
    for case in cases:
        got, _ = _in_process(case["args"][0], case["args"][1:])
        want = {k: case[k] for k in ("exit", "stdout_sha256", "stderr_sha256")}
        if got != want:
            differ.append(" ".join(case["args"]))
    return differ


def test_without_the_flag_every_report_is_what_it_was_before_the_ladder():
    """The ladder changes no report it was not asked for, held against the verifiers as they were before it
    (tests/fixtures/make_reports_without_assurance.py): every record here, with
    and without the decider registry, text and JSON, and the replay and arrival
    reports. Exit code, standard output and standard error, byte for byte. A
    check that only the flag's text is absent would pass an unrequested change
    to the report; this one fails on it. The cases that replay under Cedar are
    the next test, which needs cedarpy."""
    cases = _cases(cedar=False)
    assert len(cases) >= 250
    assert _differ(cases) == []


def test_without_the_flag_every_cedar_replay_report_is_what_it_was_before_the_ladder():
    """The same, for the cases that replay under the Cedar engine."""
    pytest.importorskip("cedarpy")
    cases = _cases(cedar=True)
    assert cases
    assert _differ(cases) == []




@pytest.mark.parametrize("fmt", ["text", "json"])
def test_the_flag_adds_the_level_and_changes_nothing_else(fmt):
    for case in json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]:
        args = case["args"]
        if ("--json" in args) != (fmt == "json"):
            continue
        r, without = _in_process(args[0], args[1:])
        _, with_flag = _in_process(args[0], [*args[1:], "--assurance"])
        if r["exit"] == 3:  # nothing was judged: no table, so no level, and nothing to add
            assert with_flag == without == "", args
            continue
        if fmt == "json":
            a, b = json.loads(without), json.loads(with_flag)
            assert set(b) - set(a) == {"assurance"}, args
            b.pop("assurance")
            assert a == b, args
        else:
            head = without.rstrip("\n") + "\n\nASSURANCE: "
            assert with_flag.startswith(head), args


def test_no_code_path_computes_or_prints_a_level_except_the_reports():
    """The level is computed in dr/assurance.py and rendered by the two
    verifiers' reports, which print the table with it. Nothing else may call it."""
    allowed = {"dr/assurance.py", "dr/verify.py", "tools/verify_arrival.py"}
    callers = []
    for f in list(ROOT.glob("dr/*.py")) + list(ROOT.glob("tools/*.py")) + list(ROOT.glob("emitters/*.py")) + list(ROOT.glob("experiments/**/*.py")):
        rel = str(f.relative_to(ROOT))
        if rel in allowed:
            continue
        if re.search(r"\b(assess|render_text)\s*\(|dr\.assurance|from \.assurance", f.read_text(encoding="utf-8")):
            callers.append(rel)
    assert callers == []
    src = (ROOT / "dr" / "verify.py").read_text(encoding="utf-8")
    assert src.count("assess(") == 2 and src.count("render_text(") == 1


# --- the level of every record here, and of the ones whose level is the point --

def _record_dirs():
    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "*record.json"], capture_output=True, text=True).stdout.split()
    return sorted({(ROOT / f).parent for f in tracked if Path(f).name == "record.json"})


def test_the_level_is_computed_for_every_record_and_agrees_with_its_table():
    dirs = _record_dirs()
    assert len(dirs) > 20
    seen = set()
    for d in dirs:
        try:
            rep = verify_directory(d, ROOT / "examples" / "keys" / "registry.json",
                                   decider_registry=ROOT / "examples" / "keys" / "deciders.json")
        except (OSError, ValueError):
            continue  # unreadable on purpose (a conformance case): nothing was judged, so no table and no level
        props = rep.all_properties()
        a = assess(props)
        states = {p["property"]: p["state"] for p in props}
        if "failed" in states.values():
            assert a["level"] is None
        else:
            assert a["level"] is not None
            for lv in a["levels"]:
                needed = [p for L, *_rest in LEVELS[:int(lv["level"][1]) + 1] for p in _rest[2]]
                na_ok = {p for *_x, na in LEVELS for p in na}
                holds = all(states.get(p) == "established" or (states.get(p) == "n/a" and p in na_ok) for p in needed)
                assert lv["reached"] == holds, (d, lv)
        seen.add(a["level"])
    assert {None, "A0", "A1"} <= seen


def test_f5_reaches_a3_and_only_the_attester_closes_a4():
    """The fabricated input, honestly decided: signed, chained, re-evaluable and
    invoked. Integrity is not occurrence; the ladder says so by stopping at A3.
    The record was decided under Cedar, so replaying it needs cedarpy."""
    pytest.importorskip("cedarpy")
    E = "experiments/rederivability/out"
    rep = json.loads(_run("-m", "dr.verify", f"{E}/f5-input-fabricated", "--registry", f"{E}/registry.json",
                          "--decider-registry", f"{E}/deciders.json", "--replay", "emitters.cedar", "--json", "--assurance").stdout)
    assert rep["verdict"] == "ESTABLISHED"
    assert rep["assurance"]["level"] == "A3"
    assert [m["property"] for m in rep["assurance"]["levels"][4]["missing"]] == ["arrival", "arrivals_accounted"]


@pytest.mark.parametrize("name,level", [("gated", "A4"), ("fabricated", None)])
def test_with_an_attester_honest_inputs_reach_a4_and_a_replaced_one_reaches_nothing(name, level):
    o = f"examples/acceptance/out/{name}"
    p = _run("tools/verify_arrival.py", o, "--registry", f"{o}.producer.json", "--decider-registry", f"{o}.decider.json",
             "--attester-registry", f"{o}.attester.json", "--arrival-log", f"{o}.attester-log.jsonl",
             "--replay", "emitters.toolgate", "--json", "--assurance")
    rep = json.loads(p.stdout)
    assert rep["assurance"]["level"] == level
    if level is None:
        assert rep["assurance"]["failed"] == ["arrival"]
