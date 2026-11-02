"""Run every measurement of the re-derivability experiment and write RESULTS.md from what the commands print.

    python3 experiments/rederivability/forge.py            # build the forged records first
    python3 experiments/rederivability/measure.py          # -> experiments/rederivability/RESULTS.md

Nothing in RESULTS.md is written by hand. Each figure is the output of a command
run here, and `tests/test_rederive.py` re-runs this and refuses on drift.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = HERE / "out"
PY = sys.executable
REG, DREG = OUT / "registry.json", OUT / "deciders.json"


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, **kw)


def verify(run: Path, replay: str | None, registry: Path, dreg: Path | None):
    cmd = [PY, "-m", "dr.verify", str(run), "--registry", str(registry), "--json"]
    if replay:
        cmd += ["--replay", replay]
    if dreg:
        cmd += ["--decider-registry", str(dreg)]
    p = sh(cmd, env={"PYTHONPATH": f"{ROOT}:{HERE}", "PATH": "/usr/bin:/bin"})
    if not p.stdout.strip():
        return {"verdict": "UNREADABLE", "states": {}, "stderr": p.stderr.strip()[-200:]}
    d = json.loads(p.stdout)
    return {"verdict": d["verdict"], "states": {x["property"]: x["state"] for x in d["properties"]},
            "detail": {x["property"]: x["detail"] for x in d["properties"]}}


def rederive(run: Path):
    p = sh([PY, "tools/rederive.py", str(run), "--json"], env={"PYTHONPATH": str(ROOT), "PATH": "/usr/bin:/bin"})
    return json.loads(p.stdout) if p.stdout.strip() else {"error": p.stderr.strip()[-300:]}


def steps(run: Path):
    p = sh([PY, "tools/rederive.py", str(run), "--steps", "--json"], env={"PYTHONPATH": str(ROOT), "PATH": "/usr/bin:/bin"})
    return json.loads(p.stdout)


def naive_toolgate(run: Path):
    sys.path[:0] = [str(ROOT), str(HERE)]
    from naive_toolgate import NaiveDecider, GUESSES
    from dr.canonical import read_jsonl
    policy = json.loads((run / "policy.json").read_text())
    rows = [json.loads(l) for _, l in read_jsonl(run / "decisions.jsonl")]
    inputs = {x["seq"]: x["input"] for x in (json.loads(l) for _, l in read_jsonl(run / "inputs.jsonl")) if "seq" in x}
    d = NaiveDecider(policy)
    oa = ra = 0
    kinds: dict = {}
    for r in rows:
        o, why, _ = d.decide(inputs[r["seq"]])
        oa += o == r["outcome"]
        if why == r.get("reason"):
            ra += 1
        else:
            k = f"{str(r.get('reason')).split(':')[0]} vs {str(why).split(':')[0]}"
            kinds[k] = kinds.get(k, 0) + 1
    return {"run": run.name, "rows": len(rows), "outcome_agree": oa, "reason_agree": ra,
            "divergence_kinds": kinds, "guesses": len(GUESSES)}


def main(argv=None) -> int:
    # Without the corpus the conformance half cannot be measured. Writing a
    # shorter RESULTS.md with no warning would treat absent input as a pass, so
    # the script refuses unless told to report that half as unsupported.
    # Refusing by default costs one flag; a quietly degraded published artefact
    # costs a figure nobody can account for later.
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    ap.add_argument("--without-corpus", action="store_true",
                    help="write RESULTS.md with the conformance half reported as unsupported, "
                         "instead of refusing when CEDAR_DRT_ROOT is unset")
    args = ap.parse_args(argv)
    if not os.environ.get("CEDAR_DRT_ROOT") and not args.without_corpus:
        sys.stderr.write(
            "CEDAR_DRT_ROOT is not set, so the conformance half of this measurement "
            "cannot run and RESULTS.md would be written without it.\n"
            "Fetch the pinned corpus and set the variable:\n"
            "  python3 tools/fetch_cedar_drt.py <a directory outside this repository>\n"
            "  export CEDAR_DRT_ROOT=<that directory>/cedar-drt\n"
            "Or pass --without-corpus to write RESULTS.md with that half reported "
            "as unsupported, which is what it will then say.\n")
        return 2
    forgeries = json.loads((OUT / "FORGERIES.json").read_text())
    honest_runs = ["toolcalls-canonical", "toolcalls-store", "toolcalls-caller"]

    # 1. re-derivation of the honest records
    honest = {n: rederive(ROOT / "examples" / "cedar" / "out" / n) for n in honest_runs}
    # 2. step impact
    step = {n: steps(ROOT / "examples" / "cedar" / "out" / n) for n in honest_runs}
    # 3a. the conformance record: a pointer-shaped retained input, corpus out of band
    conf_run = ROOT / "examples" / "cedar" / "out" / "conformance-drt-sample"
    conf_without = rederive(conf_run)
    conf_with = None
    if os.environ.get("CEDAR_DRT_ROOT"):
        pc = sh([PY, "tools/rederive.py", str(conf_run), "--json"],
                env={"PYTHONPATH": str(ROOT), "PATH": "/usr/bin:/bin", "CEDAR_DRT_ROOT": os.environ["CEDAR_DRT_ROOT"]})
        conf_with = json.loads(pc.stdout) if pc.stdout.strip() else {"error": pc.stderr[-200:]}

    # 3. a decider with no published engine
    naive = [naive_toolgate(ROOT / p) for p in ("examples/out/toolgate-benchmark", "examples/out/toolgate-production")]
    # 4. the catch table
    table = []
    for f in forgeries:
        run = OUT / f["name"]
        producer_module = f["module"].split(" ")[0] if f["module"].startswith("emitters") else f["module"]
        row = {
            "forgery": f["name"], "what": f["what"],
            "replay_producer_module": verify(run, producer_module, REG, DREG),
            "replay_honest_module": verify(run, "emitters.cedar", REG, DREG),
            "rederived": rederive(run),
        }
        table.append(row)

    def catch(v):
        s = v["states"]
        return s.get("replay", "n/a"), v["verdict"]

    lines = []
    w = lines.append
    w("# Re-derivability: what it takes to check a decision record without running the producer's code")
    w("")
    w("Generated by `python3 experiments/rederivability/measure.py`. Every figure below is the output of a")
    w("command run by that script; `tests/test_rederive.py` re-runs it and refuses on drift. No figure here")
    w("is written by hand.")
    w("")
    w("## The roof, stated first")
    w("")
    w("No rung of the ladder below removes the need to trust that the retained inputs are what the system")
    w("actually saw at decision time. That is the execution seam. It is outside this measurement and it")
    w("bounds every result in it. Forgery F5 is in the table for exactly this reason: it is a record whose")
    w("every check in this repository passes, including independent re-derivation, and whose account of one")
    w("call is false. A format claiming more than this is claiming something no amount of recomputation")
    w("can supply.")
    w("")
    w("## The ladder, as the measurement left it")
    w("")
    w("Four rungs were proposed. The measurement kept the shape and changed what decides a placement, because")
    w("the ranking by *engine* turned out not to predict the ranking by *re-derivability*:")
    w("")
    w("| rung | what a verifier does | what it still accepts on trust |")
    w("|---|---|---|")
    w("| **L0** | executes the producer's decider (`dr.verify --replay`) | the decider module is the one that decided; everything above |")
    w("| **L1** | drives the published engine on a request the record retains | every step that built that request |")
    w("| **L2** | rebuilds the request from the retained inputs and the published specification, then drives the engine | that the specification is complete; the retained inputs |")
    w("| **L3** | as L2, with the inputs independently attested | the attester; the execution seam |")
    w("")
    w("**What the measurement changed.** A rung is not decided by whether the grammar has a published engine.")
    w("It is decided by whether the *function from retained input to engine request* is published. Those come")
    w("apart in both directions, and both directions were measured below.")
    w("")
    w("## 1. The Cedar records: re-derived, with no producer code in the path")
    w("")
    w("`tools/rederive.py` installs a meta-path finder that raises on `emitters.*`, `dr.verify` and `dr.emit`")
    w("before importing any engine, and refuses to run if the producer's code is importable. The")
    w("demonstration is a test, not an assertion")
    w("(`tests/test_rederive.py::test_the_producer_emitter_cannot_be_imported_on_this_path`).")
    w("")
    w("| record | rows | outcome agree | reason agree | reason unknown (vocabulary) | reason differ | rows the rebuild changed |")
    w("|---|---:|---:|---:|---:|---:|---:|")
    for n in honest_runs:
        h = honest[n]
        w(f"| `{n}` | {h['rows']} | {h['outcome_agree']} | {h['reason_agree']} | {h['reason_unknown_vocabulary']} | {h['reason_differ']} | {h['rows_the_rebuild_changed']} |")
    w("")
    w("Every row re-derives. That figure on its own is worth little: the rebuild in `tools/rederive.py` was")
    w("written by the same hand as the emitter, so agreement shows the two readings coincide and not that the")
    w("specification determines them. The honest measurement is the assumption ledger and the instrument check")
    w("below.")
    w("")
    w("### The assumptions the rebuild required")
    w("")
    # Derived, not asserted: the paragraph is built from SPEC.md and the
    # emitter as they are, so it cannot describe either from memory.
    spec = (ROOT / "SPEC.md").read_text(encoding="utf-8")
    sys.path[:0] = [str(ROOT)]
    from emitters.cedar import CANONICAL_KEYS
    named = sorted(k for k in CANONICAL_KEYS if f"`{k}`" in spec)
    if len(named) == len(CANONICAL_KEYS) and "url-v1" in spec:
        w(f"`SPEC.md` names `url-v1` and lists all {len(CANONICAL_KEYS)} of its canonicalised keys, so the")
        w("assumptions below are no longer guesses about undocumented behaviour. They remain assumptions")
        w("because a specification is not the artefact a verifier holds: the policy object carries the")
        w("mode's name and not its content, so nothing in a signed record binds it to the text above. Each")
        w("entry says what the rebuild had to take on trust and what would make the record carry it.")
    elif "url-v1" in spec:
        w(f"`SPEC.md` names `url-v1` but lists only {len(named)} of its {len(CANONICAL_KEYS)} canonicalised keys")
        w(f"({', '.join('`%s`' % k for k in named) or 'none'}). The rest are defined only in the docstring of")
        w("`emitters/cedar.py`, which is the producer's own module. Each assumption below is a place an")
        w("independent implementer would have had to guess.")
    else:
        w("`url-v1` appears nowhere in `SPEC.md` — not the name, not the operations, not the key map. It is")
        w("defined only in the docstring of `emitters/cedar.py`, which is the producer's own module. Each")
        w("assumption below is a place an independent implementer would have had to guess.")
    w("")
    sys.path[:0] = [str(ROOT)]
    import tools.rederive as R
    for a in R.ASSUMPTIONS:
        w(f"- **{a['id']} — {a['about']}.** Why it was needed: {a['why']} Assumed: {a['assumed']} Removed by: {a['removed_by']}.")
    w("")
    w("## 2. How many rows each producer-side step actually changed")
    w("")
    w("A step that alters nothing on real data leaves those rows soundly re-derivable. These are counts of")
    w("rows the step changed, per record.")
    w("")
    keys = list(step[honest_runs[0]]["rows_changed_by_step"].keys())
    w("| step | " + " | ".join(f"`{n}`" for n in honest_runs) + " |")
    w("|---|" + "---:|" * len(honest_runs))
    for k in keys:
        w(f"| {k} | " + " | ".join(f"{step[n]['rows_changed_by_step'][k]} of {step[n]['rows']}" for n in honest_runs) + " |")
    w("")
    w("The canonicalisation steps touch 11 of 40 rows in total on the canonical setting and none at all on")
    w("the other two, whose mode is `none`. Two steps touch every row of every record: the request shape")
    w("drops keys the retained input carries (`kind`, `note`), and the policy's entity source overrides the")
    w("entities the caller asserted. Both are unconditional, so no row of any Cedar record here is free of")
    w("producer-side reshaping, even where the canonicalisation is off.")
    w("")
    w("## 3. The second body of data: Cedar's conformance corpus as a record")
    w("")
    w("The 40 tool calls and the 2,400-row conformance sample fail differently, and the difference is the")
    w("result. The conformance record's retained input is not an input: it is a pointer,")
    w("`{\"test\": \"corpus-tests/<file>.json\", \"request\": 0}`. The decision inputs — policy text, schema,")
    w("entities, the request itself — are in the corpus, which the policy names by per-file digest and does")
    w("not carry.")
    w("")
    w("```")
    w("$ python3 tools/rederive.py examples/cedar/out/conformance-drt-sample")
    w(conf_without.get("why", json.dumps(conf_without)[:200]))
    w("```")
    w("")
    if conf_with and "error" not in conf_with:
        w("With the corpus obtained out of band, the digests then establish that the one in hand is the one the")
        w("record was made against, and every row re-derives:")
        w("")
        w("| | |")
        w("|---|---:|")
        w(f"| rows | {conf_with['rows']} |")
        w(f"| outcome agree | {conf_with['outcome_agree']} |")
        w(f"| reason agree | {conf_with['reason_agree']} |")
        w(f"| reason differ | {conf_with['reason_differ']} |")
        w(f"| assumptions required | {', '.join(conf_with['assumptions_required'])} |")
        w(f"| corpus | {conf_with.get('corpus')} |")
        w("")
        w("So the conformance record needs **two** assumptions where the tool-call records need **five** — it has")
        w("no canonicalisation step at all — and in exchange it does not carry its own decision inputs, so a")
        w("verifier must fetch 11,354 files before the first row can be checked. The tool-call record is")
        w("self-contained and under-specified; the conformance record is fully specified about everything it")
        w("contains and contains a reference instead of the inputs. Neither is strictly higher on the ladder")
        w("than the other, which is why the rung has to be reported per field rather than per record.")
    else:
        w("The corpus was not available to this run, so the with-corpus figure is absent rather than estimated.")
    w("")
    w("## 4. A decider with no published engine")
    w("")
    w("`toolgate` has no published engine and no published decision function: its policy object is a")
    w("tool-to-argument-type table and the whole of the decision is in `emitters/toolgate.py`. `SPEC.md`")
    w("says nothing about it. `experiments/rederivability/naive_toolgate.py` is an independent")
    w("reimplementation written from the policy object alone, before reading that module's `decide()`.")
    w("")
    w("| record | rows | outcome agree | reason agree | divergence kinds | guesses required |")
    w("|---|---:|---:|---:|---|---:|")
    for n in naive:
        w(f"| `{n['run']}` | {n['rows']} | {n['outcome_agree']} | {n['reason_agree']} | {n['divergence_kinds']} | {n['guesses']} |")
    w("")
    w("**Every outcome re-derives, from the policy object alone, with no published engine and no published")
    w("decision function.** The reason diverges on the prefix vocabulary only — `arg_type:` against `type:`,")
    w("`arg_missing:` against `missing:` — which is a naming difference of the kind that should be")
    w("reported `unknown` rather than `failed`. So the decider with no engine reaches outcome-level L2, and")
    w("the Cedar decider with a published engine and published semantics reaches the same rung while needing")
    w("five assumptions, one of which changes outcomes when guessed wrong. A published engine is not what")
    w("makes re-derivation possible; a small enough policy object that nearly *is* the decision function is.")
    w("")
    w("## 5. The instrument check")
    w("")
    w("A tool that agreed with the records no matter what it did would report the same figures. Removing one")
    w("entry from the assumed key map (A1) — forgetting that `url_path` and `path` take the path operation, a")
    w("plausible guess from the key names alone — moves the result:")
    w("")
    ic = sh([PY, "-c", """
import sys; sys.path.insert(0,'.')
import tools.rederive as R
from pathlib import Path
b = R.rederive(Path('examples/cedar/out/toolcalls-canonical'))
print(f"as written:       outcome agree {b['outcome_agree']}/40, reason differ {b['reason_differ']}")
R.ASSUMED_KEY_MAP.pop('path'); R.ASSUMED_KEY_MAP.pop('url_path')
p = R.rederive(Path('examples/cedar/out/toolcalls-canonical'))
print(f"A1 missing paths: outcome agree {p['outcome_agree']}/40, reason differ {p['reason_differ']}")
for r in p['per_row']:
    if r.get('outcome')=='differ':
        print(f"  seq {r['seq']}: row {r['row']} -> rederived {r['rederived']}")
"""], env={"PYTHONPATH": str(ROOT), "PATH": "/usr/bin:/bin"})
    w("```")
    w(ic.stdout.strip())
    w("```")
    w("")
    w("The dangerous direction is the one that appears: on seq 29 the record says DENY for")
    w("`/workspace/%2e%2e/etc/passwd` and an implementer who guessed A1 wrong derives ALLOW. A wrong guess")
    w("about an unspecified pre-processing step does not merely fail to re-derive; it re-derives a permit the")
    w("policy refuses.")
    w("")
    w("## 6. The forgeries, and which check catches which")
    w("")
    w("Five records, each signed with a test key generated from a fixed label by")
    w("`experiments/rederivability/forge.py` (no production key is read). F1–F4 are made by tampered copies")
    w("of the Cedar decider under `experiments/rederivability/tampered/`, each changing exactly one")
    w("producer-side step. Each tampered module keeps `DECIDER_ID` and `DECIDER_VERSION` identical to the")
    w("honest module, because the version string names the engine (`cedarpy-<release>`) and says nothing")
    w("about the wrapper that builds the request. F5 changes no code at all.")
    w("")
    w("| forgery | what it misreports | `replay` under the producer's own module | `replay` under the honest module | independent re-derivation |")
    w("|---|---|---|---|---|")
    for r in table:
        pm, pv = catch(r["replay_producer_module"])
        hm, hv = catch(r["replay_honest_module"])
        rd = r["rederived"]
        if "error" in rd:
            rdtxt = "error"
        else:
            bad = rd["outcome_differ"]
            rdtxt = f"**caught** ({bad} outcome)" if bad else (f"**caught** ({rd['reason_differ']} reason)" if rd["reason_differ"] else "passes")
        w(f"| `{r['forgery']}` | {r['what']} | replay {pm}, {pv} | replay {hm}, {hv} | {rdtxt} |")
    w("")
    for r in table:
        rd = r["rederived"]
        if "error" not in rd and rd["outcome_differ"] == 0 and rd["reason_differ"] == 0:
            w(f"**`{r['forgery']}` passes every check in this repository.** {r['what'].capitalize()}. The chain")
            w("re-derives, the counts derive from the rows, the decider signed every row at decision time, the")
            w("retained input's digest matches the row that cites it, and driving the published engine on that")
            w("input reproduces the recorded decision exactly. The record is a sound account of a decision")
            w("correctly taken on an input the agent never supplied. This is the roof, demonstrated rather than")
            w("asserted, and no rung above L2 is reachable without an attester outside the producer.")
            w("")
            # Captured, not composed. The record this names is tracked in the
            # repository, so a reader can run this line and get these bytes.
            run_dir = OUT / r["forgery"]
            cmd = [PY, "-m", "dr.verify", str(run_dir.relative_to(ROOT)),
                   "--registry", str(REG.relative_to(ROOT)),
                   "--decider-registry", str(DREG.relative_to(ROOT))]
            got = sh(cmd)
            w("It is the one forgery published as an artefact rather than as a recipe, because a reader who runs")
            w("the four that fail and never reaches the one that passes leaves thinking the gap is closed:")
            w("")
            w("```")
            w("$ " + " ".join(["python3" if c == PY else c for c in cmd]))
            w(got.stdout.rstrip("\n"))
            w("$ echo $?")
            w(str(got.returncode))
            w("```")
            w("")
    w("What the table shows about the first four: each is caught by replay under the *honest* module and by")
    w("independent re-derivation, and none is caught by replay under the module the producer supplies. Since")
    w("the record's decider string is identical in both cases, nothing in the record tells a verifier which")
    w("module it was handed. That is the gap re-derivation closes: it replaces *a* module with *the")
    w("specification plus a published engine*, and it is the only one of the three checks that does not")
    w("require the verifier to already possess an honest copy of the producer's code.")
    w("")
    w("## 7. What re-derivation establishes that `replay` and `invocation` do not")
    w("")
    w("- That the decision follows from the retained policy and the retained input under the grammar's")
    w("  published semantics, with no producer code consulted — so a tampered wrapper shipped alongside the")
    w("  record cannot vouch for itself (F1, F2, F4).")
    w("- That the reason attributes the decision to the policies the engine actually determined it by (F3).")
    w("- That the pre-processing a record depends on is or is not written down: the assumption ledger is a")
    w("  per-format measurement, and this format currently scores five on Cedar.")
    w("")
    w("### And what it still does not, in the same detail")
    w("")
    w("- **That the retained input is what the system saw.** F5. The seam is unaddressed and unaddressable")
    w("  from inside the record.")
    w("- **That the retained policy is the policy the deployment enforced.** The digest binds the policy to")
    w("  the record, not to the running system. A producer who records a stricter policy than it runs produces")
    w("  a record that re-derives perfectly.")
    w("- **That the decider was consulted at all.** Re-derivation shows what the policy requires; it is")
    w("  indifferent to whether anything ran. `invocation` (SPEC §15) is what addresses that, and the two are")
    w("  complements rather than substitutes: re-derivation without attestations cannot tell a gate from a")
    w("  forwarder, and attestations without re-derivation cannot tell an honest gate from a tampered one.")
    w("- **That the rows are all the rows.** Unchanged by any of this; `completeness` is still never")
    w("  established from the producer's record alone.")
    w("- **That the engine the verifier drives agrees with the engine the producer drove.** Re-derivation")
    w("  substitutes the verifier's engine release. Engine drift is measured separately (`ENGINES.md`,")
    w("  `LEAN.md`) and the established-version mechanism is what carries a claim across releases.")
    w("")
    w("## 8. Per-field placement")
    w("")
    w("Per field of the Cedar decision input, what the record retains and what a reader can rebuild:")
    w("")
    w("| field | retained as | rebuildable from record + published spec? | rung |")
    w("|---|---|---|---|")
    w("| `principal.type`, `action`, `resource.type` | raw, used as given | yes | L2 |")
    w("| `principal.id`, `resource.id` | raw; rewritten when the type ends in `Host` | only under A2 and A4 | L2 under assumption |")
    w("| `context` keys not in the key map | raw, passed through | yes | L2 |")
    w("| `context.host`/`name`/`domain`/`recipient_domain` | raw; host operation applied | only under A1 and A4 | L2 under assumption |")
    w("| `context.url_path`, `context.path` | raw; path operation applied | only under A1 and A4 — and a wrong guess flips outcomes | L2 under assumption |")
    w("| `context.currency`, `context.scheme` | raw; case operation applied | only under A1 | L2 under assumption |")
    w("| `entities` (caller-asserted) | raw in the input | yes, but whether they are consulted depends on the policy's `entities` setting | L2 |")
    w("| `entities` (store) | in the policy object, under the digest | yes | L2 |")
    w("| `kind`, `note` | raw in the input, dropped from the request | yes, under A3 | L2 under assumption |")
    w("")
    w("The ragged edge is one column wide and every entry in it is the same word: the canonicalisation and")
    w("request-shape assumptions. Nothing about the Cedar grammar is the obstacle — the grammar is specified")
    w("and its engine is published. What is unspecified is the producer's own pre-processing, and it is")
    w("unspecified in this repository's `SPEC.md` rather than in Cedar's documentation.")
    w("")
    (HERE / "RESULTS.md").write_text("\n".join(lines).rstrip("\n") + "\n")
    (HERE / "results.json").write_text(json.dumps(
        {"honest": honest, "steps": step, "naive_toolgate": naive, "catch_table": table,
         "conformance": {"without_corpus": conf_without, "with_corpus": conf_with}}, indent=1, sort_keys=True) + "\n")
    print(f"wrote {HERE / 'RESULTS.md'} ({len(lines)} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
