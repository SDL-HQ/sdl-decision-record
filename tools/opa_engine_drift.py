"""The §6.3 three-step procedure over OPA's own test corpus, for whatever `opa` is installed.

    export OPA_TESTDATA_ROOT=/path/to/opa/v1/test/cases/testdata      # tools/fetch_opa_testdata.py
    OPA_BIN=/path/to/opa tools/opa_engine_drift.py run --out drift-<ver>.json
    python3 tools/opa_engine_drift.py merge drift-*.json               # → examples/opa/drt-results-by-engine.json
                                                                       #   and examples/opa/conformance/<engine>.json
    python3 tools/opa_engine_drift.py digest examples/opa/conformance/opa-1.0.0.json

Step 1: every case of every file through emitters.opa_conformance, agreement
by OPA's own runner's rule (class; result set as a set of bindings; error
code exact; error text by substring), both directions counted as the Cedar
tool counts them, with "allow where deny expected" replaced by the only
directional pair this corpus has: RESULT where ERROR expected and ERROR where
RESULT expected.
Step 2: the verifier's own verdict with --replay on the signed sample record
examples/opa/out/conformance-sample.
Step 3: the sample record's retained inputs re-decided with the installed
engine regardless of the version the record names; rows that differ.
"""

from __future__ import annotations

import collections
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SAMPLE = ROOT / "examples" / "opa" / "out" / "conformance-sample"
REGISTRY = ROOT / "examples" / "keys" / "registry.json"
MERGED = ROOT / "examples" / "opa" / "drt-results-by-engine.json"
EVIDENCE_DIR = ROOT / "examples" / "opa" / "conformance"
PIN_FILE = ROOT / "examples" / "opa" / "PINNED_CORPUS.txt"


# Cases OPA's Go test harness runs that the `opa` binary cannot reproduce: not engine semantics but the invocation
# path. Keyed by the case's `note`, which the corpus keeps globally unique. Each run records the matches under
# `excluded` with its reason, inside the digested result, so a record that names the run commits to the list and the
# verifier prints it (SPEC §8).
HARNESS_EXCLUSIONS = {
    "time/time caching": "uses test.sleep, a builtin the Go test harness registers and the opa binary does not have",
    "withkeyword/builtin-builtin: arity 0": "mocks opa.runtime, which the harness answers with {} and the binary with its build information",
    "baseandvirtualdocs/base/virtual: conflicts": "a base/virtual document conflict the opa binary's loader refuses at load and the library evaluates",
}


def corpus_files(root: Path):
    return sorted(str(p.relative_to(root)) for p in root.glob("**/*.yaml"))


def run_corpus(root: Path, files) -> dict:
    from emitters import opa_conformance as OC

    policy = OC.corpus_policy(root, files)
    d = OC.Decider(policy)
    t0 = time.time()
    n = agree = 0
    by_outcome = collections.Counter()
    confusion = collections.Counter()  # (expected class, got class)
    disagree_kinds = collections.Counter()
    error_kinds = collections.Counter()
    sample = []
    boolean_direction = collections.Counter()  # silent value differences whose single binding is a boolean: which way they went
    excluded = []
    for f in files:
        for i, case in enumerate(d._cases(f)):
            outcome, reason, ext = d.decide({"file": f, "case": i})
            n += 1
            by_outcome[outcome] += 1
            if case.get("note") in HARNESS_EXCLUSIONS:  # excluded cases are evaluated and named, and counted in nothing else
                excluded.append({"file": f, "case": i, "note": case["note"], "reason": HARNESS_EXCLUSIONS[case["note"]], "agreed_anyway": OC.agrees(outcome, reason, ext, case)})
                continue
            confusion[(ext["expected"], outcome)] += 1
            if OC.agrees(outcome, reason, ext, case):
                agree += 1
                continue
            kind = f"{ext['expected']}|{outcome}" if ext["expected"] != outcome else ("value-differs" if outcome == "RESULT" else "error-differs")
            disagree_kinds[kind] += 1
            if kind == "value-differs":
                w, g = ext.get("want") or [], ext.get("result") or []
                try:
                    wv, gv = (json.loads(w[0]) if len(w) == 1 else None), (json.loads(g[0]) if len(g) == 1 else None)
                    if isinstance(wv, dict) and isinstance(gv, dict) and list(wv) == list(gv) and len(wv) == 1 and all(isinstance(x, bool) for x in (*wv.values(), *gv.values())):
                        boolean_direction["true-where-corpus-expects-false" if list(gv.values())[0] else "false-where-corpus-expects-true"] += 1
                    else:
                        boolean_direction["non-boolean-value"] += 1
                except (ValueError, TypeError):
                    boolean_direction["non-boolean-value"] += 1
            if outcome == "ERROR" and ext.get("errors"):
                error_kinds[(ext["errors"][0].get("message") or "")[:70]] += 1
            if len(sample) < 25:
                sample.append({"file": f, "case": i, "note": ext.get("note"), "expected": ext["expected"], "got": [outcome, reason[:30]],
                               "errors": (ext.get("errors") or [])[:1], "want": ext.get("want"), "result": ext.get("result")})
    return {"corpus": "open-policy-agent/opa v1/test/cases/testdata", "pin": PIN_FILE.read_text().split()[0] if PIN_FILE.exists() else None,
            "engine": OC.DECIDER_VERSION, "files": len(files), "requests": n, "excluded": excluded,
            "agree_decision_reason_and_error_presence": agree, "disagree": n - len(excluded) - agree,
            "result_where_corpus_expects_error": confusion[("ERROR", "RESULT")] + confusion[("ERROR", "UNDEFINED")],
            "error_where_corpus_expects_result": confusion[("RESULT", "ERROR")] + confusion[("UNDEFINED", "ERROR")],
            "of_which_without_engine_error": disagree_kinds["value-differs"] + disagree_kinds["RESULT|UNDEFINED"] + disagree_kinds["UNDEFINED|RESULT"],
            "disagreement_kinds": dict(disagree_kinds), "silent_boolean_direction": dict(boolean_direction), "by_outcome": dict(by_outcome), "disagreement_error_kinds": error_kinds.most_common(8),
            "disagreements_sample": sample, "corpus_files_digested": len(policy["files"]), "seconds": round(time.time() - t0),
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def verifier_verdict() -> dict:
    p = subprocess.run([sys.executable, "-m", "dr.verify", str(SAMPLE), "--registry", str(REGISTRY), "--replay", "emitters.opa_conformance", "--json"], cwd=ROOT, capture_output=True, text=True)
    try:
        rep = json.loads(p.stdout)
    except json.JSONDecodeError:
        return {"exit": p.returncode, "error": (p.stdout + p.stderr)[-400:]}
    replay = next((x for x in rep["properties"] if x["property"] == "replay"), {})
    return {"exit": p.returncode, "verdict": rep.get("verdict"), "replay_state": replay.get("state"), "replay_detail": replay.get("detail")}


def forced_replay() -> dict:
    from dr.emit import LEDGER_FILE
    from dr.record import POLICY_FILE
    from dr.verify import _read_inputs
    from dr.canonical import read_jsonl
    from emitters import opa_conformance as OC

    record = json.loads((SAMPLE / "record.json").read_text())
    rows = [json.loads(l) for _, l in read_jsonl(SAMPLE / LEDGER_FILE)]
    policy = json.loads((SAMPLE / POLICY_FILE).read_text())
    inputs = [item["input"] for item in _read_inputs(SAMPLE, rows)[0]]
    d = OC.Decider(policy)
    differ = 0
    flips = collections.Counter()
    first = None
    for row, item in zip(rows, inputs):
        outcome, reason, _ = d.decide(item)
        if (outcome, reason) != (row["outcome"], row["reason"]):
            differ += 1
            flips[f"{row['outcome']}->{outcome}" if outcome != row["outcome"] else "reason-only"] += 1
            if first is None:
                first = {"seq": row["seq"], "row": [row["outcome"], row["reason"][:30]], "replay": [outcome, reason[:30]]}
    return {"record_names": f"{record['decider']['id']}@{record['decider']['version']}", "installed": f"{OC.DECIDER_ID}@{OC.DECIDER_VERSION}",
            "rows": len(rows), "rows_differ": differ, "flips": dict(flips), "first_difference": first, "would_fail_replay": differ > 0}


def cmd_run(out: Path) -> int:
    root = Path(os.environ["OPA_TESTDATA_ROOT"])
    t0 = time.time()
    corpus = run_corpus(root, corpus_files(root))
    result = {"engine": corpus["engine"], "full_corpus": corpus,
              "verifier_on_sample_record": verifier_verdict() if SAMPLE.exists() else {"error": "no sample record"},
              "forced_recomputation_on_sample_record": forced_replay() if SAMPLE.exists() else {"error": "no sample record"},
              "seconds": round(time.time() - t0), "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    out.write_text(json.dumps(result, indent=1) + "\n")
    fc = corpus
    print(json.dumps({k: v for k, v in result.items() if k != "full_corpus"}, indent=1))
    print(f"full corpus: {fc['agree_decision_reason_and_error_presence']} of {fc['requests']} agree with {len(fc['excluded'])} excluded; result where corpus expects error {fc['result_where_corpus_expects_error']}; "
          f"error where corpus expects result {fc['error_where_corpus_expects_result']}; disagreements without an engine error {fc['of_which_without_engine_error']}; kinds {fc['disagreement_kinds']}")
    return 0


def cmd_merge(files) -> int:
    runs = [json.loads(Path(f).read_text()) for f in files]
    runs.sort(key=lambda r: [int(x) if x.isdigit() else x for x in r["engine"].replace("opa-", "").split(".")])
    record = json.loads((SAMPLE / "record.json").read_text())
    table = []
    for r in runs:
        fc, v, f = r["full_corpus"], r["verifier_on_sample_record"], r["forced_recomputation_on_sample_record"]
        fc2 = {k: v2 for k, v2 in fc.items() if k not in ("disagreements_sample", "disagreement_error_kinds")}
        table.append({"engine": r["engine"], "corpus_agree": fc["agree_decision_reason_and_error_presence"], "corpus_requests": fc["requests"], "excluded": len(fc.get("excluded") or []),
                      "result_where_corpus_expects_error": fc["result_where_corpus_expects_error"], "error_where_corpus_expects_result": fc["error_where_corpus_expects_result"],
                      "disagreements_without_engine_error": fc["of_which_without_engine_error"], "disagreement_kinds": fc["disagreement_kinds"],
                      "silent_boolean_direction": fc.get("silent_boolean_direction"),
                      "verifier_replay": v.get("replay_state"), "verifier_verdict": v.get("verdict"), "verifier_exit": v.get("exit"),
                      "forced_rows_differ": f.get("rows_differ"), "forced_rows": f.get("rows"), "forced_flips": f.get("flips")})
        EVIDENCE_DIR.mkdir(exist_ok=True)
        (EVIDENCE_DIR / f"{r['engine']}.json").write_text(json.dumps(fc, indent=1, sort_keys=True) + "\n")
    merged = {"record": str(SAMPLE.relative_to(ROOT)), "record_names": f"{record['decider']['id']}@{record['decider']['version']}",
              "corpus_pin": runs[0]["full_corpus"]["pin"], "engines": table, "runs": runs, "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    MERGED.write_text(json.dumps(merged, indent=1) + "\n")
    print(json.dumps(table, indent=1))
    return 0


def cmd_digest(path: Path) -> int:
    from dr.canonical import digest_obj

    body = json.loads(path.read_text())
    print(digest_obj(body.get("full_corpus", body)))
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["run"]:
        out = Path(argv[argv.index("--out") + 1]) if "--out" in argv else ROOT / "examples" / "opa" / "drt-engine-drift.json"
        return cmd_run(out)
    if argv[:1] == ["merge"]:
        return cmd_merge(argv[1:])
    if argv[:1] == ["digest"] and len(argv) == 2:
        return cmd_digest(Path(argv[1]))
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
