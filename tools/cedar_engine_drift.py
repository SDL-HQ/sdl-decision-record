"""Does a Cedar conformance record detect a different engine? Measured per installed cedarpy.

    export CEDAR_DRT_ROOT=/path/outside/repo/cedar-drt           # from tools/fetch_cedar_drt.py
    <venv-with-some-cedarpy>/bin/python tools/cedar_engine_drift.py run --out drift-<ver>.json
    python3 tools/cedar_engine_drift.py merge drift-*.json         # → examples/cedar/drt-results-by-engine.json
                                                                   #   and examples/cedar/conformance/<engine>.json, one per engine
    python3 tools/cedar_engine_drift.py digest examples/cedar/conformance/cedarpy-4.8.7.json   # the evidence digest a record names

An engine whose run agrees in full can be named in a record as established
(`decider.established_versions`, SPEC §8) with the digest of its run's result;
`merge` writes that result per engine under `examples/cedar/conformance/` and
`digest` prints the digest the record names and the verifier checks
(`dr.verify --conformance-evidence`).

`run` does three things with whatever cedarpy is installed:

1. The full generated corpus (45,416 requests at the pin) through the
   conformance decider, compared with the corpus's expected decisions, both
   directions counted (tools/cedar_conformance.py).
2. The verifier's own verdict on the signed sample record
   `examples/cedar/out/conformance-drt-sample` with `--replay`: the record
   names the engine version it was made under, and the verifier does not
   replay under a different one (replay `unknown`, verdict NOT ESTABLISHED).
3. The recomputation the verifier declined, forced: every retained input of
   the sample record re-decided with the installed engine and compared with
   the row. This is what an engine that misreported its version, or a record
   that did not name one, would be judged by. It is a measurement of what the
   version check stands in for, not a verifier mode; the verifier has no
   switch for it.

The record's own version check is one-directional by design: an engine that
agrees on every row of the corpus is refused exactly as one that does not.
`run` reports both, so that cost is a figure and not a remark.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SAMPLE = ROOT / "examples" / "cedar" / "out" / "conformance-drt-sample"
REGISTRY = ROOT / "examples" / "keys" / "registry.json"
MERGED = ROOT / "examples" / "cedar" / "drt-results-by-engine.json"
EVIDENCE_DIR = ROOT / "examples" / "cedar" / "conformance"


def verifier_verdict(python: str) -> dict:
    p = subprocess.run([python, "-m", "dr.verify", str(SAMPLE), "--registry", str(REGISTRY), "--replay", "emitters.cedar_conformance", "--json"],
                       cwd=ROOT, capture_output=True, text=True)
    try:
        rep = json.loads(p.stdout)
    except json.JSONDecodeError:
        return {"exit": p.returncode, "error": (p.stdout + p.stderr)[-400:]}
    props = {x["property"]: x for x in rep["properties"]} if "properties" in rep else rep
    replay = props.get("replay", {})
    return {"exit": p.returncode, "verdict": rep.get("verdict"), "replay_state": replay.get("state"), "replay_detail": replay.get("detail")}


def forced_replay() -> dict:
    """Re-decide the sample record's retained inputs with the installed engine, ignoring the version the record names."""
    from dr.emit import LEDGER_FILE  # noqa: E402
    from dr.record import POLICY_FILE  # noqa: E402
    from dr.verify import _read_inputs  # noqa: E402
    from dr.canonical import read_jsonl  # noqa: E402
    from emitters import cedar_conformance as CC  # noqa: E402

    record = json.loads((SAMPLE / "record.json").read_text())
    rows = [json.loads(line) for _, line in read_jsonl(SAMPLE / LEDGER_FILE)]
    policy = json.loads((SAMPLE / POLICY_FILE).read_text())
    inputs = [item["input"] for item in _read_inputs(SAMPLE, rows)[0]]
    d = CC.Decider(policy)
    first = None
    differ = 0
    flips = {"ALLOW->DENY": 0, "DENY->ALLOW": 0, "reason-only": 0}
    for row, item in zip(rows, inputs):
        outcome, reason, _ = d.decide(item)
        if (outcome, reason) != (row["outcome"], row["reason"]):
            differ += 1
            if outcome != row["outcome"]:
                flips[f"{row['outcome']}->{outcome}"] += 1
            else:
                flips["reason-only"] += 1
            if first is None:
                first = {"seq": row["seq"], "row": [row["outcome"], row["reason"]], "replay": [outcome, reason]}
    return {"record_names": f"{record['decider']['id']}@{record['decider']['version']}", "installed": f"{CC.DECIDER_ID}@{CC.DECIDER_VERSION}",
            "rows": len(rows), "rows_differ": differ, "flips": flips, "first_difference": first,
            "would_fail_replay": differ > 0}


def cmd_run(out: Path) -> int:
    from tools.cedar_conformance import corpus_tests, run_corpus  # noqa: E402

    root = Path(os.environ["CEDAR_DRT_ROOT"])
    t0 = time.time()
    corpus = run_corpus(root, corpus_tests(root))
    corpus.pop("disagreements_sample", None)
    result = {"engine": corpus["engine"], "full_corpus": corpus, "verifier_on_sample_record": verifier_verdict(sys.executable), "forced_recomputation_on_sample_record": forced_replay(),
              "seconds": round(time.time() - t0), "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    out.write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "full_corpus"}, indent=1))
    fc = corpus
    print(f"full corpus: {fc['agree_decision_reason_and_error_presence']} of {fc['requests']} agree; allow where corpus expects deny {fc['allow_where_corpus_expects_deny']}; "
          f"deny where corpus expects allow {fc['deny_where_corpus_expects_allow']}; disagreements without an engine error {fc['of_which_without_engine_error']}")
    return 0


def cmd_merge(files) -> int:
    runs = [json.loads(Path(f).read_text()) for f in files]
    runs.sort(key=lambda r: [int(x) if x.isdigit() else x for x in r["engine"].replace("cedarpy-", "").split(".")])
    record = json.loads((SAMPLE / "record.json").read_text())
    table = []
    for r in runs:
        fc, v, f = r["full_corpus"], r["verifier_on_sample_record"], r["forced_recomputation_on_sample_record"]
        table.append({"engine": r["engine"], "corpus_agree": fc["agree_decision_reason_and_error_presence"], "corpus_requests": fc["requests"],
                      "allow_where_corpus_expects_deny": fc["allow_where_corpus_expects_deny"], "deny_where_corpus_expects_allow": fc["deny_where_corpus_expects_allow"],
                      "disagreements_without_engine_error": fc["of_which_without_engine_error"],
                      "verifier_replay": v.get("replay_state"), "verifier_verdict": v.get("verdict"), "verifier_exit": v.get("exit"),
                      "forced_rows_differ": f["rows_differ"], "forced_rows": f["rows"], "forced_flips": f["flips"]})
    merged = {"record": str(SAMPLE.relative_to(ROOT)), "record_names": f"{record['decider']['id']}@{record['decider']['version']}",
              "corpus_pin": runs[0]["full_corpus"]["pin"], "engines": table, "runs": runs, "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    MERGED.write_text(json.dumps(merged, indent=1) + "\n")
    EVIDENCE_DIR.mkdir(exist_ok=True)
    for r in runs:
        (EVIDENCE_DIR / f"{r['engine']}.json").write_text(json.dumps(r["full_corpus"], indent=1, sort_keys=True) + "\n")
    print(json.dumps(table, indent=1))
    return 0


def cmd_digest(path: Path) -> int:
    from dr.canonical import digest_obj  # noqa: E402

    body = json.loads(path.read_text())
    print(digest_obj(body.get("full_corpus", body)))
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["run"]:
        out = Path(argv[argv.index("--out") + 1]) if "--out" in argv else ROOT / "examples" / "cedar" / "drt-engine-drift.json"
        return cmd_run(out)
    if argv[:1] == ["merge"]:
        return cmd_merge(argv[1:])
    if argv[:1] == ["digest"] and len(argv) == 2:
        return cmd_digest(Path(argv[1]))
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
