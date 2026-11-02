"""Run the generated Cedar conformance corpus through the conformance decider and write the figures.

    export CEDAR_DRT_ROOT=/path/outside/repo/cedar-drt   # from tools/fetch_cedar_drt.py
    python3 tools/cedar_conformance.py                    # → examples/cedar/drt-results.json
    python3 tools/cedar_conformance.py --out other.json   # the same figures for whatever cedarpy is installed
    python3 tools/cedar_conformance.py --engine lean --out examples/cedar/conformance/cedar-lean-<commit>.json
                                                          # the same figures under the Lean definitional engine (emitters/cedar_lean.py;
                                                          #  needs CEDAR_LEAN_CLI and CEDAR_LEAN_SPEC_COMMIT; one process per request)

Every request of every test, decision and reason set compared with the
corpus's expected values; disagreements listed. The record for a seeded
sample of the same corpus is made by examples/cedar/build_conformance_inputs.py
and emitters/cedar_conformance.py (see examples/cedar/run_drt.sh).
"""

import collections
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from emitters import cedar_conformance as CC  # noqa: E402


def corpus_tests(root: Path):
    return sorted(str(p.relative_to(root)) for p in (root / "corpus-tests").glob("*.json") if not p.name.endswith(".entities.json"))


def run_corpus(root: Path, tests, engine: str = "cedarpy") -> dict:
    """Every request of every test through the conformance decider, compared with the corpus, both directions counted."""
    policy = CC.corpus_policy(root, tests)
    if engine == "lean":
        from emitters import cedar_lean as CL

        d = CL.ConformanceDecider(policy)
        engine_version = CL.DECIDER_VERSION
    else:
        d = CC.Decider(policy)
        engine_version = CC.DECIDER_VERSION
    t0 = time.time()
    agree = disagree = 0
    reasons_differ = errors_differ = 0
    sample = []
    by_outcome = collections.Counter()
    confusion = collections.Counter()  # (expected outcome, got outcome)
    disagree_without_error = 0  # the engine disagreed and reported no evaluation error: a semantic difference, not a refused feature
    error_kinds = collections.Counter()
    silent = []  # disagreements the engine reported no error for: the ones that would be a semantic difference
    for t in tests:
        n = len(json.loads((root / t).read_text())["requests"])
        for i in range(n):
            outcome, reason, ext = d.decide({"test": t, "request": i})
            expected = json.loads((root / t).read_text())["requests"][i]
            want_outcome = expected["decision"].upper()
            want_reason = "+".join(sorted(expected.get("reason", []))) or ("allow" if want_outcome == "ALLOW" else "no-policy-permits")
            by_outcome[outcome] += 1
            confusion[(want_outcome, outcome)] += 1
            ok = outcome == want_outcome and reason == want_reason and (len(ext["errors"]) > 0) == (ext["expected_errors"] > 0)
            if ok:
                agree += 1
            else:
                disagree += 1
                reasons_differ += reason != want_reason
                errors_differ += (len(ext["errors"]) > 0) != (ext["expected_errors"] > 0)
                if ext["errors"]:
                    error_kinds[ext["errors"][0][:60]] += 1
                else:
                    disagree_without_error += 1
                    if len(silent) < 20:
                        silent.append({"test": t, "request": i, "got": [outcome, reason], "want": [want_outcome, want_reason, ext["expected_errors"]], "description": ext["description"]})
                if len(sample) < 20:
                    sample.append({"test": t, "request": i, "got": [outcome, reason, ext["errors"][:1]], "want": [want_outcome, want_reason, ext["expected_errors"]]})
    return {"corpus": "cedar-integration-tests corpus-tests.tar.gz", "pin": "b157547fb8856911b293b7214768922c731878de", "engine": engine_version,
            "tests": len(tests), "requests": agree + disagree, "agree_decision_reason_and_error_presence": agree, "disagree": disagree,
            "of_which_reason_differs": reasons_differ, "of_which_error_presence_differs": errors_differ, "of_which_without_engine_error": disagree_without_error,
            "allow_where_corpus_expects_deny": confusion[("DENY", "ALLOW")], "deny_where_corpus_expects_allow": confusion[("ALLOW", "DENY")],
            "by_outcome": dict(by_outcome), "disagreement_error_kinds": error_kinds.most_common(8), "disagreements_sample": sample, "disagreements_without_engine_error_sample": silent,
            "corpus_files_digested": len(policy["files"]), "seconds": round(time.time() - t0, 1), "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "examples" / "cedar" / "drt-results.json"))
    ap.add_argument("--engine", default="cedarpy", choices=("cedarpy", "lean"))
    ap.add_argument("--limit", type=int, default=0, help="first N tests only (a sample, not evidence)")
    args = ap.parse_args(argv)
    root = Path(os.environ["CEDAR_DRT_ROOT"])
    tests = corpus_tests(root)
    if args.limit:
        tests = tests[: args.limit]
    out = run_corpus(root, tests, engine=args.engine)
    Path(args.out).write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({k: v for k, v in out.items() if k not in ("disagreements_sample", "disagreement_error_kinds")}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
