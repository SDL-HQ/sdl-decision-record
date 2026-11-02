"""Inputs and policy for the conformance records.

    python3 examples/cedar/build_conformance_inputs.py                 # hand-written tests from vendor/
    python3 examples/cedar/build_conformance_inputs.py --drt DIR --sample 300 --seed 1   # generated corpus, a seeded sample of tests
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

from emitters.cedar_conformance import corpus_policy  # noqa: E402

TS = "2026-10-20T01:00:00Z"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--drt", default=None, help="directory holding corpus-tests/ (the generated corpus); default: the vendored hand-written tests")
    ap.add_argument("--sample", type=int, default=None)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args(argv)
    if args.drt:
        root = Path(args.drt).resolve()
        tests = sorted(str(p.relative_to(root)) for p in (root / "corpus-tests").glob("*.json") if not p.name.endswith(".entities.json"))
        tag = "drt"
    else:
        root = ROOT / "vendor" / "cedar-integration-tests"
        tests = sorted(str(p.relative_to(root)) for p in root.glob("tests/**/*.json") if "requests" in json.loads(p.read_text()))
        tag = "handwritten"
    if args.sample:
        tests = sorted(random.Random(args.seed).sample(tests, min(args.sample, len(tests))))
    policy = corpus_policy(root, tests)
    policy["root"] = str(root.relative_to(ROOT)) if not args.drt else "$CEDAR_DRT_ROOT"  # vendored: relative to the repository; fetched: named by an environment variable
    (HERE / f"policy-conformance-{tag}.json").write_text(json.dumps(policy, indent=1) + "\n")
    rows = []
    for t in tests:
        d = json.loads((root / t).read_text())
        for i, r in enumerate(d["requests"]):
            rows.append({"ts": TS, "label": r["decision"].upper(), "input": {"test": t, "request": i}})
    (HERE / f"inputs-conformance-{tag}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    print(f"{tag}: {len(tests)} tests, {len(rows)} requests, {len(policy['files'])} corpus files digested")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
