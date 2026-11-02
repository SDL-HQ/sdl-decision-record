"""Build the conformance policy (the pinned corpus, every file digested) and a seeded sample of its cases as inputs.

    python3 examples/opa/build_conformance_inputs.py --sample 400 --seed 1
"""

import argparse
import json
import os
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

from emitters import opa_conformance as OC  # noqa: E402

TS = "2026-10-21T01:00:00Z"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=400)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    root = Path(os.environ["OPA_TESTDATA_ROOT"])
    files = sorted(str(p.relative_to(root)) for p in root.glob("**/*.yaml"))
    policy = OC.corpus_policy(root, files)
    (HERE / "policy-conformance.json").write_text(json.dumps(policy, indent=1, sort_keys=True) + "\n")
    import yaml

    cases = [(f, i, c) for f in files for i, c in enumerate(yaml.safe_load((root / f).read_text()).get("cases", []))]
    rng = random.Random(args.seed)
    picked = sorted(rng.sample(range(len(cases)), min(args.sample, len(cases))))
    with (HERE / "inputs-conformance.jsonl").open("w") as fh:
        for k in picked:
            f, i, c = cases[k]
            label = "ERROR" if ("want_error" in c or "want_error_code" in c) else ("UNDEFINED" if c.get("want_result") == [] else "RESULT")
            fh.write(json.dumps({"ts": TS, "label": label, "input": {"file": f, "case": i}}) + "\n")
    print(f"policy-conformance.json ({len(files)} files digested), inputs-conformance.jsonl ({len(picked)} of {len(cases)} cases, seed {args.seed})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
