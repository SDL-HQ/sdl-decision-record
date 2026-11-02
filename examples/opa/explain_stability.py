"""Is the engine's explanation a deterministic reason? Measured, not assumed.

    python3 examples/opa/explain_stability.py <opa binary> [<opa binary> ...]

For the first call of the example under policy-store, with each engine given:
run `opa eval --explain=full` five times and digest the raw `explanation`
array; then reduce each explanation to its sequence of (Op, rule head name)
events and digest that; print whether the five raw digests agree, the reduced
digests themselves, and what the reduced trace names. Also run `--coverage` once and report what it reports.
"""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def version(b):
    out = subprocess.run([b, "version"], capture_output=True, text=True).stdout
    return next(l.split(":", 1)[1].strip() for l in out.splitlines() if l.startswith("Version:"))


def main() -> int:
    policy = json.loads((HERE / "policy-store.json").read_text())
    call = json.loads((ROOT / "examples" / "cedar" / "inputs-toolcalls.jsonl").read_text().splitlines()[0])["input"]
    call = {k: v for k, v in call.items() if k != "entities"}
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "policies.rego").write_text(policy["bundle"]["policies.rego"])
        (d / "data.json").write_text(json.dumps(policy["data"]))
        (d / "input.json").write_text(json.dumps(call))
        for b in sys.argv[1:]:
            v = version(b)
            flags = ["--v1-compatible"] if int(v.split(".")[0]) < 1 else []
            raw, reduced, names = [], [], None
            for _ in range(5):
                out = subprocess.run([b, "eval", "-f", "json", "--explain=full", *flags, "-d", "policies.rego", "-d", "data.json", "-i", "input.json", policy["query"]],
                                     capture_output=True, text=True, cwd=d, env={}).stdout
                e = json.loads(out).get("explanation", [])
                raw.append(hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest()[:12])
                seq = []
                for x in e:
                    n = x.get("Node") or x.get("node")
                    op = x.get("Op") or x.get("op")
                    if op in ("Enter", "Exit", "Redo") and isinstance(n, dict) and "head" in n:
                        seq.append((op, n["head"].get("name") or str(n["head"].get("ref"))))
                reduced.append(hashlib.sha256(json.dumps(seq).encode()).hexdigest()[:12])
                names = sorted({s[1] for s in seq})
            cov = json.loads(subprocess.run([b, "eval", "-f", "json", "--coverage", *flags, "-d", "policies.rego", "-d", "data.json", "-i", "input.json", policy["query"]],
                                            capture_output=True, text=True, cwd=d, env={}).stdout)
            covered = cov.get("coverage", {}).get("files", {}).get("policies.rego", {})
            # The raw digests themselves are not printed: they vary from run to run,
            # which is the finding, and printing them would make this capture
            # impossible to reproduce byte for byte. Whether they agree is printed.
            print(f"opa {v}: raw explanation over 5 runs -> {'identical' if len(set(raw)) == 1 else 'differ'}; "
                  f"reduced (Op, rule head) trace digests {reduced} -> {'identical' if len(set(reduced)) == 1 else 'differ'}; rule heads named {names}; "
                  f"coverage reports {len(covered.get('covered', []))} covered and {len(covered.get('not_covered', []))} uncovered source ranges, no rule ids")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
