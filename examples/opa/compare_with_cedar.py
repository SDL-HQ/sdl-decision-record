"""Row by row: the OPA records against the Cedar records over the same forty calls."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def rows(p):
    return [json.loads(l) for l in (p / "decisions.jsonl").read_text().splitlines() if l.strip()]


def main() -> int:
    for n in ("caller", "store", "canonical"):
        c = rows(ROOT / "examples" / "cedar" / "out" / f"toolcalls-{n}")
        o = rows(ROOT / "examples" / "opa" / "out" / f"toolcalls-{n}")
        outcome_diff = [(a["seq"], a["outcome"], b["outcome"]) for a, b in zip(c, o) if a["outcome"] != b["outcome"]]
        naming = sum(1 for a, b in zip(c, o) if a["outcome"] == b["outcome"] and a["reason"] != b["reason"] and a["reason"].replace("policy", "p") == b["reason"])
        other = [(a["seq"], a["reason"], b["reason"]) for a, b in zip(c, o) if a["outcome"] == b["outcome"] and a["reason"] != b["reason"] and a["reason"].replace("policy", "p") != b["reason"]]
        print(f"{n}: outcomes differ on {len(outcome_diff)} of 40 rows {outcome_diff}; reasons differ by policy-id naming only (policyN vs pN) on {naming}; other reason differences {other}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
