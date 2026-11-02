"""Score a verifier implementation against the conformance corpus. Mechanical: a list of disagreements by class, nothing else.

    python3 score.py results.jsonl [--corpus DIR]

`results.jsonl` holds one JSON object per case, in the output contract of
HANDOFF.md. The corpus directory defaults to the one this file sits in.

Classes of disagreement, checked in this order for each case:

  missing          the implementation produced no line for the case
  shape            the implementation refused to read (verdict UNREADABLE) a
                   case the reference read, or read one the reference refused
  canonical-bytes  the implementation's recomputed payload_hash or terminal
                   row hash differs from the value in the record where the
                   reference found them to match (document or chain
                   established) — the canonicalisation or hashing differs,
                   not the logic
  state            the same property, a different state
  verdict          every property state agrees but the verdict does not —
                   the rule that folds states into a verdict differs

A case appears under the first class that applies, then under `state` for
every differing property. The exit code is the number of cases with any
disagreement, capped at 125.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def load_results(path: Path):
    out = {}
    # LF only, as the format's readers split: str.splitlines also splits on
    # U+2028, U+2029 and U+0085, legal unescaped inside a JSON string.
    for line in path.read_bytes().decode("utf-8").split("\n"):
        if line.strip():
            r = json.loads(line)
            out[r["case"]] = r
    return out


def score(corpus: Path, results: dict):
    manifest = json.loads((corpus / "manifest.json").read_text())
    names = manifest["property_names"]
    disagreements = []
    for case in manifest["cases"]:
        name = case["name"]
        exp = json.loads((corpus / "cases" / name / "expected.json").read_text())
        got = results.get(name)
        if got is None:
            disagreements.append({"case": name, "class": "missing"})
            continue
        exp_unreadable = exp["verdict"] == "UNREADABLE"
        got_unreadable = got.get("verdict") == "UNREADABLE"
        if exp_unreadable != got_unreadable:
            disagreements.append({"case": name, "class": "shape", "expected": exp["verdict"], "got": got.get("verdict")})
            continue
        if exp_unreadable:
            continue
        try:
            rec = json.loads((corpus / "cases" / name / "run" / "record.json").read_text())
        except (OSError, ValueError):
            rec = {}
        record_payload = rec.get("payload_hash") if isinstance(rec, dict) else None
        record_terminal = rec.get("ledger", {}).get("terminal_hash") if isinstance(rec, dict) and isinstance(rec.get("ledger"), dict) else None
        if exp["properties"].get("document") == "established" and got.get("payload_hash_recomputed") != record_payload:
            disagreements.append({"case": name, "class": "canonical-bytes", "field": "payload_hash", "record": record_payload, "got": got.get("payload_hash_recomputed")})
        if exp["properties"].get("chain") == "established" and got.get("terminal_hash_recomputed") != record_terminal:
            disagreements.append({"case": name, "class": "canonical-bytes", "field": "terminal_hash", "record": record_terminal, "got": got.get("terminal_hash_recomputed")})
        gp = got.get("properties", {})
        differing = False
        for p in names:
            e = exp["properties"].get(p)
            g = gp.get(p)
            if e != g:
                differing = True
                disagreements.append({"case": name, "class": "state", "property": p, "expected": e, "got": g})
        if not differing and exp["verdict"] != got.get("verdict"):
            disagreements.append({"case": name, "class": "verdict", "expected": exp["verdict"], "got": got.get("verdict")})
    return disagreements


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 2
    results_path = Path(argv[0])
    corpus = Path(argv[argv.index("--corpus") + 1]) if "--corpus" in argv else Path(__file__).resolve().parent
    d = score(corpus, load_results(results_path))
    by_class: dict = {}
    for x in d:
        by_class.setdefault(x["class"], []).append(x)
    total = len(json.loads((corpus / "manifest.json").read_text())["cases"])
    cases = {x["case"] for x in d}
    print(f"{total} cases, {total - len(cases)} agree, {len(cases)} disagree")
    for cls in ("missing", "shape", "canonical-bytes", "state", "verdict"):
        if cls in by_class:
            print(f"\n{cls} ({len(by_class[cls])})")
            for x in by_class[cls]:
                rest = {k: v for k, v in x.items() if k not in ("case", "class")}
                print(f"  {x['case']}: {json.dumps(rest, sort_keys=True)}")
    return min(len(cases), 125)


if __name__ == "__main__":
    raise SystemExit(main())
