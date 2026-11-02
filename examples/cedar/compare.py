"""Rows where a run's outcome differs from the author's intended label."""
import json, sys
from pathlib import Path

inputs = Path(sys.argv[1])
runs = [Path(p) for p in sys.argv[2:]]
rows = [json.loads(l) for l in inputs.read_text().splitlines() if l.strip()]
outs = [[json.loads(l) for l in (d / "decisions.jsonl").read_text().splitlines()] for d in runs]
names = [d.name.replace("toolcalls-", "") for d in runs]
print(f"{'#':>2}  {'kind':11s} {'intent':6s} " + " ".join(f"{n:9s}" for n in names) + " note")
for i, r in enumerate(rows, 1):
    cells = [o[i - 1]["outcome"] for o in outs]
    if any(c != r["label"] for c in cells):
        print(f"{i:>2}  {r['input']['kind']:11s} {r['label']:6s} " + " ".join(f"{c:9s}" for c in cells) + " " + r["input"]["note"][:100])
print()
for n, o in zip(names, outs):
    agree = sum(1 for r, x in zip(rows, o) if x["outcome"] == r["label"])
    adv = [(r, x) for r, x in zip(rows, o) if r["input"]["kind"] == "adversarial"]
    print(f"{n}: {agree} of {len(rows)} match intent; adversarial {sum(1 for r, x in adv if x['outcome'] == r['label'])} of {len(adv)}")
