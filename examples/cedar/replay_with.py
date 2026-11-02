"""Replay a record with a decider built from a different policy file: what the verifier says."""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from emitters import cedar
from dr.verify import verify_directory

run, policy_path = Path(sys.argv[1]), Path(sys.argv[2])
changed = json.loads(policy_path.read_text())
# the verifier builds the decider from the record's own retained policy; here the
# question is what happens when the engine's policy is not that one, so the
# comparison is done directly: re-decide every retained input under the changed
# policy and count disagreements with the rows
rows = [json.loads(l) for l in (run / "decisions.jsonl").read_text().splitlines()]
inputs = [json.loads(l)["input"] for l in (run / "inputs.jsonl").read_text().splitlines()]
d = cedar.Decider(changed)
diff = [(r["seq"], r["outcome"], d.decide(i)[0]) for r, i in zip(rows, inputs) if d.decide(i)[0] != r["outcome"]]
print(f"changed policy: {len(diff)} of {len(rows)} rows decide differently: {diff[:4]}")
from dr.canonical import digest_obj
print(f"policy digest in the record {rows[0]['policy_digest'][:20]}…, changed policy {digest_obj(changed)[:20]}…: the record names a policy the changed one is not")
