#!/usr/bin/env bash
# The worked example. Runs from a clean clone with python3 and the cryptography
# package, no network, no credentials. Every line of examples/TRANSCRIPT.md is
# captured from what these commands print; nothing in it is typed.
#
#   bash examples/run.sh
#
# The outputs under examples/out/ are committed. Re-running reproduces them
# byte for byte: timestamps come from the input files, and Ed25519 signatures
# are deterministic. tests/test_example_reproduces.py holds that.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=examples/out
T=examples/TRANSCRIPT.md
KEY="--key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-18T04:00:00Z"
REG=examples/keys/registry.json
rm -rf "$OUT"
mkdir -p "$OUT"

{
  echo "# Transcript"
  echo
  echo "Captured by \`bash examples/run.sh\`. Commands are shown as run, output as printed, exit codes as returned."
  echo
} > "$T"

show() {  # show <exit-expected?> command...
  echo '```' >> "$T"
  echo "\$ $*" >> "$T"
  set +e
  "$@" >> "$T" 2>&1
  rc=$?
  set -e
  echo "exit $rc" >> "$T"
  echo '```' >> "$T"
  echo >> "$T"
}

echo "## 1. Emit four records with three unalike deciders" >> "$T"
echo >> "$T"
show python3 -m emitters.toolgate   --policy examples/data/toolgate-policy.json   --inputs examples/data/toolgate-suite.jsonl   --out $OUT/toolgate-benchmark   --record-id toolgate-suite-001   $KEY
show python3 -m emitters.toolgate   --policy examples/data/toolgate-policy.json   --inputs examples/data/toolgate-traffic.jsonl --out $OUT/toolgate-production  --record-id toolgate-traffic-001 $KEY
show python3 -m emitters.ratelimit  --policy examples/data/ratelimit-policy.json  --inputs examples/data/ratelimit-traffic.jsonl --out $OUT/ratelimit-production --record-id ratelimit-traffic-001 $KEY
show python3 -m emitters.classrouter --policy examples/data/classrouter-policy.json --inputs examples/data/classrouter-suite.jsonl --out $OUT/classrouter-benchmark --record-id classrouter-suite-001 $KEY

echo "## 2. Verify each one" >> "$T"
echo >> "$T"
for d in toolgate-benchmark toolgate-production ratelimit-production classrouter-benchmark; do
  show python3 -m dr.verify $OUT/$d --registry $REG
done

echo "## 3. Replay: re-decide the retained inputs with the named decider" >> "$T"
echo >> "$T"
show python3 -m dr.verify $OUT/ratelimit-production --registry $REG --replay emitters.ratelimit
show python3 -m dr.verify $OUT/toolgate-production  --registry $REG --replay emitters.toolgate

echo "## 4. What the verifier refuses" >> "$T"
echo >> "$T"
TMP=examples/scratch
rm -rf "$TMP"; mkdir -p "$TMP"
cp -r $OUT/toolgate-benchmark "$TMP/flipped-outcome"
python3 - "$TMP/flipped-outcome" <<'EOF'
import json, sys
p = sys.argv[1] + "/decisions.jsonl"
rows = [json.loads(l) for l in open(p)]
rows[3]["outcome"] = "ALLOW"          # the row for delete_all_orders, which the gate denied
open(p, "w").write("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))
EOF
echo "A row's outcome edited on disk (row 4, DENY to ALLOW):" >> "$T"
echo >> "$T"
show python3 -m dr.verify "$TMP/flipped-outcome" --registry $REG

cp -r $OUT/toolgate-benchmark "$TMP/lying-profile"
python3 - "$TMP/lying-profile" <<'EOF'
import json, sys
sys.path.insert(0, ".")
from dr.signing import sign_record
p = sys.argv[1] + "/record.json"
r = json.load(open(p))
r["profile"] = "production"; del r["benchmark"]
for k in ("payload_hash", "signature"): r.pop(k)
json.dump(sign_record(r, open("examples/keys/example-signing-key.pem", "rb").read()), open(p, "w"), indent=2, sort_keys=True)
EOF
echo "A dishonest producer: the same labelled rows, re-signed with the real key as a production record so that no correctness figure is carried:" >> "$T"
echo >> "$T"
show python3 -m dr.verify "$TMP/lying-profile" --registry $REG

cp -r $OUT/toolgate-production "$TMP/revoked"
python3 - "$TMP/revoked" <<'EOF'
import json, sys
sys.path.insert(0, ".")
from dr.signing import sign_record
p = sys.argv[1] + "/record.json"
r = json.load(open(p))
r["signing_key_id"] = "example-compromised"
for k in ("payload_hash", "signature"): r.pop(k)
json.dump(sign_record(r, open("examples/keys/revoked-key.pem", "rb").read()), open(p, "w"), indent=2, sort_keys=True)
EOF
echo "A record signed by a key the registry has revoked:" >> "$T"
echo >> "$T"
show python3 -m dr.verify "$TMP/revoked" --registry $REG

cp -r $OUT/classrouter-benchmark "$TMP/future-format"
python3 - "$TMP/future-format" <<'EOF'
import json, sys
p = sys.argv[1] + "/decisions.jsonl"
rows = [json.loads(l) for l in open(p)]
for r in rows: r["v"] = 3
open(p, "w").write("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))
EOF
echo "Rows declaring a version this verifier does not read (not a failure: unknown):" >> "$T"
echo >> "$T"
show python3 -m dr.verify "$TMP/future-format" --registry $REG

echo "## 5. The record itself" >> "$T"
echo >> "$T"
show cat $OUT/ratelimit-production/record.json
echo "## 6. One row" >> "$T"
echo >> "$T"
show head -n 1 $OUT/ratelimit-production/decisions.jsonl

echo "## 7. A stream of records, with receipts" >> "$T"
echo >> "$T"
echo "The same toolgate traffic as two consecutive records of one stream. Each decision also gets a signed receipt, which in a deployment goes to the party the decision was about." >> "$T"
echo >> "$T"
show python3 -m emitters.toolgate --policy examples/data/toolgate-policy.json --inputs examples/data/toolgate-traffic-hour1.jsonl --out $OUT/stream-hour1 --record-id toolgate-hour1 --stream toolgate-traffic:1 --receipts $OUT/stream-hour1-receipts $KEY
show python3 -m emitters.toolgate --policy examples/data/toolgate-policy.json --inputs examples/data/toolgate-traffic-hour2.jsonl --out $OUT/stream-hour2 --record-id toolgate-hour2 --stream toolgate-traffic:2 --prior $OUT/stream-hour1/record.json --receipts $OUT/stream-hour2-receipts $KEY
echo "The second record alone: its link to the first cannot be checked without the first." >> "$T"
echo >> "$T"
show python3 -m dr.verify $OUT/stream-hour2 --registry $REG
echo "With the prior record supplied:" >> "$T"
echo >> "$T"
show python3 -m dr.verify $OUT/stream-hour2 --registry $REG --prior $OUT/stream-hour1/record.json
show python3 -m dr.stream $OUT/stream-hour1/record.json $OUT/stream-hour2/record.json
show cat $OUT/stream-hour2-receipts/receipt-000001.json

echo "## 8. What a record cannot say about itself" >> "$T"
echo >> "$T"
echo "Delete two decisions from the first record, renumber, re-chain, re-derive the counts and re-sign with the producer's own key. Every property holds: a record is a statement about the rows that are in it." >> "$T"
echo >> "$T"
show python3 tools/truncate.py $OUT/stream-hour1 "$TMP/hour1-truncated" --drop 3,7 --key examples/keys/example-signing-key.pem
show python3 -m dr.verify "$TMP/hour1-truncated" --registry $REG --replay emitters.toolgate
echo "The holder of the receipt for decision 20 can refute it, and count the gap:" >> "$T"
echo >> "$T"
show python3 -m dr.verify "$TMP/hour1-truncated" --registry $REG --receipt $OUT/stream-hour1-receipts/receipt-000020.json
echo "The holder of the receipt for decision 7 finds a different row at seq 7:" >> "$T"
echo >> "$T"
show python3 -m dr.verify "$TMP/hour1-truncated" --registry $REG --receipt $OUT/stream-hour1-receipts/receipt-000007.json
echo "The second record of the stream no longer follows the truncated first; and held together with the original, the two are a fork: two records signed for one position." >> "$T"
echo >> "$T"
show python3 -m dr.verify $OUT/stream-hour2 --registry $REG --prior "$TMP/hour1-truncated/record.json"
show python3 -m dr.stream $OUT/stream-hour1/record.json "$TMP/hour1-truncated/record.json" $OUT/stream-hour2/record.json

echo "## 9. A witness" >> "$T"
echo >> "$T"
echo "A second party countersigns the first record's payload_hash. The statement establishes that this exact record existed when the witness signed, and nothing before that." >> "$T"
echo >> "$T"
show python3 -m dr.witness $OUT/stream-hour1/record.json --key examples/keys/witness-key.pem --key-id example-witness-2026-10 --witnessed-at 2026-10-18T04:05:00Z --out $OUT/stream-hour1.witness.json
show python3 -m dr.verify $OUT/stream-hour1 --registry $REG --witness $OUT/stream-hour1.witness.json --witness-registry examples/keys/witnesses.json
show python3 -m dr.verify "$TMP/hour1-truncated" --registry $REG --witness $OUT/stream-hour1.witness.json --witness-registry examples/keys/witnesses.json
rm -rf "$TMP"

echo "## 10. Saying less: keyed digests, no ext, and a reader without the inputs" >> "$T"
echo >> "$T"
echo "The rate limiter's traffic emitted as row version 2 (keyed input digests, salt in inputs.jsonl) without the ext block. It verifies and replays exactly as before. Then the same directory as a reader who was not given inputs.jsonl sees it." >> "$T"
echo >> "$T"
show python3 -m emitters.ratelimit --policy examples/data/ratelimit-policy.json --inputs examples/data/ratelimit-traffic.jsonl --out $OUT/ratelimit-production-keyed --record-id ratelimit-traffic-001-keyed --keyed --salt 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f --no-ext $KEY
show head -n 1 $OUT/ratelimit-production-keyed/decisions.jsonl
show head -n 1 $OUT/ratelimit-production-keyed/inputs.jsonl
show python3 -m dr.verify $OUT/ratelimit-production-keyed --registry $REG --replay emitters.ratelimit
mkdir -p "$TMP"
cp -r $OUT/ratelimit-production-keyed "$TMP/without-inputs"
rm "$TMP/without-inputs/inputs.jsonl"
show python3 -m dr.verify "$TMP/without-inputs" --registry $REG --replay emitters.ratelimit
rm -rf "$TMP"

echo "wrote $T"
