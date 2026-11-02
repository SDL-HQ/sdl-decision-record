#!/usr/bin/env bash
# The execution-time example: an agent's privileged calls decided under Cedar,
# recorded, and replayed; and Cedar's own conformance corpus as a record.
#
#   pip install cedarpy      # the Cedar engine behind Python bindings
#   bash examples/cedar/run.sh
#
# Outputs under examples/cedar/out/ are committed and reproduce byte for byte
# (fixed timestamps, deterministic Ed25519). Every line of
# examples/cedar/TRANSCRIPT.md is captured from what these commands print.
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT=examples/cedar/out
T=examples/cedar/TRANSCRIPT.md
KEY="--key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-20T02:00:00Z"
REG=examples/keys/registry.json
# cedarpy 4.8.7 agreed with the whole conformance corpus (examples/cedar/conformance/cedarpy-4.8.7.json,
# from tools/cedar_engine_drift.py), so the records name it as established (SPEC §8).
EST="--established-version cedarpy-4.8.7=$(python3 tools/cedar_engine_drift.py digest examples/cedar/conformance/cedarpy-4.8.7.json)"
mkdir -p "$OUT"; rm -rf "$OUT"/toolcalls-* "$OUT"/conformance-handwritten
{
  echo "# Transcript: execution-time decisions under Cedar"
  echo
  echo "Captured by \`bash examples/cedar/run.sh\`. Commands as run, output as printed, exit codes as returned. Engine: $(python3 -c 'import importlib.metadata as m; print("cedarpy", m.version("cedarpy"))')."
  echo
} > "$T"
show() {
  echo '```' >> "$T"; echo "\$ $*" >> "$T"
  set +e; "$@" >> "$T" 2>&1; rc=$?; set -e
  echo "[exit $rc]" >> "$T"; echo '```' >> "$T"; echo >> "$T"
}
python3 examples/cedar/build_inputs.py > /dev/null
python3 examples/cedar/build_conformance_inputs.py > /dev/null

echo "## 1. The calls, entities as the caller asserts them, arguments as given" >> "$T"; echo >> "$T"
show python3 -m emitters.cedar --policy examples/cedar/policy-caller.json --inputs examples/cedar/inputs-toolcalls.jsonl --out $OUT/toolcalls-caller --record-id cedar-toolcalls-caller-2026-10-20 --profile benchmark $KEY $EST
show python3 -m dr.verify $OUT/toolcalls-caller --registry $REG --replay emitters.cedar

echo "## 2. The calls, entities from the gate's own store, arguments as given" >> "$T"; echo >> "$T"
show python3 -m emitters.cedar --policy examples/cedar/policy-store.json --inputs examples/cedar/inputs-toolcalls.jsonl --out $OUT/toolcalls-store --record-id cedar-toolcalls-store-2026-10-20 --profile benchmark $KEY $EST
show python3 -m dr.verify $OUT/toolcalls-store --registry $REG --replay emitters.cedar

echo "## 3. The calls, entities from the store, arguments canonicalised first" >> "$T"; echo >> "$T"
show python3 -m emitters.cedar --policy examples/cedar/policy-canonical.json --inputs examples/cedar/inputs-toolcalls.jsonl --out $OUT/toolcalls-canonical --record-id cedar-toolcalls-canonical-2026-10-20 --profile benchmark $KEY $EST
show python3 -m dr.verify $OUT/toolcalls-canonical --registry $REG --replay emitters.cedar

echo "## 3b. Where each run disagrees with the author's intent" >> "$T"; echo >> "$T"
show python3 examples/cedar/compare.py examples/cedar/inputs-toolcalls.jsonl $OUT/toolcalls-caller $OUT/toolcalls-store $OUT/toolcalls-canonical

echo "## 4. A changed policy is a different decider: replay against a one-line change" >> "$T"; echo >> "$T"
python3 - <<'PY'
import json; p=json.load(open("examples/cedar/policy-canonical.json")); p["policies"]=p["policies"].replace("context.amount <= 1000", "context.amount <= 100000"); json.dump(p, open("examples/cedar/out/policy-limit-changed.json","w"), indent=1, sort_keys=True)
PY
show python3 examples/cedar/replay_with.py $OUT/toolcalls-canonical $OUT/policy-limit-changed.json

echo "## 5. Cedar's own conformance corpus, hand-written part, as a record" >> "$T"; echo >> "$T"
show python3 -m emitters.cedar_conformance --policy examples/cedar/policy-conformance-handwritten.json --inputs examples/cedar/inputs-conformance-handwritten.jsonl --out $OUT/conformance-handwritten --record-id cedar-conformance-handwritten-2026-10-20 --profile benchmark $KEY $EST
show python3 -m dr.verify $OUT/conformance-handwritten --registry $REG --replay emitters.cedar_conformance
rm -f $OUT/policy-limit-changed.json
