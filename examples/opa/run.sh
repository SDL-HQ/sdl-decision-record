#!/usr/bin/env bash
# The OPA/Rego decider built from the "Other grammars" paragraph: the forty
# calls under three settings, and OPA's own test corpus as a record.
#
#   OPA_BIN=/path/to/opa OPA_TESTDATA_ROOT=$(python3 tools/fetch_opa_testdata.py | tail -1) bash examples/opa/run.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${OPA_BIN:?set OPA_BIN to an opa binary}"
: "${OPA_TESTDATA_ROOT:?set OPA_TESTDATA_ROOT (tools/fetch_opa_testdata.py)}"
OUT=examples/opa/out
T=examples/opa/TRANSCRIPT.md
KEY="--key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-21T01:00:00Z"
REG=examples/keys/registry.json
mkdir -p "$OUT"; rm -rf "$OUT"/toolcalls-* "$OUT"/conformance-sample
{
  echo "# Transcript: the OPA/Rego decider"
  echo
  echo "Captured by \`bash examples/opa/run.sh\`. Engine: $($OPA_BIN version | sed -n 1p). Commands as run, output as printed, exit codes as returned."
  echo
} > "$T"
show() {
  local line="$*"; line="${line//$OPA_BIN/\$OPA_BIN}"
  for b in ${OPA_BINS_OTHER:-}; do line="${line//$b/<opa $($b version | sed -n '1s/Version: //p')>}"; done
  echo '```' >> "$T"; echo "\$ $line" >> "$T"
  set +e; "$@" >> "$T" 2>&1; rc=$?; set -e
  echo "[exit $rc]" >> "$T"; echo '```' >> "$T"; echo >> "$T"
}
python3 examples/opa/build_inputs.py > /dev/null
python3 examples/opa/build_conformance_inputs.py --sample 400 --seed 1 > /dev/null

echo "## 1. The forty calls of the Cedar example, under the Rego translation of its eight policies, three settings" >> "$T"; echo >> "$T"
for n in caller store canonical; do
  show python3 -m emitters.opa --policy examples/opa/policy-$n.json --inputs examples/cedar/inputs-toolcalls.jsonl --out $OUT/toolcalls-$n --record-id opa-toolcalls-$n-2026-10-21 --profile benchmark $KEY
done
show python3 -m dr.verify $OUT/toolcalls-canonical --registry $REG --replay emitters.opa
show python3 examples/cedar/compare.py examples/cedar/inputs-toolcalls.jsonl $OUT/toolcalls-caller $OUT/toolcalls-store $OUT/toolcalls-canonical

echo "## 2. Row by row against the Cedar records over the same calls" >> "$T"; echo >> "$T"
show python3 examples/opa/compare_with_cedar.py

echo "## 3. A policy that uses a non-deterministic builtin is refused at construction" >> "$T"; echo >> "$T"
show python3 examples/opa/refusals.py

echo "## 4. OPA's own test corpus: a seeded sample of 400 cases as a record" >> "$T"; echo >> "$T"
show python3 -m emitters.opa_conformance --policy examples/opa/policy-conformance.json --inputs examples/opa/inputs-conformance.jsonl --out $OUT/conformance-sample --record-id opa-conformance-sample-2026-10-21 --profile benchmark $KEY
show python3 -m dr.verify $OUT/conformance-sample --registry $REG --replay emitters.opa_conformance
echo "## 5. The established-versions rule against OPA's own corpus runs (G18)" >> "$T"; echo >> "$T"
show python3 examples/opa/evidence_check.py
echo "## 6. Is the engine's explanation a deterministic reason?" >> "$T"; echo >> "$T"
show python3 examples/opa/explain_stability.py $OPA_BIN ${OPA_BINS_OTHER:-}
echo "wrote $T"
