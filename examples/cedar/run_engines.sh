#!/usr/bin/env bash
# The same records under other Cedar engines: what naming an established
# version accepts, what it refuses, and what a false name costs.
#
#   bash examples/cedar/run_engines.sh <python-with-cedarpy-4.8.7> <python-with-cedarpy-4.1.0>
#
# Each interpreter needs cedarpy at that version and cryptography. Needs the
# conformance corpus (CEDAR_DRT_ROOT) for the sample record's replay. Writes
# examples/cedar/ENGINES.md from what the commands print; the records
# themselves are the committed ones from run.sh and run_drt.sh, plus two
# throwaway records written here and removed.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${CEDAR_DRT_ROOT:?set CEDAR_DRT_ROOT to the directory tools/fetch_cedar_drt.py printed}"
PY487=$1; PY410=$2
OUT=examples/cedar/out
T=examples/cedar/ENGINES.md
KEY="--key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-20T02:00:00Z"
REG=examples/keys/registry.json
EV=examples/cedar/conformance
ver() { "$1" -c 'import importlib.metadata as m; print("cedarpy", m.version("cedarpy"))'; }
{
  echo "# Transcript: the same records under other engines"
  echo
  echo "Captured by \`bash examples/cedar/run_engines.sh\`. Interpreters: \$PY487 = $(ver "$PY487"), \$PY410 = $(ver "$PY410"); the records were made under $(ver python3). Output as printed, exit codes as returned."
  echo
} > "$T"
show() {
  local line="$*"; line="${line//$PY487/\$PY487}"; line="${line//$PY410/\$PY410}"
  echo '```' >> "$T"; echo "\$ $line" >> "$T"
  set +e; "$@" >> "$T" 2>&1; rc=$?; set -e
  echo "[exit $rc]" >> "$T"; echo '```' >> "$T"; echo >> "$T"
}
note() { echo "$1" >> "$T"; echo >> "$T"; }

note "## 1. An engine the record names as established: accepted, and checked when its run is supplied"
note "The records name cedarpy-4.8.7 with the digest of its conformance run (\`$EV/cedarpy-4.8.7.json\`, 45,416 of 45,416)."
show "$PY487" -m dr.verify $OUT/toolcalls-canonical --registry $REG --replay emitters.cedar --conformance-evidence $EV/cedarpy-4.8.7.json
show "$PY487" -m dr.verify $OUT/conformance-drt-sample --registry $REG --replay emitters.cedar_conformance --conformance-evidence $EV/cedarpy-4.8.7.json
note "Without the run supplied the name is accepted on the producer's word, which is what the record's own version is too:"
show "$PY487" -m dr.verify $OUT/toolcalls-canonical --registry $REG --replay emitters.cedar

note "## 2. An engine the record does not name: refused before any decision is recomputed"
show "$PY410" -m dr.verify $OUT/toolcalls-canonical --registry $REG --replay emitters.cedar
show "$PY410" -m dr.verify $OUT/conformance-drt-sample --registry $REG --replay emitters.cedar_conformance

note "## 3. The cost of naming: a record that names cedarpy-4.1.0, which did not agree with the corpus"
note "The producer names 4.1.0 with the digest of 4.1.0's own run (25,188 of 45,416). With that run supplied the verifier refuses the name; without it, the name is taken and the drift is caught only where the rows differ."
D410=$("python3" tools/cedar_engine_drift.py digest $EV/cedarpy-4.1.0.json)
python3 -m emitters.cedar --policy examples/cedar/policy-canonical.json --inputs examples/cedar/inputs-toolcalls.jsonl --out $OUT/tmp-names-410 --record-id cedar-toolcalls-names-410 --profile benchmark $KEY --established-version cedarpy-4.1.0=$D410 > /dev/null
python3 -m emitters.cedar_conformance --policy examples/cedar/policy-conformance-drt.json --inputs examples/cedar/inputs-conformance-drt.jsonl --out $OUT/tmp-drt-names-410 --record-id cedar-conformance-drt-names-410 --profile benchmark $KEY --established-version cedarpy-4.1.0=$D410 > /dev/null
show "$PY410" -m dr.verify $OUT/tmp-names-410 --registry $REG --replay emitters.cedar --conformance-evidence $EV/cedarpy-4.1.0.json
show "$PY410" -m dr.verify $OUT/tmp-names-410 --registry $REG --replay emitters.cedar
show "$PY410" -m dr.verify $OUT/tmp-drt-names-410 --registry $REG --replay emitters.cedar_conformance
rm -rf $OUT/tmp-names-410 $OUT/tmp-drt-names-410
echo "wrote $T"
