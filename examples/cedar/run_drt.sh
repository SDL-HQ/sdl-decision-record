#!/usr/bin/env bash
# The generated conformance corpus: the full run as figures, a seeded sample as a record.
# Needs the corpus fetched outside the repository (tools/fetch_cedar_drt.py) and CEDAR_DRT_ROOT set.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${CEDAR_DRT_ROOT:?set CEDAR_DRT_ROOT to the directory tools/fetch_cedar_drt.py printed}"
OUT=examples/cedar/out
KEY="--key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-20T02:00:00Z"
REG=examples/keys/registry.json
# cedarpy 4.8.7 agreed with the whole conformance corpus (examples/cedar/conformance/cedarpy-4.8.7.json,
# from tools/cedar_engine_drift.py), so the records name it as established (SPEC §8).
EST="--established-version cedarpy-4.8.7=$(python3 tools/cedar_engine_drift.py digest examples/cedar/conformance/cedarpy-4.8.7.json)"
python3 tools/cedar_conformance.py
python3 examples/cedar/build_conformance_inputs.py --drt "$CEDAR_DRT_ROOT" --sample 300 --seed 1
rm -rf $OUT/conformance-drt-sample
python3 -m emitters.cedar_conformance --policy examples/cedar/policy-conformance-drt.json --inputs examples/cedar/inputs-conformance-drt.jsonl --out $OUT/conformance-drt-sample --record-id cedar-conformance-drt-sample-2026-10-20 --profile benchmark $KEY $EST
python3 -m dr.verify $OUT/conformance-drt-sample --registry $REG --replay emitters.cedar_conformance
