#!/usr/bin/env bash
# The acceptance procedure: how to refuse this record.
#
#   bash examples/acceptance/run.sh
#
# One record is made and verified; then thirteen things are done to it, or to what
# is supplied with it, and the verifier is run each time; the last three are what
# an attester in front of the producer does and does not add. Every line of
# examples/acceptance/ACCEPTANCE.md and every file under examples/acceptance/out/
# is captured from what the commands print; nothing is composed by hand, and
# tests/test_acceptance.py re-runs this script and refuses on any drift.
set -euo pipefail
cd "$(dirname "$0")/../.."
A=examples/acceptance
OUT=$A/out
T=$A/ACCEPTANCE.md
REG=examples/keys/registry.json
KEY="--key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-21T03:00:00Z"
DKEY="--decider-key examples/keys/decider-key.pem --decider-key-id example-decider-2026-10"
VERIFY="python3 -m dr.verify"
rm -rf "$OUT"; mkdir -p "$OUT"
{
  echo "# How to refuse this record"
  echo
  echo "Captured by \`bash examples/acceptance/run.sh\`: each command as run, the verifier's lines that are not established, and its verdict and exit code. The verifier's full output for every step is under \`examples/acceptance/out/\`. A hand-written expected output appears nowhere in this file."
  echo
} > "$T"
n=0
step() {  # step "<title>" "<what was done>" command...   — captures full output to out/NN.txt, shows the refusing lines
  n=$((n+1)); local title="$1" what="$2"; shift 2
  local f; f=$(printf "%s/%02d.txt" "$OUT" "$n")
  echo "## $n. $title" >> "$T"; echo >> "$T"
  [ -n "$what" ] && { echo "$what" >> "$T"; echo >> "$T"; }
  echo '```' >> "$T"; echo "\$ $*" >> "$T"
  set +e; "$@" > "$f" 2>&1; rc=$?; set -e
  grep -E "^  (FAILED|UNKNOWN)|^VERDICT" "$f" >> "$T" || true
  echo "[exit $rc]" >> "$T"; echo '```' >> "$T"; echo >> "$T"
}
quiet() { "$@" > /dev/null; }

# --- the record: the tool gate over an hour of traffic, decider attestations, receipts
quiet python3 -m emitters.toolgate --policy examples/data/toolgate-policy.json --inputs examples/data/toolgate-traffic-hour1.jsonl --out $OUT/record --record-id acceptance-2026-10-21 --stream acceptance:1 --receipts $OUT/receipts $KEY $DKEY

step "The record as issued" "Verified with replay under the named decider and with the decider's own key registry: every applicable property established." \
  $VERIFY $OUT/record --registry $REG --replay emitters.toolgate --decider-registry examples/keys/deciders.json

cp -r $OUT/record $OUT/tampered-row
quiet python3 $A/forge.py tamper-row $OUT/tampered-row 4
step "A row edited on disk" "Row 4's outcome flipped from what the decider said; nothing else touched." \
  $VERIFY $OUT/tampered-row --registry $REG --replay emitters.toolgate --decider-registry examples/keys/deciders.json

cp -r $OUT/record $OUT/forged-attestation
quiet python3 $A/forge.py forge-attestation $OUT/forged-attestation 2
quiet python3 $A/forge.py resign $OUT/forged-attestation examples/keys/example-signing-key.pem
step "A decider attestation edited, and the record re-signed by the producer" "The decision inside the attestation for row 2 flipped, the retained digests recomputed and the record signed again with the producer's key, which the producer holds. The attestation's own signature is the decider's and cannot be re-made." \
  $VERIFY $OUT/forged-attestation --registry $REG --replay emitters.toolgate --decider-registry examples/keys/deciders.json

step "A different engine supplied for replay" "The record names toolgate@1.0.0; the module supplied is toolgate@9.9.9 (examples/acceptance/other_toolgate.py), which decides one tool the other way." \
  $VERIFY $OUT/record --registry $REG --replay examples.acceptance.other_toolgate --decider-registry examples/keys/deciders.json

quiet python3 tools/truncate.py $OUT/record $OUT/truncated-interior --drop 3,7 --key examples/keys/example-signing-key.pem
step "Rows deleted from the middle, the chain recomputed, the record re-signed by the producer" "Rows 3 and 7 removed and the rest renumbered. The decider's attestations are bound to the sequence numbers the decider was told, and the producer cannot re-make them." \
  $VERIFY $OUT/truncated-interior --registry $REG --replay emitters.toolgate --decider-registry examples/keys/deciders.json
quiet python3 tools/truncate.py $OUT/record $OUT/truncated --drop 19,20 --key examples/keys/example-signing-key.pem
quiet python3 $A/forge.py drop-attestations $OUT/truncated 19 20
quiet python3 $A/forge.py resign $OUT/truncated examples/keys/example-signing-key.pem
step "The last rows deleted, their attestations dropped, the record re-signed by the producer" "Rows 19 and 20 removed from the tail with their attestations, the chain recomputed, the counts re-derived, the record signed again. Every property the record can carry holds — this is the limit, not a refusal: a self-signed record cannot say it is complete." \
  $VERIFY $OUT/truncated --registry $REG --replay emitters.toolgate --decider-registry examples/keys/deciders.json
step "… and the same record against a receipt the producer issued for a deleted row" "The receipt for decision 20 was handed to the party the decision was about, at decision time; the record no longer contains row 20." \
  $VERIFY $OUT/truncated --registry $REG --decider-registry examples/keys/deciders.json --receipt $OUT/receipts/receipt-000020.json

EVD=$(python3 $A/forge.py evidence $OUT/evidence-partial.json 9.9.9 1000 900)
quiet python3 -m emitters.toolgate --policy examples/data/toolgate-policy.json --inputs examples/data/toolgate-traffic-hour1.jsonl --out $OUT/names-9.9.9 --record-id acceptance-names-2026-10-21 $KEY --established-version 9.9.9=$EVD
step "A record that names a version its conformance run did not establish, with the run supplied" "The record names toolgate@9.9.9 as established, by the digest of a run that reports 900 of 1000; the run is supplied." \
  $VERIFY $OUT/names-9.9.9 --registry $REG --replay examples.acceptance.other_toolgate --conformance-evidence $OUT/evidence-partial.json
step "… the same record with the run not supplied" "The name is taken on the producer's word; the drifted engine is then caught by recomputation at the first row that exercises the difference." \
  $VERIFY $OUT/names-9.9.9 --registry $REG --replay examples.acceptance.other_toolgate

EVX=$(python3 $A/forge.py evidence $OUT/evidence-excluded.json 9.9.9 1000 900 case-a case-b case-c)
quiet python3 -m emitters.toolgate --policy examples/data/toolgate-policy.json --inputs examples/data/toolgate-traffic-hour1.jsonl --out $OUT/names-9.9.9-excluded --record-id acceptance-excluded-2026-10-21 $KEY --established-version 9.9.9=$EVX
step "An exclusion list that does not close the gap" "The supplied run reports 900 of 1000 and names three excluded cases; 900 is not 1000 less 3." \
  $VERIFY $OUT/names-9.9.9-excluded --registry $REG --replay examples.acceptance.other_toolgate --conformance-evidence $OUT/evidence-excluded.json

quiet python3 -m dr.witness $OUT/record/record.json --key examples/keys/example-signing-key.pem --key-id independent-auditor-2026-10 --witnessed-at 2026-10-21T03:05:00Z --out $OUT/self-witness.json
step "The producer's own key enrolled as a witness" "A witness statement signed with the producer's signing key, under a witness registry that lists that key as 'independent-auditor-2026-10'." \
  $VERIFY $OUT/record --registry $REG --decider-registry examples/keys/deciders.json --witness $OUT/self-witness.json --witness-registry examples/keys/witnesses-with-producer-key.json


# --- what the record cannot see, and what an attester in front of it adds
step "An input replaced before the decision, decided honestly, under the plain verifier" "The fifth alteration of experiments/rederivability: the producer replaced one retained input with a benign one and decided it honestly; every property the record can carry holds, with replay or without. This is the roof of a self-signed record, not a refusal: nothing in it says what arrived." \
  $VERIFY experiments/rederivability/out/f5-input-fabricated --registry experiments/rederivability/out/registry.json --decider-registry experiments/rederivability/out/deciders.json

quiet python3 $A/attested.py fabricated $OUT/fabricated
step "The same alteration with an attester in front of the producer" "The tool gate over the same hour with an attester signing each input as it arrives (examples/acceptance/attested.py, fixed test keys); the producer replaced input 4 after the attester had signed it and decided the replacement honestly. The row names arrival 4; the attester signed a different input under that number." \
  python3 tools/verify_arrival.py $OUT/fabricated --registry $OUT/fabricated.producer.json --decider-registry $OUT/fabricated.decider.json --attester-registry $OUT/fabricated.attester.json --arrival-log $OUT/fabricated.attester-log.jsonl

quiet python3 $A/attested.py gated $OUT/gated
step "An input sent round the attester, under a policy that requires arrival" "The policy carries {\"arrival\": \"required\"}; input 4 reached the gate with no arrival and the gate refused it (examples/acceptance/out/gated.refused.txt), writing nothing. The verifier establishes the 19 rows that remain and accounts for arrivals 1 to 19. The pass is correct silence: the record says nothing about the refused input, the attester's log does not have it either, and the gate is what kept the record from saying something false about it." \
  python3 tools/verify_arrival.py $OUT/gated --registry $OUT/gated.producer.json --decider-registry $OUT/gated.decider.json --attester-registry $OUT/gated.attester.json --arrival-log $OUT/gated.attester-log.jsonl

echo "wrote $T"
