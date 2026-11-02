# How to refuse this record

Captured by `bash examples/acceptance/run.sh`: each command as run, the verifier's lines that are not established, and its verdict and exit code. The verifier's full output for every step is under `examples/acceptance/out/`. A hand-written expected output appears nowhere in this file.

## 1. The record as issued

Verified with replay under the named decider and with the decider's own key registry: every applicable property established.

```
$ python3 -m dr.verify examples/acceptance/out/record --registry examples/keys/registry.json --replay emitters.toolgate --decider-registry examples/keys/deciders.json
VERDICT: ESTABLISHED
[exit 0]
```

## 2. A row edited on disk

Row 4's outcome flipped from what the decider said; nothing else touched.

```
$ python3 -m dr.verify examples/acceptance/out/tampered-row --registry examples/keys/registry.json --replay emitters.toolgate --decider-registry examples/keys/deciders.json
  FAILED  chain          row 4: row_hash does not re-derive (stored 'sha256:ac1bbde70de85ec58a2e64fa719dab4c1fb4577cccd56942b6ce3f6ee1dcb2ac', computed 'sha256:825900f99529499419ed5d04a2622c2a8afb2f2e3b115e9e077c94a869ba1aab')
  UNKNOWN decisions      not computed: the rows were not established
  UNKNOWN profile        not computed: the rows were not established
  UNKNOWN correctness    not computed: the rows were not established
  UNKNOWN retained       not computed: the rows were not established
  UNKNOWN replay         not computed: the rows were not established
  UNKNOWN invocation     not computed: the rows were not established
  UNKNOWN stream         not computed: the rows were not established
  UNKNOWN completeness   not computed: the rows were not established
  UNKNOWN receipts       not computed: the rows were not established
  UNKNOWN witness        not computed: the rows were not established
VERDICT: FAILED
[exit 2]
```

## 3. A decider attestation edited, and the record re-signed by the producer

The decision inside the attestation for row 2 flipped, the retained digests recomputed and the record signed again with the producer's key, which the producer holds. The attestation's own signature is the decider's and cannot be re-made.

```
$ python3 -m dr.verify examples/acceptance/out/forged-attestation --registry examples/keys/registry.json --replay emitters.toolgate --decider-registry examples/keys/deciders.json
  FAILED  invocation     seq 2: the attestation does not match the row on ['outcome']; the row is not what the decider signed
VERDICT: FAILED
[exit 2]
```

## 4. A different engine supplied for replay

The record names toolgate@1.0.0; the module supplied is toolgate@9.9.9 (examples/acceptance/other_toolgate.py), which decides one tool the other way.

```
$ python3 -m dr.verify examples/acceptance/out/record --registry examples/keys/registry.json --replay examples.acceptance.other_toolgate --decider-registry examples/keys/deciders.json
  UNKNOWN replay         the supplied decider is toolgate@9.9.9, the record names toolgate@1.0.0; replaying with a different procedure proves nothing
VERDICT: NOT ESTABLISHED
[exit 1]
```

## 5. Rows deleted from the middle, the chain recomputed, the record re-signed by the producer

Rows 3 and 7 removed and the rest renumbered. The decider's attestations are bound to the sequence numbers the decider was told, and the producer cannot re-make them.

```
$ python3 -m dr.verify examples/acceptance/out/truncated-interior --registry examples/keys/registry.json --replay emitters.toolgate --decider-registry examples/keys/deciders.json
  FAILED  invocation     attestations for seq [19, 20] name decisions the record does not have
VERDICT: FAILED
[exit 2]
```

## 6. The last rows deleted, their attestations dropped, the record re-signed by the producer

Rows 19 and 20 removed from the tail with their attestations, the chain recomputed, the counts re-derived, the record signed again. Every property the record can carry holds — this is the limit, not a refusal: a self-signed record cannot say it is complete.

```
$ python3 -m dr.verify examples/acceptance/out/truncated --registry examples/keys/registry.json --replay emitters.toolgate --decider-registry examples/keys/deciders.json
VERDICT: ESTABLISHED
[exit 0]
```

## 7. … and the same record against a receipt the producer issued for a deleted row

The receipt for decision 20 was handed to the party the decision was about, at decision time; the record no longer contains row 20.

```
$ python3 -m dr.verify examples/acceptance/out/truncated --registry examples/keys/registry.json --decider-registry examples/keys/deciders.json --receipt examples/acceptance/out/receipts/receipt-000020.json
  FAILED  completeness   refuted: the producer signed a receipt for decision seq 20 of this run and the record has 18 rows, so at least 2 acknowledged decision(s) are not in it
  FAILED  receipts       receipt-000020.json: the producer acknowledged decision seq 20 of this run at 2026-10-18T01:00:19Z; the record has 18 rows
VERDICT: FAILED
[exit 2]
```

## 8. A record that names a version its conformance run did not establish, with the run supplied

The record names toolgate@9.9.9 as established, by the digest of a run that reports 900 of 1000; the run is supplied.

```
$ python3 -m dr.verify examples/acceptance/out/names-9.9.9 --registry examples/keys/registry.json --replay examples.acceptance.other_toolgate --conformance-evidence examples/acceptance/out/evidence-partial.json
  UNKNOWN replay         toolgate@9.9.9 is named as established by sha256:07920f38ba198633898e071e210f0e6e8e9712daa7d5e2e902dc82fcadbfcb5a, and that result reports 900 of 1000 with 0 excluded for engine '9.9.9'; the name is not supported
VERDICT: NOT ESTABLISHED
[exit 1]
```

## 9. … the same record with the run not supplied

The name is taken on the producer's word; the drifted engine is then caught by recomputation at the first row that exercises the difference.

```
$ python3 -m dr.verify examples/acceptance/out/names-9.9.9 --registry examples/keys/registry.json --replay examples.acceptance.other_toolgate
  FAILED  replay         seq 1: replay gives ('DENY', 'drifted'), the row records ('ALLOW', None)
VERDICT: FAILED
[exit 2]
```

## 10. An exclusion list that does not close the gap

The supplied run reports 900 of 1000 and names three excluded cases; 900 is not 1000 less 3.

```
$ python3 -m dr.verify examples/acceptance/out/names-9.9.9-excluded --registry examples/keys/registry.json --replay examples.acceptance.other_toolgate --conformance-evidence examples/acceptance/out/evidence-excluded.json
  UNKNOWN replay         toolgate@9.9.9 is named as established by sha256:3e190c66a719a6e7af37abc309562e16f147886a428dab696426e2c90035df35, and that result reports 900 of 1000 with 3 excluded for engine '9.9.9'; the name is not supported
VERDICT: NOT ESTABLISHED
[exit 1]
```

## 11. The producer's own key enrolled as a witness

A witness statement signed with the producer's signing key, under a witness registry that lists that key as 'independent-auditor-2026-10'.

```
$ python3 -m dr.verify examples/acceptance/out/record --registry examples/keys/registry.json --decider-registry examples/keys/deciders.json --witness examples/acceptance/out/self-witness.json --witness-registry examples/keys/witnesses-with-producer-key.json
  UNKNOWN witness        witness key 'independent-auditor-2026-10' is also a producer key (as 'example-2026-10' in the producer registry); a producer witnessing itself establishes nothing
VERDICT: NOT ESTABLISHED
[exit 1]
```

## 12. An input replaced before the decision, decided honestly, under the plain verifier

The fifth alteration of experiments/rederivability: the producer replaced one retained input with a benign one and decided it honestly; every property the record can carry holds, with replay or without. This is the roof of a self-signed record, not a refusal: nothing in it says what arrived.

```
$ python3 -m dr.verify experiments/rederivability/out/f5-input-fabricated --registry experiments/rederivability/out/registry.json --decider-registry experiments/rederivability/out/deciders.json
VERDICT: ESTABLISHED
[exit 0]
```

## 13. The same alteration with an attester in front of the producer

The tool gate over the same hour with an attester signing each input as it arrives (examples/acceptance/attested.py, fixed test keys); the producer replaced input 4 after the attester had signed it and decided the replacement honestly. The row names arrival 4; the attester signed a different input under that number.

```
$ python3 tools/verify_arrival.py examples/acceptance/out/fabricated --registry examples/acceptance/out/fabricated.producer.json --decider-registry examples/acceptance/out/fabricated.decider.json --attester-registry examples/acceptance/out/fabricated.attester.json --arrival-log examples/acceptance/out/fabricated.attester-log.jsonl
  FAILED  arrival             seq 4: the retained input is not what arrived; arrival 4 was signed over a different input
  UNKNOWN arrivals_accounted  arrival is failed, so the range the rows name cannot be trusted
VERDICT: FAILED
[exit 2]
```

## 14. An input sent round the attester, under a policy that requires arrival

The policy carries {"arrival": "required"}; input 4 reached the gate with no arrival and the gate refused it (examples/acceptance/out/gated.refused.txt), writing nothing. The verifier establishes the 19 rows that remain and accounts for arrivals 1 to 19. The pass is correct silence: the record says nothing about the refused input, the attester's log does not have it either, and the gate is what kept the record from saying something false about it.

```
$ python3 tools/verify_arrival.py examples/acceptance/out/gated --registry examples/acceptance/out/gated.producer.json --decider-registry examples/acceptance/out/gated.decider.json --attester-registry examples/acceptance/out/gated.attester.json --arrival-log examples/acceptance/out/gated.attester-log.jsonl
VERDICT: ESTABLISHED
[exit 0]
```

