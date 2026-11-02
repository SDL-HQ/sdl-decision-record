# Transcript: the same records under other engines

Captured by `bash examples/cedar/run_engines.sh`. Interpreters: $PY487 = cedarpy 4.8.7, $PY410 = cedarpy 4.1.0; the records were made under cedarpy 4.12.2. Output as printed, exit codes as returned.

## 1. An engine the record names as established: accepted, and checked when its run is supplied

The records name cedarpy-4.8.7 with the digest of its conformance run (`examples/cedar/conformance/cedarpy-4.8.7.json`, 45,416 of 45,416).

```
$ $PY487 -m dr.verify examples/cedar/out/toolcalls-canonical --registry examples/keys/registry.json --replay emitters.cedar --conformance-evidence examples/cedar/conformance/cedarpy-4.8.7.json
examples/cedar/out/toolcalls-canonical

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          40 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      40 rows written, by outcome {'ALLOW': 16, 'DENY': 24}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    39 of 40 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  OK      replay         re-deciding all 40 retained inputs with cedar-authorizer@cedarpy-4.8.7 reproduced every outcome and reason; under cedar-authorizer@cedarpy-4.8.7, which the record names as established by a conformance run (45416 of 45416; cedarpy-4.8.7.json, digest matches)
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 40 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
[exit 0]
```

```
$ $PY487 -m dr.verify examples/cedar/out/conformance-drt-sample --registry examples/keys/registry.json --replay emitters.cedar_conformance --conformance-evidence examples/cedar/conformance/cedarpy-4.8.7.json
examples/cedar/out/conformance-drt-sample

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          2400 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      2400 rows written, by outcome {'ALLOW': 1394, 'DENY': 1006}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    2400 of 2400 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  OK      replay         re-deciding all 2400 retained inputs with cedar-conformance@cedarpy-4.8.7 reproduced every outcome and reason; under cedar-conformance@cedarpy-4.8.7, which the record names as established by a conformance run (45416 of 45416; cedarpy-4.8.7.json, digest matches)
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 2400 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
[exit 0]
```

Without the run supplied the name is accepted on the producer's word, which is what the record's own version is too:

```
$ $PY487 -m dr.verify examples/cedar/out/toolcalls-canonical --registry examples/keys/registry.json --replay emitters.cedar
examples/cedar/out/toolcalls-canonical

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          40 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      40 rows written, by outcome {'ALLOW': 16, 'DENY': 24}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    39 of 40 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  OK      replay         re-deciding all 40 retained inputs with cedar-authorizer@cedarpy-4.8.7 reproduced every outcome and reason; under cedar-authorizer@cedarpy-4.8.7, which the record names as established by a conformance run (evidence sha256:d9c811235bbd…, not supplied; the producer's claim)
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 40 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
[exit 0]
```

## 2. An engine the record does not name: refused before any decision is recomputed

```
$ $PY410 -m dr.verify examples/cedar/out/toolcalls-canonical --registry examples/keys/registry.json --replay emitters.cedar
examples/cedar/out/toolcalls-canonical

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          40 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      40 rows written, by outcome {'ALLOW': 16, 'DENY': 24}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    39 of 40 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  UNKNOWN replay         the supplied decider is cedar-authorizer@cedarpy-4.1.0, the record names cedar-authorizer@cedarpy-4.12.2; replaying with a different procedure proves nothing
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 40 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: NOT ESTABLISHED
Nothing failed. At least one property could not be established, and an unestablished property is not one that holds.
[exit 1]
```

```
$ $PY410 -m dr.verify examples/cedar/out/conformance-drt-sample --registry examples/keys/registry.json --replay emitters.cedar_conformance
examples/cedar/out/conformance-drt-sample

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          2400 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      2400 rows written, by outcome {'ALLOW': 1394, 'DENY': 1006}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    2400 of 2400 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  UNKNOWN replay         the supplied decider is cedar-conformance@cedarpy-4.1.0, the record names cedar-conformance@cedarpy-4.12.2; replaying with a different procedure proves nothing
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 2400 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: NOT ESTABLISHED
Nothing failed. At least one property could not be established, and an unestablished property is not one that holds.
[exit 1]
```

## 3. The cost of naming: a record that names cedarpy-4.1.0, which did not agree with the corpus

The producer names 4.1.0 with the digest of 4.1.0's own run (25,188 of 45,416). With that run supplied the verifier refuses the name; without it, the name is taken and the drift is caught only where the rows differ.

```
$ $PY410 -m dr.verify examples/cedar/out/tmp-names-410 --registry examples/keys/registry.json --replay emitters.cedar --conformance-evidence examples/cedar/conformance/cedarpy-4.1.0.json
examples/cedar/out/tmp-names-410

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          40 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      40 rows written, by outcome {'ALLOW': 16, 'DENY': 24}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    39 of 40 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  UNKNOWN replay         cedar-authorizer@cedarpy-4.1.0 is named as established by sha256:617c68feb5d8c47addf6bfae7824152765d753f4be20fe033d2e1e285829a7cc, and that result reports 25188 of 45416 with 0 excluded for engine 'cedarpy-4.1.0'; the name is not supported
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 40 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: NOT ESTABLISHED
Nothing failed. At least one property could not be established, and an unestablished property is not one that holds.
[exit 1]
```

```
$ $PY410 -m dr.verify examples/cedar/out/tmp-names-410 --registry examples/keys/registry.json --replay emitters.cedar
examples/cedar/out/tmp-names-410

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          40 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      40 rows written, by outcome {'ALLOW': 16, 'DENY': 24}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    39 of 40 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  UNKNOWN replay         the decider raised while replaying, so replay could not be completed: module 'cedarpy' has no attribute 'validate_policies'
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 40 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: NOT ESTABLISHED
Nothing failed. At least one property could not be established, and an unestablished property is not one that holds.
[exit 1]
```

```
$ $PY410 -m dr.verify examples/cedar/out/tmp-drt-names-410 --registry examples/keys/registry.json --replay emitters.cedar_conformance
failed to parse schema from request: extension function `duration` does not exist
examples/cedar/out/tmp-drt-names-410

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          2400 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      2400 rows written, by outcome {'ALLOW': 1394, 'DENY': 1006}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    2400 of 2400 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  FAILED  replay         seq 1: replay gives ('DENY', 'request-invalid'), the row records ('ALLOW', 'policy0')
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 2400 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: FAILED
[exit 2]
```

