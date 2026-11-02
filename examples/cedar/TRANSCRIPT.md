# Transcript: execution-time decisions under Cedar

Captured by `bash examples/cedar/run.sh`. Commands as run, output as printed, exit codes as returned. Engine: cedarpy 4.12.2.

## 1. The calls, entities as the caller asserts them, arguments as given

```
$ python3 -m emitters.cedar --policy examples/cedar/policy-caller.json --inputs examples/cedar/inputs-toolcalls.jsonl --out examples/cedar/out/toolcalls-caller --record-id cedar-toolcalls-caller-2026-10-20 --profile benchmark --key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-20T02:00:00Z --established-version cedarpy-4.8.7=sha256:d9c811235bbd80f3951e26f4f7a8f60dd73247affa034bbd6cbc210f1e26683c
wrote examples/cedar/out/toolcalls-caller/record.json (40 decisions)
[exit 0]
```

```
$ python3 -m dr.verify examples/cedar/out/toolcalls-caller --registry examples/keys/registry.json --replay emitters.cedar
examples/cedar/out/toolcalls-caller

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          40 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      40 rows written, by outcome {'ALLOW': 11, 'DENY': 29}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    30 of 40 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  OK      replay         re-deciding all 40 retained inputs with cedar-authorizer@cedarpy-4.12.2 reproduced every outcome and reason
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 40 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
[exit 0]
```

## 2. The calls, entities from the gate's own store, arguments as given

```
$ python3 -m emitters.cedar --policy examples/cedar/policy-store.json --inputs examples/cedar/inputs-toolcalls.jsonl --out examples/cedar/out/toolcalls-store --record-id cedar-toolcalls-store-2026-10-20 --profile benchmark --key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-20T02:00:00Z --established-version cedarpy-4.8.7=sha256:d9c811235bbd80f3951e26f4f7a8f60dd73247affa034bbd6cbc210f1e26683c
wrote examples/cedar/out/toolcalls-store/record.json (40 decisions)
[exit 0]
```

```
$ python3 -m dr.verify examples/cedar/out/toolcalls-store --registry examples/keys/registry.json --replay emitters.cedar
examples/cedar/out/toolcalls-store

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          40 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      40 rows written, by outcome {'ALLOW': 10, 'DENY': 30}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    31 of 40 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  OK      replay         re-deciding all 40 retained inputs with cedar-authorizer@cedarpy-4.12.2 reproduced every outcome and reason
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 40 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
[exit 0]
```

## 3. The calls, entities from the store, arguments canonicalised first

```
$ python3 -m emitters.cedar --policy examples/cedar/policy-canonical.json --inputs examples/cedar/inputs-toolcalls.jsonl --out examples/cedar/out/toolcalls-canonical --record-id cedar-toolcalls-canonical-2026-10-20 --profile benchmark --key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-20T02:00:00Z --established-version cedarpy-4.8.7=sha256:d9c811235bbd80f3951e26f4f7a8f60dd73247affa034bbd6cbc210f1e26683c
wrote examples/cedar/out/toolcalls-canonical/record.json (40 decisions)
[exit 0]
```

```
$ python3 -m dr.verify examples/cedar/out/toolcalls-canonical --registry examples/keys/registry.json --replay emitters.cedar
examples/cedar/out/toolcalls-canonical

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          40 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      40 rows written, by outcome {'ALLOW': 16, 'DENY': 24}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    39 of 40 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  OK      replay         re-deciding all 40 retained inputs with cedar-authorizer@cedarpy-4.12.2 reproduced every outcome and reason
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 40 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
[exit 0]
```

## 3b. Where each run disagrees with the author's intent

```
$ python3 examples/cedar/compare.py examples/cedar/inputs-toolcalls.jsonl examples/cedar/out/toolcalls-caller examples/cedar/out/toolcalls-store examples/cedar/out/toolcalls-canonical
 #  kind        intent caller    store     canonical note
22  adversarial ALLOW  DENY      DENY      ALLOW     upper-cased allow-listed host: as given, the store has no such id
23  adversarial ALLOW  DENY      DENY      ALLOW     trailing-dot FQDN of an allow-listed host
26  adversarial ALLOW  DENY      DENY      ALLOW     scheme case on an allow-listed host: the policy compares the string as given
27  adversarial DENY   ALLOW     DENY      DENY      caller-asserted entity: the caller says the host is allow-listed
29  adversarial DENY   ALLOW     ALLOW     DENY      percent-encoded traversal: no literal .. for p5, and p3's prefix matches
30  adversarial ALLOW  DENY      DENY      ALLOW     a benign path that contains ..: p5 forbids it raw
32  adversarial ALLOW  DENY      DENY      ALLOW     trailing dot on the tenant domain
33  adversarial ALLOW  DENY      DENY      ALLOW     upper-cased tenant domain
35  adversarial ALLOW  DENY      DENY      ALLOW     lower-cased currency
37  adversarial DENY   ALLOW     ALLOW     ALLOW     negative amount is <= 1000: p7 permits it; the policy has no lower bound

caller: 30 of 40 match intent; adversarial 9 of 19
store: 31 of 40 match intent; adversarial 10 of 19
canonical: 39 of 40 match intent; adversarial 18 of 19
[exit 0]
```

## 4. A changed policy is a different decider: replay against a one-line change

```
$ python3 examples/cedar/replay_with.py examples/cedar/out/toolcalls-canonical examples/cedar/out/policy-limit-changed.json
changed policy: 1 of 40 rows decide differently: [(18, 'DENY', 'ALLOW')]
policy digest in the record sha256:bb9bf7984e68c…, changed policy sha256:ae393af61702b…: the record names a policy the changed one is not
[exit 0]
```

## 5. Cedar's own conformance corpus, hand-written part, as a record

```
$ python3 -m emitters.cedar_conformance --policy examples/cedar/policy-conformance-handwritten.json --inputs examples/cedar/inputs-conformance-handwritten.jsonl --out examples/cedar/out/conformance-handwritten --record-id cedar-conformance-handwritten-2026-10-20 --profile benchmark --key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-20T02:00:00Z --established-version cedarpy-4.8.7=sha256:d9c811235bbd80f3951e26f4f7a8f60dd73247affa034bbd6cbc210f1e26683c
wrote examples/cedar/out/conformance-handwritten/record.json (78 decisions)
[exit 0]
```

```
$ python3 -m dr.verify examples/cedar/out/conformance-handwritten --registry examples/keys/registry.json --replay emitters.cedar_conformance
examples/cedar/out/conformance-handwritten

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          78 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      78 rows written, by outcome {'ALLOW': 40, 'DENY': 38}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    78 of 78 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  OK      replay         re-deciding all 78 retained inputs with cedar-conformance@cedarpy-4.12.2 reproduced every outcome and reason
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 78 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
[exit 0]
```

