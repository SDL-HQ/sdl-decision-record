# Transcript: the OPA/Rego decider

Captured by `bash examples/opa/run.sh`. Engine: Version: 1.21.3. Commands as run, output as printed, exit codes as returned.

## 1. The forty calls of the Cedar example, under the Rego translation of its eight policies, three settings

```
$ python3 -m emitters.opa --policy examples/opa/policy-caller.json --inputs examples/cedar/inputs-toolcalls.jsonl --out examples/opa/out/toolcalls-caller --record-id opa-toolcalls-caller-2026-10-21 --profile benchmark --key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-21T01:00:00Z
wrote examples/opa/out/toolcalls-caller/record.json (40 decisions)
[exit 0]
```

```
$ python3 -m emitters.opa --policy examples/opa/policy-store.json --inputs examples/cedar/inputs-toolcalls.jsonl --out examples/opa/out/toolcalls-store --record-id opa-toolcalls-store-2026-10-21 --profile benchmark --key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-21T01:00:00Z
wrote examples/opa/out/toolcalls-store/record.json (40 decisions)
[exit 0]
```

```
$ python3 -m emitters.opa --policy examples/opa/policy-canonical.json --inputs examples/cedar/inputs-toolcalls.jsonl --out examples/opa/out/toolcalls-canonical --record-id opa-toolcalls-canonical-2026-10-21 --profile benchmark --key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-21T01:00:00Z
wrote examples/opa/out/toolcalls-canonical/record.json (40 decisions)
[exit 0]
```

```
$ python3 -m dr.verify examples/opa/out/toolcalls-canonical --registry examples/keys/registry.json --replay emitters.opa
examples/opa/out/toolcalls-canonical

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          40 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      40 rows written, by outcome {'ALLOW': 16, 'DENY': 24}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    39 of 40 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  OK      replay         re-deciding all 40 retained inputs with opa-authorizer@opa-1.21.3 reproduced every outcome and reason
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 40 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
[exit 0]
```

```
$ python3 examples/cedar/compare.py examples/cedar/inputs-toolcalls.jsonl examples/opa/out/toolcalls-caller examples/opa/out/toolcalls-store examples/opa/out/toolcalls-canonical
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

## 2. Row by row against the Cedar records over the same calls

```
$ python3 examples/opa/compare_with_cedar.py
caller: outcomes differ on 0 of 40 rows []; reasons differ by policy-id naming only (policyN vs pN) on 13; other reason differences [(36, 'request-invalid', 'no-policy-permits')]
store: outcomes differ on 0 of 40 rows []; reasons differ by policy-id naming only (policyN vs pN) on 12; other reason differences [(36, 'request-invalid', 'no-policy-permits')]
canonical: outcomes differ on 0 of 40 rows []; reasons differ by policy-id naming only (policyN vs pN) on 16; other reason differences [(36, 'request-invalid', 'no-policy-permits')]
[exit 0]
```

## 3. A policy that uses a non-deterministic builtin is refused at construction

```
$ python3 examples/opa/refusals.py
the policy as shipped: constructed
policy text uses time.now_ns(), builtins list unchanged: refused — the policy does not check against its declared builtins: 1 error occurred: policies.rego:86: rego_type_error: undefined function time.now_ns
policy text uses time.now_ns(), builtins list adds it: refused — policy.builtins names non-deterministic builtins: ['time.now_ns']
policy text uses http.send, builtins list adds it: refused — policy.builtins names non-deterministic builtins: ['http.send']
policy text uses sprintf (deterministic), builtins list unchanged: refused — the policy does not check against its declared builtins: 1 error occurred: policies.rego:86: rego_type_error: undefined function sprintf
policy text uses sprintf, builtins list adds it: constructed
builtins list names a builtin this engine does not have: refused — policy.builtins names builtins this engine does not have: ['no.such_builtin']
policy text does not parse: refused — the policy does not check against its declared builtins: 1 error occurred during loading: policies.rego:3: rego_parse_error: unexpected eof token
	allow if {
	 
rego_version 0 for v1 text: constructed
[exit 0]
```

## 4. OPA's own test corpus: a seeded sample of 400 cases as a record

```
$ python3 -m emitters.opa_conformance --policy examples/opa/policy-conformance.json --inputs examples/opa/inputs-conformance.jsonl --out examples/opa/out/conformance-sample --record-id opa-conformance-sample-2026-10-21 --profile benchmark --key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-21T01:00:00Z
wrote examples/opa/out/conformance-sample/record.json (400 decisions)
[exit 0]
```

```
$ python3 -m dr.verify examples/opa/out/conformance-sample --registry examples/keys/registry.json --replay emitters.opa_conformance
examples/opa/out/conformance-sample

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          400 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      400 rows written, by outcome {'ERROR': 44, 'RESULT': 333, 'UNDEFINED': 23}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    400 of 400 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  OK      replay         re-deciding all 400 retained inputs with opa-conformance@opa-1.21.3 reproduced every outcome and reason
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 400 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
[exit 0]
```

## 5. The established-versions rule against OPA's own corpus runs (G18)

```
$ python3 examples/opa/evidence_check.py
opa-0.70.0: refused — opa-conformance@opa-0.70.0 is named as established by sha256:1d523a7c8913063c9096844498b728f40b160b173392e56dd3e35289396b4a9a, and that result reports 3741 of 4347 with 6 excluded for engine 'opa-0.70.0'; the name is not supported
opa-1.0.0: refused — opa-conformance@opa-1.0.0 is named as established by sha256:ba46fef696018ddcb3f31c45868f3297dfdaebde58b6d7d0b5369e3ddb902ede, and that result reports 3767 of 4347 with 6 excluded for engine 'opa-1.0.0'; the name is not supported
opa-1.21.3: accepted — under opa-conformance@opa-1.21.3, which the record names as established by a conformance run (4341 of 4347, 6 excluded and named: a base/virtual document conflict the opa binary's loader refuses at load and the library evaluates; mocks opa.runtime, which the harness answers with {} and the binary with its build information; uses test.sleep, a builtin the Go test harness registers and the opa binary does not have; opa-1.21.3.json, digest matches)
[exit 0]
```

## 6. Is the engine's explanation a deterministic reason?

```
$ python3 examples/opa/explain_stability.py $OPA_BIN <opa 1.0.0> <opa 0.70.0>
opa 1.21.3: raw explanation over 5 runs -> differ; reduced (Op, rule head) trace digests ['28e7dad4c95b', '28e7dad4c95b', '28e7dad4c95b', '28e7dad4c95b', '28e7dad4c95b'] -> identical; rule heads named ['action', 'allow', 'ctx', 'decision', 'forbid', 'permit', 'resource']; coverage reports 32 covered and 30 uncovered source ranges, no rule ids
opa 1.0.0: raw explanation over 5 runs -> differ; reduced (Op, rule head) trace digests ['28e7dad4c95b', '28e7dad4c95b', '28e7dad4c95b', '28e7dad4c95b', '28e7dad4c95b'] -> identical; rule heads named ['action', 'allow', 'ctx', 'decision', 'forbid', 'permit', 'resource']; coverage reports 13 covered and 16 uncovered source ranges, no rule ids
opa 0.70.0: raw explanation over 5 runs -> differ; reduced (Op, rule head) trace digests ['28e7dad4c95b', '28e7dad4c95b', '28e7dad4c95b', '28e7dad4c95b', '28e7dad4c95b'] -> identical; rule heads named ['action', 'allow', 'ctx', 'decision', 'forbid', 'permit', 'resource']; coverage reports 13 covered and 16 uncovered source ranges, no rule ids
[exit 0]
```

