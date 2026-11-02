# Transcript: the Cedar records under the Lean definitional engine

Captured by `bash examples/cedar/run_lean.sh`. The engine is cedar-spec's Lean formalisation of Cedar behind `cedar-lean-cli` (cedar-spec commit `b86afb951485`, built here from source; the CLI reports `cedar-cli 4.4.0`, the Cedar crate it parses with), as the decider `cedar-authorizer@cedar-lean-b86afb951485` (`emitters/cedar_lean.py`). The cedarpy records were made under cedarpy 4.12.2. Output as printed, exit codes as returned.

## 1. The Lean engine over Cedar's own corpus

Every request of every generated test, decision and reason set and error presence compared with what the corpus expects, by the same rule as the cedarpy engines (`tools/cedar_conformance.py --engine lean`). The result file is the evidence a record may name (`examples/cedar/conformance/cedar-lean-b86afb951485.json`); its figures:

```
$ python3 -c import json; d=json.load(open('examples/cedar/conformance/cedar-lean-b86afb951485.json')); print(json.dumps({k: d[k] for k in ('engine','tests','requests','agree_decision_reason_and_error_presence','disagree','allow_where_corpus_expects_deny','deny_where_corpus_expects_allow','by_outcome','seconds')}, indent=1))
{
 "engine": "cedar-lean-b86afb951485",
 "tests": 5677,
 "requests": 45416,
 "agree_decision_reason_and_error_presence": 45416,
 "disagree": 0,
 "allow_where_corpus_expects_deny": 0,
 "deny_where_corpus_expects_allow": 0,
 "by_outcome": {
  "ALLOW": 24124,
  "DENY": 21292
 },
 "seconds": 2297.5
}
[exit 0]
```

The evidence digest a record names:

```
$ python3 tools/cedar_engine_drift.py digest examples/cedar/conformance/cedar-lean-b86afb951485.json
sha256:c7a9c5cf325bf01e053e2c8a0f608405089b1cd805a2010f31798e948b954311
[exit 0]
```

**What this agreement does and does not establish.** The corpus's expected values are produced by the Rust engine, not by the Lean model: cedar-spec's `abac` fuzz target computes them with `cedar_policy::Authorizer` before dumping each test. But every dumped input first passed `run_auth_test`, which asserts that the Rust response and the Lean response are equal and panics otherwise, so the corpus is a filtered record of inputs on which the two already agreed. Agreement here is therefore the expected outcome rather than evidence about Cedar: what it establishes is that this decider's wiring — entity-id escaping, request construction, reason mapping, the agreement rule — reproduces the published expectations on every one of the 45,416 requests. That is a statement about this harness, and it is the only statement the figure supports.

```
$ grep -n 're-parsed\|Authorizer::new\|new_id(PolicyId::new' cedar-drt/fuzz/fuzz_targets/abac.rs
55:        // When the corpus is re-parsed, the policy will be given id "policy0".
62:            .new_id(PolicyId::new("policy0"));
67:                let authorizer = Authorizer::new();
[exit 0]
```

```
$ grep -n -A 3 'assert_eq!' cedar-drt/src/tests.rs
133:            assert_eq!(
134-                rust_res_for_comparison,
135-                definitional_res.response,
136-                "Mismatch for {request}, with error comparison mode {ecmode:?}\nPolicies:\n{policies}\nEntities:\n{es}",
[exit 0]
```

## 2. What the corpus cannot say: policy naming

The corpus exercises exactly one policy identifier. Measured over all 5,677 generated tests and all of their expected reason and error entries:

```
$ python3 -
corpus policy files:                5677
  carrying an @id annotation:       0
  carrying any annotation at all:   938
distinct policy ids ever expected:  1  -> {'policy0': 31075}
[exit 0]
```

The generator renames every policy to `policy0` on purpose before computing expectations — `abac.rs`: *"When the corpus is re-parsed, the policy will be given id policy0"* — because the corpus format does not preserve policy identity. So no run against this corpus, by any engine, can say anything about how an engine names policies: there is one name, and every engine produces it. An engine named as established on 45,416 of 45,416 is named on evidence that is structurally silent about a field this repository's own records depend on in every row.

## 3. A cedarpy record replayed under the Lean engine

The record names `cedar-authorizer@cedarpy-4.12.2` and, as established, cedarpy-4.8.7; it does not name the Lean engine. Replay refuses, as it must: a different procedure proves nothing about this one.

```
$ python3 -m dr.verify examples/cedar/out/toolcalls-canonical --registry examples/keys/registry.json --replay emitters.cedar_lean
examples/cedar/out/toolcalls-canonical

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          40 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      40 rows written, by outcome {'ALLOW': 16, 'DENY': 24}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    39 of 40 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  UNKNOWN replay         the supplied decider is cedar-authorizer@cedar-lean-b86afb951485, the record names cedar-authorizer@cedarpy-4.12.2; replaying with a different procedure proves nothing
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 40 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: NOT ESTABLISHED
Nothing failed. At least one property could not be established, and an unestablished property is not one that holds.
[exit 1]
```

## 4. A record made by the Lean engine over the same forty calls, naming cedarpy-4.12.2 as established

```
$ python3 -m emitters.cedar_lean --policy examples/cedar/policy-canonical.json --inputs examples/cedar/inputs-toolcalls.jsonl --out examples/cedar/out/toolcalls-lean --record-id cedar-toolcalls-lean-2026-10-21 --profile benchmark --key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-21T05:00:00Z --established-version cedarpy-4.12.2=sha256:67b6fcf9ec7040ff172d387f79a11e2c9e686c7994a666b16e518eb8a817981c
wrote examples/cedar/out/toolcalls-lean/record.json (40 decisions)
[exit 0]
```

Verified under its own engine:

```
$ python3 -m dr.verify examples/cedar/out/toolcalls-lean --registry examples/keys/registry.json --replay emitters.cedar_lean
examples/cedar/out/toolcalls-lean

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          40 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      40 rows written, by outcome {'ALLOW': 16, 'DENY': 24}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    39 of 40 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  OK      replay         re-deciding all 40 retained inputs with cedar-authorizer@cedar-lean-b86afb951485 reproduced every outcome and reason
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 40 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
[exit 0]
```

Replayed under cedarpy-4.12.2, which the record names as established by a run that agrees on all 45,416 corpus requests, with that run supplied. The name is accepted and the replay then fails at the first row: the Lean front end reports a policy by its `@id` annotation (`p0`) and cedarpy by its position (`policy0`). The decisions agree on every row; the reason strings differ on every row that names a policy. The corpus the name rests on has no `@id` annotations, so 45,416 of 45,416 said nothing about them.

```
$ python3 -m dr.verify examples/cedar/out/toolcalls-lean --registry examples/keys/registry.json --replay emitters.cedar --conformance-evidence examples/cedar/conformance/cedarpy-4.12.2.json
examples/cedar/out/toolcalls-lean

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          40 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      40 rows written, by outcome {'ALLOW': 16, 'DENY': 24}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    39 of 40 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  FAILED  replay         seq 1: replay gives ('ALLOW', 'policy0'), the row records ('ALLOW', 'p0')
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 40 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: FAILED
[exit 2]
```

The forty rows side by side, Lean against cedarpy, outcome and reason:

```
$ python3 -
40 rows: outcome agrees on 40, reason agrees on 23
  seq 36: lean DENY no-policy-permits {'errors': ['p7']}  |  cedarpy DENY request-invalid {'decision': 'Decision.NoDecision', 'errors': ['failed to build request: context `{amount: "250", approved_intent: "pay-
[exit 0]
```

## 5. Where the difference actually is

Not between the Lean model and the Rust engine. The determining-policy ids both front ends report come from the Rust parser; what differs is that cedarpy ignores an `@id` annotation and assigns a positional id, while the `cedar-policy` crate the Lean CLI parses with honours it. The same two-policy set through each:

```
$ python3 -c 
import cedarpy, importlib.metadata as m
policies = '@id("p0")\npermit(principal, action, resource) when { context.x == 1 };\n@id("p1")\npermit(principal, action, resource) when { context.x == 2 };\n'
schema = 'entity U; action a appliesTo { principal: U, resource: U, context: { x: Long } };'
req = {'principal': 'U::"x"', 'action': 'Action::"a"', 'resource': 'U::"y"', 'context': {'x': 1}}
r = cedarpy.is_authorized(req, policies, [], schema)
print('cedarpy', m.version('cedarpy'), '->', str(r.decision).split('.')[-1], 'reasons', sorted(r.diagnostics.reasons))

cedarpy 4.12.2 -> Allow reasons ['policy0']
[exit 0]
```

So the forty-row difference is between two invocation paths to Cedar, which §4 of the specification already calls two deciders, and the decisions themselves agree on every row. It is not a semantic divergence between an implementation and its proved specification, and nothing here should be described as one.

Row 36 is the one row whose reason differs for another cause: the input gives `amount` as a string where the schema types it Long. cedarpy, handed the schema, refuses to build the request (`request-invalid`); the Lean CLI builds the request without schema validation, evaluates, and the one policy that could permit errors on the comparison, so the decision is DENY with that policy erroring. Same outcome, a different route to it, and a difference between front ends, not between the engines' semantics.

