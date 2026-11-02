# Transcript

Captured by `bash examples/run.sh`. Commands are shown as run, output as printed, exit codes as returned.

## 1. Emit four records with three unalike deciders

```
$ python3 -m emitters.toolgate --policy examples/data/toolgate-policy.json --inputs examples/data/toolgate-suite.jsonl --out examples/out/toolgate-benchmark --record-id toolgate-suite-001 --key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-18T04:00:00Z
wrote examples/out/toolgate-benchmark/record.json (12 decisions)
exit 0
```

```
$ python3 -m emitters.toolgate --policy examples/data/toolgate-policy.json --inputs examples/data/toolgate-traffic.jsonl --out examples/out/toolgate-production --record-id toolgate-traffic-001 --key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-18T04:00:00Z
wrote examples/out/toolgate-production/record.json (40 decisions)
exit 0
```

```
$ python3 -m emitters.ratelimit --policy examples/data/ratelimit-policy.json --inputs examples/data/ratelimit-traffic.jsonl --out examples/out/ratelimit-production --record-id ratelimit-traffic-001 --key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-18T04:00:00Z
wrote examples/out/ratelimit-production/record.json (18 decisions)
exit 0
```

```
$ python3 -m emitters.classrouter --policy examples/data/classrouter-policy.json --inputs examples/data/classrouter-suite.jsonl --out examples/out/classrouter-benchmark --record-id classrouter-suite-001 --key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-18T04:00:00Z
wrote examples/out/classrouter-benchmark/record.json (9 decisions)
exit 0
```

## 2. Verify each one

```
$ python3 -m dr.verify examples/out/toolgate-benchmark --registry examples/keys/registry.json
examples/out/toolgate-benchmark

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          12 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      12 rows written, by outcome {'ALLOW': 6, 'DENY': 6}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    12 of 12 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  n/a     replay         not requested; pass --replay <decider module> to re-decide the retained inputs
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 12 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
exit 0
```

```
$ python3 -m dr.verify examples/out/toolgate-production --registry examples/keys/registry.json
examples/out/toolgate-production

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          40 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      40 rows written, by outcome {'ALLOW': 21, 'DENY': 19}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'production'
  n/a     correctness    the production profile carries no correctness property: the rows have no labels and the record claims none
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  n/a     replay         not requested; pass --replay <decider module> to re-decide the retained inputs
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 40 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
exit 0
```

```
$ python3 -m dr.verify examples/out/ratelimit-production --registry examples/keys/registry.json
examples/out/ratelimit-production

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          18 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      18 rows written, by outcome {'ALLOW': 15, 'DENY': 3}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'production'
  n/a     correctness    the production profile carries no correctness property: the rows have no labels and the record claims none
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  n/a     replay         not requested; pass --replay <decider module> to re-decide the retained inputs
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 18 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
exit 0
```

```
$ python3 -m dr.verify examples/out/classrouter-benchmark --registry examples/keys/registry.json
examples/out/classrouter-benchmark

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          9 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      9 rows written, by outcome {'DENY': 3, 'REDACT': 2, 'ROUTE': 4}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'benchmark'
  OK      correctness    9 of 9 decisions agree with their labels; recomputed from the rows
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  n/a     replay         not requested; pass --replay <decider module> to re-decide the retained inputs
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 9 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
exit 0
```

## 3. Replay: re-decide the retained inputs with the named decider

```
$ python3 -m dr.verify examples/out/ratelimit-production --registry examples/keys/registry.json --replay emitters.ratelimit
examples/out/ratelimit-production

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          18 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      18 rows written, by outcome {'ALLOW': 15, 'DENY': 3}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'production'
  n/a     correctness    the production profile carries no correctness property: the rows have no labels and the record claims none
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  OK      replay         re-deciding all 18 retained inputs with ratelimit@1.0.0 reproduced every outcome and reason
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 18 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
exit 0
```

```
$ python3 -m dr.verify examples/out/toolgate-production --registry examples/keys/registry.json --replay emitters.toolgate
examples/out/toolgate-production

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          40 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      40 rows written, by outcome {'ALLOW': 21, 'DENY': 19}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'production'
  n/a     correctness    the production profile carries no correctness property: the rows have no labels and the record claims none
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  OK      replay         re-deciding all 40 retained inputs with toolgate@1.0.0 reproduced every outcome and reason
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 40 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
exit 0
```

## 4. What the verifier refuses

A row's outcome edited on disk (row 4, DENY to ALLOW):

```
$ python3 -m dr.verify examples/scratch/flipped-outcome --registry examples/keys/registry.json
examples/scratch/flipped-outcome

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  FAILED  chain          row 4: row_hash does not re-derive (stored 'sha256:60a33422a4a65ce2062544c54774c391683d50ebc5bb06e3b3185fc998fca577', computed 'sha256:5f3f8b1052bc6d096091e06efac59a81bea0064ce600eae66745e163275806f1')
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
exit 2
```

A dishonest producer: the same labelled rows, re-signed with the real key as a production record so that no correctness figure is carried:

```
$ python3 -m dr.verify examples/scratch/lying-profile --registry examples/keys/registry.json
examples/scratch/lying-profile

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          12 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      12 rows written, by outcome {'ALLOW': 6, 'DENY': 6}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  FAILED  profile        the record declares 'production' and the rows support 'benchmark'
  FAILED  correctness    every row carries a label, so correctness is computable, and the record declares a profile that omits it
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  n/a     replay         not requested; pass --replay <decider module> to re-decide the retained inputs
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 12 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: FAILED
exit 2
```

A record signed by a key the registry has revoked:

```
$ python3 -m dr.verify examples/scratch/revoked --registry examples/keys/registry.json
examples/scratch/revoked

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  FAILED  signing_trust  key 'example-compromised' is revoked and the registry does not individually trust this record
  UNKNOWN signature      no honoured key to verify with, so the signature was not checked
  OK      chain          40 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      40 rows written, by outcome {'ALLOW': 21, 'DENY': 19}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'production'
  n/a     correctness    the production profile carries no correctness property: the rows have no labels and the record claims none
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  n/a     replay         not requested; pass --replay <decider module> to re-decide the retained inputs
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 40 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: FAILED
exit 2
```

Rows declaring a version this verifier does not read (not a failure: unknown):

```
$ python3 -m dr.verify examples/scratch/future-format --registry examples/keys/registry.json
examples/scratch/future-format

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  UNKNOWN chain          row declares v=3, which this verifier does not read; it reads [1, 2]
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

VERDICT: NOT ESTABLISHED
Nothing failed. At least one property could not be established, and an unestablished property is not one that holds.
exit 1
```

## 5. The record itself

```
$ cat examples/out/ratelimit-production/record.json
{
  "counts": {
    "by_outcome": {
      "ALLOW": 15,
      "DENY": 3
    },
    "decisions": 18
  },
  "decider": {
    "id": "ratelimit",
    "outcomes": [
      "ALLOW",
      "DENY"
    ],
    "version": "1.0.0"
  },
  "format": "sdl-decision-record",
  "format_version": 1,
  "issued_at": "2026-10-18T04:00:00Z",
  "ledger": {
    "path": "decisions.jsonl",
    "row_count": 18,
    "terminal_hash": "sha256:fa59c2fb7d46c82a800d7ed8026294afc3d06ba4e356314710fe0cc9ed34b23c"
  },
  "payload_hash": "sha256:04906e9cf6aed277e488ebf8dea7da3531fcc646c97e17e579e95e9bccdf457d",
  "policy_digests": [
    "sha256:d81b96cd07f7df02ac1ebde2829e6ae6cee3d97ffaefb784db7c941a6ed7c151"
  ],
  "profile": "production",
  "record_id": "ratelimit-traffic-001",
  "retained": {
    "inputs.jsonl": "sha256:1b7f92ba458d1495a4379b91b9b310ebf73040cb1760ca52115702f43f424086",
    "policy.json": "sha256:d81b96cd07f7df02ac1ebde2829e6ae6cee3d97ffaefb784db7c941a6ed7c151"
  },
  "signature": "zoOxANJkV68DGFOLePDJysVLoSZ9o/Vw98E9CRLZWs/kKHqKdw/mYruT50ri03hQVd8rNeZmEdO2YAofmoa9DA==",
  "signing_key_id": "example-2026-10"
}
exit 0
```

## 6. One row

```
$ head -n 1 examples/out/ratelimit-production/decisions.jsonl
{"decider": "ratelimit@1.0.0", "ext": {"window_count": 1}, "input_digest": "sha256:30074b2ab4695e23c62d268518bd4200fc7996825a3e8a7d16eb281a3df6deae", "outcome": "ALLOW", "policy_digest": "sha256:d81b96cd07f7df02ac1ebde2829e6ae6cee3d97ffaefb784db7c941a6ed7c151", "prev_hash": "GENESIS", "reason": null, "row_hash": "sha256:28d261bc9549db243284f0254c015b97b533d335b2b176d7b18ddac0a3340934", "seq": 1, "ts": "2026-10-18T02:00:00Z", "v": 1}
exit 0
```

## 7. A stream of records, with receipts

The same toolgate traffic as two consecutive records of one stream. Each decision also gets a signed receipt, which in a deployment goes to the party the decision was about.

```
$ python3 -m emitters.toolgate --policy examples/data/toolgate-policy.json --inputs examples/data/toolgate-traffic-hour1.jsonl --out examples/out/stream-hour1 --record-id toolgate-hour1 --stream toolgate-traffic:1 --receipts examples/out/stream-hour1-receipts --key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-18T04:00:00Z
wrote examples/out/stream-hour1/record.json (20 decisions, 20 receipts in examples/out/stream-hour1-receipts)
exit 0
```

```
$ python3 -m emitters.toolgate --policy examples/data/toolgate-policy.json --inputs examples/data/toolgate-traffic-hour2.jsonl --out examples/out/stream-hour2 --record-id toolgate-hour2 --stream toolgate-traffic:2 --prior examples/out/stream-hour1/record.json --receipts examples/out/stream-hour2-receipts --key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-18T04:00:00Z
wrote examples/out/stream-hour2/record.json (20 decisions, 20 receipts in examples/out/stream-hour2-receipts)
exit 0
```

The second record alone: its link to the first cannot be checked without the first.

```
$ python3 -m dr.verify examples/out/stream-hour2 --registry examples/keys/registry.json
examples/out/stream-hour2

  OK      document       format_version 2 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          20 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      20 rows written, by outcome {'ALLOW': 11, 'DENY': 9}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'production'
  n/a     correctness    the production profile carries no correctness property: the rows have no labels and the record claims none
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  n/a     replay         not requested; pass --replay <decider module> to re-decide the retained inputs
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  UNKNOWN stream         the record claims to follow seq 1 of stream 'toolgate-traffic' (prev_record_hash sha256:63e4882e9686adcf...); pass --prior to check the link
  n/a     completeness   not claimed and not establishable: the 20 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: NOT ESTABLISHED
Nothing failed. At least one property could not be established, and an unestablished property is not one that holds.
exit 1
```

With the prior record supplied:

```
$ python3 -m dr.verify examples/out/stream-hour2 --registry examples/keys/registry.json --prior examples/out/stream-hour1/record.json
examples/out/stream-hour2

  OK      document       format_version 2 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          20 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      20 rows written, by outcome {'ALLOW': 11, 'DENY': 9}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'production'
  n/a     correctness    the production profile carries no correctness property: the rows have no labels and the record claims none
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  n/a     replay         not requested; pass --replay <decider module> to re-decide the retained inputs
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  OK      stream         follows seq 1 of stream 'toolgate-traffic': prev_record_hash, seq and decision numbering all continue from the prior; nothing here says whether a record after seq 2 exists
  n/a     completeness   not claimed and not establishable: the 20 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
exit 0
```

```
$ python3 -m dr.stream examples/out/stream-hour1/record.json examples/out/stream-hour2/record.json
OK: 2 records link in sequence: 1..2. Nothing here says whether a record after 2 exists.
exit 0
```

```
$ cat examples/out/stream-hour2-receipts/receipt-000001.json
{
  "decision_no": 21,
  "kind": "sdl-decision-receipt",
  "payload_hash": "sha256:e32cd0061e1c3498bf1f0e39161baabed58c4f91c749f28d72f6f1c8c666ea11",
  "record_id": "toolgate-hour2",
  "row_hash": "sha256:9ea20f3114d137c0ec466fe155fd93cc948dd66927792e1008a04447fcfa9eb6",
  "seq": 1,
  "signature": "DgV3DbSe99FHx8fTYEeB/c2VGmuWdR/6Igendsi92iGWrj05X0N/llCxel72P4jkhqOJckKZdS73sOG6NaDgAA==",
  "signing_key_id": "example-2026-10",
  "stream_id": "toolgate-traffic",
  "ts": "2026-10-18T01:00:20Z"
}
exit 0
```

## 8. What a record cannot say about itself

Delete two decisions from the first record, renumber, re-chain, re-derive the counts and re-sign with the producer's own key. Every property holds: a record is a statement about the rows that are in it.

```
$ python3 tools/truncate.py examples/out/stream-hour1 examples/scratch/hour1-truncated --drop 3,7 --key examples/keys/example-signing-key.pem
wrote examples/scratch/hour1-truncated: dropped rows [3, 7], renumbered, re-chained, re-signed
exit 0
```

```
$ python3 -m dr.verify examples/scratch/hour1-truncated --registry examples/keys/registry.json --replay emitters.toolgate
examples/scratch/hour1-truncated

  OK      document       format_version 2 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          18 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      18 rows written, by outcome {'ALLOW': 9, 'DENY': 9}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'production'
  n/a     correctness    the production profile carries no correctness property: the rows have no labels and the record claims none
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  OK      replay         re-deciding all 18 retained inputs with toolgate@1.0.0 reproduced every outcome and reason
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  OK      stream         first record of stream 'toolgate-traffic'; nothing prior to link to
  n/a     completeness   not claimed and not establishable: the 18 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
exit 0
```

The holder of the receipt for decision 20 can refute it, and count the gap:

```
$ python3 -m dr.verify examples/scratch/hour1-truncated --registry examples/keys/registry.json --receipt examples/out/stream-hour1-receipts/receipt-000020.json
examples/scratch/hour1-truncated

  OK      document       format_version 2 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          18 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      18 rows written, by outcome {'ALLOW': 9, 'DENY': 9}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'production'
  n/a     correctness    the production profile carries no correctness property: the rows have no labels and the record claims none
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  n/a     replay         not requested; pass --replay <decider module> to re-decide the retained inputs
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  OK      stream         first record of stream 'toolgate-traffic'; nothing prior to link to
  FAILED  completeness   refuted: the producer signed a receipt for decision seq 20 of this run and the record has 18 rows, so at least 2 acknowledged decision(s) are not in it
  FAILED  receipts       receipt-000020.json: the producer acknowledged decision seq 20 of this run at 2026-10-18T01:00:19Z; the record has 18 rows
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: FAILED
exit 2
```

The holder of the receipt for decision 7 finds a different row at seq 7:

```
$ python3 -m dr.verify examples/scratch/hour1-truncated --registry examples/keys/registry.json --receipt examples/out/stream-hour1-receipts/receipt-000007.json
examples/scratch/hour1-truncated

  OK      document       format_version 2 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          18 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      18 rows written, by outcome {'ALLOW': 9, 'DENY': 9}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'production'
  n/a     correctness    the production profile carries no correctness property: the rows have no labels and the record claims none
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  n/a     replay         not requested; pass --replay <decider module> to re-decide the retained inputs
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  OK      stream         first record of stream 'toolgate-traffic'; nothing prior to link to
  n/a     completeness   not claimed and not establishable: the 18 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it; 1 receipt(s) checked, 0 matched a row, none pointed past the ledger
  FAILED  receipts       receipt-000007.json: seq 7: the receipted row_hash sha256:43c31dfee66552141046365724f49e41b279be6c0d34c0ff94c6dacbd8d850c1 is not the row in the record (sha256:1f756f867a16d03c4a6bbb6546b66af3bf33e221ebcbe1b824b8af8766f1d5fc)
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: FAILED
exit 2
```

The second record of the stream no longer follows the truncated first; and held together with the original, the two are a fork: two records signed for one position.

```
$ python3 -m dr.verify examples/out/stream-hour2 --registry examples/keys/registry.json --prior examples/scratch/hour1-truncated/record.json
examples/out/stream-hour2

  OK      document       format_version 2 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          20 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      20 rows written, by outcome {'ALLOW': 11, 'DENY': 9}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'production'
  n/a     correctness    the production profile carries no correctness property: the rows have no labels and the record claims none
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  n/a     replay         not requested; pass --replay <decider module> to re-decide the retained inputs
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  FAILED  stream         prev_record_hash sha256:63e4882e9686adcf87125b354735b6166b7abbd0e8e93a978471af38ea558a5c is not the prior's payload_hash, computed from its fields: sha256:d814eb29ab1e918a65e7aeb60f059496465b3e5a949a8d9b3617b27398782aab; first_decision: record says 21, the prior's numbering continues at 19
  n/a     completeness   not claimed and not establishable: the 20 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: FAILED
exit 2
```

```
$ python3 -m dr.stream examples/out/stream-hour1/record.json examples/scratch/hour1-truncated/record.json examples/out/stream-hour2/record.json
FORK   stream 'toolgate-traffic' seq 1: 2 distinct records signed for the same position: ['sha256:63e4882e9686adcf87125b354735b6166b7abbd0e8e93a978471af38ea558a5c', 'sha256:d814eb29ab1e918a65e7aeb60f059496465b3e5a949a8d9b3617b27398782aab']
DEFECT stream 'toolgate-traffic' seq 2 after 1: prev_record_hash sha256:63e4882e9686adcf87125b354735b6166b7abbd0e8e93a978471af38ea558a5c is not the prior's payload_hash, computed from its fields: sha256:d814eb29ab1e918a65e7aeb60f059496465b3e5a949a8d9b3617b27398782aab
DEFECT stream 'toolgate-traffic' seq 2 after 1: first_decision: record says 21, the prior's numbering continues at 19
exit 2
```

## 9. A witness

A second party countersigns the first record's payload_hash. The statement establishes that this exact record existed when the witness signed, and nothing before that.

```
$ python3 -m dr.witness examples/out/stream-hour1/record.json --key examples/keys/witness-key.pem --key-id example-witness-2026-10 --witnessed-at 2026-10-18T04:05:00Z --out examples/out/stream-hour1.witness.json
wrote examples/out/stream-hour1.witness.json: witnessed sha256:63e4882e9686adcf87125b354735b6166b7abbd0e8e93a978471af38ea558a5c
exit 0
```

```
$ python3 -m dr.verify examples/out/stream-hour1 --registry examples/keys/registry.json --witness examples/out/stream-hour1.witness.json --witness-registry examples/keys/witnesses.json
examples/out/stream-hour1

  OK      document       format_version 2 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          20 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      20 rows written, by outcome {'ALLOW': 10, 'DENY': 10}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'production'
  n/a     correctness    the production profile carries no correctness property: the rows have no labels and the record claims none
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  n/a     replay         not requested; pass --replay <decider module> to re-decide the retained inputs
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  OK      stream         first record of stream 'toolgate-traffic'; nothing prior to link to
  n/a     completeness   not claimed and not establishable: the 20 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  OK      witness        witness 'example-witness-2026-10' signed this record's payload_hash at 2026-10-18T04:05:00Z; it bounds nothing before that

VERDICT: ESTABLISHED
exit 0
```

```
$ python3 -m dr.verify examples/scratch/hour1-truncated --registry examples/keys/registry.json --witness examples/out/stream-hour1.witness.json --witness-registry examples/keys/witnesses.json
examples/scratch/hour1-truncated

  OK      document       format_version 2 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          18 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      18 rows written, by outcome {'ALLOW': 9, 'DENY': 9}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'production'
  n/a     correctness    the production profile carries no correctness property: the rows have no labels and the record claims none
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  n/a     replay         not requested; pass --replay <decider module> to re-decide the retained inputs
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  OK      stream         first record of stream 'toolgate-traffic'; nothing prior to link to
  n/a     completeness   not claimed and not establishable: the 18 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  FAILED  witness        the statement witnesses sha256:63e4882e9686adcf87125b354735b6166b7abbd0e8e93a978471af38ea558a5c, this record is sha256:d814eb29ab1e918a65e7aeb60f059496465b3e5a949a8d9b3617b27398782aab

VERDICT: FAILED
exit 2
```

## 10. Saying less: keyed digests, no ext, and a reader without the inputs

The rate limiter's traffic emitted as row version 2 (keyed input digests, salt in inputs.jsonl) without the ext block. It verifies and replays exactly as before. Then the same directory as a reader who was not given inputs.jsonl sees it.

```
$ python3 -m emitters.ratelimit --policy examples/data/ratelimit-policy.json --inputs examples/data/ratelimit-traffic.jsonl --out examples/out/ratelimit-production-keyed --record-id ratelimit-traffic-001-keyed --keyed --salt 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f --no-ext --key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-18T04:00:00Z
wrote examples/out/ratelimit-production-keyed/record.json (18 decisions)
exit 0
```

```
$ head -n 1 examples/out/ratelimit-production-keyed/decisions.jsonl
{"decider": "ratelimit@1.0.0", "input_digest": "hmac-sha256:254e0bc32bc4873bad4be1b076616ec6bee3903cf1e5e65614c875822d67f3a9", "outcome": "ALLOW", "policy_digest": "sha256:d81b96cd07f7df02ac1ebde2829e6ae6cee3d97ffaefb784db7c941a6ed7c151", "prev_hash": "GENESIS", "reason": null, "row_hash": "sha256:8788b1fda12747bd1447612fabbe7bd5179333d197d8a504b7c602c753549755", "seq": 1, "ts": "2026-10-18T02:00:00Z", "v": 2}
exit 0
```

```
$ head -n 1 examples/out/ratelimit-production-keyed/inputs.jsonl
{"salt": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}
exit 0
```

```
$ python3 -m dr.verify examples/out/ratelimit-production-keyed --registry examples/keys/registry.json --replay emitters.ratelimit
examples/out/ratelimit-production-keyed

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          18 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      18 rows written, by outcome {'ALLOW': 15, 'DENY': 3}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'production'
  n/a     correctness    the production profile carries no correctness property: the rows have no labels and the record claims none
  OK      retained       2 retained file(s) present with their digests, inputs match the rows, policy matches the rows
  OK      replay         re-deciding all 18 retained inputs with ratelimit@1.0.0 reproduced every outcome and reason
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 18 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: ESTABLISHED
exit 0
```

```
$ python3 -m dr.verify examples/scratch/without-inputs --registry examples/keys/registry.json --replay emitters.ratelimit
examples/scratch/without-inputs

  OK      document       format_version 1 shape, and payload_hash recomputes from the canonical payload
  OK      signing_trust  key 'example-2026-10' is active in the registry
  OK      signature      the signature verifies over the payload
  OK      chain          18 rows re-derive from GENESIS to the signed terminal hash
  OK      decisions      18 rows written, by outcome {'ALLOW': 15, 'DENY': 3}, one decider, 1 policy; a count of what the producer wrote, not of what happened
  OK      profile        the rows support the declared profile 'production'
  n/a     correctness    the production profile carries no correctness property: the rows have no labels and the record claims none
  UNKNOWN retained       named by the record and not present in this copy, so their digests could not be checked: ['inputs.jsonl']; the other 1 retained file(s) match
  UNKNOWN replay         replay needs inputs.jsonl and policy.json established, and retained is unknown in this copy
  n/a     invocation     not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called
  n/a     stream         the record is not part of a stream
  n/a     completeness   not claimed and not establishable: the 18 rows are what the producer wrote, and nothing in a self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it
  n/a     receipts       no receipts supplied
  n/a     witness        no witness statement supplied; a record witnesses nothing about itself

VERDICT: NOT ESTABLISHED
Nothing failed. At least one property could not be established, and an unestablished property is not one that holds.
exit 1
```

