# Handoff: write a verifier from the specification alone

You receive `SPEC.md` and this directory, and nothing else: no reference
code, no tests, no decision log, no conversation with the people who wrote
the specification. The question being asked is whether the specification is
sufficient for an implementation written by someone who was not in the room.
Do not go looking for the reference implementation; if you find it, the
exercise is over.

## What to build

A verifier of decision records as `SPEC.md` describes them: given a run
directory and a key registry, and optionally a prior record, receipts, a
witness statement with its registry, and a decider registry, report every
property of SPEC §9 as one of `established`, `unknown`, `failed` or `n/a`,
and the verdict §9 defines. Replay (§8) needs decider code that is not
provided: report `replay` as `n/a` throughout.

Use any language. The reference is not a constraint on structure, only on
what the states are.

## The corpus

`cases/<name>/run/` is a run directory as a verifier receives it.
`cases/<name>/case.json` gives the options to verify it with, as paths
relative to this directory (`keys/` holds the registries, `inputs/` the
priors, receipts and witness statements). `manifest.json` lists the cases.
Some are records as issued; others are deliberate alterations of them, and
`what` says what was done, so you can tell whether your implementation
refused for the reason the alteration supplies.

`cases/<name>/expected.json` holds the reference verifier's states. Write
and run your implementation first, over every case, and only then score.
An implementation tuned case by case against the expectations tells us
nothing about the specification.

## The output contract

One JSON object per line, one line per case:

    {"case": "<name>",
     "payload_hash_recomputed": "sha256:…" | null,
     "terminal_hash_recomputed": "sha256:…" | null,
     "properties": {"document": "…", "signing_trust": "…", "signature": "…", "chain": "…", "decisions": "…",
                    "profile": "…", "correctness": "…", "retained": "…", "replay": "n/a", "invocation": "…",
                    "stream": "…", "completeness": "…", "receipts": "…", "witness": "…"},
     "verdict": "ESTABLISHED" | "NOT ESTABLISHED" | "FAILED" | "UNREADABLE"}

`payload_hash_recomputed` is the digest your implementation computes over
the record's signed payload (SPEC §2, §5, §7). `terminal_hash_recomputed`
is the last row hash your re-derivation of the chain produces (§3, §4),
or null if it produced none. `UNREADABLE` is the verdict for a directory
that could not be read at all (exit 3 in §9). These two digests are what
lets the scorer tell a canonical-bytes disagreement from a logic one.

## Scoring

    python3 score.py results.jsonl

prints the disagreements by class and nothing else:

- `missing` — no line for the case;
- `shape` — you refused to read a case the reference read, or read one
  it refused;
- `canonical-bytes` — your recomputed digest differs from the record's
  where the reference found it to match, so the bytes you canonicalise or
  hash differ before any property is judged;
- `state` — the same property, a different state;
- `verdict` — every state agrees and the verdict does not.

The output is a list, not an opinion. Send back the list, and for each
entry the sentence of the specification you followed, or the sentence that
was missing. A disagreement where your reading of the specification is the
defensible one is the most useful result this exercise can produce.
