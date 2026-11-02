# sdl-decision-record

A signed, hash-chained, recomputable record of what a deterministic decision
procedure decided, verifiable offline by someone who does not trust the
producer. Start with `EVALUATING.md`, then `SPEC.md`. What such a record cannot
say about itself, and what it leaks about the policy it ran under, are in
`SPEC.md` §13–14.

```
python3 -m pip install cryptography        # the verifier's only dependency
bash examples/run.sh                        # emit records, verify them, show refusals, streams, receipts, a witness, a truncation
python3 -m dr.verify examples/out/ratelimit-production --registry examples/keys/registry.json --replay emitters.ratelimit
python3 -m pip install pytest && python3 -m pytest -q
python3 tools/mutate.py                     # regenerate tests/MUTATIONS.md (about an hour)
```

**What reproduces.** Every capture and result here is written by a command,
and re-running the command reproduces it byte for byte, given the engines and
corpora the script names at its top. Two things are stated rather than left to
be found. Wall-clock measurements differ on every run: a result file's
`seconds` and `generated_utc` fields record how long a run took and when, and
are not part of what reproduces. And `experiments/spec_sufficiency/` cannot be
re-run, by construction: its verifier pins the digest of the `SPEC.md` it was
written from, and its `RESULTS.md` says why.

## What is here

Every entry at the top of the repository, what it is, and whether you need it.

| entry | what it is | do you need it |
|---|---|---|
| `EVALUATING.md` | what you may do with this, what to run first, and what the evidence does not establish | yes: start here |
| `SPEC.md` | the format: rows, chain, record, profiles, keys, the verification states and the assurance levels, and what a record cannot establish about itself | yes |
| `SEAMS.md` | the JSON parser disagreements the format refuses or pins, class by class, with the one that is still open | if you write a reader or an emitter |
| `dr/` | the verifier and the writer: `verify.py` checks a record, `emit.py` writes one, `attest.py` is the decider's signature over each decision (SPEC §15) | yes: this is what you run |
| `tools/` | the attester, `arrive.py`, and its verifier, `verify_arrival.py`: the party other than the producer that A4 rests on (SPEC §16). `truncate.py` deletes decisions and re-signs, and the record still verifies (SPEC §13). `rederive.py` re-derives decisions without the producer's code. The rest fetch pinned corpora, measure engine drift, build the conformance handoff, check corpus coverage, and generate `tests/MUTATIONS.md` and the exit-code table below | yes for the attester; the rest to reproduce results |
| `emitters/` | eight example deciders. `toolgate`, `ratelimit` and `classrouter`, none of them text-matching; `cedar`, a decision over a privileged call under Cedar, with `cedar_conformance` for Cedar's own corpus (`pip install cedarpy`) and `cedar_lean` for cedar-spec's Lean engine (`CEDAR_LEAN_CLI`); `opa`, the same decision under Rego, with `opa_conformance` for OPA's test corpus (an `opa` binary in `OPA_BIN`, `pip install pyyaml`) | to run the examples, or as models for your own |
| `examples/` | keys, data, the scripts and their captured output. `run.sh` → `TRANSCRIPT.md` is the core example. `acceptance/` is how to refuse a record: one record, fourteen things done to it, the verdict on each (`run.sh` → `ACCEPTANCE.md`). `cedar/` and `opa/` are the execution-time example under each engine, their conformance corpora as records, and the same records under several engine releases. `consume.py` is a consumer that sets its own threshold over the per-property states | yes: `acceptance/` first |
| `experiments/` | the evidence behind the release's two findings. `rederivability/`: five forged records and which check catches which; F5, the one nothing catches; and the same forgeries rebuilt with an attester, where F5 fails (`forge.py`, `measure.py` → `RESULTS.md`, `ladder.py` → `LADDER.md`). `spec_sufficiency/`: a verifier written from `SPEC.md` alone and scored against the conformance corpus | to check the findings |
| `conformance/verifier/` | the handoff for a second verifier: every committed record and thirty-two deliberate alterations of them, each with the states this verifier reports, a `HANDOFF.md` for an implementer who gets `SPEC.md` and nothing else, and `score.py` | if you write a verifier |
| `tests/` | the suite, and `MUTATIONS.md`: each behaviour the tests hold, broken on purpose, and which tests fail | to check that the claims hold |
| `docs/` | one technical report: building the OPA decider from the specification's description of other grammars, and what the description left out | optional |
| `vendor/` | Cedar's hand-written integration tests, third-party, under their own licence; the Cedar examples read them | no |
| `LICENSE`, `LICENSES/`, `NOTICE` | the licences, and which one covers which file | yes, before you use anything |
| `pyproject.toml` | package metadata | no |
| `.github/` | the publication check this repository runs on every change | no |
| `.gitignore` | keeps generated and fetched files out of the tree | no |

The keys under `examples/keys/` are for the example only and are committed on
purpose. Anything signed with them proves nothing about anyone.

## Licence

The terms are in `LICENSE`, and `NOTICE` says who holds the copyright and
what in here is somebody else's. The licence is not named here on purpose:
a second copy of it in prose is a second copy that can disagree.

Third-party material keeps its own. Cedar's integration tests are vendored
under `vendor/cedar-integration-tests/` with their `LICENSE` and `NOTICE`;
Cedar's generated corpus and OPA's test corpus are fetched by digest rather
than vendored (`tools/fetch_cedar_drt.py`, `tools/fetch_opa_testdata.py`).

<!-- BEGIN GENERATED: exit codes -->

`dr.verify` exits with one of four codes, from `dr/verify.py`; SPEC §9 defines the fold:

| exit | verdict | meaning |
|---|---|---|
| 0 | ESTABLISHED | every applicable property established; none failed, none unknown |
| 1 | NOT ESTABLISHED | none failed, but something is unknown -- including a core property nobody judged. **Unknown is not a pass.** This is the common case for a record verified without its decider, receipts or a witness |
| 2 | FAILED | an applicable property failed: a claim the record makes is contradicted by its rows or files |
| 3 | unreadable | nothing was judged: the directory or `record.json` could not be read, or the verifier itself failed (standard error says which). A fault in the verifier exits here, not with a verdict's code, except where it raises the same kind of exception a malformed file raises, at a place guarded for that file: while a supplied file is read, or inside the witness and receipt checks, which run under the guard for their file; there the file is reported as the cause (`SPEC.md` §9) |

A consumer decides its own threshold over the per-property states (`--json`); see `examples/consume.py`.

<!-- END GENERATED: exit codes -->
