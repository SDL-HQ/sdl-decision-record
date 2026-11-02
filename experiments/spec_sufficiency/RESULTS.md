# Is the specification sufficient to implement from?

`conformance/verifier/HANDOFF.md` asks a question this repository has never answered
with a figure: whether `SPEC.md` is sufficient for a verifier written by someone who
was not in the room. The corpus has existed since 21 October and no second implementer
has run against it, so every statement about the specification's sufficiency has been a
hypothesis. This is the first measurement.

Run on 25 October 2026 against the `SPEC.md` whose digest `verifier.py` pins as `MEASURED_AGAINST`. The implementation is
`experiments/spec_sufficiency/verifier.py`; `results.jsonl` beside it is its output over
all 47 cases, and `conformance/verifier/score.py` scored it once.

## What this can and cannot establish

The instrument is asymmetric and that is its shape, not a caveat on it.

- **A case the implementation cannot decide is a case the specification does not
  determine.** That direction is sound: nothing outside `SPEC.md` was available to decide
  it, and the exclusion is structural rather than promised (below).
- **A case it decides correctly establishes much less.** The author of the implementation
  has read the reference in the past, and an import hook does not unlearn that. Agreement
  is consistent with a sufficient specification and equally consistent with remembering.

So the figures below are read in one direction. The disagreements are the result; the
agreements bound nothing.

## Exclusion, by construction

A meta-path finder installed before any other import raises `ReferenceCodeBlocked` on
`dr`, `emitters` and `tools`, so the implementation cannot consult the code whose
specification it is testing. An `open()` guard additionally refuses any path named
`expected.json`, so the corpus's expectations cannot be read during a run — the failure
mode `HANDOFF.md` names, an implementation tuned case by case, is prevented rather than
promised. `tests/test_spec_sufficiency.py` demonstrates both by attempting them.

For the information side, which no import hook reaches, every rule in the implementation
carries the sentence of `SPEC.md` that licenses it, in `CITES`, and the run audits all 57
against the specification text before verifying anything. A rule whose licence is not in
the specification is a rule that came from somewhere else, and it is visible as a failed
audit rather than as a matter of trust. The audit caught two of its own on first run:
two citations were paraphrases of the specification rather than quotations of it, and
were corrected to the text.

## The figure

| measure | result |
|---|---:|
| cases | 47 |
| cases agreeing on all 14 properties | **42** |
| cases disagreeing on at least one property | **5** |
| verdicts agreeing | **46 of 47** |
| disagreement rows, by class: `shape` | 0 |
| `canonical-bytes` | 0 |
| `state` | 20 |
| `verdict` (states agree, verdict differs) | 0 |
| distinct readings behind the 20 state rows | **3** |
| assumptions the specification left to the implementer | 11 |
| of those, assumed wrongly | **1** |

Zero `canonical-bytes` rows is the broadest thing here: canonical JSON, the digest form,
the row hash over `prev_hash_bytes + canonical(row)`, the payload construction and the
Ed25519 verification all reproduce from §2, §3 and §7 with no reference to the
implementation. Zero `shape` rows means every case this verifier read, the reference read,
and the one it refused, the reference refused.

What the corpus exercises, so the agreements are not over an untouched surface: record
`format_version` 1 on 31 cases, 2 on 14, and one unreadable version; first-row version 1
on 42 and version 2 on 2, with a salt line in 2 runs, so the keyed-digest rule of §3 and
§14 is reached; `production` on 22 and `benchmark` on 24; 3 cases with a decider registry,
3 with receipts, 3 with a witness statement, 2 with a prior record.

## The three readings

### 1. What "the rest" means in the bail-out rule — three cases, 18 rows, no verdict moved

Cases `counts-wrong`, `payload-hash-wrong`, `format-version-unknown`. After a `document`
that is not established, the reference reports the 8 core properties and omits the 6
conditional ones; this implementation reported all 14, the conditional 6 as unknown.

**The specification determines this and the implementation misread it.** §9 says "a
verifier that stops early reports the rest as unknown with the reason rather than
omitting them", and the next sentence says "The remaining properties are conditional and
are absent or `n/a` legitimately". Read together, "the rest" is the core eight. The
implementation read the first sentence and not the second. Recorded because it took two
sentences in tension to settle, and because the verdict is identical either way — unknown
is never a pass, so over-reporting unknown costs nothing but noise.

### 2. A signature that verifies under a key the registry does not honour — one case, one row

Case `signed-by-revoked-key`. The record is signed by a revoked key the registry does not
name for this payload. Both report `signing_trust` **failed**. The reference reports
`signature` **unknown**; this implementation reported it **established**.

**The specification does not determine this, and the two readings publish different
things.** §9's row is "`signature` | the signature verifies with that key", and it does
verify: the bytes are good. Nothing in §9 or §7 says what `signature` is when the key is
not honoured. The literal reading therefore publishes `signature: established` over a
revoked key, which reads as establishing something the record has not established, and a
second implementer following the sentence as written arrives there.

The sentence that would close it: §9's `signature` row stating that the property is
unknown where `signing_trust` is not established, or §7 stating that a key the registry
does not honour is not used to establish any property. Either removes the reading.

The verdict does not move — `signing_trust` failed, so both are FAILED — which is why
this is a reporting defect rather than a verdict defect. It is the same shape as the verdict
computed over whichever properties a report happened to carry, which §9 now rules out in
terms: a state that reads as establishing something over a check whose premise did not
hold.

### 3. An absent ledger — one case, one row, and the verdict moves

Case `ledger-missing`. The record names a ledger that is not in the directory. The
reference reports `chain` **failed** and the verdict FAILED; this implementation reported
`chain` **unknown** and NOT ESTABLISHED.

**The specification does not determine this, and it is the one disagreement that changes
the published answer.** §8 gives the rule for a named file that is absent — `retained`
unknown, because the digest check could not run — but that rule is about retained files,
and §5 requires that `retained` "must not name the ledger", so the ledger is explicitly
outside it. §9's `chain` row says what established means and not what an absent ledger
is. §9's definition of unknown — "the check could not be performed" — supports this
implementation; the reference's reading, that a record whose ledger is not there has made
a false claim about its ledger, is the stronger one and is not written down.

This was recorded as assumption S10 before the run, which is the one of the 11 that was
assumed wrongly.

The sentence that would close it: §9's `chain` row, or §8 beside the retained-file rule,
stating the state for a ledger that is named and absent.

## What was done about them, 25 October 2026

All three readings were closed in `SPEC.md` §9 the day after this run, and this
section is a dated note rather than a rewrite: the findings above are the
measurement and they describe the specification as it stood.

- The `signature` row now names its premise and states that the property is
  unknown where no honoured key was resolved.
- The `chain` row now states that an absent named ledger is failed and not
  unknown, and names the reason: §14 enumerates what a producer may withhold
  and the ledger is not among it, so a record naming a ledger that is not there
  is incomplete rather than unchecked. That premise is now tested, because
  adding the ledger to §14 would quietly invalidate the rule.
- The bail-out sentence now reads "the rest of these eight" and says that
  nothing is reported about the conditional properties.

One attribution above is corrected by the data. The third reading is recorded
here as this implementation's own misreading of "the rest". The scorer's output
says otherwise: `counts-wrong`, `payload-hash-wrong` and `format-version-unknown`
each diverge on the same six conditional properties, which is 18 of the 20
disagreements it reported, all from one phrase — and that phrase was added to
§9 on 24 October, the day before this run, by the change that made the verdict
refuse an absent core property. A text-only reader applied it to all fourteen
because the sentence permitted that. The ambiguity was the specification's, not
the reader's.

**This measurement cannot be re-run, by construction.** `verifier.py` pins the
digest of the `SPEC.md` it read and refuses against any other, at exit 5. The
rules were written by a reader who had not seen the reference implementation,
and that reader has since seen it, so re-running them against the corrected
text would measure consistent editing rather than sufficiency. A new figure
needs a new reader. The committed `results.jsonl` stays the finding.

## The assumption ledger

Eleven places where the specification left a choice to the implementer. Each is in
`verifier.py`'s `ASSUMPTIONS` with what was assumed and the sentence that would remove it
(`--assumptions` prints them). Ten produced agreement and one, S10, did not.

The ten that agreed are the weak direction of the instrument and are not evidence that
the specification determines them: S1 (a signing key the registry does not carry),
S2 (whether the version 2 HMAC key is the decoded salt or its hex text), S3 (the signing
rule for receipts, witness statements and attestations, reached by analogy from §7's rule
for the record), S4 (whether `by_outcome` carries a zero entry), S5 (the arithmetic of the
four `benchmark` members, which §5 delegates to a file rather than defining), S6 (whether
the declared outcome vocabulary must equal the observed one), S7 (which property a shape
refusal lands on), S8 (an empty `retained` block), S9 (attestations retained with no
decider registry), S11 (`completeness` when receipts are supplied and none refutes).

S3 and S5 are worth separating from the rest. Both were reached by inference from a
sentence about a different object — §7 states the payload construction for the record and
§13 and §15 give three more signed shapes without restating it; §5 names the four
`benchmark` members and points at a file for their definitions. Both guesses happened to
be right. Neither is written down.

## Declared: one contamination, and two handoff gaps

**One expectation was read before the discipline was in place.** While surveying the
corpus, `cases/row-prev-hash-edited/expected.json` was read, before the rule that no
expectation is read until after scoring had been adopted. The reading it could have
influenced is the bail-out cascade of §1 above; §9 states that rule in terms, and this
implementation got that case right and the scope of the cascade wrong, but the influence
cannot be excluded and is recorded rather than argued away. Every other `expected.json`
was first read after the single scoring run, and the `open()` guard made it impossible
during one.

**Two things a second implementer discovers from the data rather than the handoff.**
`HANDOFF.md` says `case.json` "gives the options to verify it with, as paths relative to
this directory" without saying that `receipts` is a list of paths while the others are
single, or that `prior` is a path to the prior's `record.json` rather than to its run
directory. Both were found by reading `case.json` files, which costs nothing but is not
in the contract.

## What was not done

Replay was reported `n/a` throughout, as `HANDOFF.md` instructs: no decider code is
supplied to a second implementer. The three agreements on `invocation` are therefore over
attestation checking and not over re-deciding anything. No case exercises an empty
`retained` block or a declared outcome that never occurs, so S8 and S6 are recorded and
unexercised rather than confirmed.
