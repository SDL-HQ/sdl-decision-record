# Decision Record format, versions 1 and 2

A decision record is a signed document over a hash-chained ledger of decisions
made by a deterministic procedure. Its purpose is that a reader, holding the
directory and a key registry, can establish offline what the producer recorded:
that the record is unchanged since a key the registry honours signed it, which
decisions it states the procedure made and under which policy, and, where the
inputs and the policy are retained and the procedure is supplied, that re-running
the procedure on them gives the decisions stated. Whether those are all the
decisions the procedure made (§13), and whether a retained input is the one that
arrived (§16), are questions for a party other than the producer: a receipt
holder, a witness, an attester and its log. It does not establish that any
decision was right, except in the benchmark profile, where "right" means "agreed
with a label the run's author supplied".

This document is enough to write an emitter in another language. `dr/` holds the
verifier and the writer that this repository's records were made and checked
with, and `examples/TRANSCRIPT.md` is what they print.

Version 2 of the record adds one optional block, `stream` (§12), and version 2
of the row changes one field, `input_digest`, to a keyed digest (§14). A
version 1 reader judges version 1 documents exactly as before and reports
version 2 as unknown (§10). Sections 12 to 14 are the additions; §13 states the
limit they are built around: completeness is not a property a self-signed
record can carry.

## 1. Terms

- **decider**: a deterministic procedure with no model in its path, identified
  as `<id>@<version>`, that maps an input and a policy to an outcome and an
  optional reason. Same input, same policy, same state: same decision.
- **policy**: the configuration the decider ran under, identified by the digest
  of its canonical form.
- **outcome**: one of the decider's declared vocabulary, e.g. `ALLOW`, `DENY`,
  `ROUTE`. The format fixes no vocabulary.
- **run directory**: `record.json`, the ledger, and any retained files.
- **profile**: which properties the record carries. v1 defines `production`
  and `benchmark`.

## 2. Canonical bytes and digests

Everything hashed or signed is the canonical JSON of an object: UTF-8, keys
sorted, separators `,` and `:` with no whitespace, non-ASCII unescaped. A
digest is `"sha256:" + lowercase hex` of SHA-256 over bytes. `digest(obj)` means
the digest of the canonical bytes of `obj`; `digest(file)` means the digest of
the file's bytes as stored.

Field order in a file on disk is therefore irrelevant. Reformatting a record or
a row changes nothing; changing a value changes its digest.

Every file the format defines is I-JSON (RFC 7493), the profile RFC 8785
requires. A reader refuses, where the file is read, everything that is not:
the bare constants `NaN`, `Infinity` and `-Infinity` (not JSON at all);
numbers past a double's range, written as `1e400` or as an integer with more
digits than a double holds; lone surrogates; and duplicate member names, on
which parsers disagree about which value wins. A file carrying any of these is
treated as a file that is not JSON (a record is unreadable, a ledger line fails
`chain`, a registry is unreadable), never left to whichever check would hash it
first. The canonical form therefore rejects nothing a reader accepts, and no
two conforming readers see different values in a file a reader accepts.

A JSON Lines file (`decisions.jsonl`, `inputs.jsonl`, `attestations.jsonl`,
`arrivals.jsonl`) is read as bytes, decoded as UTF-8, and split into lines at
LF (U+000A) and at nothing else. Lines that are empty or hold only JSON
whitespace are skipped. U+2028, U+2029 and U+0085 may stand unescaped inside a
JSON string, and the canonical form writes them that way, so a reader that also
ends a line at them breaks an honest line in two. A CR is JSON whitespace, and
a reader in text mode that turns a lone CR into a line end does the same.

An input carries one more refusal, because its digest is the input's identity:
a number whose spelling denotes a different value from the one its canonical
bytes denote. Examples are `1.00000000000000001`, which a double reads as 1,
and `1e-400`, which it reads as 0. The digest is the digest of the double's
value, and a party that reads the same text keeping every digit decides
another number under that digest. Spellings of the same value (`1E2`, `100.0`,
`1.0e2`) are one input. The gate's command line reads its inputs this way, and
so does the attester given text (§16.2). A document may carry such a number,
and its digest covers the double. `SEAMS.md` records, class by class, how each
party here and each engine reads the classes of JSON on which parsers are
known to disagree.

**Equal digests, equal decisions.** An input is identified by `digest(input)`,
and two inputs can have one canonical form: `{"n": 396}` and `{"n": 396.0}` are
the same bytes, and a decider with its own type model can decide them
differently. So an input is decided, re-decided and attested as **the value its
canonical bytes denote** — the canonical bytes read back, an integer within
±(2^53 − 1) as an integer and any other number as the double it renders. The
gate refuses an input that is not already that value, so what it decides and
retains is what the digest covers; replay (§8) and re-derivation decide that
value whatever form the retained file holds; the attester (§16) signs its
digest. Two inputs with equal digests are then decided identically by any
deterministic decider. An input carrying an integer beyond ±(2^53 − 1) has no
such value — its canonical bytes stand for its neighbours too — and is refused
by the gate and the attester and fails replay. The canonical bytes themselves
are unchanged: a document (a policy, a corpus, a result set) may carry such an
integer and is digested as RFC 8785 renders it; the refusal is of an input.

## 3. The ledger row

The ledger is a file of JSON objects, one per line, in decision order. Row
version 1 carries exactly these keys and no others:

| key | type | meaning |
|---|---|---|
| `v` | integer | `1` |
| `seq` | integer | 1..n, in file order, no gaps |
| `ts` | string | `YYYY-MM-DDTHH:MM:SSZ`, the time the decision is recorded as having been made |
| `input_digest` | digest | `digest(input)`, the input as the decider saw it |
| `decider` | string | `<id>@<version>` |
| `policy_digest` | digest | `digest(policy)` |
| `outcome` | string | non-empty, one of the decider's declared outcomes |
| `reason` | string or null | the decider's own account of why; non-empty when present |
| `label` | string | optional: the outcome this input was expected to receive |
| `ext` | object | optional: decider-defined, opaque to the verifier except for `prior_row` (§12), covered by the hash |
| `prev_hash` | string | the previous row's `row_hash`, or `GENESIS` for row 1 |
| `row_hash` | digest | `digest(prev_hash_bytes + canonical(row without prev_hash and row_hash))` |

`prev_hash_bytes` is the UTF-8 of the `prev_hash` string. Because the hash
covers the canonical form of every other key, there is no list of covered
fields to maintain: adding a key to a row changes its hash. A row with an
undeclared key is refused on shape as well.

**Row version 2** is identical except that `v` is `2` and `input_digest` is
`"hmac-sha256:" + lowercase hex` of HMAC-SHA256 keyed with the run's salt over
the canonical input. The salt is the first line of `inputs.jsonl`,
`{"salt": hex}`, so a reader with the inputs checks the rows exactly as for
version 1 and a reader without them cannot test guessed inputs against the
digests (§14). A ledger has one row version throughout. A v2 row whose
`input_digest` is not a keyed digest, or a v1 row whose inputs file starts with
a salt line, is malformed.

A row's `ts`, `input_digest`, `outcome` and `reason` are what the producer
wrote. The chain makes them tamper-evident after the fact; it does not make
them true. What makes them checkable is §8.

## 4. The chain

Verification re-derives every `row_hash` from `GENESIS` forward and requires
each row's `prev_hash` to equal the previous row's `row_hash`. The terminal
hash is the last row's `row_hash`. A ledger that mixes row versions is
malformed. A ledger whose rows declare a version the verifier does not read is
**unknown**, not failed: the verifier cannot judge it and says so.

Two consequences worth stating. A tamperer who edits a row and recomputes that
row's hash from its own `prev_hash` produces a row that re-derives; the next
row's `prev_hash` no longer matches, and that is what the linkage check is
for. A tamperer who recomputes every hash forward produces a valid chain with
a different terminal hash, and the record signs the terminal hash.

## 5. The record

`record.json` is one JSON object with exactly these keys:

| key | content |
|---|---|
| `format` | `"sdl-decision-record"` |
| `format_version` | `1`, or `2` when the record carries `stream` |
| `profile` | `"production"` or `"benchmark"` |
| `record_id` | a non-empty string the emitter chooses; opaque |
| `issued_at` | `YYYY-MM-DDTHH:MM:SSZ`, when it was signed; asserted, not checked |
| `decider` | `{"id", "version", "outcomes": [distinct non-empty strings]}`, optionally `"established_versions": [{"version", "evidence": digest}]` (§8) |
| `policy_digests` | sorted, distinct digests of every policy the rows ran under |
| `ledger` | `{"path": bare filename, "row_count": n > 0, "terminal_hash": digest}` |
| `counts` | `{"decisions": n, "by_outcome": {outcome: n}}` |
| `benchmark` | `{"labelled", "agree", "disagree", "by_label": {label: {outcome: n}}}`; present iff profile is `benchmark` |
| `retained` | `{relative path: digest(file)}` for files kept beside the ledger; may be `{}`; must not name the ledger |
| `stream` | version 2 only, optional: `{"stream_id", "seq", "prev_record_hash", "first_decision"}` (§12) |
| `signing_key_id` | the registry key that signed |
| `payload_hash` | `digest(canonical(record without payload_hash and signature))` |
| `signature` | Ed25519 over the same bytes, base64 |

Every figure in `counts`, `benchmark` and `policy_digests` is derived from the
rows by one definition (`dr/derive.py`), which the emitter and the verifier
both call. The record has no boolean field and no field that states a check
was performed. That is deliberate and tested: a record supplies claims the
rows can contradict, never flags a verifier reads to decide whether to look.

## 6. Profiles

A profile is what the rows' own content supports, read off the rows:

- every row carries `label`: the rows support **benchmark**;
- no row carries `label`: the rows support **production**;
- some do and some do not: the rows support **no profile**, and a record over
  them fails whatever it declares.

The record's `profile` is a declaration compared against that. A record may
not choose a profile that excuses it from a property its rows support: a
production record over labelled rows fails both `profile` and `correctness`,
because correctness was computable and was withheld. A benchmark record over
unlabelled rows fails because it claims a property it cannot have.

| property | production | benchmark |
|---|---|---|
| document, signing_trust, signature, chain, decisions, retained | required | required |
| correctness | not applicable | required |
| replay | on request | on request |

**What production does not carry, by design.** A record of real traffic has no
labels, so no statement about whether any decision was *correct* is available
from the rows, and the format does not invent one. What is available is what
the procedure decided, under which policy, how often, and, with retained
inputs, that the procedure re-decides the same way. That is the honest extent
of a decision record without a corpus.

## 7. Signing and keys

Payload: canonical bytes of the record without `payload_hash` and `signature`.
`payload_hash` is its digest. `signature` is Ed25519 (RFC 8032) over the
payload, base64. Ed25519 signatures are deterministic, so the same record
signed by the same key is the same bytes.

The registry is `{"registry_version": 1, "keys": [{"key_id", "status",
"public_key_pem", "trusted_after_revocation": [payload_hash, ...]}]}`. Status
is `active` (signs now), `retired` (no longer signs; honoured for what it
signed) or `revoked` (not honoured for anything the registry does not name).
A revoked key is assumed held by someone who can sign any content with any
timestamp, so nothing inside a record places it before the revocation; trust
after revocation is granted by the registry listing that record's
`payload_hash`, and in no other way.

## 8. Retained files and replay

A record may name files kept beside the ledger, each with its digest. Two
names have meaning:

- `inputs.jsonl`: one line per row, `{"seq": n, "input": <object>}`, where
  `digest(input)` is row n's `input_digest`. The verifier checks every line.
- `policy.json`: the policy, whose `digest(parsed object)` must be the rows'
  single `policy_digest`. Checked when the rows carry exactly one.

With both retained, a verifier can **replay**: load the decider named by the
record, construct it with the retained policy, feed it the retained inputs in
`seq` order from a fresh state — each as the value its digest covers (§2), not
the retained bytes' own reading of it — and require every `(outcome, reason)`
to equal the row's. Replay runs on request because it executes the decider's code,
which the verifier does not ship. A replay with a decider whose `<id>@<version>`
is not the record's proves nothing and is reported as unknown.

**Re-derivation under the grammar's own engine.** Replay above runs the
decider the record names. A third party may instead rebuild the engine
request from the retained input and evaluate it under the grammar's own
engine, with none of the producer's code in the path. That is only possible
where the mapping from retained input to engine request is published, so for
the Cedar profile it is stated here rather than left in the emitter.

The retained input is an object carrying `principal`, `action` and `resource`,
each `{"type", "id"}`, an optional `context` object and an optional `entities`
list. The request is `{principal, action, resource, context}` taken by those
names, `context` defaulting to `{}`. Any other key of the retained input is
commentary and is not part of the request. The entities the engine is given
are the policy's own `store` when the policy sets `"entities": "store"`, and
the input's `entities`, or `[]`, when it sets `"entities": "caller"`.

Where the policy sets `"canonicalise": "url-v1"` the input is rewritten before
the request is built. The rewrite walks the whole input object and replaces
every string value sitting under one of these keys, at any depth:

| key | operation |
|---|---|
| `host`, `name`, `domain`, `recipient_domain` | host |
| `url_path`, `path` | path |
| `currency` | upper-case |
| `scheme` | lower-case |

*host* is: strip surrounding whitespace, drop trailing dots, lower-case, then
IDNA-encode, keeping the lower-cased form if the encoding raises. *path* is:
percent-decode once, then normalise `.` and `..` under POSIX path semantics,
re-attaching a leading `/` when the decoded path carried one. After that
rewrite, the `id` of `principal` and of `resource` is host-canonicalised when
its `type` name ends in `Host`. Under `"canonicalise": "none"` none of it runs.

That `name` is in the table is a property of this profile and not of Cedar: a
key called `name` is host-canonicalised wherever it appears.

The reason string is formed from the engine's diagnostics: for ALLOW, the
determining policy ids sorted and joined with `+`, or `allow` where there are
none; for DENY, the same join, or `no-policy-permits` where nothing
determined it, or `request-invalid` where the engine refused the request.

What this publishes is the content of the mapping, not a binding to it. The
policy object carries the mode's name and not its content, so a record and
this specification can still drift apart; carrying the key map and the
canonicalised entity types in the policy object, where the policy digest
covers them, is the stronger fix and is not done here. A re-derivation should
therefore report what it had to assume rather than presenting its agreement as
unconditional. `experiments/rederivability/` measures what an assumption is
worth: against a record whose canonicalisation was widened, re-derivation
reproduces 39 of 40 decisions and differs on one, where a homograph host the
record admitted is refused; against one with a context key dropped, 37 of 40,
with three refusals re-derived as permits.

**Established versions.** A record may name other versions of its decider
under `decider.established_versions`: each `{"version", "evidence"}` says
that a conformance run established that version as agreeing with the
record's on every case the run did not exclude by name, and `evidence` is
`digest(result)` of that run's result object, exclusions included: a result
may carry `excluded`, each entry a named case with a stated reason (a case
the corpus's own harness runs that the engine's invocation path cannot
reproduce), and the verifier compares agreement with the request count less
the exclusions and prints the reasons it accepted. A replay under a named version is accepted and reported as under
that version. The naming is the producer's claim, as the record's own
version is; a verifier given the run's result (`--conformance-evidence`)
checks that its digest is the one named, that it reports the named engine,
and that it agrees on every case it did not exclude, and refuses the name otherwise. A version the
record does not name is refused as before. What naming costs: the version
check no longer refuses a drifted engine by name, so a falsely named engine
is caught by recomputation where the rows exercise the difference and not
where they do not. `examples/cedar/ENGINES.md` measures both, against
released engines.

The converse limit is the corpus's, and it is not symmetrical with the one
above: agreement establishes nothing about a field the corpus does not vary.
Measured on Cedar's generated corpus (`examples/cedar/LEAN.md` §2): none of
its 5,677 policies carries an `@id` annotation, and exactly one policy id,
`policy0`, appears in all 31,075 of its expected reason and error entries,
because the generator renames every policy before computing expectations.
A run against that corpus is therefore silent about how an engine names
policies — a field every row of this repository's own Cedar records carries
and replay compares. A producer naming a version on a perfect conformance
run has no way to discover that from the mechanism. The record retains the
policy and the inputs, so comparing what the corpus exercised against what
the rows depend on is computable, and `tools/corpus_coverage.py` computes it,
on request, as a property beside §9's: `corpus_coverage`. A *feature* is a
structural element of a policy or a request that an engine's evaluation can
depend on — operators, extension functions, condition kinds, the number of
policies, identifier annotations, how many distinct policies the reasons
name; entity types read as namespaced or plain, the presence of a context,
entity counts in buckets. The record side is read from the retained policy
and the retained inputs, never from the decisions; the corpus side is read
from the corpus. The rule is subset, not variety: a feature is covered when
every value the rows use appears somewhere in the corpus, because an engine
that mishandled that value would then have disagreed on some case. The
property is **established** when every feature the rows depend on is covered
and **unknown**, naming the silent features and the values on each side,
otherwise; it has no failed state beyond malformed input, because a silence
is a limit on what the named conformance evidence establishes, not a false
claim by the record. The policy side is read from the grammar's own parse
when `cedarpy` is present and from the text otherwise, and the output names
which. Run over this repository's Cedar records (`tools/corpus_coverage.py`,
with the pinned corpus), every one is unknown, on exactly
the three features above — one policy per case, no `@id`, one policy named —
so 45,416 of 45,416 says nothing about a `forbid` in one policy overriding a
`permit` in another, which is the interaction the toolcalls policy set is
built on.

A decider under a second grammar (`emitters/opa.py`, Rego evaluated by the
OPA binary) carries in its policy object what that engine's evaluation
consults beyond the policy text and the data: the Rego language version, the
allowed builtin set (filtered from the engine's capabilities and refused at
construction when it names a builtin whose value depends on the clock, the
network or the process), and the builtin error mode. The record format is
unchanged by it; what changed is what counts as "the policy".

A stateful decider (a rate limiter) can be replayed only over the whole ledger
in order; a single row of such a decider is not independently re-derivable, and
its `ext` should carry the state the decision was taken on so the row says what
the decider saw.

Without retained inputs a record is a tamper-evident account of what the
producer wrote. With them it is replayable. The format supports both and the
verifier says which it has.

A named file that is **absent** from the copy being verified leaves `retained`
**unknown**: the digest check could not run. A named file that is present and
differs from its digest is a **failure**: the record's claim about it is false.
The distinction matters because one signed record may be handed to different
readers with different files beside it (§14): the reader without `inputs.jsonl`
sees that custody of the inputs is not established and that replay is not
possible, not that the record lied.

## 9. Verification

Every property is one of **established**, **unknown**, **failed**, or
**n/a** when the profile has no such property. Unknown means the check could
not be performed or could not be computed: a registry entry that is malformed,
a row version this verifier does not read, rows that did not re-derive so
nothing over them was computed. Unknown is a statement about what the
verifier was given or what it does not read, never about the document's
honesty, and it is never a pass. It is never the verifier's own fault: a check
that raises on something other than a supplied file it could not read, or one
of the wrong shape, is not reported as any property's state. It reaches the
command's guard, which exits 3 with `VERIFIER ERROR` (below). A malformed file
and a broken verifier can raise the same kind of exception, and where they do,
the file is given the benefit of being read as the cause. That residue is
recorded.

| property | established when |
|---|---|
| `document` | the shape of its `format_version`; `payload_hash` recomputes |
| `signing_trust` | the registry honours `signing_key_id` for this record (§7) |
| `signature` | the signature verifies with the key `signing_trust` honoured. Unknown when no honoured key was resolved, because the check has no premise then: bytes that verify under a key the registry refuses establish nothing |
| `chain` | the ledger re-derives from GENESIS to the signed `terminal_hash` with the signed `row_count`. **Failed, not unknown, when the named ledger is absent**: §14 enumerates what a producer may withhold and the ledger is not among it, so a record naming a ledger that is not there is incomplete rather than unchecked. This is the one place the rule differs from an absent retained file (§8), which is unknown because §14 licenses withholding it |
| `decisions` | `counts`, `policy_digests` and `decider` recompute from the rows; every outcome is in the declared vocabulary |
| `profile` | the declared profile is the one the rows support (§6) |
| `correctness` | benchmark only: `benchmark` recomputes from labels |
| `retained` | every named file is present with its digest; `inputs.jsonl` and `policy.json` match the rows (§8); an absent named file is unknown |
| `replay` | on request: the named decider reproduces every outcome and reason from the retained inputs |
| `stream` | n/a without `stream`; established for `seq` 1; for `seq` > 1, established only when the prior record is supplied and the link holds (§12), unknown without it |
| `completeness` | **never established.** n/a when no receipt is supplied; failed when a supplied receipt names a decision the record lacks (§13) |
| `receipts` | n/a without receipts; established when every supplied receipt is for a row that is present with the receipted `row_hash`; failed on a missing, altered or invalid receipt; unknown for receipts that could not be checked or belong to another run |
| `witness` | n/a without a statement; established when a key in the witness registry, which is not a producer key, signed this record's `payload_hash` (§13); failed when the statement is for another payload or does not verify; unknown without a witness registry or when the witness is the producer |

`document`, `signing_trust`, `signature`, `chain`, `decisions`, `profile`,
`correctness` and `retained` are decided by every verification of every record.
A report that does not carry one of them has not judged it, and a property
nobody judged is unknown: a verifier that stops early reports the rest of
these eight as unknown with the reason rather than omitting them, and reports
nothing about the conditional properties. The remaining properties are
conditional and are absent or `n/a` legitimately. Without this rule a verdict
computed over the properties a report happens to carry is a statement about the
checks that ran, and is read as a statement about the checks there are.

Verdict: **FAILED** (exit 2) if any applicable property failed; **NOT
ESTABLISHED** (exit 1) if none failed and any is unknown, an absent core
property included; **ESTABLISHED** (exit 0) otherwise; exit 3 if the directory
could not be read, or if the verifier itself failed, which it says on standard
error: nothing was judged either way, and a fault in the verifier never exits
with a verdict's code. Files in the directory the record does not name are listed
as a note and vouched for by nothing.

### 9.1 The assurance ladder

The four-state report answers, property by property, what a verification
established. The ladder names what a set of properties, all established, lets
a reader rely on. It is a way to read the report and never a substitute for it.

| level | name | adds, all established | what a reader may rely on |
|---|---|---|---|
| A0 | the operator's word | — | nothing beyond what the producer says |
| A1 | integrity | `document`, `signing_trust`, `signature`, `chain`, `decisions`, `profile`, `correctness` (or n/a), `stream` (or n/a) | the record and its rows are unchanged since they were signed, and its counts recompute |
| A2 | re-evaluable | `retained`, `replay` | the retained inputs, re-decided under the retained policy, give every recorded outcome and reason |
| A3 | invoked | `invocation` | the decider itself signed each decision, under a key the producer does not hold |
| A4 | witnessed | `arrival`, `arrivals_accounted` (§16) | a party other than the producer signed each input as it arrived, and the rows account for its log |

- **A level is a set of properties that must all be established**, and it
  includes every level below it. One property in a level's set that is
  unknown, not judged, or n/a where the level needs it means the level is not
  reached. `correctness` may be n/a outside the benchmark profile, and `stream`
  outside a stream. Nothing else may.
- **A failed property voids the ladder.** A report with a failed property
  reaches no level, A0 included.
- **No level is shown without the table.** A verifier states the level only
  after the properties and the verdict, in the same report. In JSON the level
  is an `assurance` object beside `properties`, and it carries the states it
  was computed from. The level is stated on request (`--assurance`); without
  the request the report is unchanged, and the exit code is the verdict's in
  either case.

No level covers `completeness` (never established, §13), `receipts` or
`witness`. These stay in the table and are not ranked.

**A level is not truth, and the ladder is built to say where it stops.** A
record whose retained input was replaced by one that never arrived, and then
decided honestly, reaches A3: it is signed, chained, re-evaluable and invoked,
and it is a fabrication (`experiments/rederivability/out/f5-input-fabricated`).
Only A4 is closed to it, because only an independent party's signature over
what arrived contradicts it. Integrity is not occurrence.

The levels are numbered A0–A4 so that they are not confused with the rungs
L0–L3 of `experiments/rederivability/RESULTS.md`. Those rungs order the ways a
verifier can re-derive a decision by what each still accepts on trust, which
is a different question.

## 10. Versioning

A record declares `format_version`; a row declares `v`. A verifier judges each
by the rules of the version it declares and reports a version it does not read
as unknown. A new version adds a new version number with its own rules; it
never adds a required key to an earlier version, because a key required at a
floor that predates it invalidates every record in between. Record version 2
adds the optional `stream` block and nothing else; row version 2 changes the
digest function of one field and nothing else. A version 1 record over
version 2 rows is permitted (the row version is about the digest, the record
version about the stream).

## 11. What a verified record does not establish

- That any decision was correct, outside the benchmark profile, and there only
  against the labels the run's author supplied.
- That the inputs were what the system actually received, unless retained; and
  if retained, only that the retained bytes hash to what the rows carry.
- That the times are true. `ts` and `issued_at` are the producer's assertions.
- That the decider named is the code that ran. Replay establishes that a
  supplied implementation reproduces the decisions; it does not identify the
  original.
- That a run was complete. The ledger is what the producer wrote; a row never
  written leaves no trace, and a row deleted before signing leaves none
  either. §13 states this precisely and names what crosses it. Nor does a
  record say how far a written row had got when the producer's process
  stopped — whether it was handed to the kernel or to the medium before the
  next decision was taken is the producer's durability policy, and a run
  stopped before signing yields no record rather than a shorter one.
- That each row is a distinct event. A decision recorded twice — the ordinary
  cause is a request retried after its worker died before acknowledging, so
  the restarted worker decided it again — is two rows with the same
  `input_digest`, `policy_digest` and `outcome` and different `seq` and `ts`.
  Every property holds, `counts.decisions` is two for one request, and the
  benchmark counts are counts over rows. A repeated digest is not by itself
  evidence of this, because some deciders are meant to see the same input
  twice; §13 says what it would take to tell.
- Anything about a model, a user, or a downstream effect. The record describes
  a decision procedure's output and nothing beyond it.

## 12. Streams (record version 2)

A deployment produces records one after another. A version 2 record may carry

    "stream": {"stream_id": <string>, "seq": n >= 1,
               "prev_record_hash": <digest or null>, "first_decision": m >= 1}

`prev_record_hash` is the previous record's `payload_hash` (null iff `seq` is
1). `first_decision` is the stream-wide number of this record's row 1: 1 for
the first record, and for each later record the prior's `first_decision` plus
the prior's `row_count`. The block is inside the signed payload.

Given the prior record, the verifier establishes `stream` when `stream_id`
matches, `seq` is the prior's plus one, `prev_record_hash` is the prior's
`payload_hash`, and `first_decision` continues the prior's numbering. The
prior's `payload_hash` is the one computed from its fields (§5), never the
copy the prior carries: an edited body keeps that copy unchanged. A record
whose `prev_record_hash` is not the prior's computed hash fails `stream`; a
prior whose fields do hash to it but whose stated copy does not recompute is
the predecessor with a corrupted copy of its own identity, and the link holds
with that said. A prior that cannot be read, is not a record, or holds a
value with no canonical form leaves `stream` **unknown** with the reason: it is
a statement about the file supplied, not about the record. The verifier's own
failure while hashing is not a reason; it exits 3 (§9). Given a
set of records, `dr.stream` additionally reports **forks**: two distinct
records signed for one `(stream_id, seq)`, which is a producer having signed
two histories; distinct means distinct computed `payload_hash`. A record whose
hash cannot be computed is named as such and grouped by the `payload_hash` it
states, so records that cannot be hashed never merge into one. `dr.stream`
exits 0 when every record links, 1 on defects, 2 on a fork, and 3 when nothing
was judged: a file could not be read, none of the records given is part of a
stream, or the checker itself failed. A record given that is not part of a
stream is named and not checked.

A row of a stream record may name a row of the prior record: `ext.prior_row`
is that row's `row_hash`. Given the prior record with its ledger beside it,
the verifier reads every `prior_row` present and establishes `stream` only
when the prior's ledger re-derives to the terminal hash the prior signs and
every named hash is a row of it; a named hash the prior's ledger lacks fails
`stream`, and a prior supplied without its ledger leaves `stream` unknown
when any row names one. What a reference establishes: that the named row
existed, signed, before this row was written — a hash points one way, so a
later record can name the rows of an earlier one and not the reverse. It
does not establish that the named row caused this one, or what either
decider did with the other's decision; it is a join, not a dependency. A
record whose rows name none is checked exactly as before.

What a stream establishes: that the records held form one unbroken sequence
from the earliest held, and that no record in the middle of what is held has
been replaced without the replacement being visible as a fork or a broken
link. What it does not establish: that the earliest record held is the first
(the verifier says so when `seq` > 1), or that any record exists after the
latest held. The tail is always open. A stream converts "a record was removed"
into "a record is missing here" for every position but the last.

## 13. Completeness: the boundary, and what crosses it

**A self-signed record cannot establish that it is complete.** The producer
holds the key; the producer chooses what is signed. Delete any rows, renumber,
recompute the chain forward, re-derive the counts from the rows that remain,
sign: every property in §9 holds, because every property is a statement about
the rows that are in the record. `tools/truncate.py` does
exactly this and the verifier reports ESTABLISHED (`tests/test_completeness.py`
holds it; `examples/TRANSCRIPT.md` §8 shows it). The `counts` block is a count
of what the producer wrote, not of what happened, and the verifier's
`decisions` detail says so in those words.

Accordingly the verifier has a `completeness` property that is **never
established**. It is n/a (not claimed) or failed (refuted). A test holds that
no code path reports it otherwise. What can be established is narrower and
comes from outside the producer:

**Receipts.** At decision time the producer signs, for each row, a receipt
`{"kind": "sdl-decision-receipt", "record_id", "stream_id", "seq",
"decision_no", "row_hash", "ts", "signing_key_id", "payload_hash",
"signature"}` and hands it to the party the decision was about. The receipt
leaves the producer. A reader who holds the record and a receipt checks it:
**included** (the row is present with the receipted `row_hash`), **missing**
(`seq` is beyond the ledger: the producer acknowledged a decision the record
does not contain), **altered** (the row at that `seq` is a different row),
**foreign** (another run), **invalid** (shape, signature, trust) or
**unknown**. A missing receipt refutes completeness and gives a quantitative
gap: a receipt for decision `seq` k of a record with n < k rows proves that at
least k - n acknowledged decisions are not in it. An interior deletion turns
every later receipt into an alteration. Receipts establish a lower bound on
what happened, held by whoever holds them; they say nothing about decisions
whose receipts no one kept.

**Witness statements.** A second party countersigns a record's `payload_hash`:
`{"kind": "sdl-witness-statement", "record_payload_hash", "witnessed_at",
"witness_key_id", "payload_hash", "signature"}`, with its own key registry.
It establishes that this exact record existed when the witness signed, and
bounds nothing before that: a producer who deleted rows before the witness saw
the record has a witnessed truncation. With a stream it fixes the sequence from
that point on. A witness key that is also a producer key establishes nothing
and is reported unknown.

**Self-witnessing by a stateful decider.** When the decider's decision at row
n depends on rows before it (the rate limiter), replay partly witnesses
deletions: deleting a row that influenced a later decision makes that later
decision unreproducible, and replay fails. Deleting a row nothing depended on
is not detected. Stateless deciders cannot self-witness at all. This is a
property of the decider, not of the format, and it is partial; it is recorded
because it falls out of replay for free and because it bounds what a
"tamper-evident" claim about a stateless gate can mean.

**The other direction: a decision recorded twice.** Omission has a twin that
§11 names: a request decided and recorded more than once, as at-least-once
retry produces. Nothing here refutes it, and nothing in the record can, for
the reason the self-witnessing paragraph gives in reverse: whether a repeated
`input_digest` is one request seen twice or two requests with the same bytes
is a property of the decider and the caller, not of the rows. A rate limiter
is built to see the same input twice; a stateless gate under a retrying
client sees it twice by accident. The bias is directional, not noise: the
requests that die before acknowledgement are the ones that exhausted a
budget, which concentrates duplicates in the inputs a reader is most likely
to care about. Nothing in this specification tells the two apart, and a
reader of the benchmark counts should know that.

**Ranking, by what the counterparty must do.** Witness statement: one
signature per record, one trusted second key. Stream: nothing from a second
party, but it closes only the middle. Receipts: one signature per decision and
a counterparty who keeps them. Only receipts refute completeness; a witness and
a stream make a refutation stick to a position.

**Ranking, by what survives the producer's process stopping.** A witness
statement is made over a record after it is signed, and a stream links records
after they are written; a run that stops before `record.json` exists leaves
nothing for either to attach to. Receipts are the one artefact that leaves the
producer before the stop: they are issued at decision time and held elsewhere.
Under interruption — a crash, a kill, the power — they are not merely the
strongest refutation of what the record omits; they are the only one that
exists.

## 14. Saying less

A record exposes what its rows carry. These are the options for saying less,
each with what it costs the verifier.

- **Withholding `inputs.jsonl`** from a reader removes what the inputs reveal
  about the policy's content (allowlists, thresholds, class boundaries). It costs that reader replay and custody of the inputs, which the
  verifier reports as unknown, never as failure or as a pass. The producer
  keeps one signed record and chooses per reader what to put beside it.
- **Row version 2 (keyed digests).** A version 1 `input_digest` is a plain
  hash of the input, so a reader without the inputs can still test guesses
  against it, and for low-entropy inputs (a principal name and a time, a
  destination and a few field levels) the test succeeds for every row. The
  keyed digest removes that at no cost to a reader with the inputs. It costs a
  reader without them the ability to find their own input in the ledger by
  hashing it; a receipt (§13) gives that reader the row directly.
- **`ext` withheld** (emitter option). The `ext` block is what the decider saw;
  with inputs it is redundant with replay, and without them it is the leak (the
  rate limiter's `ext.window_count` gives its threshold exactly from rows
  alone). Withholding it costs nothing the verifier checks.
- **Coarse reasons** (a decider policy setting, `reason_detail`). A reason that
  names an argument or a field leaks the schema one name at a time from rows
  alone. A coarse reason names the kind of defect only. Replay still matches,
  because the decider reads the setting from the same policy the rows digest;
  the cost is to a human reader of the rows, not to the verifier.

None of these changes what the record claims. They change what a reader who
is not given the inputs can learn. With all four, such a reader still learns
the outcome distribution, the row count, the timing, and the kinds of defect
that occurred.

## 15. Invocation: did the decider decide these rows?

A row is the producer's statement of what the decider said. Replay (§8)
re-decides the retained inputs with the named decider and compares; it
establishes that the rows are what that decider would say, and nothing about
whether the decider was called. A producer that forwards without the decider
and writes the outcome the decider would have given produces rows replay
establishes.

A decider attestation closes this. The decider holds a key the producer does
not, and signs each decision as it makes it:

    {"kind": "decider-attestation", "record_id": "...", "seq": n, "input_digest": "sha256:...",
     "outcome": "...", "reason": ... | null, "policy_digest": "sha256:...", "decider": "<id>@<version>",
     "decider_key_id": "...", "payload_hash": "sha256:...", "signature": "..."}

one per line in `attestations.jsonl` beside the rows, retained and so named
in the record with its digest. The body is the decision the decider knows it
made, bound to the run id and to the sequence number the producer told it;
it is not the row hash, which the producer computes afterwards from fields of
its own. Where the input came with an arrival (§16), the body also carries
`"arrival": n`, the arrival's number: it reached the decider from the attester
with the input, not from the producer afterwards, so it is the decider's to
sign, and the invocation check below requires the row to name the same one.
`dr.emit.Run` writes one per `decide()` when given `decider_key_id` and
`decider_private_key_pem`, and writes none for a row passed
`decided_by_decider=False`.

The verifier's **invocation** property, checked when `attestations.jsonl` is
retained and `--decider-registry` names the decider's keys: every row has an
attestation; each matches its row on record id, seq, input digest, outcome,
reason, policy digest and decider, and, where the attestation carries
`arrival`, the row's `ext.arrival` is that number — a row re-pointed at another
arrival after the decision fails here on the attestation alone, whatever §16
says; each verifies under an active key of the
decider registry; and that key's material is not any producer key (the
witness rule, §10). Any row without one fails the property, whatever replay
says of it. `n/a` when no attestations are retained: the rows are then the
producer's word, as before.

What it does not establish: that the decider key was held only by the
decider. Key material being distinct from the producer's is checkable;
custody is organisational.

## 16. Arrival: did these inputs arrive?

Decided by `tools/verify_arrival.py` on request, on top of the verification of §9,
as re-derivation is by `tools/rederive.py` (§8): the reference verifier `dr/verify.py`
is unchanged and reports neither property. A report that carries them carries them
beside §9's, with the same four states and the same rule that unknown is not a pass.

### 16.0 The precondition, first

An arrival is worth exactly as much as the attesting party's interest runs against the
producer's. The mechanism below is a signature; the evidence is the signer. A producer
that operates its own attester has signed twice, and the verifier says so rather than
establishing anything (§16.4). What the format can check is key material; whether the
party holding the key would in fact dispute the producer's account is organisational
and outside it, as for witnesses (§13) and decider attestations (§15).

### 16.1 What a record cannot establish about its inputs

Replay (§8) and re-derivation re-decide the retained inputs and establish that the
decisions follow from them. Neither establishes that the retained inputs are what the
system received. A record whose retained input at one row is a call that never arrived,
honestly decided, establishes on every property of §9: that is the limit this section
closes, and it is the mirror of §15. An attestation establishes that the producer could
not have written a row's decision without the decider; an arrival establishes that it
could not have written the row's input without the party that received it.

### 16.2 Arrivals

An **attester** stands in front of the decider, holds a key the producer does not, and
signs each input as it arrives:

```
{"kind": "input-arrival", "arrival_seq": n, "input_digest": "sha256:…",
 "attester_key_id": "…", "payload_hash": "…", "signature": "…"}
```

`arrival_seq` is the attester's own count, starting at 1 and increasing by 1 per arrival.
The count belongs to the attester, not to a process: a restarted attester reads its own
log and continues from the last arrival in it, and refuses to open a log that is not a
contiguous run from 1. A final line cut short by a stop is the one exception: an arrival
is handed out only after its line and newline are written, so a torn line was never
handed to anyone, and it is dropped.
`input_digest` is `digest(input)` under §2 — the plain digest, never the keyed one of
§3, because the attester does not hold the run's salt. The signature is over the
canonical body as for a record (§7). One file, one arrival per line, in arrival order:
`arrivals.jsonl`, retained like any other file (§8) and so bound by digest in
`record.retained`.

The attester keeps its own copy. The copy the record retains is the producer's; the
two are the same bytes or the property fails (§16.4).

The attester and the gate must read an input's bytes as one value. Given the text, the
attester reads it with the input reader of §2, as the gate's command line does, and
refuses what that reader refuses before a number is spent. Given a value that someone
else parsed, it signs that value, and the parser is theirs. A parser that keeps the
first of two duplicate member names, or every digit of a number, can then sign one
value while the gate decides another (`SEAMS.md`, rows 1 and 8).

### 16.3 A row names its arrival

A row whose input arrived carries `ext.arrival`: the `arrival_seq` of the arrival that
input came with. Because `ext` is inside the row hash (§3), the link is part of what the
chain and the signature cover: re-pointing a row at another arrival changes the row hash.

The link is by number, not by digest, for two reasons. The same bytes legitimately
arrive more than once — a rate limiter is meant to see them twice — and a caller's
retried request is two arrivals and two rows. A digest identifies the bytes; the number
identifies the event.

### 16.4 The `arrival` property

A conditional property beside those of §9, decided only when arrivals are present:

- **n/a** — `arrivals.jsonl` is not retained and no log was supplied. Not claimed: the
  retained inputs are the producer's word on what arrived.
- **unknown** — arrivals are retained and `retained` is not established in this copy;
  no attester registry was given; a row's digest is keyed (§3) and its input is not
  retained, so the plain digest cannot be recomputed; or the honoured attester key is a
  producer key, or the decider's key. A producer attesting its own inputs establishes
  nothing; a decider attesting them puts one party at both ends of the decision and
  establishes nothing about the input.
- **failed** — a row names no arrival; two rows name one arrival (one input, decided
  twice by the producer's own account); a row names an arrival the log does not have;
  a row's input digest, plain, is not the one its arrival was signed over (the retained
  input is not what arrived); a signature does not verify; or the attester's own copy of
  the log and the retained copy differ.
- **established** — every row names an arrival that an honoured attester key, held by
  neither the producer nor the decider, signed over that row's input.

The absence of an arrival is reported, not excused: a row with no arrival fails whatever
the producer writes about why, as a row the
decider did not sign fails `invocation` (§15). The other direction is an arrival with no
row — a producer that received an input, had it signed, and then declined to decide it —
which §16.6 fails and cannot tell from an omission. The format's answer is that a
refusal to decide an input the procedure received is a decision about it: the decider
declares its own outcomes (§3), and a row naming the arrival with a declining outcome
is a signed fact where a written reason would be an excuse.

Arrivals the log holds that no row names are reported in the detail and not judged by
this property; §16.6 judges them.

### 16.5 Withholding (§14)

A producer may withhold `arrivals.jsonl` as it may withhold attestations: the property
is then n/a and the record claims less. The attester's own copy, supplied to the
verifier, restores the check from outside the record — the receipt shape of §13 applied
to the input, with the same consequence: evidence the producer did not retain can still
refute what it did sign.

### 16.6 The `arrivals_accounted` property

The arrivals a record's rows name have a first number and a last. Every arrival the
attester logged between them that no row names is one the producer received and
recorded no decision for: the input-side analogue of a receipt for a decision the record
lacks (§13), with one difference. A receipt holder may have kept some receipts and not
others, so receipts can only refute. The attester's own log is complete for its endpoint
by construction, so from that copy the range can be **established**, which no mechanism
of §13 can do for the middle of a run.

- **n/a** — no arrivals; or arrivals from the record's retained copy only, every one in
  the range accounted for. Not claimed: that copy is the producer's selection.
- **unknown** — `arrival` is not established, so the range the rows name cannot be
  trusted; or the prior record could not be read.
- **failed** — the copy's own numbering has a hole inside the range: the attester
  numbers every arrival, so a missing number is a signed arrival removed from the copy,
  and the range cannot be accounted for from it, whichever copy it is. Or an arrival in
  the range has no row, from either copy. The detail gives the count and the first few
  numbers: a quantitative gap, as a missing receipt gives.
- **established** — from the attester's own copy, every arrival between the first and
  last named has a row.

Whatever the state, the property carries beside it a `range` field,
`{"first", "last", "accounted"}`: the bounds the state is about and how many
arrivals inside them have a row. The detail leads with the bounds for the same
reason: a consumer applying a threshold over states (§9) never reads the detail,
and "established" without its bounds reads as complete for the period, which this
property never claims.

Arrivals before the first named or after the last are not judged; they belong to
neighbouring records, and the tail is open exactly as it is for a stream (§12). Given the
prior record of a stream, the range begins after that record's last named arrival, so
the seam between two records is judged as well. A producer that drops a decision, its
row and its arrival from the retained copy is caught from that copy by the hole in its
numbering, and again by §16.4's rule that the two copies must be the same bytes. What the
range does not reach is the head: a record whose rows name arrivals 50 to 90 says nothing
about 1 to 49 unless the prior record is supplied.

### 16.7 What this does not establish

That the attester is independent beyond its key material (§16.0). That an arrival's
input is what the *caller* sent, rather than what the attester received — an attester
that alters inputs before signing them is a different producer, not a solved problem.
That every arrival was decided, beyond the range §16.6 judges and from the attester's own copy. That every input
the decider decided travelled through the attester: that is how the system is built, not
something a record shows, and a decision taken on an input that bypassed the attester is
reported only if its row is in the record (it names no arrival) — a decision left out of
the record entirely is the completeness limit of §13. That the log a verifier was given
came from the attester rather than through the producer: the hole rule and the
signatures leave a producer able to cut the log's tail and nothing else, but which party
handed the file over is custody, as key custody is (§15). Anything about timing: an
arrival carries no timestamp in this addendum, and ordering between arrivals is by number.

### 16.8 The gate decides nothing it was not handed an arrival for

Everything above reports. A deployment can configure an attester and still have
a path by which an input reaches the decider without passing it; §16.7 names
that as a limit the record cannot see. The party positioned to close it is the
gate — the code that calls the decider — because it holds a key the producer
does not and it sees every input the decider is asked about.

A policy object may carry `{"arrival": "required"}`. It is a setting of the
decision, under the policy digest like any other, so a decider configured not
to require arrivals is a different policy, and a re-deriving party sees which it
was. It is not a registry: the attester's keys are supplied to the gate at
runtime and to the verifier at verification, as every registry is, so that an
attester's key rotation does not change the policy digest of every record after
it. Under such a policy the gate (`dr.emit.Run.decide`) takes the arrival with
the input and refuses — writing nothing — an input that came with none, or
whose arrival is not an input-arrival signed over this input's plain digest by
a key the attester registry honours (`ArrivalRefused`). An input that bypassed
the attester therefore gets no decision from this gate. The refusal is the
gate's, before the decider: `Decider.decide(item)` is unchanged, so replay (§8)
is unchanged, and a refused input leaves no row and no arrival — the correct
silence of §16.4, since nothing was decided. The gate names the arrival in the
row itself and the decider's attestation carries it (§15).

What the verifier makes of the setting: a row under a policy requiring arrivals
that names none contradicts the record from its own contents — the gate under
that policy could not have written it — and `arrival` is **failed** on it with
no arrival file or log in hand. This is the one place the `arrival` property
reads the policy.

What this does not establish: that the gate was the only path to the decider.
A producer that forwards without the gate and writes the row itself writes a
row with no attestation (§15) and, under this policy, no arrival; one that
writes no row is the completeness limit of §13 and §16.6. The refusal is of the
same family as the decider's refusals at construction (§8): a policy that
fails validation, a permitted-operation set naming a non-deterministic
operation. It is not a departure from the rule that the format reports and the
operator decides whether to fail open or closed: under this setting the
operator has decided, in the policy, and the record shows the decision.
