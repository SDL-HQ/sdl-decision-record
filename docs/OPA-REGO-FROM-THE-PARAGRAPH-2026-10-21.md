# Is the description of other grammars enabling? OPA/Rego built from it

21 October 2026. The Cedar decider (`emitters/cedar.py`) came with a one-paragraph description of how the same decider shape would apply to other policy grammars. This document records an attempt to build the OPA/Rego decider from that paragraph alone, logging every decision the paragraph did not make. The paragraph, as written before the build:

> The same decider shape applies to any policy language with a published specification and an evaluation engine, the policy object carrying the engine name and version, the policy text or bundle, every data document the evaluation consults, and the canonicalisation setting. For OPA/Rego: `{"engine": "opa", "bundle": {path: text, …}, "data": {…}, "query": "data.<package>.<rule>", "canonicalise": …}`, the reason being the set of rule paths whose evaluation produced the decision (obtained from the engine's explain or coverage output, or from a policy written to return the rule names it fired), and identity `opa-authorizer@opa-<version>`. […] In each case the conformance decider is formed from that language's own conformance suite (OPA's test corpus; the OASIS XACML conformance tests), and the drift measurement runs unchanged over engine versions. What the grammar supplies is stated semantics and a corpus; what the record supplies is the digest of everything the evaluation consulted and the replay.

## The answer

**The mechanism carries over; the paragraph does not describe it.** An OPA/Rego decider built to the paragraph decides the Cedar example's forty calls identically on every outcome under all three settings (30 → 31 → 39 of 40), its records verify and replay ESTABLISHED, OPA's own test corpus becomes a signed record, and the three-step drift procedure runs over three OPA releases and finds the same shape of result as Cedar's — plus one Cedar did not show. So the description's width survives contact with a second grammar in the sense that a skilled reader *can* build it.

But not from the paragraph alone. Nineteen decisions the paragraph does not make were needed to get there (the gap log below), and four of them are mechanism rather than convention: the policy object must carry the Rego language version, the allowed builtin set, and the builtin error mode, or the policy digest does not fix what was evaluated; and the conformance decider's agreement rule had to be re-derived from OPA's own test runner because the corpus expects values, not decisions. Two further findings bear on other parts of the specification: Rego has no engine-level "determining policy", so the reason is a policy-author convention; and the established-versions rule (SPEC §8) as it stood could name *no* OPA version, including the one that made the record, because the `opa` binary cannot reproduce OPA's own corpus in full — now addressed by a digested exclusion list in the result (transcript §5 shows 1.21.3 accepted with its six exclusions named).

The description should say what the policy object carries for a grammar whose evaluation consults more than text and data; the "agrees in full" rule of SPEC §8 now carries a digested exclusion list.

## The five questions, in order

**1. Does OPA publish a conformance corpus?** Yes. `open-policy-agent/opa`, `v1/test/cases/testdata/{v0,v1}/**/*.yaml`, Apache-2.0: 2,333 files, **4,347 cases** at tag `v1.21.3` (`fa9da828`), each a `{note, query, modules, data, input | input_term, want_result | want_error | want_error_code, flags}`. It is what OPA's own evaluator is tested against (`v1/topdown/exported_test.go`) and what third-party Rego implementations use. Pinned, not vendored (11 MB), every file digested into the policy (`tools/fetch_opa_testdata.py`, `examples/opa/PINNED_CORPUS.txt`).

**2. Can the policy object carry everything the evaluation consults?** Not as the paragraph wrote it. `{engine, bundle, data, query, canonicalise}` leaves out three things OPA reads that change the result: the **Rego language version** (OPA 1.x parses v1 by default and v0 only under `--v0-compatible`; the same text is valid in one and not the other — G2), the **builtin set and its environment** (G3), and the **builtin error mode** (`--strict-builtin-errors` turns an undefined result into an error — G8). The built object is `{engine, rego_version, bundle, data, query, builtins, strict_builtin_errors, canonicalise, entities}`. With those three added, nothing the evaluation reads is outside the digest — measured, not asserted, by the forty calls replaying under the record's own engine and by the sample record of 400 corpus cases replaying ESTABLISHED.

**3. Is Rego evaluation deterministic enough to be a decider?** Only if restricted, and OPA provides the means to restrict it at construction. `opa capabilities --current` lists the engine's 206 builtins; a capabilities file with a subset makes `opa check --strict --capabilities` fail on any builtin outside it (`rego_type_error: undefined function time.now_ns`). The decider carries the allowed list in the policy object (so it is under the digest), filters the engine's capabilities to it, refuses a list that names a builtin in its own non-deterministic set (`time.now_ns`, `rand.intn`, `uuid.rfc4122`, `http.send`, `net.lookup_ip_addr`, `opa.runtime`, `io.jwt.decode_verify`), and runs `opa check` — so a policy using the clock is refused the way the Cedar decider refuses a policy that fails schema validation (`examples/opa/refusals.py`, transcript §3: nine attempts, the expected six refused and three constructed). One limit stays: `io.jwt.decode_verify` is deterministic or not depending on whether the policy passes a `time` constraint, which the builtin list cannot see (G3b). And one finding that was not expected: **"the engine" is not one thing** (G17) — OPA's Go test harness and the `opa` binary differ on six cases of the corpus (a test-only builtin, `opa.runtime` mocked versus real, a base/virtual document conflict the CLI loader refuses and the library evaluates). The invocation path is part of the decider's identity, and the decider now runs the binary in a clean environment because `opa.runtime()` reports the process environment verbatim.

**4. Can a reason be extracted deterministically?** From the policy, yes; from the engine, no. Rego has no "determining policy"; a query returns a value. The built convention is a query evaluating to `{"allow", "permit", "forbid"}` with author-chosen ids, which replays byte-stably (five repeated decisions identical; test). The paragraph's two engine-side sources were measured and both fail the requirement: `opa eval --explain=full` is **not byte-stable across runs** — the `Locals` list order varies — and a normalised trace of rule-head Enter/Exit events, which *is* stable across runs and across 1.21.3, 1.0.0 and 0.70.0, names rule **heads** (`permit`, `decision`), not the ids of the rule bodies that fired; `--coverage` reports source line ranges. Neither is "rule paths whose evaluation produced the decision" (G14). Across grammars the reasons also differ by naming: Cedar reports `policy0` by position and ignores `@id`; the Rego convention returns `p0` (G19).

**5. The drift table.** The three-step procedure of `tools/cedar_engine_drift.py`, generalised, over OPA's corpus (`tools/opa_engine_drift.py` → `examples/opa/drt-results-by-engine.json`; the 400-row sample record `examples/opa/out/conformance-sample`, made under 1.21.3):

Every figure is the artefact's. The six cases excluded and named in it (below) are counted in none of the columns; the figures first written here, on 21 October, counted them, and were corrected to the artefact on 31 October.

| opa | corpus agree | result where corpus expects error | error where corpus expects result | disagreements with no engine error | of which a boolean the other way | verifier `replay` (record names 1.21.3) | forced recomputation: rows differ of 400 |
|---|---:|---:|---:|---:|---|---|---:|
| 1.21.3 (the corpus's tag) | 4,341 / 4,347 | 0 | 0 | 0 | — | established, ESTABLISHED | 0 |
| 1.0.0 | 3,767 / 4,347 | 8 | 451 | 91 | **24 true where false expected**, 4 the other way, 13 non-boolean | unknown, NOT ESTABLISHED | 50 (36 RESULT→ERROR, 9 RESULT→UNDEFINED, 2 UNDEFINED→ERROR, 3 reason only) |
| 0.70.0 | 3,741 / 4,347 | 12 | 450 | 110 | 24 / 4 / 13 | unknown, NOT ESTABLISHED | 52 |

Reading, both directions. The dominant difference is the Cedar shape: an older engine denying with an error on a feature it lacks (`as` keyword references, `and`/`or` operators, string interpolation, `array.flatten`, `io.jwt.verify_eddsa`, newer URI builtins) — 451 and 450 cases, deny-closed. **What Cedar did not show**: 24 cases (12 distinct, in both Rego versions) where an older OPA returns `true` where the current corpus expects `false`, silently — `glob.match` wildcard semantics (a single `?` matching more than one character; wildcards crossing delimiters) and `semver.is_valid` accepting leading zeros. `glob.match` on an allowlist is an ordinary authorisation pattern; under it an older engine **permits where the current one denies**, with no error for the decider to report. Cedar's analogue was seven requests of one test with the same decision and a different reason; Rego's is twenty-four with a different decision. The six under 1.21.3 are the harness differences of G17, recorded rather than special-cased.

## What was built

- `emitters/opa.py` — the decider; `emitters/opa_conformance.py` — the corpus as a record; `tools/opa_engine_drift.py` (run / merge / digest); `tools/fetch_opa_testdata.py`.
- `examples/opa/`: `policies.rego` (p0–p7 translated), `build_inputs.py` (the Cedar store re-keyed as `data.entities[type][id]`; the forty calls reused unchanged), `build_conformance_inputs.py`, `run.sh` → `TRANSCRIPT.md` (five sections), `compare_with_cedar.py`, `refusals.py`, `evidence_check.py`, `out/{toolcalls-caller,toolcalls-store,toolcalls-canonical,conformance-sample}`, `conformance/opa-*.json`, `drt-results-by-engine.json`, `PINNED_CORPUS.txt`.
- `tests/test_opa.py` (5, skipped without `OPA_BIN`); a SPEC §8 paragraph; README rows.
- Engines: `opa_linux_amd64_static` for 1.21.3, 1.0.0 and 0.70.0 from the project's GitHub releases, each checked against its published `.sha256`; not vendored.

## The gap log (the primary output)

| # | what the paragraph did not say | decision taken | kind |
|---|---|---|---|
| G1 | how the engine is invoked | the `opa` binary at `$OPA_BIN`, version from `opa version` | convention — and load-bearing, see G17 |
| G2 | Rego language version | `rego_version: 0 \| 1` in the policy object; `--v0-compatible` / `--v1-compatible` | **mechanism** |
| G3 | builtin restriction | `builtins: [names]`; capabilities filtered; non-deterministic set refused; `opa check --strict --capabilities` | **mechanism** |
| G3b | builtins deterministic by argument (`io.jwt.decode_verify` with `time`) | refused as a class | limit |
| G4 | how a query value becomes ALLOW/DENY | `{allow, permit, forbid}` convention; undefined → `no-policy-permits`; other shape → `request-invalid` | convention the author must follow |
| G5 | which reason source | policy-returned ids; explain and coverage measured and rejected | convention |
| G6 | entity source caller/store | kept in the object; under `caller` the input's entities become `data.entities` for that decision | **mechanism** (needed for the Cedar example's measurement) |
| G7 | what "refuses an invalid policy" means | `opa check --strict` with the capabilities file | convention |
| G8 | builtin error mode | `strict_builtin_errors` in the object | **mechanism** |
| G9 | data representation | one object; sufficient | — |
| G10 | value-valued corpus expectations | `RESULT \| ERROR \| UNDEFINED`; reason = digest of the normalised result set; label = class | **mechanism** |
| G11 | corpus case flags (`sort_bindings`, `ignore_generated_vars`, `strict_error`, `input_term`, `env`) | per OPA's own runner | mechanism |
| G12 | `input_term` (raw Rego term) | `… with input as <term>` in the query | convention; changes the retained query text |
| G13 | the canonicalisation key map | reused from the Cedar decider's function; **not under the policy digest in either decider** | gap in the specification |
| G14 | "rule paths" has no engine-level meaning in Rego | a convention | limit |
| G15 | request validation (`request-invalid`) | not an engine feature in OPA; row 36 is `no-policy-permits` here and `request-invalid` under Cedar | limit |
| G16 | error text format | the CLI separates location/code/message; OPA's runner matches `<file>:<row>: <code>: <message>`; rebuilt | mechanism |
| G17 | "the engine" is two things (harness vs CLI) | recorded; clean environment for the subprocess | finding |
| G18 | `established_versions` "agrees in full" | refused every OPA version including 1.21.3 on its own record (4,341 of 4,347); the result now names its exclusions inside the digest and the verifier counts agreement over the rest; transcript §5 | **limit of the mechanism as specified, then changed** |
| G19 | reason naming across grammars (`policy0` vs `p0`) | none | gap in the specification |

## What this means for the specification

- The description's OPA policy object should read `{engine, rego_version, bundle, data, query, builtins, strict_builtin_errors, canonicalise, entities}`, with the construction-time refusal of unlisted and non-deterministic builtins (SPEC §8 now says so in one paragraph).
- SPEC §8, established versions: "agrees in full" did not survive a corpus the invocation path cannot reproduce exactly. The G18 run was the measurement; the change is a digested exclusion list, and transcript §5 shows it accepting 1.21.3 and refusing the other two.
- The conformance decider's agreement rule is corpus-specific; the Rego version (value sets, error substrings, error codes, five flags) is the second instance and shows which parts of the Cedar one were Cedar-specific.
- The canonicalisation key map should be in the policy object (G13) — true of the Cedar decider too.
- "The reason being the set of rule paths" is right for Cedar and a convention for Rego.

## Figures and their commands

All in `examples/opa/TRANSCRIPT.md` (`bash examples/opa/run.sh`) and `examples/opa/drt-results-by-engine.json` (`tools/opa_engine_drift.py run` ×3, `merge`); the explain/coverage measurements are in the report only and reproduce with `opa eval --explain=full` / `--coverage` on `examples/opa/policies.rego` with the transcript's first call. Third-party material: OPA (Apache-2.0, LICENSE read from the clone), its test corpus at `fa9da828`, the release binaries by published checksum. Nothing measured here could have been built from the corpus: the forty calls and the eight policies are the Cedar example's; the corpus is OPA's own tests of OPA.

## Gap log, in the order the gaps were met

Each entry: what the paragraph did not specify, the decision taken to proceed, and whether the decision is a convention (could go either way), a mechanism (the paragraph is missing a part), or a limit (the mechanism does not carry over).

G1. How the engine is invoked. Paragraph: "an evaluation engine", identity `opa-authorizer@opa-<version>`. Not said: binary, Go SDK, or wasm; where the version string comes from. Decision: the `opa` CLI binary found at `$OPA_BIN`, version from `opa version` (first line), identity `opa-authorizer@opa-<Version>`. Convention.

G2. Rego language version. OPA 1.x parses Rego v1 by default and v0 only with `--v0-compatible`; the same policy text is valid in one and not the other. Not in the paragraph. Decision: policy object carries `"rego_version": 0 | 1`; the decider passes the matching flag. Mechanism — without it the policy digest does not fix what the policy means.

G3. Builtin restriction. Not in the paragraph (question 3 above). Decision: policy object carries `"builtins": [sorted names]`; at construction the decider takes `opa capabilities --current`, keeps only the named builtins, writes a capabilities file, and runs `opa check --strict --capabilities`; a policy referencing an unlisted builtin fails check and construction refuses. The decider also refuses at construction when the list names a builtin in its own non-deterministic set (`time.now_ns`, `rand.intn`, `uuid.rfc4122`, `http.send`, `net.lookup_ip_addr`, `opa.runtime`, `net.cidr_expand`? no — deterministic; `io.jwt.decode_verify` — see G3b). Mechanism.

G3b. `io.jwt.decode_verify` and `time.*` family: `io.jwt.decode_verify` checks `exp`/`nbf` against the wall clock unless `time` is supplied in constraints — a builtin that is deterministic or not depending on its arguments. Decision: treat as non-deterministic (refuse) unless the policy is written with the `time` constraint; the decider cannot see that from the builtin list alone. Limit: builtin-level restriction is coarser than determinism.

G4. Mapping the query result to an outcome. Paragraph: `"query": "data.<package>.<rule>"`. Not said: what the rule returns and how ALLOW/DENY and the reason are read from it. Decision: the query evaluates to an object `{"allow": bool, "permit": set-of-ids, "forbid": set-of-ids}`; ALLOW iff `allow == true`; undefined result → DENY `no-policy-permits`; a result that is not such an object → DENY `request-invalid`. Convention, but a convention the policy author has to follow, which the Cedar decider did not need (Cedar's engine returns decision and determining-policy ids itself).

G5. Reasons. Paragraph offers three sources (explain, coverage, policy-returned names) without choosing. Decision: policy-returned ids (G4). Explain and coverage measured separately for determinism and for whether they yield "rule paths". See report.

G6. Entity source (`caller` | `store`). The Cedar object carries it; the OPA object in the paragraph does not. Decision: `"entities": "caller" | "store"` kept in the OPA policy object; under `caller` the decider overlays `input.entities` (keyed by id) onto `data.entities` before evaluation and strips `entities` from the input; under `store` the input's entities are dropped. Mechanism: without this the "whose entities" measurement of the Cedar example cannot be repeated.

G7. What "refuses an invalid policy at construction" means for Rego. Cedar validates against a schema. Decision: `opa check --strict` with the capabilities file; schema annotations optional. Convention.

G8. Builtin error mode. OPA evaluates with builtin errors either as undefined (default) or as errors (`--strict-builtin-errors`); the result of the same policy differs. Not in the paragraph. Decision: policy object carries `"strict_builtin_errors": bool`. Mechanism.

G9. Data representation. Paragraph: `"data": {…}`. Sufficient: one JSON object is the whole base document; OPA merges files by path but one object expresses any such merge.

G10. The conformance corpus's expectations are values and errors, not decisions. the conformance-corpus description's row has outcome/reason/label; OPA's cases expect a result set (a set of variable bindings), an error substring, or an error code. Decision: outcome vocabulary `RESULT | ERROR | UNDEFINED`; `reason` = `sha256` digest of the canonical normalised result set (RESULT), the error code or message head (ERROR); `label` = the corpus's expected class; `ext` carries the expected and actual values. Replay compares (outcome, reason), which is value-exact; correctness compares class only. Mechanism: the agreement rule of the conformance-corpus description (decision, reason set, error presence) does not carry over as written and had to be re-derived from OPA's own runner (`v1/topdown/exported_test.go`: binding sets compared as sets; `sort_bindings`; `__localq*` vars ignored; error text by substring; error code exact).

G11. Case flags the corpus needs the runner to honour: `sort_bindings`, `ignore_generated_vars`, `strict_error`, `input_term`, `experimental_keywords`, `env`. None in the conformance-corpus description. Decision: implemented per OPA's runner; `env` (0 cases at the pin) unsupported.

G12. `input_term` — a raw Rego term as input, which the CLI cannot take as JSON. Decision: rewritten into the query as `… with input as <term>`. Convention, but one that changes the query text the record retains.

G13. The canonicalisation key map. the canonicalisation section of the description says "a declared key map" and names it for the Cedar example; it lives in the Cedar decider as a constant, not in the policy object. Decision: the OPA decider reuses the the canonicalisation section of the description `url-v1` function and the same constant map. Gap in the specification: the key map is not under the policy digest in either decider.

G14. Rego has no "determining policy" concept. Cedar reports which policies determined the decision; Rego reports a value. "Rule paths whose evaluation produced the decision" has no engine-level meaning in OPA; it is whatever the policy returns (G4/G5) or an explain trace (measured).

G15. Request validation. Cedar's engine refuses a request whose context does not match the schema (`request-invalid`); Rego is untyped and compares across types by term ordering, so an amount sent as the string `"250"` is simply not `<= 1000` (row 36: Cedar `DENY request-invalid`, OPA `DENY no-policy-permits`; same outcome, different reason class). OPA's schema support (`--schema`) type-checks the policy statically and does not validate input at evaluation; runtime validation is a policy-level matter (`json.match_schema`) or a decider-level pre-check. Limit: the `request-invalid` reason class does not carry over from the grammar; it has to be rebuilt in the decider or the policy.

G16. Error text format. OPA's own runner matches `want_error` against the Go error's string form, `<file>:<row>: <code>: <message>`; the CLI's JSON separates location, code and message. Twenty-two cases disagreed until the decider rebuilt the Go form. Mechanism: the conformance decider has to know the harness's rendering of an error, which the conformance-corpus description did not anticipate because Cedar's corpus expresses errors as a count.

G17. "The engine" is not one thing. Under the corpus's own tag (1.21.3) six cases do not reproduce through the CLI because OPA's Go test harness and the `opa` binary differ: a test-only builtin (`test.sleep`, 2 cases), `opa.runtime` mocked to `{}` in the harness and returning the build commit through the CLI (2), and a base/virtual document conflict that the CLI loader refuses at load and the library evaluates (2). The paragraph says "evaluation engine"; the measurement says the invocation path is part of the identity. G1's choice (the binary) is therefore load-bearing and belongs in the policy object or the decider version string, not in a comment.

G18. The `established_versions` rule cannot name any OPA version, including the record's own. SPEC §8 accepts a named version only when the supplied run "agrees in full" (agreement count equals request count). Under its own tag the CLI reaches 4,341 of 4,347 for the G17 reasons, so `--conformance-evidence` would refuse `opa-1.21.3` on a record made under `opa-1.21.3`. Limit of the mechanism as specified: "agrees in full" presumes a corpus the engine's invocation path reproduces exactly; a harness-exclusion list carried (and digested) in the result object, or a stated tolerance, would be a change to the mechanism, not a parameter of it.

G19. Reason naming across grammars. Cedar reports determining policies by position (`policy0`), ignoring `@id` annotations; the Rego convention returns the author's ids (`p0`). Over the forty calls every outcome agrees and the reasons differ only by this naming on 12–16 rows per setting (and row 36, G15). A reader comparing records across grammars needs a reason-naming convention the specification does not have.
