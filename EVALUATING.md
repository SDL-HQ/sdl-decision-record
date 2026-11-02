# Evaluating this

No sign-up, no form, no key to request. Clone it and start. This page says
what you may do, what to run, and what the evidence does not establish.

## What you may do, in plain terms

The licence is PolyForm Free Trial 1.0.0 (`LICENSE`). What it means here:

- **Read, run and modify it to evaluate whether it suits something you have in
  mind.** Expressly on behalf of your employer, so an engineering team
  assessing it for their own organisation is the intended case.
- **For under 32 consecutive days.** After that there is no permitted purpose,
  so no licence. If you need longer, ask; see the bottom of this page.
- **You may not redistribute it.** Not a copy, not inside something else.
- **You may not deploy it in production.** Evaluation is the only permitted
  purpose in the licence.

If what you want to do is not evaluation, the answer is not in this file. Ask.

That is the software. The documents and the evidence are under different
terms, and you may keep them after your trial ends:

- **The prose** (every Markdown file, the specification included) is under CC
  BY-ND 4.0: keep it, copy it, share it, cite it, unmodified and attributed.
  Implement the format from it if you can; that is the point of it.
- **The evidence** (the records, ledgers, captured output and conformance
  cases) is under CC BY 4.0: keep it, change it, and publish what you find,
  attributed.

Neither licence grants any patent right. `NOTICE` has the detail, says who
holds the copyright, and names the parts that are not ours: everything under
`vendor/` is somebody else's, under their own terms.

## The fastest path to a verdict you did not get from us

The verifier needs one dependency; the Cedar replay below needs a second.

```
python3 -m pip install cryptography
```

Verify a record as issued:

```
python3 -m dr.verify examples/acceptance/out/record \
  --registry examples/keys/registry.json \
  --replay emitters.toolgate \
  --decider-registry examples/keys/deciders.json
```

Then break one and watch it refuse. Change any value in a row of
`examples/acceptance/out/record/decisions.jsonl` (an outcome, a reason, a
digest, a sequence number) and run the same command. The chain will not
re-derive and every property downstream reports unknown rather than passing,
which is the behaviour worth checking: a verifier that cannot read the rows
must not report anything about them.

Whitespace between a row's tokens is not a value. Rows are hashed in their
canonical form (`SPEC.md` §2), so reformatting one, a space for a tab, changes
nothing the verifier checks and the record still verifies.

## The record that passes every check and is a fiction

The fabricated record (acceptance case 12) was decided under Cedar, and
replaying it needs the Cedar engine at the release the record names:

```
python3 -m pip install cedarpy==4.12.2
python3 -m dr.verify experiments/rederivability/out/f5-input-fabricated \
  --registry experiments/rederivability/out/registry.json \
  --decider-registry experiments/rederivability/out/deciders.json \
  --replay emitters.cedar --assurance
```

Every property established, verdict ESTABLISHED, assurance A3. Without
cedarpy, replay reports unknown, so the verdict is NOT ESTABLISHED and the
level drops from A3 to A1: `replay` is one of the properties A2 and every level
above it require, and a property nobody could check is not passed. The levels,
A0 to A4, and what each requires are defined in `SPEC.md` §9.1.

The other experiments name what they need at the top of their own scripts and
in `README.md`.

## The refusals, already captured

`examples/acceptance/ACCEPTANCE.md` holds fourteen ways to refuse a record,
each with the command as run and the verifier's actual output. Nothing in that
file is a hand-written expected result; it is produced by

```
bash examples/acceptance/run.sh
```

and the full output of every step is under `examples/acceptance/out/`. Run it
and diff against what is committed. If they differ, that is a defect and we
would like to know.

Cases 12 to 14 are the ones to read first if you are short of time. They are
the limit of what a record can establish about itself, and case 12 is a record
that passes every check and is a fiction.

## What this does not establish

Stated here rather than left for you to find.

- **A record cannot establish its own completeness.** Delete rows, renumber,
  recompute the chain, re-sign: every property holds, because every property
  is a statement about the rows that are present.
  `tools/truncate.py` does exactly that and the verifier
  reports established. What bounds it is a party other than the producer.
- **Replay re-derives the decision, never that the retained input is the one
  the system saw.** A producer can write an input the agent never supplied,
  decide it honestly with the real decider, and produce a record where the
  chain, the counts, the attestation and the re-derivation all hold. That is
  acceptance case 12, and it is a built artefact in this repository, not a
  hypothetical.
- **Unknown is not a pass.** The verifier reports four states and a property
  nobody could check is reported as unchecked. A verdict of NOT ESTABLISHED
  means something could not be established, which is not the same as nothing
  being wrong.
- **The measurements are a demonstration, not a deployment.** Forty
  hand-written calls, one policy, one tenant.

`SPEC.md` §13 and §14 are the full version, including what a record leaks
about the policy it ran under.

## What we would like from you

Any one of these is worth more to us than a download.

- Tell us a property you think the verifier reports wrongly, with the command.
- Tell us an alteration the acceptance set does not catch.
- Tell us the claim you do not believe, and what would change your mind.
- Tell us it solves nothing you have, and why. That is a result.

## Asking for something different

Email `info@structuraldesignlabs.com`.

- **Longer than 32 days.** Say roughly how long and we will say yes or no. No
  cost, no form. Procurement and a test environment can take longer than the
  trial allows and we would rather extend it than have you stop.
- **Deploying it, or shipping it inside something.** Not permitted under this
  licence. Ask and we will talk about terms.
- **A defect.** Send the command and what it printed.
