"""Three sentences of §9 did not say what the reference verifier does.

Found by the second-implementer measurement in `experiments/spec_sufficiency/`:
five of 47 corpus cases disagreed, and all five reduce to three readings of §9
that the text permitted and the reference does not take.

  signature   §9 said "the signature verifies with that key" without saying the
              check has a premise. On `signed-by-revoked-key` the bytes verify,
              so a text-only reader establishes `signature` over a key the
              registry refuses. The verdict does not move, because
              `signing_trust` fails either way, so it is a reporting defect —
              but a state that reads as establishing something over a check
              whose premise did not hold is the one shape this format exists to
              refuse.

  chain       §9 said what established means and not what absence is, and the
              absent-file rule of §8 is about retained files, which §5 forbids
              from naming the ledger. A text-only reader got unknown and
              NOT ESTABLISHED where the reference gets FAILED: the only
              disagreement that moved a published verdict. Failed is right, and
              the reason is §14 — it enumerates what a producer may withhold and
              the ledger is not in it, so a record naming an absent ledger is
              incomplete rather than unchecked. That premise is tested here too,
              because adding the ledger to §14 would quietly invalidate it.

  bail-out    "reports the rest as unknown", immediately after a list of eight
              and immediately before a sentence about the conditional
              properties, read as all fourteen. Three of the five disagreeing
              cases are this one ambiguity, which is 18 of the 20 disagreements
              the scorer reported, from one phrase.

These hold the sentences against what the reference does, in both directions:
reword §9 and they fail, change the verifier and they fail. The corpus's
`expected.json` is the reference's own recorded output, so the behaviour side is
derived rather than restated.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
CASES = ROOT / "conformance" / "verifier" / "cases"
SECTION_9 = SPEC.split("## 9. Verification", 1)[1].split("## 10.", 1)[0]
SECTION_14 = SPEC.split("## 14. Saying less", 1)[1].split("## 15.", 1)[0]


def _case(name):
    return json.loads((CASES / name / "expected.json").read_text(encoding="utf-8"))


def _row(prop):
    for line in SECTION_9.splitlines():
        if line.startswith(f"| `{prop}` |"):
            return line
    raise AssertionError(f"§9 has no {prop} row")


def test_signature_states_its_premise_and_the_verifier_honours_it():
    row = _row("signature")
    assert "signing_trust" in row, "§9's signature row does not name what the check depends on"
    assert "nknown when no honoured key" in row

    case = _case("signed-by-revoked-key")
    assert case["properties"]["signing_trust"] == "failed"
    assert case["properties"]["signature"] == "unknown", (
        "the reference establishes a signature over a key the registry refuses"
    )


def test_an_absent_ledger_is_failed_and_the_spec_now_says_so():
    row = _row("chain")
    assert "absent" in row and "ailed, not unknown" in row, (
        "§9's chain row does not say what an absent ledger is"
    )
    assert "§14" in row, "the chain row asserts a rule without naming what makes it true"

    assert _case("ledger-missing")["properties"]["chain"] == "failed"
    assert _case("ledger-missing")["verdict"] == "FAILED"


def test_the_premise_of_that_rule_is_still_true_of_section_14():
    """§14's withholding list is what makes an absent ledger incomplete, not unchecked."""
    options = [ln for ln in SECTION_14.splitlines() if ln.startswith("- **")]
    assert len(options) >= 4, "§14's enumerated options have moved; the chain rule's reason rests on them"
    assert not any("ledger" in o.lower() for o in options), (
        "§14 now appears to license withholding the ledger, which would make §9's "
        "chain row wrong: an absent ledger would be unknown, as an absent retained file is"
    )


def test_the_bail_out_sentence_names_which_properties_it_means():
    assert "the rest of\nthese eight" in SECTION_9 or "the rest of these eight" in " ".join(SECTION_9.split()), (
        "§9's bail-out sentence says 'the rest' without saying the rest of what"
    )
    assert "nothing about the conditional properties" in " ".join(SECTION_9.split())

    # the reference reports the eight and stays silent on the conditional ones
    case = _case("counts-wrong")
    core = {"document", "signing_trust", "signature", "chain",
            "decisions", "profile", "correctness", "retained"}
    assert set(case["properties"]) == core, (
        f"a bail-out case reports {sorted(set(case['properties']) ^ core)} "
        "outside the eight core properties"
    )
    assert case["properties"]["document"] == "failed"
    assert all(case["properties"][p] == "unknown" for p in core - {"document"})
