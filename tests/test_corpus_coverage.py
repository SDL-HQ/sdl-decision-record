"""corpus_coverage over a synthetic corpus, so no fetch is needed.

Run with the suite.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

import tools.corpus_coverage as coverage  # noqa: E402

PARSERS = ["regex", pytest.param("ast", marks=pytest.mark.skipif(coverage._parser_in_use("auto") != "ast", reason="cedarpy not installed"))]

POLICY = '''@id("p0")
permit(principal, action == A::Action::"get", resource) when { resource.ok && context.scheme == "https" };
@id("p1")
forbid(principal, action, resource) unless { principal.role == "operator" };
'''


def write_run(d: Path, policy_text: str, inputs: list, reasons: list) -> Path:
    d.mkdir(parents=True)
    (d / "policy.json").write_text(json.dumps({"engine": "cedar", "policies": policy_text}))
    (d / "inputs.jsonl").write_text("".join(json.dumps({"seq": i, "input": x}) + "\n" for i, x in enumerate(inputs, 1)))
    (d / "decisions.jsonl").write_text("".join(json.dumps({"seq": i, "reason": r}) + "\n" for i, r in enumerate(reasons, 1)))
    return d


def write_corpus(root: Path, cases: list) -> Path:
    """cases: list of (policy_text, [request dicts with 'reason' lists])."""
    (root / "corpus-tests").mkdir(parents=True)
    for i, (pol, reqs) in enumerate(cases):
        (root / "corpus-tests" / f"c{i}.cedar").write_text(pol)
        ents = next((r.get("entities") for r in reqs if r.get("entities")), [])
        (root / "corpus-tests" / f"c{i}.entities.json").write_text(json.dumps(ents))
        (root / "corpus-tests" / f"c{i}.json").write_text(json.dumps({
            "policies": f"corpus-tests/c{i}.cedar", "entities": f"corpus-tests/c{i}.entities.json", "requests": reqs}))
    return root


REQ = {"principal": {"type": "A::User", "id": "u"}, "action": {"type": "A::Action", "id": "get"},
       "resource": {"type": "A::Doc", "id": "d"}, "context": {"scheme": "https"}, "entities": []}
# A request unlike REQ on every request-side dimension: other types, a hierarchy,
# a boolean context value, more entities.
OTHER = {"principal": {"type": "B::Svc", "id": "s"}, "action": {"type": "B::Act", "id": "put"},
         "resource": {"type": "B::Blob", "id": "b"}, "context": {"flag": True},
         "entities": [{"uid": {"type": "B::Svc", "id": "s"}, "attrs": {"n": 1}, "parents": [{"type": "B::Grp", "id": "g"}]}]
         + [{"uid": {"type": "B::Blob", "id": str(i)}, "attrs": {}, "parents": []} for i in range(5)]}


@pytest.mark.parametrize("parser", PARSERS)
def test_policy_dimensions_read_what_the_policy_uses(parser):
    d = coverage.policy_dimensions(POLICY, parser=parser)
    assert d["effect"] == {"permit", "forbid"}
    assert d["condition_kind"] == {"when", "unless"}
    assert d["policy_id_annotation"] == {"present"}
    assert d["policy_count"] == {"2+"}
    assert {"==", "&&"} <= d["operator"]
    assert any(s.startswith("action") and "==" in s for s in d["scope"])
    assert {"resource", "context", "principal"} <= d["attribute_access"]


@pytest.mark.parametrize("parser", PARSERS)
def test_comments_do_not_count(parser):
    d = coverage.policy_dimensions('// forbid( x || y ) unless\npermit(principal, action, resource);', parser=parser)
    assert d["effect"] == {"permit"}
    assert "||" not in d["operator"]
    assert d["condition_clause"] == {"absent"}


@pytest.mark.parametrize("parser", PARSERS)
def test_a_corpus_that_varies_everything_the_rows_use_establishes(tmp_path, parser):
    run = write_run(tmp_path / "run", POLICY, [REQ], ["p0"])
    corpus = write_corpus(tmp_path / "corpus", [
        (POLICY, [dict(REQ, reason=["p0"]), dict(REQ, reason=["p1"])]),
        ('permit(principal, action, resource);', [dict(REQ, context={}, reason=["policy0"])]),
        ('@id("z")\nforbid(principal in B::Grp::"g", action, resource) when { 1 < 2 };', [dict(OTHER, reason=["z"])]),
    ])
    state, detail, report = coverage.check(run, corpus, parser=parser)
    assert state == "established", (detail, report["comparison"])


@pytest.mark.parametrize("parser", PARSERS)
def test_a_corpus_with_one_policy_per_case_and_one_name_is_silent_on_both(tmp_path, parser):
    run = write_run(tmp_path / "run", POLICY, [REQ], ["p0", "p1"])
    one = 'permit(principal, action, resource) when { true };'
    corpus = write_corpus(tmp_path / "corpus", [
        (one, [dict(REQ, reason=["policy0"]), dict(REQ, context={}, reason=["policy0"])]),
        ('forbid(principal, action, resource) when { 1 < 2 };', [dict(REQ, reason=["policy0"])]),
    ])
    state, detail, report = coverage.check(run, corpus, parser=parser)
    assert state == "unknown"
    silent = {s["dimension"] for s in report["comparison"]["silent"]}
    assert {"policy_count", "policy_naming", "policy_id_annotation"} <= silent
    # The rows use `unless`; this corpus has only `when`, so that value was never exercised.
    assert "condition_kind" in silent
    assert "effect" not in silent  # permit and forbid both appear in the corpus
    assert "never exercises" in detail


def test_the_rows_side_never_reads_the_decisions_outcome(tmp_path):
    """Only the reason field is read from the rows; the outcome is not a dependency."""
    run = write_run(tmp_path / "run", POLICY, [REQ], ["p0"])
    dims, assumptions = coverage.record_dependencies(run)
    assert "outcome" not in dims
    assert any("policy dimensions were read" in a for a in assumptions)


@pytest.mark.skipif(coverage._parser_in_use("auto") != "ast", reason="cedarpy not installed")
def test_the_ast_parser_is_not_fooled_by_operator_shaped_text():
    # A string literal containing operators: the regex path sees them, the AST does not.
    pol = 'permit(principal, action, resource) when { context.note == "a || b && c" };'
    assert "||" in coverage.policy_dimensions(pol, parser="regex")["operator"]
    assert "||" not in coverage.policy_dimensions(pol, parser="ast")["operator"]
