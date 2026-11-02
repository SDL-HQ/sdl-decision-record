"""A property the report never judged does not drop out of the verdict.

`Report.verdict` is computed over the properties a report carries. Until this
landed, a property that was never added contributed nothing, so a report that
skipped a check could still verdict ESTABLISHED, and an empty report did. No
path reached it: the only way to skip an `add` was an uncaught exception, which
crashes instead. The verdict was therefore sound by accident, held up by every
code path remembering, and one broad `except` away from saying ESTABLISHED
about a record it had not finished checking.

That is the same rule the format states everywhere else. Unknown is not a pass,
and a check nobody ran is not a check that passed. It has to hold of the
verdict itself, not only of the properties the verdict reads.

Breaking these: drop a name from CORE_PROPERTIES, or make `verdict` read only
`self.properties` again.
"""

import json

import pytest

from conftest import build_run, verify
from dr.verify import CORE_PROPERTIES, ESTABLISHED, NOT_ESTABLISHED, Report


def test_an_empty_report_is_not_established():
    assert Report().verdict == NOT_ESTABLISHED
    assert list(Report().missing_core()) == list(CORE_PROPERTIES)


def test_a_report_missing_one_core_property_is_not_established():
    for omitted in CORE_PROPERTIES:
        r = Report()
        for name in CORE_PROPERTIES:
            if name != omitted:
                r.add(name, "established", "fine")
        assert r.verdict == NOT_ESTABLISHED, f"omitting {omitted} still verdicted ESTABLISHED"
        assert r.missing_core() == [omitted]


def test_a_conditional_property_may_be_absent_without_penalty():
    """replay, stream, receipts and witness are legitimately absent."""
    r = Report()
    for name in CORE_PROPERTIES:
        r.add(name, "established", "fine")
    assert r.verdict == ESTABLISHED
    assert r.missing_core() == []


def test_an_honest_run_still_verifies(tmp_path, keys):
    """The change must cost a valid record nothing."""
    report = verify(build_run(tmp_path / "run", keys), keys)
    assert report.missing_core() == []
    assert report.verdict == ESTABLISHED


def test_an_absent_property_is_visible_in_both_renderings(tmp_path):
    """A verdict a reader cannot account for is its own defect."""
    r = Report()
    for name in CORE_PROPERTIES:
        if name != "chain":
            r.add(name, "established", "fine")
    text = r.to_text(tmp_path)
    assert "chain" in text and "never decided it" in text
    assert "VERDICT: NOT ESTABLISHED" in text
    payload = json.loads(r.to_json(tmp_path))
    assert payload["verdict"] == "NOT ESTABLISHED"
    assert any(p["property"] == "chain" and p["state"] == "unknown" for p in payload["properties"])
