"""The OPA drift table in docs/ states the figures of the artefact it names.

The table in `docs/OPA-REGO-FROM-THE-PARAGRAPH-2026-10-21.md` names
`examples/opa/drt-results-by-engine.json` as its source. A table typed from an
artefact keeps its old counts when the artefact moves, as when six harness
cases were excluded and named. This reads every number in the table back from
the artefact.

Breaking this: change a figure in either.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "OPA-REGO-FROM-THE-PARAGRAPH-2026-10-21.md"
ART = ROOT / "examples" / "opa" / "drt-results-by-engine.json"


def _n(s: str) -> int:
    return int(s.replace(",", "").strip("* "))


def _rows():
    out = {}
    for line in DOC.read_text(encoding="utf-8").splitlines():
        m = re.match(r"\| (\d+\.\d+\.\d+)[^|]*\|(.*)\|\s*$", line)
        if m:
            out[m.group(1)] = [c.strip() for c in m.group(2).split("|")]
    return out


def test_every_figure_in_the_table_is_the_artefacts():
    engines = {e["engine"].removeprefix("opa-"): e for e in json.loads(ART.read_text(encoding="utf-8"))["engines"]}
    rows = _rows()
    assert set(rows) == set(engines) == {"1.21.3", "1.0.0", "0.70.0"}
    for v, cells in rows.items():
        e = engines[v]
        agree, total = (_n(x) for x in cells[0].split("/"))
        assert (agree, total) == (e["corpus_agree"], e["corpus_requests"]), v
        assert _n(cells[1]) == e["result_where_corpus_expects_error"], v
        assert _n(cells[2]) == e["error_where_corpus_expects_result"], v
        assert _n(cells[3]) == e["disagreements_without_engine_error"], v
        sb = e["silent_boolean_direction"]
        if sb:
            nums = [int(x) for x in re.findall(r"\d+", cells[4])]
            assert nums == [sb["true-where-corpus-expects-false"], sb["false-where-corpus-expects-true"], sb["non-boolean-value"]], v
        else:
            assert cells[4] == "—", v
        assert int(re.match(r"\d+", cells[6]).group()) == e["forced_rows_differ"], v


def test_the_prose_counts_beside_the_table_are_the_artefacts():
    text = " ".join(DOC.read_text(encoding="utf-8").split())
    engines = {e["engine"]: e for e in json.loads(ART.read_text(encoding="utf-8"))["engines"]}
    a, b = engines["opa-1.0.0"]["error_where_corpus_expects_result"], engines["opa-0.70.0"]["error_where_corpus_expects_result"]
    assert f"{a} and {b} cases, deny-closed" in text
