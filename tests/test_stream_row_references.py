"""Rows naming rows of the prior record by hash (SPEC §12)."""

import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dr import verify as V  # noqa: E402
from dr.rows import GENESIS, row_hash  # noqa: E402
from dr.signing import sign_record  # noqa: E402
from dr.canonical import digest_file  # noqa: E402

REG = ROOT / "examples" / "keys" / "registry.json"
KEY = (ROOT / "examples" / "keys" / "example-signing-key.pem").read_bytes()
H1 = ROOT / "examples" / "out" / "stream-hour1"
H2 = ROOT / "examples" / "out" / "stream-hour2"


def _rows(d):
    return [json.loads(l) for l in (d / "decisions.jsonl").read_text().splitlines() if l.strip()]


def _with_refs(tmp, refs):
    """hour 2 copied with ext.prior_row set from `refs` (seq -> hash), rechained and re-signed."""
    d = tmp / "hour2"
    shutil.copytree(H2, d)
    rows = _rows(d)
    prev = GENESIS
    for r in rows:
        if r["seq"] in refs:
            r.setdefault("ext", {})["prior_row"] = refs[r["seq"]]
        r["prev_hash"] = prev
        r["row_hash"] = row_hash(prev, r)
        prev = r["row_hash"]
    (d / "decisions.jsonl").write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))
    rec = json.loads((d / "record.json").read_text())
    for k in ("payload_hash", "signature"):
        rec.pop(k)
    rec["ledger"]["terminal_hash"] = prev
    rec["retained"] = {n: digest_file(d / n) for n in rec["retained"]}
    (d / "record.json").write_text(json.dumps(sign_record(rec, KEY), indent=2, sort_keys=True) + "\n")
    return d


def _stream(d, prior):
    rep = V.verify_directory(d, REG, prior_record=prior)
    return rep.state("stream"), next(p["detail"] for p in rep.properties if p["property"] == "stream")


def test_references_to_rows_the_prior_signs_are_established(tmp_path):
    h1 = _rows(H1)
    d = _with_refs(tmp_path, {1: h1[0]["row_hash"], 5: h1[4]["row_hash"], 20: h1[19]["row_hash"]})
    state, detail = _stream(d, H1 / "record.json")
    assert state == "established" and "3 row(s) name rows of the prior" in detail


def test_a_reference_the_prior_lacks_fails(tmp_path):
    d = _with_refs(tmp_path, {3: "sha256:" + "a" * 64})
    state, detail = _stream(d, H1 / "record.json")
    assert state == "failed" and "rows [3] name rows the prior's ledger does not have" in detail


def test_prior_without_its_ledger_is_unknown(tmp_path):
    h1 = _rows(H1)
    d = _with_refs(tmp_path, {1: h1[0]["row_hash"]})
    p = tmp_path / "prior-only"
    p.mkdir()
    shutil.copy(H1 / "record.json", p / "record.json")
    state, detail = _stream(d, p / "record.json")
    assert state == "unknown" and "not beside its record" in detail


def test_a_prior_ledger_edited_after_signing_cannot_vouch(tmp_path):
    h1 = _rows(H1)
    p = tmp_path / "prior-edited"
    shutil.copytree(H1, p)
    rows = _rows(p)
    rows[2]["outcome"] = "DENY" if rows[2]["outcome"] == "ALLOW" else "ALLOW"
    prev = GENESIS
    for r in rows:
        r["prev_hash"] = prev
        r["row_hash"] = row_hash(prev, r)
        prev = r["row_hash"]
    (p / "decisions.jsonl").write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))
    d = _with_refs(tmp_path, {1: rows[0]["row_hash"]})
    state, detail = _stream(d, p / "record.json")
    assert state == "failed" and "terminal hash the prior does not sign" in detail


def test_no_references_checked_exactly_as_before():
    state, detail = _stream(H2, H1 / "record.json")
    assert state == "established" and "name rows" not in detail
