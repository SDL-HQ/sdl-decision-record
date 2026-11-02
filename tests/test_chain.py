"""The chain: every row's contents are under its hash, and the order is under the chain."""

import pytest

from conftest import build_run, read_rows, verify, write_rows
from dr.rows import GENESIS, RowError, UnknownRowVersion, row_hash, verify_chain


def _rows(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    return d, read_rows(d)


def test_a_written_chain_re_derives(tmp_path, keys):
    d, rows = _rows(tmp_path, keys)
    assert verify_chain(rows) == rows[-1]["row_hash"]
    assert rows[0]["prev_hash"] == GENESIS


@pytest.mark.parametrize("field,value", [("outcome", "ALLOW"), ("reason", "x"), ("input_digest", "sha256:" + "0" * 64), ("ts", "2000-01-01T00:00:00Z"), ("label", "ZZZ")])
def test_changing_any_row_field_breaks_the_chain(tmp_path, keys, field, value):
    d, rows = _rows(tmp_path, keys)
    rows[2][field] = value
    with pytest.raises(RowError, match="row 3: row_hash does not re-derive"):
        verify_chain(rows)


def test_adding_a_key_to_a_row_breaks_the_chain(tmp_path, keys):
    d, rows = _rows(tmp_path, keys)
    rows[1]["ext"] = {"smuggled": True}
    with pytest.raises(RowError, match="row 2: row_hash does not re-derive"):
        verify_chain(rows)


def test_reordering_rows_breaks_the_chain(tmp_path, keys):
    d, rows = _rows(tmp_path, keys)
    rows[1], rows[2] = rows[2], rows[1]
    with pytest.raises(RowError):
        verify_chain(rows)


def test_removing_the_last_row_changes_the_terminal(tmp_path, keys):
    d, rows = _rows(tmp_path, keys)
    assert verify_chain(rows[:-1]) != verify_chain(rows)


def test_rehashing_a_tampered_row_moves_the_terminal_hash(tmp_path, keys):
    """A tamperer who recomputes every hash produces a valid chain with a different head, which the signed record refuses."""
    d, rows = _rows(tmp_path, keys)
    rows[2]["outcome"] = "ALLOW"
    prev = GENESIS
    for r in rows:
        r["prev_hash"] = prev
        r["row_hash"] = row_hash(prev, r)
        prev = r["row_hash"]
    write_rows(d, rows)
    s = {p["property"]: (p["state"], p["detail"]) for p in verify(d, keys).properties}
    assert s["chain"][0] == "failed" and "the record signs" in s["chain"][1]


def test_mixed_row_versions_are_a_failure_not_unknown(tmp_path, keys):
    d, rows = _rows(tmp_path, keys)
    rows[3]["v"] = 2
    with pytest.raises(RowError, match="mixed row versions"):
        verify_chain(rows)


def test_a_row_version_this_code_does_not_read_is_unknown(tmp_path, keys):
    d, rows = _rows(tmp_path, keys)
    for r in rows:
        r["v"] = 3
    with pytest.raises(UnknownRowVersion):
        verify_chain(rows)


def test_seq_must_be_1_to_n(tmp_path, keys):
    d, rows = _rows(tmp_path, keys)
    rows[0]["seq"] = 5
    with pytest.raises(RowError, match="seq is 5"):
        verify_chain(rows)


def test_an_undeclared_key_is_refused_by_shape_not_only_by_hash(tmp_path, keys):
    from dr.rows import row_defects

    d, rows = _rows(tmp_path, keys)
    rows[0]["note"] = "hello"
    assert any("undeclared keys ['note']" in x for x in row_defects(rows[0], 1))


def test_empty_ledger_is_refused(tmp_path):
    with pytest.raises(RowError, match="empty"):
        verify_chain([])


def test_a_spliced_row_with_a_self_consistent_hash_is_caught_by_linkage(tmp_path, keys):
    """Replace row 3 and recompute only its own hash from its own prev_hash. Every row hash
    still re-derives from the prev_hash it carries; only the linkage from row 4 back to the new
    row 3 is broken, and the terminal hash is unchanged. The linkage check is what catches it."""
    d, rows = _rows(tmp_path, keys)
    rows[2]["outcome"] = "ALLOW"
    rows[2]["row_hash"] = row_hash(rows[2]["prev_hash"], rows[2])
    assert rows[-1]["row_hash"] == verify_chain(read_rows(d))  # terminal unchanged
    with pytest.raises(RowError, match="row 4: prev_hash"):
        verify_chain(rows)
