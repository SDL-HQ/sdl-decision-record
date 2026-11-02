"""The ledger row: what one decision looks like on disk, and the chain over rows.

A row records one decision by a deterministic procedure. It carries exactly the
keys below and no others. An exact key set is used instead of a list of
forbidden keys because a forbidden list cannot be complete.

Row version 1:

    v              1
    seq            1..n, in file order, no gaps
    ts             UTC time, YYYY-MM-DDTHH:MM:SSZ
    input_digest   sha256 digest of the canonical input the decision was made on
    decider        "<id>@<version>", the decision procedure
    policy_digest  sha256 digest of the policy the procedure ran under
    outcome        the decision, one of the decider's declared outcomes
    reason         why, in the decider's own vocabulary, or null
    label          optional: the outcome a labelled input was expected to get
    ext            optional: an object the decider wants on the record; opaque
    prev_hash      the previous row's row_hash, or "GENESIS"
    row_hash       sha256:(prev_hash + canonical(row without the two chain fields))

Row version 2 is identical except that input_digest is a keyed digest,
"hmac-sha256:" + HMAC-SHA256(salt, canonical(input)), where the salt is the
first line of the retained inputs file ({"salt": hex}). A reader without the
salt cannot test guessed inputs against the digests (experiments/leakage); a
reader with it checks them exactly as for version 1. A ledger has one row
version throughout.

Every field except the two chain fields is covered by row_hash, because the
row hash is computed over the canonical form of the whole row minus those two.
Adding a key to a row therefore changes its hash; a maintained include-list is
not needed and is not used.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .canonical import DIGEST_PREFIX, canonical_bytes, is_digest
from .canonical import NotJSON
from .canonical import read_jsonl, loads as strict_loads

ROW_VERSION = 1
# Row version 2 differs from 1 in one field: input_digest is a keyed digest,
# "hmac-sha256:" + HMAC-SHA256(salt, canonical(input)), with the salt kept in
# the first line of inputs.jsonl. Without the salt a digest cannot be tested
# against guessed inputs, which is what a plain sha256 of a low-entropy input
# allows (experiments/leakage). With the salt, the verifier checks it exactly
# as before. Everything else about the row is identical.
ROW_VERSION_KEYED = 2
SUPPORTED_ROW_VERSIONS = (1, 2)
KEYED_DIGEST_PREFIX = "hmac-sha256:"
GENESIS = "GENESIS"
CHAIN_FIELDS = ("prev_hash", "row_hash")
REQUIRED_ROW_KEYS = frozenset(
    {"v", "seq", "ts", "input_digest", "decider", "policy_digest", "outcome", "reason"} | set(CHAIN_FIELDS)
)
OPTIONAL_ROW_KEYS = frozenset({"label", "ext"})
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DECIDER_RE = re.compile(r"^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+$")


def keyed_input_digest(salt: bytes, input_obj: Any) -> str:
    """The v2 input digest: HMAC-SHA256 over the canonical input, keyed with the run's salt."""
    return KEYED_DIGEST_PREFIX + hmac.new(salt, canonical_bytes(input_obj), hashlib.sha256).hexdigest()


def is_keyed_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(KEYED_DIGEST_PREFIX)
        and len(value) == len(KEYED_DIGEST_PREFIX) + 64
        and all(c in "0123456789abcdef" for c in value[len(KEYED_DIGEST_PREFIX) :])
    )


class RowError(ValueError):
    """A row or chain that is not what the format says it is. A failure."""


class UnknownRowVersion(ValueError):
    """A row declaring a version this code does not read. Not a failure: unknown."""


def row_payload(row: Dict[str, Any]) -> bytes:
    body = {k: v for k, v in row.items() if k not in CHAIN_FIELDS}
    return canonical_bytes(body)


def row_hash(prev_hash: str, row: Dict[str, Any]) -> str:
    return DIGEST_PREFIX + hashlib.sha256(prev_hash.encode("utf-8") + row_payload(row)).hexdigest()


def declared_version(row: Dict[str, Any]) -> int:
    v = row.get("v")
    if isinstance(v, bool) or not isinstance(v, int):
        raise RowError(f"row v must be an integer, got {v!r}")
    if v not in SUPPORTED_ROW_VERSIONS:
        raise UnknownRowVersion(f"row declares v={v}, which this verifier does not read; it reads {list(SUPPORTED_ROW_VERSIONS)}")
    return v


def row_defects(row: Dict[str, Any], index: int) -> List[str]:
    """Every way one row fails the v1 shape. The chain is checked separately."""
    d: List[str] = []
    keys = set(row)
    extra = sorted(keys - REQUIRED_ROW_KEYS - OPTIONAL_ROW_KEYS)
    if extra:
        d.append(f"row {index}: undeclared keys {extra}")
    missing = sorted(REQUIRED_ROW_KEYS - keys)
    if missing:
        d.append(f"row {index}: missing keys {missing}")
        return d
    seq = row["seq"]
    if isinstance(seq, bool) or not isinstance(seq, int) or seq != index:
        d.append(f"row {index}: seq is {seq!r}, expected {index}")
    if not isinstance(row["ts"], str) or not TS_RE.match(row["ts"]):
        d.append(f"row {index}: ts {row['ts']!r} is not YYYY-MM-DDTHH:MM:SSZ")
    if row.get("v") == ROW_VERSION_KEYED:
        if not is_keyed_digest(row["input_digest"]):
            d.append(f"row {index}: a v2 row's input_digest must be a keyed digest ({KEYED_DIGEST_PREFIX}...)")
    elif not is_digest(row["input_digest"]):
        d.append(f"row {index}: input_digest is not a sha256 digest")
    if not is_digest(row["policy_digest"]):
        d.append(f"row {index}: policy_digest is not a sha256 digest")
    if not isinstance(row["decider"], str) or not DECIDER_RE.match(row["decider"]):
        d.append(f"row {index}: decider {row['decider']!r} is not <id>@<version>")
    if not isinstance(row["outcome"], str) or not row["outcome"]:
        d.append(f"row {index}: outcome must be a non-empty string")
    if row["reason"] is not None and (not isinstance(row["reason"], str) or not row["reason"]):
        d.append(f"row {index}: reason must be a non-empty string or null")
    if "label" in row and (not isinstance(row["label"], str) or not row["label"]):
        d.append(f"row {index}: label must be a non-empty string when present")
    if "ext" in row and not isinstance(row["ext"], dict):
        d.append(f"row {index}: ext must be an object when present")
    return d


def load_rows(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    # LF only: iterating a text file also ends a line at a lone CR (SEAMS.md).
    for n, line in read_jsonl(Path(path)):
        try:
            obj = strict_loads(line)
        except NotJSON as exc:  # parsed, but carries what the canonical form cannot render; the reason says which
            raise RowError(f"line {n}: {exc}") from exc
        except ValueError as exc:  # JSONDecodeError
            raise RowError(f"line {n}: not JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise RowError(f"line {n}: not an object")
        rows.append(obj)
    if not rows:
        raise RowError("the ledger is empty")
    return rows


def verify_chain(rows: Iterable[Dict[str, Any]]) -> str:
    """Re-derive the chain from GENESIS. Returns the terminal row_hash.

    Raises RowError on any defect, UnknownRowVersion if a row declares a
    version this code does not read. Mixed versions are a defect: one run
    writes one version.
    """
    rows = list(rows)
    if not rows:
        raise RowError("the ledger is empty")
    # Mixed versions are judged before unknown ones: a ledger that mixes
    # versions is a defect whatever the versions are, because one run writes
    # one version, and reporting it as "a version I do not read" would hide
    # that.
    raw_versions = []
    for index, row in enumerate(rows, start=1):
        v = row.get("v")
        if isinstance(v, bool) or not isinstance(v, int):
            raise RowError(f"row {index}: v must be an integer, got {v!r}")
        raw_versions.append(v)
    if len(set(raw_versions)) > 1:
        raise RowError(f"mixed row versions {sorted(set(raw_versions))} in one ledger")
    prev = GENESIS
    for index, row in enumerate(rows, start=1):
        declared_version(row)
        defects = row_defects(row, index)
        if defects:
            raise RowError("; ".join(defects))
        if row["prev_hash"] != prev:
            raise RowError(f"row {index}: prev_hash {row['prev_hash']!r} does not match the previous row_hash {prev!r}")
        expected = row_hash(prev, row)
        if row["row_hash"] != expected:
            raise RowError(f"row {index}: row_hash does not re-derive (stored {row['row_hash']!r}, computed {expected!r})")
        prev = row["row_hash"]
    return prev
