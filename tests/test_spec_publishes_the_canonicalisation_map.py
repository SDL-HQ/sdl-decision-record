"""SPEC.md's canonicalisation table is the emitter's map, not a copy of it.

A third party re-deriving a decision under Cedar's own engine needs the
mapping from retained input to engine request. If that mapping lived only in
`emitters/cedar.py`, re-deriving would need this repository's source to be
read, so SPEC.md §8 carries it.

A table in SPEC.md is a second copy of the emitter's map, and a second copy
drifts from the first in silence. These tests
derive the documented table from the implementation rather than restating it,
so adding a key to `CANONICAL_KEYS` without documenting it fails here.

Breaking any of these: change `CANONICAL_KEYS` and leave SPEC.md alone.
"""

import re
from pathlib import Path

from emitters.cedar import CANONICAL_KEYS, canonical_host, canonical_path

ROOT = Path(__file__).resolve().parents[1]
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")

OPERATION_NAMES = {"host": "host", "path": "path", "upper": "upper-case", "lower": "lower-case"}


def _documented_map():
    """Parse the key/operation table out of SPEC.md §8."""
    section = SPEC.split("**Re-derivation under the grammar's own engine.**", 1)
    assert len(section) == 2, "SPEC.md no longer carries the re-derivation subsection"
    body = re.split(r"^\*\*", section[1], maxsplit=1, flags=re.M)[0]
    out = {}
    for row in re.finditer(r"^\|\s*(`[^|]+`)\s*\|\s*([^|]+?)\s*\|$", body, re.M):
        keys, operation = row.group(1), row.group(2).strip()
        if operation == "operation":
            continue
        for key in re.findall(r"`([^`]+)`", keys):
            out[key] = operation
    return out


def test_every_canonicalised_key_is_documented():
    documented = _documented_map()
    assert set(documented) == set(CANONICAL_KEYS), (
        "SPEC.md's table and CANONICAL_KEYS disagree on which keys are canonicalised: "
        f"only in spec {sorted(set(documented) - set(CANONICAL_KEYS))}, "
        f"only in code {sorted(set(CANONICAL_KEYS) - set(documented))}"
    )


def test_every_documented_key_names_the_operation_the_code_applies():
    documented = _documented_map()
    for key, operation in CANONICAL_KEYS.items():
        assert documented[key] == OPERATION_NAMES[operation], (
            f"SPEC.md says {key!r} gets {documented[key]!r}; the code applies {operation!r}"
        )


def test_the_documented_host_and_path_operations_are_what_runs():
    """The prose describes the operations; these are the operations."""
    assert canonical_host(" EXAMPLE.COM.. ") == "example.com"  # strip, trailing dots, lower
    assert canonical_host("аpi.example.com") == "xn--pi-6kc.example.com"  # IDNA
    assert canonical_host("!!\u0080") == "!!\u0080"  # encoding raises -> lower-cased form kept
    assert canonical_path("/a/%2e%2e/b") == "/b"  # percent-decode once, then normalise
    assert canonical_path("a/./b") == "a/b"  # no leading slash to re-attach
    assert canonical_path("/a/b/") == "/a/b"


def test_the_spec_does_not_claim_the_map_is_bound_to_the_record():
    """Publishing the map closes enablement, not drift. The spec must say so."""
    assert "not a binding to it" in SPEC, (
        "SPEC.md §8 no longer states that the policy object carries the mode's name "
        "and not its content; without that, a reader may take the table as digest-covered"
    )
