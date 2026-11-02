"""Everything a record asserts about its rows, computed from the rows.

This is the one definition. The emitter calls it over the rows it has just
written to disk to fill the record, and the verifier calls it over the rows it
reads to check the record. If the two ever disagreed it would be because one
of them stopped calling this.

Nothing here reads the record. A quantity that cannot be computed from the
rows is not a quantity a record may carry.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

PROFILE_PRODUCTION = "production"
PROFILE_BENCHMARK = "benchmark"
PROFILES = (PROFILE_PRODUCTION, PROFILE_BENCHMARK)


def counts(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_outcome: Dict[str, int] = {}
    for r in rows:
        by_outcome[r["outcome"]] = by_outcome.get(r["outcome"], 0) + 1
    return {"decisions": len(rows), "by_outcome": dict(sorted(by_outcome.items()))}


def deciders(rows: List[Dict[str, Any]]) -> List[str]:
    return sorted({r["decider"] for r in rows})


def policy_digests(rows: List[Dict[str, Any]]) -> List[str]:
    return sorted({r["policy_digest"] for r in rows})


def labelled_count(rows: List[Dict[str, Any]]) -> int:
    return sum(1 for r in rows if "label" in r)


def supported_profile(rows: List[Dict[str, Any]]) -> Optional[str]:
    """Which profile the rows' own content supports.

    Every row labelled: benchmark. No row labelled: production. A mixture
    supports neither, and a record over a mixture is refused whatever it
    declares. The declared profile is compared against this; it is never read
    as a licence to skip a check the content would allow.
    """
    n = labelled_count(rows)
    if n == 0:
        return PROFILE_PRODUCTION
    if n == len(rows):
        return PROFILE_BENCHMARK
    return None


def benchmark(rows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Correctness figures, defined only when every row carries a label."""
    if supported_profile(rows) != PROFILE_BENCHMARK:
        return None
    by_label: Dict[str, Dict[str, int]] = {}
    agree = 0
    for r in rows:
        cell = by_label.setdefault(r["label"], {})
        cell[r["outcome"]] = cell.get(r["outcome"], 0) + 1
        if r["outcome"] == r["label"]:
            agree += 1
    return {
        "labelled": len(rows),
        "agree": agree,
        "disagree": len(rows) - agree,
        "by_label": {k: dict(sorted(v.items())) for k, v in sorted(by_label.items())},
    }


def derive_all(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "counts": counts(rows),
        "deciders": deciders(rows),
        "policy_digests": policy_digests(rows),
        "supported_profile": supported_profile(rows),
    }
    b = benchmark(rows)
    if b is not None:
        out["benchmark"] = b
    return out
