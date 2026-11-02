"""The signed record: what a run asserts about its ledger, and nothing else.

Record version 1, exact key set:

    format           "sdl-decision-record"
    format_version   1
    profile          "production" | "benchmark"
    record_id        a string the emitter chooses; opaque to the verifier
    issued_at        UTC time the record was signed
    decider          {"id", "version", "outcomes": [the decision vocabulary]}
    policy_digests   sorted digests of every policy the rows ran under
    ledger           {"path", "row_count", "terminal_hash"}
    counts           {"decisions", "by_outcome": {outcome: n}}
    benchmark        {"labelled", "agree", "disagree", "by_label"}; benchmark profile only
    retained         {relative path: digest} for files kept beside the ledger; may be {}
    signing_key_id   which registry key signed this
    payload_hash     digest of the canonical record without these two fields
    signature        Ed25519 over the same bytes, base64

There is no field of the form "X was checked" anywhere in it, on purpose. A
record carries claims a verifier recomputes, never flags a verifier reads to
decide whether to recompute. The profile is the one declared field that
selects rules, and the verifier compares it against what the rows support
rather than trusting it.

Retained files are a convention plus a digest. `inputs.jsonl`, if retained,
holds one line per row: {"seq": n, "input": <the object whose canonical digest
is the row's input_digest>}. `policy.json`, if retained, is the policy whose
canonical digest is the rows' single policy_digest. Both are what makes replay
possible; neither is required.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .canonical import is_digest
from .derive import PROFILES, PROFILE_BENCHMARK

FORMAT = "sdl-decision-record"
FORMAT_VERSION = 1
# Version 2 adds one optional key, `stream`, which links a record to the one
# before it in a named sequence (see SPEC §12). A record without a stream is
# written as version 1, so nothing published as v1 changes meaning, and a v1
# verifier refuses a v2 record as a version it does not read rather than
# misreading it.
FORMAT_VERSION_STREAM = 2
SUPPORTED_FORMAT_VERSIONS = (1, 2)
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

REQUIRED_KEYS = frozenset(
    {
        "format", "format_version", "profile", "record_id", "issued_at", "decider",
        "policy_digests", "ledger", "counts", "retained", "signing_key_id",
        "payload_hash", "signature",
    }
)
CONDITIONAL_KEYS = frozenset({"benchmark"})
# Keys a v2 record may carry in addition. `stream` is optional in v2 and
# refused in v1.
V2_OPTIONAL_KEYS = frozenset({"stream"})
STREAM_KEYS = frozenset({"stream_id", "seq", "prev_record_hash", "first_decision"})
INPUTS_FILE = "inputs.jsonl"
POLICY_FILE = "policy.json"


class UnknownFormatVersion(ValueError):
    pass


def declared_format_version(record: Dict[str, Any]) -> int:
    v = record.get("format_version")
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"format_version must be an integer, got {v!r}")
    if v not in SUPPORTED_FORMAT_VERSIONS:
        raise UnknownFormatVersion(
            f"record declares format_version {v}, which this verifier does not read; it reads {list(SUPPORTED_FORMAT_VERSIONS)}"
        )
    return v


def _nonneg_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def record_defects(record: Dict[str, Any]) -> List[str]:
    """Every way the document fails the v1 shape. Content is checked elsewhere."""
    d: List[str] = []
    keys = set(record)
    version = record.get("format_version")
    allowed = REQUIRED_KEYS | CONDITIONAL_KEYS | (V2_OPTIONAL_KEYS if version == FORMAT_VERSION_STREAM else frozenset())
    extra = sorted(keys - allowed)
    if extra:
        d.append(f"undeclared keys {extra}" + (" (stream is a format_version 2 key)" if "stream" in extra else ""))
    missing = sorted(REQUIRED_KEYS - keys)
    if missing:
        d.append(f"missing keys {missing}")
        return d
    if record["format"] != FORMAT:
        d.append(f"format is {record['format']!r}, not {FORMAT!r}")
    if record["profile"] not in PROFILES:
        d.append(f"profile {record['profile']!r} is not one of {list(PROFILES)}")
    if ("benchmark" in record) != (record["profile"] == PROFILE_BENCHMARK):
        d.append("benchmark block is present exactly when profile is benchmark; here it is not")
    if not isinstance(record["record_id"], str) or not record["record_id"]:
        d.append("record_id must be a non-empty string")
    if not isinstance(record["issued_at"], str) or not TS_RE.match(record["issued_at"]):
        d.append("issued_at is not YYYY-MM-DDTHH:MM:SSZ")
    dec = record["decider"]
    if (
        not isinstance(dec, dict)
        or set(dec) - {"established_versions"} != {"id", "version", "outcomes"}
        or not isinstance(dec.get("id"), str) or not dec["id"]
        or not isinstance(dec.get("version"), str) or not dec["version"]
        or not isinstance(dec.get("outcomes"), list)
        or not dec["outcomes"]
        or any(not isinstance(o, str) or not o for o in dec["outcomes"])
        or len(set(dec["outcomes"])) != len(dec["outcomes"])
    ):
        d.append("decider must be {id, version, outcomes: [distinct non-empty strings]}")
    elif "established_versions" in dec:
        ev = dec["established_versions"]
        if (
            not isinstance(ev, list) or not ev
            or any(not isinstance(e, dict) or set(e) != {"version", "evidence"} or not isinstance(e["version"], str) or not e["version"]
                   or e["version"] == dec["version"] or not is_digest(e["evidence"]) for e in ev)
            or len({e["version"] for e in ev}) != len(ev)
        ):
            d.append("decider.established_versions must be a list of distinct {version, evidence: digest}, none the record's own version")
    pd = record["policy_digests"]
    if not isinstance(pd, list) or not pd or any(not is_digest(x) for x in pd) or pd != sorted(set(pd)):
        d.append("policy_digests must be a sorted list of distinct sha256 digests")
    led = record["ledger"]
    if (
        not isinstance(led, dict)
        or set(led) != {"path", "row_count", "terminal_hash"}
        or not isinstance(led.get("path"), str) or not led["path"] or "/" in led["path"] or led["path"].startswith(".")
        or not _nonneg_int(led.get("row_count")) or led["row_count"] == 0
        or not is_digest(led.get("terminal_hash"))
    ):
        d.append("ledger must be {path: a bare filename, row_count: positive integer, terminal_hash: digest}")
    c = record["counts"]
    if (
        not isinstance(c, dict)
        or set(c) != {"decisions", "by_outcome"}
        or not _nonneg_int(c.get("decisions"))
        or not isinstance(c.get("by_outcome"), dict)
        or any(not isinstance(k, str) or not _nonneg_int(v) for k, v in c["by_outcome"].items())
    ):
        d.append("counts must be {decisions: integer, by_outcome: {outcome: integer}}")
    if "benchmark" in record:
        b = record["benchmark"]
        if (
            not isinstance(b, dict)
            or set(b) != {"labelled", "agree", "disagree", "by_label"}
            or not all(_nonneg_int(b.get(k)) for k in ("labelled", "agree", "disagree"))
            or not isinstance(b.get("by_label"), dict)
        ):
            d.append("benchmark must be {labelled, agree, disagree, by_label}")
    ret = record["retained"]
    if not isinstance(ret, dict) or any(
        not isinstance(p, str) or not p or p.startswith(("/", ".")) or ".." in p or not is_digest(v)
        for p, v in ret.items()
    ):
        d.append("retained must map relative file paths to sha256 digests")
    elif isinstance(led, dict) and led.get("path") in ret:
        d.append("the ledger is bound by terminal_hash and must not also appear in retained")
    if "stream" in record:
        st = record["stream"]
        if (
            not isinstance(st, dict)
            or set(st) != STREAM_KEYS
            or not isinstance(st.get("stream_id"), str) or not st["stream_id"]
            or not _nonneg_int(st.get("seq")) or st["seq"] < 1
            or not _nonneg_int(st.get("first_decision")) or st["first_decision"] < 1
            or not (st.get("prev_record_hash") is None or is_digest(st["prev_record_hash"]))
            or ((st.get("seq") == 1) != (st.get("prev_record_hash") is None))
            or (st.get("seq") == 1 and st.get("first_decision") != 1)
        ):
            d.append("stream must be {stream_id, seq >= 1, prev_record_hash: digest or null exactly when seq is 1, first_decision >= 1, and 1 when seq is 1}")
    if not isinstance(record["signing_key_id"], str) or not record["signing_key_id"]:
        d.append("signing_key_id must be a non-empty string")
    if not is_digest(record["payload_hash"]):
        d.append("payload_hash is not a sha256 digest")
    if not isinstance(record["signature"], str) or not record["signature"]:
        d.append("signature must be a non-empty string")
    return d
