"""A verifier of decision records, written from `SPEC.md` and nothing else.

This is the second-implementer instrument of `conformance/verifier/HANDOFF.md`,
run against itself: the question is whether the specification is sufficient for
an implementation written by someone who was not in the room. It is not a second
verifier for production use and nothing depends on it.

**The reference implementation is excluded by construction, not by convention.**
A meta-path finder installed at import refuses `dr`, `emitters` and `tools`
before anything else is imported, so this file cannot consult the code it is
measuring the specification against; an `open()` guard additionally refuses any
`expected.json`, so the corpus's expectations cannot be read during a run. Both
are demonstrated by `tests/test_spec_sufficiency.py` rather than asserted.

**What the result can and cannot establish.** The asymmetry is the instrument's
shape and not a caveat on it. A case this verifier cannot decide is a case the
specification does not determine, soundly: nothing outside `SPEC.md` was
available to decide it. A case it decides correctly establishes much less,
because the author of this file has read the reference implementation in the
past and that knowledge cannot be unlearned by an import hook. The useful
direction is the negative one. Every rule below therefore carries the sentence
of the specification that licenses it, in `CITES`, and `audit_citations()`
checks at start-up that each of those sentences is actually in `SPEC.md`; a rule
whose licence is not in the specification is a rule that came from somewhere
else, and that is mechanically visible rather than a matter of trust.

Assumptions the specification left to the implementer are in `ASSUMPTIONS`,
reported with every run, in the manner `tools/rederive.py` reports its own.

    python3 experiments/spec_sufficiency/verifier.py --corpus conformance/verifier --out results.jsonl
    python3 experiments/spec_sufficiency/verifier.py <run-dir> --registry <file> [--prior ...]
"""

from __future__ import annotations

import importlib.abc
import importlib.machinery
import sys

BLOCKED = ("dr", "emitters", "tools")


class ReferenceCodeBlocked(ImportError):
    """Raised when this file tries to import the code it is measuring against."""


class _Blocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        root = fullname.split(".")[0]
        if root in BLOCKED:
            raise ReferenceCodeBlocked(
                f"{fullname!r} is the reference implementation or its tooling; this verifier is "
                "written from SPEC.md alone and may not import it"
            )
        return None


def install_blocker() -> None:
    if not any(isinstance(f, _Blocker) for f in sys.meta_path):
        sys.meta_path.insert(0, _Blocker())


install_blocker()

import argparse  # noqa: E402
import base64  # noqa: E402
import builtins  # noqa: E402
import hashlib  # noqa: E402
import hmac  # noqa: E402
import json  # noqa: E402
import posixpath  # noqa: E402
import re  # noqa: E402
from pathlib import Path  # noqa: E402

_REAL_OPEN = builtins.open


def _guarded_open(file, *a, **kw):
    name = str(file)
    if posixpath.basename(name.replace("\\", "/")) == "expected.json":
        raise PermissionError(
            f"refusing to open {name!r}: the corpus's expected states may not be read during a run "
            "(HANDOFF.md: an implementation tuned case by case against the expectations tells us nothing)"
        )
    return _REAL_OPEN(file, *a, **kw)


builtins.open = _guarded_open

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

# --------------------------------------------------------------------------- #
# What licenses each rule. Checked against SPEC.md at start-up.
# --------------------------------------------------------------------------- #

CITES = {
    "canonical": ("2", "UTF-8, keys\nsorted, separators `,` and `:` with no whitespace, non-ASCII unescaped"),
    "digest": ("2", '`"sha256:" + lowercase hex` of SHA-256 over bytes'),
    "row_keys": ("3", "Row\nversion 1 carries exactly these keys and no others"),
    "row_shape_refusal": ("3", "A row with an\nundeclared key is refused on shape as well"),
    "row_hash": ("3", "`digest(prev_hash_bytes + canonical(row without prev_hash and row_hash))`"),
    "prev_hash_bytes": ("3", "`prev_hash_bytes` is the UTF-8 of the `prev_hash` string"),
    "row_v2": ("3", '`"hmac-sha256:" + lowercase hex` of HMAC-SHA256 keyed with the run\'s salt over\nthe canonical input'),
    "salt_line": ("3", "The salt is the first line of `inputs.jsonl`,\n`{\"salt\": hex}`"),
    "one_row_version": ("3", "A ledger has one row version throughout"),
    "chain": ("4", "re-derives every `row_hash` from `GENESIS` forward and requires\neach row's `prev_hash` to equal the previous row's `row_hash`"),
    "terminal": ("4", "The terminal\nhash is the last row's `row_hash`"),
    "mixed_malformed": ("4", "A ledger that mixes row versions is\nmalformed"),
    "unread_version_unknown": ("4", "A ledger whose rows declare a version the verifier does not read is\n**unknown**, not failed"),
    "record_keys": ("5", "`record.json` is one JSON object with exactly these keys"),
    "payload": ("7", "canonical bytes of the record without `payload_hash` and `signature`"),
    "signature_alg": ("7", "`signature` is Ed25519 (RFC 8032) over the\npayload, base64"),
    "registry": ("7", 'Status\nis `active` (signs now), `retired` (no longer signs; honoured for what it\nsigned) or `revoked`'),
    "revoked": ("7", "trust\nafter revocation is granted by the registry listing that record's\n`payload_hash`, and in no other way"),
    "profile_rows": ("6", "every row carries `label`: the rows support **benchmark**"),
    "profile_mixed": ("6", "some do and some do not: the rows support **no profile**"),
    "profile_declared": ("6", "The record's `profile` is a declaration compared against that"),
    "production_no_correctness": ("6", "correctness | not applicable | required"),
    "inputs_file": ("8", '`inputs.jsonl`: one line per row, `{"seq": n, "input": <object>}`'),
    "policy_file": ("8", "`policy.json`: the policy, whose `digest(parsed object)` must be the rows'\n  single `policy_digest`"),
    "policy_single": ("8", "Checked when the rows carry exactly one"),
    "retained_absent": ("8", "A named file that is **absent** from the copy being verified leaves `retained`\n**unknown**"),
    "retained_differs": ("8", "A named file that is present and\ndiffers from its digest is a **failure**"),
    "states": ("9", "Every property is one of **established**, **unknown**, **failed**, or\n**n/a**"),
    "unknown_never_pass": ("9", "it is never a pass"),
    "unknown_means": ("9", "rows that did not re-derive so\nnothing over them was computed"),
    "core": ("9", "are decided by every verification of every record"),
    "bail_out": ("9", "a verifier that stops early reports the rest as\nunknown with the reason rather than omitting them"),
    "verdict": ("9", "**FAILED** (exit 2) if any applicable property failed"),
    "verdict_not_established": ("9", "**NOT\nESTABLISHED** (exit 1) if none failed and any is unknown, an absent core\nproperty included"),
    "unreadable": ("9", "exit 3 if the directory\ncould not be read"),
    "document": ("9", "the shape of its `format_version`; `payload_hash` recomputes"),
    "decisions": ("9", "`counts`, `policy_digests` and `decider` recompute from the rows; every outcome is in the declared vocabulary"),
    "correctness": ("9", "benchmark only: `benchmark` recomputes from labels"),
    "policy_digests": ("5", "sorted, distinct digests of every policy the rows ran under"),
    "stream_block": ("12", '"stream": {"stream_id": <string>, "seq": n >= 1'),
    "stream_prev": ("12", "`prev_record_hash` is the previous record's `payload_hash` (null iff `seq` is\n1)"),
    "stream_first_decision": ("12", "the prior's `first_decision` plus\nthe prior's `row_count`"),
    "stream_established": ("12", "establishes `stream` when `stream_id`\nmatches, `seq` is the prior's plus one"),
    "stream_seq1": ("9", "established for `seq` 1"),
    "completeness_never": ("13", "a `completeness` property that is **never\nestablished**"),
    "receipt_shape": ("13", '`{"kind": "sdl-decision-receipt", "record_id", "stream_id", "seq",'),
    "receipt_states": ("13", "**included** (the row is present with the receipted `row_hash`), **missing**"),
    "receipts_prop": ("9", "established when every supplied receipt is for a row that is present with the receipted `row_hash`"),
    "witness_shape": ("13", '`{"kind": "sdl-witness-statement", "record_payload_hash", "witnessed_at",'),
    "witness_prop": ("9", "established when a key in the witness registry, which is not a producer key, signed this record's `payload_hash`"),
    "witness_is_producer": ("13", "A witness key that is also a producer key establishes nothing\nand is reported unknown"),
    "attestation_shape": ("15", '{"kind": "decider-attestation", "record_id": "...", "seq": n'),
    "invocation": ("15", "every row has an\nattestation; each matches its row on record id, seq, input digest, outcome,\nreason, policy digest and decider"),
    "invocation_na": ("15", "`n/a` when no attestations are retained"),
    "invocation_not_producer": ("15", "that key's material is not any producer key"),
    "format_version": ("5", "`1`, or `2` when the record carries `stream`"),
    "v1_over_v2_rows": ("10", "A version 1 record over\nversion 2 rows is permitted"),
}

ASSUMPTIONS = [
    {
        "id": "S1",
        "about": "a signing key the registry does not carry",
        "why": "§9 names a malformed registry entry as a cause of unknown; it does not say what an absent key is. §7 says a revoked key is 'not honoured for anything the registry does not name', which treats the registry as the authority on what is honoured.",
        "assumed": "signing_trust failed",
        "removed_by": "one sentence in §7 or §9 stating the state for a key_id absent from the registry",
    },
    {
        "id": "S2",
        "about": "the HMAC key for a version 2 input digest",
        "why": "§3 says the digest is 'HMAC-SHA256 keyed with the run's salt' and that the salt is hex, without saying whether the key is the decoded bytes or the hex text.",
        "assumed": "bytes.fromhex(salt)",
        "removed_by": "§3 saying which of the two the key is",
    },
    {
        "id": "S3",
        "about": "the signing rule for receipts, witness statements and decider attestations",
        "why": "§7 states payload = the object without payload_hash and signature for the record. §13 and §15 give the three other signed shapes with both fields and never restate the rule, so it is reached by analogy.",
        "assumed": "the §7 construction applied to each of the three objects",
        "removed_by": "§7 stating the rule for every signed object of this format rather than for the record",
    },
    {
        "id": "S4",
        "about": "counts.by_outcome for a declared outcome that never occurred",
        "why": "§5 gives the shape and §9 says counts recompute from the rows; neither says whether a zero entry is present or absent.",
        "assumed": "only outcomes that occur appear",
        "removed_by": "§5 stating the key set of by_outcome",
    },
    {
        "id": "S5",
        "about": "the definition of the benchmark block's members",
        "why": "§5 names labelled, agree, disagree and by_label and §9 says they recompute from labels; the arithmetic is not written down, and §5 points at dr/derive.py for it.",
        "assumed": "labelled = rows carrying a label; agree = rows whose label equals their outcome; disagree = labelled - agree; by_label[label][outcome] = count",
        "removed_by": "§5 defining the four members as expressions over the rows",
    },
    {
        "id": "S6",
        "about": "whether decider.outcomes must equal the observed outcomes",
        "why": "§9 requires 'every outcome is in the declared vocabulary', which is containment; §5 requires the declared list be distinct and non-empty. Equality is neither required nor excluded.",
        "assumed": "containment: observed ⊆ declared",
        "removed_by": "§9 or §5 saying whether a declared outcome that never occurs is permitted",
    },
    {
        "id": "S7",
        "about": "which property an undeclared key fails",
        "why": "§3 says a row with an undeclared key 'is refused on shape as well' and §5 says the record has exactly its keys; neither names the property that carries the refusal.",
        "assumed": "a record-level undeclared key fails document; a row-level one fails chain",
        "removed_by": "§9's table naming the property each shape refusal lands on",
    },
    {
        "id": "S8",
        "about": "an empty retained block",
        "why": "§5 permits retained to be {} and §6 makes retained a required property of both profiles; §8 and §9 describe the states for named files without saying what no named files gives.",
        "assumed": "established, there being nothing whose digest fails to match",
        "removed_by": "§9's retained row stating the state when no file is named",
    },
    {
        "id": "S9",
        "about": "attestations retained with no decider registry supplied",
        "why": "§15 says invocation is checked when attestations are retained and --decider-registry names the decider's keys, and that n/a is for when no attestations are retained. The remaining combination is not given a state.",
        "assumed": "unknown, by §9's rule that a check that could not be performed is unknown",
        "removed_by": "§15 stating the state for retained attestations without a registry",
    },
]

STATES = ("established", "unknown", "failed", "n/a")
PROPERTIES = (
    "document", "signing_trust", "signature", "chain", "decisions", "profile", "correctness",
    "retained", "replay", "invocation", "stream", "completeness", "receipts", "witness",
)
CORE = ("document", "signing_trust", "signature", "chain", "decisions", "profile", "correctness", "retained")

ROW_REQUIRED = {"v", "seq", "ts", "input_digest", "decider", "policy_digest", "outcome", "reason", "prev_hash", "row_hash"}
ROW_OPTIONAL = {"label", "ext"}
RECORD_REQUIRED = {
    "format", "format_version", "profile", "record_id", "issued_at", "decider", "policy_digests",
    "ledger", "counts", "retained", "signing_key_id", "payload_hash", "signature",
}
RECORD_OPTIONAL = {"benchmark", "stream"}
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


# The specification this was read against, by digest of its bytes. A
# second-implementer result is bound to one revision: these rules were written
# by a reader who had not seen the reference, and that reader no longer exists.
# Re-running them against a later SPEC.md is not a second measurement -- it
# measures whether someone who has since read the reference edited the rules
# consistently, which nobody needs to know. So the run refuses, and the
# committed results.jsonl stays what it is: a dated finding about SPEC.md at
# this digest, not a claim about the specification as it stands.
MEASURED_AGAINST = "993988680fa0da258432c205027d59865a2ac28dd3cf13fffcc1747adda1a419"


def spec_digest(spec_path: Path) -> str:
    return hashlib.sha256(spec_path.read_bytes()).hexdigest()


def audit_citations(spec_path: Path) -> list[str]:
    """Every rule's licence must actually be in SPEC.md. Returns the ones that are not."""
    spec = spec_path.read_text()
    return [name for name, (_sec, phrase) in CITES.items() if phrase not in spec]


# --------------------------------------------------------------------------- #
# §2 Canonical bytes and digests
# --------------------------------------------------------------------------- #

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest_bytes(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def digest_obj(obj) -> str:
    return digest_bytes(canonical(obj))


def keyed_digest(salt_hex: str, obj) -> str:
    return "hmac-sha256:" + hmac.new(bytes.fromhex(salt_hex), canonical(obj), hashlib.sha256).hexdigest()


def payload_of(obj: dict) -> bytes:
    """§7, assumption S3 for the three objects other than the record."""
    return canonical({k: v for k, v in obj.items() if k not in ("payload_hash", "signature")})


ASSUMPTIONS += [
    {
        "id": "S10",
        "about": "a run directory whose record.json reads but whose ledger file does not",
        "why": "§9 gives exit 3 for a directory that 'could not be read' without saying which files that covers.",
        "assumed": "only an unreadable record.json is exit 3; an unreadable ledger leaves chain unknown",
        "removed_by": "§9 naming the files whose absence makes a directory unreadable",
    },
    {
        "id": "S11",
        "about": "completeness when receipts are supplied and none is refuting",
        "why": "§9 gives n/a for 'no receipt is supplied' and failed for a receipt naming a decision the record lacks, and the property is never established; §13 says it is 'n/a (not claimed) or failed (refuted)'.",
        "assumed": "n/a, taking §13's two-way split as the rule",
        "removed_by": "§9 stating the state when receipts are supplied and all are included",
    },
]


# --------------------------------------------------------------------------- #
# §9 report and verdict
# --------------------------------------------------------------------------- #

class Report:
    def __init__(self) -> None:
        self.props: dict[str, str] = {}
        self.details: dict[str, str] = {}
        self.payload_hash_recomputed: str | None = None
        self.terminal_hash_recomputed: str | None = None

    def add(self, name: str, state: str, detail: str = "") -> None:
        assert state in STATES, state
        self.props[name] = state
        if detail:
            self.details[name] = detail

    def skipped(self, reason: str) -> None:
        """§9: a verifier that stops early reports the rest as unknown with the reason."""
        for p in PROPERTIES:
            if p not in self.props:
                self.add(p, "unknown", reason)

    def verdict(self) -> tuple[str, int]:
        states = {p: self.props.get(p, "unknown" if p in CORE else "n/a") for p in PROPERTIES}
        if any(s == "failed" for s in states.values()):
            return "FAILED", 2
        if any(s == "unknown" for s in states.values()):
            return "NOT ESTABLISHED", 1
        return "ESTABLISHED", 0


# --------------------------------------------------------------------------- #
# §7 keys and signatures
# --------------------------------------------------------------------------- #

def _load_registry(path: Path) -> dict:
    return json.loads(path.read_text())


def _entry(registry: dict, key_id: str) -> dict | None:
    for k in registry.get("keys") or []:
        if isinstance(k, dict) and k.get("key_id") == key_id:
            return k
    return None


def honour(registry: dict, key_id: str, payload_hash: str) -> tuple[str, str]:
    e = _entry(registry, key_id)
    if e is None:
        return "failed", f"the registry carries no entry for {key_id!r} (S1)"
    if not isinstance(e.get("status"), str) or not isinstance(e.get("public_key_pem"), str):
        return "unknown", "the registry entry is malformed"
    st = e["status"]
    if st in ("active", "retired"):
        return "established", f"status {st}"
    if st == "revoked":
        named = e.get("trusted_after_revocation") or []
        if isinstance(named, list) and payload_hash in named:
            return "established", "revoked, and the registry names this payload_hash"
        return "failed", "the key is revoked and the registry does not name this payload_hash"
    return "unknown", f"unreadable status {st!r}"


def _public_key(entry: dict) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(entry["public_key_pem"].encode("utf-8"))


def _raw(entry: dict) -> bytes:
    return _public_key(entry).public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


def check_signature(obj: dict, registry: dict, key_id: str) -> tuple[str, str]:
    e = _entry(registry, key_id)
    if e is None or not isinstance(e.get("public_key_pem"), str):
        return "unknown", "no key material to verify with"
    try:
        _public_key(e).verify(base64.b64decode(obj["signature"]), payload_of(obj))
    except InvalidSignature:
        return "failed", "the signature does not verify under that key"
    except Exception as exc:  # noqa: BLE001 - §9: a check that could not run is unknown
        return "unknown", f"the signature check could not run: {type(exc).__name__}"
    return "established", "verifies"


# --------------------------------------------------------------------------- #
# §3, §4 the ledger
# --------------------------------------------------------------------------- #

def _read_jsonl(path: Path) -> list:
    out = []
    for line in path.read_text().splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def check_chain(rec: dict, run: Path) -> tuple[str, str, str | None, list | None, str | None]:
    """Returns (state, detail, terminal_recomputed, rows, salt)."""
    ledger = rec.get("ledger")
    if not isinstance(ledger, dict) or not isinstance(ledger.get("path"), str):
        return "failed", "the record does not name a ledger", None, None, None
    lpath = run / ledger["path"]
    try:
        rows = _read_jsonl(lpath)
    except Exception as exc:  # noqa: BLE001
        return "unknown", f"the ledger could not be read: {type(exc).__name__} (S10)", None, None, None
    if not rows:
        return "failed", "the ledger carries no rows", None, rows, None

    versions = {r.get("v") for r in rows}
    if len(versions) > 1:
        return "failed", f"the ledger mixes row versions {sorted(map(str, versions))}", None, rows, None
    (version,) = tuple(versions)
    if version not in (1, 2):
        return "unknown", f"row version {version!r} is one this verifier does not read", None, rows, None

    salt = None
    ipath = run / "inputs.jsonl"
    if ipath.exists():
        try:
            first = _read_jsonl(ipath)[0]
            if isinstance(first, dict) and set(first) == {"salt"}:
                salt = first["salt"]
        except Exception:  # noqa: BLE001
            salt = None
    if version == 2 and salt is None:
        pass  # a v2 ledger may be handed on without its inputs; §14
    if version == 1 and salt is not None:
        return "failed", "version 1 rows with a salt line in inputs.jsonl is malformed", None, rows, salt

    prefix = "hmac-sha256:" if version == 2 else "sha256:"
    terminal = None
    for i, row in enumerate(rows):
        where = f"row {i + 1}"
        if not isinstance(row, dict):
            return "failed", f"{where} is not an object", terminal, rows, salt
        keys = set(row)
        if not ROW_REQUIRED <= keys:
            return "failed", f"{where} is missing {sorted(ROW_REQUIRED - keys)}", terminal, rows, salt
        undeclared = keys - ROW_REQUIRED - ROW_OPTIONAL
        if undeclared:
            return "failed", f"{where} carries undeclared keys {sorted(undeclared)} (S7)", terminal, rows, salt
        if row["seq"] != i + 1:
            return "failed", f"{where} declares seq {row['seq']}, breaking 1..n in file order", terminal, rows, salt
        if not isinstance(row["ts"], str) or not TS_RE.match(row["ts"]):
            return "failed", f"{where} has a malformed ts", terminal, rows, salt
        if not isinstance(row["outcome"], str) or not row["outcome"]:
            return "failed", f"{where} has an empty outcome", terminal, rows, salt
        if row["reason"] is not None and (not isinstance(row["reason"], str) or not row["reason"]):
            return "failed", f"{where} has an empty reason", terminal, rows, salt
        if not isinstance(row["input_digest"], str) or not row["input_digest"].startswith(prefix):
            return "failed", f"{where}'s input_digest is not a {prefix[:-1]} digest for a v{version} row", terminal, rows, salt
        expected_prev = "GENESIS" if i == 0 else rows[i - 1]["row_hash"]
        if row["prev_hash"] != expected_prev:
            return "failed", f"{where}'s prev_hash is not the previous row's row_hash", terminal, rows, salt
        body = {k: v for k, v in row.items() if k not in ("prev_hash", "row_hash")}
        recomputed = digest_bytes(row["prev_hash"].encode("utf-8") + canonical(body))
        if recomputed != row["row_hash"]:
            return "failed", f"{where}'s row_hash does not re-derive", terminal, rows, salt
        terminal = recomputed

    if ledger.get("row_count") != len(rows):
        return "failed", f"the record signs row_count {ledger.get('row_count')} over {len(rows)} rows", terminal, rows, salt
    if ledger.get("terminal_hash") != terminal:
        return "failed", "the re-derived terminal hash is not the one the record signs", terminal, rows, salt
    return "established", f"{len(rows)} rows re-derive from GENESIS to the signed terminal hash", terminal, rows, salt


# --------------------------------------------------------------------------- #
# §5, §6 figures derived from the rows
# --------------------------------------------------------------------------- #

def _count(items) -> dict:
    out: dict = {}
    for x in items:
        out[x] = out.get(x, 0) + 1
    return out


def check_decisions(rec: dict, rows: list) -> tuple[str, str]:
    outcomes = [r["outcome"] for r in rows]
    want_counts = {"decisions": len(rows), "by_outcome": _count(outcomes)}  # S4
    if rec.get("counts") != want_counts:
        return "failed", "counts do not recompute from the rows"
    want_digests = sorted({r["policy_digest"] for r in rows})
    if rec.get("policy_digests") != want_digests:
        return "failed", "policy_digests do not recompute from the rows"
    d = rec.get("decider")
    if not isinstance(d, dict):
        return "failed", "the record does not carry a decider block"
    ident = f"{d.get('id')}@{d.get('version')}"
    row_idents = {r["decider"] for r in rows}
    if row_idents != {ident}:
        return "failed", f"the rows name {sorted(row_idents)} and the record names {ident!r}"
    declared = d.get("outcomes")
    if not isinstance(declared, list) or not declared or len(set(declared)) != len(declared):
        return "failed", "the declared outcome vocabulary is malformed"
    undeclared = sorted(set(outcomes) - set(declared))
    if undeclared:
        return "failed", f"the rows carry outcomes outside the declared vocabulary: {undeclared}"
    return "established", "counts, policy_digests and decider recompute from the rows"


def rows_support(rows: list) -> str | None:
    labelled = sum("label" in r for r in rows)
    if labelled == len(rows):
        return "benchmark"
    if labelled == 0:
        return "production"
    return None


def check_profile(rec: dict, rows: list) -> tuple[str, str]:
    supported = rows_support(rows)
    declared = rec.get("profile")
    if supported is None:
        return "failed", "some rows carry a label and some do not, so the rows support no profile"
    if declared != supported:
        return "failed", f"the record declares {declared!r} over rows that support {supported!r}"
    return "established", f"the rows support {supported!r} and the record declares it"


def check_correctness(rec: dict, rows: list) -> tuple[str, str]:
    supported = rows_support(rows)
    declared = rec.get("profile")
    if declared == "production":
        if supported == "benchmark":
            return "failed", "the rows are labelled, so correctness was computable and was withheld"
        return "n/a", "production carries no correctness"
    if declared != "benchmark":
        return "failed", f"profile {declared!r} is not one this version defines"
    if supported != "benchmark":
        return "failed", "a benchmark record over rows that are not all labelled"
    agree = sum(r["label"] == r["outcome"] for r in rows)
    by_label: dict = {}
    for r in rows:
        by_label.setdefault(r["label"], {})
        by_label[r["label"]][r["outcome"]] = by_label[r["label"]].get(r["outcome"], 0) + 1
    want = {"labelled": len(rows), "agree": agree, "disagree": len(rows) - agree, "by_label": by_label}  # S5
    if rec.get("benchmark") != want:
        return "failed", "the benchmark block does not recompute from the labels"
    return "established", f"{agree} of {len(rows)} agree with their label"


# --------------------------------------------------------------------------- #
# §8 retained files
# --------------------------------------------------------------------------- #

def check_retained(rec: dict, run: Path, rows: list, salt: str | None) -> tuple[str, str]:
    ret = rec.get("retained")
    if not isinstance(ret, dict):
        return "failed", "the record does not carry a retained block"
    ledger_name = (rec.get("ledger") or {}).get("path")
    if ledger_name in ret:
        return "failed", "retained names the ledger"
    if not ret:
        return "established", "the record names no retained file (S8)"

    absent, failures = [], []
    for name, dg in sorted(ret.items()):
        f = run / name
        if not f.exists():
            absent.append(name)
            continue
        if digest_bytes(f.read_bytes()) != dg:
            failures.append(f"{name} is present and its digest differs from the record's claim")

    if "inputs.jsonl" in ret and (run / "inputs.jsonl").exists() and not failures:
        try:
            lines = _read_jsonl(run / "inputs.jsonl")
            body = lines[1:] if (lines and isinstance(lines[0], dict) and set(lines[0]) == {"salt"}) else lines
            if len(body) != len(rows):
                failures.append(f"inputs.jsonl carries {len(body)} inputs for {len(rows)} rows")
            else:
                for line, row in zip(body, rows):
                    if line.get("seq") != row["seq"]:
                        failures.append(f"inputs.jsonl line for seq {line.get('seq')} is out of order")
                        break
                    got = keyed_digest(salt, line["input"]) if row["v"] == 2 else digest_obj(line["input"])
                    if got != row["input_digest"]:
                        failures.append(f"the retained input for seq {row['seq']} does not hash to the row's input_digest")
                        break
        except Exception as exc:  # noqa: BLE001
            return "unknown", f"inputs.jsonl could not be checked: {type(exc).__name__}"

    if "policy.json" in ret and (run / "policy.json").exists() and not failures:
        digests = {r["policy_digest"] for r in rows}
        if len(digests) == 1:
            try:
                if digest_obj(json.loads((run / "policy.json").read_text())) != next(iter(digests)):
                    failures.append("the retained policy does not hash to the rows' policy_digest")
            except Exception as exc:  # noqa: BLE001
                return "unknown", f"policy.json could not be checked: {type(exc).__name__}"

    if failures:
        return "failed", "; ".join(failures)
    if absent:
        return "unknown", f"named but absent, so the digest check could not run: {absent}"
    return "established", f"{len(ret)} named file(s) present with the digests the record claims"


# --------------------------------------------------------------------------- #
# §15 invocation, §12 stream, §13 completeness, receipts, witness
# --------------------------------------------------------------------------- #

def check_invocation(rec: dict, run: Path, rows: list, producer_registry: dict, decider_registry: dict | None) -> tuple[str, str]:
    if "attestations.jsonl" not in (rec.get("retained") or {}):
        return "n/a", "no attestations are retained"
    f = run / "attestations.jsonl"
    if not f.exists():
        return "unknown", "attestations.jsonl is named but absent"
    if decider_registry is None:
        return "unknown", "no decider registry was supplied (S9)"
    try:
        atts = _read_jsonl(f)
    except Exception as exc:  # noqa: BLE001
        return "unknown", f"attestations.jsonl could not be read: {type(exc).__name__}"

    producer_raw = set()
    for k in producer_registry.get("keys") or []:
        try:
            producer_raw.add(_raw(k))
        except Exception:  # noqa: BLE001
            pass
    by_seq = {a.get("seq"): a for a in atts if isinstance(a, dict)}
    for row in rows:
        a = by_seq.get(row["seq"])
        if a is None:
            return "failed", f"row {row['seq']} has no attestation"
        if a.get("kind") != "decider-attestation":
            return "failed", f"the attestation for row {row['seq']} is not a decider attestation"
        for field, value in (
            ("record_id", rec.get("record_id")), ("input_digest", row["input_digest"]),
            ("outcome", row["outcome"]), ("reason", row["reason"]),
            ("policy_digest", row["policy_digest"]), ("decider", row["decider"]),
        ):
            if a.get(field) != value:
                return "failed", f"the attestation for row {row['seq']} disagrees with the row on {field}"
        kid = a.get("decider_key_id")
        e = _entry(decider_registry, kid)
        if e is None:
            return "failed", f"the decider registry carries no entry for {kid!r}"
        if e.get("status") != "active":
            return "failed", f"the decider key {kid!r} is not active"
        try:
            if _raw(e) in producer_raw:
                return "unknown", f"the decider key {kid!r} is a producer key"
        except Exception:  # noqa: BLE001
            return "unknown", f"the decider key {kid!r} could not be parsed"
        state, detail = check_signature(a, decider_registry, kid)
        if state != "established":
            return ("failed" if state == "failed" else "unknown"), f"row {row['seq']}: {detail}"
    return "established", f"every one of {len(rows)} rows carries an attestation that verifies"


def check_stream(rec: dict, run: Path, rows: list, prior_dir: Path | None) -> tuple[str, str]:
    st = rec.get("stream")
    if st is None:
        return "n/a", "the record carries no stream block"
    if not isinstance(st, dict) or set(st) != {"stream_id", "seq", "prev_record_hash", "first_decision"}:
        return "failed", "the stream block does not carry its four keys"
    names_prior = [r for r in rows if isinstance(r.get("ext"), dict) and "prior_row" in r["ext"]]
    if st["seq"] == 1:
        if st["prev_record_hash"] is not None:
            return "failed", "seq 1 carries a prev_record_hash"
        if st["first_decision"] != 1:
            return "failed", "seq 1 does not start the numbering at 1"
        if names_prior:
            return "failed", "a row of the first record of a stream names a prior row"
        return "established", "seq 1, the first record of the stream"
    if prior_dir is None:
        return "unknown", f"seq {st['seq']} and no prior record was supplied"
    prior_dir = prior_dir.parent if prior_dir.name == "record.json" else prior_dir
    try:
        prior = json.loads((prior_dir / "record.json").read_text())
    except Exception as exc:  # noqa: BLE001
        return "unknown", f"the prior record could not be read: {type(exc).__name__}"
    pst = prior.get("stream") or {}
    if pst.get("stream_id") != st["stream_id"]:
        return "failed", "the prior record belongs to another stream"
    if st["seq"] != (pst.get("seq") or 0) + 1:
        return "failed", "seq does not follow the prior's"
    if st["prev_record_hash"] != prior.get("payload_hash"):
        return "failed", "prev_record_hash is not the prior record's payload_hash"
    want_first = (pst.get("first_decision") or 0) + ((prior.get("ledger") or {}).get("row_count") or 0)
    if st["first_decision"] != want_first:
        return "failed", f"first_decision is {st['first_decision']} where the prior's numbering continues at {want_first}"
    if names_prior:
        pstate, pdetail, pterminal, prows, _ = check_chain(prior, prior_dir)
        if prows is None or pstate == "unknown":
            return "unknown", f"rows name prior rows and the prior's ledger could not be checked: {pdetail}"
        if pstate != "established":
            return "failed", f"rows name prior rows and the prior's ledger does not re-derive: {pdetail}"
        have = {r["row_hash"] for r in prows}
        for r in names_prior:
            if r["ext"]["prior_row"] not in have:
                return "failed", f"row {r['seq']} names a prior row the prior's ledger does not carry"
    return "established", f"seq {st['seq']} links to the prior record"


def _load_many(paths) -> list[dict]:
    """A receipt option is one path or several; a path may be a file or a directory of them."""
    out = []
    for path in ([paths] if isinstance(paths, (str, Path)) else list(paths)):
        path = Path(path)
        if path.is_dir():
            out += [json.loads(f.read_text()) for f in sorted(path.glob("*.json"))]
        else:
            out.append(json.loads(path.read_text()))
    return out


def check_receipts(rec: dict, rows: list, registry: dict, receipt_path) -> tuple[str, str, bool]:
    """Returns (state, detail, refutes_completeness)."""
    if receipt_path is None:
        return "n/a", "no receipt was supplied", False
    try:
        receipts = _load_many(receipt_path)
    except Exception as exc:  # noqa: BLE001
        return "unknown", f"the receipts could not be read: {type(exc).__name__}", False
    by_seq = {r["seq"]: r for r in rows}
    missing, altered, invalid, foreign, unknown = [], [], [], [], []
    for rcpt in receipts:
        if not isinstance(rcpt, dict) or rcpt.get("kind") != "sdl-decision-receipt":
            invalid.append("a receipt is not a decision receipt")
            continue
        if rcpt.get("record_id") != rec.get("record_id"):
            foreign.append(str(rcpt.get("seq")))
            continue
        state, detail = check_signature(rcpt, registry, rcpt.get("signing_key_id"))
        if state == "failed":
            invalid.append(f"seq {rcpt.get('seq')}: {detail}")
            continue
        if state == "unknown":
            unknown.append(f"seq {rcpt.get('seq')}: {detail}")
            continue
        trust, tdetail = honour(registry, rcpt.get("signing_key_id"), rcpt.get("payload_hash"))
        if trust == "failed":
            invalid.append(f"seq {rcpt.get('seq')}: {tdetail}")
            continue
        if trust == "unknown":
            unknown.append(f"seq {rcpt.get('seq')}: {tdetail}")
            continue
        row = by_seq.get(rcpt.get("seq"))
        if row is None:
            missing.append(str(rcpt.get("seq")))
        elif row["row_hash"] != rcpt.get("row_hash"):
            altered.append(str(rcpt.get("seq")))
    if missing or altered or invalid:
        parts = []
        if missing:
            parts.append(f"missing: the record lacks the decisions receipted at seq {missing}")
        if altered:
            parts.append(f"altered: the row at seq {altered} is a different row")
        if invalid:
            parts.append("invalid: " + "; ".join(invalid))
        return "failed", "; ".join(parts), bool(missing)
    if foreign or unknown:
        return "unknown", f"foreign: {foreign}; uncheckable: {unknown}", False
    return "established", f"{len(receipts)} receipt(s), each for a present row with the receipted row_hash", False


def check_witness(rec: dict, registry: dict, witness_path: Path | None, witness_registry_path: Path | None) -> tuple[str, str]:
    if witness_path is None:
        return "n/a", "no witness statement was supplied"
    try:
        st = json.loads(witness_path.read_text())
    except Exception as exc:  # noqa: BLE001
        return "unknown", f"the witness statement could not be read: {type(exc).__name__}"
    if not isinstance(st, dict) or st.get("kind") != "sdl-witness-statement":
        return "failed", "the statement is not a witness statement"
    if witness_registry_path is None:
        return "unknown", "no witness registry was supplied"
    try:
        wreg = _load_registry(witness_registry_path)
    except Exception as exc:  # noqa: BLE001
        return "unknown", f"the witness registry could not be read: {type(exc).__name__}"
    if st.get("record_payload_hash") != rec.get("payload_hash"):
        return "failed", "the statement is for another record's payload_hash"
    kid = st.get("witness_key_id")
    e = _entry(wreg, kid)
    if e is None:
        return "unknown", f"the witness registry carries no entry for {kid!r}"
    producer_raw = set()
    for k in registry.get("keys") or []:
        try:
            producer_raw.add(_raw(k))
        except Exception:  # noqa: BLE001
            pass
    try:
        if _raw(e) in producer_raw:
            return "unknown", f"the witness key {kid!r} is a producer key, which establishes nothing"
    except Exception:  # noqa: BLE001
        return "unknown", f"the witness key {kid!r} could not be parsed"
    state, detail = check_signature(st, wreg, kid)
    if state == "failed":
        return "failed", f"the statement does not verify: {detail}"
    if state == "unknown":
        return "unknown", detail
    return "established", f"{kid!r}, not a producer key, signed this record's payload_hash"


# --------------------------------------------------------------------------- #
# §9 orchestration
# --------------------------------------------------------------------------- #

def check_document(rec: dict, report: Report) -> tuple[str, str]:
    report.payload_hash_recomputed = digest_bytes(payload_of(rec))
    keys = set(rec)
    if not RECORD_REQUIRED <= keys:
        return "failed", f"the record is missing {sorted(RECORD_REQUIRED - keys)}"
    undeclared = keys - RECORD_REQUIRED - RECORD_OPTIONAL
    if undeclared:
        return "failed", f"the record carries undeclared keys {sorted(undeclared)} (S7)"
    if rec.get("format") != "sdl-decision-record":
        return "failed", f"format is {rec.get('format')!r}"
    fv = rec.get("format_version")
    if fv not in (1, 2):
        return "unknown", f"format_version {fv!r} is one this verifier does not read"
    if "stream" in rec and fv != 2:
        return "failed", "a record carrying stream declares format_version 1"
    if ("benchmark" in rec) != (rec.get("profile") == "benchmark"):
        return "failed", "the benchmark block is present iff the profile is benchmark, and is not"
    if not isinstance(rec.get("record_id"), str) or not rec["record_id"]:
        return "failed", "record_id is empty"
    if not isinstance(rec.get("issued_at"), str) or not TS_RE.match(rec["issued_at"]):
        return "failed", "issued_at is malformed"
    if report.payload_hash_recomputed != rec.get("payload_hash"):
        return "failed", "payload_hash does not recompute over the canonical payload"
    return "established", "the shape is version 1's and payload_hash recomputes"


def verify(run: Path, registry_path: Path, *, prior: Path | None = None, receipts: Path | None = None,
           witness: Path | None = None, witness_registry: Path | None = None,
           decider_registry: Path | None = None) -> Report:
    report = Report()
    try:
        rec = json.loads((run / "record.json").read_text())
        if not isinstance(rec, dict):
            raise ValueError("record.json is not an object")
    except Exception:  # noqa: BLE001 - §9 exit 3
        report.unreadable = True  # type: ignore[attr-defined]
        return report
    try:
        registry = _load_registry(registry_path)
    except Exception as exc:  # noqa: BLE001
        report.skipped(f"the key registry could not be read: {type(exc).__name__}")
        return report

    state, detail = check_document(rec, report)
    report.add("document", state, detail)
    if state != "established":
        report.skipped(f"the document was not established ({detail}), so nothing over it was judged")
        return report

    report.add("signing_trust", *honour(registry, rec.get("signing_key_id"), rec.get("payload_hash")))
    report.add("signature", *check_signature(rec, registry, rec.get("signing_key_id")))

    cstate, cdetail, terminal, rows, salt = check_chain(rec, run)
    report.terminal_hash_recomputed = terminal
    report.add("chain", cstate, cdetail)
    if cstate != "established":
        report.skipped(f"the chain was not established ({cdetail}), so nothing over the rows was computed")
        return report

    report.add("decisions", *check_decisions(rec, rows))
    report.add("profile", *check_profile(rec, rows))
    report.add("correctness", *check_correctness(rec, rows))
    report.add("retained", *check_retained(rec, run, rows, salt))

    report.add("replay", "n/a", "no decider code is supplied to this verifier (HANDOFF.md)")
    dreg = _load_registry(decider_registry) if decider_registry else None
    report.add("invocation", *check_invocation(rec, run, rows, registry, dreg))
    report.add("stream", *check_stream(rec, run, rows, prior))
    rstate, rdetail, refutes = check_receipts(rec, rows, registry, receipts)
    report.add("receipts", rstate, rdetail)
    if refutes:
        report.add("completeness", "failed", "a supplied receipt names a decision the record lacks")
    elif receipts is None:
        report.add("completeness", "n/a", "no receipt was supplied, so completeness is not claimed")
    else:
        report.add("completeness", "n/a", "never established; no supplied receipt refutes it (S11)")
    report.add("witness", *check_witness(rec, registry, witness, witness_registry))
    return report


def as_line(name: str, report: Report) -> dict:
    if getattr(report, "unreadable", False):
        return {"case": name, "payload_hash_recomputed": None, "terminal_hash_recomputed": None,
                "properties": {p: "unknown" for p in PROPERTIES}, "verdict": "UNREADABLE"}
    verdict, _exit = report.verdict()
    return {"case": name, "payload_hash_recomputed": report.payload_hash_recomputed,
            "terminal_hash_recomputed": report.terminal_hash_recomputed,
            "properties": {p: report.props.get(p, "unknown" if p in CORE else "n/a") for p in PROPERTIES},
            "verdict": verdict}


def run_corpus(corpus: Path, out: Path) -> int:
    manifest = json.loads((corpus / "manifest.json").read_text())
    lines = []
    for case in manifest["cases"]:
        name = case["name"]
        cfg = json.loads((corpus / "cases" / name / "case.json").read_text())
        opt = cfg.get("options") or {}

        def p(key, opt=opt):
            if key not in opt:
                return None
            v = opt[key]
            return [corpus / x for x in v] if isinstance(v, list) else corpus / v

        report = verify(
            corpus / "cases" / name / "run", corpus / opt["registry"],
            prior=p("prior"), receipts=p("receipts"), witness=p("witness"),
            witness_registry=p("witness_registry"), decider_registry=p("decider_registry"),
        )
        lines.append(as_line(name, report))
    out.write_text("\n".join(json.dumps(x, sort_keys=True) for x in lines) + "\n")
    return len(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run", nargs="?", help="a run directory")
    ap.add_argument("--registry")
    ap.add_argument("--prior")
    ap.add_argument("--receipts")
    ap.add_argument("--witness")
    ap.add_argument("--witness-registry")
    ap.add_argument("--decider-registry")
    ap.add_argument("--corpus", help="a conformance corpus directory; verify every case")
    ap.add_argument("--out", default="results.jsonl")
    ap.add_argument("--spec", default="SPEC.md")
    ap.add_argument("--assumptions", action="store_true", help="print the assumption ledger and exit")
    args = ap.parse_args(argv)

    if args.assumptions:
        print(json.dumps(ASSUMPTIONS, indent=1))
        return 0

    got = spec_digest(Path(args.spec))
    if got != MEASURED_AGAINST:
        print(
            f"{args.spec} is at {got[:16]} and this measurement was taken against "
            f"{MEASURED_AGAINST[:16]}.\n"
            "Refusing: re-running these rules against a changed specification is not a "
            "second measurement. The reader who wrote them had not seen the reference "
            "implementation, and has since. A new figure needs a new reader.\n"
            "The committed results.jsonl is the finding, dated to the digest above.",
            file=sys.stderr)
        return 5
    missing = audit_citations(Path(args.spec))
    if missing:
        print(f"citation audit FAILED: {len(missing)} rule(s) cite text not in {args.spec}: {missing}", file=sys.stderr)
        return 4
    print(f"citation audit: {len(CITES)} rules, every cited sentence found in {args.spec}", file=sys.stderr)
    print(f"assumptions the specification left open: {len(ASSUMPTIONS)} ({', '.join(a['id'] for a in ASSUMPTIONS)})", file=sys.stderr)

    if args.corpus:
        n = run_corpus(Path(args.corpus), Path(args.out))
        print(f"{n} cases verified -> {args.out}", file=sys.stderr)
        return 0
    if not args.run or not args.registry:
        ap.error("a run directory and --registry, or --corpus")
    report = verify(
        Path(args.run), Path(args.registry),
        prior=Path(args.prior) if args.prior else None,
        receipts=Path(args.receipts) if args.receipts else None,
        witness=Path(args.witness) if args.witness else None,
        witness_registry=Path(args.witness_registry) if args.witness_registry else None,
        decider_registry=Path(args.decider_registry) if args.decider_registry else None,
    )
    line = as_line(Path(args.run).name, report)
    for prop in PROPERTIES:
        print(f"  {prop:14} {line['properties'][prop]:12} {report.details.get(prop, '')}")
    print(f"\n{line['verdict']}")
    return 0 if line["verdict"] == "ESTABLISHED" else (3 if line["verdict"] == "UNREADABLE" else report.verdict()[1])


if __name__ == "__main__":
    raise SystemExit(main())
