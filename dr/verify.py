"""Verify a decision record. Three-valued, per property, nothing taken on trust.

    python3 -m dr.verify <run directory> --registry <registry.json> [--replay <module>] [--json]

Properties, each reported as established / unknown / failed, or n/a when the
record's profile has no such property:

    document      the record has the shape of its format_version and its payload_hash recomputes
    signing_trust the registry honours the named key for this record
    signature     the signature verifies over the payload with that key
    chain         the ledger re-derives from GENESIS to the signed terminal hash,
                  with the signed row count
    decisions     counts, policy digests and decider recompute from the rows
    profile       the declared profile is the one the rows' content supports
    correctness   (benchmark profile only) agree/disagree recompute from labels
    retained      every retained file is present with its digest; inputs.jsonl
                  matches the rows' input digests; policy.json matches the rows'
                  policy digest
    replay        (only when --replay is given) re-deciding the retained inputs
                  with the named decider reproduces every outcome and reason
    stream        (format_version 2) the record links to the prior record given
                  with --prior; n/a without a stream block
    completeness  never established: a self-signed record cannot bound what its
                  producer did not write (SPEC §13). n/a unless a receipt given
                  with --receipt names a decision the record lacks, which fails it
    receipts      (only when --receipt is given) each receipt's decision is in the
                  record with the receipted row hash
    witness       (only when --witness is given) a key in --witness-registry
                  countersigned this record's payload_hash
    invocation    (only when attestations.jsonl is retained) every row carries
                  the decider's own signature over that decision, under a key
                  in --decider-registry that is not a producer key; n/a when
                  no attestations are retained

Verdict: FAILED if any applicable property failed; NOT ESTABLISHED if none
failed and any is unknown; ESTABLISHED otherwise. Exit 2 / 1 / 0. Exit 3 when
the directory cannot be read at all.

Two rules this file is built around. Nothing is read from the record to decide
whether a check runs or what it found: the record supplies claims, the rows
supply facts, and a property is the comparison. And a check that could not be
performed is reported as unknown, with the reason, never as the record's
failure: a malformed registry entry or a row version this code does not read
is a statement about this verifier, not about the document.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import attest as attest_mod, derive, receipts as receipts_mod, witness as witness_mod
from .canonical import NotAnInput, NotCanonicalisable, canonical_input, digest_file, digest_obj, same_value
from .record import INPUTS_FILE, POLICY_FILE, UnknownFormatVersion, declared_format_version, record_defects
from .registry import RegistryUnreadable, load_registry, resolve
from .stream import link_check
from .rows import ROW_VERSION_KEYED, RowError, UnknownRowVersion, keyed_input_digest, load_rows, verify_chain
from .signing import SignatureCheckRaised, payload_hash, verify_signature
from .assurance import assess, render_text
from .canonical import read_jsonl, loads as strict_loads

ESTABLISHED, NOT_ESTABLISHED, FAILED, UNREADABLE = 0, 1, 2, 3

# The properties every verification of every record decides. A report that does
# not carry one of these has not judged it, and a property nobody judged is not
# a property that holds: the verdict treats an absent core property as unknown
# rather than letting it drop out of the set it is computed over. Without this
# the verdict is a statement about the checks that ran and is read as a
# statement about the checks there are. The conditional properties (replay,
# stream, receipts, witness, invocation, completeness) are absent legitimately
# and are not listed.
CORE_PROPERTIES = (
    "document", "signing_trust", "signature", "chain",
    "decisions", "profile", "correctness", "retained",
)
RECORD_FILE = "record.json"

# What a supplied file that cannot be read, or is valid JSON of the wrong shape,
# raises while a check reads it: I/O (OSError); decoding, parsing and canonical
# form (ValueError: JSONDecodeError, NotJSON, UnicodeDecodeError,
# NotCanonicalisable, RowError); a missing member or a value of the wrong kind
# (KeyError, TypeError, AttributeError, IndexError); an unreadable registry; and
# key material the signature library will not parse. A check that catches these
# reports the file's state. Anything else is the verifier's own fault: it
# reaches the command's guard and exits 3, never a property's state.
SUPPLIED_FILE_FAULTS = (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError,
                        RegistryUnreadable, SignatureCheckRaised)


class Report:
    def __init__(self) -> None:
        self.properties: List[Dict[str, Any]] = []
        self.notes: List[str] = []

    def add(self, name: str, state: str, detail: str) -> None:
        assert state in ("established", "unknown", "failed", "n/a"), state
        self.properties.append({"property": name, "state": state, "detail": detail})

    def state(self, name: str) -> Optional[str]:
        for p in self.properties:
            if p["property"] == name:
                return p["state"]
        return None

    def missing_core(self) -> List[str]:
        """Core properties this report never judged. Absence is not agreement."""
        present = {p["property"] for p in self.properties}
        return [n for n in CORE_PROPERTIES if n not in present]

    @property
    def verdict(self) -> int:
        states = {p["state"] for p in self.properties}
        if "failed" in states:
            return FAILED
        if "unknown" in states or self.missing_core():
            return NOT_ESTABLISHED
        return ESTABLISHED

    def all_properties(self) -> List[Dict[str, Any]]:
        """The properties as the report states them, the core ones never judged included as unknown."""
        return self.properties + [
            {"property": n, "state": "unknown", "detail": "not judged: this verification never decided it"}
            for n in self.missing_core()
        ]

    def to_text(self, directory: Path, assurance: bool = False) -> str:
        label = {0: "ESTABLISHED", 1: "NOT ESTABLISHED", 2: "FAILED"}[self.verdict]
        width = max(len(p["property"]) for p in self.properties)
        mark = {"established": "OK     ", "unknown": "UNKNOWN", "failed": "FAILED ", "n/a": "n/a    "}
        lines = [str(directory), ""]
        for p in self.properties:
            lines.append(f"  {mark[p['state']]} {p['property']:<{width}}  {p['detail']}")
        for n in self.missing_core():
            lines.append(f"  {mark['unknown']} {n:<{width}}  not judged: this verification never decided it")
        for n in self.notes:
            lines.append(f"  note: {n}")
        lines += ["", f"VERDICT: {label}"]
        if self.verdict == NOT_ESTABLISHED:
            lines.append("Nothing failed. At least one property could not be established, and an unestablished property is not one that holds.")
        if assurance:  # after the table and the verdict, never in place of them (dr/assurance.py)
            lines += [""] + render_text(assess(self.all_properties()))
        return "\n".join(lines)

    def to_json(self, directory: Path, assurance: bool = False) -> str:
        out = {
            "run_directory": str(directory),
            "verdict": {0: "ESTABLISHED", 1: "NOT ESTABLISHED", 2: "FAILED"}[self.verdict],
            "exit_code": self.verdict,
            "properties": self.all_properties(),
            "notes": self.notes,
        }
        if assurance:  # beside the properties it is computed from, and carrying them (dr/assurance.py)
            out["assurance"] = assess(out["properties"])
        return json.dumps(out, indent=2, sort_keys=True)


def _not_judged(report: "Report", why: str) -> None:
    """Record the core properties a bail-out never reached, rather than omitting them."""
    for name in report.missing_core():
        report.add(name, "unknown", f"not judged: {why}")


def _load_json(path: Path) -> Any:
    return strict_loads(path.read_text(encoding="utf-8"))


def verify_directory(
    directory: Path,
    registry_path: Path,
    *,
    replay_module: Optional[str] = None,
    prior_record: Optional[Path] = None,
    receipt_paths: Optional[List[Path]] = None,
    witness_statement: Optional[Path] = None,
    witness_registry: Optional[Path] = None,
    decider_registry: Optional[Path] = None,
    conformance_evidence: Optional[List[Path]] = None,
) -> Report:
    report = Report()
    registry: Optional[Dict[str, Any]] = None
    directory = Path(directory)
    record_path = directory / RECORD_FILE
    record = _load_json(record_path)
    if not isinstance(record, dict):
        raise ValueError("record.json is not an object")

    # --- document ---------------------------------------------------------
    try:
        declared_format_version(record)
    except UnknownFormatVersion as exc:
        report.add("document", "unknown", str(exc))
        for name in (n for n in CORE_PROPERTIES if n != "document"):
            report.add(name, "unknown", "not judged: the record's format version is not one this verifier reads")
        return report
    except ValueError as exc:
        report.add("document", "failed", str(exc))
        _not_judged(report, "the record's document property failed, so nothing further was checked")
        return report
    defects = record_defects(record)
    if defects:
        report.add("document", "failed", "the record is not a v1 record: " + "; ".join(defects))
        _not_judged(report, "the record's document property failed, so nothing further was checked")
        return report
    if record["payload_hash"] != payload_hash(record):
        report.add("document", "failed", "payload_hash does not recompute from the record's own fields")
        return report
    report.add("document", "established", f"format_version {record['format_version']} shape, and payload_hash recomputes from the canonical payload")

    # --- signing trust and signature ---------------------------------------
    pem: Optional[str] = None
    try:
        registry = load_registry(registry_path)
        state, detail, pem = resolve(registry, record["signing_key_id"], record["payload_hash"])
        report.add("signing_trust", {"honoured": "established", "failed": "failed", "unknown": "unknown"}[state], detail)
    except RegistryUnreadable as exc:
        report.add("signing_trust", "unknown", f"the registry could not be read, so nothing about trust can be decided: {exc}")
    if pem is None:
        report.add("signature", "unknown", "no honoured key to verify with, so the signature was not checked")
    else:
        try:
            ok, detail = verify_signature(record, pem)
            report.add("signature", "established" if ok else "failed", detail)
        except SignatureCheckRaised as exc:
            report.add("signature", "unknown", f"the signature check could not be performed: {exc}")

    # --- chain -------------------------------------------------------------
    rows: Optional[List[Dict[str, Any]]] = None
    ledger_path = directory / record["ledger"]["path"]
    if not ledger_path.is_file():
        report.add("chain", "failed", f"the record names ledger {record['ledger']['path']!r} and it is not in this directory")
    else:
        try:
            loaded = load_rows(ledger_path)
            terminal = verify_chain(loaded)
            if terminal != record["ledger"]["terminal_hash"]:
                report.add("chain", "failed", f"the chain re-derives to {terminal} and the record signs {record['ledger']['terminal_hash']}")
            elif len(loaded) != record["ledger"]["row_count"]:
                report.add("chain", "failed", f"the ledger has {len(loaded)} rows and the record signs {record['ledger']['row_count']}")
            else:
                rows = loaded
                report.add("chain", "established", f"{len(rows)} rows re-derive from GENESIS to the signed terminal hash")
        except UnknownRowVersion as exc:
            report.add("chain", "unknown", str(exc))
        except RowError as exc:
            report.add("chain", "failed", str(exc))

    if rows is None:
        # The chain's own state already decides the verdict. Everything computed
        # from rows is unknown, not failed: it was never computed.
        why = "not computed: the rows were not established"
        for name in ("decisions", "profile", "correctness", "retained", "replay", "invocation", "stream", "completeness", "receipts", "witness"):
            report.add(name, "unknown", why)
        return report

    # --- decisions ---------------------------------------------------------
    derived = derive.derive_all(rows)
    problems: List[str] = []
    if derived["counts"] != record["counts"]:
        problems.append(f"counts: record {record['counts']} rows {derived['counts']}")
    if derived["policy_digests"] != record["policy_digests"]:
        problems.append(f"policy_digests: record {record['policy_digests']} rows {derived['policy_digests']}")
    expected_decider = f"{record['decider']['id']}@{record['decider']['version']}"
    if derived["deciders"] != [expected_decider]:
        problems.append(f"decider: record {expected_decider!r} rows {derived['deciders']}")
    undeclared = sorted(set(derived["counts"]["by_outcome"]) - set(record["decider"]["outcomes"]))
    if undeclared:
        problems.append(f"outcomes not in the decider's declared vocabulary: {undeclared}")
    if problems:
        report.add("decisions", "failed", "; ".join(problems))
    else:
        report.add("decisions", "established", f"{derived['counts']['decisions']} rows written, by outcome {derived['counts']['by_outcome']}, one decider, {len(derived['policy_digests'])} policy; a count of what the producer wrote, not of what happened")

    # --- profile -----------------------------------------------------------
    supported = derived["supported_profile"]
    if supported is None:
        report.add("profile", "failed", f"{derive.labelled_count(rows)} of {len(rows)} rows are labelled; a ledger supports a profile only when all or none are")
    elif supported != record["profile"]:
        report.add("profile", "failed", f"the record declares {record['profile']!r} and the rows support {supported!r}")
    else:
        report.add("profile", "established", f"the rows support the declared profile {supported!r}")

    # --- correctness -------------------------------------------------------
    if record["profile"] == derive.PROFILE_BENCHMARK and supported == derive.PROFILE_BENCHMARK:
        if derived.get("benchmark") == record.get("benchmark"):
            b = derived["benchmark"]
            report.add("correctness", "established", f"{b['agree']} of {b['labelled']} decisions agree with their labels; recomputed from the rows")
        else:
            report.add("correctness", "failed", f"record {record.get('benchmark')} rows {derived.get('benchmark')}")
    elif record["profile"] == derive.PROFILE_BENCHMARK:
        report.add("correctness", "failed", "the record claims correctness figures over rows that do not all carry labels")
    elif supported == derive.PROFILE_BENCHMARK:
        # The content supports a correctness property and the record declined
        # to carry it. A declared profile is never a licence to skip a check
        # the rows allow, so this is a failure of the record, not an absence.
        report.add("correctness", "failed", "every row carries a label, so correctness is computable, and the record declares a profile that omits it")
    else:
        report.add("correctness", "n/a", "the production profile carries no correctness property: the rows have no labels and the record claims none")

    # --- retained files ----------------------------------------------------
    retained = record["retained"]
    if not retained:
        report.add("retained", "n/a", "no retained files are named by the record")
    else:
        issues: List[str] = []
        absent: List[str] = []
        for name, digest in retained.items():
            p = directory / name
            if not p.is_file():
                # The record names it and this copy lacks it. The digest check
                # could not run, so this is unknown, not failed: a producer may
                # hand the same signed record to a reader without the file
                # (selective disclosure), and the reader must see that
                # custody of that file is not established, not that the
                # record lied. A file that is present and differs is a failure.
                absent.append(name)
                continue
            actual = digest_file(p)
            if actual != digest:
                issues.append(f"{name}: digest {actual} differs from the recorded {digest}")
        # Reading a file is in the catch; hashing what was read is not. The
        # file's shape raises inside the read, and a parsed JSON value that
        # has no canonical form raises NotCanonicalisable, named below. Any
        # other exception from the hash is the verifier's own, and reaches the
        # command's guard rather than this property's state.
        if POLICY_FILE in retained and POLICY_FILE not in absent and not any(i.startswith(POLICY_FILE) for i in issues):
            try:
                pol = _load_json(directory / POLICY_FILE)
            except SUPPLIED_FILE_FAULTS as exc:
                issues.append(f"{POLICY_FILE}: not readable as JSON: {exc}")
            else:
                try:
                    pol_digest = digest_obj(pol)
                except NotCanonicalisable as exc:
                    issues.append(f"{POLICY_FILE}: has no canonical form: {exc}")
                else:
                    if len(record["policy_digests"]) == 1 and pol_digest != record["policy_digests"][0]:
                        issues.append(f"{POLICY_FILE}: its canonical digest is not the policy digest the rows carry")
        if INPUTS_FILE in retained and INPUTS_FILE not in absent and not any(i.startswith(INPUTS_FILE) for i in issues):
            try:
                lines, salt = _read_inputs(directory, rows)
            except SUPPLIED_FILE_FAULTS as exc:
                issues.append(f"{INPUTS_FILE}: not readable: {exc}")
            else:
                if len(lines) != len(rows):
                    issues.append(f"{INPUTS_FILE}: {len(lines)} inputs for {len(rows)} rows")
                else:
                    for row, item in zip(rows, lines):
                        if not isinstance(item, dict) or item.get("seq") != row["seq"]:
                            issues.append(f"{INPUTS_FILE}: entry for seq {row['seq']} does not hash to the row's input_digest")
                            break
                        try:
                            expected = keyed_input_digest(salt, item.get("input")) if salt is not None else digest_obj(item.get("input"))
                        except NotCanonicalisable as exc:
                            issues.append(f"{INPUTS_FILE}: entry for seq {row['seq']} has no canonical form: {exc}")
                            break
                        if expected != row["input_digest"]:
                            issues.append(f"{INPUTS_FILE}: entry for seq {row['seq']} does not hash to the row's input_digest")
                            break
        if issues:
            report.add("retained", "failed", "; ".join(issues) + (f"; not present in this copy: {absent}" if absent else ""))
        elif absent:
            report.add("retained", "unknown", f"named by the record and not present in this copy, so their digests could not be checked: {absent}; the other {len(retained) - len(absent)} retained file(s) match")
        else:
            report.add("retained", "established", f"{len(retained)} retained file(s) present with their digests" + (", inputs match the rows" if INPUTS_FILE in retained else "") + (", policy matches the rows" if POLICY_FILE in retained else ""))
    unnamed = sorted(p.name for p in directory.iterdir() if p.is_file() and p.name not in retained and p.name not in (RECORD_FILE, record["ledger"]["path"]))
    if unnamed:
        report.notes.append(f"files in the directory the record does not name, and says nothing about: {unnamed}")

    # --- replay ------------------------------------------------------------
    if replay_module:
        _replay(report, directory, record, rows, replay_module, conformance_evidence or [])
    else:
        report.add("replay", "n/a", "not requested; pass --replay <decider module> to re-decide the retained inputs")

    # --- invocation ----------------------------------------------------------
    _invocation(report, directory, record, rows, registry, decider_registry)

    # --- stream ------------------------------------------------------------
    stream = record.get("stream")
    if stream is None:
        report.add("stream", "n/a", "the record is not part of a stream")
    elif stream["seq"] == 1:
        report.add("stream", "established", f"first record of stream {stream['stream_id']!r}; nothing prior to link to")
    elif prior_record is None:
        report.add("stream", "unknown", f"the record claims to follow seq {stream['seq'] - 1} of stream {stream['stream_id']!r} (prev_record_hash {stream['prev_record_hash'][:23]}...); pass --prior to check the link")
    else:
        # Three outcomes kept apart: the prior could not be read (about the file
        # supplied), the check could not run (about the verifier), and the link
        # does not hold (about the record). Only the last is the record's failure.
        state, reasons = "unknown", []
        try:
            prior = _load_json(prior_record)
        except (OSError, ValueError) as exc:  # NotJSON is a ValueError
            reasons = [f"the prior record supplied could not be read: {exc}"]
        else:
            try:
                state, reasons = link_check(record, prior)
            except SUPPLIED_FILE_FAULTS as exc:  # the prior's or the record's shape; anything else is the verifier's and propagates
                state, reasons = "unknown", [f"the prior supplied could not be checked against: {type(exc).__name__}: {exc}"]
        if state == "failed":
            report.add("stream", "failed", "; ".join(reasons))
        elif state == "unknown":
            report.add("stream", "unknown", "; ".join(reasons))
        else:
            note = ("; " + "; ".join(reasons)) if reasons else ""
            state, detail = _prior_row_references(rows, prior, Path(prior_record))
            if state == "failed":
                report.add("stream", "failed", detail)
            elif state == "unknown":
                report.add("stream", "unknown", detail)
            else:
                report.add("stream", "established", f"follows seq {stream['seq'] - 1} of stream {stream['stream_id']!r}: prev_record_hash, seq and decision numbering all continue from the prior{detail}{note}; nothing here says whether a record after seq {stream['seq']} exists")

    # --- completeness and receipts ------------------------------------------
    _completeness(report, record, rows, registry, receipt_paths or [])

    # --- witness -----------------------------------------------------------
    if witness_statement is None:
        report.add("witness", "n/a", "no witness statement supplied; a record witnesses nothing about itself")
    else:
        try:
            statement = _load_json(witness_statement)
            wreg = load_registry(witness_registry) if witness_registry else None
            if wreg is None:
                report.add("witness", "unknown", "a witness statement was supplied without --witness-registry, so the witness key cannot be resolved")
            elif registry is None:
                report.add("witness", "unknown", "the producer registry could not be read, so a witness key cannot be told apart from a producer key")
            else:
                state, detail = witness_mod.check(statement, record, wreg, registry)
                report.add("witness", state, detail)
        except RegistryUnreadable as exc:
            report.add("witness", "unknown", f"the witness registry could not be read: {exc}")
        except SUPPLIED_FILE_FAULTS as exc:
            report.add("witness", "unknown", f"the witness statement could not be read: {exc}")
    return report


def _prior_row_references(rows, prior, prior_path: Path):
    """Rows of a stream record may name rows of the prior record by hash (`ext.prior_row`, SPEC §12).

    Returns (state, detail). Established with an empty detail when no row
    names one; established with a clause when every named hash is a row of
    the prior's ledger and that ledger re-derives to what the prior signs;
    unknown when rows name prior rows and the prior's ledger is not beside
    its record; failed when a named hash is not a row of the prior, or the
    prior's ledger does not re-derive to the prior's signed terminal hash.
    """
    if not rows:
        return "established", ""
    named = [(r["seq"], r["ext"]["prior_row"]) for r in rows if isinstance(r.get("ext"), dict) and "prior_row" in r["ext"]]
    if not named:
        return "established", ""
    bad_shape = [seq for seq, h in named if not isinstance(h, str)]
    if bad_shape:
        return "failed", f"rows {bad_shape} carry ext.prior_row that is not a string"
    ledger_path = prior_path.parent / prior["ledger"]["path"]
    if not ledger_path.exists():
        return "unknown", f"{len(named)} row(s) name rows of the prior by hash; the prior's ledger ({prior['ledger']['path']}) is not beside its record, so they cannot be checked"
    try:
        prior_rows = load_rows(ledger_path)
        terminal = verify_chain(prior_rows)
    except (RowError, UnknownRowVersion) as exc:
        return "failed", f"{len(named)} row(s) name rows of the prior by hash, and the prior's ledger does not re-derive: {exc}"
    if terminal != prior["ledger"]["terminal_hash"] or len(prior_rows) != prior["ledger"]["row_count"]:
        return "failed", f"{len(named)} row(s) name rows of the prior by hash, and the prior's ledger re-derives to a terminal hash the prior does not sign"
    present = {r["row_hash"] for r in prior_rows}
    missing = [seq for seq, h in named if h not in present]
    if missing:
        return "failed", f"rows {missing} name rows the prior's ledger does not have"
    return "established", f"; {len(named)} row(s) name rows of the prior by hash, every one a row the prior signs"


def _completeness(report: Report, record: Dict[str, Any], rows: List[Dict[str, Any]], registry: Optional[Dict[str, Any]], receipt_paths: List[Path]) -> None:
    """Completeness is never established. It is n/a (not claimed) or failed (refuted)."""
    not_claimed = (
        f"not claimed and not establishable: the {len(rows)} rows are what the producer wrote, and nothing in a "
        "self-signed record bounds what it did not write. A receipt (--receipt) for a decision the record lacks refutes it"
    )
    if not receipt_paths:
        report.add("completeness", "n/a", not_claimed)
        report.add("receipts", "n/a", "no receipts supplied")
        return
    if registry is None:
        report.add("completeness", "n/a", not_claimed)
        report.add("receipts", "unknown", "receipts were supplied and the registry could not be read, so their signatures cannot be checked")
        return
    outcomes: Dict[str, List[str]] = {}
    for path in receipt_paths:
        try:
            receipt = _load_json(path)
            state, detail = receipts_mod.check(receipt, record, rows, registry)
        except SUPPLIED_FILE_FAULTS as exc:
            state, detail = "unknown", f"{path}: could not be read: {exc}"
        outcomes.setdefault(state, []).append(f"{Path(path).name}: {detail}")
    missing = outcomes.get("missing", [])
    altered = outcomes.get("altered", [])
    invalid = outcomes.get("invalid", [])
    unknown = outcomes.get("unknown", [])
    included = outcomes.get("included", [])
    foreign = outcomes.get("foreign", [])
    if missing:
        highest = max(int(m.split("decision seq ")[1].split(" ")[0]) for m in missing)
        report.add("completeness", "failed", f"refuted: the producer signed a receipt for decision seq {highest} of this run and the record has {len(rows)} rows, so at least {highest - len(rows)} acknowledged decision(s) are not in it")
    else:
        report.add("completeness", "n/a", not_claimed + f"; {len(receipt_paths)} receipt(s) checked, {len(included)} matched a row, none pointed past the ledger")
    if missing or altered or invalid:
        report.add("receipts", "failed", "; ".join(missing + altered + invalid))
    elif unknown:
        report.add("receipts", "unknown", "; ".join(unknown))
    elif included:
        report.add("receipts", "established", f"{len(included)} receipt(s) name decisions that are in the record unchanged" + (f"; {len(foreign)} receipt(s) were for other runs and were ignored" if foreign else ""))
    else:
        report.add("receipts", "unknown", f"{len(foreign)} receipt(s) supplied and none was for this run")


def _invocation(report: Report, directory: Path, record: Dict[str, Any], rows: List[Dict[str, Any]], registry: Optional[Dict[str, Any]], decider_registry: Optional[Path]) -> None:
    """Did the named decider decide these rows? Established only by the decider's own signatures (dr.attest)."""
    if attest_mod.ATTESTATIONS_FILE not in record["retained"]:
        report.add("invocation", "n/a", "not claimed: no decider attestations are retained, so the rows are the producer's word on what the decider said; replay checks the words, not that the decider was called")
        return
    if report.state("retained") != "established":
        report.add("invocation", "unknown", f"attestations are retained and retained is {report.state('retained')} in this copy, so they cannot be read as what was signed")
        return
    if decider_registry is None:
        report.add("invocation", "unknown", "attestations are retained and no --decider-registry was given, so the decider's key cannot be resolved")
        return
    try:
        dreg = load_registry(decider_registry)
        attestations = attest_mod.load(directory / attest_mod.ATTESTATIONS_FILE)
    except SUPPLIED_FILE_FAULTS as exc:
        report.add("invocation", "unknown", f"the attestations or the decider registry could not be read: {exc}")
        return
    state, detail = attest_mod.check(attestations, record, rows, dreg, registry)
    report.add("invocation", state, detail)


def _read_inputs(directory: Path, rows: List[Dict[str, Any]]):
    """The retained inputs and, for keyed (v2) rows, the salt from the file's first line.

    A v2 ledger's inputs file must start with {"salt": hex}; a v1 ledger's must
    not. Either mismatch is reported as an unreadable inputs file.
    """
    lines = [strict_loads(l) for _, l in read_jsonl(directory / INPUTS_FILE)]
    keyed = bool(rows) and rows[0].get("v") == ROW_VERSION_KEYED
    salt = None
    if keyed:
        if not lines or set(lines[0]) != {"salt"}:
            raise ValueError("v2 rows need a salt line first in inputs.jsonl")
        salt = bytes.fromhex(lines[0]["salt"])
        lines = lines[1:]
    elif lines and set(lines[0]) == {"salt"}:
        raise ValueError("a salt line is present but the rows are not keyed (v1)")
    return lines, salt


def _established_version(record: Dict[str, Any], ident: str, evidence_paths: List[Path]) -> Tuple[bool, str]:
    """Is `ident` a version the record names as established by a conformance run? Returns (accepted, what to say).

    The naming is the producer's claim, like the record's own version. With
    the run's result supplied (--conformance-evidence), its digest must be the
    one the record names and it must report agreement on every request it did
    not exclude: a result may carry `excluded`, a list of named cases with a
    stated reason each (a corpus case the engine's invocation path cannot
    reproduce, for instance), and the exclusions are inside the digested
    result, so the name commits to them and the detail prints them. A result
    that does not support the name refuses the replay.
    """
    dec = record["decider"]
    for e in dec.get("established_versions") or []:
        if f"{dec['id']}@{e['version']}" != ident:
            continue
        for path in evidence_paths:
            try:
                run = strict_loads(path.read_text(encoding="utf-8"))
                body = run.get("full_corpus", run)
                got = digest_obj(body)
            except (OSError, ValueError, TypeError):
                continue
            if got != e["evidence"]:
                continue
            agree, total = body.get("agree_decision_reason_and_error_presence"), body.get("requests")
            excluded = body.get("excluded") or []
            well_formed = isinstance(excluded, list) and all(isinstance(x, dict) and isinstance(x.get("reason"), str) and x["reason"] for x in excluded)
            if isinstance(agree, int) and isinstance(total, int) and total > 0 and well_formed and agree == total - len(excluded) and body.get("engine") == e["version"]:
                exc = f", {len(excluded)} excluded and named: " + "; ".join(sorted({x['reason'] for x in excluded})) if excluded else ""
                return True, f"under {ident}, which the record names as established by a conformance run ({agree} of {total}{exc}; {path.name}, digest matches)"
            return False, f"{ident} is named as established by {e['evidence']}, and that result reports {agree} of {total} with {len(excluded) if well_formed else 'malformed'} excluded for engine {body.get('engine')!r}; the name is not supported"
        return True, f"under {ident}, which the record names as established by a conformance run (evidence {e['evidence'][:19]}…, not supplied; the producer's claim)"
    return False, ""


def _replay(report: Report, directory: Path, record: Dict[str, Any], rows: List[Dict[str, Any]], module_name: str, evidence_paths: List[Path]) -> None:
    if INPUTS_FILE not in record["retained"] or POLICY_FILE not in record["retained"]:
        report.add("replay", "unknown", f"replay needs {INPUTS_FILE} and {POLICY_FILE} retained; this record does not name them")
        return
    if report.state("retained") != "established":
        report.add("replay", "unknown", f"replay needs {INPUTS_FILE} and {POLICY_FILE} established, and retained is {report.state('retained')} in this copy")
        return
    try:
        mod = importlib.import_module(module_name)
        ident = f"{mod.DECIDER_ID}@{mod.DECIDER_VERSION}"
    except Exception as exc:
        report.add("replay", "unknown", f"the decider module could not be loaded: {exc}")
        return
    expected = f"{record['decider']['id']}@{record['decider']['version']}"
    how = ""
    if ident != expected:
        accepted, how = _established_version(record, ident, evidence_paths)
        if not accepted:
            report.add("replay", "unknown", how or f"the supplied decider is {ident}, the record names {expected}; replaying with a different procedure proves nothing")
            return
        how = "; " + how
    policy = _load_json(directory / POLICY_FILE)
    inputs = [item["input"] for item in _read_inputs(directory, rows)[0]]
    try:
        decider = mod.Decider(policy)
        for row, item in zip(rows, inputs):
            # Replay decides the value the row's digest covers, not the retained
            # bytes' own reading of it: two inputs with one digest are one input
            # (SPEC §2), so a retained 396.0 is re-decided as 396.
            try:
                value = canonical_input(item)
            except NotAnInput as exc:
                report.add("replay", "failed", f"seq {row['seq']}: the retained input has no canonical value, so no gate decides it: {exc}")
                return
            outcome, reason, _ext = decider.decide(value)
            if (outcome, reason) != (row["outcome"], row["reason"]):
                form = "" if same_value(value, item) else "; the retained input is not in canonical form, and replay decided the value its digest covers"
                report.add("replay", "failed", f"seq {row['seq']}: replay gives ({outcome!r}, {reason!r}), the row records ({row['outcome']!r}, {row['reason']!r}){form}")
                return
    except Exception as exc:
        report.add("replay", "unknown", f"the decider raised while replaying, so replay could not be completed: {exc}")
        return
    report.add("replay", "established", f"re-deciding all {len(rows)} retained inputs with {ident} reproduced every outcome and reason{how}")


def main(argv: Optional[List[str]] = None) -> int:
    """The whole command, rendering and output included, under one guard: a
    fault in the verifier anywhere exits 3, never a verdict's code."""
    try:
        return _main(argv)
    except Exception as exc:  # noqa: BLE001 — a fault in the verifier must not exit with a verdict's code
        print(f"VERIFIER ERROR: {type(exc).__name__}: {exc} -- a fault in the verifier, not a verdict about the record; nothing was judged", file=sys.stderr)
        return UNREADABLE


class _Parser(argparse.ArgumentParser):
    """argparse exits 2 on a usage error, which is FAILED's code. A command
    line the verifier could not read judged nothing, so it exits 3."""

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message} -- nothing was judged", file=sys.stderr)
        raise SystemExit(UNREADABLE)


def _main(argv: Optional[List[str]] = None) -> int:
    ap = _Parser(description="Verify a decision record directory.")
    ap.add_argument("run_directory")
    ap.add_argument("--registry", required=True, help="key registry JSON")
    ap.add_argument("--replay", default=None, help="importable decider module to re-decide retained inputs")
    ap.add_argument("--prior", default=None, help="the previous record.json in this record's stream")
    ap.add_argument("--receipt", action="append", default=[], help="a decision receipt to check against the record; repeatable")
    ap.add_argument("--witness", default=None, help="a witness statement over this record")
    ap.add_argument("--witness-registry", default=None, help="key registry of witnesses")
    ap.add_argument("--decider-registry", default=None, help="key registry of the decider, for the invocation property (decider attestations, SPEC §15)")
    ap.add_argument("--conformance-evidence", action="append", default=[], help="a conformance run's result JSON, to check a decider version the record names as established (SPEC §8); repeatable")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--assurance", action="store_true", help="also state the assurance level the properties reach (A0-A4), after the table (SPEC §9.1)")
    args = ap.parse_args(argv)
    directory = Path(args.run_directory)
    if not directory.is_dir() or not (directory / RECORD_FILE).is_file():
        print(f"ERROR: {directory} is not a run directory with a {RECORD_FILE}", file=sys.stderr)
        return UNREADABLE
    try:
        report = verify_directory(
            directory,
            Path(args.registry),
            replay_module=args.replay,
            prior_record=Path(args.prior) if args.prior else None,
            receipt_paths=[Path(p) for p in args.receipt],
            witness_statement=Path(args.witness) if args.witness else None,
            witness_registry=Path(args.witness_registry) if args.witness_registry else None,
            decider_registry=Path(args.decider_registry) if args.decider_registry else None,
            conformance_evidence=[Path(p) for p in args.conformance_evidence],
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: could not read the run directory: {exc}", file=sys.stderr)
        return UNREADABLE
    print(report.to_json(directory, assurance=args.assurance) if args.json else report.to_text(directory, assurance=args.assurance))
    return report.verdict


if __name__ == "__main__":
    raise SystemExit(main())
