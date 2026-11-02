"""The reference verifier plus one property, `arrival`, without changing `dr/`.

    python3 tools/verify_arrival.py <run> --registry R.json \
        --attester-registry A.json [--decider-registry D.json] [--arrival-log L.jsonl] [--json]

Two properties. `arrival` reads like `invocation` (SPEC §15):

  n/a         no arrivals are retained and none were supplied: not claimed.
  unknown     arrivals are retained but `retained` is not established in this
              copy; no attester registry was given; a keyed row's plain digest
              cannot be recomputed; or the attester key is a producer or
              decider key.
  failed      a row names no arrival, two rows name one, a named arrival is
              absent, a retained input is not what arrived, or a signature does
              not verify.
  established every row names an arrival that an honoured attester key, held
              by neither the producer nor the decider, signed over that row's
              input.

`arrivals_accounted` judges the range the rows name: every arrival the
attester logged between the first and last named has a row, or the record
omitted a decision the attester can show it received. Established only from
the attester's own copy; unknown from the record's; failed from either when
an arrival in the range has no row. `--prior-run` extends the range back to the
prior record's last arrival, closing the seam of a stream.

An arrival log supplied from outside (`--arrival-log`, the attester's own copy)
is checked instead of the retained one when the record retains none, and must
be the same bytes when both exist: the attester's copy and the producer's copy
disagreeing is a failure, not a choice between them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tools.arrive as arrive  # noqa: E402
from dr.registry import load_registry  # noqa: E402
from dr.rows import load_rows  # noqa: E402
from dr.verify import RECORD_FILE, SUPPLIED_FILE_FAULTS, Report, verify_directory  # noqa: E402
from dr.assurance import assess  # noqa: E402
from dr.canonical import loads as strict_loads


def _digest(p: Path) -> str:
    return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()


def _policy_requires_arrival(directory: Path, record: Dict[str, Any]):
    """(required, rows naming no arrival) read from the retained policy, if any."""
    try:
        policy = strict_loads((directory / "policy.json").read_text(encoding="utf-8"))
        if not (isinstance(policy, dict) and policy.get("arrival") == "required"):
            return False, []
        rows = load_rows(directory / record["ledger"]["path"])
    except Exception:  # noqa: BLE001  — no retained policy, or unreadable: nothing to contradict
        return False, []
    unnamed = [r["seq"] for r in rows if not (isinstance(r.get("ext"), dict) and isinstance(r["ext"].get(arrive.EXT_KEY), int))]
    return True, unnamed


def add_arrival(report: Report, directory: Path, *, registry: Optional[Path], attester_registry: Optional[Path],
                decider_registry: Optional[Path], arrival_log: Optional[Path], prior: Optional[Path] = None) -> None:
    record = strict_loads((directory / RECORD_FILE).read_text(encoding="utf-8"))
    retained = record.get("retained", {}) if isinstance(record, dict) else {}
    in_record = arrive.ARRIVALS_FILE in retained
    # A policy that requires an arrival for every input (section 16.8) is under the
    # policy digest, so a row under it that names no arrival contradicts the record
    # itself, whether or not any arrival file is in hand.
    required, unnamed = _policy_requires_arrival(directory, record)
    if required and unnamed:
        report.add("arrival", "failed", f"the policy requires an arrival for every input and {len(unnamed)} row(s) name none (seq {unnamed[:6]}{'…' if len(unnamed) > 6 else ''}): the gate under this policy decides nothing without one, so these rows were not written by it")
        report.add("arrivals_accounted", "unknown", "arrival is failed, so the range the rows name cannot be trusted")
        return
    if not in_record and arrival_log is None:
        report.add("arrival", "n/a", "not claimed: no input arrivals are retained and none were supplied, so the retained inputs are the producer's word on what arrived" + (" (the policy requires one per input, and every row names one)" if required else ""))
        report.add("arrivals_accounted", "n/a", "no arrivals, so nothing to account for")
        return
    if in_record and report.state("retained") != "established":
        report.add("arrival", "unknown", f"arrivals are retained and retained is {report.state('retained')} in this copy, so they cannot be read as what was signed")
        return
    source = directory / arrive.ARRIVALS_FILE if in_record else arrival_log
    if in_record and arrival_log is not None and _digest(arrival_log) != retained[arrive.ARRIVALS_FILE]:
        report.add("arrival", "failed", "the attester's copy of the log and the copy the record retains are different bytes")
        return
    if attester_registry is None:
        report.add("arrival", "unknown", "arrivals are present and no --attester-registry was given, so the attester's key cannot be resolved")
        return
    try:
        arrivals = arrive.load(source)
        rows = load_rows(directory / record["ledger"]["path"])
        areg = load_registry(attester_registry)
        preg = load_registry(registry) if registry else None
        dreg = load_registry(decider_registry) if decider_registry else None
    except SUPPLIED_FILE_FAULTS as exc:  # anything else is the verifier's own fault, and reaches the guard
        report.add("arrival", "unknown", f"the arrivals, rows or a registry could not be read: {exc}")
        return
    state, detail = arrive.check(arrivals, rows, directory, areg, preg, dreg)
    if arrival_log is not None and not in_record:
        detail += " (from the attester's own log, not the record)"
    report.add("arrival", state, detail)
    # arrivals_accounted: only meaningful once every row's arrival is established.
    if state != "established":
        report.add("arrivals_accounted", "unknown", f"arrival is {state}, so the range the rows name cannot be trusted")
        return
    prior_rows = None
    if prior is not None:
        try:
            prior_record = strict_loads((prior / RECORD_FILE).read_text(encoding="utf-8"))
            prior_rows = load_rows(prior / prior_record["ledger"]["path"])
        except SUPPLIED_FILE_FAULTS as exc:
            report.add("arrivals_accounted", "unknown", f"the prior record could not be read: {exc}")
            return
    a_state, a_detail, rng = arrive.accounted(arrivals, rows, from_attester=arrival_log is not None, prior_rows=prior_rows)
    report.add("arrivals_accounted", a_state, a_detail)
    if rng is not None:
        # The bounds are a field beside the state, not only words in the detail.
        report.properties[-1]["range"] = rng


def main(argv=None) -> int:
    """The whole command, rendering and output included, under one guard."""
    try:
        return _main(argv)
    except Exception as exc:  # noqa: BLE001 — a fault in the verifier must not exit with a verdict's code
        print(f"VERIFIER ERROR: {type(exc).__name__}: {exc} -- a fault in the verifier, not a verdict about the record; nothing was judged", file=sys.stderr)
        return 3


def _main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run_directory")
    ap.add_argument("--registry", required=True)
    ap.add_argument("--attester-registry", default=None)
    ap.add_argument("--decider-registry", default=None)
    ap.add_argument("--arrival-log", default=None, help="the attester's own copy of its log")
    ap.add_argument("--prior-run", default=None, help="the prior record's directory in this record's stream, to close the seam")
    ap.add_argument("--replay", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--assurance", action="store_true", help="also state the assurance level the properties reach (A0-A4), after the table (SPEC §9.1)")
    a = ap.parse_args(argv)
    directory = Path(a.run_directory)
    try:
        report = verify_directory(directory, Path(a.registry), replay_module=a.replay,
                                  decider_registry=Path(a.decider_registry) if a.decider_registry else None)
    except (OSError, ValueError) as exc:  # NotJSON is a ValueError
        print(f"could not read {directory}: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # noqa: BLE001 — a fault in the verifier must not exit with a verdict's code
        print(f"VERIFIER ERROR: {type(exc).__name__}: {exc} -- a fault in the verifier, not a verdict about the record; nothing was judged", file=sys.stderr)
        return 3
    try:
        add_arrival(report, directory, registry=Path(a.registry), attester_registry=Path(a.attester_registry) if a.attester_registry else None,
                    decider_registry=Path(a.decider_registry) if a.decider_registry else None,
                    arrival_log=Path(a.arrival_log) if a.arrival_log else None,
                    prior=Path(a.prior_run) if a.prior_run else None)
    except Exception as exc:  # noqa: BLE001
        print(f"VERIFIER ERROR: {type(exc).__name__}: {exc} -- a fault in the verifier, not a verdict about the record; nothing was judged", file=sys.stderr)
        return 3
    if a.json:
        out = {"verdict": report.verdict, "properties": report.properties}
        if a.assurance:  # beside the properties, and carrying them (dr/assurance.py)
            out["assurance"] = assess(report.all_properties())
        print(json.dumps(out, indent=1))
    else:
        print(report.to_text(directory, assurance=a.assurance))
    return report.verdict


if __name__ == "__main__":
    raise SystemExit(main())
