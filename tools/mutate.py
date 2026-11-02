#!/usr/bin/env python3
"""Mutation evidence: break each behaviour the tests name, and record what fails.

Each mutation is a literal source substitution. The tool applies one, runs the
whole suite, records which tests failed, and restores the file before the next.
A mutation that no test catches is written down as uncaught; it is not hidden
and it is not excused.

    python3 tools/mutate.py            # run all, write tests/MUTATIONS.md
    python3 tools/mutate.py --only M3  # one mutation, print the failing tests

The report is generated from what pytest actually printed. Nothing in it is
typed by hand.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Mutation:
    id: str
    file: str
    old: str
    new: str
    breaks: str


MUTATIONS: List[Mutation] = [
    Mutation("M01", "dr/verify.py", "terminal = verify_chain(loaded)", 'terminal = record["ledger"]["terminal_hash"]; verify_chain(loaded[:1])', "chain: the terminal hash is taken from the record instead of re-derived"),
    Mutation("M02", "dr/verify.py", 'if derived["counts"] != record["counts"]:', "if False:", "decisions: counts are not compared"),
    Mutation("M03", "dr/verify.py", 'elif supported != record["profile"]:', "elif False:", "profile: the declared profile is trusted"),
    Mutation("M04", "dr/verify.py", 'if derived.get("benchmark") == record.get("benchmark"):', "if True:", "correctness: the benchmark block is trusted"),
    Mutation("M05", "dr/verify.py", '        if "unknown" in states or self.missing_core():\n            return NOT_ESTABLISHED\n', "", "verdict: unknown counts as established"),
    Mutation("M06", "dr/verify.py", "                absent.append(name)\n                continue", "                continue", "retained: an absent retained file is ignored (established instead of unknown)"),
    Mutation("M07", "dr/verify.py", 'expected != row["input_digest"]', "False", "retained: inputs are not checked against the rows' digests"),
    Mutation("M08", "dr/verify.py", 'report.add("signature", "established" if ok else "failed", detail)', 'report.add("signature", "established", detail)', "signature: a failed signature is reported as established"),
    Mutation("M09", "dr/registry.py", 'if status == "revoked":', "if False:", "signing_trust: a revoked key is honoured"),
    Mutation("M10", "dr/rows.py", "prev_hash.encode(\"utf-8\") + row_payload(row)", 'prev_hash.encode("utf-8")', "chain: the row hash no longer covers the row's contents"),
    Mutation("M11", "dr/rows.py", 'if row["prev_hash"] != prev:', "if False:", "chain: linkage between rows is not checked"),
    Mutation("M12", "dr/rows.py", "    if extra:\n        d.append(f\"row {index}: undeclared keys {extra}\")", "    if False:\n        d.append(f\"row {index}: undeclared keys {extra}\")", "rows: undeclared row keys are accepted"),
    Mutation("M13", "dr/derive.py", "    if n == len(rows):\n        return PROFILE_BENCHMARK\n    return None", "    if n == len(rows):\n        return PROFILE_BENCHMARK\n    return PROFILE_PRODUCTION", "profile: a mixed ledger is treated as production"),
    Mutation("M14", "dr/derive.py", 'if r["outcome"] == r["label"]:', "if True:", "correctness: every decision counts as agreeing"),
    Mutation("M15", "dr/verify.py", 'if derived["deciders"] != [expected_decider]:', "if False:", "decisions: the decider identity is not checked against the rows"),
    Mutation("M16", "dr/verify.py", "    if undeclared:\n        problems.append", "    if False:\n        problems.append", "decisions: an outcome outside the declared vocabulary is accepted"),
    Mutation("M17", "dr/record.py", '    if extra:\n        d.append(f"undeclared keys {extra}"', '    if False:\n        d.append(f"undeclared keys {extra}"', "document: undeclared record keys are accepted"),
    Mutation("M18", "emitters/toolgate.py", '            if arg not in declared:\n                return "DENY", self._why("arg_undeclared", arg), None', "            if arg not in declared:\n                pass", "toolgate: an undeclared argument is allowed through"),
    Mutation("M19", "emitters/ratelimit.py", "if in_window > self.max:", "if in_window > self.max + 1:", "ratelimit: off by one on the window limit"),
    Mutation("M20", "emitters/classrouter.py", 'if dest["redactable"]:', "if True:", "classrouter: a non-redactable destination redacts instead of denying"),
    Mutation("M21", "dr/verify.py", '(outcome, reason) != (row["outcome"], row["reason"])', 'outcome != row["outcome"]', "replay: the reason is not compared"),
    Mutation("M22", "dr/signing.py", 'UNSIGNED_FIELDS = ("payload_hash", "signature")', 'UNSIGNED_FIELDS = ("payload_hash", "signature", "counts")', "signing: counts are left outside the signature"),
    Mutation("M23", "dr/verify.py", 'if record["payload_hash"] != payload_hash(record):', "if False:", "document: payload_hash is not recomputed"),
    Mutation("M24", "dr/verify.py", 'elif len(loaded) != record["ledger"]["row_count"]:', "elif False:", "chain: the signed row count is not compared"),
    Mutation("M25", "dr/emit.py", "        rows = load_rows(self.directory / LEDGER_FILE)", "        rows = load_rows(self.directory / LEDGER_FILE)[:0] or load_rows(self.directory / LEDGER_FILE)", "emit: (control) a no-op rewrite; must change nothing"),
    Mutation("M26", "dr/verify.py", '    elif supported == derive.PROFILE_BENCHMARK:\n        # The content supports', '    elif False:\n        # The content supports', "correctness: a production declaration over labelled rows is excused"),
    # tonight: completeness, receipts, streams, witnesses, keyed digests, selective disclosure
    Mutation("M27", "dr/receipts.py", "    if seq > len(rows):\n        return \"missing\"", "    if False:\n        return \"missing\"", "receipts: a receipt for a decision beyond the ledger is not reported missing"),
    Mutation("M28", "dr/receipts.py", 'if row["row_hash"] != receipt["row_hash"]:', "if False:", "receipts: the receipted row_hash is not compared with the row"),
    Mutation("M29", "dr/receipts.py", "    if not ok:\n        return \"invalid\", \"the receipt's signature does not verify\"", "    if False:\n        return \"invalid\", \"the receipt's signature does not verify\"", "receipts: a forged receipt is accepted"),
    Mutation("M30", "dr/receipts.py", 'if receipt["record_id"] != record["record_id"]:', "if False:", "receipts: a receipt for another run is applied to this one"),
    Mutation("M31", "dr/verify.py", '        report.add("completeness", "failed", f"refuted:', '        report.add("completeness", "n/a", f"refuted:', "completeness: a refuted record is reported as not claimed"),
    Mutation("M32", "dr/verify.py", 'so at least {highest - len(rows)} acknowledged', 'so at least {highest - len(rows) - 1} acknowledged', "completeness: the gap is under-counted by one"),
    Mutation("M33", "dr/stream.py", 'if computed != st["prev_record_hash"]:', "if False:", "stream: the link to the prior record's payload_hash is not checked"),
    Mutation("M34", "dr/stream.py", 'if st["first_decision"] != expected_first:', "if False:", "stream: decision numbering across records is not checked"),
    Mutation("M35", "dr/witness.py", "    if not ok:\n        return \"failed\", \"the witness signature does not verify\"", "    if False:\n        return \"failed\", \"the witness signature does not verify\"", "witness: a forged witness statement is accepted"),
    Mutation("M36", "dr/witness.py", 'if statement["record_payload_hash"] != record["payload_hash"]:', "if False:", "witness: a statement about another record is accepted for this one"),
    Mutation("M37", "dr/rows.py", '        if not is_keyed_digest(row["input_digest"]):', "        if False:", "rows: a v2 row may carry an unkeyed digest"),
    Mutation("M38", "dr/verify.py", 'expected = keyed_input_digest(salt, item.get("input")) if salt is not None else digest_obj(item.get("input"))', 'expected = keyed_input_digest(salt, item.get("input")) if salt is not None else digest_obj(item.get("input")); expected = row["input_digest"]', "retained: keyed inputs are not checked against the rows' digests"),
    Mutation("M39", "dr/verify.py", "            report.add(\"retained\", \"unknown\", f\"named by the record and not present in this copy", "            report.add(\"retained\", \"established\", f\"named by the record and not present in this copy", "retained: an absent retained file is established"),
    Mutation("M40", "emitters/toolgate.py", 'return kind if self.coarse else f"{kind}:{arg}"', 'return f"{kind}:{arg}"', "toolgate: coarse reasons still name the argument"),
    Mutation("M41", "dr/emit.py", "if ext is not None and self.retain_ext:", "if ext is not None:", "emit: retain_ext=False still writes ext"),
    Mutation("M42", "dr/stream.py", "        if len(keys) > 1:", "        if False:", "stream: two different records at one seq (a fork) are not reported"),
]


def apply(m: Mutation) -> str:
    path = ROOT / m.file
    src = path.read_text(encoding="utf-8")
    if src.count(m.old) != 1:
        raise SystemExit(f"{m.id}: the mutation target occurs {src.count(m.old)} times in {m.file}, expected exactly 1")
    path.write_text(src.replace(m.old, m.new), encoding="utf-8")
    return src


def _clear_bytecode() -> None:
    """A mutation that keeps a file's size and lands in the same second as the
    restore leaves a stale .pyc that Python trusts (it checks mtime and size):
    M12 swaps `extra` for `False`, five characters for five, and the restored
    source would run under the mutated bytecode. So no bytecode is written and
    any that exists is removed before every run."""
    for cache in ROOT.rglob("__pycache__"):
        for f in cache.glob("*.pyc"):
            f.unlink()


def run_suite(skips: list | None = None) -> tuple[int, int, List[str]]:
    _clear_bytecode()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run([sys.executable, "-B", "-m", "pytest", "-q", "-rfEs", "-p", "no:cacheprovider", "--no-header",
                           *[f"--ignore={f}" for f in LEFT_OUT]], cwd=ROOT, capture_output=True, text=True, env=env)
    out = proc.stdout
    failed = re.findall(r"^FAILED (\S+)", out, re.M)
    errors = re.findall(r"^ERROR (\S+)", out, re.M)
    m = re.search(r"(\d+) passed", out)
    # pytest exits 0 when every test passed and 1 when some failed; any other
    # code (2 interrupted or a collection error, 3 an internal error, 4 usage,
    # 5 nothing collected) means the suite did not run, and so does an ERROR
    # line or a summary with no count of passes. That is not a measurement:
    # read as "0 failed" it would pass a baseline that ran no test, or report
    # a mutation that broke an import as uncaught, or as caught, by nothing.
    if proc.returncode not in (0, 1) or errors or m is None:
        tail = "\n".join(out.strip().splitlines()[-15:])
        raise SystemExit(f"the suite did not run to a result (pytest exit {proc.returncode}, "
                         f"{len(errors)} ERROR line(s)); nothing was measured:\n{tail}")
    passed = int(m.group(1))
    if skips is not None:
        # "SKIPPED [n] path:line: reason", one line per distinct reason
        skips.extend((int(n), where.split(":", 1)[0], why.strip())
                     for n, where, why in re.findall(r"^SKIPPED \[(\d+)\] (\S+?): (.*)$", out, re.M))
    return passed, len(failed), failed


# Left out of every run, because under a mutation each always fails: the first
# checks that every mutation's target exists, the second that this table was
# generated over the code and tests in hand.
LEFT_OUT = ("tests/test_every_mutation_still_applies.py", "tests/test_the_mutation_table_is_its_generators.py")
MEASURED = ("dr/", "emitters/", "tools/", "tests/")
TABLE = "tests/MUTATIONS.md"


def is_control(breaks: str) -> bool:
    return "(control)" in breaks


def measured_files() -> List[str]:
    """The code and tests a run executes: every tracked file under MEASURED but
    this table."""
    files = subprocess.run(["git", "ls-files", *MEASURED], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    return sorted(f for f in files if f != TABLE)


def measured_digest() -> str:
    """sha256 over one line per measured file, "<sha256 of the file>  <path>",
    sorted by path. `python3 tools/mutate.py --digest` prints it."""
    import hashlib
    lines = "".join(f"{hashlib.sha256((ROOT / f).read_bytes()).hexdigest()}  {f}\n" for f in measured_files())
    return "sha256:" + hashlib.sha256(lines.encode("utf-8")).hexdigest()


def count_left_out() -> int:
    out = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", *LEFT_OUT],
                         cwd=ROOT, capture_output=True, text=True).stdout
    return sum(1 for l in out.splitlines() if "::" in l)


def head(digest: str, passed: int, skipped: int, left_out: int, skips: list) -> List[str]:
    return [
        "# Mutation evidence",
        "",
        f"Generated by `tools/mutate.py` over the code and tests whose digest is `{digest}`",
        "(`python3 tools/mutate.py --digest` prints it for the tree in hand; a test fails when they differ).",
        f"Baseline: {passed} tests pass, 0 fail, {skipped} skipped, with "
        + " and ".join(f"`{f}`" for f in LEFT_OUT) + f" ({left_out} tests)",
        "left out of every run, because under a mutation each always fails. `pytest -q` over the same tree,",
        f"with the same skips, therefore reports {passed + left_out} passed.",
        "Each row applies one source mutation, runs the suite, and records what pytest reported.",
        "A mutation with zero failing tests is a behaviour the suite does not hold; it is listed, not hidden.",
        "The exception is a control, marked (control): a rewrite that changes no behaviour, for which zero",
        "failing tests is the correct result. It shows the harness does not report a catch where there is",
        "nothing to catch.",
        "",
        "A skipped test holds nothing in this run, so a mutation only a skipped test would catch counts here",
        "as fewer failures, or as uncaught. The skips, as pytest reported them:",
        "",
        *[f"- {n} in `{where}`: {why}" for n, where, why in sorted(skips, key=lambda x: x[1])],
        *(["- none"] if not skips else []),
        "",
        "| id | file | behaviour broken | tests failing | first three |",
        "|---|---|---|---:|---|",
    ]


def foot(results: list) -> List[str]:
    """results: (id, tests failing, is a control) per mutation."""
    real = [(i, n) for i, n, c in results if not c]
    controls = [(i, n) for i, n, c in results if c]
    caught = [i for i, n in real if n > 0]
    uncaught = [i for i, n in real if n == 0]
    quiet = [i for i, n in controls if n == 0]
    loud = [i for i, n in controls if n > 0]
    line = (f"Mutations applied: {len(results)}. {len(caught)} of {len(real)} caught, "
            f"{len(uncaught)} uncaught" + (f" ({', '.join(uncaught)})" if uncaught else "") + ". "
            f"{len(controls)} control" + ("" if len(controls) == 1 else "s") + ": "
            f"{len(quiet)} unchanged, as a control must be" + (f" ({', '.join(quiet)})" if quiet else ""))
    if loud:
        line += f"; {len(loud)} failed tests, which is a fault in the harness ({', '.join(loud)})"
    return ["", line + ".", ""]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None)
    ap.add_argument("--digest", action="store_true", help="print the digest of the code and tests in hand, and exit")
    args = ap.parse_args()
    if args.digest:
        print(measured_digest())
        return 0
    selected = [m for m in MUTATIONS if args.only is None or m.id == args.only]

    digest = measured_digest()  # before any mutation touches a file
    skips: list = []
    baseline_passed, baseline_failed, _ = run_suite(skips)
    if baseline_failed:
        raise SystemExit(f"the unmutated suite has {baseline_failed} failures; fix those first")

    rows = []
    for m in selected:
        original = apply(m)
        try:
            passed, nfailed, failed = run_suite()
        finally:
            (ROOT / m.file).write_text(original, encoding="utf-8")
        rows.append((m, passed, nfailed, failed))
        print(f"{m.id} {m.file}: {nfailed} failed  ({m.breaks})")
        if args.only:
            for f in failed:
                print("   ", f)

    if args.only:
        return 0

    left_out = count_left_out()
    lines = head(digest, baseline_passed, sum(n for n, _, _ in skips), left_out, skips)
    for m, passed, nfailed, failed in rows:
        first = "; ".join(f.split("::", 1)[1] for f in failed[:3]) if failed else "—"
        lines.append(f"| {m.id} | `{m.file}` | {m.breaks} | {nfailed} | {first} |")
    uncaught = [m.id for m, _, n, _ in rows if n == 0 and not is_control(m.breaks)]
    lines += foot([(m.id, n, is_control(m.breaks)) for m, _, n, _ in rows])
    (ROOT / "tests" / "MUTATIONS.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote tests/MUTATIONS.md; uncaught: {uncaught}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
