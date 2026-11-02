#!/usr/bin/env python3
"""Write the verifier's exit-code table into README.md, from the constants that define it.

    python3 tools/readme_exit_codes.py          # rewrite the block
    python3 tools/readme_exit_codes.py --check  # exit 1 if README's block is stale

The codes are defined once, in `dr/verify.py`; SPEC §9 states them in prose
and the README shows them on the front page. Three surfaces reading one
constant is one too many to keep by hand, so the README block is generated
between markers and a test holds it to the generator and the generator to
§9. A typed copy drifts; this project has watched that happen.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dr import verify  # noqa: E402

BEGIN = "<!-- BEGIN GENERATED: exit codes -->"
END = "<!-- END GENERATED: exit codes -->"

MEANING = {
    verify.ESTABLISHED: ("ESTABLISHED", "every applicable property established; none failed, none unknown"),
    verify.NOT_ESTABLISHED: ("NOT ESTABLISHED", "none failed, but something is unknown -- including a core property nobody judged. **Unknown is not a pass.** This is the common case for a record verified without its decider, receipts or a witness"),
    verify.FAILED: ("FAILED", "an applicable property failed: a claim the record makes is contradicted by its rows or files"),
    verify.UNREADABLE: ("unreadable", "nothing was judged: the directory or `record.json` could not be read, or the verifier itself failed (standard error says which). A fault in the verifier exits here, not with a verdict's code, except where it raises the same kind of exception a malformed file raises, at a place guarded for that file: while a supplied file is read, or inside the witness and receipt checks, which run under the guard for their file; there the file is reported as the cause (`SPEC.md` §9)"),
}


def block() -> str:
    lines = [BEGIN, "", "`dr.verify` exits with one of four codes, from `dr/verify.py`; SPEC §9 defines the fold:", "",
             "| exit | verdict | meaning |", "|---|---|---|"]
    for code in sorted(MEANING):
        name, meaning = MEANING[code]
        lines.append(f"| {code} | {name} | {meaning} |")
    lines += ["", "A consumer decides its own threshold over the per-property states (`--json`); see `examples/consume.py`.", "", END]
    return "\n".join(lines)


def spec_codes() -> dict[str, int]:
    """The codes as SPEC §9 states them, read from the text."""
    text = (ROOT / "SPEC.md").read_text(encoding="utf-8")
    m = re.search(r"\*\*FAILED\*\* \(exit (\d)\).*?\*\*NOT\s+ESTABLISHED\*\* \(exit (\d)\).*?\*\*ESTABLISHED\*\* \(exit (\d)\).*?exit (\d) if the directory", text, re.S)
    if not m:
        raise SystemExit("SPEC.md §9 no longer states the verdict fold in the form this reads")
    return {"FAILED": int(m.group(1)), "NOT_ESTABLISHED": int(m.group(2)), "ESTABLISHED": int(m.group(3)), "UNREADABLE": int(m.group(4))}


def main(argv=None) -> int:
    check = "--check" in (argv or sys.argv[1:])
    readme = ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    new = block()
    if BEGIN in text and END in text:
        before = text[: text.index(BEGIN)]
        after = text[text.index(END) + len(END):]
        rendered = before + new + after
    else:
        rendered = text.rstrip("\n") + "\n\n" + new + "\n"
    if check:
        if rendered != text:
            print("README.md exit-code block is stale; run tools/readme_exit_codes.py", file=sys.stderr)
            return 1
        return 0
    readme.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
