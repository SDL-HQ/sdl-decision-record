"""Every reader of a JSON Lines file in the shipped code splits on LF only.

`dr.canonical.jsonl_lines` says why: `str.splitlines` also splits on U+2028,
U+2029, U+0085 and a lone CR, the first three legal unescaped inside a JSON
string and written literally by this format's own writer. A reader that uses
it breaks an honest line in two. The format's own readers in `dr/` use
`jsonl_lines`; this holds the tools and the shipped experiments to the same,
by refusing a source line that reads a ledger, an inputs file or any
`.jsonl` with `splitlines`.

Breaking this: read a `.jsonl` file with `read_text().splitlines()` in
`tools/`, `emitters/` or `experiments/rederivability/`.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHIPPED_CODE = ("dr", "emitters", "tools", "experiments/rederivability", "experiments/spec_sufficiency")
JSONL_READ = re.compile(r"splitlines\(\)")
JSONL_NAMES = re.compile(r"jsonl|ledger|inputs\b|decisions|attestations|LEDGER_FILE|INPUTS_FILE", re.I)


def test_no_shipped_reader_splits_jsonl_with_splitlines():
    offenders = []
    for top in SHIPPED_CODE:
        for path in sorted((ROOT / top).rglob("*.py")):
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if JSONL_READ.search(line) and JSONL_NAMES.search(line) and "read_text" in line:
                    offenders.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()}")
    assert not offenders, "\n".join(offenders)
