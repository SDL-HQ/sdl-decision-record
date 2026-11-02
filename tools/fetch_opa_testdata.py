"""Fetch OPA's test-case corpus at the pinned tag, outside the repository, and check its digest.

    python3 tools/fetch_opa_testdata.py [DEST]     # default: ../opa-testdata beside the repository

Clones open-policy-agent/opa (Apache-2.0; the LICENSE file is kept beside the
corpus) at the tag in examples/opa/PINNED_CORPUS.txt with a sparse checkout
of v1/test/cases/testdata, and prints the directory to put in
OPA_TESTDATA_ROOT. The corpus is not vendored (11 MB, 2,333 files); the
record's policy digests every file, so the pin and the digests identify it.
"""

import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = (ROOT / "examples" / "opa" / "PINNED_CORPUS.txt").read_text().split()
COMMIT, TAG = PIN[0], PIN[1]


def main() -> int:
    dest = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT.parent / "opa-testdata"
    if not (dest / ".git").exists():
        subprocess.run(["git", "clone", "--no-checkout", "--filter=blob:none", "--depth", "1", "--branch", TAG, "https://github.com/open-policy-agent/opa", str(dest)], check=True)
        subprocess.run(["git", "-C", str(dest), "sparse-checkout", "set", "--no-cone", "v1/test/cases/testdata", "/LICENSE"], check=True)
        subprocess.run(["git", "-C", str(dest), "checkout", TAG], check=True)
    head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    if head != COMMIT:
        print(f"HEAD is {head}, pinned {COMMIT}", file=sys.stderr)
        return 1
    root = dest / "v1" / "test" / "cases" / "testdata"
    files = sorted(root.glob("**/*.yaml"))
    h = hashlib.sha256()
    for f in files:
        h.update(str(f.relative_to(root)).encode())
        h.update(f.read_bytes())
    print(f"{len(files)} files, corpus digest sha256:{h.hexdigest()}")
    print(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
