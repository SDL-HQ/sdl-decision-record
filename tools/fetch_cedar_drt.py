"""Fetch Cedar's generated conformance corpus at the pinned commit, outside the repository.

    python3 tools/fetch_cedar_drt.py /path/outside/repo      # → <path>/cedar-drt/corpus-tests/
    export CEDAR_DRT_ROOT=/path/outside/repo/cedar-drt

cedar-policy/cedar-integration-tests at b157547f (Apache-2.0; see
vendor/cedar-integration-tests/LICENSE and NOTICE): corpus-tests.tar.gz,
5,677 differential-testing cases with 45,416 requests, verified by digest
before extraction. Not vendored: 5.8 MB of generated fixtures the pin and
digest identify completely.
"""

import hashlib
import io
import subprocess
import sys
import tarfile
from pathlib import Path

PIN = "b157547fb8856911b293b7214768922c731878de"
SHA256 = "67a3698263d2a4530464b88c3094e5930570862c7123362bd7e848b305ad20ec"


def main() -> int:
    dest = Path(sys.argv[1]).resolve()
    repo = dest / "cedar-integration-tests"
    if not (repo / ".git").exists():
        subprocess.run(["git", "clone", "-q", "--depth", "50", "https://github.com/cedar-policy/cedar-integration-tests", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "checkout", "-q", PIN], check=True)
    data = (repo / "corpus-tests.tar.gz").read_bytes()
    got = hashlib.sha256(data).hexdigest()
    if got != SHA256:
        raise SystemExit(f"corpus-tests.tar.gz sha256 {got} != pinned {SHA256}")
    out = dest / "cedar-drt"
    out.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        tar.extractall(out, filter="data")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
