"""G18: can the established-versions rule (SPEC §8) name any OPA version, given OPA's own corpus run?

Under the corpus's own tag the opa binary reaches 4,341 of 4,347; the six
are harness differences, which the run names under `excluded`, inside
the digested result, with a reason each. The rule accepts a named version
when the run agrees on every request it did not exclude, and prints the
exclusions. Shown by calling the verifier's own check with a record that
names each measured version, against that version's result file.
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

from dr.canonical import digest_obj  # noqa: E402
from dr.verify import _established_version  # noqa: E402


def main() -> int:
    for f in sorted((HERE / "conformance").glob("opa-*.json")):
        body = json.loads(f.read_text())
        version = body["engine"]
        record = {"decider": {"id": "opa-conformance", "version": "opa-other", "established_versions": [{"version": version, "evidence": digest_obj(body)}]}}
        accepted, detail = _established_version(record, f"opa-conformance@{version}", [f])
        print(f"{version}: {'accepted' if accepted else 'refused'} — {detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
