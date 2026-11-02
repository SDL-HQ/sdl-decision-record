"""The second-verifier handoff: the committed corpus reproduces, and the scorer is mechanical.

The corpus's expected states are captured from the reference verifier, so
the test is that regenerating the corpus changes nothing, and that scoring
the reference against itself lists no disagreement while a wrong state, a
wrong digest and a missing case each land in their class.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import verifier_conformance as VC  # noqa: E402
from tools import verifier_score as VS  # noqa: E402

CORPUS = ROOT / "conformance" / "verifier"


def test_committed_corpus_reproduces():
    assert VC.check() == 0


def _reference_results():
    out = {}
    for case in json.loads((CORPUS / "manifest.json").read_text())["cases"]:
        exp = json.loads((CORPUS / "cases" / case["name"] / "expected.json").read_text())
        try:
            rec = json.loads((CORPUS / "cases" / case["name"] / "run" / "record.json").read_text())
        except ValueError:
            rec = {"ledger": {}}
        out[case["name"]] = {"case": case["name"], "payload_hash_recomputed": rec.get("payload_hash"),
                             "terminal_hash_recomputed": rec["ledger"].get("terminal_hash"), "properties": exp["properties"], "verdict": exp["verdict"]}
    return out


def test_scorer_agrees_with_reference_and_classifies_disagreements():
    results = _reference_results()
    assert VS.score(CORPUS, results) == []
    results["toolgate-benchmark"]["properties"]["chain"] = "failed"
    results["signature-wrong"]["payload_hash_recomputed"] = "sha256:" + "0" * 64
    results["stream-hour1"]["verdict"] = "FAILED"
    del results["witness-altered"]
    d = VS.score(CORPUS, results)
    by = {(x["case"], x["class"]) for x in d}
    assert by == {("toolgate-benchmark", "state"), ("signature-wrong", "canonical-bytes"), ("stream-hour1", "verdict"), ("witness-altered", "missing")}


def test_package_holds_the_specification_and_the_corpus_only():
    import tarfile

    with tempfile.TemporaryDirectory() as t:
        tar = Path(t) / "h.tar.gz"
        assert VC.package(tar) == 0
        with tarfile.open(tar) as tf:
            names = tf.getnames()
    assert "verifier-handoff/SPEC.md" in names
    assert any(n.endswith("/score.py") for n in names) and any(n.endswith("/HANDOFF.md") for n in names)
    assert not any("/dr/" in n or "/emitters/" in n or "/tests/" in n or n.endswith(".pem") for n in names)
