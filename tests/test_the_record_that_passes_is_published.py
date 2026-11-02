"""The one forgery that passes every check is published, and is what forge.py makes.

F1-F4 are forgeries the verifier catches, and a reader can take a catch on
trust. F5 is the one it cannot catch: the retained input of seq 24 is a call
the agent never made, and every property is established over it. That is the
boundary this format names, as a runnable artefact rather than a sentence, so
it is the one tracked in the repository. A reader who runs the four that fail
and never reaches the one that passes leaves thinking the gap is closed.

A published built artefact is a second copy of what its generator makes, and a
second copy can drift, so the tracked bytes are held against what forge.py
reproduces rather than trusted. The build is deterministic: the test keys are
derived from a fixed seed, Ed25519 signatures are deterministic, and every
timestamp in the forgery is a literal.

Publishing a record that verifies is only safe while it cannot be mistaken for
a genuine one, so that is asserted here too rather than assumed: --registry has
no default, and F5's key exists in no registry but the experiment's own.

Breaking these: change forge.py's inputs, keys or timestamps without
re-running it; or widen the gitignore carve-out to ship a forgery that fails.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from dr.verify import ESTABLISHED, FAILED, verify_directory

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiments" / "rederivability" / "out"
F5 = OUT / "f5-input-fabricated"
PUBLISHED = ("record.json", "decisions.jsonl", "inputs.jsonl", "policy.json", "attestations.jsonl")


def test_the_published_forgery_is_tracked():
    tracked = subprocess.run(
        [*("git -C".split()), str(ROOT), "ls-files", str(OUT.relative_to(ROOT))],
        capture_output=True, text=True, check=True).stdout.split()
    names = {Path(t).name for t in tracked}
    assert names == {*PUBLISHED, "registry.json", "deciders.json"}, (
        f"the carve-out tracks {sorted(names)}; it must track F5 and its two registries, and no forgery that fails"
    )


def test_forge_reproduces_the_published_bytes(tmp_path):
    pytest.importorskip("cedarpy")  # forge.py decides every forgery under the Cedar engine
    subprocess.run([sys.executable, str(ROOT / "experiments" / "rederivability" / "forge.py"),
                    "--out", str(tmp_path)], check=True, capture_output=True, cwd=ROOT)
    for name in PUBLISHED:
        assert (tmp_path / "f5-input-fabricated" / name).read_bytes() == (F5 / name).read_bytes(), (
            f"{name} differs from what forge.py produces; the published copy has drifted from its generator"
        )
    for name in ("registry.json", "deciders.json"):
        assert (tmp_path / name).read_bytes() == (OUT / name).read_bytes(), f"{name} differs"


def test_it_passes_every_property_which_is_the_point():
    report = verify_directory(F5, registry_path=OUT / "registry.json",
                              decider_registry=OUT / "deciders.json")
    assert report.verdict == ESTABLISHED, report.to_text(F5)
    states = {p["property"]: p["state"] for p in report.properties}
    assert states["chain"] == "established"
    assert states["retained"] == "established"
    assert states["invocation"] == "established"
    seq = json.loads((F5 / "inputs.jsonl").read_text().splitlines()[23])
    assert seq["seq"] == 24, "the fabricated row moved; the docstring and RESULTS.md name seq 24"


def test_it_cannot_be_mistaken_for_a_genuine_record(tmp_path):
    """Safe to publish only because no real registry honours its key.

    Measured rather than assumed, and it is stronger than it needed to be: a
    key the registry does not carry is a failure and not an unknown, so a
    reader who points a real registry at this record gets FAILED, and
    --registry has no default to fall back on.
    """
    empty = tmp_path / "registry.json"
    empty.write_text(json.dumps({"registry_version": 1, "keys": []}))
    report = verify_directory(F5, registry_path=empty, decider_registry=OUT / "deciders.json")
    assert report.verdict == FAILED, report.to_text(F5)
    assert report.state("signing_trust") == "failed"
    assert report.state("signature") == "unknown"
