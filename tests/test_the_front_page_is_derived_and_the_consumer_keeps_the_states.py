"""Two front-door surfaces held to their sources.

The README's exit-code table is generated from `dr/verify.py`'s constants and
must match SPEC section 9's prose; a typed copy would drift. And
`examples/consume.py`, the
consumer example, must keep the four states rather than collapse them: it
accepts a NOT ESTABLISHED record whose unknowns are allowed, refuses one whose
required property is unknown, and refuses anything failed whatever is allowed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import readme_exit_codes as gen  # noqa: E402
from dr import verify  # noqa: E402


def test_the_readme_block_is_what_the_generator_writes():
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "readme_exit_codes.py"), "--check"], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stderr


def test_the_generator_and_section_nine_name_the_same_codes():
    spec = gen.spec_codes()
    assert spec == {"FAILED": verify.FAILED, "NOT_ESTABLISHED": verify.NOT_ESTABLISHED,
                    "ESTABLISHED": verify.ESTABLISHED, "UNREADABLE": verify.UNREADABLE}


def _consume(report: dict, *args: str) -> tuple[int, str]:
    r = subprocess.run([sys.executable, str(ROOT / "examples" / "consume.py"), *args],
                       input=json.dumps(report), capture_output=True, text=True, cwd=ROOT)
    return r.returncode, r.stdout + r.stderr


def _report(**states: str) -> dict:
    core = {n: "established" for n in ("document", "signing_trust", "signature", "chain", "decisions", "profile", "correctness", "retained")}
    cond = {n: "n/a" for n in ("replay", "invocation", "stream", "completeness", "receipts", "witness")}
    allst = {**core, **cond, **states}
    verdict = "FAILED" if "failed" in allst.values() else ("NOT ESTABLISHED" if "unknown" in allst.values() else "ESTABLISHED")
    return {"verdict": verdict, "properties": [{"property": n, "state": s, "detail": f"{n} detail"} for n, s in allst.items()]}


def test_not_established_with_allowed_unknowns_is_accepted():
    code, out = _consume(_report(invocation="unknown", replay="unknown"))
    assert code == 0 and "ACCEPTED" in out and "NOT ESTABLISHED" in out


def test_a_required_property_unknown_is_refused():
    code, out = _consume(_report(retained="unknown"))
    assert code == 1 and "retained is unknown" in out


def test_anything_failed_is_refused_even_if_allowed_unknown():
    code, out = _consume(_report(witness="failed"), "--allow-unknown", "witness")
    assert code == 1 and "witness FAILED" in out


def test_the_consumer_can_require_a_conditional_property():
    code, _ = _consume(_report(invocation="established"), "--require", "chain,invocation")
    assert code == 0
    code, out = _consume(_report(invocation="unknown"), "--require", "chain,invocation")
    assert code == 1 and "invocation is unknown" in out


def test_not_a_report_is_exit_two():
    r = subprocess.run([sys.executable, str(ROOT / "examples" / "consume.py")], input="nope", capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 2
