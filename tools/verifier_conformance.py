"""The handoff for a second, independent verifier: a conformance corpus and its packaging.

    python3 tools/verifier_conformance.py build      # → conformance/verifier/  (cases, expected states, score.py, HANDOFF.md)
    python3 tools/verifier_conformance.py package    # → verifier-handoff.tar.gz beside the repository: SPEC.md + conformance/verifier/, nothing else
    python3 tools/verifier_conformance.py check      # rebuild into a temporary directory and compare with the committed corpus

The hypothesis (SPEC §8 and the specification's own words): an implementation
written from SPEC.md alone, with no reference to this code, either
reproduces every expected property state over this corpus or surfaces a
disagreement of one of three kinds — canonical bytes, shape, state. The
corpus is every committed record plus deliberate mutations of them, each
with the reference verifier's states as the expectation. Expected states
are captured from `dr.verify --json`, never written by hand.

What the implementer receives is exactly what `package` produces. The
private keys the mutations are signed with stay here; the package carries
public registries only.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dr import derive  # noqa: E402
from dr.canonical import digest_file, read_jsonl  # noqa: E402
from dr.rows import GENESIS, row_hash  # noqa: E402
from dr.signing import sign_record  # noqa: E402

OUT = ROOT / "conformance" / "verifier"
KEYS = ROOT / "examples" / "keys"
PRODUCER_KEY = (KEYS / "example-signing-key.pem").read_bytes()
RETIRED_KEY = (KEYS / "retired-key.pem").read_bytes()
REVOKED_KEY = (KEYS / "revoked-key.pem").read_bytes()
DECIDER_KEY = (KEYS / "decider-key.pem").read_bytes()

# (case name, source run directory, verifier options relative to the case directory or to conformance/verifier/keys/)
BASES = [
    ("toolgate-benchmark", "examples/out/toolgate-benchmark", {}),
    ("toolgate-production", "examples/out/toolgate-production", {}),
    ("ratelimit-production", "examples/out/ratelimit-production", {}),
    ("ratelimit-production-keyed", "examples/out/ratelimit-production-keyed", {}),
    ("classrouter-benchmark", "examples/out/classrouter-benchmark", {}),
    ("stream-hour1", "examples/out/stream-hour1", {}),
    ("stream-hour2-with-prior", "examples/out/stream-hour2", {"prior": "examples/out/stream-hour1/record.json"}),
    ("stream-hour2-without-prior", "examples/out/stream-hour2", {}),
    ("stream-hour1-receipts", "examples/out/stream-hour1", {"receipts": ["examples/out/stream-hour1-receipts/receipt-000001.json", "examples/out/stream-hour1-receipts/receipt-000020.json"]}),
    ("stream-hour1-witnessed", "examples/out/stream-hour1", {"witness": "examples/out/stream-hour1.witness.json", "witness_registry": "examples/keys/witnesses.json"}),
    ("cedar-toolcalls-canonical", "examples/cedar/out/toolcalls-canonical", {}),
    ("cedar-conformance-handwritten", "examples/cedar/out/conformance-handwritten", {}),
    ("opa-conformance-sample", "examples/opa/out/conformance-sample", {}),
    ("acceptance-attested", "examples/acceptance/out/record", {"decider_registry": "examples/keys/deciders.json"}),
    ("acceptance-attested-no-decider-registry", "examples/acceptance/out/record", {}),
]


def _rows(d: Path) -> List[Dict[str, Any]]:
    return [json.loads(l) for _, l in read_jsonl(d / "decisions.jsonl")]


def _write_rows(d: Path, rows) -> None:
    (d / "decisions.jsonl").write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


def _record(d: Path) -> Dict[str, Any]:
    return json.loads((d / "record.json").read_text())


def _write_record(d: Path, rec: Dict[str, Any]) -> None:
    (d / "record.json").write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")


def _resign(d: Path, key: bytes = PRODUCER_KEY, rederive: bool = False) -> None:
    rec = _record(d)
    for k in ("payload_hash", "signature"):
        rec.pop(k, None)
    if rederive:
        rows = _rows(d)
        der = derive.derive_all(rows)
        rec["ledger"]["row_count"] = len(rows)
        rec["ledger"]["terminal_hash"] = rows[-1]["row_hash"]
        rec["counts"] = der["counts"]
        rec["policy_digests"] = der["policy_digests"]
        if "benchmark" in rec:
            rec["benchmark"] = der["benchmark"]
    rec["retained"] = {name: digest_file(d / name) for name in rec["retained"] if (d / name).exists()}
    _write_record(d, sign_record(rec, key))


def _rechain(rows) -> None:
    prev = GENESIS
    for i, r in enumerate(rows, start=1):
        r["seq"] = i
        r["prev_hash"] = prev
        r["row_hash"] = row_hash(prev, r)
        prev = r["row_hash"]


# Each mutation: (name, base case name, function(case dir) -> description). The reference verifier's states are the expectation.
def m_row_outcome_flipped(d):
    rows = _rows(d)
    rows[3]["outcome"] = "DENY" if rows[3]["outcome"] == "ALLOW" else "ALLOW"
    _write_rows(d, rows)
    return "row 4's outcome edited on disk; hashes left as they were"


def m_row_prev_hash_edited(d):
    rows = _rows(d)
    rows[5]["prev_hash"] = "sha256:" + "0" * 64
    _write_rows(d, rows)
    return "row 6's prev_hash replaced; its own row_hash left as it was"


def m_row_rehashed_after_edit(d):
    rows = _rows(d)
    rows[3]["outcome"] = "DENY" if rows[3]["outcome"] == "ALLOW" else "ALLOW"
    rows[3]["row_hash"] = row_hash(rows[3]["prev_hash"], rows[3])
    _write_rows(d, rows)
    return "row 4 edited and its own hash recomputed from its prev_hash; row 5's prev_hash no longer matches"


def m_rows_rehashed_forward_not_resigned(d):
    rows = _rows(d)
    rows[3]["outcome"] = "DENY" if rows[3]["outcome"] == "ALLOW" else "ALLOW"
    _rechain(rows)
    _write_rows(d, rows)
    return "row 4 edited and every hash recomputed forward; the record still signs the old terminal hash"


def m_rows_rehashed_forward_resigned(d):
    rows = _rows(d)
    rows[3]["outcome"] = "DENY" if rows[3]["outcome"] == "ALLOW" else "ALLOW"
    _rechain(rows)
    _write_rows(d, rows)
    _resign(d, rederive=True)
    return "row 4 edited, hashes recomputed forward, counts re-derived, record re-signed by the producer (replay would catch it; nothing else can)"


def m_row_deleted_resigned(d):
    rows = _rows(d)
    del rows[6]
    _rechain(rows)
    _write_rows(d, rows)
    inputs = d / "inputs.jsonl"
    if inputs.exists():
        lines = [json.loads(l) for _, l in read_jsonl(inputs)]
        head, body = ([lines[0]], lines[1:]) if lines and set(lines[0]) == {"salt"} else ([], lines)
        body = [x for x in body if x["seq"] != 7]
        for i, x in enumerate(body, start=1):
            x["seq"] = i
        inputs.write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in head + body))
    _resign(d, rederive=True)
    return "row 7 deleted, the rest renumbered, counts re-derived, record re-signed: the completeness limit"


def m_counts_wrong(d):
    rec = _record(d)
    rec["counts"]["decisions"] += 1
    _write_record(d, rec)
    return "counts.decisions off by one in the record; signature now stale"


def m_counts_wrong_resigned(d):
    rec = _record(d)
    rec["counts"]["decisions"] += 1
    _write_record(d, rec)
    _resign(d)
    return "counts.decisions off by one and the record re-signed"


def m_profile_lies(d):
    rec = _record(d)
    rec["profile"] = "production"
    rec.pop("benchmark", None)
    _write_record(d, rec)
    _resign(d)
    return "a benchmark ledger declared production, benchmark block removed, re-signed"


def m_profile_claims_benchmark(d):
    rec = _record(d)
    rec["profile"] = "benchmark"
    rec["benchmark"] = {"labelled": 0, "agree": 0, "disagree": 0, "by_label": {}}
    _write_record(d, rec)
    _resign(d)
    return "an unlabelled ledger declared benchmark, re-signed"


def m_payload_hash_wrong(d):
    rec = _record(d)
    rec["payload_hash"] = "sha256:" + "1" * 64
    _write_record(d, rec)
    return "payload_hash replaced; signature untouched"


def m_signature_wrong(d):
    rec = _record(d)
    rec["signature"] = rec["signature"][:-4] + ("AAAA" if not rec["signature"].endswith("AAAA") else "BBBB")
    _write_record(d, rec)
    return "last bytes of the signature altered"


def m_unknown_key_id(d):
    rec = _record(d)
    rec["signing_key_id"] = "no-such-key"
    _write_record(d, rec)
    _resign(d)
    return "signing_key_id names a key the registry does not have; signed by the producer's key, re-signed"


def m_signed_by_retired_key(d):
    rec = _record(d)
    rec["signing_key_id"] = "example-2026-09"
    _write_record(d, rec)
    _resign(d, key=RETIRED_KEY)
    return "signed by the retired key under its own id"


def m_signed_by_revoked_key(d):
    rec = _record(d)
    rec["signing_key_id"] = "example-compromised"
    _write_record(d, rec)
    _resign(d, key=REVOKED_KEY)
    return "signed by the revoked key; the registry does not list this payload_hash"


def m_retained_file_missing(d):
    (d / "inputs.jsonl").unlink()
    return "inputs.jsonl absent from this copy"


def m_retained_file_differs(d):
    p = d / "policy.json"
    p.write_text(p.read_text() + "\n")
    return "policy.json has one byte appended; its digest no longer matches"


def m_format_version_unknown(d):
    rec = _record(d)
    rec["format_version"] = 99
    _write_record(d, rec)
    _resign(d)
    return "format_version 99, re-signed"


def m_row_version_unknown(d):
    rows = _rows(d)
    for r in rows:
        r["v"] = 99
    _write_rows(d, rows)
    return "every row declares v 99"


def m_rows_mixed_versions(d):
    rows = _rows(d)
    rows[2]["v"] = 2
    _write_rows(d, rows)
    return "row 3 declares v 2 in a v 1 ledger"


def m_row_undeclared_key(d):
    rows = _rows(d)
    rows[0]["note"] = "an undeclared key"
    _write_rows(d, rows)
    return "row 1 carries a key the row version does not declare"


def m_extra_file_unnamed(d):
    (d / "notes.txt").write_text("a file the record does not name\n")
    return "a file beside the ledger that the record does not name"


def m_stream_prior_wrong(d):
    rec = _record(d)
    rec["stream"]["prev_record_hash"] = "sha256:" + "2" * 64
    _write_record(d, rec)
    _resign(d)
    return "stream.prev_record_hash does not match the prior supplied"


def m_receipt_row_deleted(d):
    rows = _rows(d)
    del rows[19]
    _rechain(rows)
    _write_rows(d, rows)
    inputs = d / "inputs.jsonl"
    lines = [json.loads(l) for _, l in read_jsonl(inputs)]
    inputs.write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in lines if x.get("seq") != 20))
    _resign(d, rederive=True)
    return "row 20 deleted from the tail, counts re-derived, record re-signed; the receipt for decision 20 is still supplied"


def m_witness_altered(d):
    return "the witness statement supplied names a different payload_hash (case options point at an altered copy)"


def m_witness_self_signed(d):
    return "a witness statement signed with the producer's own key, under a witness registry that enrols that key as 'independent-auditor-2026-10'"


def m_record_not_json(d):
    (d / "record.json").write_text("{ not json\n")
    return "record.json is not JSON: the directory cannot be read"


def m_ledger_missing(d):
    (d / "decisions.jsonl").unlink()
    return "the ledger file the record names is absent"


def m_attestation_forged(d):
    p = d / "attestations.jsonl"
    atts = [json.loads(l) for _, l in read_jsonl(p)]
    atts[1]["outcome"] = "DENY" if atts[1]["outcome"] == "ALLOW" else "ALLOW"
    p.write_text("".join(json.dumps(a, sort_keys=True) + "\n" for a in atts))
    _resign(d)
    return "attestation for seq 2 edited; record re-signed by the producer"


def m_attestation_missing(d):
    p = d / "attestations.jsonl"
    atts = [json.loads(l) for _, l in read_jsonl(p)]
    p.write_text("".join(json.dumps(a, sort_keys=True) + "\n" for a in atts if a["seq"] not in (4, 5)))
    _resign(d)
    return "attestations for seq 4 and 5 removed; record re-signed"


MUTATIONS = [
    ("row-outcome-flipped", "toolgate-benchmark", m_row_outcome_flipped),
    ("row-prev-hash-edited", "toolgate-benchmark", m_row_prev_hash_edited),
    ("row-rehashed-after-edit", "toolgate-benchmark", m_row_rehashed_after_edit),
    ("rows-rehashed-forward-not-resigned", "toolgate-benchmark", m_rows_rehashed_forward_not_resigned),
    ("rows-rehashed-forward-resigned", "toolgate-benchmark", m_rows_rehashed_forward_resigned),
    ("row-deleted-resigned", "toolgate-production", m_row_deleted_resigned),
    ("row-deleted-resigned-keyed", "ratelimit-production-keyed", m_row_deleted_resigned),
    ("counts-wrong", "toolgate-benchmark", m_counts_wrong),
    ("counts-wrong-resigned", "toolgate-benchmark", m_counts_wrong_resigned),
    ("profile-lies-production", "toolgate-benchmark", m_profile_lies),
    ("profile-claims-benchmark", "toolgate-production", m_profile_claims_benchmark),
    ("payload-hash-wrong", "toolgate-benchmark", m_payload_hash_wrong),
    ("signature-wrong", "toolgate-benchmark", m_signature_wrong),
    ("unknown-key-id", "toolgate-benchmark", m_unknown_key_id),
    ("signed-by-retired-key", "toolgate-benchmark", m_signed_by_retired_key),
    ("signed-by-revoked-key", "toolgate-benchmark", m_signed_by_revoked_key),
    ("retained-file-missing", "toolgate-production", m_retained_file_missing),
    ("retained-file-differs", "toolgate-production", m_retained_file_differs),
    ("format-version-unknown", "toolgate-benchmark", m_format_version_unknown),
    ("row-version-unknown", "toolgate-benchmark", m_row_version_unknown),
    ("rows-mixed-versions", "toolgate-benchmark", m_rows_mixed_versions),
    ("row-undeclared-key", "toolgate-benchmark", m_row_undeclared_key),
    ("extra-file-unnamed", "toolgate-benchmark", m_extra_file_unnamed),
    ("stream-prior-wrong", "stream-hour2-with-prior", m_stream_prior_wrong),
    ("receipt-row-deleted", "stream-hour1-receipts", m_receipt_row_deleted),
    ("receipt-foreign", "stream-hour1", lambda d: "a receipt issued for the next record in the stream (hour 2, its decision 1, which is decision 21 of the stream) supplied against hour 1"),
    ("witness-altered", "stream-hour1-witnessed", m_witness_altered),
    ("witness-self-signed", "stream-hour1", m_witness_self_signed),
    ("record-not-json", "toolgate-benchmark", m_record_not_json),
    ("ledger-missing", "toolgate-benchmark", m_ledger_missing),
    ("attestation-forged", "acceptance-attested", m_attestation_forged),
    ("attestation-missing", "acceptance-attested", m_attestation_missing),
]


# cases whose verifier options are not their base's
OPTION_OVERRIDES = {
    "receipt-foreign": {"registry": "keys/registry.json", "receipts": ["inputs/stream-hour2-receipts/receipt-000001.json"]},
    "witness-altered": {"registry": "keys/registry.json", "witness": "inputs/stream-hour1.witness-altered.json", "witness_registry": "keys/witnesses.json"},
    "witness-self-signed": {"registry": "keys/registry.json", "witness": "inputs/stream-hour1.self-witness.json", "witness_registry": "keys/witnesses-with-producer-key.json"},
}


def _options_for_package(opts: Dict[str, Any]) -> Dict[str, Any]:
    """Options rewritten to paths inside the package."""
    out: Dict[str, Any] = {"registry": "keys/registry.json"}
    if "prior" in opts:
        out["prior"] = "inputs/" + Path(opts["prior"]).parent.name + "/record.json"
    if "receipts" in opts:
        out["receipts"] = ["inputs/" + Path(p).parent.name + "/" + Path(p).name for p in opts["receipts"]]
    if "witness" in opts:
        out["witness"] = "inputs/" + Path(opts["witness"]).name
        out["witness_registry"] = "keys/" + Path(opts["witness_registry"]).name
    if "decider_registry" in opts:
        out["decider_registry"] = "keys/" + Path(opts["decider_registry"]).name
    return out


def _reference(case_dir: Path, opts: Dict[str, Any], base_dir: Path) -> Dict[str, Any]:
    cmd = [sys.executable, "-m", "dr.verify", str(case_dir / "run"), "--registry", str(base_dir / opts["registry"]), "--json"]
    for k in ("prior", "witness", "witness_registry", "decider_registry"):
        if k in opts:
            cmd += ["--" + k.replace("_", "-"), str(base_dir / opts[k])]
    for r in opts.get("receipts", []):
        cmd += ["--receipt", str(base_dir / r)]
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    if not p.stdout.strip():
        return {"verdict": "UNREADABLE", "exit_code": p.returncode, "properties": [], "notes": [p.stderr.strip().splitlines()[-1][:200] if p.stderr.strip() else ""]}
    return json.loads(p.stdout)


def build(out: Path) -> int:
    if out.exists():
        shutil.rmtree(out)
    (out / "cases").mkdir(parents=True)
    (out / "keys").mkdir()
    (out / "inputs").mkdir()
    for name in ("registry.json", "witnesses.json", "witnesses-with-producer-key.json", "deciders.json"):
        shutil.copy(KEYS / name, out / "keys" / name)
    # supporting inputs: priors, receipts, witness statements, as files beside the cases
    shutil.copytree(ROOT / "examples" / "out" / "stream-hour1", out / "inputs" / "stream-hour1")
    (out / "inputs" / "stream-hour1-receipts").mkdir()
    for n in ("receipt-000001.json", "receipt-000020.json"):
        shutil.copy(ROOT / "examples" / "out" / "stream-hour1-receipts" / n, out / "inputs" / "stream-hour1-receipts" / n)
    shutil.copy(ROOT / "examples" / "out" / "stream-hour1.witness.json", out / "inputs" / "stream-hour1.witness.json")
    (out / "inputs" / "stream-hour2-receipts").mkdir()
    shutil.copy(ROOT / "examples" / "out" / "stream-hour2-receipts" / "receipt-000001.json", out / "inputs" / "stream-hour2-receipts" / "receipt-000001.json")
    w = json.loads((out / "inputs" / "stream-hour1.witness.json").read_text())
    w["record_payload_hash"] = "sha256:" + "3" * 64
    (out / "inputs" / "stream-hour1.witness-altered.json").write_text(json.dumps(w, indent=2, sort_keys=True) + "\n")
    subprocess.run([sys.executable, "-m", "dr.witness", str(ROOT / "examples" / "out" / "stream-hour1" / "record.json"), "--key", str(KEYS / "example-signing-key.pem"),
                    "--key-id", "independent-auditor-2026-10", "--witnessed-at", "2026-10-21T03:05:00Z", "--out", str(out / "inputs" / "stream-hour1.self-witness.json")], check=True, cwd=ROOT)
    manifest = []
    built: Dict[str, Path] = {}
    for name, src, opts in BASES:
        cd = out / "cases" / name
        shutil.copytree(ROOT / src, cd / "run")
        popts = _options_for_package(opts)
        (cd / "case.json").write_text(json.dumps({"name": name, "kind": "committed record", "source": src, "options": popts}, indent=1) + "\n")
        exp = _reference(cd, popts, out)
        (cd / "expected.json").write_text(json.dumps(_expected(exp), indent=1, sort_keys=True) + "\n")
        manifest.append({"name": name, "kind": "committed record", "verdict": exp["verdict"]})
        built[name] = cd
    for name, base, fn in MUTATIONS:
        cd = out / "cases" / name
        shutil.copytree(built[base] / "run", cd / "run")
        what = fn(cd / "run")
        popts = OPTION_OVERRIDES.get(name) or json.loads((built[base] / "case.json").read_text())["options"]
        (cd / "case.json").write_text(json.dumps({"name": name, "kind": "mutation", "of": base, "what": what, "options": popts}, indent=1) + "\n")
        exp = _reference(cd, popts, out)
        (cd / "expected.json").write_text(json.dumps(_expected(exp), indent=1, sort_keys=True) + "\n")
        manifest.append({"name": name, "kind": "mutation", "of": base, "what": what, "verdict": exp["verdict"]})
    (out / "manifest.json").write_text(json.dumps({"cases": manifest, "property_names": PROPERTY_NAMES, "states": ["established", "unknown", "failed", "n/a"]}, indent=1) + "\n")
    shutil.copy(ROOT / "tools" / "verifier_score.py", out / "score.py")
    (out / "HANDOFF.md").write_text(HANDOFF)
    print(f"{len(manifest)} cases under {out}")
    return 0


PROPERTY_NAMES = ["document", "signing_trust", "signature", "chain", "decisions", "profile", "correctness", "retained", "replay", "invocation", "stream", "completeness", "receipts", "witness"]


def _expected(rep: Dict[str, Any]) -> Dict[str, Any]:
    return {"verdict": rep["verdict"], "exit_code": rep["exit_code"], "properties": {p["property"]: p["state"] for p in rep.get("properties", [])}}


HANDOFF = """# Handoff: write a verifier from the specification alone

You receive `SPEC.md` and this directory, and nothing else: no reference
code, no tests, no decision log, no conversation with the people who wrote
the specification. The question being asked is whether the specification is
sufficient for an implementation written by someone who was not in the room.
Do not go looking for the reference implementation; if you find it, the
exercise is over.

## What to build

A verifier of decision records as `SPEC.md` describes them: given a run
directory and a key registry, and optionally a prior record, receipts, a
witness statement with its registry, and a decider registry, report every
property of SPEC §9 as one of `established`, `unknown`, `failed` or `n/a`,
and the verdict §9 defines. Replay (§8) needs decider code that is not
provided: report `replay` as `n/a` throughout.

Use any language. The reference is not a constraint on structure, only on
what the states are.

## The corpus

`cases/<name>/run/` is a run directory as a verifier receives it.
`cases/<name>/case.json` gives the options to verify it with, as paths
relative to this directory (`keys/` holds the registries, `inputs/` the
priors, receipts and witness statements). `manifest.json` lists the cases.
Some are records as issued; others are deliberate alterations of them, and
`what` says what was done, so you can tell whether your implementation
refused for the reason the alteration supplies.

`cases/<name>/expected.json` holds the reference verifier's states. Write
and run your implementation first, over every case, and only then score.
An implementation tuned case by case against the expectations tells us
nothing about the specification.

## The output contract

One JSON object per line, one line per case:

    {"case": "<name>",
     "payload_hash_recomputed": "sha256:…" | null,
     "terminal_hash_recomputed": "sha256:…" | null,
     "properties": {"document": "…", "signing_trust": "…", "signature": "…", "chain": "…", "decisions": "…",
                    "profile": "…", "correctness": "…", "retained": "…", "replay": "n/a", "invocation": "…",
                    "stream": "…", "completeness": "…", "receipts": "…", "witness": "…"},
     "verdict": "ESTABLISHED" | "NOT ESTABLISHED" | "FAILED" | "UNREADABLE"}

`payload_hash_recomputed` is the digest your implementation computes over
the record's signed payload (SPEC §2, §5, §7). `terminal_hash_recomputed`
is the last row hash your re-derivation of the chain produces (§3, §4),
or null if it produced none. `UNREADABLE` is the verdict for a directory
that could not be read at all (exit 3 in §9). These two digests are what
lets the scorer tell a canonical-bytes disagreement from a logic one.

## Scoring

    python3 score.py results.jsonl

prints the disagreements by class and nothing else:

- `missing` — no line for the case;
- `shape` — you refused to read a case the reference read, or read one
  it refused;
- `canonical-bytes` — your recomputed digest differs from the record's
  where the reference found it to match, so the bytes you canonicalise or
  hash differ before any property is judged;
- `state` — the same property, a different state;
- `verdict` — every state agrees and the verdict does not.

The output is a list, not an opinion. Send back the list, and for each
entry the sentence of the specification you followed, or the sentence that
was missing. A disagreement where your reading of the specification is the
defensible one is the most useful result this exercise can produce.
"""


def package(out_tar: Path) -> int:
    if not OUT.exists():
        build(OUT)
    with tarfile.open(out_tar, "w:gz") as tf:
        tf.add(ROOT / "SPEC.md", arcname="verifier-handoff/SPEC.md")
        tf.add(OUT, arcname="verifier-handoff/conformance")
    print(out_tar)
    return 0


def check() -> int:
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t) / "verifier"
        build(tmp)
        import filecmp

        def tree_equal(a: Path, b: Path) -> bool:
            cmp = filecmp.dircmp(a, b)
            if cmp.left_only or cmp.right_only or cmp.diff_files or cmp.funny_files:
                print("differs:", cmp.left_only, cmp.right_only, cmp.diff_files)
                return False
            return all(tree_equal(a / d, b / d) for d in cmp.common_dirs)

        ok = tree_equal(tmp, OUT)
        print("committed corpus reproduces" if ok else "committed corpus does not reproduce")
        return 0 if ok else 1


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["build"]:
        return build(OUT)
    if argv[:1] == ["package"]:
        return package(Path(argv[1]) if len(argv) > 1 else ROOT.parent / "verifier-handoff.tar.gz")
    if argv[:1] == ["check"]:
        return check()
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
