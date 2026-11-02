"""Re-derive a decision record's decisions with only published software in the trust path.

    python3 tools/rederive.py examples/cedar/out/toolcalls-canonical
    python3 tools/rederive.py <run> --json
    python3 tools/rederive.py <run> --steps        # how many rows each producer-side step changes

What this is, and what it is not. `dr.verify --replay emitters.cedar` executes
the producer's decider: to check the record you run the producer's code. This
tool does not. It reads the record's retained policy, entities, canonicalisation
setting and inputs, rebuilds the engine request itself from the specification,
drives the published engine (cedarpy, or cedar-lean-cli) directly, and compares
with the rows. The producer's emitter is not importable on this path and the
tool refuses to run if it is: see `BLOCKED_PREFIXES` and
`tests/test_rederive.py::test_the_producer_emitter_cannot_be_imported_on_this_path`.

The roof. No amount of re-derivation establishes that the retained inputs are
what the system actually saw at decision time. That is the execution seam; it
is outside this tool and it bounds everything the tool reports. A record whose
inputs were fabricated re-derives perfectly.

Every piece of information the request rebuild needs comes from one of three
places, and the tool labels which: the record (R), the published specification
of the grammar or of this format (S), or an assumption this tool had to make
because neither supplied it (A). The assumptions are the measurement: each is
a place an independent implementer would have had to guess, and a guess that
happens to match the producer is not re-derivation. `ASSUMPTIONS` carries them
with what each would cost to remove.

Two tiers, reported separately. Outcome agreement is the strong claim. Reason
agreement is vocabulary-dependent: a difference traceable to how an engine's
front end names policies is reported `unknown`, not `failed`,
because the record's reason and the engine's are then two spellings of one
fact rather than a disagreement about the decision.
"""

from __future__ import annotations

import argparse
import importlib.abc
import importlib.machinery
import json
import posixpath
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]

# --- the demonstration that the producer's code is not in the trust path -----
# A meta-path finder placed ahead of every other importer. Importing the
# producer's emitters, or the reference verifier's replay machinery, raises.
# This is installed before cedarpy is imported and is not removed.
BLOCKED_PREFIXES = ("emitters", "dr.verify", "dr.emit")


class ProducerCodeBlocked(ImportError):
    pass


class _Blocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        for p in BLOCKED_PREFIXES:
            if fullname == p or fullname.startswith(p + "."):
                raise ProducerCodeBlocked(
                    f"re-derivation refuses to import {fullname!r}: the producer's decision code "
                    f"must not be in this trust path (tools/rederive.py BLOCKED_PREFIXES)"
                )
        return None


def install_blocker() -> None:
    if not any(isinstance(f, _Blocker) for f in sys.meta_path):
        sys.meta_path.insert(0, _Blocker())


install_blocker()

# `dr.canonical` is the format's own canonical-bytes definition (SPEC §2), not
# decision code; it is needed to recompute input digests and is published.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from dr.canonical import canonical_input, digest_obj, read_jsonl, loads as strict_loads  # noqa: E402

# --- the assumption ledger ---------------------------------------------------
# Each entry: a pre-processing decision the *record* does not determine, why, and
# what would remove the need for it. SPEC.md §8 published the Cedar request
# mapping on 24 October 2026, after the measurement in experiments/rederivability
# was first taken, so several of these stopped being guesses on that date. They
# remain listed because the specification is not the artefact a verifier holds: a
# signed record carries the mode's name and not its content, so a record and the
# specification can drift apart. Only the policy object closes that.
ASSUMPTIONS: List[Dict[str, str]] = [
    {
        "id": "A1",
        "about": "which context keys the url-v1 mode applies to, and which operation each receives",
        "why": "when this was measured SPEC.md did not mention url-v1 at all and the map existed only as a "
               "variable name in emitters/cedar.py's docstring; SPEC.md §8 has listed the keys and their "
               "operations since 24 October 2026. The policy object still carries the mode's name and not "
               "its content, so the map is published and no digest covers it.",
        "assumed": "host-kind: host, name, domain, recipient_domain; path-kind: url_path, path; "
                   "upper: currency; lower: scheme — inferred from the key names and the prose",
        "removed_by": "carrying the key map in the policy object (canonical_keys), so the digest covers it",
    },
    {
        "id": "A2",
        "about": "that entity ids are canonicalised only for entity types whose name ends in 'Host'",
        "why": "stated in the emitter's docstring and, since 24 October 2026, in SPEC.md §8; the suffix test "
               "remains a producer convention and the policy object does not say which types carry "
               "host-shaped ids",
        "assumed": "principal and resource only, type name ending in 'Host', using the host operation",
        "removed_by": "declaring the canonicalised entity types in the policy object",
    },
    {
        "id": "A3",
        "about": "which keys of the retained input are part of the engine request",
        "why": "the retained input carries keys the request does not (kind, note, entities); until SPEC.md "
               "§8 declared the request shape on 24 October 2026 no published text said which were decision "
               "inputs and which were commentary, and the record itself still does not",
        "assumed": "principal, action, resource and context form the request; entities is the caller-asserted "
                   "entity set; kind and note are commentary and are dropped",
        "removed_by": "retaining the constructed request beside the raw input, or declaring the request shape",
    },
    {
        "id": "A4",
        "about": "the exact host and path operations",
        "why": "the docstring says 'lower-cases and IDNA-encodes', 'strips a trailing dot', 'normalises . "
               "and .. after percent-decoding'; SPEC.md §8 has fixed the order, the leading slash and the "
               "encoding-failure fallback since 24 October 2026, by description and not by reference to a "
               "standard",
        "assumed": "strip whitespace, strip trailing dots, lower-case, then Python's 'idna' codec, falling back "
                   "to the lower-cased form on UnicodeError; percent-decode once then posixpath.normpath, "
                   "re-attaching a leading slash when the input had one",
        "removed_by": "specifying the operations by reference to a standard (RFC 5891 for IDNA, RFC 3986 §6 for paths)",
    },
    {
        "id": "A6",
        "about": "for a conformance record, how a corpus test file becomes an engine request",
        "why": "the record's retained input is a pointer ({test, request}), not an input. The decision inputs live "
               "in the corpus, which the policy names by per-file digest but does not carry. Nothing published says "
               "how a test file's fields become a request, which policy/schema format each extension implies, or "
               "which file of the test supplies the entities",
        "assumed": "the test JSON's requests[i] gives principal, action, resource and context directly; "
                   "policies are Cedar text unless the filename ends .json/.cedarjson; the schema is JSON when it "
                   "ends .json and Cedar schema text otherwise; entities come from the test's entities file",
        "removed_by": "retaining the constructed request per row, or carrying the corpus in the record",
    },
    {
        "id": "A5",
        "about": "how the reason string is derived from the engine's diagnostics",
        "why": "the emitter's docstring describes it, and SPEC.md §8 has defined it for this grammar since "
               "24 October 2026; before that the replay section said the comparison was on (outcome, reason) "
               "without saying how a reason is formed",
        "assumed": "sorted determining policy ids joined with '+'; 'allow' when ALLOW with none; "
                   "'no-policy-permits' when DENY with none; 'request-invalid' when the engine refuses the request",
        "removed_by": "defining the reason derivation in the specification, per grammar",
    },
]

# --- the request rebuild, written from the published text alone ---------------
# Mirrors no producer module: `emitters` cannot be imported here at all.
ASSUMED_KEY_MAP = {  # A1
    "host": "host", "name": "host", "domain": "host", "recipient_domain": "host",
    "url_path": "path", "path": "path", "currency": "upper", "scheme": "lower",
}


def op_host(h: str) -> str:  # A4
    h = h.strip().rstrip(".").lower()
    try:
        return h.encode("idna").decode("ascii")
    except UnicodeError:
        return h


def op_path(p: str) -> str:  # A4
    decoded = urllib.parse.unquote(p)
    out = posixpath.normpath(decoded)
    return "/" + out.lstrip("/") if decoded.startswith("/") else out


OPS = {"host": op_host, "path": op_path, "upper": str.upper, "lower": str.lower}


def apply_mode(obj: Any, mode: str, touched: Optional[List[str]] = None, where: str = "") -> Any:
    """url-v1 over a structure, recording which paths it changed."""
    if mode == "none":
        return obj
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kind = ASSUMED_KEY_MAP.get(k)
            if isinstance(v, str) and kind:
                nv = OPS[kind](v)
                if nv != v and touched is not None:
                    touched.append(f"{where}{k} ({kind}): {v!r} -> {nv!r}")
                out[k] = nv
            else:
                out[k] = apply_mode(v, mode, touched, f"{where}{k}.")
        return out
    if isinstance(obj, list):
        return [apply_mode(x, mode, touched, f"{where}[{i}].") for i, x in enumerate(obj)]
    return obj


def rebuild_request(raw: Dict[str, Any], policy: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    """(request, entities, what the rebuild changed) from the retained input and the retained policy."""
    mode = policy.get("canonicalise", "none")
    touched: List[str] = []
    item = apply_mode(raw, mode, touched)
    if mode != "none":  # A2
        for k in ("principal", "resource"):
            e = item.get(k)
            if isinstance(e, dict) and isinstance(e.get("type"), str) and e["type"].endswith("Host"):
                nid = op_host(e["id"])
                if nid != e["id"]:
                    touched.append(f"{k}.id (entity-type Host): {e['id']!r} -> {nid!r}")
                item[k] = {"type": e["type"], "id": nid}
    request = {  # A3
        "principal": item["principal"], "action": item["action"],
        "resource": item["resource"], "context": item.get("context") or {},
    }
    source = policy.get("entities", "caller")
    entities = list(policy.get("store") or []) if source == "store" else list(item.get("entities") or [])
    return request, entities, touched


def rel(run: Path) -> str:
    """A run directory as the repository names it, never as this checkout happens to sit.

    An absolute path in a generated artifact makes that artifact depend on where the clone lives, and
    a checkout under a scratchpad would write its container path into the repository.
    """
    try:
        return str(Path(run).resolve().relative_to(ROOT))
    except ValueError:
        return str(run)


def _resolve_corpus(policy: Dict[str, Any]):
    """A conformance record names its corpus by per-file digest and does not carry it.

    The corpus must be obtained out of band. The digests then establish that the one in hand is the
    one the record was made against, which is the part the record does supply.
    """
    import os

    root = policy.get("root", "")
    if isinstance(root, str) and root.startswith("$"):
        env = os.environ.get(root[1:], "")
        if not env:
            return None, (f"the record's policy names its corpus as {root} and does not carry it; "
                          f"set {root[1:]} to a checkout whose files match the 1200+ digests in the policy")
        root = env
    rp = Path(root)
    if not rp.is_dir():
        return None, f"corpus root {root!r} is not a directory"
    files = policy.get("files") or {}
    differing = [f for f, want in list(files.items()) if not (rp / f).exists() or digest_obj_file(rp / f) != want]
    if differing:
        return None, (f"the corpus under {root} is not the one the record names: {len(differing)} of "
                      f"{len(files)} files differ (first {differing[:2]})")
    return rp, f"corpus resolved from {policy.get('root')}, all {len(files)} named file digests match"


def digest_obj_file(path: Path) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def rebuild_conformance_request(raw: Dict[str, Any], root: Path):
    """A corpus pointer ({test, request}) into an engine request. Every step here is assumption A6."""
    test = json.loads((root / raw["test"]).read_text())
    r = test["requests"][raw["request"]]
    request = {"principal": r["principal"], "action": r["action"], "resource": r["resource"],
               "context": r.get("context", {})}
    ptxt = (root / test["policies"]).read_text()
    if test["policies"].endswith((".json", ".cedarjson")):
        import cedarpy

        policies = cedarpy.policies_from_json_str(ptxt)
    else:
        policies = ptxt
    schema = None
    if test.get("schema"):
        stxt = (root / test["schema"]).read_text()
        schema = json.loads(stxt) if test["schema"].endswith(".json") else stxt
    entities = json.loads((root / test["entities"]).read_text())
    return request, entities, policies, schema, []


# --- engines (published software only) ---------------------------------------
def engine_cedarpy(request, policies, entities, schema):
    import cedarpy
    from importlib.metadata import version

    try:
        res = cedarpy.is_authorized(request, policies, entities, schema)
    except Exception as exc:
        return "DENY", "request-invalid", [], f"cedarpy-{version('cedarpy')}", str(exc)[:200]
    decision = str(res.decision)
    reasons = sorted(res.diagnostics.reasons)
    errors = [str(e)[:200] for e in res.diagnostics.errors]
    if decision.endswith("Allow"):  # A5
        return "ALLOW", "+".join(reasons) if reasons else "allow", errors, f"cedarpy-{version('cedarpy')}", None
    if decision.endswith("Deny"):
        return "DENY", "+".join(reasons) if reasons else "no-policy-permits", errors, f"cedarpy-{version('cedarpy')}", None
    return "DENY", "request-invalid", errors, f"cedarpy-{version('cedarpy')}", decision


ENGINES = {"cedarpy": engine_cedarpy}


# --- reason tiering ----------------------------------------------------
def reason_tier(row_reason: Optional[str], got_reason: Optional[str], policies_text: str) -> str:
    """'agree', 'vocabulary' (report unknown) or 'differ' (report failed)."""
    if row_reason == got_reason:
        return "agree"
    if not isinstance(row_reason, str) or not isinstance(got_reason, str):
        return "differ"
    a, b = sorted(row_reason.split("+")), sorted(got_reason.split("+"))
    if len(a) != len(b):
        return "differ"
    # positional ids (policyN) against @id annotations, in declaration order
    declared = [ln.split('"')[1] for ln in policies_text.splitlines() if ln.strip().startswith("@id(")]  # not JSON Lines: Cedar text
    positional = [f"policy{i}" for i in range(len(declared))]
    fwd = dict(zip(declared, positional))
    rev = dict(zip(positional, declared))
    if [fwd.get(x, x) for x in a] == [fwd.get(x, x) for x in b]:
        return "vocabulary"
    if [rev.get(x, x) for x in a] == [rev.get(x, x) for x in b]:
        return "vocabulary"
    return "differ"


def rederive(run: Path, engine: str = "cedarpy") -> Dict[str, Any]:
    record = strict_loads((run / "record.json").read_text(encoding="utf-8"))
    rows = [strict_loads(l) for _, l in read_jsonl(run / "decisions.jsonl")]
    policy = strict_loads((run / "policy.json").read_text(encoding="utf-8"))
    lines = [strict_loads(l) for _, l in read_jsonl(run / "inputs.jsonl")]
    inputs = {x["seq"]: x["input"] for x in lines if "seq" in x}

    conformance = policy.get("corpus") == "cedar-integration-tests"
    if policy.get("engine") != "cedar" and not conformance:
        return {"run": rel(run), "supported": False,
                "why": f"policy.engine is {policy.get('engine')!r} and policy.corpus is {policy.get('corpus')!r}; "
                       "this tool drives Cedar engines only"}
    corpus_root = None
    corpus_note = None
    if conformance:
        corpus_root, corpus_note = _resolve_corpus(policy)
        if corpus_root is None:
            return {"run": rel(run), "supported": False, "why": corpus_note}

    out_rows, changed_any, tier_counts = [], 0, {"agree": 0, "vocabulary": 0, "differ": 0}
    outcome_agree = 0
    for row in rows:
        raw = inputs.get(row["seq"])
        if raw is None:
            out_rows.append({"seq": row["seq"], "status": "no retained input"})
            continue
        digest_ok = digest_obj(raw) == row["input_digest"]
        raw = canonical_input(raw)  # re-derive the value the digest covers, as replay does (SPEC §2)
        if conformance:
            request, entities, policies_text, schema_text, touched = rebuild_conformance_request(raw, corpus_root)
        else:
            request, entities, touched = rebuild_request(raw, policy)
            policies_text, schema_text = policy["policies"], policy["schema"]
        outcome, reason, errors, engine_id, note = ENGINES[engine](request, policies_text, entities, schema_text)
        tier = reason_tier(row.get("reason"), reason, policies_text)
        tier_counts[tier] += 1
        if outcome == row["outcome"]:
            outcome_agree += 1
        if touched:
            changed_any += 1
        out_rows.append({
            "seq": row["seq"], "input_digest_matches": digest_ok,
            "row": [row["outcome"], row.get("reason")], "rederived": [outcome, reason],
            "outcome": "agree" if outcome == row["outcome"] else "differ",
            "reason": tier, "rebuild_changed": touched, "engine_note": note,
        })
    return {
        "run": rel(run),
        "supported": True,
        "record_decider": f"{record['decider']['id']}@{record['decider']['version']}",
        "engine_driven": engine,
        "rows": len(rows),
        "outcome_agree": outcome_agree,
        "outcome_differ": len(rows) - outcome_agree,
        "reason_agree": tier_counts["agree"],
        "reason_unknown_vocabulary": tier_counts["vocabulary"],
        "reason_differ": tier_counts["differ"],
        "rows_the_rebuild_changed": changed_any,
        "input_digests_all_match": all(r.get("input_digest_matches") for r in out_rows if "input_digest_matches" in r),
        "assumptions_required": (["A6", "A5"] if conformance else [a["id"] for a in ASSUMPTIONS if a["id"] != "A6"]),
        "corpus": corpus_note,
        "per_row": out_rows,
    }


def step_impact(run: Path) -> Dict[str, Any]:
    """How many rows each producer-side step actually changes, per step, over this run's inputs."""
    policy = strict_loads((run / "policy.json").read_text(encoding="utf-8"))
    lines = [strict_loads(l) for _, l in read_jsonl(run / "inputs.jsonl")]
    mode = policy.get("canonicalise", "none")
    counts = {k: 0 for k in ("host", "path", "upper", "lower", "entity_id_host", "dropped_keys", "entity_source_substitution")}
    detail: Dict[str, List[str]] = {k: [] for k in counts}
    for x in lines:
        raw = x["input"]
        seen = set()
        if mode != "none":
            touched: List[str] = []
            apply_mode(raw, mode, touched)
            for t in touched:
                kind = t.split("(")[1].split(")")[0]
                if kind in counts and kind not in seen:
                    counts[kind] += 1; seen.add(kind)
                    if len(detail[kind]) < 3: detail[kind].append(f"seq {x['seq']}: {t}")
            for k in ("principal", "resource"):
                e = raw.get(k)
                if isinstance(e, dict) and str(e.get("type", "")).endswith("Host") and op_host(e["id"]) != e["id"]:
                    if "entity_id_host" not in seen:
                        counts["entity_id_host"] += 1; seen.add("entity_id_host")
                        if len(detail["entity_id_host"]) < 3:
                            detail["entity_id_host"].append(f"seq {x['seq']}: {k}.id {e['id']!r} -> {op_host(e['id'])!r}")
        dropped = sorted(set(raw) - {"principal", "action", "resource", "context", "entities"})
        if dropped:
            counts["dropped_keys"] += 1
            if len(detail["dropped_keys"]) < 3: detail["dropped_keys"].append(f"seq {x['seq']}: {dropped}")
        if policy.get("entities", "caller") == "store" and raw.get("entities"):
            counts["entity_source_substitution"] += 1
            if len(detail["entity_source_substitution"]) < 3:
                detail["entity_source_substitution"].append(f"seq {x['seq']}: {len(raw['entities'])} caller entities ignored for the policy's store")
    return {"run": rel(run), "mode": mode, "rows": len(lines), "rows_changed_by_step": counts, "examples": detail}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run")
    ap.add_argument("--engine", default="cedarpy", choices=sorted(ENGINES))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--steps", action="store_true", help="report how many rows each producer-side step changes")
    a = ap.parse_args(argv)
    run = Path(a.run)
    res = step_impact(run) if a.steps else rederive(run, a.engine)
    if a.json:
        print(json.dumps(res, indent=1))
        return 0
    if a.steps:
        print(f"{res['run']}  mode={res['mode']}  rows={res['rows']}")
        for k, v in res["rows_changed_by_step"].items():
            print(f"  {k:30s} {v:5d} of {res['rows']}")
            for e in res["examples"][k]:
                print(f"      {e}")
        return 0
    if not res["supported"]:
        print(res["why"]); return 2
    print(f"{res['run']}  record names {res['record_decider']}  driving {res['engine_driven']} directly")
    print(f"  rows                          {res['rows']}")
    print(f"  outcome agree                 {res['outcome_agree']} / {res['rows']}")
    print(f"  reason agree                  {res['reason_agree']}")
    print(f"  reason unknown (vocabulary)   {res['reason_unknown_vocabulary']}")
    print(f"  reason differ                 {res['reason_differ']}")
    print(f"  rows the rebuild changed      {res['rows_the_rebuild_changed']}")
    print(f"  input digests all match       {res['input_digests_all_match']}")
    print(f"  assumptions required          {', '.join(res['assumptions_required'])}  (see ASSUMPTIONS)")
    for r in res["per_row"]:
        if r.get("outcome") == "differ" or r.get("reason") == "differ":
            print(f"    seq {r['seq']}: row {r['row']} rederived {r['rederived']}")
    return 0 if res["outcome_differ"] == 0 and res["reason_differ"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
