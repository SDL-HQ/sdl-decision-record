"""Corpus coverage: does a conformance corpus vary what this record's rows depend on?

    python3 tools/corpus_coverage.py <run> --corpus $CEDAR_DRT_ROOT [--json]

SPEC §8 states the converse limit of conformance evidence: agreement on a
corpus establishes nothing about a field the corpus does not vary, and the
Cedar corpus varies one policy id. The comparison is computable from what the
record retains, and this computes it.

A *dimension* is a structural feature of a Cedar policy or request that an
engine's evaluation can depend on. The record side asks which dimensions the
rows depend on — read from the retained policy text and the retained inputs,
never from the decisions. The corpus side asks, for each of those, how many
distinct values the corpus takes. A dimension the rows use that the corpus
holds at one value is one the corpus is silent about: an engine that differs
there would agree on every case and be named as established.

The property this yields is `corpus_coverage`, and it has no failed state
beyond malformed input. A shortfall is not a false claim by the record; it is
a limit on what the named conformance evidence establishes. So it reports
established when every dimension the rows depend on is varied by the corpus,
and unknown, naming the silent dimensions, otherwise. Unknown is never a pass.

Extraction on the policy side uses cedarpy's parse of the policy set when
cedarpy is installed (`--parser ast`), so the dimensions are the grammar's own
node keys and an operator this file never anticipated is still recorded; it
falls back to regular expressions over the text (`--parser regex`) otherwise,
which can be fooled by operator-shaped text. The assumption ledger in the
output says which was used. The request side is a walk over JSON either way.
A second grammar needs its own extractor.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dr.canonical import read_jsonl, loads as strict_loads  # noqa: E402  the run is read as the verifier reads it

# --- dimensions ---------------------------------------------------------------
#
# name -> (how to read it from policy text or a request, what "varied" means).
# Every dimension is a set-valued observation. A corpus varies a dimension when
# the union over its cases has at least two distinct values; for a presence
# dimension that means both present and absent occur.

_OPS = [("==", "=="), ("!=", "!="), ("<=", "<="), (">=", ">="), ("<", "<"), (">", ">"),
        ("&&", "&&"), ("||", "||"), (" in ", "in"), (" like ", "like"), (" has ", "has"),
        (".contains(", "contains"), (".containsAll(", "containsAll"), (".containsAny(", "containsAny"),
        ("if ", "if-then-else"), ("!", "not")]
_SCOPES = [(r"\bprincipal\s*==", "principal=="), (r"\bprincipal\s+in\b", "principal in"), (r"\bprincipal\s+is\b", "principal is"),
           (r"\baction\s*==", "action=="), (r"\baction\s+in\b", "action in"),
           (r"\bresource\s*==", "resource=="), (r"\bresource\s+in\b", "resource in"), (r"\bresource\s+is\b", "resource is")]
_EXTN = ["ip(", "decimal(", "datetime(", "duration("]


def _strip_comments(text: str) -> str:
    return re.sub(r"//[^\n]*", "", text)


# Scope-constraint ops and condition-body node keys, as cedarpy's JSON policy
# format names them. Anything else that appears as a node key is recorded as
# itself, so an operator this list does not anticipate is still a value.
_LEAF_KEYS = {"Value", "Var", "Slot", "Unknown"}
_CALL_KEYS = {"ip", "decimal", "datetime", "duration", "offset", "durationSince", "toDate", "toTime",
              "toMilliseconds", "toSeconds", "toMinutes", "toHours", "toDays", "lessThan", "greaterThan",
              "lessThanOrEqual", "greaterThanOrEqual", "isIpv4", "isIpv6", "isLoopback", "isMulticast", "isInRange"}


def _walk(node: Any, d: Dict[str, Set[str]]) -> None:
    """Record every operator, extension call and attribute access in a condition body."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in _LEAF_KEYS:
                if k == "Value":
                    d["literal_type"].add(type(v).__name__ if not isinstance(v, dict) else "entity")
                continue
            if k == ".":
                base = v.get("left", {})
                if isinstance(base, dict) and "Var" in base:
                    d["attribute_access"].add(base["Var"])
                _walk(v, d)
                continue
            if k in _CALL_KEYS:
                d["extension_function"].add(k)
            else:
                d["operator"].add(k)
            _walk(v, d)
    elif isinstance(node, list):
        for x in node:
            _walk(x, d)


def policy_dimensions_from_ast(policy_text: str) -> Dict[str, Set[str]]:
    """Dimensions read from cedarpy's parse of the policy set. Raises if the
    text does not parse; the caller decides whether to fall back."""
    import cedarpy  # local import: the regex path must work without it

    j = json.loads(cedarpy.policies_to_json_str(policy_text))
    pols = list((j.get("staticPolicies") or {}).values())
    tmpl = list((j.get("templates") or {}).values())
    d: Dict[str, Set[str]] = defaultdict(set)
    d["policy_count"].add("1" if len(pols) + len(tmpl) <= 1 else "2+")
    d["policy_id_annotation"].add("present" if any((p.get("annotations") or {}).get("id") for p in pols) else "absent")
    d["template"].add("present" if tmpl else "absent")
    for p in pols + tmpl:
        d["effect"].add(p.get("effect", "?"))
        for head in ("principal", "action", "resource"):
            c = p.get(head) or {}
            op = c.get("op", "All")
            d["scope"].add(f"{head} {op}" if op != "All" else f"{head} All")
            if "entity_type" in c:
                d["scope"].add(f"{head} is")
        conds = p.get("conditions") or []
        d["condition_clause"].add("present" if conds else "absent")
        for c in conds:
            d["condition_kind"].add(c.get("kind", "?"))
            _walk(c.get("body"), d)
    return d


def policy_dimensions(policy_text: str, *, parser: str = "auto") -> Dict[str, Set[str]]:
    """Dimensions of a policy set as sets of observed values. `parser` is
    "ast" (cedarpy, raise if absent), "regex", or "auto" (ast if available)."""
    if parser in ("ast", "auto"):
        try:
            return policy_dimensions_from_ast(policy_text)
        except ImportError:
            if parser == "ast":
                raise
    t = _strip_comments(policy_text)
    d: Dict[str, Set[str]] = defaultdict(set)
    ids = re.findall(r'@id\("([^"]*)"\)', t)
    d["policy_id_annotation"].add("present" if ids else "absent")
    n_pol = len(re.findall(r"\b(permit|forbid)\s*\(", t))
    d["policy_count"].add("1" if n_pol <= 1 else "2+")
    for eff in re.findall(r"\b(permit|forbid)\s*\(", t):
        d["effect"].add(eff)
    body_present = bool(re.search(r"\b(when|unless)\s*\{", t))
    d["condition_clause"].add("present" if body_present else "absent")
    for kw in ("when", "unless"):
        if re.search(rf"\b{kw}\s*\{{", t):
            d["condition_kind"].add(kw)
    for needle, name in _OPS:
        if needle in t:
            d["operator"].add(name)
    for pat, name in _SCOPES:
        if re.search(pat, t):
            d["scope"].add(name)
    for fn in _EXTN:
        if fn in t:
            d["extension_function"].add(fn.rstrip("("))
    for head in ("principal", "resource", "context", "action"):
        if re.search(rf"\b{head}\.[A-Za-z_]", t):
            d["attribute_access"].add(head)
    d["string_literal"].add("present" if re.search(r'"[^"]*"', t) else "absent")
    d["numeric_literal"].add("present" if re.search(r"\b\d+\b", t) else "absent")
    return d


def request_dimensions(req: Dict[str, Any]) -> Dict[str, Set[str]]:
    """Dimensions of one request object (principal/action/resource/context/entities)."""
    d: Dict[str, Set[str]] = defaultdict(set)
    ctx = req.get("context") or {}
    d["context_present"].add("yes" if ctx else "no")
    for k, v in ctx.items():
        d["context_value_type"].add(type(v).__name__)
    ents = req.get("entities") or []
    d["entity_count_bucket"].add("0" if not ents else "1-4" if len(ents) <= 4 else "5+")
    for e in ents:
        if e.get("parents"):
            d["entity_hierarchy"].add("present")
        for v in (e.get("attrs") or {}).values():
            if isinstance(v, dict) and "__extn" in v:
                d["extension_function"].add(v["__extn"].get("fn", "?"))
            d["attribute_value_type"].add(type(v).__name__)
    if not any(e.get("parents") for e in ents):
        d["entity_hierarchy"].add("absent")
    return d


def merge(into: Dict[str, Set[str]], frm: Dict[str, Set[str]]) -> None:
    for k, v in frm.items():
        into[k] |= v


# --- the record side ------------------------------------------------------------

# The emitter's reason for a deny no policy caused (`emitters/cedar.py`). The
# corpus expresses the same outcome as an empty reason list; both are read as
# the naming value "none".
NO_POLICY_REASON = "no-policy-permits"

def _parser_in_use(parser: str) -> str:
    if parser == "regex":
        return "regex"
    try:
        import cedarpy  # noqa: F401
        return "ast"
    except ImportError:
        if parser == "ast":
            raise
        return "regex"


def record_dependencies(run: Path, *, parser: str = "auto") -> Tuple[Dict[str, Set[str]], List[str]]:
    """What the rows depend on, from policy.json and inputs.jsonl. Returns
    (dimensions, assumptions)."""
    assumptions = []
    policy = strict_loads((run / "policy.json").read_text(encoding="utf-8"))
    text = policy.get("policies") if isinstance(policy, dict) else None
    if not isinstance(text, str):
        raise ValueError("policy.json carries no Cedar policy text under 'policies'")
    used = _parser_in_use(parser)
    dims = policy_dimensions(text, parser=used)
    if used == "ast":
        assumptions.append("policy dimensions were read from cedarpy's parse of the policy set; the dimension names are the JSON policy format's node keys")
    else:
        assumptions.append("policy dimensions were read by regular expression over the policy text, not by a Cedar parser")
    lines = [strict_loads(l) for _, l in read_jsonl(run / "inputs.jsonl")]
    types: Dict[str, Set[str]] = defaultdict(set)
    for l in lines:
        if "input" not in l:
            continue
        req = l["input"]
        merge(dims, request_dimensions(req))
        for head in ("principal", "action", "resource"):
            u = req.get(head) or {}
            if isinstance(u, dict) and "type" in u:
                types[head].add(u["type"])
    for head, s in types.items():
        dims[f"{head}_entity_type"] |= {_type_shape(x) for x in s}
    # The rows' reasons name policies. What evaluation depends on is not the
    # spelling of an id but how many distinct policies the reasons can name:
    # one engine naming the single policy of a single-policy set is exercised
    # by any corpus; naming the determining one of several is not.
    rows = [strict_loads(l) for _, l in read_jsonl(run / "decisions.jsonl")]
    ids = {r.get("reason") for r in rows if r.get("reason") and r.get("reason") != NO_POLICY_REASON}
    dims["policy_naming"].add(_naming_bucket(len(ids)))
    if any(r.get("reason") == NO_POLICY_REASON for r in rows):
        dims["policy_naming"].add("none")
    assumptions.append("policy naming is taken from the rows' reason field; a decider whose reason is not a policy id makes this dimension meaningless")
    return dims, assumptions


def _type_shape(t: str) -> str:
    return "namespaced" if "::" in t else "plain"


def _naming_bucket(n_distinct: int) -> str:
    return "none" if n_distinct == 0 else "one" if n_distinct == 1 else "several"


# --- the corpus side ------------------------------------------------------------

def corpus_values(corpus_root: Path, limit: int | None = None, *, parser: str = "auto") -> Tuple[Dict[str, Set[str]], int]:
    """For each dimension, the set of values the corpus takes, and the case count."""
    used = _parser_in_use(parser)
    dims: Dict[str, Set[str]] = defaultdict(set)
    cases = sorted(p for p in (corpus_root / "corpus-tests").glob("*.json") if not p.name.endswith(".entities.json"))
    if limit:
        cases = cases[:limit]
    for case in cases:
        t = json.loads(case.read_text(encoding="utf-8"))
        pol = corpus_root / t["policies"]
        merge(dims, policy_dimensions(pol.read_text(encoding="utf-8"), parser=used))
        ents_path = corpus_root / t["entities"]
        ents = json.loads(ents_path.read_text(encoding="utf-8")) if ents_path.exists() else []
        types: Dict[str, Set[str]] = defaultdict(set)
        case_ids: Set[str] = set()
        for req in t.get("requests", []):
            r = dict(req)
            r["entities"] = ents
            merge(dims, request_dimensions(r))
            for head in ("principal", "action", "resource"):
                u = req.get(head) or {}
                if isinstance(u, dict) and "type" in u:
                    types[head].add(u["type"])
            reasons = req.get("reason", []) or []
            case_ids |= {str(r) for r in reasons}
            if not reasons:
                dims["policy_naming"].add("none")
        if case_ids:
            dims["policy_naming"].add(_naming_bucket(len(case_ids)))
        for head, s in types.items():
            dims[f"{head}_entity_type"] |= {_type_shape(x) for x in s}
    return dims, len(cases)


# --- the comparison -------------------------------------------------------------

def compare(record: Dict[str, Set[str]], corpus: Dict[str, Set[str]]) -> Dict[str, Any]:
    """Which values the rows exercise did the corpus never exercise?

    The rule is subset, not variety: a dimension is covered when every value
    the rows use appears somewhere in the corpus, because an engine that
    mishandled that value would then have disagreed on at least one case. A
    corpus that holds one value is not silent about that value; it is silent
    about every other.
    """
    silent, covered = [], []
    for name, used in sorted(record.items()):
        if not used:
            continue
        have = corpus.get(name, set())
        missing = sorted(used - have)
        if missing:
            silent.append({"dimension": name, "rows_use": sorted(used)[:8], "corpus_never_takes": missing[:8], "corpus_holds": sorted(have)[:4]})
        else:
            covered.append(name)
    return {"covered": covered, "silent": silent}


def check(run: Path, corpus_root: Path, limit: int | None = None, *, parser: str = "auto") -> Tuple[str, str, Dict[str, Any]]:
    """(state, detail, report) for the corpus_coverage property."""
    rec, assumptions = record_dependencies(run, parser=parser)
    cor, n = corpus_values(corpus_root, limit, parser=parser)
    cmp = compare(rec, cor)
    report = {"corpus_cases": n, "record_dimensions": {k: sorted(v) for k, v in rec.items() if v},
              "comparison": cmp, "assumptions": assumptions}
    if cmp["silent"]:
        names = [s["dimension"] for s in cmp["silent"]]
        return ("unknown",
                f"the corpus ({n} cases) exercises every value these rows use on {len(cmp['covered'])} of {len(cmp['covered']) + len(names)} dimensions and never exercises some value they use on {names}: an engine that differed there would agree on every case",
                report)
    return ("established", f"the corpus ({n} cases) exercises every value these rows use on every one of the {len(cmp['covered'])} dimensions they depend on", report)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run_directory")
    ap.add_argument("--corpus", required=True, help="CEDAR_DRT_ROOT: a directory holding corpus-tests/")
    ap.add_argument("--limit", type=int, default=None, help="read only the first N cases")
    ap.add_argument("--parser", choices=("auto", "ast", "regex"), default="auto", help="ast needs cedarpy; auto falls back to regex")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    state, detail, report = check(Path(a.run_directory), Path(a.corpus), a.limit, parser=a.parser)
    if a.json:
        print(json.dumps({"property": "corpus_coverage", "state": state, "detail": detail, **report}, indent=1))
    else:
        print(f"corpus_coverage: {state}\n  {detail}")
        for s in report["comparison"]["silent"]:
            print(f"  silent: {s['dimension']}  rows use {s['rows_use']}  corpus never takes {s['corpus_never_takes']}")
        for a_ in report["assumptions"]:
            print(f"  assumed: {a_}")
    return 0 if state == "established" else 1


if __name__ == "__main__":
    raise SystemExit(main())
