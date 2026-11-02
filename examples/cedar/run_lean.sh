#!/usr/bin/env bash
# The Cedar records under the Lean definitional engine: the proved specification as a decider.
#
#   CEDAR_LEAN_CLI=/path/to/cedar-lean-cli CEDAR_LEAN_SPEC_COMMIT=<cedar-spec commit> \
#   CEDAR_DRT_ROOT=/path/to/cedar-drt bash examples/cedar/run_lean.sh
#
# Needs the cedar-lean-cli binary built from cedar-spec (its Lean toolchain's
# lib directory on LD_LIBRARY_PATH), cedarpy, and the conformance corpus. The
# full-corpus run is `tools/cedar_conformance.py --engine lean` and takes about
# an hour at one process per request; this script reads its result file and
# does not re-run it. Writes examples/cedar/LEAN.md from what the commands
# print and examples/cedar/out/toolcalls-lean, a record made by the Lean engine.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${CEDAR_LEAN_CLI:?set CEDAR_LEAN_CLI to the built cedar-lean-cli binary}"
: "${CEDAR_LEAN_SPEC_COMMIT:?set CEDAR_LEAN_SPEC_COMMIT to the cedar-spec commit it was built from}"
: "${CEDAR_SPEC_ROOT:?set CEDAR_SPEC_ROOT to the cedar-spec checkout the binary was built from}"
: "${CEDAR_DRT_ROOT:?set CEDAR_DRT_ROOT to the conformance corpus directory}"
OUT=examples/cedar/out
T=examples/cedar/LEAN.md
KEY="--key examples/keys/example-signing-key.pem --key-id example-2026-10 --issued-at 2026-10-21T05:00:00Z"
REG=examples/keys/registry.json
EV=examples/cedar/conformance
LEANV="cedar-lean-${CEDAR_LEAN_SPEC_COMMIT:0:12}"
{
  echo "# Transcript: the Cedar records under the Lean definitional engine"
  echo
  echo "Captured by \`bash examples/cedar/run_lean.sh\`. The engine is cedar-spec's Lean formalisation of Cedar behind \`cedar-lean-cli\` (cedar-spec commit \`${CEDAR_LEAN_SPEC_COMMIT:0:12}\`, built here from source; the CLI reports \`$("$CEDAR_LEAN_CLI" --version)\`, the Cedar crate it parses with), as the decider \`cedar-authorizer@$LEANV\` (\`emitters/cedar_lean.py\`). The cedarpy records were made under $(python3 -c 'import importlib.metadata as m; print("cedarpy", m.version("cedarpy"))'). Output as printed, exit codes as returned."
  echo
} > "$T"
show() {
  local line="$*"; line="${line//$CEDAR_LEAN_CLI/\$CEDAR_LEAN_CLI}"
  echo '```' >> "$T"; echo "\$ $line" >> "$T"
  set +e; "$@" >> "$T" 2>&1; rc=$?; set -e
  echo "[exit $rc]" >> "$T"; echo '```' >> "$T"; echo >> "$T"
}
note() { echo "$1" >> "$T"; echo >> "$T"; }

note "## 1. The Lean engine over Cedar's own corpus"
note "Every request of every generated test, decision and reason set and error presence compared with what the corpus expects, by the same rule as the cedarpy engines (\`tools/cedar_conformance.py --engine lean\`). The result file is the evidence a record may name (\`$EV/$LEANV.json\`); its figures:"
show python3 -c "import json; d=json.load(open('$EV/$LEANV.json')); print(json.dumps({k: d[k] for k in ('engine','tests','requests','agree_decision_reason_and_error_presence','disagree','allow_where_corpus_expects_deny','deny_where_corpus_expects_allow','by_outcome','seconds')}, indent=1))"
note "The evidence digest a record names:"
show python3 tools/cedar_engine_drift.py digest $EV/$LEANV.json

note "**What this agreement does and does not establish.** The corpus's expected values are produced by the Rust engine, not by the Lean model: cedar-spec's \`abac\` fuzz target computes them with \`cedar_policy::Authorizer\` before dumping each test. But every dumped input first passed \`run_auth_test\`, which asserts that the Rust response and the Lean response are equal and panics otherwise, so the corpus is a filtered record of inputs on which the two already agreed. Agreement here is therefore the expected outcome rather than evidence about Cedar: what it establishes is that this decider's wiring — entity-id escaping, request construction, reason mapping, the agreement rule — reproduces the published expectations on every one of the 45,416 requests. That is a statement about this harness, and it is the only statement the figure supports."
show grep -n "re-parsed\|Authorizer::new\|new_id(PolicyId::new" $CEDAR_SPEC_ROOT/cedar-drt/fuzz/fuzz_targets/abac.rs
show grep -n -A 3 "assert_eq!" $CEDAR_SPEC_ROOT/cedar-drt/src/tests.rs

note "## 2. What the corpus cannot say: policy naming"
note "The corpus exercises exactly one policy identifier. Measured over all 5,677 generated tests and all of their expected reason and error entries:"
show python3 - <<'EOF'
import json, glob, collections, os
root = os.environ["CEDAR_DRT_ROOT"] + "/corpus-tests"
pol = glob.glob(root + "/*.cedar")
with_id = [f for f in pol if "@id" in open(f).read()]
any_annot = [f for f in pol if any(l.lstrip().startswith("@") for l in open(f))]
c = collections.Counter()
for f in glob.glob(root + "/*.json"):
    if f.endswith(".entities.json"): continue
    try: d = json.load(open(f))
    except Exception: continue
    for r in d.get("requests", []):
        for name in r.get("reason", []) + r.get("errors", []):
            c[name] += 1
print(f"corpus policy files:                {len(pol)}")
print(f"  carrying an @id annotation:       {len(with_id)}")
print(f"  carrying any annotation at all:   {len(any_annot)}")
print(f"distinct policy ids ever expected:  {len(c)}  -> {dict(c)}")
EOF
note "The generator renames every policy to \`policy0\` on purpose before computing expectations — \`abac.rs\`: *\"When the corpus is re-parsed, the policy will be given id policy0\"* — because the corpus format does not preserve policy identity. So no run against this corpus, by any engine, can say anything about how an engine names policies: there is one name, and every engine produces it. An engine named as established on 45,416 of 45,416 is named on evidence that is structurally silent about a field this repository's own records depend on in every row."

note "## 3. A cedarpy record replayed under the Lean engine"
note "The record names \`cedar-authorizer@cedarpy-4.12.2\` and, as established, cedarpy-4.8.7; it does not name the Lean engine. Replay refuses, as it must: a different procedure proves nothing about this one."
show python3 -m dr.verify $OUT/toolcalls-canonical --registry $REG --replay emitters.cedar_lean

note "## 4. A record made by the Lean engine over the same forty calls, naming cedarpy-4.12.2 as established"
D4122=$(python3 tools/cedar_engine_drift.py digest $EV/cedarpy-4.12.2.json)
rm -rf $OUT/toolcalls-lean
show python3 -m emitters.cedar_lean --policy examples/cedar/policy-canonical.json --inputs examples/cedar/inputs-toolcalls.jsonl --out $OUT/toolcalls-lean --record-id cedar-toolcalls-lean-2026-10-21 --profile benchmark $KEY --established-version cedarpy-4.12.2=$D4122
note "Verified under its own engine:"
show python3 -m dr.verify $OUT/toolcalls-lean --registry $REG --replay emitters.cedar_lean
note "Replayed under cedarpy-4.12.2, which the record names as established by a run that agrees on all 45,416 corpus requests, with that run supplied. The name is accepted and the replay then fails at the first row: the Lean front end reports a policy by its \`@id\` annotation (\`p0\`) and cedarpy by its position (\`policy0\`). The decisions agree on every row; the reason strings differ on every row that names a policy. The corpus the name rests on has no \`@id\` annotations, so 45,416 of 45,416 said nothing about them."
show python3 -m dr.verify $OUT/toolcalls-lean --registry $REG --replay emitters.cedar --conformance-evidence $EV/cedarpy-4.12.2.json
note "The forty rows side by side, Lean against cedarpy, outcome and reason:"
show python3 - <<'EOF'
import json
L = [json.loads(l) for l in open("examples/cedar/out/toolcalls-lean/decisions.jsonl")]
C = [json.loads(l) for l in open("examples/cedar/out/toolcalls-canonical/decisions.jsonl")]
same_outcome = sum(a["outcome"] == b["outcome"] for a, b in zip(L, C))
same_reason = sum(a["reason"] == b["reason"] for a, b in zip(L, C))
print(f"{len(L)} rows: outcome agrees on {same_outcome}, reason agrees on {same_reason}")
for a, b in zip(L, C):
    if a["outcome"] != b["outcome"] or (a["reason"] != b["reason"] and a["reason"].replace("p", "policy") != b["reason"]):
        print(f"  seq {a['seq']}: lean {a['outcome']} {a['reason']} {a.get('ext')}  |  cedarpy {b['outcome']} {b['reason']} {str(b.get('ext'))[:120]}")
EOF
note "## 5. Where the difference actually is"
note "Not between the Lean model and the Rust engine. The determining-policy ids both front ends report come from the Rust parser; what differs is that cedarpy ignores an \`@id\` annotation and assigns a positional id, while the \`cedar-policy\` crate the Lean CLI parses with honours it. The same two-policy set through each:"
show python3 -c "
import cedarpy, importlib.metadata as m
policies = '@id(\"p0\")\npermit(principal, action, resource) when { context.x == 1 };\n@id(\"p1\")\npermit(principal, action, resource) when { context.x == 2 };\n'
schema = 'entity U; action a appliesTo { principal: U, resource: U, context: { x: Long } };'
req = {'principal': 'U::\"x\"', 'action': 'Action::\"a\"', 'resource': 'U::\"y\"', 'context': {'x': 1}}
r = cedarpy.is_authorized(req, policies, [], schema)
print('cedarpy', m.version('cedarpy'), '->', str(r.decision).split('.')[-1], 'reasons', sorted(r.diagnostics.reasons))
"
note "So the forty-row difference is between two invocation paths to Cedar, which §4 of the specification already calls two deciders, and the decisions themselves agree on every row. It is not a semantic divergence between an implementation and its proved specification, and nothing here should be described as one."

note "Row 36 is the one row whose reason differs for another cause: the input gives \`amount\` as a string where the schema types it Long. cedarpy, handed the schema, refuses to build the request (\`request-invalid\`); the Lean CLI builds the request without schema validation, evaluates, and the one policy that could permit errors on the comparison, so the decision is DENY with that policy erroring. Same outcome, a different route to it, and a difference between front ends, not between the engines' semantics."

echo "wrote $T"
