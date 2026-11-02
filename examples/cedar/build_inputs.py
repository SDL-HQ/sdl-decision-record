"""Build the example's policies and labelled inputs.

    python3 examples/cedar/build_inputs.py

Writes, beside this file: policy-none.json and policy-url-v1.json (the same
schema and policy set, canonicalisation off and on), inputs-toolcalls.jsonl
(the agent's privileged calls, labelled with the decision the policy's author
intends). Cedar's own conformance requests are a separate emitter,
emitters/cedar_conformance.py, whose policy is the pinned corpus itself.
Timestamps are fixed so the records reproduce byte for byte.

The intended labels on the tool calls are the author's and are the point of
the exercise: where the decider's outcome under "none" disagrees with the
intent and under "url-v1" agrees, the argument was the attack surface; where
it disagrees under both, the policy or the entity design is. The adversarial
rows name the mechanism in `note`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

TS = "2026-10-20T01:00:00Z"
SCHEMA = (HERE / "schema.cedarschema").read_text()
POLICIES = (HERE / "policies.cedar").read_text()


def ent(t, i, **attrs):
    return {"uid": {"type": t, "id": i}, "attrs": attrs, "parents": []}


ANALYST = ent("Agentic::Agent", "analyst-7", tenant="acme", role="analyst", mail_domain="acme.example")
OPERATOR = ent("Agentic::Agent", "operator-2", tenant="acme", role="operator", mail_domain="acme.example")
OPS = ent("Agentic::Agent", "ops-1", tenant="acme", role="ops", mail_domain="acme.example")
# the gate's own host store: these are what the gate knows, keyed by canonical name
STORE_HOSTS = {
    "api.example.com": ent("Agentic::Host", "api.example.com", name="api.example.com", allowlisted=True),
    "docs.example.com": ent("Agentic::Host", "docs.example.com", name="docs.example.com", allowlisted=True),
    "evil.example.net": ent("Agentic::Host", "evil.example.net", name="evil.example.net", allowlisted=False),
    "xn--pi-5kc.example.com": ent("Agentic::Host", "xn--pi-5kc.example.com", name="xn--pi-5kc.example.com", allowlisted=False),  # аpi with a Cyrillic а
}
WORKSPACE = ent("Agentic::Path", "ws", root="/workspace", path="/workspace")
MAIL_ACME = ent("Agentic::Mailbox", "acme", domain="acme.example")
MAIL_OTHER = ent("Agentic::Mailbox", "other", domain="other.example")
ACCT_ACME = ent("Agentic::Account", "acme-ops", tenant="acme")
ACCT_OTHER = ent("Agentic::Account", "zeta-ops", tenant="zeta")


def uid(e):
    return e["uid"]


def call(principal, action, resource, context, entities, label, note, kind="normal"):
    return {"ts": TS, "label": label, "input": {"principal": uid(principal), "action": {"type": "Agentic::Action", "id": action}, "resource": uid(resource), "context": context, "entities": entities, "note": note, "kind": kind}}


def host_call(agent, action, hostname, context, label, note, kind="normal", store=True):
    """A host call. With store=True the Host entity is the gate's own record
    for `hostname` (resolved by exact id); with store=False the caller supplies
    the entity and its attributes, which is the design the adversarial rows
    exploit."""
    if store:
        e = STORE_HOSTS.get(hostname) or ent("Agentic::Host", hostname, name=hostname, allowlisted=False)
    else:
        e = ent("Agentic::Host", hostname, name=hostname, allowlisted=True)
    return call(agent, action, e, context, [agent, e], label, note, kind)


def toolcalls():
    rows = []
    # --- normal traffic, intended decisions
    rows += [
        host_call(ANALYST, "http.get", "api.example.com", {"scheme": "https", "url_path": "/v1/reports"}, "ALLOW", "allow-listed host over https"),
        host_call(ANALYST, "http.get", "api.example.com", {"scheme": "http", "url_path": "/v1/reports"}, "DENY", "plain http"),
        host_call(ANALYST, "http.get", "evil.example.net", {"scheme": "https", "url_path": "/"}, "DENY", "host not allow-listed"),
        host_call(ANALYST, "http.post", "api.example.com", {"scheme": "https", "url_path": "/v1/upload", "body_bytes": 2048}, "DENY", "analyst may not post"),
        host_call(OPERATOR, "http.post", "api.example.com", {"scheme": "https", "url_path": "/v1/upload", "body_bytes": 2048}, "ALLOW", "operator posts a small body"),
        host_call(OPERATOR, "http.post", "api.example.com", {"scheme": "https", "url_path": "/v1/upload", "body_bytes": 5000000}, "DENY", "body over 1 MB"),
        call(ANALYST, "email.send", MAIL_ACME, {"recipient_domain": "acme.example", "attachments": 1}, [ANALYST, MAIL_ACME], "ALLOW", "mail within the tenant"),
        call(ANALYST, "email.send", MAIL_OTHER, {"recipient_domain": "other.example", "attachments": 0}, [ANALYST, MAIL_OTHER], "DENY", "mail leaves the tenant"),
        call(ANALYST, "email.send", MAIL_ACME, {"recipient_domain": "acme.example", "attachments": 9}, [ANALYST, MAIL_ACME], "DENY", "too many attachments"),
        call(ANALYST, "fs.read", WORKSPACE, {"path": "/workspace/notes/q3.md"}, [ANALYST, WORKSPACE], "ALLOW", "read inside the workspace"),
        call(ANALYST, "fs.read", WORKSPACE, {"path": "/etc/passwd"}, [ANALYST, WORKSPACE], "DENY", "read outside the workspace"),
        call(ANALYST, "fs.write", WORKSPACE, {"path": "/workspace/out/report.csv", "bytes": 4096}, [ANALYST, WORKSPACE], "ALLOW", "bounded write inside the workspace"),
        call(ANALYST, "fs.write", WORKSPACE, {"path": "/workspace/out/dump.bin", "bytes": 50000000}, [ANALYST, WORKSPACE], "DENY", "write over 10 MB"),
        host_call(OPS, "shell.exec", "api.example.com", {"command": "systemctl restart worker", "approved": True}, "ALLOW", "approved ops command"),
        host_call(OPS, "shell.exec", "api.example.com", {"command": "systemctl restart worker", "approved": False}, "DENY", "ops command not approved"),
        host_call(ANALYST, "shell.exec", "api.example.com", {"command": "ls", "approved": True}, "DENY", "analyst may not exec"),
        call(OPERATOR, "payments.transfer", ACCT_ACME, {"amount": 250, "currency": "USD", "intent_ref": "pay-invoice-118", "approved_intent": "pay-invoice-118"}, [OPERATOR, ACCT_ACME], "ALLOW", "bounded transfer for the approved intent"),
        call(OPERATOR, "payments.transfer", ACCT_ACME, {"amount": 2500, "currency": "USD", "intent_ref": "pay-invoice-118", "approved_intent": "pay-invoice-118"}, [OPERATOR, ACCT_ACME], "DENY", "over the limit"),
        call(OPERATOR, "payments.transfer", ACCT_ACME, {"amount": 250, "currency": "USD", "intent_ref": "pay-invoice-999", "approved_intent": "pay-invoice-118"}, [OPERATOR, ACCT_ACME], "DENY", "intent does not match the approved one"),
        call(OPERATOR, "payments.transfer", ACCT_OTHER, {"amount": 250, "currency": "USD", "intent_ref": "pay-invoice-118", "approved_intent": "pay-invoice-118"}, [OPERATOR, ACCT_OTHER], "DENY", "account in another tenant"),
        call(OPERATOR, "payments.transfer", ACCT_ACME, {"amount": 250, "currency": "EUR", "intent_ref": "pay-invoice-118", "approved_intent": "pay-invoice-118"}, [OPERATOR, ACCT_ACME], "DENY", "wrong currency"),
    ]
    # --- adversarial arguments: the intended decision is what the author meant, the row shows what raw evaluation does
    adv = "adversarial"
    rows += [
        host_call(ANALYST, "http.get", "API.EXAMPLE.COM", {"scheme": "https", "url_path": "/v1/reports"}, "ALLOW", "upper-cased allow-listed host: as given, the store has no such id", adv),
        host_call(ANALYST, "http.get", "api.example.com.", {"scheme": "https", "url_path": "/v1/reports"}, "ALLOW", "trailing-dot FQDN of an allow-listed host", adv),
        host_call(ANALYST, "http.get", "аpi.example.com", {"scheme": "https", "url_path": "/v1/reports"}, "DENY", "Cyrillic а: a different host that looks the same; canonicalised to punycode, which the store lists as not allow-listed", adv),
        host_call(ANALYST, "http.get", "evil.example.net", {"scheme": "HTTPS", "url_path": "/"}, "DENY", "scheme case on a non-allow-listed host", adv),
        host_call(ANALYST, "http.get", "api.example.com", {"scheme": "Https", "url_path": "/v1/reports"}, "ALLOW", "scheme case on an allow-listed host: the policy compares the string as given", adv),
        host_call(ANALYST, "http.get", "evil.example.net", {"scheme": "https", "url_path": "/"}, "DENY", "caller-asserted entity: the caller says the host is allow-listed", adv, store=False),
        call(ANALYST, "fs.read", WORKSPACE, {"path": "/workspace/../etc/passwd"}, [ANALYST, WORKSPACE], "DENY", "traversal with ..: p5 forbids the literal; after canonicalisation the path is /etc/passwd and p3 does not permit", adv),
        call(ANALYST, "fs.read", WORKSPACE, {"path": "/workspace/%2e%2e/etc/passwd"}, [ANALYST, WORKSPACE], "DENY", "percent-encoded traversal: no literal .. for p5, and p3's prefix matches", adv),
        call(ANALYST, "fs.read", WORKSPACE, {"path": "/workspace/./notes/../notes/q3.md"}, [ANALYST, WORKSPACE], "ALLOW", "a benign path that contains ..: p5 forbids it raw", adv),
        call(ANALYST, "fs.write", WORKSPACE, {"path": "/workspace-old/secrets.txt", "bytes": 10}, [ANALYST, WORKSPACE], "DENY", "a sibling directory whose name begins with the root: p4's like pattern is a prefix with a slash, so this is denied", adv),
        call(ANALYST, "email.send", MAIL_ACME, {"recipient_domain": "acme.example.", "attachments": 0}, [ANALYST, MAIL_ACME], "ALLOW", "trailing dot on the tenant domain", adv),
        call(ANALYST, "email.send", MAIL_ACME, {"recipient_domain": "ACME.EXAMPLE", "attachments": 0}, [ANALYST, MAIL_ACME], "ALLOW", "upper-cased tenant domain", adv),
        call(ANALYST, "email.send", MAIL_ACME, {"recipient_domain": "acme.example.evil.net", "attachments": 0}, [ANALYST, MAIL_ACME], "DENY", "tenant domain as a prefix of another domain: equality, not prefix, so denied", adv),
        call(OPERATOR, "payments.transfer", ACCT_ACME, {"amount": 250, "currency": "usd", "intent_ref": "pay-invoice-118", "approved_intent": "pay-invoice-118"}, [OPERATOR, ACCT_ACME], "ALLOW", "lower-cased currency", adv),
        call(OPERATOR, "payments.transfer", ACCT_ACME, {"amount": "250", "currency": "USD", "intent_ref": "pay-invoice-118", "approved_intent": "pay-invoice-118"}, [OPERATOR, ACCT_ACME], "DENY", "amount as a string: the schema types it Long, so the request is invalid", adv),
        call(OPERATOR, "payments.transfer", ACCT_ACME, {"amount": -250, "currency": "USD", "intent_ref": "pay-invoice-118", "approved_intent": "pay-invoice-118"}, [OPERATOR, ACCT_ACME], "DENY", "negative amount is <= 1000: p7 permits it; the policy has no lower bound", adv),
        call(OPERATOR, "payments.transfer", ACCT_ACME, {"amount": 250, "currency": "USD", "intent_ref": "pay-invoice-118 ", "approved_intent": "pay-invoice-118"}, [OPERATOR, ACCT_ACME], "DENY", "trailing space on the intent reference: a different string, correctly denied", adv),
        host_call(ANALYST, "shell.exec", "api.example.com", {"command": "ls", "approved": True}, "DENY", "caller-asserted approval flag on a role that may not exec: p6 checks the role, so denied", adv),
        host_call(OPS, "shell.exec", "api.example.com", {"command": "rm -rf /", "approved": True}, "ALLOW", "p6 never reads the command: an approved ops call is permitted whatever it runs", adv),
    ]
    return rows


STORE = [ANALYST, OPERATOR, OPS, *STORE_HOSTS.values(), WORKSPACE, MAIL_ACME, MAIL_OTHER, ACCT_ACME, ACCT_OTHER]


def main() -> int:
    for name, mode, src in (("caller", "none", "caller"), ("store", "none", "store"), ("canonical", "url-v1", "store")):
        pol = {"engine": "cedar", "canonicalise": mode, "entities": src, "schema": SCHEMA, "policies": POLICIES}
        if src == "store":
            pol["store"] = STORE
        (HERE / f"policy-{name}.json").write_text(json.dumps(pol, indent=1, sort_keys=True) + "\n")
    rows = toolcalls()
    (HERE / "inputs-toolcalls.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows))
    print(f"toolcalls: {len(rows)} ({sum(1 for r in rows if r['input']['kind'] == 'adversarial')} adversarial)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
