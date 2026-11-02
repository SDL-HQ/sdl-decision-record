package agentic

import rego.v1

# The eight policies of examples/cedar/policies.cedar, in Rego. Each rule adds
# its id to `permit` or `forbid`; `decision` is what the decider queries (G4).

principal := data.entities[input.principal.type][input.principal.id]

resource := data.entities[input.resource.type][input.resource.id]

action := input.action.id

ctx := input.context

# p0: outbound reads to allow-listed hosts over https
permit contains "p0" if {
	action == "http.get"
	resource.allowlisted
	ctx.scheme == "https"
}

# p1: outbound writes only by an operator, to allow-listed hosts, under 1 MB
permit contains "p1" if {
	action == "http.post"
	resource.allowlisted
	ctx.scheme == "https"
	principal.role == "operator"
	ctx.body_bytes <= 1048576
}

# p2: mail only to the agent's own tenant domain, few attachments
permit contains "p2" if {
	action == "email.send"
	ctx.recipient_domain == principal.mail_domain
	resource.domain == principal.mail_domain
	ctx.attachments <= 3
}

# p3: files inside the workspace root; p4: writes bounded
permit contains "p3" if {
	action == "fs.read"
	resource.root == "/workspace"
	startswith(ctx.path, "/workspace/")
}

permit contains "p4" if {
	action == "fs.write"
	resource.root == "/workspace"
	startswith(ctx.path, "/workspace/")
	ctx.bytes <= 10485760
}

# p5: nothing that climbs out of the root, whatever else permits
forbid contains "p5" if {
	action in {"fs.read", "fs.write"}
	contains(ctx.path, "..")
}

# p6: shell only for ops, and only when the call was approved
permit contains "p6" if {
	action == "shell.exec"
	principal.role == "ops"
	ctx.approved == true
}

# p7: transfers within the tenant, bounded, and only for the intent that was approved
permit contains "p7" if {
	action == "payments.transfer"
	resource.tenant == principal.tenant
	ctx.currency == "USD"
	ctx.amount <= 1000
	ctx.intent_ref == ctx.approved_intent
}

default allow := false

allow if {
	count(forbid) == 0
	count(permit) > 0
}

decision := {"allow": allow, "permit": permit, "forbid": forbid}
