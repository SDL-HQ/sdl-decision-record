// p0: outbound reads to allow-listed hosts over https
@id("p0")
permit(principal, action == Agentic::Action::"http.get", resource)
when { resource.allowlisted && context.scheme == "https" };

// p1: outbound writes only by an operator, to allow-listed hosts, under 1 MB
@id("p1")
permit(principal, action == Agentic::Action::"http.post", resource)
when { resource.allowlisted && context.scheme == "https" && principal.role == "operator" && context.body_bytes <= 1048576 };

// p2: mail only to the agent's own tenant domain, few attachments
@id("p2")
permit(principal, action == Agentic::Action::"email.send", resource)
when { context.recipient_domain == principal.mail_domain && resource.domain == principal.mail_domain && context.attachments <= 3 };

// p3: files inside the workspace root; p4: writes bounded
@id("p3")
permit(principal, action == Agentic::Action::"fs.read", resource)
when { resource.root == "/workspace" && context.path like "/workspace/*" };
@id("p4")
permit(principal, action == Agentic::Action::"fs.write", resource)
when { resource.root == "/workspace" && context.path like "/workspace/*" && context.bytes <= 10485760 };
// p5: nothing that climbs out of the root, whatever else permits
@id("p5")
forbid(principal, action in [Agentic::Action::"fs.read", Agentic::Action::"fs.write"], resource)
when { context.path like "*..*" };

// p6: shell only for ops, and only when the call was approved
@id("p6")
permit(principal, action == Agentic::Action::"shell.exec", resource)
when { principal.role == "ops" && context.approved };

// p7: transfers within the tenant, bounded, and only for the intent that was approved
@id("p7")
permit(principal, action == Agentic::Action::"payments.transfer", resource)
when { resource.tenant == principal.tenant && context.currency == "USD" && context.amount <= 1000 && context.intent_ref == context.approved_intent };
