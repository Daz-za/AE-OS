# AE-OS example policy for supplier payments, compiled to WebAssembly for the gateway.
#
# input: {"tool", "agent", "principal", "arguments": {...},
#         "invoice": {...} (when the call names one), "approval": {"approver", "decision"}
#         (when the agent repeats an escalated call with a person's signed answer)}
# data:  {"escalate_above_minor", "sanctioned_vendors": [...], "approvers": [...]}
#
# The decision is "allow", "deny" or "escalate", with reasons in plain language.
package aeos.payments

import rego.v1

payment if input.tool == "erp.invoice.pay"

amount := object.get(input.arguments, "amount_minor", 0)

deny_reasons contains "the invoice was not found" if {
	payment
	not input.invoice
}

deny_reasons contains "the invoice is not approved for payment" if {
	payment
	input.invoice.status != "approved for payment"
}

deny_reasons contains "the supplier is on the sanctions list" if {
	payment
	input.invoice.vendor in data.sanctioned_vendors
}

deny_reasons contains "the amount differs from the invoice amount" if {
	payment
	amount != input.invoice.amount_minor
}

deny_reasons contains "the approver authorized the agent and may not approve its payments" if {
	payment
	input.approval.approver == input.principal
}

deny_reasons contains "the approver is not on the list of approvers" if {
	payment
	input.approval
	not input.approval.approver in data.approvers
}

deny_reasons contains "a person rejected this payment" if {
	payment
	input.approval.decision == "reject"
}

needs_approval if {
	payment
	amount > data.escalate_above_minor
}

approved if input.approval.decision == "approve"

default decision := {"decision": "allow", "reasons": []}

decision := {"decision": "deny", "reasons": sort(deny_reasons)} if count(deny_reasons) > 0

decision := {"decision": "escalate", "reasons": ["payments above the threshold need approval from someone on the approvers list"]} if {
	count(deny_reasons) == 0
	needs_approval
	not approved
}
