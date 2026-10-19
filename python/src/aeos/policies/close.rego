# AE-OS example policy for a quarter-end close, compiled to WebAssembly for the gateway.
#
# input: {"tool", "agent", "principal", "arguments": {...},
#         "approval": {"approver", "decision"} (when the agent repeats an escalated call
#         with a person's signed answer)}
# data:  {"escalate_above_minor", "escalate_reason", "approvers": [...],
#         "blocked_tools": {"<tool>": "<reason>"},
#         "agent_entities": {"<agent SPIFFE ID>": ["<entity>", ...]},
#         "default_entity"}
#
# The amount of a call is its amount_minor argument or, for a journal entry, its total
# debits. The decision is "allow", "deny" or "escalate", with reasons in plain language.
package aeos.close

import rego.v1

posting if input.tool == "ledger.post"

debits := [d |
	some line in object.get(input.arguments, "lines", [])
	is_object(line)
	d := object.get(line, "debit_minor", 0)
	is_number(d)
]

amount := input.arguments.amount_minor if {
	is_number(input.arguments.amount_minor)
} else := sum(debits)

entity := object.get(input.arguments, "entity", data.default_entity)

deny_reasons contains reason if {
	some tool, reason in data.blocked_tools
	input.tool == tool
}

deny_reasons contains concat("", ["this agent may not post to the books of ", entity]) if {
	posting
	allowed := data.agent_entities[input.agent]
	not entity in allowed
}

deny_reasons contains "the approver is not on the list of approvers" if {
	input.approval
	not input.approval.approver in data.approvers
}

deny_reasons contains "a person rejected this call" if {
	input.approval.decision == "reject"
}

approved if input.approval.decision == "approve"

default decision := {"decision": "allow", "reasons": []}

decision := {"decision": "deny", "reasons": sort(deny_reasons)} if count(deny_reasons) > 0

decision := {"decision": "escalate", "reasons": [data.escalate_reason]} if {
	count(deny_reasons) == 0
	amount > data.escalate_above_minor
	not approved
}
