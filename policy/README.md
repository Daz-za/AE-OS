# Policies

The rules here are written in [Rego](https://www.openpolicyagent.org/docs/policy-language), the policy language of Open Policy Agent, and compiled to WebAssembly so the gateway can run them in a sandbox.

`close.rego` holds the rules for Kestrel Foods' quarter-end close, the default workspace:

- a tool on the blocked list, such as a payment, is refused;
- an agent may post only to the books of the entities it is given;
- a journal entry above the threshold, counted as the sum of its debits, waits until someone on the approvers list approves it;
- a person's rejection refuses the entry.

`payments.rego` holds the example payment rules used by `aeos demo --full` and the Acme workspace.

The payment rules:

- a payment must match an invoice that is approved for payment, for the invoice's amount;
- the supplier must not be on the sanctions list;
- a payment above the threshold is escalated until someone on the approvers list approves it, and the person who authorized the agent may not approve it;
- a person's rejection refuses the payment.

The thresholds, the lists and the approvers come from each policy's data, which the gateway is given when it starts.

To rebuild the modules in `python/src/aeos/policies/` after changing the rules, install OPA and run:

```
policy/build.sh
```

`policy/build.sh --check` fails if the committed module differs from a fresh build; CI runs it with a pinned OPA version. The log and the audit name each module by the SHA-256 of its bytes, and a module built from changed rules has a different name.
