# Policies

`payments.rego` holds the example payment rules used by `aeos demo --full`. They are written in [Rego](https://www.openpolicyagent.org/docs/policy-language), the policy language of Open Policy Agent, and compiled to WebAssembly so the gateway can run them in a sandbox.

The rules:

- a payment must match an invoice that is approved for payment, for the invoice's amount;
- the supplier must not be on the sanctions list;
- a payment above the threshold is escalated until someone on the approvers list approves it, and the person who authorized the agent may not approve it;
- a person's rejection refuses the payment.

The threshold, the sanctions list and the approvers come from the policy's data, which the gateway is given when it starts.

To rebuild `python/src/aeos/policies/payments.wasm` after changing the rules, install OPA and run:

```
policy/build.sh
```

CI runs `policy/build.sh --check` with a pinned OPA version, which fails if the committed module differs from a fresh build. The audit names each module by the SHA-256 of its bytes, so a changed module is a different policy.
