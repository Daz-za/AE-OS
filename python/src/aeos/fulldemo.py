"""The architecture walk-through: `aeos demo --full`.

The simple demo shows receipts. This one runs the parts of the AE-OS architecture that
are built so far, for real, on one computer:

- workload identity: a SPIFFE trust domain issues short-lived X.509-SVIDs, and the agent
  and the MCP gateway authenticate each other over mutual TLS;
- delegated authority: a person signs an intent, an authorization service turns it into
  a Biscuit capability token, and the agent can narrow that token for a helper;
- an MCP gateway that takes the agent's identity from its certificate, checks the token
  against it, the tool, the amount and the time, and records every call and decision;
- payment rules written in Rego and compiled to WebAssembly, run in a sandbox, with
  escalation to a person whose signed approval the gateway checks and records;
- witnesses that cosign checkpoints and refuse a log that shows them a different history;
- an end-to-end audit of the evidence (`aeos audit`).

It leaves an evidence folder for `aeos audit`. Private keys go in private/,
apart from the evidence.
"""
from __future__ import annotations

import datetime as dt
import json
import shutil
import textwrap
from pathlib import Path
from typing import Callable, Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import audit, delegation, identity, keys, policy, witness
from .gateway import AgentClient, Gateway, handshake_error
from .canon import decode_dag_cbor, json_digest
from .log import ReceiptLog, now_ms

DOMAIN = "acme.example"
AP_AGENT = f"spiffe://{DOMAIN}/agent/accounts-payable"
PAYROLL_AGENT = f"spiffe://{DOMAIN}/agent/payroll"
GATEWAY = f"spiffe://{DOMAIN}/gateway/erp-mcp"
HELPER_AGENT = f"{AP_AGENT}/helper"
CONTROLLER = f"spiffe://{DOMAIN}/human/controller-7f3c"
CFO = f"spiffe://{DOMAIN}/human/cfo-2b81"
POLICY_DATA = {"escalate_above_minor": 500_000, "sanctioned_vendors": ["V-0666"],
               "approvers": [CFO]}

POLICY_WASM = Path(__file__).with_name("policies") / "payments.wasm"

INVOICES = {"INV-20431": {"vendor": "V-1182", "amount_minor": 420_000, "currency": "USD",
                          "status": "approved for payment"},
            "INV-20457": {"vendor": "V-0907", "amount_minor": 780_000, "currency": "USD",
                          "status": "approved for payment"},
            "INV-20466": {"vendor": "V-0666", "amount_minor": 95_000, "currency": "USD",
                          "status": "approved for payment"}}


def _facts(tool: str, args: Dict) -> Dict:
    """What the payment policy needs to know beyond the call: the invoice it names."""
    inv = INVOICES.get(args.get("invoice", ""))
    return {"invoice": inv} if inv else {}


def _erp() -> Dict[str, Callable]:
    paid: Dict[str, str] = {}

    def get(args):
        inv = INVOICES[args["invoice"]]
        return {"invoice": args["invoice"], **inv}

    def pay(args):
        inv = INVOICES[args["invoice"]]
        if args.get("amount_minor") != inv["amount_minor"]:
            raise ValueError("amount does not match the invoice")
        paid.setdefault(args["invoice"], f"PAY-{len(paid) + 301}")
        return {"invoice": args["invoice"], "payment": paid[args["invoice"]],
                "amount_minor": inv["amount_minor"], "currency": inv["currency"]}

    return {"erp.invoice.get": get, "erp.invoice.pay": pay}


def run(folder: Path, out: Callable[[str], None] = print) -> int:
    folder = Path(folder)
    if folder.exists() and any(folder.iterdir()):
        out(f"{folder} already has files in it. Choose an empty or new folder, for example:\n"
            f"  aeos demo --full {folder}-2")
        return 2
    step = 0

    def say(title: str, text: str) -> None:
        nonlocal step
        step += 1
        out(f"\n{step}. {title}")
        out(textwrap.fill(text, 88, initial_indent="   ", subsequent_indent="   "))

    out("AE-OS architecture demo: Acme, a fictional company, lets an AI agent pay supplier "
        "invoices.\nEach step below runs for real on this computer, and an auditor checks "
        "the evidence at the end.")
    private, svid_dir, trust = folder / "private", folder / "svids", folder / "trust"
    private.mkdir(parents=True)
    private.chmod(0o700)

    td = identity.TrustDomain(DOMAIN)
    trust.mkdir()
    bundle = trust / "bundle.pem"
    bundle.write_bytes(td.bundle_pem())
    say("Acme's identity service is set up",
        f"A trust domain, {DOMAIN}, gets a root certificate authority and an intermediate "
        "that issues identities to software. It plays the part of SPIRE, the standard "
        "SPIFFE identity service, without SPIRE's checks of the machine and process that "
        f"ask for an identity. Its root certificate (trust/bundle.pem) is what others use "
        "to recognise Acme's software.")

    def issue(spiffe_id: str, name: str, **kw):
        svid = td.issue(spiffe_id, **kw)
        cert, key = svid.write(private, name)
        shutil.copy(cert, svid_dir / f"{name}.pem")
        return svid, (cert, key)

    svid_dir.mkdir()
    ap, ap_files = issue(AP_AGENT, "accounts-payable-1")
    gw, gw_files = issue(GATEWAY, "erp-gateway")
    pr, pr_files = issue(PAYROLL_AGENT, "payroll")
    helper_svid, helper_files = issue(HELPER_AGENT, "payments-helper")
    say("Each agent and the gateway get a short-lived identity",
        f"The accounts payable agent receives an X.509-SVID for {AP_AGENT}: a certificate "
        f"that names it, valid for 15 minutes ({ap.leaf.not_valid_before_utc:%H:%M} to "
        f"{ap.leaf.not_valid_after_utc:%H:%M} UTC), and a private key for the agent alone (in "
        "this preview the issuer generates it; under SPIRE the key never leaves the "
        "agent). The ERP gateway, a payments helper and a payroll agent get their own. "
        "Identity rests on the certificate alone.")

    controller_key = keys.generate_key(private / "controller.key")
    cfo_key = keys.generate_key(private / "cfo.key")
    authority = delegation.Authority()
    (private / "authority.key").write_bytes(authority.private_bytes())
    (private / "authority.key").chmod(0o600)
    (trust / "authority-public-key.txt").write_text(authority.public_key.hex() + "\n")
    (trust / "principals.json").write_text(json.dumps(
        {CONTROLLER: keys.public_bytes(controller_key).hex(),
         CFO: keys.public_bytes(cfo_key).hex()}, indent=2) + "\n")
    now = dt.datetime.now(dt.timezone.utc)
    envelope = delegation.IntentEnvelope(
        principal=CONTROLLER, audience=AP_AGENT,
        purpose="Pay approved supplier invoices for October",
        actions=["erp.invoice.get", "erp.invoice.pay"], per_action_max_minor=1_000_000,
        budget_minor=2_000_000, currency="USD",
        not_after=int((now + dt.timedelta(hours=8)).timestamp() * 1000)).sign(controller_key)
    intents_dir = folder / "intents"
    intents_dir.mkdir()
    (intents_dir / f"{envelope.cid}.json").write_text(
        json.dumps(envelope.to_json(), indent=2) + "\n")
    token = authority.mint(envelope, keys.public_bytes(controller_key))
    say("The controller signs what the agent may do",
        "Acme's financial controller signs an intent for the accounts payable agent: read "
        "and pay supplier invoices, up to USD 10,000.00 a payment and USD 20,000.00 in "
        "total, for the next 8 hours. The stated purpose, 'Pay approved supplier invoices "
        "for October', is recorded with the intent; the gateway does not check it. Acme's "
        "authorization service checks the signature and gives the agent a capability "
        f"token (a Biscuit) bound to that intent ({envelope.cid[:16]}…) and to the agent's "
        "SPIFFE ID. The gateway requires this token on every tool call the agent makes.")

    rules = policy.Policy.load(POLICY_WASM, POLICY_DATA, "aeos/payments/decision")
    policies_dir = folder / "policies"
    policies_dir.mkdir()
    (policies_dir / f"{rules.sha256.hex()}.wasm").write_bytes(rules.wasm)
    (policies_dir / f"data-{rules.data_sha256.hex()}.json").write_text(
        json.dumps(POLICY_DATA, indent=2) + "\n")
    say("Acme's payment rules are loaded into the gateway",
        "The rules are written in Rego, the policy language of Open Policy Agent "
        "(policy/payments.rego), and compiled to WebAssembly (module "
        f"{rules.sha256.hex()[:16]}…). A payment must match an approved invoice and must "
        "not go to a supplier on the sanctions list. A payment above USD 5,000.00 needs "
        "the approval of someone on the approvers list, other than the person who "
        "authorized the agent. The gateway runs the module in a sandbox that can read only "
        "the call and the rules' data, with limits on memory and on the work done per "
        "decision.")

    log = ReceiptLog.create(folder / "log", log_id="urn:example:acme:accounts-payable",
                            key_path=private / "log-signing.key")
    (folder / "public-key.txt").write_text(log.public_key.hex() + "\n")
    gateway = Gateway(log, _erp(), trust_domain=DOMAIN, svid_files=gw_files,
                      bundle_file=bundle,
                      permissions={AP_AGENT: ["erp.invoice.get", "erp.invoice.pay"],
                                   HELPER_AGENT: ["erp.invoice.get", "erp.invoice.pay"],
                                   PAYROLL_AGENT: ["erp.payroll.get"]},
                      authority_key=authority.public_key, intents={envelope.cid: envelope},
                      principal_keys={CONTROLLER: keys.public_bytes(controller_key),
                                      CFO: keys.public_bytes(cfo_key)},
                      policy=rules, policy_facts=_facts)
    port = gateway.start()

    def client(files, tok=None):
        return AgentClient(port, files, bundle, gateway_id=GATEWAY, trust_domain=DOMAIN,
                           token=tok.to_bytes() if tok is not None else None)

    def refusal(reply):
        return reply["result"]["content"][0]["text"].removeprefix("Refused: ")

    try:
        agent = client(ap_files, token)
        agent.initialize()
        inv = agent.call("erp.invoice.get", {"invoice": "INV-20431"})["result"]
        inv = inv["structuredContent"]
        paid = agent.call("erp.invoice.pay", {"invoice": "INV-20431",
                                              "amount_minor": inv["amount_minor"]})
        payment = paid["result"]["structuredContent"]["payment"]
        say("The agent pays an invoice through the gateway",
            "The agent connects to the ERP gateway over mutual TLS: each side proves its "
            "identity with its certificate, and each checks the other's against Acme's root. "
            "The gateway takes the agent's identity from the certificate, checks the token "
            "against it, the tool, the amount and the time, and then asks the payment "
            "rules. The agent reads invoice "
            f"INV-20431 and pays USD 4,200.00 (payment {payment}). Each call and each "
            f"decision is recorded under {AP_AGENT}, on behalf of the controller, and the "
            "session's first record holds the fingerprint of the certificate the agent "
            "presented.")

        big_args = {"invoice": "INV-20457", "amount_minor": 780_000}
        big = agent.call("erp.invoice.pay", big_args)["result"]
        escalation = big["structuredContent"]["escalation"]

        def answer(person, key, verdict="approve"):
            return delegation.Approval(
                escalation=escalation, approver=person, decision=verdict,
                tool="erp.invoice.pay", args_sha256=json_digest(big_args),
                time=now_ms()).sign(key)

        own = agent.call("erp.invoice.pay", big_args, approval=answer(CONTROLLER,
                                                                      controller_key))
        done = agent.call("erp.invoice.pay", big_args, approval=answer(CFO, cfo_key))
        payment2 = done["result"]["structuredContent"]["payment"]
        say("A large payment waits for a person",
            "The agent tries to pay invoice INV-20457 for USD 7,800.00. The token allows it, "
            "but the rules escalate it: payments above the threshold need a person's "
            "approval. The controller, who authorized the agent, signs an approval and is "
            f"refused: {refusal(own)}. The CFO then signs an approval of that exact call "
            "(the invoice and amount), the agent repeats the call with it, and the payment "
            f"goes through (payment {payment2}). The escalation, each approval and each "
            "decision are recorded, with the exact input the rules saw.")

        blocked = agent.call("erp.invoice.pay", {"invoice": "INV-20466",
                                                 "amount_minor": 95_000})
        say("A payment to a sanctioned supplier is refused",
            "The agent tries to pay invoice INV-20466 for USD 950.00 to supplier V-0666. The "
            f"rules refuse it: {refusal(blocked)}.")

        narrow = delegation.attenuate(token, subject=HELPER_AGENT,
                                      actions=["erp.invoice.get"], max_minor=0)
        helper = client(helper_files, narrow)
        helper.initialize()
        helper.call("erp.invoice.get", {"invoice": "INV-20457"})
        tried = helper.call("erp.invoice.pay", {"invoice": "INV-20431",
                                                "amount_minor": inv["amount_minor"]})
        helper.close()
        agent.close()
        say("The agent hands a narrower token to a helper",
            "The agent adds a block to its own token, without contacting the authorization "
            "service: only its helper, whose identity sits under the agent's own "
            f"({HELPER_AGENT}), may use it, only to read invoices, and only for calls that move no money. "
            "The helper reads invoice INV-20457. When it tries to pay "
            f"INV-20431, the gateway refuses: {refusal(tried)}. A block added to a token can "
            "only take authority away.")

        other = client(pr_files, token)
        other.initialize()
        refused = other.call("erp.invoice.pay", {"invoice": "INV-20431",
                                                 "amount_minor": inv["amount_minor"]})
        other.close()
        say("A copied token does not work for another agent",
            "The payroll agent has a valid Acme identity and a copy of the accounts payable "
            "agent's token. The gateway refuses the payment for two separate reasons and "
            f"records both under the payroll agent's identity: {refusal(refused)}.")

        stale_svid = td.issue(AP_AGENT, not_before=dt.datetime.now(dt.timezone.utc)
                              - dt.timedelta(minutes=30))
        stale = stale_svid.write(private, "accounts-payable-expired")
        outsider_td = identity.TrustDomain("rogue.example")
        outsider = outsider_td.issue("spiffe://rogue.example/agent/accounts-payable") \
            .write(private, "outsider")
        (private / "outsider-bundle.pem").write_bytes(outsider_td.bundle_pem() +
                                                      td.bundle_pem())
        reasons = []
        for files, b in ((stale, bundle), (outsider, private / "outsider-bundle.pem")):
            try:
                AgentClient(port, files, b, gateway_id=GATEWAY,
                            trust_domain=DOMAIN).initialize()
                reasons.append("accepted")
            except OSError as e:
                reasons.append(handshake_error(e))
        say("Expired and foreign certificates are refused",
            "Someone replays an accounts payable certificate that expired 15 minutes ago, "
            "and someone else presents a certificate from another trust domain that claims "
            "the same agent name. The gateway ends both connections during the TLS "
            f"handshake ({reasons[0]}; {reasons[1]}), before any request is read. "
            "Neither reaches the ERP.")

        ap2, ap2_files = issue(AP_AGENT, "accounts-payable-2")
        agent = client(ap2_files, token)
        agent.initialize()
        agent.call("erp.invoice.get", {"invoice": "INV-20431"})
        agent.close()
        say("The agent's identity is renewed",
            "Before its certificate expires, the agent gets a new one with a new private "
            "key. SPIRE renews a certificate once half its lifetime has passed; the demo renews "
            "it straight away. Its next session is recorded with the new certificate's "
            "fingerprint. A stolen key works only until its certificate expires, at most 15 "
            "minutes.")
    finally:
        gateway.stop()

    w_keys = {"external-auditor": Ed25519PrivateKey.generate(),
              "industry-witness": Ed25519PrivateKey.generate()}
    witnesses = [witness.Witness(n, k, private / f"witness-{n}.json") for n, k in w_keys.items()]
    (folder / "witnesses.json").write_text(json.dumps(
        {"required": 2, "keys": {n: keys.public_bytes(k).hex() for n, k in w_keys.items()}},
        indent=2) + "\n")
    cp = log.checkpoint()
    witness.request_cosignatures(log, cp, witnesses)
    say("The log signs a checkpoint and two witnesses cosign it",
        f"The log seals its {cp.size} records in a signed checkpoint. Two witnesses, playing "
        "an external auditor and an industry body, check the log's signature, record this "
        "checkpoint as the last one they cosigned, and sign it. Their public keys are in "
        "witnesses.json.")

    fork = ReceiptLog.create(private / "forked-log", log_id=log.log_id,
                             key_path=private / "log-signing.key")
    for e in log.entries():
        rec = decode_dag_cbor(e.raw)
        if rec["kind"] == "policy.decision" and rec["agent"] == PAYROLL_AGENT:
            continue                                    # hide the refusal from this copy
        fork.append(rec)
    while len(fork) < len(log):                         # same size, different records
        fork.append(decode_dag_cbor(log.entries()[0].raw) | {"ts": cp.ts + len(fork),
                                                              "parents": []})
    fork_cp = fork.checkpoint()
    try:
        witness.request_cosignatures(fork, fork_cp, witnesses[:1])
        caught = "the witness cosigned it (this should not happen)"
    except witness.WitnessRefused as e:
        caught = str(e).split(": ", 1)[1]
    say("A rewritten history is caught",
        "An insider with the log's signing key builds a second version of the log without "
        "the payroll agent's refusal, signs a checkpoint for it, and shows it to the "
        f"external auditor's witness. The witness refuses: {caught.rstrip('.')}.")

    def cert_entry(role, cert, holder, signs):
        return {"role": role, "subject": cert.subject.rfc4514_string(),
                "issued_by": cert.issuer.rfc4514_string(),
                "algorithm": f"ECDSA {cert.public_key().curve.name}",
                "valid_from": f"{cert.not_valid_before_utc:%Y-%m-%dT%H:%M:%SZ}",
                "valid_to": f"{cert.not_valid_after_utc:%Y-%m-%dT%H:%M:%SZ}",
                "sha256": identity.fingerprint(cert), "holder": holder, "signs": signs}

    hierarchy = [
        cert_entry("Trust domain root CA", td.root, "Acme security team (in production: "
                   "offline HSM with several custodians)", "the intermediate CA certificate"),
        cert_entry("Intermediate CA", td.intermediate, "the identity service (SPIRE in "
                   "production, keys in an HSM or cloud KMS)", "workload certificates (SVIDs)"),
        *[cert_entry("Workload certificate (X.509-SVID)", s.leaf, identity.spiffe_id_of(s.leaf),
                     "its side of each mutual TLS connection")
          for s in (ap, ap2, gw, helper_svid, pr)],
        {"role": "Log checkpoint key", "algorithm": "Ed25519", "key_id": log.meta["key_id"],
         "holder": "the log operator (in production: an HSM with dual control)",
         "signs": "checkpoints", "public_key_file": "public-key.txt"},
        {"role": "Authorization service key", "algorithm": "Ed25519",
         "holder": "Acme's authorization service (in production: an HSM or cloud KMS)",
         "signs": "capability tokens (the first block of each Biscuit)",
         "public_key_file": "trust/authority-public-key.txt"},
        {"role": "Person's signing key", "algorithm": "Ed25519", "holder": CONTROLLER,
         "key_id": keys.key_id(keys.public_bytes(controller_key)),
         "signs": "intent envelopes and approvals (in production: a passkey or smart card, "
                  "with step-up authentication)", "public_key_file": "trust/principals.json"},
        {"role": "Person's signing key", "algorithm": "Ed25519", "holder": CFO,
         "key_id": keys.key_id(keys.public_bytes(cfo_key)),
         "signs": "approvals of escalated payments", "public_key_file": "trust/principals.json"},
        *[{"role": "Witness key", "algorithm": "Ed25519", "holder": n,
           "key_id": keys.key_id(keys.public_bytes(k)), "signs": "cosignatures of checkpoints",
           "public_key_file": "witnesses.json"} for n, k in w_keys.items()],
    ]
    (folder / "key-hierarchy.json").write_text(json.dumps(hierarchy, indent=2) + "\n")

    manifest = {"format": "aeos-evidence/v0", "trust_domain": DOMAIN,
                "bundle": "trust/bundle.pem", "svids": "svids", "log": "log",
                "witnesses": "witnesses.json", "authority": "trust/authority-public-key.txt",
                "principals": "trust/principals.json", "intents": "intents", "tokens": "tokens",
                "policies": "policies"}
    tokens_dir = folder / "tokens"
    tokens_dir.mkdir()
    for sha, raw in gateway.tokens.items():
        (tokens_dir / f"{sha}.biscuit").write_bytes(raw)
    (folder / "evidence.json").write_text(json.dumps(manifest, indent=2) + "\n")
    findings, problems = audit.run(folder)
    say("The auditor checks all of the evidence",
        "The auditor runs one command over the evidence folder. Here it uses the trust "
        "bundle and keys stored in the folder; a real auditor passes their own copies with "
        "--bundle, --public-key, --witnesses, --authority-key and --principals. key-hierarchy.json lists every key "
        "and certificate involved: who holds it, what it signs, and what issued it. " + " ".join(f + "." for f in findings)
        + (" Result: VALID" if not problems else " Result: INVALID: " + "; ".join(problems)))

    out("\nStill to come in this walk-through: a ledger that refuses postings to a closed "
        "period.")
    out(f"\nThe evidence is in {folder}; the private keys are in {private}. Try:")
    out(f"  aeos audit {folder}")
    out(f"  aeos show {folder / 'log'}")
    return 0 if not problems else 1
