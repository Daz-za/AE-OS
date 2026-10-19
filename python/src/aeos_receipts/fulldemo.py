"""The architecture walk-through: `aeos-receipts demo --full`.

The simple demo shows receipts. This one runs the parts of the AE-OS architecture that
are built so far, for real, on one computer:

- workload identity: a SPIFFE trust domain issues short-lived X.509-SVIDs, and the agent
  and the MCP gateway authenticate each other over mutual TLS;
- an MCP gateway that takes the agent's identity from its certificate, checks what that
  identity may do, and records every call under it;
- witnesses that cosign checkpoints and refuse a log that shows them a different history;
- an end-to-end audit of the evidence (`aeos-receipts audit`).

It leaves an evidence folder for `aeos-receipts audit`. Private keys go in private/,
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

from . import audit, identity, keys, witness
from .gateway import AgentClient, Gateway, handshake_error
from .canon import decode_dag_cbor
from .log import ReceiptLog

DOMAIN = "acme.example"
AP_AGENT = f"spiffe://{DOMAIN}/agent/accounts-payable"
PAYROLL_AGENT = f"spiffe://{DOMAIN}/agent/payroll"
GATEWAY = f"spiffe://{DOMAIN}/gateway/erp-mcp"
CONTROLLER = f"spiffe://{DOMAIN}/human/controller-7f3c"

INVOICES = {"INV-20431": {"vendor": "V-1182", "amount_minor": 420_000, "currency": "USD",
                          "status": "approved for payment"}}


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
            f"  aeos-receipts demo --full {folder}-2")
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
    say("Each agent and the gateway get a short-lived identity",
        f"The accounts payable agent receives an X.509-SVID for {AP_AGENT}: a certificate "
        f"that names it, valid for 15 minutes ({ap.leaf.not_valid_before_utc:%H:%M} to "
        f"{ap.leaf.not_valid_after_utc:%H:%M} UTC), and a private key for the agent alone (in "
        "this preview the issuer generates it; under SPIRE the key never leaves the "
        "agent). The ERP gateway and a payroll agent get their own. Identity rests on the "
        "certificate alone.")

    log = ReceiptLog.create(folder / "log", log_id="urn:example:acme:accounts-payable",
                            key_path=private / "log-signing.key")
    (folder / "public-key.txt").write_text(log.public_key.hex() + "\n")
    gateway = Gateway(log, _erp(), trust_domain=DOMAIN, svid_files=gw_files,
                      bundle_file=bundle, on_behalf_of={AP_AGENT: CONTROLLER},
                      permissions={AP_AGENT: ["erp.invoice.get", "erp.invoice.pay"],
                                   PAYROLL_AGENT: ["erp.payroll.get"]})
    port = gateway.start()

    def client(files):
        return AgentClient(port, files, bundle, gateway_id=GATEWAY, trust_domain=DOMAIN)

    try:
        agent = client(ap_files)
        agent.initialize()
        inv = agent.call("erp.invoice.get", {"invoice": "INV-20431"})["result"]
        inv = inv["structuredContent"]
        paid = agent.call("erp.invoice.pay", {"invoice": "INV-20431",
                                              "amount_minor": inv["amount_minor"]})
        payment = paid["result"]["structuredContent"]["payment"]
        agent.close()
        say("The agent pays an invoice through the gateway",
            "The agent connects to the ERP gateway over mutual TLS: each side proves its "
            "identity with its certificate, and each checks the other's against Acme's root. "
            "The gateway takes the agent's identity from the certificate, never from the "
            "request. The agent reads invoice INV-20431 and pays USD 4,200.00 (payment "
            f"{payment}). Every call is recorded under {AP_AGENT}, and the session's first "
            "record holds the fingerprint of the certificate the agent presented.")

        other = client(pr_files)
        other.initialize()
        refused = other.call("erp.invoice.pay", {"invoice": "INV-20431",
                                                 "amount_minor": inv["amount_minor"]})
        other.close()
        say("Another agent is refused",
            "The payroll agent has a valid Acme identity but no permission to pay invoices. "
            "The gateway refuses the call and records the refusal under the payroll agent's "
            "identity: " + refused["result"]["content"][0]["text"] + ".")

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
        agent = client(ap2_files)
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
        "checkpoint as the last one they cosigned, and sign it. Their public keys are in witnesses.json.")

    fork = ReceiptLog.create(private / "forked-log", log_id=log.log_id,
                             key_path=private / "log-signing.key")
    for e in log.entries():
        rec = decode_dag_cbor(e.raw)
        if rec["kind"] == "policy.decision":
            continue                                    # hide the refusal from this copy
        fork.append(rec)
    fork.append(decode_dag_cbor(log.entries()[0].raw) | {"ts": cp.ts + 1, "parents": []})
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
                     "its side of each mutual TLS connection") for s in (ap, ap2, gw, pr)],
        {"role": "Log checkpoint key", "algorithm": "Ed25519", "key_id": log.meta["key_id"],
         "holder": "the log operator (in production: an HSM with dual control)",
         "signs": "checkpoints", "public_key_file": "public-key.txt"},
        *[{"role": "Witness key", "algorithm": "Ed25519", "holder": n,
           "key_id": keys.key_id(keys.public_bytes(k)), "signs": "cosignatures of checkpoints",
           "public_key_file": "witnesses.json"} for n, k in w_keys.items()],
    ]
    (folder / "key-hierarchy.json").write_text(json.dumps(hierarchy, indent=2) + "\n")

    manifest = {"format": "aeos-evidence/v0", "trust_domain": DOMAIN,
                "bundle": "trust/bundle.pem", "svids": "svids", "log": "log",
                "witnesses": "witnesses.json"}
    (folder / "evidence.json").write_text(json.dumps(manifest, indent=2) + "\n")
    findings, problems = audit.run(folder)
    say("The auditor checks all of the evidence",
        "The auditor runs one command over the evidence folder. Here it uses the trust "
        "bundle and witness keys in the folder; a real auditor passes their own copies with "
        "--bundle, --public-key and --witnesses. key-hierarchy.json lists every key "
        "and certificate involved: who holds it, what it signs, and what issued it. " + " ".join(f + "." for f in findings)
        + (" Result: VALID" if not problems else " Result: INVALID: " + "; ".join(problems)))

    out("\nStill to come in this walk-through: the controller's signed mandate and a token "
        "that can only narrow it,\npolicy as code in a WebAssembly sandbox, and a ledger "
        "that refuses postings to a closed period.")
    out(f"\nThe evidence is in {folder}; the private keys are in {private}. Try:")
    out(f"  aeos-receipts audit {folder}")
    out(f"  aeos-receipts show {folder / 'log'}")
    return 0 if not problems else 1
