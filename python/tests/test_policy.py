import json
import shutil

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aeos import ReceiptLog, audit, delegation, fulldemo, identity, keys, policy
from aeos.canon import json_digest
from aeos.gateway import AgentClient, Gateway
from aeos.log import now_ms

DOMAIN = "acme.example"
AGENT = f"spiffe://{DOMAIN}/agent/ap"
GATEWAY = f"spiffe://{DOMAIN}/gateway/erp"
PERSON = f"spiffe://{DOMAIN}/human/controller"
CFO = f"spiffe://{DOMAIN}/human/cfo"
DATA = {"escalate_above_minor": 500, "sanctioned_vendors": ["V-BAD"], "approvers": [CFO]}
INVOICES = {"I1": {"vendor": "V1", "amount_minor": 100, "status": "approved for payment"},
            "I2": {"vendor": "V1", "amount_minor": 900, "status": "approved for payment"},
            "I3": {"vendor": "V-BAD", "amount_minor": 50, "status": "approved for payment"},
            "I4": {"vendor": "V1", "amount_minor": 50, "status": "on hold"}}


@pytest.fixture(scope="module")
def rules():
    return policy.Policy.load(fulldemo.POLICY_WASM, DATA, "aeos/payments/decision")


def pay(invoice, amount, **kw):
    doc = {"tool": "erp.invoice.pay", "agent": AGENT, "principal": PERSON,
           "arguments": {"invoice": invoice, "amount_minor": amount}}
    if invoice in INVOICES:
        doc["invoice"] = INVOICES[invoice]
    doc.update(kw)
    return doc


def test_payment_rules(rules):
    ev = rules.evaluate
    assert ev(pay("I1", 100)) == {"decision": "allow", "reasons": []}
    assert ev(pay("I2", 900))["decision"] == "escalate"
    assert ev(pay("I2", 900, approval={"approver": CFO, "decision": "approve"}))["decision"] \
        == "allow"
    own = ev(pay("I2", 900, approval={"approver": PERSON, "decision": "approve"}))
    assert own["decision"] == "deny" and \
        "the approver may not approve their own request" in own["reasons"]
    assert ev(pay("I2", 900, approval={"approver": CFO, "decision": "reject"}))["reasons"] \
        == ["a person rejected this payment"]
    assert ev(pay("I3", 50))["reasons"] == ["the supplier is on the sanctions list"]
    assert ev(pay("I4", 50))["reasons"] == ["the invoice is not approved for payment"]
    assert ev(pay("I1", 99))["reasons"] == ["the amount differs from the invoice"]
    assert ev(pay("NOPE", 1))["reasons"] == ["the invoice was not found"]
    assert ev({"tool": "erp.invoice.get", "agent": AGENT, "arguments": {}})["decision"] \
        == "allow"
    assert len(rules.sha256) == 32 and rules.data_sha256 == policy.data_sha256(dict(DATA))


def test_sandbox_limits_and_bad_modules(rules, monkeypatch):
    monkeypatch.setattr(policy, "FUEL", 1000)
    with pytest.raises(policy.PolicyError, match="failed to run"):
        rules.evaluate(pay("I1", 100))
    monkeypatch.undo()
    with pytest.raises(policy.PolicyError, match="no entrypoint"):
        policy.Policy(rules.wasm, DATA, "aeos/other").evaluate(pay("I1", 100))
    with pytest.raises(Exception):
        policy.Policy(b"not wasm", DATA, "x")


@pytest.fixture
def gateway(tmp_path, rules):
    td = identity.TrustDomain(DOMAIN)
    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(td.bundle_pem())
    files = {n: td.issue(i).write(tmp_path / "svid", n) for n, i in (("gw", GATEWAY),
                                                                      ("ap", AGENT))}
    person, cfo = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    env = delegation.IntentEnvelope(PERSON, AGENT, "pay", ["erp.invoice.pay"], 10_000, 10_000,
                                    "USD", now_ms() + 3_600_000).sign(person)
    auth = delegation.Authority()
    token = auth.mint(env, keys.public_bytes(person))
    log = ReceiptLog.create(tmp_path / "log", log_id="urn:example:pol")
    gw = Gateway(log, {"erp.invoice.pay": lambda a: {"paid": a["invoice"]}},
                 permissions={AGENT: ["erp.invoice.pay"]}, trust_domain=DOMAIN,
                 svid_files=files["gw"], bundle_file=bundle, authority_key=auth.public_key,
                 intents={env.cid: env},
                 principal_keys={PERSON: keys.public_bytes(person), CFO: keys.public_bytes(cfo)},
                 policy=rules, policy_facts=lambda t, a: {"invoice": INVOICES[a["invoice"]]}
                 if a.get("invoice") in INVOICES else {})
    port = gw.start()
    c = AgentClient(port, files["ap"], bundle, gateway_id=GATEWAY, trust_domain=DOMAIN,
                    token=token.to_bytes())
    c.initialize()
    yield gw, log, c, {"person": person, "cfo": cfo}
    gw.stop()


def text(reply):
    return reply["result"]["content"][0]["text"]


def test_gateway_escalates_and_accepts_one_valid_approval(gateway):
    gw, log, c, k = gateway
    args = {"invoice": "I2", "amount_minor": 900}
    esc = c.call("erp.invoice.pay", args)["result"]["structuredContent"]["escalation"]

    def approval(who, key, a=args, e=esc):
        return delegation.Approval(e, who, "approve", "erp.invoice.pay", json_digest(a),
                                   now_ms()).sign(key)

    assert "different call" in text(c.call("erp.invoice.pay", {"invoice": "I1",
                                                               "amount_minor": 100},
                                           approval=approval(CFO, k["cfo"])))
    assert "does not verify" in text(c.call("erp.invoice.pay", args,
                                            approval=approval(CFO, k["person"])))
    assert "their own request" in text(c.call("erp.invoice.pay", args,
                                              approval=approval(PERSON, k["person"])))
    ok = c.call("erp.invoice.pay", args, approval=approval(CFO, k["cfo"]))
    assert ok["result"]["structuredContent"] == {"paid": "I2"}
    assert "open escalation" in text(c.call("erp.invoice.pay", args,
                                            approval=approval(CFO, k["cfo"])))
    kinds = [log.record(e)["kind"] for e in log.entries()]
    assert kinds.count("approval") == 2 and gw.escalations == {}


def test_audit_replays_policy_and_checks_approvals(tmp_path):
    folder = tmp_path / "full"
    assert fulldemo.run(folder, out=lambda _: None) == 0
    findings, problems = audit.run(folder)
    assert problems == [] and any("policy decisions" in f for f in findings)

    broken = tmp_path / "broken"
    shutil.copytree(folder, broken)
    for f in (broken / "policies").glob("*.wasm"):
        f.unlink()
    assert any("not in the evidence" in p for p in audit.run(broken)[1])

    other = tmp_path / "other"
    shutil.copytree(folder, other)
    data_file = next((other / "policies").glob("data-*.json"))
    doc = json.loads(data_file.read_text())
    doc["escalate_above_minor"] = 10**9                  # rules the gateway did not use
    new = other / "policies" / f"data-{policy.data_sha256(doc).hex()}.json"
    new.write_text(json.dumps(doc))
    data_file.unlink()
    assert any("not in the evidence" in p for p in audit.run(other)[1])

    stranger = {fulldemo.CONTROLLER: "00" * 32, fulldemo.CFO: "00" * 32}
    (tmp_path / "p.json").write_text(json.dumps(stranger))
    assert any("approval is not signed" in p
               for p in audit.run(folder, principals=tmp_path / "p.json")[1])
