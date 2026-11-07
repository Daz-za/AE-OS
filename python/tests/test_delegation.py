import datetime as dt
import json
import shutil

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aeos import ActionLog, audit, delegation, fulldemo, identity, keys
from aeos.gateway import AgentClient, Gateway
from aeos.log import now_ms

DOMAIN = "acme.example"
AGENT = f"spiffe://{DOMAIN}/agent/ap"
HELPER = f"{AGENT}/helper"
OTHER = f"spiffe://{DOMAIN}/agent/apx"
PERSON = f"spiffe://{DOMAIN}/human/controller"
GATEWAY = f"spiffe://{DOMAIN}/gateway/erp"


def envelope(key, **kw):
    fields = dict(principal=PERSON, audience=AGENT, purpose="Pay invoices",
                  actions=["erp.get", "erp.pay"], per_action_max_minor=500, budget_minor=800,
                  currency="USD", not_after=now_ms() + 3_600_000)
    fields.update(kw)
    return delegation.IntentEnvelope(**fields).sign(key)


@pytest.fixture(scope="module")
def setup():
    person = Ed25519PrivateKey.generate()
    env = envelope(person)
    auth = delegation.Authority()
    return person, env, auth, auth.mint(env, keys.public_bytes(person))


def check(auth, token, subject=AGENT, tool="erp.pay", amount=100, at=None):
    return delegation.authorize(token.to_bytes(), auth.public_key, subject=subject, tool=tool,
                                amount=amount, at=at or now_ms())


def test_token_checks_subject_tool_amount_and_time(setup):
    person, env, auth, token = setup
    ok = check(auth, token)
    assert ok.allowed and ok.intent == env.cid and ok.principal == PERSON
    assert check(auth, token, subject=HELPER).allowed           # sub-agents of the audience
    assert check(auth, token, subject=OTHER).reasons == [
        "the token was issued to a different agent"]
    assert check(auth, token, tool="erp.delete").reasons == ["the token does not cover this tool"]
    assert check(auth, token, amount=501).reasons == ["the amount is above the token's limit"]
    assert check(auth, token, at=env.not_after + 1).reasons == ["the token has expired"]
    other = delegation.Authority()
    assert "not signed by the trusted authority" in delegation.authorize(
        token.to_bytes(), other.public_key, subject=AGENT, tool="erp.pay", amount=1,
        at=now_ms()).reasons[0]
    with pytest.raises(delegation.DelegationError):
        auth.mint(env, keys.public_bytes(Ed25519PrivateKey.generate()))


def test_attenuation_only_narrows(setup):
    _, _, auth, token = setup
    narrow = delegation.attenuate(token, subject=HELPER, actions=["erp.get"], max_minor=0)
    assert check(auth, narrow, subject=HELPER, tool="erp.get", amount=0).allowed
    assert not check(auth, narrow, subject=AGENT, tool="erp.get", amount=0).allowed
    assert not check(auth, narrow, subject=HELPER, tool="erp.pay", amount=0).allowed
    wider = delegation.attenuate(token, max_minor=10_000, actions=["erp.pay", "erp.delete"])
    assert check(auth, wider, amount=501).reasons == ["the amount is above the token's limit"]
    assert not check(auth, wider, tool="erp.delete").allowed


def test_envelope_signature_and_round_trip(setup):
    person, env, _, _ = setup
    again = delegation.IntentEnvelope.from_json(json.loads(json.dumps(env.to_json())))
    assert again.cid == env.cid and again.verify(keys.public_bytes(person))
    again.per_action_max_minor = 10**9
    assert not again.verify(keys.public_bytes(person))


@pytest.fixture
def gateway(tmp_path, setup):
    person, env, auth, token = setup
    td = identity.TrustDomain(DOMAIN)
    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(td.bundle_pem())
    files = {n: td.issue(i).write(tmp_path / "svid", n)
             for n, i in (("gw", GATEWAY), ("ap", AGENT), ("other", OTHER))}

    def pay(a):
        if a.get("fail"):
            raise ValueError("bank unavailable")
        return {"paid": a["amount_minor"]}

    log = ActionLog.create(tmp_path / "log", log_id="urn:example:cap")
    gw = Gateway(log, {"erp.pay": pay}, permissions={AGENT: ["erp.pay"], OTHER: ["erp.pay"]},
                 trust_domain=DOMAIN, svid_files=files["gw"], bundle_file=bundle,
                 authority_key=auth.public_key, intents={env.cid: env},
                 principal_keys={PERSON: keys.public_bytes(person)})
    port = gw.start()

    def client(name, tok=token):
        c = AgentClient(port, files[name], bundle, gateway_id=GATEWAY, trust_domain=DOMAIN,
                        token=tok.to_bytes() if tok else None)
        c.initialize()
        return c

    yield gw, log, client
    gw.stop()


def text(reply):
    return reply["result"]["content"][0]["text"]


def _fail_appends(log, when):
    real = log.append

    def append(record, *a, **kw):
        if when(record):
            raise OSError(28, "No space left on device")
        return real(record, *a, **kw)

    log.append = append
    return real


def test_a_decision_write_that_fails_gives_the_reserved_budget_back(gateway, setup):
    gw, log, client = gateway
    env = setup[1]
    ap = client("ap")
    assert ap.call("erp.pay", {"amount_minor": 100})["result"]["structuredContent"]
    assert gw.budget.spent[env.cid] == 100
    real = _fail_appends(log, lambda r: r["kind"] == "policy.decision")
    reply = ap.call("erp.pay", {"amount_minor": 300})
    assert reply["result"]["structuredContent"] == {"recorded": False, "ran": False}
    assert gw.budget.spent[env.cid] == 100                     # the 300 went back
    log.append = real
    assert ap.call("erp.pay", {"amount_minor": 300})["result"]["structuredContent"]
    assert gw.budget.spent[env.cid] == 400


def test_an_unexpected_error_also_gives_the_reserved_budget_back(gateway, setup, monkeypatch,
                                                                caplog):
    gw, log, client = gateway
    env = setup[1]
    ap = client("ap")

    def boom(*a, **kw):
        raise RuntimeError("something nobody expected")

    monkeypatch.setattr(gw.recorder(AGENT), "decision", boom)
    with caplog.at_level("ERROR", logger="aeos.gateway"):
        reply = ap.call("erp.pay", {"amount_minor": 200})
    assert reply["error"]["code"] == -32603 and "may not have been recorded" in \
        reply["error"]["message"]
    assert gw.budget.spent.get(env.cid, 0) == 0
    assert any("something nobody expected" in r.getMessage() or r.exc_info
               for r in caplog.records if r.levelno == 40)


def test_a_failure_that_cannot_be_recorded_is_not_called_a_success(gateway, setup):
    gw, log, client = gateway
    env = setup[1]
    ap = client("ap")
    _fail_appends(log, lambda r: r["kind"] == "tool.result")
    reply = ap.call("erp.pay", {"amount_minor": 300, "fail": True})       # the tool raises
    text_ = text(reply)
    assert text_.startswith("The action was attempted and failed")
    assert "ran" not in text_.split(",")[0]
    assert reply["result"]["structuredContent"] == {"recorded": False, "ran": False,
                                                    "attempted": True}
    assert gw.budget.spent.get(env.cid, 0) == 0                # a call that failed spends nothing


def test_gateway_requires_a_token_and_meters_the_budget(gateway, setup):
    gw, log, client = gateway
    env = setup[1]
    assert "no readable capability token" in text(client("ap", None).call("erp.pay",
                                                                          {"amount_minor": 1}))
    assert "different agent" in text(client("other").call("erp.pay", {"amount_minor": 1}))
    ap = client("ap")
    assert ap.call("erp.pay", {"amount_minor": 500})["result"]["structuredContent"]
    assert "bank unavailable" in text(ap.call("erp.pay", {"amount_minor": 300, "fail": True}))
    assert ap.call("erp.pay", {"amount_minor": 300})["result"]["structuredContent"]
    assert "above its budget of USD 8.00" in text(ap.call("erp.pay", {"amount_minor": 1}))
    assert "whole, non-negative" in text(ap.call("erp.pay", {"amount_minor": -5}))
    assert gw.budget.spent[env.cid] == 800
    decisions = [log.record(e) for e in log.entries()
                 if log.record(e)["kind"] == "policy.decision"]
    allowed = [d for d in decisions if d["body"]["decision"] == "allow"]
    assert len(allowed) == 3 and all(d["obo"] == PERSON for d in allowed)
    assert allowed[0]["body"]["intent"] == env.cid


def test_audit_replays_decisions_and_catches_missing_evidence(tmp_path):
    folder = tmp_path / "full"
    assert fulldemo.run(folder, out=lambda _: None) == 0
    findings, problems = audit.run(folder)
    assert problems == [] and any("capability decisions" in f for f in findings)

    broken = tmp_path / "broken"
    shutil.copytree(folder, broken)
    for f in (broken / "tokens").glob("*.biscuit"):
        f.unlink()
    assert any("is not in the evidence" in p for p in audit.run(broken)[1])

    stranger = {fulldemo.CONTROLLER: "00" * 32}
    (tmp_path / "p.json").write_text(json.dumps(stranger))
    problems = audit.run(folder, principals=tmp_path / "p.json")[1]
    # Unsigned period changes leave the books' periods unopened, so their entries fail too, and
    # a decision that rests on an approval that does not verify fails with it.
    assert problems and all("is not signed by" in p or "has not been opened" in p
                            or "verified approval of this call" in p for p in problems)
    assert audit.run(folder, authority_key=delegation.Authority().public_key.hex())[1]
