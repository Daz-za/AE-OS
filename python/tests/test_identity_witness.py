import datetime as dt
import json
import shutil

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aeos import ReceiptLog, audit, fulldemo, identity, witness
from aeos.gateway import AgentClient, Gateway
from aeos.log import make_record

DOMAIN = "acme.example"
AGENT = f"spiffe://{DOMAIN}/agent/ap"
GATEWAY = f"spiffe://{DOMAIN}/gateway/erp"


@pytest.fixture(scope="module")
def td():
    return identity.TrustDomain(DOMAIN)


def test_svids_verify_within_their_lifetime_and_domain(td):
    svid = td.issue(AGENT)
    assert identity.verify_svid(svid.chain, [td.root], trust_domain=DOMAIN) == AGENT
    later = svid.leaf.not_valid_after_utc + dt.timedelta(seconds=1)
    with pytest.raises(identity.IdentityError, match="was not valid at"):
        identity.verify_svid(svid.chain, [td.root], at=later)
    other = identity.TrustDomain("rogue.example")
    with pytest.raises(identity.IdentityError, match="not issued by a trusted authority"):
        identity.verify_svid(other.issue("spiffe://rogue.example/agent/ap").chain, [td.root])
    with pytest.raises(identity.IdentityError, match="belongs to trust domain"):
        identity.verify_svid(svid.chain, [td.root], trust_domain="other.example")
    with pytest.raises(identity.IdentityError):
        td.issue("spiffe://rogue.example/agent/ap")
    for bad in ("https://acme.example/x", "spiffe://Acme.example/x", "spiffe://acme.example/"):
        with pytest.raises(identity.IdentityError):
            identity.parse_spiffe_id(bad)
    assert svid.leaf.not_valid_after_utc - svid.leaf.not_valid_before_utc == identity.SVID_TTL


@pytest.fixture
def gateway(tmp_path, td):
    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(td.bundle_pem())
    files = {n: td.issue(i).write(tmp_path / "svid", n)
             for n, i in (("gw", GATEWAY), ("ap", AGENT),
                          ("payroll", f"spiffe://{DOMAIN}/agent/payroll"))}
    log = ReceiptLog.create(tmp_path / "log", log_id="urn:example:gw")
    gw = Gateway(log, {"erp.pay": lambda a: {"paid": a["amount"]}},
                 permissions={AGENT: ["erp.pay"]}, trust_domain=DOMAIN,
                 svid_files=files["gw"], bundle_file=bundle)
    port = gw.start()

    def client(name, b=bundle):
        return AgentClient(port, files[name] if isinstance(name, str) else name, b,
                           gateway_id=GATEWAY, trust_domain=DOMAIN)

    yield log, client, tmp_path
    gw.stop()


def test_gateway_records_calls_under_the_certificate_identity(gateway, td):
    log, client, tmp = gateway
    c = client("ap")
    c.initialize()
    assert c.call("erp.pay", {"amount": 5})["result"]["structuredContent"] == {"paid": 5}
    c.close()
    p = client("payroll")
    p.initialize()
    assert p.call("erp.pay", {"amount": 5})["result"]["isError"]
    p.session = c.session or "x"                    # another identity's session is refused
    assert p.call("erp.pay", {"amount": 5})["error"]["code"] == -32001
    recs = [log.record(e) for e in log.entries()]
    start = recs[0]
    assert start["kind"] == "session.start" and start["agent"] == AGENT
    assert len(start["body"]["svid_sha256"]) == 32
    denied = [r for r in recs if r["kind"] == "policy.decision"]
    assert denied[0]["agent"].endswith("/payroll") and denied[0]["body"]["decision"] == "deny"
    assert log.verify().ok


def test_gateway_refuses_expired_and_foreign_certificates(gateway, td):
    log, client, tmp = gateway
    old = td.issue(AGENT, not_before=dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1))
    with pytest.raises(OSError):
        client(old.write(tmp / "svid", "old")).initialize()
    rogue = identity.TrustDomain("rogue.example")
    both = tmp / "both.pem"
    both.write_bytes(rogue.bundle_pem() + td.bundle_pem())
    with pytest.raises(OSError):
        client(rogue.issue("spiffe://rogue.example/agent/ap").write(tmp / "svid", "r"),
               both).initialize()
    assert len(log) == 0


def _log_with(tmp_path, name, n):
    log = ReceiptLog.create(tmp_path / name, log_id="urn:example:w",
                            key_path=tmp_path / "log.key")
    for i in range(n):
        log.append(make_record("x-step", AGENT, body={"i": i}))
    return log


def test_witnesses_cosign_growth_and_refuse_a_split_view(tmp_path):
    log = _log_with(tmp_path, "log", 3)
    a = witness.Witness("a", Ed25519PrivateKey.generate(), tmp_path / "a.json")
    b = witness.Witness("b", Ed25519PrivateKey.generate())
    keys = {"a": a.public_key, "b": b.public_key}
    cp1 = log.checkpoint()
    witness.request_cosignatures(log, cp1, [a, b])
    log.append(make_record("x-step", AGENT, body={"i": 3}))
    cp2 = log.checkpoint()
    cos = witness.request_cosignatures(log, cp2, [a, b])
    assert witness.verify_cosignatures(cp2, witness.load_cosignatures(log.path), keys, 2) == []
    assert witness.verify_cosignatures(cp2, cos[:1], keys, 2)[-1].endswith("at least 2 needed")
    bad = dict(cos[0], sig=cos[1]["sig"])
    assert "does not verify" in witness.verify_cosignatures(cp2, [bad], keys, 1)[0]

    fork = _log_with(tmp_path, "fork", 4)            # same key, different fourth record
    fork.append(make_record("x-step", AGENT, body={"i": 99}))
    with pytest.raises(witness.WitnessRefused, match="does not extend"):
        witness.request_cosignatures(fork, fork.checkpoint(), [a])
    small = _log_with(tmp_path, "small", 2)
    with pytest.raises(witness.WitnessRefused, match="smaller"):
        witness.request_cosignatures(small, small.checkpoint(), [b])
    # the witness remembers what it cosigned between runs
    assert witness.Witness("a", Ed25519PrivateKey.generate(), tmp_path / "a.json") \
        .last_size("urn:example:w") == 4


def test_full_demo_leaves_evidence_that_audits_clean_and_catches_changes(tmp_path):
    out = []
    folder = tmp_path / "full"
    assert fulldemo.run(folder, out=out.append) == 0
    text = " ".join("\n".join(out).split())          # undo line wrapping
    assert "has expired" in text and "not issued by a trusted authority" in text
    assert "split view" in text and "Result: VALID" in text
    assert audit.run(folder)[1] == []
    assert fulldemo.run(folder, out=out.append) == 2

    # an SVID missing from the evidence, and witnesses an auditor does not trust
    broken = tmp_path / "broken"
    shutil.copytree(folder, broken)
    next(iter(sorted((broken / "svids").glob("accounts-payable-1.pem")))).unlink()
    other = {"required": 1, "keys": {"stranger": "00" * 32}}
    (broken / "witnesses.json").write_text(json.dumps(other))
    problems = audit.run(broken)[1]
    assert any("is not in the evidence" in p for p in problems)
    assert any("at least 1 needed" in p for p in problems)
    assert audit.run(folder, public_key="ab" * 32)[1][0].startswith("the log's public key")
