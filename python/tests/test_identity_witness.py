import datetime as dt
import json
import logging
import shutil
import ssl
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aeos import ActionLog, audit, fulldemo, identity, witness
from aeos.gateway import AgentClient, CertificateExpiredError, Gateway, handshake_error
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
    log = ActionLog.create(tmp_path / "log", log_id="urn:example:gw")
    log.tool_runs = []                    # what the tool actually did, to compare with the log

    def pay(a):
        log.tool_runs.append(a)
        return {"paid": a["amount"]}

    gw = Gateway(log, {"erp.pay": pay},
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
    start = recs[1]                                 # recs[0] is the signing marker
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


def test_the_gateway_itself_refuses_an_expired_certificate_with_the_real_reason(gateway, td):
    # The client's own check is off here, as for software that replays a stolen certificate.
    # The reason must arrive every time: the alert used to race the request and lose, leaving
    # "connection reset by peer".
    log, client, tmp = gateway
    old = td.issue(AGENT, not_before=dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
                   ).write(tmp / "svid", "old")
    port = client("ap").port
    for _ in range(25):
        replay = AgentClient(port, old, tmp / "bundle.pem", gateway_id=GATEWAY,
                             trust_domain=DOMAIN, check_own_certificate=False)
        with pytest.raises(OSError) as refused:
            replay.initialize()
        assert handshake_error(refused.value) == "the certificate has expired"
    assert len(log) == 0


def test_a_certificate_that_expires_mid_session_is_refused_locally_with_a_plain_reason(
        gateway, td):
    log, client, tmp = gateway
    short = td.issue(AGENT, ttl=dt.timedelta(minutes=5)).write(tmp / "svid", "short")
    now = [dt.datetime.now(dt.timezone.utc)]
    port = client("ap").port
    c = AgentClient(port, short, tmp / "bundle.pem", gateway_id=GATEWAY, trust_domain=DOMAIN,
                    clock=lambda: now[0])
    c.initialize()
    assert c.call("erp.pay", {"amount": 1})["result"]["structuredContent"] == {"paid": 1}
    before = len(log)
    now[0] += dt.timedelta(minutes=6)
    with pytest.raises(CertificateExpiredError, match="your certificate has expired") as e:
        c.call("erp.pay", {"amount": 1})
    assert handshake_error(e.value) == "your certificate has expired"
    assert len(log) == before                      # nothing was sent


def _failing_append(log, fails_when):
    real = log.append

    def append(record, *args, **kwargs):
        if fails_when(record):
            raise OSError(28, "No space left on device")
        return real(record, *args, **kwargs)

    log.append = append


def test_a_call_that_cannot_be_recorded_is_not_run_and_the_agent_is_told(gateway, caplog):
    log, client, tmp = gateway
    c = client("ap")
    c.initialize()
    _failing_append(log, lambda r: r["kind"] == "tool.call")      # the disk fills up
    with caplog.at_level(logging.ERROR, logger="aeos.gateway"):
        reply = c.call("erp.pay", {"amount": 5})
    assert reply["result"]["isError"] is True
    assert reply["result"]["structuredContent"] == {"recorded": False, "ran": False}
    assert "not performed" in reply["result"]["content"][0]["text"]
    assert log.tool_runs == []                       # the tool never ran: record first, then act
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert errors and "No space left on device" in errors[0].getMessage()


def test_a_result_that_cannot_be_recorded_is_reported_as_run_but_not_on_record(gateway, caplog):
    log, client, tmp = gateway
    c = client("ap")
    c.initialize()
    _failing_append(log, lambda r: r["kind"] == "tool.result")
    with caplog.at_level(logging.ERROR, logger="aeos.gateway"):
        reply = c.call("erp.pay", {"amount": 5})
    assert reply["result"]["isError"] is True
    assert reply["result"]["structuredContent"] == {"recorded": False, "ran": True}
    assert "ran, but its result could not be written" in reply["result"]["content"][0]["text"]
    assert log.tool_runs == [{"amount": 5}]
    assert any(r.levelno == logging.ERROR for r in caplog.records)
    kinds = [log.record(e)["kind"] for e in log.entries()]
    assert kinds[-1] == "tool.call"                  # the call is on record, with no result


def test_a_session_that_cannot_be_recorded_is_not_opened(gateway, caplog):
    log, client, tmp = gateway
    _failing_append(log, lambda r: True)
    with caplog.at_level(logging.ERROR, logger="aeos.gateway"):
        reply = client("ap").initialize()
    assert reply["error"]["code"] == -32003
    assert any(r.levelno == logging.ERROR for r in caplog.records)


def test_a_refused_handshake_is_logged_at_info_without_certificate_contents(gateway, td,
                                                                          caplog):
    log, client, tmp = gateway
    old = td.issue(AGENT, not_before=dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
                   ).write(tmp / "svid", "old")
    with caplog.at_level(logging.INFO, logger="aeos.gateway"):
        with pytest.raises(OSError):
            AgentClient(client("ap").port, old, tmp / "bundle.pem", gateway_id=GATEWAY,
                        trust_domain=DOMAIN, check_own_certificate=False).initialize()
    refused = [r.getMessage() for r in caplog.records
               if r.getMessage().startswith("refused a TLS handshake")]
    assert refused and refused[0].startswith("refused a TLS handshake from 127.0.0.1: ")
    assert "certificate has expired" in refused[0] and "BEGIN" not in refused[0]
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


def test_the_server_only_stays_quiet_about_refused_handshakes(caplog):
    from aeos.gateway import HandshakeRefused, _MutualTlsServer
    server = object.__new__(_MutualTlsServer)
    with caplog.at_level(logging.INFO, logger="aeos.gateway"):
        for exc, expect_error in ((HandshakeRefused("x"), False),
                                  (OSError(28, "disk full"), True),
                                  (PermissionError("no key"), True),
                                  (ssl.SSLError("late"), True)):
            caplog.clear()
            try:
                raise exc
            except Exception:
                server.handle_error(None, ("127.0.0.1", 1))
            logged_error = any(r.levelno == logging.ERROR for r in caplog.records)
            assert logged_error is expect_error, exc


def test_a_reset_after_the_handshake_is_described_plainly():
    for err in (ConnectionResetError(), BrokenPipeError()):
        assert handshake_error(err) == (
            "the gateway closed the connection; it may have refused this certificate")


def test_an_accepted_first_call_adds_no_waiting(gateway):
    log, client, tmp = gateway
    client("ap").initialize()                       # warm up imports and caches
    took = []
    for _ in range(7):
        c = client("ap")
        t0 = time.perf_counter()
        c.initialize()
        took.append(time.perf_counter() - t0)
    assert sorted(took)[len(took) // 2] < 0.05, took


def _log_with(tmp_path, name, n):
    log = ActionLog.create(tmp_path / name, log_id="urn:example:w",
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
        .last_size("urn:example:w") == 5


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
