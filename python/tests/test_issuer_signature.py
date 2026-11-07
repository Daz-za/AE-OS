"""Each action record is signed by the issuer key, and verifiers check it when present."""
import base64
import json
from pathlib import Path

import pytest

from aeos import ActionLog, keys, make_record, verify_action_record_detail
from aeos.canon import cid_of_bytes, dag_cbor
from aeos.cli import main
from aeos.log import ISSUER_SIGNED, LOG_SIGNED_ONLY, b64, statement_message

AGENT = "spiffe://acme.example/agent/a"
V0_FILE = Path(__file__).resolve().parents[2] / "testvectors" / "receipts-v0.json"


def _log(tmp_path, n=3):
    log = ActionLog.create(tmp_path / "log")
    for i in range(n):
        log.append(make_record("note", AGENT, body={"i": i}))
    log.checkpoint()
    return log


def test_append_signs_the_cid_under_its_own_context(tmp_path):
    log = _log(tmp_path)
    e = log.entries()[1]
    assert e.sig and e.signer == log.meta["key_id"]
    assert keys.verify(log.public_key, e.sig, b"aeos-action-record/statement/v1\n" + e.cid)
    assert not keys.verify(log.public_key, e.sig, b"aeos-receipts/checkpoint/v0\n" + e.cid)
    # a reopened log reads the signatures back
    again = ActionLog.open(tmp_path / "log", read_only=True)
    assert again.entries()[1].sig == e.sig
    doc = log.action_record(e)
    assert doc["statement_signature"] == {"key_id": e.signer, "sig": b64(e.sig)}
    assert verify_action_record_detail(doc, log.public_key) == ([], ISSUER_SIGNED)


def test_signature_does_not_change_the_record_bytes_or_cid(tmp_path):
    # the signature sits beside the record, so v0 CIDs, leaves and checkpoints are untouched
    log = _log(tmp_path)
    e = log.entries()[0]
    assert cid_of_bytes(dag_cbor(log.record(e))) == e.cid
    assert b"sig" not in e.raw and b"key_id" not in e.raw


def test_tampered_and_foreign_signatures_are_problems_never_log_signed_only(tmp_path):
    log = _log(tmp_path)
    good = log.action_record(log.entries()[1])
    other = keys.generate_key(tmp_path / "other.key")

    wrong_key = json.loads(json.dumps(good))
    wrong_key["statement_signature"]["sig"] = b64(other.sign(statement_message(
        log.entries()[1].cid)))
    problems, state = verify_action_record_detail(wrong_key, log.public_key)
    assert state == ISSUER_SIGNED and problems == [
        "issuer signature does not verify with the given public key"]

    bad = json.loads(json.dumps(good))
    sig = bytearray(base64.b64decode(bad["statement_signature"]["sig"]))
    sig[0] ^= 1
    bad["statement_signature"]["sig"] = b64(bytes(sig))
    assert verify_action_record_detail(bad, log.public_key)[0]

    other_record = log.action_record(log.entries()[0])["statement_signature"]
    swapped = json.loads(json.dumps(good))
    swapped["statement_signature"] = other_record
    assert verify_action_record_detail(swapped, log.public_key)[0]

    # a verifier holding another key is told the signature names a different key
    problems, _ = verify_action_record_detail(good, keys.public_bytes(other))
    assert "issuer signature names a different key than the given public key" in problems


def test_records_without_a_signature_are_log_signed_only_not_failures(tmp_path):
    log = _log(tmp_path)
    doc = log.action_record(log.entries()[0])
    del doc["statement_signature"]
    assert verify_action_record_detail(doc, log.public_key) == ([], LOG_SIGNED_ONLY)
    # v0 documents from the frozen vectors
    v0 = json.loads(V0_FILE.read_text())["receipts"][0]
    assert verify_action_record_detail(v0["receipt"], bytes.fromhex(v0["public_key"])) == \
        ([], LOG_SIGNED_ONLY)


def test_a_writer_without_the_key_refuses_to_append(tmp_path):
    _log(tmp_path, 2)
    keyless = ActionLog.open(tmp_path / "log", key_path=tmp_path / "missing.key")
    with pytest.raises(PermissionError, match="missing.key"):
        keyless.append(make_record("note", AGENT, body={"i": 99}))
    read_only = ActionLog.open(tmp_path / "log", read_only=True)
    with pytest.raises(PermissionError):
        read_only.append(make_record("note", AGENT, body={"i": 99}))
    assert len(ActionLog.open(tmp_path / "log", read_only=True)) == 2


def test_importing_version_0_data_may_append_unsigned_explicitly(tmp_path):
    keyless = ActionLog.create(tmp_path / "log")
    keyless._key = None
    for i in range(2):
        keyless.append(make_record("note", AGENT, body={"i": i}), allow_unsigned=True)
    rep = ActionLog.open(tmp_path / "log", read_only=True).verify()
    assert rep.ok and rep.records == 2 and rep.issuer_signed == 0


def test_recorder_and_gateway_refuse_a_log_that_cannot_sign(tmp_path):
    from aeos.recorder import Recorder
    _log(tmp_path, 1)
    keyless = ActionLog.open(tmp_path / "log", key_path=tmp_path / "missing.key")
    with pytest.raises(PermissionError, match="missing.key"):
        Recorder(keyless, agent=AGENT)
    from aeos.gateway import Gateway
    with pytest.raises(PermissionError, match="missing.key"):
        Gateway(keyless, {}, permissions={}, trust_domain="acme.example",
                svid_files=(tmp_path / "a", tmp_path / "b"), bundle_file=tmp_path / "c")


def test_every_cli_path_that_writes_names_where_it_looked_for_the_key(tmp_path, capsys):
    log = _log(tmp_path, 1)
    missing = str(tmp_path / "nowhere.key")
    events = tmp_path / "events.jsonl"
    events.write_text("")
    for argv in (["append", str(log.path), "--agent", AGENT, "--kind", "note", "--key", missing],
                 ["checkpoint", str(log.path), "--key", missing],
                 ["ingest", str(log.path), str(events), "--agent", AGENT, "--key", missing],
                 ["mcp-proxy", str(log.path), "--agent", AGENT, "--key", missing, "--", "true"]):
        assert main(argv) == 2, argv
        assert "nowhere.key" in capsys.readouterr().err, argv
    assert len(ActionLog.open(log.path, read_only=True)) == 1


def test_a_hook_without_the_key_refuses_the_tool_call_and_says_why(tmp_path):
    from aeos import hooks
    from aeos.recorder import Recorder
    log = _log(tmp_path, 1)

    def recorder():
        return Recorder(ActionLog.open(log.path, key_path=tmp_path / "gone.key"), agent=AGENT)

    code, out, err = hooks.run(recorder, json.dumps(
        {"hook_event_name": "PreToolUse", "tool_name": "t", "tool_use_id": "1",
         "session_id": "s"}))
    assert "deny" in out and "gone.key" in err
    assert len(ActionLog.open(log.path, read_only=True)) == 1


def test_stripping_a_signature_is_a_problem_even_when_the_rest_still_holds(tmp_path):
    _log(tmp_path, 4)
    path = tmp_path / "log" / "records.jsonl"
    lines = path.read_text().splitlines()
    for i, expected in ((3, "record 3: issuer signature missing after record 0 was signed"),
                        (1, "record 1: issuer signature missing after record 0 was signed")):
        stripped = json.loads(lines[i])
        del stripped["sig"], stripped["key_id"]
        edited = list(lines)
        edited[i] = json.dumps(stripped, separators=(",", ":"))
        path.write_text("\n".join(edited) + "\n")
        problems = ActionLog.open(tmp_path / "log", read_only=True).verify().problems
        assert problems == [expected]
    # a key id left behind without its signature is a problem of its own
    kept = json.loads(lines[2])
    kept["sig"] = ""
    edited = list(lines)
    edited[2] = json.dumps(kept, separators=(",", ":"))
    path.write_text("\n".join(edited) + "\n")
    assert ActionLog.open(tmp_path / "log", read_only=True).verify().problems == [
        "record 2: issuer key id present without a signature",
        "record 2: issuer signature missing after record 0 was signed"]
    path.write_text("\n".join(lines) + "\n")
    assert ActionLog.open(tmp_path / "log", read_only=True).verify().ok


def test_a_trail_with_no_signatures_at_all_is_a_version_0_trail_not_a_failure(tmp_path):
    _log(tmp_path, 3)
    path = tmp_path / "log" / "records.jsonl"
    out = []
    for line in path.read_text().splitlines():
        d = json.loads(line)
        del d["sig"], d["key_id"]
        out.append(json.dumps(d, separators=(",", ":")))
    path.write_text("\n".join(out) + "\n")
    rep = ActionLog.open(tmp_path / "log", read_only=True).verify()
    assert rep.ok and rep.issuer_signed == 0


def test_a_malformed_signature_is_reported_never_a_crash(tmp_path):
    _log(tmp_path, 3)
    path = tmp_path / "log" / "records.jsonl"
    lines = path.read_text().splitlines()
    for bad in (5, ["x"], {"a": 1}, True, "not base64!"):
        d = json.loads(lines[1])
        d["sig"] = bad
        edited = list(lines)
        edited[1] = json.dumps(d, separators=(",", ":"))
        path.write_text("\n".join(edited) + "\n")
        opened = ActionLog.open(tmp_path / "log", read_only=True)      # still opens
        assert opened.verify().problems == ["record 1: issuer signature does not verify"], bad


def test_weak_keys_and_signatures_are_refused(tmp_path):
    identity_key = bytes.fromhex("01" + "00" * 31)
    forged = identity_key + bytes(32)                 # verifies for every message if lax
    assert keys.is_small_order(identity_key) and not keys.verify(identity_key, forged, b"x")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(identity_key).verify(forged, b"x")   # OpenSSL is lax
    real = keys.generate_key(tmp_path / "k.key")
    pub = keys.public_bytes(real)
    assert not keys.is_small_order(pub) and keys.verify(pub, real.sign(b"m"), b"m")
    sig = real.sign(b"m")
    unreduced = sig[:32] + (int.from_bytes(sig[32:], "little") + keys._L).to_bytes(32, "little")
    assert not keys.verify(pub, unreduced, b"m")
    assert not keys.verify(pub, identity_key + sig[32:], b"m")
    with pytest.raises(SystemExit, match="small order"):
        from aeos.cli import _public_key
        _public_key(identity_key.hex())


def test_audit_trail_verification_flags_an_altered_issuer_signature(tmp_path):
    log = _log(tmp_path)
    path = tmp_path / "log" / "records.jsonl"
    lines = path.read_text().splitlines()
    d = json.loads(lines[1])
    sig = bytearray(base64.b64decode(d["sig"]))
    sig[0] ^= 1
    d["sig"] = b64(bytes(sig))
    lines[1] = json.dumps(d, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    rep = ActionLog.open(tmp_path / "log", read_only=True).verify()
    assert rep.problems == ["record 1: issuer signature does not verify"]
    assert log.public_key


def test_cli_reports_who_vouches_for_the_record(tmp_path, capsys):
    log = _log(tmp_path)
    pub = str(log.path / "log.json")
    signed = tmp_path / "signed.json"
    assert main(["action-record", str(log.path), "0", "-o", str(signed)]) == 0
    capsys.readouterr()
    assert main(["verify-action-record", str(signed), "--public-key", pub]) == 0
    assert "signed by its issuer" in capsys.readouterr().out
    doc = json.loads(signed.read_text())
    del doc["statement_signature"]
    unsigned = tmp_path / "unsigned.json"
    unsigned.write_text(json.dumps(doc))
    assert main(["verify-action-record", str(unsigned), "--public-key", pub]) == 0
    assert "log-signed only" in capsys.readouterr().out
    doc["statement_signature"] = {"key_id": log.meta["key_id"], "sig": b64(b"\0" * 64)}
    unsigned.write_text(json.dumps(doc))
    assert main(["verify-action-record", str(unsigned), "--public-key", pub]) == 1
    assert "issuer signature does not verify" in capsys.readouterr().out
