"""Each action record is signed by the issuer key, and verifiers check it when present."""
import base64
import json
from pathlib import Path

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


def test_log_written_without_the_key_has_unsigned_records_that_still_verify(tmp_path):
    log = _log(tmp_path, 2)
    reader = ActionLog.open(tmp_path / "log")           # signing.key is found: signs
    reader._key = None                                   # a writer without the key
    reader.append(make_record("note", AGENT, body={"i": 99}))
    rep = ActionLog.open(tmp_path / "log", read_only=True).verify()
    assert rep.ok and rep.records == 3 and rep.issuer_signed == 2
    assert log.public_key


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
