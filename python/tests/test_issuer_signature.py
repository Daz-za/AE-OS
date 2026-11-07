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
    e = log.entries()[1]
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
    assert len(ActionLog.open(tmp_path / "log", read_only=True)) == 3   # marker and two


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
    assert len(ActionLog.open(log.path, read_only=True)) == 2     # marker and one


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
    assert len(ActionLog.open(log.path, read_only=True)) == 2     # marker and one


def _edit_lines(tmp_path, edits):
    """Rewrite records.jsonl with `edits` ({index: function(dict)}) applied; returns problems."""
    path = tmp_path / "log" / "records.jsonl"
    lines = path.read_text().splitlines()
    for i, fn in edits.items():
        d = json.loads(lines[i])
        fn(d)
        lines[i] = json.dumps(d, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    return ActionLog.open(tmp_path / "log", read_only=True).verify().problems


def _strip(d):
    del d["sig"], d["key_id"]


MARKER_NOTE = "(the issuer-signing marker is record 0)"


def test_the_first_signed_append_writes_a_signed_marker_first(tmp_path):
    log = ActionLog.create(tmp_path / "log")
    first = log.append(make_record("note", AGENT, body={"i": 0}, ts=1234))
    marker = log.entries()[0]
    rec = log.record(marker)
    assert first.index == 1 and marker.index == 0
    assert rec["kind"] == "x-issuer-signing" and rec["ts"] == 1234
    assert rec["body"] == {"key_id": log.meta["key_id"]} and marker.sig
    log.append(make_record("note", AGENT, body={"i": 1}))
    reopened = ActionLog.open(tmp_path / "log")
    reopened.append(make_record("note", AGENT, body={"i": 2}))
    kinds = [reopened.record(e)["kind"] for e in reopened.entries()]
    assert kinds == ["x-issuer-signing", "note", "note", "note"]       # written once
    assert reopened.verify().ok and reopened.verify().issuer_signed == 4


def test_stripping_signatures_after_the_marker_is_always_a_problem(tmp_path):
    _log(tmp_path, 4)
    path = tmp_path / "log" / "records.jsonl"
    original = path.read_text()
    for i in (1, 2, 4):                                      # first, middle and last record
        path.write_text(original)
        assert _edit_lines(tmp_path, {i: _strip}) == [
            f"record {i}: issuer signature missing {MARKER_NOTE}"]
    path.write_text(original)
    problems = _edit_lines(tmp_path, {i: _strip for i in range(5)})       # all of them
    assert problems == [f"record {i}: issuer signature missing {MARKER_NOTE}"
                        for i in range(5)]
    path.write_text(original)
    problems = _edit_lines(tmp_path, {0: _strip, 1: _strip})              # a prefix, marker too
    assert problems == [f"record {i}: issuer signature missing {MARKER_NOTE}" for i in (0, 1)]


def test_a_key_id_left_without_its_signature_is_its_own_problem(tmp_path):
    _log(tmp_path, 3)
    problems = _edit_lines(tmp_path, {2: lambda d: d.update(sig="")})
    assert problems == ["record 2: issuer key id present without a signature",
                        f"record 2: issuer signature missing {MARKER_NOTE}"]


def test_removing_the_marker_breaks_the_checkpoint_that_covers_it(tmp_path):
    _log(tmp_path, 3)
    path = tmp_path / "log" / "records.jsonl"
    lines = path.read_text().splitlines()
    # drop the marker and renumber, as a careful forger would
    kept = []
    for n, line in enumerate(lines[1:]):
        d = json.loads(line)
        d["i"] = n
        kept.append(json.dumps(d, separators=(",", ":")))
    path.write_text("\n".join(kept) + "\n")
    problems = ActionLog.open(tmp_path / "log", read_only=True).verify().problems
    assert any("covers more records" in p for p in problems), problems


def test_a_corrupted_marker_is_reported_not_a_crash(tmp_path, capsys):
    _log(tmp_path, 3)
    path = tmp_path / "log" / "records.jsonl"
    lines = path.read_text().splitlines()
    d = json.loads(lines[0])
    d["cbor"] = b64(base64.b64decode(d["cbor"]) + b"\x00")      # not canonical any more
    lines[0] = json.dumps(d, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    opened = ActionLog.open(tmp_path / "log", read_only=True)       # opens: it used to raise
    problems = opened.verify().problems
    assert problems[0] == "line 1: unreadable record (trailing bytes)"
    assert main(["verify", str(tmp_path / "log")]) == 1             # and the CLI reports it
    assert "unreadable record" in capsys.readouterr().out


def test_a_marker_naming_another_key_is_a_problem(tmp_path):
    log = ActionLog.create(tmp_path / "log")
    other = keys.generate_key(tmp_path / "other.key")
    # a marker for a different key, signed by the trail's key and written by hand
    with log._locked():
        log._write(make_record("x-issuer-signing", log.log_id,
                               body={"key_id": keys.key_id(keys.public_bytes(other))}), None)
    problems = ActionLog.open(tmp_path / "log", read_only=True).verify().problems
    assert problems == ["record 0: the issuer-signing marker names a different key than "
                        "the trail's"]


def test_a_trail_with_no_marker_and_no_signatures_is_a_version_0_trail(tmp_path):
    keyless = ActionLog.create(tmp_path / "log")
    for i in range(3):
        keyless.append(make_record("note", AGENT, body={"i": i}), allow_unsigned=True)
    keyless.checkpoint()
    rep = ActionLog.open(tmp_path / "log", read_only=True).verify()
    assert rep.ok and rep.issuer_signed == 0 and rep.records == 3


def test_a_signed_writer_can_continue_a_version_0_trail_and_the_marker_marks_the_start(
        tmp_path):
    log = ActionLog.create(tmp_path / "log")
    for i in range(2):
        log.append(make_record("note", AGENT, body={"i": i}), allow_unsigned=True)
    log.append(make_record("note", AGENT, body={"i": 2}))
    rep = ActionLog.open(tmp_path / "log", read_only=True).verify()
    assert rep.ok and rep.records == 4 and rep.issuer_signed == 2        # marker and the record
    kinds = [log.record(e)["kind"] for e in log.entries()]
    assert kinds == ["note", "note", "x-issuer-signing", "note"]


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
