"""Version 0 names, files and commands keep working next to the version 1 names."""
import hashlib
import json
import warnings
from pathlib import Path

import pytest

import aeos
from aeos import ActionLog, make_record, verify_action_record
from aeos import log as log_module
from aeos.cli import main

ROOT = Path(__file__).resolve().parents[2]
V0_FILE = ROOT / "testvectors" / "receipts-v0.json"
# The version 0 vectors are frozen: any change to the file is a change to the wire format.
V0_SHA256 = "e1de174a2455f96fb958bb940ee3af67186dec334d791578120e7419935ca1aa"
OLD_WRONG_TYPE = "not an aeos-receipt/v0 document"
NEW_WRONG_TYPE = "not an aeos-action-record/v1 document (or aeos-receipt/v0)"


def _small_log(tmp_path):
    log = ActionLog.create(tmp_path / "log")
    e = log.append(make_record("note", "spiffe://acme.example/agent/a", body={"n": 1}))
    log.checkpoint()
    return log, e


def test_v0_vectors_file_is_frozen():
    assert hashlib.sha256(V0_FILE.read_bytes()).hexdigest() == V0_SHA256


def test_v0_receipts_in_the_frozen_vectors_still_verify():
    v0 = json.loads(V0_FILE.read_text())
    assert v0["receipts"][0]["receipt"]["type"] == "aeos-receipt/v0"
    for c in v0["receipts"]:
        expected = [NEW_WRONG_TYPE if p == OLD_WRONG_TYPE else p for p in c["expect_problems"]]
        got = verify_action_record(c["receipt"], bytes.fromhex(c["public_key"]))
        assert got == expected, c["name"]
    # the valid ones really are valid, not merely agreeing with an expectation
    assert verify_action_record(v0["receipts"][0]["receipt"],
                                bytes.fromhex(v0["receipts"][0]["public_key"])) == []


def test_v0_audit_trails_and_consistency_proofs_in_the_frozen_vectors_still_verify(tmp_path):
    v0 = json.loads(V0_FILE.read_text())
    for c in v0["consistency"]:
        got = aeos.verify_consistency_doc(c["proof"], bytes.fromhex(c["public_key"]))
        assert got == c["expect_problems"], c["name"]
    logs = v0["logs"]
    for i, c in enumerate(logs["cases"]):
        d = tmp_path / f"log{i}"
        d.mkdir()
        (d / "log.json").write_text(logs["log_json"])
        (d / "records.jsonl").write_text(c["records"])
        (d / "checkpoints.jsonl").write_text(c["checkpoints"])
        rep = ActionLog.open(d, read_only=True).verify()
        assert rep.problems == c["expect"]["problems"], c["name"]


def test_v0_receipt_document_made_today_verifies(tmp_path):
    log, e = _small_log(tmp_path)
    doc = log.action_record(e)
    doc["type"] = "aeos-receipt/v0"
    assert verify_action_record(doc, log.public_key) == []


def test_deprecated_python_names_still_import_and_work(tmp_path):
    with pytest.warns(DeprecationWarning, match="ActionLog") as seen:
        old_log_class = aeos.ReceiptLog
    assert old_log_class is ActionLog
    assert seen[0].filename == __file__           # the warning points at the caller
    with pytest.warns(DeprecationWarning, match="verify_action_record") as seen:
        old_verify = log_module.verify_receipt
    assert old_verify is verify_action_record
    assert seen[0].filename == __file__
    with pytest.warns(DeprecationWarning) as seen:
        from aeos.log import ReceiptLog  # noqa: F401  (how downstream code imports it)
    assert seen[0].filename == __file__
    with pytest.raises(AttributeError):
        aeos.NoSuchName  # noqa: B018


def test_deprecated_receipt_method_returns_the_action_record(tmp_path):
    log, e = _small_log(tmp_path)
    with pytest.warns(DeprecationWarning, match="action_record") as seen:
        doc = log.receipt(e)
    assert seen[0].filename == __file__
    assert doc == log.action_record(e) and doc["type"] == "aeos-receipt/v0"
    cp = log.checkpoints()[-1]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        assert log.receipt(e, checkpoint=cp) == log.action_record(e, checkpoint=cp)


def test_old_and_new_commands_do_the_same_thing(tmp_path, capsys):
    log, _ = _small_log(tmp_path)
    key = str(log.path / "signing.key")
    pub = str(log.path / "log.json")
    for export, verify in (("receipt", "verify-receipt"),
                           ("action-record", "verify-action-record")):
        out = tmp_path / f"{export}.json"
        assert main([export, str(log.path), "0", "--key", key, "-o", str(out)]) == 0
        capsys.readouterr()
        assert main([verify, str(out), "--public-key", pub]) == 0
        text = capsys.readouterr().out
        assert text.startswith("VALID") and "verified" in text
    # each command reads the other's file, and the old v0 type
    doc = json.loads((tmp_path / "receipt.json").read_text())
    doc["type"] = "aeos-receipt/v0"
    old_file = tmp_path / "old.json"
    old_file.write_text(json.dumps(doc))
    assert main(["verify-action-record", str(old_file), "--public-key", pub]) == 0
    assert main(["verify-receipt", str(old_file), "--public-key", pub]) == 0
    # a tampered file is refused by both
    doc["cid"] = "b" + "a" * 58
    old_file.write_text(json.dumps(doc))
    capsys.readouterr()
    assert main(["verify-receipt", str(old_file), "--public-key", pub]) == 1
    assert "What to do:" in capsys.readouterr().out
