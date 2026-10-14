import json

import pytest

from aeos_receipts import ReceiptLog, make_record, verify_consistency_doc, verify_receipt
from aeos_receipts.canon import json_digest

AGENT = "spiffe://acme.example/agent/ap-clerk/1"
CFO = "spiffe://acme.example/human/cfo"


def _fill(log, n, start=0):
    out = []
    for i in range(start, start + n):
        parents = [out[-1].cid] if out else []
        rec = make_record("tool.call", AGENT, on_behalf_of=CFO, subject="erp.invoice.pay",
                          body={"args_sha256": json_digest({"invoice": i}), "amount": 100 * i},
                          parents=parents, ts=1_760_000_000_000 + i)
        out.append(log.append(rec))
    return out


def test_receipt_round_trip(tmp_path):
    log = ReceiptLog.create(tmp_path / "log")
    entries = _fill(log, 5)
    receipt = log.receipt(entries[2])
    assert verify_receipt(receipt, log.public_key) == []
    # same receipt survives JSON serialisation
    assert verify_receipt(json.loads(json.dumps(receipt)), log.public_key) == []


def test_receipt_rejects_wrong_key_and_altered_record(tmp_path):
    log = ReceiptLog.create(tmp_path / "log")
    other = ReceiptLog.create(tmp_path / "other")
    e = _fill(log, 3)[1]
    receipt = log.receipt(e)
    assert verify_receipt(receipt, other.public_key)
    altered = dict(receipt)
    rec = log.record(e)
    rec["body"]["amount"] = 999_999
    from aeos_receipts.canon import dag_cbor
    from aeos_receipts.log import b64
    altered["record"] = b64(dag_cbor(rec))
    problems = verify_receipt(altered, log.public_key)
    assert any("CID" in p for p in problems)


def test_append_is_idempotent_and_requires_known_parents(tmp_path):
    log = ReceiptLog.create(tmp_path / "log")
    rec = make_record("note", AGENT, ts=1)
    assert log.append(rec).index == log.append(rec).index == 0
    with pytest.raises(KeyError):
        log.append(make_record("note", AGENT, parents=[b"\x01" * 36], ts=2))


def test_reopen_and_verify_clean_log(tmp_path):
    log = ReceiptLog.create(tmp_path / "log")
    _fill(log, 4)
    log.checkpoint()
    _fill(log, 1, start=4)
    log.checkpoint()
    again = ReceiptLog.open(tmp_path / "log")
    assert len(again) == 5
    rep = again.verify()
    assert rep.ok, rep.problems
    assert (rep.records, rep.checkpoints) == (5, 2)


def test_verify_detects_edited_deleted_and_reordered_records(tmp_path):
    path = tmp_path / "log"
    log = ReceiptLog.create(path)
    _fill(log, 6)
    log.checkpoint()
    lines = (path / "records.jsonl").read_text().splitlines()

    def check(new_lines, expect):
        (path / "records.jsonl").write_text("\n".join(new_lines) + "\n")
        problems = ReceiptLog.open(path, read_only=True).verify().problems
        assert any(expect in p for p in problems), problems

    # edit the readable view only
    d = json.loads(lines[3])
    d["view"]["body"]["amount"] = 1
    check(lines[:3] + [json.dumps(d)] + lines[4:], "readable view")
    # replace the signed bytes with a different record and matching CID
    rec = make_record("tool.call", AGENT, subject="erp.invoice.pay", body={"amount": 1}, ts=5)
    from aeos_receipts.canon import cid_of_bytes, cid_str, dag_cbor
    from aeos_receipts.log import b64, to_view
    raw = dag_cbor(rec)
    forged = json.dumps({"i": 5, "cid": cid_str(cid_of_bytes(raw)), "cbor": b64(raw),
                         "view": to_view(rec)})
    check(lines[:5] + [forged], "root does not match")
    # delete a record
    check(lines[:5], "covers more records")
    # reorder records
    check([lines[1], lines[0]] + lines[2:], "out of sequence")


def test_consistency_between_checkpoints(tmp_path):
    log = ReceiptLog.create(tmp_path / "log")
    _fill(log, 3)
    old = log.checkpoint()
    _fill(log, 4, start=3)
    new = log.checkpoint()
    doc = log.consistency(old, new)
    assert verify_consistency_doc(doc, log.public_key) == []
    doc["old"]["root"] = "00" * 32
    assert verify_consistency_doc(doc, log.public_key)


def test_open_rejects_mismatched_key(tmp_path):
    ReceiptLog.create(tmp_path / "a")
    ReceiptLog.create(tmp_path / "b")
    with pytest.raises(ValueError):
        ReceiptLog.open(tmp_path / "a", key_path=tmp_path / "b" / "signing.key")


def test_read_only_log_cannot_sign(tmp_path):
    ReceiptLog.create(tmp_path / "log")
    with pytest.raises(PermissionError):
        ReceiptLog.open(tmp_path / "log", read_only=True).checkpoint()
