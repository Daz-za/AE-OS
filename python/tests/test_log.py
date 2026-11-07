import json

import pytest

from aeos import ActionLog, make_record, verify_consistency_doc, verify_action_record
from aeos.canon import json_digest

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


def test_action_record_round_trip(tmp_path):
    log = ActionLog.create(tmp_path / "log")
    entries = _fill(log, 5)
    receipt = log.action_record(entries[2])
    assert verify_action_record(receipt, log.public_key) == []
    # writers keep the version 0 document type for now; readers accept both
    assert receipt["type"] == "aeos-receipt/v0" and "statement_signature" in receipt
    # same action record survives JSON serialisation
    assert verify_action_record(json.loads(json.dumps(receipt)), log.public_key) == []


def test_action_record_rejects_wrong_key_and_altered_record(tmp_path):
    log = ActionLog.create(tmp_path / "log")
    other = ActionLog.create(tmp_path / "other")
    e = _fill(log, 3)[1]
    receipt = log.action_record(e)
    assert verify_action_record(receipt, other.public_key)
    altered = dict(receipt)
    rec = log.record(e)
    rec["body"]["amount"] = 999_999
    from aeos.canon import dag_cbor
    from aeos.log import b64
    altered["record"] = b64(dag_cbor(rec))
    problems = verify_action_record(altered, log.public_key)
    assert any("CID" in p for p in problems)


def test_append_is_idempotent_and_requires_known_parents(tmp_path):
    log = ActionLog.create(tmp_path / "log")
    rec = make_record("note", AGENT, ts=1)
    assert log.append(rec).index == log.append(rec).index == 1       # 0 is the signing marker
    with pytest.raises(KeyError):
        log.append(make_record("note", AGENT, parents=[b"\x01" * 36], ts=2))


def test_reopen_and_verify_clean_log(tmp_path):
    log = ActionLog.create(tmp_path / "log")
    _fill(log, 4)
    log.checkpoint()
    _fill(log, 1, start=4)
    log.checkpoint()
    again = ActionLog.open(tmp_path / "log")
    assert len(again) == 6                      # five records and the signing marker
    rep = again.verify()
    assert rep.ok, rep.problems
    assert (rep.records, rep.checkpoints) == (6, 2)


def test_verify_detects_edited_deleted_and_reordered_records(tmp_path):
    path = tmp_path / "log"
    log = ActionLog.create(path)
    _fill(log, 6)
    log.checkpoint()
    lines = (path / "records.jsonl").read_text().splitlines()

    def check(new_lines, expect):
        (path / "records.jsonl").write_text("\n".join(new_lines) + "\n")
        problems = ActionLog.open(path, read_only=True).verify().problems
        assert any(expect in p for p in problems), problems

    # edit the readable view only
    d = json.loads(lines[3])
    d["view"]["body"]["amount"] = 1
    check(lines[:3] + [json.dumps(d)] + lines[4:], "readable view")
    # replace the signed bytes with a different record and matching CID
    rec = make_record("tool.call", AGENT, subject="erp.invoice.pay", body={"amount": 1}, ts=5)
    from aeos.canon import cid_of_bytes, cid_str, dag_cbor
    from aeos.log import b64, to_view
    raw = dag_cbor(rec)
    forged = json.dumps({"i": 6, "cid": cid_str(cid_of_bytes(raw)), "cbor": b64(raw),
                         "view": to_view(rec)})
    check(lines[:6] + [forged], "root does not match")
    # delete a record
    check(lines[:6], "covers more records")
    # reorder records
    check([lines[1], lines[0]] + lines[2:], "out of sequence")


def test_consistency_between_checkpoints(tmp_path):
    log = ActionLog.create(tmp_path / "log")
    _fill(log, 3)
    old = log.checkpoint()
    _fill(log, 4, start=3)
    new = log.checkpoint()
    doc = log.consistency(old, new)
    assert verify_consistency_doc(doc, log.public_key) == []
    doc["old"]["root"] = "00" * 32
    assert verify_consistency_doc(doc, log.public_key)


def test_open_rejects_mismatched_key(tmp_path):
    ActionLog.create(tmp_path / "a")
    ActionLog.create(tmp_path / "b")
    with pytest.raises(ValueError):
        ActionLog.open(tmp_path / "a", key_path=tmp_path / "b" / "signing.key")


def test_read_only_log_cannot_sign(tmp_path):
    ActionLog.create(tmp_path / "log")
    with pytest.raises(PermissionError):
        ActionLog.open(tmp_path / "log", read_only=True).checkpoint()


# ---- writing together, failing cleanly, and reading while another thread writes --------------


def test_records_appended_together_land_in_one_write_and_may_cite_each_other(tmp_path):
    log = ActionLog.create(tmp_path / "log")
    parent = make_record("note", AGENT, body={"n": 1}, ts=1)
    from aeos.canon import cid_of_bytes, dag_cbor
    child = make_record("note", AGENT, body={"n": 2}, parents=[cid_of_bytes(dag_cbor(parent))],
                        ts=1)
    a, b = log.append_all([parent, child])
    assert (a.index, b.index) == (1, 2)            # the marker is record 0
    assert log.append_all([parent, child]) == [a, b]           # already there: not written again
    assert len(log) == 3 and ActionLog.open(log.path).verify().ok


def test_a_failed_write_leaves_nothing_behind_and_the_next_write_lands_clean(tmp_path,
                                                                             monkeypatch):
    log = ActionLog.create(tmp_path / "log")
    _fill(log, 2)
    import aeos.log as log_module
    real_open = open

    class TornFile:
        """Writes half of what it is given, then fails, as a full disk does."""

        def __init__(self, f):
            self.f = f

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.f.close()

        def write(self, data):
            self.f.write(data[:len(data) // 2])
            self.f.flush()
            raise OSError("No space left on device")

    def torn_open(path, mode="r", *a, **k):
        f = real_open(path, mode, *a, **k)
        return TornFile(f) if str(path).endswith("records.jsonl") and "a" in mode else f

    monkeypatch.setattr(log_module, "open", torn_open, raising=False)
    with pytest.raises(OSError):
        log.append(make_record("note", AGENT, body={"n": 1}))
    monkeypatch.undo()
    assert len(log) == 3 and len(ActionLog.open(log.path).entries()) == 3
    assert (log.path / "records.jsonl").read_bytes().endswith(b"\n")    # the torn line is cut
    log.append(make_record("note", AGENT, body={"n": 3}))
    reopened = ActionLog.open(log.path)
    assert len(reopened) == 4 and reopened.verify().ok


def test_a_line_left_half_written_by_a_dead_writer_is_skipped_then_cut(tmp_path):
    log = ActionLog.create(tmp_path / "log")
    _fill(log, 2)
    with open(log.path / "records.jsonl", "ab") as f:
        f.write(b'{"i":3,"cid":"bafy')                   # a writer died mid-line
    other = ActionLog.open(log.path)
    assert len(other) == 3                               # readers skip it
    other.append(make_record("note", AGENT, body={"after": 1}))
    rep = ActionLog.open(log.path).verify()
    assert rep.ok and rep.records == 4


def test_a_judge_runs_before_anything_is_written_and_a_refusal_writes_nothing(tmp_path):
    log = ActionLog.create(tmp_path / "log", log_id="urn:example:judge")

    def refuse(index):
        raise ValueError(f"refused at {index}")

    with pytest.raises(ValueError, match="refused at 1"):       # position 1: the marker is 0
        log._append_judged([make_record("note", AGENT, body={"i": 1})], judge=refuse)
    assert len(log) == 0                                        # not even the marker
    seen = []
    for i in (1, 2):
        _, verdict = log._append_judged([make_record("note", AGENT, body={"i": i})],
                                        judge=lambda index: seen.append(index) or index)
        assert verdict == seen[-1]
    assert seen == [1, 2] and len(log) == 3


def test_writing_to_the_trail_from_inside_its_own_write_raises_instead_of_hanging(tmp_path):
    import threading
    log = ActionLog.create(tmp_path / "log")
    errors = []

    def nested(index):
        log.append(make_record("note", AGENT, body={"inner": index}))

    def outer():
        try:
            log._append_judged([make_record("note", AGENT, body={"outer": 1})], judge=nested)
        except RuntimeError as e:
            errors.append(str(e))

    t = threading.Thread(target=outer, daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive(), "the nested write deadlocked"
    assert errors and "would deadlock" in errors[0]
    assert len(log) == 0
    log.append(make_record("note", AGENT, body={"after": 1}))   # the lock was let go
    assert len(log) == 2


def test_a_read_between_a_write_and_its_indexing_does_not_count_the_line_twice(tmp_path,
                                                                               monkeypatch):
    """A reader in another thread runs at the worst moment: the writer's line is on disk and
    not yet in its index. It must wait, not index the line itself."""
    import threading
    import aeos.log as log_module
    log = ActionLog.create(tmp_path / "log")
    log.append(make_record("note", AGENT, body={"n": 0}))
    real_open = open
    readers = []

    class ReadAfterWrite:
        def __init__(self, f):
            self.f = f

        def __enter__(self):
            return self.f.__enter__()

        def __exit__(self, *exc):
            done = self.f.__exit__(*exc)
            reader = threading.Thread(target=log.entries)
            reader.start()
            readers.append(reader)
            reader.join(0.3)          # blocks on the index lock; without it, it reads now
            return done

    def hooked(path, mode="r", *a, **k):
        f = real_open(path, mode, *a, **k)
        return ReadAfterWrite(f) if str(path).endswith("records.jsonl") and "a" in mode else f

    monkeypatch.setattr(log_module, "open", hooked, raising=False)
    log.append(make_record("note", AGENT, body={"n": 1}))
    monkeypatch.undo()
    for r in readers:
        r.join(5)
    log.append(make_record("note", AGENT, body={"n": 2}))
    assert [e.index for e in log.entries()] == [0, 1, 2, 3]
    lines = [json.loads(x) for x in (log.path / "records.jsonl").read_text().splitlines()]
    assert [x["i"] for x in lines] == [0, 1, 2, 3]
    assert log.checkpoint().size == 4
    assert ActionLog.open(log.path).verify().ok
