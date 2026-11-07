import json

import pytest

from aeos import ActionLog, make_record, verify_consistency_doc, verify_action_record
from aeos.canon import json_digest
from crash_support import die_after, fork, start_child

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
    a, b = log._append_all([parent, child])
    assert (a.index, b.index) == (1, 2)            # the marker is record 0
    assert log._append_all([parent, child]) == [a, b]           # already there: not written again
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


def test_a_line_left_half_written_by_a_dead_writer_is_reported_skipped_then_cut_and_kept(
        tmp_path):
    log = ActionLog.create(tmp_path / "log")
    _fill(log, 2)
    size = (log.path / "records.jsonl").stat().st_size
    with open(log.path / "records.jsonl", "ab") as f:
        f.write(b'{"i":3,"cid":"bafy')                   # a writer died mid-line
    reader = ActionLog.open(log.path, read_only=True)
    assert len(reader) == 3                              # readers skip it
    assert reader.verify().problems == ["line 4: an unfinished write, not yet recovered"]
    ActionLog.open(log.path).append(make_record("note", AGENT, body={"after": 1}))
    rep = ActionLog.open(log.path).verify()
    assert rep.ok and rep.records == 4
    assert (log.path / "torn" / f"{size}.bin").read_bytes() == b'{"i":3,"cid":"bafy'


@pytest.mark.parametrize("whole_lines", [0, 1, 2], ids=["nothing", "one line", "every line"])
def test_a_batch_cut_short_by_a_dying_writer_is_cut_off_whole(tmp_path, monkeypatch,
                                                            whole_lines):
    """Two records written together: the process dies part way (or after the last byte but
    before the write is finished). No reader ever sees part of the batch, and the next writer
    cuts all of it off, keeping the bytes."""
    from aeos.canon import cid_of_bytes, dag_cbor
    log = ActionLog.create(tmp_path / "log")
    _fill(log, 2)
    size = (log.path / "records.jsonl").stat().st_size
    a = make_record("note", AGENT, body={"n": "a"}, ts=1)
    b = make_record("note", AGENT, body={"n": "b"}, parents=[cid_of_bytes(dag_cbor(a))], ts=1)

    def child():
        die_after(monkeypatch, whole_lines)
        log._append_all([a, b])

    assert fork(child) == 9
    if whole_lines == 2:                 # every byte down, but never declared finished
        assert (log.path / "records.jsonl").read_bytes().count(b"\n") == 5
    reader = ActionLog.open(log.path, read_only=True)
    assert len(reader) == 3 and len(log.entries()) == 3
    assert reader.verify().problems[-1].endswith("an unfinished write, not yet recovered "
                                                 "(.pending is present)")
    after = ActionLog.open(log.path)
    after.append(make_record("note", AGENT, body={"after": "restart"}))
    assert not (log.path / ".pending").exists() and (log.path / "torn" / f"{size}.bin").exists()
    rep = ActionLog.open(log.path).verify()
    assert rep.ok and rep.records == 4
    assert [e.index for e in after._append_all([a, b])] == [4, 5]     # the retry lands whole
    assert ActionLog.open(log.path).verify().ok


def test_a_batch_already_partly_in_the_trail_is_refused(tmp_path):
    from aeos.canon import cid_of_bytes, dag_cbor
    log = ActionLog.create(tmp_path / "log")
    a = make_record("note", AGENT, body={"n": "a"}, ts=1)
    b = make_record("note", AGENT, body={"n": "b"}, parents=[cid_of_bytes(dag_cbor(a))], ts=1)
    log.append(a)
    with pytest.raises(ValueError, match="cut short"):
        log._append_all([a, b])
    assert len(log) == 2


def test_passkey_records_are_refused_by_the_plain_append_and_the_command_line(tmp_path,
                                                                             capsys):
    from aeos.cli import main
    from aeos.log import PASSKEY_KINDS
    log = ActionLog.create(tmp_path / "log")
    for kind in sorted(PASSKEY_KINDS):
        with pytest.raises(ValueError, match="only through Recorder with a passkey directory"):
            log.append(make_record(kind, CFO, body={"approver": CFO}))
    assert main(["append", str(log.path), "--agent", CFO, "--kind", "x-passkey-revoked",
                 "--body", "{}"]) == 2
    assert "only through Recorder" in capsys.readouterr().err
    assert len(ActionLog.open(log.path)) == 0


def test_without_file_locking_nothing_is_ever_cut(tmp_path, monkeypatch):
    """Where the platform has no file locks, a second process takes no lock, so nothing may
    cut what another process wrote between its read and its write."""
    import aeos.log as log_module
    monkeypatch.setattr(log_module, "fcntl", None)
    writer = ActionLog.create(tmp_path / "log")
    writer.append(make_record("note", AGENT, body={"n": 0}))
    other = ActionLog.open(writer.path)               # say, `aeos log checkpoint`
    real = other._load_new_locked

    def load_then_the_writer_writes():
        real()
        writer.append(make_record("note", AGENT, body={"n": "acknowledged"}))

    other._load_new_locked = load_then_the_writer_writes
    other.checkpoint()
    assert len(ActionLog.open(writer.path, read_only=True)) == 3   # nothing was cut
    with open(writer.path / "records.jsonl", "ab") as f:
        f.write(b'{"i":3,"cid')                        # a line a dead writer left unended
    writer.append(make_record("note", AGENT, body={"n": 2}))
    problems = ActionLog.open(writer.path, read_only=True).verify().problems
    assert problems and all("unreadable record" in p for p in problems[:1])
    assert (writer.path / "records.jsonl").read_bytes().count(b'{"i":3,"cid\n') == 1


def test_a_record_and_its_checkpoint_are_flushed_to_the_disk(tmp_path, monkeypatch):
    import os
    import aeos.log as log_module
    synced = []
    real = os.fsync

    def fsync(fd):
        synced.append(os.path.basename(os.readlink(f"/proc/self/fd/{fd}")))
        real(fd)

    if not os.path.exists("/proc/self/fd"):
        pytest.skip("needs /proc to name a file descriptor")
    monkeypatch.setattr(log_module.os, "fsync", fsync)
    log = ActionLog.create(tmp_path / "log")
    assert {"records.jsonl", "checkpoints.jsonl", "log.json", "log"} <= set(synced)
    synced.clear()
    log.append(make_record("note", AGENT, body={"n": 1}))
    assert "records.jsonl" in synced and ".pending" in synced
    synced.clear()
    log.checkpoint()
    assert synced == ["checkpoints.jsonl"]


def test_an_action_record_is_proved_against_records_another_process_wrote(tmp_path):
    from aeos.log import verify_action_record
    one = ActionLog.create(tmp_path / "log")
    e = one.append(make_record("note", AGENT, body={"n": 0}))
    other = ActionLog.open(one.path)
    for n in range(1, 4):
        other.append(make_record("note", AGENT, body={"n": n}))
    newer = other.checkpoint()
    assert verify_action_record(one.action_record(e), one.public_key) == []
    old = other.checkpoint()                           # the same size: no proof needed
    assert one.consistency(newer, old)["proof"] == []


def test_processes_and_threads_writing_batches_together_leave_a_whole_trail(tmp_path):
    """Four processes, three threads each, append pairs, sign checkpoints and read at once:
    every record lands once, in sequence, every pair side by side, and the trail verifies."""
    import threading
    from aeos.canon import cid_of_bytes, dag_cbor
    ActionLog.create(tmp_path / "log")
    procs, threads, n = 4, 3, 15

    def work(p):
        log = ActionLog.open(tmp_path / "log")

        def thread(t):
            for i in range(n):
                a = make_record("note", AGENT, body={"p": p, "t": t, "n": i}, ts=1)
                b = make_record("note", AGENT, body={"child": True, "p": p, "t": t, "n": i},
                                parents=[cid_of_bytes(dag_cbor(a))], ts=1)
                log._append_all([a, b])
                if i % 5 == 0:
                    log.checkpoint()
                log.entries()

        ts = [threading.Thread(target=thread, args=(t,)) for t in range(threads)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()

    import os
    pids = []
    for p in range(procs):
        pid = start_child()
        if pid == 0:                                     # pragma: no cover - the child
            code = 1
            try:
                work(p)
                code = 0
            finally:
                os._exit(code)
        pids.append(pid)
    assert [os.waitstatus_to_exitcode(os.waitpid(x, 0)[1]) for x in pids] == [0] * procs
    rep = ActionLog.open(tmp_path / "log", read_only=True).verify()
    assert rep.ok and rep.records == 1 + procs * threads * n * 2
    lines = [json.loads(x) for x in (tmp_path / "log" / "records.jsonl").read_text().splitlines()]
    views = [x["view"]["body"] for x in lines[1:]]
    for first, second in zip(views[::2], views[1::2]):
        assert "child" not in first and second["child"]
        assert (first["p"], first["t"], first["n"]) == (second["p"], second["t"], second["n"])


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
    """A reader in another thread runs at the worst moment: the writer's line is on the disk
    and declared finished (.pending removed), and not yet in its index. It must wait, not
    index the line itself."""
    import threading
    import aeos.log as log_module
    log = ActionLog.create(tmp_path / "log")
    log.append(make_record("note", AGENT, body={"n": 0}))
    real_fsync_dir = log_module._fsync_dir
    readers = []

    def read_after_finishing(path):
        real_fsync_dir(path)
        if log._holder is not None and not (log.path / ".pending").exists() and not readers:
            reader = threading.Thread(target=log.entries)
            reader.start()
            readers.append(reader)
            reader.join(0.3)          # blocks on the index lock; without it, it reads now

    monkeypatch.setattr(log_module, "_fsync_dir", read_after_finishing)
    log.append(make_record("note", AGENT, body={"n": 1}))
    monkeypatch.undo()
    assert readers
    for r in readers:
        r.join(5)
    log.append(make_record("note", AGENT, body={"n": 2}))
    assert [e.index for e in log.entries()] == [0, 1, 2, 3]
    lines = [json.loads(x) for x in (log.path / "records.jsonl").read_text().splitlines()]
    assert [x["i"] for x in lines] == [0, 1, 2, 3]
    assert log.checkpoint().size == 4
    assert ActionLog.open(log.path).verify().ok


# ---- readers hold the lock shared; a stale or unreadable .pending; a torn checkpoint --------


def _two(tag):
    from aeos.canon import cid_of_bytes, dag_cbor
    a = make_record("note", AGENT, body={"n": tag}, ts=1)
    return [a, make_record("note", AGENT, body={"n": tag, "child": True},
                           parents=[cid_of_bytes(dag_cbor(a))], ts=1)]


def test_a_crash_its_recovery_and_a_new_batch_cannot_land_inside_one_read(tmp_path,
                                                                        monkeypatch):
    """A reader pauses inside its read. Meanwhile a writer process dies mid-batch, and another
    writer recovers the trail and writes a new batch. The read holds the lock shared, so all
    of that waits for it, and the reader never indexes the batch that was cut off."""
    import threading
    import aeos.log as log_module
    log = ActionLog.create(tmp_path / "log")
    _fill(log, 2)
    reader = ActionLog.open(log.path)
    writer = ActionLog.open(log.path)
    real_pending, real_lines = reader._pending, log_module._lines
    me, helpers = {}, []

    def crash():
        def child():
            import os
            for fd in os.listdir("/proc/self/fd"):     # a process of its own: not the
                try:                                   # reader's lock, inherited by fork
                    if os.readlink(f"/proc/self/fd/{fd}").endswith("/.lock"):
                        os.close(int(fd))
                except OSError:
                    pass
            die_after(monkeypatch, 2)                  # every byte, never declared finished
            ActionLog.open(log.path)._append_all(_two("cut"))
        fork(child)

    def in_the_read(work):
        t = threading.Thread(target=work)
        t.start()
        helpers.append(t)
        t.join(1.0)                                    # finishes now only without the lock

    def pending_then_crash():
        got = real_pending()
        if threading.get_ident() == me.get("reader") and not helpers:
            in_the_read(crash)
        return got

    def lines_then_recover(data):
        if threading.get_ident() == me.get("reader") and len(helpers) == 1:
            in_the_read(lambda: writer._append_all(_two("new")))
        return real_lines(data)

    reader._pending = pending_then_crash
    monkeypatch.setattr(log_module, "_lines", lines_then_recover)

    def read():
        me["reader"] = threading.get_ident()
        reader.entries()

    t = threading.Thread(target=read)
    t.start()
    t.join(10)
    for h in helpers:
        h.join(10)
    monkeypatch.setattr(log_module, "_lines", real_lines)
    assert len(helpers) == 2 and not any(h.is_alive() for h in helpers)
    on_disk = [e.cid for e in ActionLog.open(log.path, read_only=True).entries()]
    assert [e.cid for e in reader.entries()] == on_disk and len(on_disk) == 5
    assert ActionLog.open(log.path).verify().ok


def test_a_reader_waits_for_no_lock_file_and_never_makes_one(tmp_path):
    log = ActionLog.create(tmp_path / "log")
    _fill(log, 2)
    (log.path / ".lock").unlink()                     # say, a read-only copy of the folder
    copy = ActionLog.open(log.path, read_only=True)
    assert len(copy.entries()) == 3 and copy.verify().ok and len(copy.checkpoints()) == 0
    assert not (log.path / ".lock").exists()


def test_writing_while_reading_on_the_same_thread_raises_instead_of_hanging(tmp_path):
    log = ActionLog.create(tmp_path / "log")
    with log._shared():
        with pytest.raises(RuntimeError, match="would deadlock"):
            log.append(make_record("note", AGENT, body={"n": 1}))
    log.append(make_record("note", AGENT, body={"n": 1}))
    assert len(log) == 2


def _stale_pending(log, **over):
    """A .pending naming the second record, as a copy of a trail taken mid-write would."""
    lines = (log.path / "records.jsonl").read_bytes().split(b"\n")
    offset = len(lines[0]) + 1
    doc = {"offset": offset, "length": 700, "first_cid": json.loads(lines[1])["cid"], **over}
    (log.path / ".pending").write_text(json.dumps(doc))
    return doc


@pytest.mark.parametrize("why", ["length", "first_cid", "checkpoint"])
def test_a_stale_pending_never_cuts_records(tmp_path, why):
    log = ActionLog.create(tmp_path / "log")
    _fill(log, 6)
    if why == "checkpoint":
        log.checkpoint()
        _stale_pending(log, length=10 ** 6)
        reason = "a signed checkpoint covers records past its offset"
    elif why == "first_cid":
        _stale_pending(log, length=10 ** 6, first_cid="bafyother")
        reason = "the record at its offset is not the first of its batch"
    else:
        _stale_pending(log)
        reason = "the trail goes on past the batch it names"
    before = (log.path / "records.jsonl").read_bytes()
    reader = ActionLog.open(log.path, read_only=True)
    assert len(reader.entries()) == 7                  # readers ignore it
    assert reader.verify().problems == [f".pending is stale and was ignored: {reason}"]
    writer = ActionLog.open(log.path)
    with pytest.raises(log_module_error(), match="stale"):
        writer.append(make_record("note", AGENT, body={"n": "next"}))
    assert (log.path / "records.jsonl").read_bytes() == before      # nothing was cut
    assert not (log.path / ".pending").exists() and (log.path / "torn" / "pending.json").exists()
    writer.append(make_record("note", AGENT, body={"n": "next"}))
    rep = ActionLog.open(log.path).verify()
    assert rep.ok and rep.records == 8


def log_module_error():
    from aeos.log import StalePendingError
    return StalePendingError


def test_an_unreadable_pending_hides_nothing_and_is_moved_aside(tmp_path):
    log = ActionLog.create(tmp_path / "log")
    _fill(log, 2)
    (log.path / ".pending").write_bytes(b'{"offset": 12')   # cut short as it was written
    reader = ActionLog.open(log.path, read_only=True)
    assert len(reader.entries()) == 3 and reader.verify().ok
    log.append(make_record("note", AGENT, body={"n": "next"}))
    assert not (log.path / ".pending").exists()
    assert (log.path / "torn" / "pending.json").read_bytes() == b'{"offset": 12'
    assert ActionLog.open(log.path).verify().ok


def test_a_writer_that_dies_while_cutting_is_finished_by_the_next(tmp_path, monkeypatch):
    log = ActionLog.create(tmp_path / "log")
    _fill(log, 2)
    size = (log.path / "records.jsonl").stat().st_size

    def dies_mid_batch():
        die_after(monkeypatch, 1)
        ActionLog.open(log.path)._append_all(_two("cut"))

    def dies_mid_cut():                                # the torn/ copy is kept, not the cut
        import os
        import aeos.log as log_module
        monkeypatch.setattr(log_module.os, "truncate", lambda *a: os._exit(9))
        ActionLog.open(log.path).append(make_record("note", AGENT, body={"n": "x"}))

    assert fork(dies_mid_batch) == 9
    assert fork(dies_mid_cut) == 9
    assert (log.path / "torn" / f"{size}.bin").exists() and (log.path / ".pending").exists()
    log.append(make_record("note", AGENT, body={"n": "after"}))
    assert (log.path / "torn" / f"{size}.1.bin").exists()
    rep = ActionLog.open(log.path).verify()
    assert rep.ok and rep.records == 4


def test_a_writer_that_indexed_past_an_unfinished_write_starts_its_index_again(tmp_path):
    log = ActionLog.create(tmp_path / "log")
    _fill(log, 3)
    lines = (log.path / "records.jsonl").read_bytes().split(b"\n")
    offset = sum(len(x) + 1 for x in lines[:3])
    (log.path / ".pending").write_text(json.dumps({     # the last record: never finished
        "offset": offset, "length": len(lines[3]) + 1, "first_cid": json.loads(lines[3])["cid"]}))
    assert len(log) == 4                                # this process had indexed it
    e = log.append(make_record("note", AGENT, body={"n": "next"}))
    assert e.index == 3 and len(log) == 4
    assert [x.cid for x in log.entries()] == [x.cid for x in ActionLog.open(log.path).entries()]
    assert ActionLog.open(log.path).verify().ok


def test_a_checkpoint_cut_short_is_reported_skipped_and_moved_aside(tmp_path):
    log = ActionLog.create(tmp_path / "log")
    log.append(make_record("note", AGENT, body={"n": 0}))
    log.checkpoint()
    path = log.path / "checkpoints.jsonl"
    size = path.stat().st_size
    with open(path, "a") as f:
        f.write('{"log":"urn:x","size":2,"ro')           # a writer died mid-checkpoint
    reader = ActionLog.open(log.path, read_only=True)
    assert [c.size for c in reader.checkpoints()] == [2]
    assert reader.verify().problems == ["checkpoints line 2: an unfinished write, not yet "
                                        "recovered"]
    log.append(make_record("note", AGENT, body={"n": 1}))
    log.checkpoint()
    assert (log.path / "torn" / f"checkpoints-{size}.bin").read_text().startswith('{"log"')
    reader = ActionLog.open(log.path, read_only=True)
    assert [c.size for c in reader.checkpoints()] == [2, 3] and reader.verify().ok
    assert reader.action_record(reader.entries()[-1])["checkpoint"]["size"] == 3


def test_content_that_cannot_be_stored_does_not_undo_the_record(tmp_path, monkeypatch, caplog):
    import aeos.log as log_module
    log = ActionLog.create(tmp_path / "log")
    (log.path / "content").write_text("not a folder")   # the content store is broken
    e = log.append(make_record("note", AGENT, body={"n": 1}), {"arguments": {"x": 1}})
    assert e.index == 1 and ActionLog.open(log.path).verify().ok
    assert any("could not be stored" in r.message and log.log_id in r.message
               for r in caplog.records if r.name == log_module.LOG.name)


def test_without_file_locking_a_read_between_a_write_and_its_indexing_still_waits(
        tmp_path, monkeypatch):
    """Where there are no file locks, the index lock alone keeps a reader in another thread
    from indexing a line that is on the disk but not yet in the writer's index."""
    import os
    import threading
    import aeos.log as log_module
    monkeypatch.setattr(log_module, "fcntl", None)
    log = ActionLog.create(tmp_path / "log")
    log.append(make_record("note", AGENT, body={"n": 0}))
    real_fsync = os.fsync
    readers = []

    def read_after_writing(fd):
        real_fsync(fd)
        if log._holder is not None and not readers and \
                os.readlink(f"/proc/self/fd/{fd}").endswith("records.jsonl"):
            reader = threading.Thread(target=log.entries)
            reader.start()
            readers.append(reader)
            reader.join(0.3)          # blocks on the index lock; without it, it reads now

    if not os.path.exists("/proc/self/fd"):
        pytest.skip("needs /proc to name a file descriptor")
    monkeypatch.setattr(log_module.os, "fsync", read_after_writing)
    log.append(make_record("note", AGENT, body={"n": 1}))
    monkeypatch.setattr(log_module.os, "fsync", real_fsync)
    assert readers
    for r in readers:
        r.join(5)
    log.append(make_record("note", AGENT, body={"n": 2}))
    assert [e.index for e in log.entries()] == [0, 1, 2, 3]
    assert [json.loads(x)["i"] for x in
            (log.path / "records.jsonl").read_text().splitlines()] == [0, 1, 2, 3]
    assert log.checkpoint().size == 4
