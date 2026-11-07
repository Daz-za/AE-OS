"""A verifier reports a tampered trail; it never crashes on one."""
import json
import random
import shutil

import pytest

from aeos import ActionLog, audit, fulldemo, make_record
from aeos.canon import dag_cbor
from aeos.cli import main
from aeos.log import b64

AGENT = "spiffe://acme.example/agent/a"


def swaps(original: bytes, rng: random.Random):
    """What a record's bytes might be swapped for: not a map, an empty map, cut short,
    nested too deep, or noise."""
    return [dag_cbor([]), dag_cbor(0), dag_cbor("x"), dag_cbor(None), dag_cbor({}),
            original[:len(original) // 2], original[:-1], b"", b"\x81" * 300 + b"\x00",
            rng.randbytes(1), rng.randbytes(40), rng.randbytes(400)]


BAD_LINES = [b"[]", b"0", b'"x"', b"null", b"{}", b'{"cbor":5}', b'{"cbor":"not base64!"}',
             b"\xff\xfe", b"{", b"[" * 5000]


def _trail(tmp_path):
    log = ActionLog.create(tmp_path / "log")
    for i in range(4):
        log.append(make_record("note", AGENT, body={"i": i}))
    log.checkpoint()
    return log


def _verify(path, lines):
    (path / "records.jsonl").write_bytes(b"".join(line + b"\n" for line in lines))
    return ActionLog.open(path, read_only=True).verify()


def test_swapping_any_record_for_anything_is_reported_not_raised(tmp_path):
    log = _trail(tmp_path)
    original = (log.path / "records.jsonl").read_bytes().splitlines()
    rng = random.Random(7)
    for i, line in enumerate(original):
        d = json.loads(line)
        for n, swap in enumerate(swaps(log.entries()[i].raw, rng)):
            lines = list(original)
            lines[i] = json.dumps({**d, "cbor": b64(swap)}, separators=(",", ":")).encode()
            assert _verify(log.path, lines).problems, f"record {i}, swap {n}"
        for n, bad in enumerate(BAD_LINES):
            lines = list(original)
            lines[i] = bad
            assert _verify(log.path, lines).problems, f"record {i}, line {n}"


def test_a_record_that_is_not_a_map_is_named(tmp_path):
    log = _trail(tmp_path)
    lines = (log.path / "records.jsonl").read_bytes().splitlines()
    for i, expected in ((0, "line 1"), (2, "line 3")):
        d = json.loads(lines[i])
        edited = list(lines)
        edited[i] = json.dumps({**d, "cbor": b64(dag_cbor([1]))}).encode()
        assert f"{expected}: unreadable record (not a map)" in _verify(log.path, edited).problems


def test_a_bad_checkpoint_line_is_reported_not_raised(tmp_path):
    log = _trail(tmp_path)
    good = (log.path / "checkpoints.jsonl").read_bytes()
    for bad in (b"[]", b"{}", b'{"log":1}', b'{"log":"x","size":-1}', b"\xff\xfe", b"{"):
        (log.path / "checkpoints.jsonl").write_bytes(good + bad + b"\n")
        problems = ActionLog.open(log.path, read_only=True).verify().problems
        assert any(p.startswith("checkpoints line 2: unreadable checkpoint") for p in problems)


def test_the_command_line_reports_and_shows_a_tampered_trail(tmp_path, capsys):
    log = _trail(tmp_path)
    lines = (log.path / "records.jsonl").read_bytes().splitlines()
    lines[2] = b"[]"
    (log.path / "records.jsonl").write_bytes(b"\n".join(lines) + b"\n")
    assert main(["verify", str(log.path)]) == 1
    assert "unreadable record (missing field 'cbor')" in capsys.readouterr().out
    assert main(["show", str(log.path)]) == 0
    shown = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert shown[2]["record"] == {"unreadable": "truncated"} and len(shown) == 5


@pytest.fixture(scope="module")
def evidence(tmp_path_factory):
    folder = tmp_path_factory.mktemp("evidence") / "full"
    assert fulldemo.run(folder, out=lambda _: None) == 0
    return folder


def _tamper(evidence, tmp_path, index, cbor):
    copy = tmp_path / "copy"
    if copy.exists():
        shutil.rmtree(copy)
    shutil.copytree(evidence, copy)
    path = copy / "log" / "records.jsonl"
    lines = path.read_bytes().splitlines()
    d = json.loads(lines[index])
    lines[index] = json.dumps({**d, "cbor": b64(cbor)}, separators=(",", ":")).encode()
    path.write_bytes(b"\n".join(lines) + b"\n")
    return copy


def test_audit_fails_on_a_tampered_trail_and_never_crashes(evidence, tmp_path):
    # The kinds each audit check reads; the verify test above covers every swap for every
    # record, so these three (not a map, an empty map, cut short) are enough here.
    log = ActionLog.open(evidence / "log", read_only=True)
    first_of_kind = {}
    for e in log.entries():
        first_of_kind.setdefault(log.record(e)["kind"], e)
    for kind in ("session.start", "tool.call", "policy.decision", "approval", "journal.entry"):
        e = first_of_kind[kind]
        for n, swap in enumerate([dag_cbor([]), dag_cbor({}), e.raw[:-1]]):
            problems = audit.run(_tamper(evidence, tmp_path, e.index, swap))[1]
            assert any(p.startswith("log: ") for p in problems), f"{kind}, swap {n}"


def test_audit_fails_closed_on_a_record_with_the_right_shape_and_the_wrong_contents(
        evidence, tmp_path):
    log = ActionLog.open(evidence / "log", read_only=True)
    for e in log.entries():
        rec = log.record(e)
        if rec["kind"] in ("session.start", "policy.decision", "journal.entry"):
            odd = dict(rec, body={"svid_sha256": 5, "policy": 5, "decision": [], "amount": "x",
                                  "policy_sha256": 7, "data_sha256": 7, "input_json": 7})
            problems = audit.run(_tamper(evidence, tmp_path, e.index, dag_cbor(odd)))[1]
            assert problems, rec["kind"]
            assert all(isinstance(p, str) for p in problems)
