"""Generate the shared AE-OS Receipts test vectors.

Every implementation of the format checks itself against receipts-v0.json. The expected
results (CIDs, roots, proofs, and the problems a verifier reports) come from the Python
reference implementation, so a second implementation that passes agrees with it.

Run from the repository root after `pip install -e python`:

    python testvectors/generate.py            # rewrite receipts-v0.json
    python testvectors/generate.py --check    # fail if the file is out of date

The log is signed with a public test key derived from a fixed phrase below. Never use it
for a real log.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aeos import ReceiptLog, make_record, verify_consistency_doc, verify_receipt
from aeos import merkle
from aeos.canon import (Link, canonical_json, cid_of_bytes, cid_str, dag_cbor,
                        decode_dag_cbor, json_digest)
from aeos.log import b64, to_view

OUT = Path(__file__).with_name("receipts-v0.json")

TEST_SEED = hashlib.sha256(b"aeos-receipts public test key; never use for a real log").digest()
LOG_ID = "urn:example:acme:ap"
AGENT = "spiffe://acme.example/agent/accounts-payable/7f3a"
CONTROLLER = "spiffe://acme.example/human/controller/j-smith"
T0 = 1_760_000_000_000


def h(b: bytes) -> str:
    return b.hex()


# --------------------------------------------------------------------------------------
# Encodings
# --------------------------------------------------------------------------------------

def cbor_cases():
    link = Link(cid_of_bytes(dag_cbor({"a": 1})))
    values = {
        "null": None,
        "true": True,
        "false": False,
        "small integers": [0, 1, 23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296],
        "negative integers": [-1, -24, -25, -256, -257, -65537, -4294967297],
        "largest 64-bit integers": [18446744073709551615, -9223372036854775808],
        "text": ["", "a", "invoice INV-20417", "Zürich ✓ 東京"],
        "bytes": b"\x00\x01\xfe\xff",
        "map key order": {"b": 1, "a": 2, "aa": 3, "B": 4, "ba": 5, "": 6},
        "link": link,
        "nested": {"body": {"amount_minor": 1250000, "reasons": ["above-agent-limit"]},
                   "parents": [link, link], "obo": None},
    }
    out = []
    for name, v in values.items():
        enc = dag_cbor(v)
        out.append({"name": name, "view": to_view(v), "cbor": h(enc),
                    "cid": cid_str(cid_of_bytes(enc))})
    return out


def cbor_rejects():
    cases = {
        "integer not in shortest form": "1817",
        "map keys out of order": "a2616201616102",
        "map keys sorted bytewise only": "a262616101616202",
        "duplicate map key": "a2616101616102",
        "float": "f93c00",
        "undefined": "f7",
        "indefinite-length array": "9f01ff",
        "trailing bytes": "0101",
        "truncated text": "6361",
        "non-text map key": "a10101",
        "tag other than 42": "c100",
        "link without leading zero byte": "d82a4101",
        "empty input": "",
    }
    out = []
    for name, hx in cases.items():
        data = bytes.fromhex(hx)
        try:
            decode_dag_cbor(data)
        except ValueError:
            out.append({"name": name, "cbor": h(data)})
            continue
        raise AssertionError(f"Python accepted reject case {name!r}")
    return out


def json_cases():
    values = [
        {"invoice": "INV-20417", "vendor": "V-1182", "amount_minor": 1250000},
        {"b": [1, 2, {"z": None, "a": True}], "a": False},
        {"é": 1, "e": 2, "€": 3, "\U0001f600": 4, "דּ": 5},
        {"text": "line\nbreak \"quoted\" back\\slash \t tab \u0001 control \u007f del"},
        [], {}, "", 0, -42, 9007199254740993,
        {"integral float": 1.0},
    ]
    return [{"value": v, "canonical": canonical_json(v).decode("utf-8"),
             "sha256": h(json_digest(v))} for v in values]


# --------------------------------------------------------------------------------------
# Merkle tree
# --------------------------------------------------------------------------------------

def merkle_cases(max_size=12):
    leaves = [merkle.leaf_hash(bytes([i])) for i in range(max_size)]
    roots = [h(merkle.root(leaves[:n])) for n in range(max_size + 1)]
    inclusion = [{"index": i, "size": n,
                  "proof": [h(p) for p in merkle.inclusion_proof(i, leaves[:n])]}
                 for n in range(1, max_size + 1) for i in range(n)]
    consistency = [{"old_size": m, "new_size": n,
                    "proof": [h(p) for p in merkle.consistency_proof(m, leaves[:n])]}
                   for n in range(1, max_size + 1) for m in range(1, n + 1)]
    return {"leaf_data": "leaf i is SHA-256(0x00 || the single byte i)",
            "leaves": [h(x) for x in leaves], "roots": roots,
            "inclusion": inclusion, "consistency": consistency}


# --------------------------------------------------------------------------------------
# A small log, its receipts and consistency proofs, and tampered copies
# --------------------------------------------------------------------------------------

def build_log(work: Path):
    key_path = work / "test.key"
    key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    log = ReceiptLog.create(work / "log", log_id=LOG_ID, key_path=key_path)
    log.meta["created"] = T0
    (work / "log" / "log.json").write_text(json.dumps(log.meta, indent=2) + "\n")

    args = {"invoice": "INV-20417", "vendor": "V-1182", "amount_minor": 1250000}
    ts = iter(range(T0 + 1000, T0 + 100000, 1000))
    s = log.append(make_record("session.start", AGENT, on_behalf_of=CONTROLLER,
                               subject="erp-mcp-server",
                               body={"allow_list": ["erp.invoice.read", "erp.invoice.pay"]},
                               ts=next(ts)))
    c = log.append(make_record("tool.call", AGENT, on_behalf_of=CONTROLLER,
                               subject="erp.invoice.pay",
                               body={"args_sha256": json_digest(args), "rpc_id": 7},
                               parents=[s.cid], ts=next(ts)))
    d = log.append(make_record("policy.decision", AGENT, subject="erp.invoice.pay",
                               body={"decision": "escalate", "policy": "ap-limits/v3",
                                     "reasons": ["above-agent-limit"]},
                               parents=[c.cid], ts=next(ts)))
    first = log.checkpoint(ts=next(ts))
    a = log.append(make_record("approval", CONTROLLER, subject="erp.invoice.pay",
                               body={"decision": "approve", "approver": CONTROLLER},
                               parents=[d.cid], ts=next(ts)))
    r = log.append(make_record("tool.result", AGENT, on_behalf_of=CONTROLLER,
                               subject="erp.invoice.pay",
                               body={"outcome": "ok",
                                     "result_sha256": json_digest({"payment": "PAY-88"})},
                               parents=[a.cid], ts=next(ts)))
    log.append(make_record("x-acme.fx-rate", AGENT, subject="ZAR/USD",
                           body={"rate_millionths": 54321, "delta": -12,
                                 "source_digest": hashlib.sha256(b"rates").digest()},
                           parents=[s.cid], ts=next(ts)))
    log.append(make_record("session.end", AGENT, body={"unanswered_calls": 0},
                           parents=[s.cid], ts=next(ts)))
    second = log.checkpoint(ts=next(ts))
    return log, args, first, second, r


def log_files(path: Path):
    return {"log_json": (path / "log.json").read_text(),
            "records": (path / "records.jsonl").read_text(),
            "checkpoints": (path / "checkpoints.jsonl").read_text()}


def tampered_logs(log: ReceiptLog, work: Path):
    base = log_files(log.path)
    recs = base["records"].splitlines(keepends=True)
    cps = base["checkpoints"].splitlines(keepends=True)

    def edit_record(i, fn):
        d = json.loads(recs[i])
        fn(d)
        return recs[:i] + [json.dumps(d, separators=(",", ":")) + "\n"] + recs[i + 1:]

    def view_edit(d):
        d["view"]["body"]["decision"] = "allow"

    def bytes_edit(d):
        rec = decode_dag_cbor(base64_decode(d["cbor"]))
        rec["body"]["decision"] = "allow"
        d["cbor"] = b64(dag_cbor(rec))
        d["view"] = to_view(rec)

    def sig_edit(line):
        d = json.loads(line)
        sig = bytearray(base64_decode(d["sig"]))
        sig[0] ^= 1
        d["sig"] = b64(bytes(sig))
        return json.dumps(d, separators=(",", ":")) + "\n"

    cases = {
        "untouched log": (recs, cps),
        "readable view edited": (edit_record(2, view_edit), cps),
        "record rewritten with a new CID": (edit_record(2, bytes_edit), cps),
        "record removed": (recs[:1] + recs[2:], cps),
        "records reordered": (recs[:1] + [recs[2], recs[1]] + recs[3:], cps),
        "checkpoint signature altered": (recs, [cps[0], sig_edit(cps[1])]),
        "checkpoints out of order": (recs, [cps[1], cps[0]]),
        "log truncated after a checkpoint": (recs[:5], cps),
    }
    out = []
    for name, (r, c) in cases.items():
        d = work / ("t-" + name.replace(" ", "-"))
        d.mkdir()
        (d / "log.json").write_text(base["log_json"])
        (d / "records.jsonl").write_text("".join(r))
        (d / "checkpoints.jsonl").write_text("".join(c))
        rep = ReceiptLog.open(d, read_only=True).verify()
        out.append({"name": name, "records": "".join(r), "checkpoints": "".join(c),
                    "expect": {"records": rep.records, "checkpoints": rep.checkpoints,
                               "problems": rep.problems}})
    return base["log_json"], out


def base64_decode(s):
    import base64
    return base64.b64decode(s, validate=True)


def receipt_cases(log, first, second, entry, other_pub):
    good = log.receipt(entry, second)

    def variant(fn):
        doc = json.loads(json.dumps(good))
        fn(doc)
        return doc

    def change_record(doc):
        rec = decode_dag_cbor(base64_decode(doc["record"]))
        rec["body"]["outcome"] = "error"
        doc["record"] = b64(dag_cbor(rec))

    def change_both(doc):
        change_record(doc)
        doc["cid"] = cid_str(cid_of_bytes(base64_decode(doc["record"])))

    def noncanonical(doc):
        raw = base64_decode(doc["record"])
        doc["record"] = b64(raw + b"\x00")

    pub = log.public_key
    cases = [
        ("valid receipt, latest checkpoint", good, pub),
        ("valid receipt, first record", log.receipt(log.entries()[0], first), pub),
        ("valid receipt, last record of first checkpoint", log.receipt(log.entries()[2], first), pub),
        ("wrong public key", good, other_pub),
        ("record changed", variant(change_record), pub),
        ("record and CID changed together", variant(change_both), pub),
        ("record bytes not canonical", variant(noncanonical), pub),
        ("index changed", variant(lambda d: d.update(index=d["index"] - 1)), pub),
        ("proof hash altered",
         variant(lambda d: d["inclusion_proof"].__setitem__(0, "00" * 32)), pub),
        ("proof hash missing", variant(lambda d: d["inclusion_proof"].pop()), pub),
        ("checkpoint from another log",
         variant(lambda d: d.update(log_id="urn:example:other")), pub),
        ("checkpoint size changed",
         variant(lambda d: d["checkpoint"].update(size=d["checkpoint"]["size"] + 1)), pub),
        ("checkpoint key id changed",
         variant(lambda d: d["checkpoint"].update(key_id="0" * 16)), pub),
        ("wrong document type", variant(lambda d: d.update(type="aeos-receipt/v9")), pub),
    ]
    return [{"name": n, "public_key": h(k), "receipt": doc,
             "expect_problems": verify_receipt(doc, k)} for n, doc, k in cases]


def consistency_cases(log, first, second, other_pub):
    good = log.consistency(first, second)

    def variant(fn):
        doc = json.loads(json.dumps(good))
        fn(doc)
        return doc

    same = log.consistency(second, second)
    pub = log.public_key
    cases = [
        ("valid proof", good, pub),
        ("same checkpoint twice", same, pub),
        ("wrong public key", good, other_pub),
        ("proof hash altered", variant(lambda d: d["proof"].__setitem__(0, "00" * 32)), pub),
        ("proof hash missing", variant(lambda d: d["proof"].pop()), pub),
        ("old root changed after signing",
         variant(lambda d: d["old"].update(root="00" * 32)), pub),
        ("checkpoints swapped",
         variant(lambda d: d.update(old=d["new"], new=d["old"])), pub),
    ]
    return [{"name": n, "public_key": h(k), "proof": doc,
             "expect_problems": verify_consistency_doc(doc, k)} for n, doc, k in cases]


def generate():
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        log, args, first, second, result = build_log(work)
        other_pub = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(b"another public test key").digest()).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        log_json, logs = tampered_logs(log, work)
        return {
            "format": "aeos-receipts/test-vectors/v0",
            "about": "Shared test vectors for AE-OS Receipts v0 (spec/receipts-v0.md). "
                     "Generated by testvectors/generate.py from the Python reference "
                     "implementation. The test key is public; never use it for a real log.",
            "test_key": {"ed25519_seed": h(TEST_SEED), "public_key": h(log.public_key),
                         "key_id": log.meta["key_id"]},
            "cbor": cbor_cases(),
            "cbor_reject": cbor_rejects(),
            "canonical_json": json_cases(),
            "merkle": merkle_cases(),
            "receipts": receipt_cases(log, first, second, result, other_pub),
            "consistency": consistency_cases(log, first, second, other_pub),
            "logs": {"public_key": h(log.public_key), "log_json": log_json, "cases": logs},
        }


def render() -> str:
    return json.dumps(generate(), indent=1, ensure_ascii=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if the file is out of date")
    text = render()
    if ap.parse_args().check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            print(f"{OUT} is out of date; run python testvectors/generate.py", file=sys.stderr)
            return 1
        print(f"{OUT.name} is up to date")
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
