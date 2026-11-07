"""Generate the shared AE-OS action record test vectors.

Every implementation of the format checks itself against action-records-v1.json. The expected
results (CIDs, roots, proofs, and the problems a verifier reports) come from the Python
reference implementation, so a second implementation that passes agrees with it.

testvectors/passkey-approvals-v1.json holds the passkey approval vectors (spec section 10); its
trails and keys are built by python/tests/passkey_scenarios.py from fixed seeds and a
deterministic software authenticator, never from a real key.

Run from the repository root after `pip install -e python`:

    python testvectors/generate.py            # rewrite action-records-v1.json
    python testvectors/generate.py --check    # fail if the file is out of date

testvectors/receipts-v0.json is the version 0 file, frozen: it is never regenerated, and
every implementation must keep verifying it (it holds `aeos-receipt/v0` documents).

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

from aeos import ActionLog, make_record, verify_action_record_detail, verify_consistency_doc
from aeos import merkle
from aeos.canon import (Link, canonical_json, cid_of_bytes, cid_str, dag_cbor,
                        decode_dag_cbor, json_digest)
from aeos.log import b64, statement_message, to_view

OUT = Path(__file__).with_name("action-records-v1.json")
PASSKEY_OUT = Path(__file__).with_name("passkey-approvals-v1.json")

# The seed phrase is unchanged from version 0 so both vector files share one test key.
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
# A small log, its action records and consistency proofs, and tampered copies
# --------------------------------------------------------------------------------------

def build_log(work: Path):
    key_path = work / "test.key"
    key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    log = ActionLog.create(work / "log", log_id=LOG_ID, key_path=key_path)
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


def tampered_logs(log: ActionLog, work: Path):
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

    def drop_sig(d):
        d.pop("sig")
        d.pop("key_id")

    def bad_record_sig(d):
        sig = bytearray(base64_decode(d["sig"]))
        sig[0] ^= 1
        d["sig"] = b64(bytes(sig))

    def corrupt_bytes(d):
        d["cbor"] = b64(base64_decode(d["cbor"]) + b"\x00")       # not canonical: trailing byte

    def swap_cbor(value):
        def swap(d):
            d["cbor"] = b64(dag_cbor(value))
        return swap

    def truncated(d):
        d["cbor"] = b64(base64_decode(d["cbor"])[:-3])

    def replace_line(i, text):
        return recs[:i] + [text + "\n"] + recs[i + 1:]

    def empty_sig(d):
        d["sig"] = ""

    def sig_not_text(d):
        d["sig"] = 5

    def strip(indexes):
        out = []
        for i, line in enumerate(recs):
            d = json.loads(line)
            if i in indexes:
                drop_sig(d)
            out.append(json.dumps(d, separators=(",", ":")) + "\n")
        return out

    # A version 0 trail: the same records without the marker and without signatures, written
    # as an importer would, with a signed checkpoint.
    v0 = ActionLog.create(work / "v0-trail", log_id=LOG_ID, key_path=work / "test.key")
    for e in log.entries()[1:]:
        v0.append(log.record(e), allow_unsigned=True)
    v0.checkpoint(ts=T0 + 200000)
    v0_files = log_files(v0.path)

    last = len(recs) - 1
    cases = {
        "untouched log": (recs, cps),
        "issuer signature altered": (edit_record(1, bad_record_sig), cps),
        "issuer signature removed from one record": (edit_record(1, drop_sig), cps),
        "issuer signature removed from the last record": (edit_record(last, drop_sig), cps),
        "issuer key id kept, signature emptied": (edit_record(1, empty_sig), cps),
        "issuer signature is not text": (edit_record(1, sig_not_text), cps),
        "signatures stripped from the first records, marker included": (strip({0, 1, 2}), cps),
        "every signature stripped, marker still in the trail": (strip(set(range(len(recs)))),
                                                               cps),
        "marker removed": (recs[1:], cps),
        "marker bytes corrupted": (edit_record(0, corrupt_bytes), cps),
        "first record is not a map": (edit_record(0, swap_cbor([1, 2])), cps),
        "middle record is not a map": (edit_record(2, swap_cbor("x")), cps),
        "record nested too deep": (edit_record(2, lambda d: d.update(
            cbor=b64(b"\x81" * 300 + b"\x00"))), cps),
        "record is an empty map": (edit_record(2, swap_cbor({})), cps),
        "record bytes truncated": (edit_record(2, truncated), cps),
        "record line is not a JSON object": (replace_line(2, "[]"), cps),
        "record line has no cbor field": (replace_line(2, "{}"), cps),
        "record cbor is not text": (replace_line(2, '{"cbor":5}'), cps),
        "checkpoint line is not a JSON object": (recs, [cps[0], "[]\n"]),
        "checkpoint size is negative": (recs, [cps[0], cps[1].replace('"size":8', '"size":-8')]),
        "version 0 trail with no marker and no signatures": (
            v0_files["records"].splitlines(keepends=True),
            v0_files["checkpoints"].splitlines(keepends=True)),
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
        rep = ActionLog.open(d, read_only=True).verify()
        out.append({"name": name, "records": "".join(r), "checkpoints": "".join(c),
                    "expect": {"records": rep.records, "checkpoints": rep.checkpoints,
                               "issuer_signed": rep.issuer_signed,
                               "problems": rep.problems}})
    return base["log_json"], out


def base64_decode(s):
    import base64
    return base64.b64decode(s, validate=True)


IDENTITY = bytes.fromhex("01" + "00" * 31)                  # the point of order 1
ORDER_8 = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")


def weak_key_cases(log, entry, second):
    """Signatures a lax Ed25519 verifier accepts and a strict one must not.

    A small-order public key makes some signatures verify for every message (with the
    identity as key, R = identity and S = 0 does), so a verifier that accepts them accepts
    forged checkpoints and issuer signatures. Every verifier here refuses small-order keys,
    small-order R and unreduced S, and the lax OpenSSL check is asserted to accept the
    forgeries so the vectors keep meaning something.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from aeos import keys
    from aeos.canon import cid_of_bytes as _cid
    from aeos.log import Checkpoint, statement_message

    base = log.action_record(entry, second)

    def lax_accepts(pub, sig, message):
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
            return True
        except Exception:
            return False

    def doc_with(pub, checkpoint_sig, statement_sig, ts=None):
        d = json.loads(json.dumps(base))
        d["checkpoint"]["key_id"] = keys.key_id(pub)
        if ts is not None:
            d["checkpoint"]["ts"] = ts
        d["checkpoint"]["sig"] = b64(checkpoint_sig)
        if statement_sig is None:
            d.pop("statement_signature")
        else:
            d["statement_signature"] = {"key_id": keys.key_id(pub), "sig": b64(statement_sig)}
        return d

    def checkpoint_message(d):
        return Checkpoint.from_json(d["checkpoint"]).message()

    out = []
    # 1. identity as the key: R = identity, S = 0 verifies for every message.
    forged = bytes(IDENTITY) + bytes(32)
    d = doc_with(IDENTITY, forged, forged)
    assert lax_accepts(IDENTITY, forged, checkpoint_message(d))
    assert lax_accepts(IDENTITY, forged, statement_message(_cid(base64_decode(d["record"]))))
    out.append(("small-order public key with a forged signature", d, IDENTITY))

    # 2. an order-8 key with R = identity and S = 0 verifies when 8 divides the hash k, so
    #    search the checkpoint time for a message where it does.
    for ts in range(base["checkpoint"]["ts"], base["checkpoint"]["ts"] + 1000):
        d = doc_with(ORDER_8, forged, None, ts)
        msg = checkpoint_message(d)
        k = int.from_bytes(hashlib.sha512(IDENTITY + ORDER_8 + msg).digest(), "little") % keys._L
        if k % 8 == 0:
            break
    assert lax_accepts(ORDER_8, forged, checkpoint_message(d))
    out.append(("small-order key and small-order R, forged checkpoint", d, ORDER_8))

    # 3. an honest key but a small-order R.
    d = json.loads(json.dumps(base))
    sig = bytes(IDENTITY) + base64_decode(base["checkpoint"]["sig"])[32:]
    d["checkpoint"]["sig"] = b64(sig)
    out.append(("small-order R in the checkpoint signature", d, log.public_key))

    # 4. honest signatures with S + L: the same point, but S is not reduced.
    def unreduced(sig_b64):
        raw = base64_decode(sig_b64)
        s = int.from_bytes(raw[32:], "little") + keys._L
        return raw[:32] + s.to_bytes(32, "little")

    d = json.loads(json.dumps(base))
    d["checkpoint"]["sig"] = b64(unreduced(base["checkpoint"]["sig"]))
    out.append(("checkpoint signature with S not reduced", d, log.public_key))
    d = json.loads(json.dumps(base))
    d["statement_signature"]["sig"] = b64(unreduced(base["statement_signature"]["sig"]))
    out.append(("issuer signature with S not reduced", d, log.public_key))
    return out


def action_record_cases(log, first, second, entry, other_pub):
    good = log.action_record(entry, second)

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
    weak_cases = weak_key_cases(log, entry, second)
    other_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"another public test key").digest())
    other_sig = other_key.sign(statement_message(entry.cid))

    def sig_edit(d):
        sig = bytearray(base64_decode(d["statement_signature"]["sig"]))
        sig[0] ^= 1
        d["statement_signature"]["sig"] = b64(bytes(sig))

    def sig_of_other_record(d):
        other = log.action_record(log.entries()[0], second)
        d["statement_signature"] = other["statement_signature"]

    cases = [
        ("valid action record, latest checkpoint", good, pub),
        ("valid action record, first record", log.action_record(log.entries()[0], first), pub),
        ("valid action record, last record of first checkpoint",
         log.action_record(log.entries()[2], first), pub),
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
        ("wrong document type", variant(lambda d: d.update(type="aeos-action-record/v9")), pub),
        ("no issuer signature (log-signed only)",
         variant(lambda d: d.pop("statement_signature")), pub),
        ("issuer signature altered", variant(sig_edit), pub),
        ("issuer signature belongs to another record", variant(sig_of_other_record), pub),
        ("issuer signature made by a different key under the right key id",
         variant(lambda d: d["statement_signature"].update(sig=b64(other_sig))), pub),
        ("issuer signature names another key id",
         variant(lambda d: d["statement_signature"].update(key_id="0" * 16)), pub),
        ("issuer signature malformed", variant(lambda d: d.update(statement_signature="x")), pub),
        ("issuer signature not text", variant(lambda d: d["statement_signature"].update(sig=5)),
         pub),
        ("document type under its later name",
         variant(lambda d: d.update(type="aeos-action-record/v1")), pub),
    ] + weak_cases
    out = []
    for n, doc, k in cases:
        problems, state = verify_action_record_detail(doc, k)
        out.append({"name": n, "public_key": h(k), "action_record": doc,
                    "expect_problems": problems, "expect_signature": state})
    return out


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
            "format": "aeos-action-records/test-vectors/v1",
            "about": "Shared test vectors for AE-OS action records v1 (spec/action-records-v1.md). "
                     "Generated by testvectors/generate.py from the Python reference "
                     "implementation. The test key is public; never use it for a real log.",
            "test_key": {"ed25519_seed": h(TEST_SEED), "public_key": h(log.public_key),
                         "key_id": log.meta["key_id"]},
            "cbor": cbor_cases(),
            "cbor_reject": cbor_rejects(),
            "canonical_json": json_cases(),
            "merkle": merkle_cases(),
            "action_records": action_record_cases(log, first, second, result, other_pub),
            "consistency": consistency_cases(log, first, second, other_pub),
            "logs": {"public_key": h(log.public_key), "log_json": log_json, "cases": logs},
        }


def passkey_vectors():
    """The passkey approval vectors: constructions, COSE keys, assertions and whole trails."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python" / "tests"))
    import passkey_scenarios as ps
    import webauthn_support as ws
    from aeos import audit, webauthn

    def hx(b):
        return b.hex()

    args = json_digest(ps.ARGS)
    esc = cid_of_bytes(dag_cbor({"example": "an escalation"}))
    items = [(ps.TOOL, json_digest(a), esc) for _, a in ps._batch_items(4)]
    doc_items = [(webauthn.DOCUMENT_TOOL, hashlib.sha256(b"a document").digest(), b"")] + items
    n = ws.nonce(1)
    rd = webauthn.request_digest(ps.TOOL, args, esc)
    cons = {
        "contexts": {"challenge": webauthn.CHALLENGE_CONTEXT.decode(),
                     "request_without_escalation": webauthn.REQUEST_CONTEXT.decode(),
                     "request_for_an_escalation": webauthn.ESCALATED_CONTEXT.decode(),
                     "batch": webauthn.BATCH_CONTEXT.decode(),
                     "enrol": webauthn.ENROL_CONTEXT.decode()},
        "tool": ps.TOOL, "args_sha256": hx(args), "escalation": hx(esc), "nonce": hx(n),
        "request_digest": hx(rd),
        "request_digest_without_escalation": hx(webauthn.request_digest(ps.TOOL, args)),
        "challenge": hx(webauthn.challenge_for(n, rd)),
        "batch_items": [{"tool": t, "args_sha256": hx(a), "escalation": hx(e)}
                        for t, a, e in items],
        "batch_digest": hx(webauthn.batch_digest(items)),
        "batch_challenge": hx(webauthn.challenge_for(n, webauthn.batch_digest(items))),
        "batch_with_document_digest": hx(webauthn.batch_digest(doc_items)),
        "enrol": {"approver": ws.APPROVER, "identity_evidence_sha256": hx(doc_items[0][1]),
                  "challenge": hx(webauthn.enrol_challenge(ws.APPROVER, doc_items[0][1]))},
    }

    def cose_case(name, key):
        try:
            webauthn.parse_cose_key(key)
            err = None
        except webauthn.WebAuthnError as e:
            err = str(e)
        return {"name": name, "cose_key": hx(key), "expect_error": err}

    keys_ = [cose_case("valid ES256 key", ps.A.cose_key),
             cose_case("valid EdDSA key", ps.E.cose_key)]
    keys_ += [cose_case(c["name"], bytes.fromhex(c["key"])) for c in _key_cases(ps, ws)]

    def assertion_case(name, auth, ev_fn=None, **wrong):
        ch = webauthn.challenge_for(n, rd)
        ad, cdj, sig = auth.assertion(ch, **wrong)
        if ev_fn:
            ad, cdj, sig = ev_fn(ad, cdj, sig)
        try:
            webauthn.verify_assertion(webauthn.parse_cose_key(auth.cose_key), ad, cdj, sig,
                                      rp_id=auth.rp_id, origin=auth.origin, challenge=ch)
            err = None
        except webauthn.WebAuthnError as e:
            err = str(e)
        return {"name": name, "cose_key": hx(auth.cose_key), "rp_id": auth.rp_id,
                "origin": auth.origin, "challenge": hx(ch), "authenticator_data": hx(ad),
                "client_data_json": hx(cdj), "signature": hx(sig), "expect_error": err}

    flip = ps.flip
    assertions = [
        assertion_case("valid ES256 assertion", ps.A),
        assertion_case("valid EdDSA assertion", ps.E),
        assertion_case("signature changed", ps.A, lambda a, c, s: (a, c, flip(s, 10))),
        assertion_case("authenticator data changed", ps.A, lambda a, c, s: (flip(a, 34), c, s)),
        assertion_case("client data changed", ps.A, lambda a, c, s: (a, flip(c, 30), s)),
        assertion_case("EdDSA signature changed", ps.E, lambda a, c, s: (a, c, flip(s, 3))),
        assertion_case("another origin", ps.A, origin="https://evil.example"),
        assertion_case("another relying party", ps.A, rp_id="evil.example"),
        assertion_case("no user verification", ps.A, uv=False),
        assertion_case("no user presence", ps.A, up=False),
        assertion_case("sign counter that never moves (a synced passkey) is accepted", ps.A),
        assertion_case("extension data that is one canonical map", ps.A,
                       extensions=b"\xa1\x69credProps\xa1\x62rk\xf5"),
        assertion_case("extension data that is not exactly one map", ps.A, extensions=b"\xa0\x00"),
        assertion_case("extension flag with no extension data", ps.A, ed_flag=True),
        assertion_case("client data with a repeated key", ps.A,
                       client_raw=b'{"type":"webauthn.get","type":"webauthn.get"}'),
        assertion_case("cross-origin client data", ps.A, extra_client={"crossOrigin": True}),
    ]
    cases = []
    for name, trail, pr, expect in ps.scenarios():
        findings, problems, notes = audit.check_approvals(trail.triples(), pr,
                                                          demo=name in ps.DEMO_CASES)
        assert len(problems) == len(expect) and all(x in y for x, y in zip(expect, problems)), \
            (name, expect, problems)
        cases.append({"name": name, "principals": pr,
                      "records": [{"cid": cid_str(c), "cbor": hx(dag_cbor(r))}
                                  for _, c, r in trail.triples()],
                      **({"demo": True} if name in ps.DEMO_CASES else {}),
                      "expect_problems": problems, "expect_notes": notes})
    return {
        "format": "aeos-passkey-approvals/test-vectors/v1",
        "about": "Test vectors for passkey approvals (spec/action-records-v1.md, section 10). "
                 "Generated by testvectors/generate.py from the Python reference implementation "
                 "with a deterministic software authenticator; every key is derived from a "
                 "public seed, never use one for real. A case is a trail (records in order, "
                 "each with its CID), the principals file the auditor trusts, and the problems "
                 "a verifier must report, in order (none means the approvals verify), and the notes it makes.",
        "public_suffixes": sorted(webauthn.PUBLIC_SUFFIXES),
        "constructions": cons, "cose_keys": keys_, "assertions": assertions, "cases": cases,
    }


def _key_cases(ps, ws):
    """The bent COSE keys of the scenarios, by name."""
    return [{"name": n, "key": k.hex()} for n, k in (
        ("wrong curve", ws.cose_es256(ps.A.cose_key[-70:-38], ps.A.cose_key[-32:], crv=2)),
        ("not on the curve", ws.cose_es256(b"\x01" * 32, b"\x02" * 32)),
        ("coordinates not reduced", ws.cose_es256(b"\xff" * 32, b"\xff" * 32)),
        ("EdDSA small order", ws.cose_eddsa(b"\x01" + b"\x00" * 31)),
        ("EdDSA on Ed448", ws.cose_eddsa(ps.E.cose_key[-32:], crv=7)),
        ("unsupported algorithm", ws.cose_es256(ps.A.cose_key[-70:-38], ps.A.cose_key[-32:],
                                                alg=-257)),
        ("trailing bytes", ps.A.cose_key + b"\x00"),
        ("truncated", ps.A.cose_key[:-1]),
        ("empty", b""))]


def render() -> str:
    return json.dumps(generate(), indent=1, ensure_ascii=False) + "\n"


def render_passkey() -> str:
    return json.dumps(passkey_vectors(), indent=1, ensure_ascii=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if the file is out of date")
    files = ((OUT, render()), (PASSKEY_OUT, render_passkey()))
    if ap.parse_args().check:
        stale = [f for f, text in files if not f.exists()
                 or f.read_text(encoding="utf-8") != text]
        for f in stale:
            print(f"{f} is out of date; run python testvectors/generate.py", file=sys.stderr)
        if not stale:
            print(" and ".join(f.name for f, _ in files) + " are up to date")
        return 1 if stale else 0
    for f, text in files:
        f.write_text(text, encoding="utf-8")
        print(f"wrote {f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
