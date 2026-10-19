"""Canonical encodings used by AE-OS Receipts.

* Deterministic DAG-CBOR (the subset AE-OS needs): null, bool, int, text, bytes,
  list, map with text keys, and tag-42 CID links. Floats are rejected so that every
  record has exactly one encoding.
* CIDv1 (dag-cbor codec, sha2-256 multihash) and its base32 string form.
* A canonical JSON form for hashing tool arguments and results (RFC 8785 style).
"""
from __future__ import annotations

import hashlib
import json
import math
import struct
from typing import Any, Tuple

# --------------------------------------------------------------------------------------
# DAG-CBOR encode
# --------------------------------------------------------------------------------------


class Link(bytes):
    """A CID used as a link to an earlier record: CBOR tag 42 over (0x00 || binary CID)."""


def _head(major: int, n: int) -> bytes:
    """CBOR initial byte plus shortest-form argument (RFC 8949 s.4.2.1)."""
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + struct.pack(">H", n)
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + struct.pack(">I", n)
    if n < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + struct.pack(">Q", n)
    raise ValueError("integer out of range for CBOR")


def _key_order(k: str) -> Tuple[int, bytes]:
    b = k.encode("utf-8")
    return (len(b), b)


def dag_cbor(v: Any) -> bytes:
    """Encode v deterministically. Map keys are sorted length-first, then bytewise."""
    if isinstance(v, Link):
        body = b"\x00" + bytes(v)
        return b"\xd8\x2a" + _head(2, len(body)) + body
    if v is None:
        return b"\xf6"
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        return _head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, (list, tuple)):
        return _head(4, len(v)) + b"".join(dag_cbor(x) for x in v)
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise TypeError("map keys must be text")
        keys = sorted(v, key=_key_order)
        return _head(5, len(v)) + b"".join(dag_cbor(k) + dag_cbor(v[k]) for k in keys)
    raise TypeError(f"unsupported type in record: {type(v).__name__}")


# --------------------------------------------------------------------------------------
# DAG-CBOR decode (same subset; rejects non-canonical input)
# --------------------------------------------------------------------------------------


class DecodeError(ValueError):
    pass


def _read_arg(data: bytes, i: int, info: int) -> Tuple[int, int]:
    if info < 24:
        return info, i
    size = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
    if size is None or i + size > len(data):
        raise DecodeError("bad length")
    return int.from_bytes(data[i:i + size], "big"), i + size


def _decode(data: bytes, i: int) -> Tuple[Any, int]:
    if i >= len(data):
        raise DecodeError("truncated")
    ib = data[i]
    major, info = ib >> 5, ib & 31
    i += 1
    if major == 7:
        if info == 20:
            return False, i
        if info == 21:
            return True, i
        if info == 22:
            return None, i
        raise DecodeError("unsupported simple value or float")
    n, i = _read_arg(data, i, info)
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        if i + n > len(data):
            raise DecodeError("truncated string")
        raw = data[i:i + n]
        return (bytes(raw) if major == 2 else raw.decode("utf-8")), i + n
    if major == 4:
        out = []
        for _ in range(n):
            x, i = _decode(data, i)
            out.append(x)
        return out, i
    if major == 5:
        m = {}
        for _ in range(n):
            k, i = _decode(data, i)
            if not isinstance(k, str):
                raise DecodeError("map key must be text")
            m[k], i = _decode(data, i)
        return m, i
    if major == 6 and n == 42:
        body, i = _decode(data, i)
        if not isinstance(body, bytes) or not body.startswith(b"\x00"):
            raise DecodeError("bad CID link")
        return Link(body[1:]), i
    raise DecodeError(f"unsupported major type {major}")


def decode_dag_cbor(data: bytes) -> Any:
    """Decode and check the input is the canonical encoding of the decoded value."""
    v, i = _decode(data, 0)
    if i != len(data):
        raise DecodeError("trailing bytes")
    if dag_cbor(v) != data:
        raise DecodeError("input is not canonical DAG-CBOR")
    return v


# --------------------------------------------------------------------------------------
# CIDs
# --------------------------------------------------------------------------------------

# CIDv1 = version 0x01, codec dag-cbor 0x71, multihash sha2-256 0x12, length 0x20
CID_PREFIX = bytes([0x01, 0x71, 0x12, 0x20])


def cid_of_bytes(encoded: bytes) -> bytes:
    return CID_PREFIX + hashlib.sha256(encoded).digest()


def cid_str(cid: bytes) -> str:
    """Multibase base32 (RFC 4648 lower case, no padding, prefix 'b')."""
    alphabet, bits, acc, out = "abcdefghijklmnopqrstuvwxyz234567", 0, 0, []
    for byte in cid:
        acc, bits = (acc << 8) | byte, bits + 8
        while bits >= 5:
            bits -= 5
            out.append(alphabet[(acc >> bits) & 31])
    if bits:
        out.append(alphabet[(acc << (5 - bits)) & 31])
    return "b" + "".join(out)


def cid_parse(s: str) -> bytes:
    if not s.startswith("b"):
        raise ValueError("expected base32 CID starting with 'b'")
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    acc, bits, out = 0, 0, bytearray()
    for ch in s[1:]:
        acc, bits = (acc << 5) | alphabet.index(ch), bits + 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out)


# --------------------------------------------------------------------------------------
# Canonical JSON for digests of tool arguments and results
# --------------------------------------------------------------------------------------


def _jcs_number(x: float) -> str:
    if math.isnan(x) or math.isinf(x):
        raise ValueError("NaN and infinity have no JSON form")
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))
    return repr(x)


def canonical_json(v: Any) -> bytes:
    """Serialize JSON-compatible data deterministically.

    Follows RFC 8785 (JCS) for objects, arrays, strings, integers, booleans and null:
    keys sorted by UTF-16 code units, no whitespace. Non-integral floats use Python's
    shortest round-trip form, which matches JCS for common values.
    """
    if v is None:
        return b"null"
    if v is True:
        return b"true"
    if v is False:
        return b"false"
    if isinstance(v, int):
        return str(v).encode()
    if isinstance(v, float):
        return _jcs_number(v).encode()
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False).encode("utf-8")
    if isinstance(v, (list, tuple)):
        return b"[" + b",".join(canonical_json(x) for x in v) + b"]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return b"{" + b",".join(canonical_json(k) + b":" + canonical_json(v[k])
                                for k in keys) + b"}"
    raise TypeError(f"not JSON data: {type(v).__name__}")


def json_digest(v: Any) -> bytes:
    """SHA-256 over the canonical JSON form."""
    return hashlib.sha256(canonical_json(v)).digest()
