import pytest

from aeos_receipts.canon import (DecodeError, Link, canonical_json, cid_of_bytes, cid_parse,
                                 cid_str, dag_cbor, decode_dag_cbor)


def test_rfc8949_integer_vectors():
    vec = {0: "00", 23: "17", 24: "1818", 100: "1864", 1000: "1903e8",
           1000000: "1a000f4240", -1: "20", -100: "3863"}
    for v, hx in vec.items():
        assert dag_cbor(v).hex() == hx


def test_map_keys_sorted_length_first():
    assert dag_cbor({"aa": 1, "z": 2}) == dag_cbor({"z": 2, "aa": 1})
    assert dag_cbor({"aa": 1, "z": 2}).hex() == "a2617a0262616101"


def test_round_trip_and_links():
    cid = cid_of_bytes(b"\xa0")
    v = {"kind": "tool.call", "n": -5, "b": b"\x01\x02", "ok": True, "x": None,
         "parents": [Link(cid)], "body": {"list": [1, "two"]}}
    enc = dag_cbor(v)
    assert decode_dag_cbor(enc) == v
    assert isinstance(decode_dag_cbor(enc)["parents"][0], Link)
    assert dag_cbor(Link(cid)).hex().startswith("d82a58250001711220")


def test_non_canonical_input_is_rejected():
    with pytest.raises(DecodeError):
        decode_dag_cbor(bytes.fromhex("1800"))          # 0 in long form
    with pytest.raises(DecodeError):
        decode_dag_cbor(bytes.fromhex("a2626161016178f5"[:0] + "a262616101617a02"))  # unsorted
    with pytest.raises(TypeError):
        dag_cbor(1.5)


def test_cid_string_round_trip():
    cid = cid_of_bytes(dag_cbor({"a": 1}))
    s = cid_str(cid)
    assert s.startswith("bafyrei") and cid_parse(s) == cid


def test_canonical_json():
    assert canonical_json({"b": 1, "a": [True, None, "x"]}) == b'{"a":[true,null,"x"],"b":1}'
    assert canonical_json({"n": 2.0, "m": 0.5}) == b'{"m":0.5,"n":2}'
    assert canonical_json("é") == '"é"'.encode()
