"""Policy as code: Rego policies compiled to WebAssembly and run in a sandbox.

A policy is written in Rego (Open Policy Agent's language) and compiled with
`opa build -t wasm`. The gateway runs the compiled module with wasmtime: the module can
read only the input and data it is given, has no access to files, the network or the
clock, and is limited in memory and in the work it may do per decision. The same module,
named by the SHA-256 of its bytes, gives the same decision for the same input and data,
so an auditor can replay any recorded decision.

The host side follows OPA's WebAssembly ABI (version 1.2 or later): it parses the data
and input as JSON inside the module, calls `opa_eval`, and reads the JSON result. The
policy must use no built-in functions that the module leaves to the host.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import wasmtime

from .canon import canonical_json

POLICY = "aeos-policy/v0"
PAGES = 64                     # initial memory: 64 pages of 64 KiB (4 MiB)
MAX_PAGES = 256                # at most 16 MiB
FUEL = 50_000_000              # instructions a single decision may run
DECISIONS = ("allow", "deny", "escalate")


class PolicyError(Exception):
    """The policy could not be loaded or did not produce a decision."""


def policy_sha256(wasm: bytes) -> bytes:
    return hashlib.sha256(wasm).digest()


class Policy:
    """One compiled policy module with its data, ready to make decisions."""

    def __init__(self, wasm: bytes, data: Dict[str, Any], entrypoint: str) -> None:
        self.wasm, self.data, self.entrypoint = wasm, json.loads(json.dumps(data)), entrypoint
        self.sha256 = policy_sha256(wasm)
        self.data_sha256 = data_sha256(data)
        config = wasmtime.Config()
        config.consume_fuel = True
        self._engine = wasmtime.Engine(config)
        self._module = wasmtime.Module(self._engine, wasm)

    @classmethod
    def load(cls, wasm_path: Path, data: Dict[str, Any], entrypoint: str) -> "Policy":
        return cls(Path(wasm_path).read_bytes(), data, entrypoint)

    def _instance(self) -> Tuple[wasmtime.Store, Any, wasmtime.Memory]:
        store = wasmtime.Store(self._engine)
        store.set_fuel(FUEL)
        memory = wasmtime.Memory(store, wasmtime.MemoryType(wasmtime.Limits(PAGES, MAX_PAGES)))

        def text(addr: int) -> str:
            raw = memory.read(store, addr, min(addr + 4096, memory.data_len(store)))
            return bytes(raw).split(b"\0", 1)[0].decode("utf-8", "replace")

        def abort(addr: int) -> None:
            raise PolicyError(f"the policy stopped: {text(addr)}")

        def builtin(*_: int) -> int:
            raise PolicyError("the policy needs a built-in function this host does not offer")

        i32 = wasmtime.ValType.i32()
        imports = {"memory": memory,
                   "opa_abort": wasmtime.Func(store, wasmtime.FuncType([i32], []), abort)}
        for n in range(5):
            imports[f"opa_builtin{n}"] = wasmtime.Func(
                store, wasmtime.FuncType([i32] * (n + 2), [i32]), builtin)
        unknown = sorted({i.name for i in self._module.imports} - set(imports))
        if unknown:
            raise PolicyError("the policy needs functions this host does not offer: "
                              + ", ".join(unknown))
        ordered = [imports[i.name] for i in self._module.imports]
        instance = wasmtime.Instance(store, self._module, ordered)
        return store, instance.exports(store), memory

    def evaluate(self, input_doc: Dict[str, Any]) -> Dict[str, Any]:
        """The policy's decision for `input_doc`: {"decision", "reasons"}."""
        try:
            store, ex, memory = self._instance()
            if ex["opa_wasm_abi_version"].value(store) != 1 or \
                    ex["opa_wasm_abi_minor_version"].value(store) < 2:
                raise PolicyError("the policy was compiled for an unsupported OPA ABI")
            needs = self._read_json(store, ex, memory, ex["builtins"](store))
            if needs:
                raise PolicyError("the policy needs built-in functions this host does not "
                                  "offer: " + ", ".join(sorted(needs)))
            entrypoints = self._read_json(store, ex, memory, ex["entrypoints"](store))
            if self.entrypoint not in entrypoints:
                raise PolicyError(f"the policy has no entrypoint {self.entrypoint}")
            data_addr = self._parse(store, ex, memory, json.dumps(self.data).encode())
            raw = json.dumps(input_doc).encode()
            heap = ex["opa_heap_ptr_get"](store)
            if heap + len(raw) > memory.data_len(store):
                memory.grow(store, (len(raw) >> 16) + 1)
            memory.write(store, raw, heap)
            out = ex["opa_eval"](store, 0, entrypoints[self.entrypoint], data_addr, heap,
                                 len(raw), heap + len(raw), 0)
            result = json.loads(self._cstring(store, memory, out))
        except wasmtime.WasmtimeError as e:
            raise PolicyError(f"the policy failed to run: {str(e).splitlines()[0]}") from e
        except wasmtime.Trap as e:
            raise PolicyError(f"the policy failed to run: {str(e).splitlines()[0]}") from e
        if not result or "result" not in result[0]:
            raise PolicyError("the policy gave no decision for this input")
        d = result[0]["result"]
        if not isinstance(d, dict) or d.get("decision") not in DECISIONS:
            raise PolicyError("the policy's answer is not a decision")
        return {"decision": d["decision"], "reasons": list(d.get("reasons") or [])}

    @staticmethod
    def _cstring(store: wasmtime.Store, memory: wasmtime.Memory, addr: int) -> bytes:
        end = memory.data_len(store)
        out = bytearray()
        while addr < end:
            chunk = bytes(memory.read(store, addr, min(addr + 65536, end)))
            i = chunk.find(b"\0")
            if i >= 0:
                return bytes(out + chunk[:i])
            out += chunk
            addr += len(chunk)
        return bytes(out)

    def _parse(self, store, ex, memory, raw: bytes) -> int:
        addr = ex["opa_malloc"](store, len(raw))
        memory.write(store, raw, addr)
        value = ex["opa_json_parse"](store, addr, len(raw))
        if not value:
            raise PolicyError("the policy data is not valid JSON")
        return value

    def _read_json(self, store, ex, memory, value_addr: int) -> Any:
        return json.loads(self._cstring(store, memory, ex["opa_json_dump"](store, value_addr)))


def data_sha256(data: Dict[str, Any]) -> bytes:
    """The digest that names a policy's data in the log and the evidence folder."""
    return hashlib.sha256(canonical_json(data)).digest()


def replay(wasm: bytes, data: Dict[str, Any], entrypoint: str,
           input_doc: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Evaluate a recorded decision again: (decision, problems)."""
    try:
        return Policy(wasm, data, entrypoint).evaluate(input_doc), []
    except PolicyError as e:
        return None, [str(e)]
