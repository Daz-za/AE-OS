"""`aeos-receipts audit`: check an evidence folder from end to end, as an auditor would.

An evidence folder holds a receipt log plus what is needed to check who acted:

    evidence.json   what is where: trust domain, trust bundle, SVID certificates,
                    the log folder, the witnesses' public keys and how many must cosign
    trust/          the trust domain's root certificate (trust bundle)
    svids/          the X.509-SVID certificate chains the agents presented (no keys)
    log/            the receipt log, with cosignatures.jsonl from the witnesses

The audit recomputes the whole log, then checks that each session was opened with an SVID whose
fingerprint the gateway recorded, and that this SVID was valid for the recorded identity
at that moment, and that the latest
checkpoint carries enough valid witness cosignatures. In a real audit the auditor takes
the trust bundle, the log's public key and the witnesses' keys from sources they trust,
not from the folder under review; `audit` accepts them as options for that reason.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import identity, witness
from .log import ReceiptLog


def _load_svids(folder: Path) -> Dict[str, List[Any]]:
    """SVID chains in the folder, by the SHA-256 fingerprint of the leaf certificate."""
    out: Dict[str, List[Any]] = {}
    for f in sorted(folder.glob("*.pem")):
        chain = identity.load_chain(f.read_bytes())
        if chain:
            out[identity.fingerprint(chain[0])] = chain
    return out


def run(folder: Path, *, bundle: Optional[Path] = None, public_key: Optional[str] = None,
        witnesses: Optional[Path] = None) -> Tuple[List[str], List[str]]:
    """Return (findings, problems). No problems means the evidence holds together."""
    folder = Path(folder)
    manifest = json.loads((folder / "evidence.json").read_text())
    findings: List[str] = []
    problems: List[str] = []

    log = ReceiptLog.open(folder / manifest["log"], read_only=True)
    if public_key and public_key.lower() != log.public_key.hex():
        problems.append("the log's public key differs from the one you trust")
    rep = log.verify()
    problems += [f"log: {p}" for p in rep.problems]
    findings.append(f"The log's {rep.records} records were recomputed and its "
                    f"{rep.checkpoints} checkpoint signatures verified"
                    + ("" if rep.ok else ", with problems"))

    roots = identity.load_chain((Path(bundle) if bundle else folder / manifest["bundle"])
                                .read_bytes())
    svids = _load_svids(folder / manifest["svids"])
    domain = manifest["trust_domain"]
    sessions = 0
    for e in log.entries():
        rec = log.record(e)
        if rec["kind"] != "session.start" or "svid_sha256" not in rec["body"]:
            continue
        sessions += 1
        fp = rec["body"]["svid_sha256"].hex()
        chain = svids.get(fp)
        if chain is None:
            problems.append(f"record {e.index}: the SVID {fp[:16]}… used to open this "
                            "session is not in the evidence")
            continue
        at = dt.datetime.fromtimestamp(rec["ts"] / 1000, dt.timezone.utc)
        try:
            sid = identity.verify_svid(chain, roots, at=at, trust_domain=domain)
        except identity.IdentityError as err:
            problems.append(f"record {e.index}: {err}")
            continue
        if sid != rec["agent"]:
            problems.append(f"record {e.index}: recorded agent {rec['agent']} differs from "
                            f"the SVID's identity {sid}")
    findings.append(f"Each of the {sessions} session records names a certificate that "
                    f"chains to the {domain} trust bundle and was valid when the session "
                    "started" + ("" if not any(p.startswith("record") for p in problems)
                                 else " (except as listed below)"))

    wfile = Path(witnesses) if witnesses else folder / manifest["witnesses"]
    wdoc = json.loads(wfile.read_text())
    wkeys = {n: bytes.fromhex(k) for n, k in wdoc["keys"].items()}
    cps = log.checkpoints()
    if not cps:
        problems.append("the log has no signed checkpoint")
    else:
        cp = cps[-1]
        wp = witness.verify_cosignatures(cp, witness.load_cosignatures(log.path), wkeys,
                                         int(wdoc["required"]))
        problems += [f"witnesses: {p}" for p in wp]
        if not wp:
            findings.append(f"The latest checkpoint (size {cp.size}) is cosigned by "
                            f"{wdoc['required']} of the {len(wkeys)} trusted witnesses; each has "
                            "cosigned only this history of the log")
    return findings, problems
