"""`aeos-receipts audit`: check an evidence folder from end to end, as an auditor would.

An evidence folder holds a receipt log plus what is needed to check who acted:

    evidence.json   what is where: trust domain, trust bundle, SVID certificates,
                    the log folder, the witnesses' public keys and how many must cosign
    trust/          the trust domain's root certificate (trust bundle)
    svids/          the X.509-SVID certificate chains the agents presented (no keys)
    log/            the receipt log, with cosignatures.jsonl from the witnesses
    intents/        the signed intent envelopes, and tokens/ the capability tokens the
                    agents presented, when the gateway required them

The audit recomputes the whole log, then checks that each session was opened with an SVID whose
fingerprint the gateway recorded, and that this SVID was valid for the recorded identity
at that moment, and that the latest
checkpoint carries enough valid witness cosignatures. Where the gateway required capability
tokens, it replays each recorded decision from the token, the person's signed intent and
the facts in the record, and checks that every call that ran was allowed. In a real audit the auditor takes
the trust bundle, the log's public key, the witnesses' keys, the authorization service's
key and each person's key from sources they trust,
not from the folder under review; `audit` accepts them as options for that reason.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import delegation, identity, witness
from .canon import cid_str
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
        witnesses: Optional[Path] = None, authority_key: Optional[str] = None,
        principals: Optional[Path] = None) -> Tuple[List[str], List[str]]:
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

    if manifest.get("authority"):
        key = bytes.fromhex(authority_key or (folder / manifest["authority"]).read_text().strip())
        pdoc = json.loads((Path(principals) if principals else folder / manifest["principals"])
                          .read_text())
        _check_capabilities(log, folder, manifest, key,
                            {k: bytes.fromhex(v) for k, v in pdoc.items()}, findings, problems)

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


def _check_capabilities(log: ReceiptLog, folder: Path, manifest: Dict[str, Any],
                        authority_key: bytes, principal_keys: Dict[str, bytes],
                        findings: List[str], problems: List[str]) -> None:
    """Replay each capability decision and check that every call that ran was allowed."""
    tokens = {f.stem: f.read_bytes() for f in (folder / manifest["tokens"]).glob("*.biscuit")}
    intents = {}
    for f in (folder / manifest["intents"]).glob("*.json"):
        env = delegation.IntentEnvelope.from_json(json.loads(f.read_text()))
        intents[env.cid] = env
    records = [(e, log.record(e)) for e in log.entries()]
    results = [(cid_str(r["parents"][0]), r["body"].get("outcome")) for _, r in records
               if r["kind"] == "tool.result" and r["parents"]]
    ran_calls = {c for c, outcome in results if outcome != "error"}
    governed = {cid_str(e.cid) for e, r in records if r["kind"] == "session.start"
                and r["body"].get("authorization") == delegation.POLICY}
    allowed_calls = set()
    spent: Dict[str, int] = {}
    counts = {"allow": 0, "deny": 0}
    for e, rec in records:
        body = rec["body"]
        if rec["kind"] != "policy.decision" or body.get("policy") != delegation.POLICY:
            continue
        call = cid_str(rec["parents"][0]) if rec["parents"] else ""
        recorded = body.get("decision")
        counts[recorded] = counts.get(recorded, 0) + 1
        replay, why = _replay(rec, tokens, intents, principal_keys, authority_key, spent)
        if replay != (recorded == "allow"):
            problems.append(f"record {e.index}: the gateway recorded {recorded}, but replaying "
                            f"the token and intent gives {'allow' if replay else 'deny'}"
                            + (f" ({why})" if why else ""))
        if recorded == "allow":
            allowed_calls.add(call)
            if replay and call in ran_calls:
                intent = body["intent"]
                spent[intent] = spent.get(intent, 0) + body["amount"]
    for e, rec in records:
        if rec["kind"] != "tool.call" or not rec["parents"]:
            continue
        call = cid_str(e.cid)
        if cid_str(rec["parents"][0]) in governed and call in ran_calls \
                and call not in allowed_calls:
            problems.append(f"record {e.index}: the call ran without an allow decision")
    findings.append(f"Each of the {counts['allow'] + counts['deny']} capability decisions "
                    f"({counts['allow']} allowed, {counts['deny']} refused) was replayed from "
                    "the agent's token and the person's signed intent")


def _replay(rec: Dict[str, Any], tokens: Dict[str, bytes],
            intents: Dict[str, "delegation.IntentEnvelope"], principal_keys: Dict[str, bytes],
            authority_key: bytes, spent: Dict[str, int]) -> Tuple[bool, str]:
    """Decide the call again from the evidence alone: (allowed, why not)."""
    body = rec["body"]
    sha = body.get("token_sha256")
    if not isinstance(sha, bytes):
        return False, "no token"
    raw = tokens.get(sha.hex())
    if raw is None:
        return False, f"the token {sha.hex()[:16]}… is not in the evidence"
    amount = body.get("amount")
    if not isinstance(amount, int) or amount < 0:
        return False, "the recorded amount is not valid"
    d = delegation.authorize(raw, authority_key, subject=rec["agent"], tool=rec["subject"],
                             amount=amount, at=rec["ts"])
    if not d.allowed:
        return False, "; ".join(d.reasons)
    env = intents.get(d.intent or "")
    if env is None:
        return False, f"the intent {d.intent} is not in the evidence"
    if not env.verify(principal_keys.get(env.principal, b"")):
        return False, f"the intent is not signed by {env.principal}"
    if rec.get("obo") != env.principal:
        return False, f"the record names {rec.get('obo')} rather than {env.principal}"
    if spent.get(env.cid, 0) + amount > env.budget_minor:
        return False, "the intent's budget would be exceeded"
    return True, ""
