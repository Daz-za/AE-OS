"""`aeos audit`: check an evidence folder from end to end, as an auditor would.

An evidence folder holds an audit trail plus what is needed to check who acted:

    evidence.json   what is where: trust domain, trust bundle, SVID certificates,
                    the log folder, the witnesses' public keys and how many must cosign
    trust/          the trust domain's root certificate (trust bundle)
    svids/          the X.509-SVID certificate chains the agents presented (no keys)
    log/            the audit trail, with cosignatures.jsonl from the witnesses
    intents/        the signed intent envelopes, and tokens/ the capability tokens the
                    agents presented, when the gateway required them
    policies/       the compiled policy modules (<sha256>.wasm) and their data
                    (data-<sha256>.json), when the gateway ran a policy
    books           when the log holds books of account: the books service's SPIFFE ID,
                    the controllers who may open and close periods, and the chart of
                    accounts; people's keys are in the principals file

The audit recomputes the whole log, then checks that each session was opened with an SVID whose
fingerprint the gateway recorded, and that this SVID was valid for the recorded identity
at that moment, and that the latest
checkpoint carries enough valid witness cosignatures. Where the gateway required capability
tokens, it replays each recorded decision from the token, the person's signed intent and
the facts in the record, and checks that every call that ran was allowed. Where it ran a
policy, it runs the same compiled module on the recorded input again, checks each
person's approval, and checks that every call that ran had the policy's allow. Where the log holds books of
account, it rebuilds them from the journal entries and checks that each entry balances, is
dated in an open period and is numbered without gaps, and that each period change is
signed by a controller. In a real audit the auditor takes
the trust bundle, the log's public key, the witnesses' keys, the authorization service's
key and each person's key from sources they trust,
not from the folder under review; `audit` accepts them as options for that reason.

An audit of a tampered trail fails and says why; it does not stop. A record that cannot be read
is a problem from the log check and is left out of the later checks, and a check that meets
contents it cannot make sense of reports that as a problem too.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import books, delegation, identity, policy, witness
from .canon import cid_str
from .log import ActionLog


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

    log = ActionLog.open(folder / manifest["log"], read_only=True)
    if public_key and public_key.lower() != log.public_key.hex():
        problems.append("the log's public key differs from the one you trust")
    rep = log.verify()
    problems += [f"log: {p}" for p in rep.problems]
    findings.append(f"The log's {rep.records} records were recomputed and its "
                    f"{rep.checkpoints} checkpoint signatures verified"
                    + ("" if rep.ok else ", with problems"))

    records = log.readable()
    roots = identity.load_chain((Path(bundle) if bundle else folder / manifest["bundle"])
                                .read_bytes())
    svids = _load_svids(folder / manifest["svids"])
    domain = manifest["trust_domain"]
    _guarded("the session certificates", _check_sessions, records, roots, svids, domain,
             findings, problems)

    if manifest.get("authority"):
        key = bytes.fromhex(authority_key or (folder / manifest["authority"]).read_text().strip())
        pdoc = json.loads((Path(principals) if principals else folder / manifest["principals"])
                          .read_text())
        _guarded("the capability decisions", _check_capabilities, records, folder, manifest, key,
                 {k: bytes.fromhex(v) for k, v in pdoc.items()}, findings, problems)

    if manifest.get("policies"):
        pkeys = {}
        if manifest.get("principals"):
            pdoc = json.loads((Path(principals) if principals else folder / manifest["principals"])
                              .read_text())
            pkeys = {k: bytes.fromhex(v) for k, v in pdoc.items()}
        _guarded("the policy decisions", _check_policies, records, folder / manifest["policies"],
                 pkeys, findings, problems)

    if manifest.get("books"):
        pdoc = json.loads((Path(principals) if principals else folder / manifest["principals"])
                          .read_text())
        setup = manifest["books"] if isinstance(manifest["books"], dict) else {}
        _guarded("the books", _check_books, records,
                 {k: bytes.fromhex(v) for k, v in pdoc.items()}, setup, findings, problems)

    wfile = Path(witnesses) if witnesses else folder / manifest["witnesses"]
    wdoc = json.loads(wfile.read_text())
    wkeys = {n: bytes.fromhex(k) for n, k in wdoc["keys"].items()}
    _guarded("the witness cosignatures", _check_witnesses, log, wkeys, wdoc, findings, problems)
    return findings, problems


def _guarded(what: str, check: Any, *args: Any) -> None:
    """Run one check. Evidence that someone tampered with can break a check's assumptions;
    that must end in a problem, never a crash, so an audit of it can only fail."""
    problems = args[-1]
    try:
        check(*args)
    except Exception as ex:              # noqa: BLE001 - fail closed on any malformed evidence
        problems.append(f"{what} could not be checked because the evidence is malformed "
                        f"({type(ex).__name__}: {ex})")


def _check_sessions(records: List[Tuple[Any, Dict[str, Any]]], roots: List[Any],
                    svids: Dict[str, List[Any]], domain: str, findings: List[str],
                    problems: List[str]) -> None:
    """Each session was opened with a certificate that chained to the trust bundle."""
    sessions = 0
    for e, rec in records:
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


def _check_witnesses(log: ActionLog, wkeys: Dict[str, bytes], wdoc: Dict[str, Any],
                     findings: List[str], problems: List[str]) -> None:
    """The latest checkpoint carries enough valid cosignatures."""
    cps = log.checkpoints()
    if not cps:
        problems.append("the log has no signed checkpoint")
        return
    cp = cps[-1]
    wp = witness.verify_cosignatures(cp, witness.load_cosignatures(log.path), wkeys,
                                     int(wdoc["required"]))
    problems += [f"witnesses: {p}" for p in wp]
    if not wp:
        findings.append(f"The latest checkpoint (size {cp.size}) is cosigned by "
                        f"{wdoc['required']} of the {len(wkeys)} trusted witnesses; each has "
                        "cosigned only this history of the log")


def _check_capabilities(records: List[Tuple[Any, Dict[str, Any]]], folder: Path, manifest: Dict[str, Any],
                        authority_key: bytes, principal_keys: Dict[str, bytes],
                        findings: List[str], problems: List[str]) -> None:
    """Replay each capability decision and check that every call that ran was allowed."""
    tokens = {f.stem: f.read_bytes() for f in (folder / manifest["tokens"]).glob("*.biscuit")}
    intents = {}
    for f in (folder / manifest["intents"]).glob("*.json"):
        env = delegation.IntentEnvelope.from_json(json.loads(f.read_text()))
        intents[env.cid] = env
    results = [(cid_str(r["parents"][0]), r["body"].get("outcome")) for _, r in records
               if r["kind"] == "tool.result" and r["parents"]]
    ran_calls = {c for c, outcome in results if outcome != "error"}
    governed = {cid_str(e.cid) for e, r in records if r["kind"] == "session.start"
                and r["body"].get("authorization") == delegation.POLICY}
    allowed_calls = set()
    spent: Dict[str, int] = {}
    counts = {"allow": 0, "deny": 0}
    before = len(problems)
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
                    f"({counts['allow']} allowed, {counts['deny']} refused) gives the recorded "
                    "answer when replayed from the token the agent presented and the signed "
                    "intent" + ("" if len(problems) == before else " (except as listed below)"))


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


def _check_policies(records: List[Tuple[Any, Dict[str, Any]]], folder: Path, principal_keys: Dict[str, bytes],
                    findings: List[str], problems: List[str]) -> None:
    """Replay each policy decision, check approvals, and check that calls that ran were
    allowed by the policy."""
    modules = {f.stem: f.read_bytes() for f in folder.glob("*.wasm")}
    data = {}
    for f in folder.glob("data-*.json"):
        doc = json.loads(f.read_text())
        data[policy.data_sha256(doc).hex()] = doc
    by_cid = {cid_str(e.cid): r for e, r in records}
    ran = {cid_str(r["parents"][0]) for _, r in records if r["kind"] == "tool.result"
           and r["parents"] and r["body"].get("outcome") != "error"}
    governed = {cid_str(e.cid) for e, r in records if r["kind"] == "session.start"
                and "policy_sha256" in r["body"]}
    allowed, counts, before, approvals, early = set(), {}, len(problems), 0, 0
    for e, rec in records:
        body = rec["body"]
        if rec["kind"] == "approval":
            approvals += 1
            problems += [f"record {e.index}: {p}" for p in _check_approval(rec, by_cid,
                                                                             principal_keys)]
            continue
        if rec["kind"] != "policy.decision" or body.get("policy") != policy.POLICY:
            continue
        recorded = body.get("decision")
        counts[recorded] = counts.get(recorded, 0) + 1
        if "input_json" not in body:                # refused before the policy ran
            early += 1
            if recorded != "deny":
                problems.append(f"record {e.index}: a decision without its input must be deny")
            continue
        wasm = modules.get(body["policy_sha256"].hex())
        doc = data.get(body["data_sha256"].hex())
        if wasm is None or doc is None:
            problems.append(f"record {e.index}: the policy module or its data is not in the "
                            "evidence")
            continue
        again, errs = policy.replay(wasm, doc, body.get("entrypoint", ""),
                                    json.loads(body["input_json"]))
        if errs:
            problems.append(f"record {e.index}: {errs[0]}")
        elif again["decision"] != recorded:
            problems.append(f"record {e.index}: the gateway recorded {recorded}, but the "
                            f"policy gives {again['decision']} on the recorded input")
        if recorded == "allow":
            allowed.add(cid_str(rec["parents"][0]) if rec["parents"] else "")
    for e, rec in records:
        call = cid_str(e.cid)
        if rec["kind"] == "tool.call" and rec["parents"] and \
                cid_str(rec["parents"][0]) in governed and call in ran and call not in allowed:
            problems.append(f"record {e.index}: the call ran without the policy's allow")
    n = sum(counts.values())
    tally = (f"{counts.get('allow', 0)} allowed, {counts.get('escalate', 0)} escalated, "
             f"{counts.get('deny', 0)} refused")
    findings.append((f"Each of the {n} policy decisions ({tally})" if not early else
                     f"Of the {n} policy decisions ({tally}), each of the {n - early} the "
                     "policy made")
                    + " gives the recorded answer when the same compiled policy runs again on "
                    "the recorded input"
                    + (f", and the {early} refusals made before the policy ran are deny, as "
                       "required" if early else "")
                    + f"; each of the {approvals} approvals is signed by its approver and "
                    "answers an escalation of the same call, and every call that ran had the "
                    "policy's allow"
                    + ("" if len(problems) == before else " (except as listed below)"))



def _check_books(records: List[Tuple[Any, Dict[str, Any]]], principal_keys: Dict[str, bytes], setup: Dict[str, Any],
                 findings: List[str], problems: List[str]) -> None:
    """Rebuild the books from the log and check their rules and numbering."""
    triples = [(e.index, cid_str(e.cid), r) for e, r in records]
    s, found = books.replay(triples, principal_keys, controllers=setup.get("controllers"),
                            accounts=setup.get("accounts"), service=setup.get("service"))
    problems += found
    currencies = {r["body"].get("currency") for _, _, r in triples if r["kind"] == "journal.entry"}
    cur = currencies.pop() if len(currencies) == 1 else ""
    docs, n = s["documents"], s["entries"]
    if not n:
        text = "The books hold no journal entries"
    else:
        series: Dict[str, List[str]] = {}
        for d in docs:                              # one series per entity and year
            series.setdefault(d.rsplit("/", 1)[0], []).append(d)
        ranges = [f"{ds[0]} to {ds[-1]}" if len(ds) > 1 else ds[0] for ds in series.values()]
        text = (f"The books hold {n} journal entr{'y' if n == 1 else 'ies'}, "
                + "; ".join(ranges) + (", numbered without gaps" if n > 1 else "")
                + ". Each one balances, is linked to the tool call that asked for it, uses "
                "accounts in the chart of accounts, and is dated in a period that was open "
                "when it was recorded")
        if s["reversals"]:
            text += (". One is a reversal that exactly undoes an earlier entry"
                     if s["reversals"] == 1 else
                     f". {s['reversals']} are reversals that exactly undo earlier entries")
    if s["refused"]:
        text += (f". The books refused {s['refused']} "
                 + ("entry, and the refusal is recorded" if s["refused"] == 1 else
                    "entries, and the refusals are recorded"))
    if s["signers"]:
        text += (". The period changes are signed by the controller"
                 + ("s " if len(s["signers"]) > 1 else " ") + ", ".join(s["signers"]))
    if n:
        text += (f". The trial balance rebuilt from the entries shows "
                 f"{delegation.money(s['debits'], cur)} of debits and "
                 f"{delegation.money(s['credits'], cur)} of credits")
    text += "" if not found else " (except as listed below)"
    findings.append(text)


def _check_approval(rec: Dict[str, Any], by_cid: Dict[str, Dict[str, Any]],
                    principal_keys: Dict[str, bytes]) -> List[str]:
    b = rec["body"]
    try:
        a = delegation.Approval(escalation=b["escalation"], approver=b["approver"],
                                decision=b["decision"], tool=b["tool"],
                                args_sha256=b["args_sha256"], time=b["time"],
                                signature=b["signature"])
    except KeyError:
        return ["the approval record is incomplete"]
    out = []
    if rec["agent"] != a.approver or not a.verify(principal_keys.get(a.approver, b"")):
        out.append(f"the approval is not signed by {a.approver}")
    esc = by_cid.get(a.escalation)
    if esc is None or esc["body"].get("decision") != "escalate" or esc.get("subject") != a.tool:
        out.append("the approval does not answer an escalation in this log")
    else:
        call = by_cid.get(cid_str(esc["parents"][0])) if esc["parents"] else None
        if call is None or call["body"].get("args_sha256") != a.args_sha256:
            out.append("the approval is for a different call from the one escalated")
    return out
