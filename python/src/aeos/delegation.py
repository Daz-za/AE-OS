"""Delegated authority: a person's signed intent and a capability token that can only narrow.

An agent holds no authority of its own. A person signs an intent envelope that says what
an agent may do on their behalf: which tools, up to what amount per action and in
total, until when. An authorization service checks that signature and mints a Biscuit
capability token bound to the envelope's CID:

    intent("<envelope CID>"); principal("<person's SPIFFE ID>");
    check if subject($s), $s == "<agent>" || $s.starts_with("<agent>/");
    check if tool($t), {"erp.invoice.get", ...}.contains($t);
    check if amount($a), $a <= <per-action ceiling>;
    check if time($t), $t <= <expiry>;

Biscuit tokens are public-key signed chains of Datalog blocks. Any holder can append a
block of further checks offline, for example to hand a narrower token to a sub-agent
(an agent whose SPIFFE ID extends its parent's path), and nobody can remove a block.
An appended block can only take authority away, because every check in every block must
pass.

The gateway authorizes each tool call by supplying facts it knows itself: the SPIFFE ID
from the mutual TLS connection, the tool, the call's amount and the current time. It
meters the envelope's total budget, which a token cannot express.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from biscuit_auth import (Algorithm, AuthorizationError, AuthorizerBuilder, Biscuit, BiscuitBuilder,
                          BlockBuilder, KeyPair, PrivateKey, PublicKey, Rule)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import keys
from .canon import cid_of_bytes, cid_str, dag_cbor
from .log import b64, unb64

POLICY = "aeos-capability/v0"
ENVELOPE_CONTEXT = b"aeos/intent-envelope/v0\n"
AMOUNT_ARGUMENT = "amount_minor"


class DelegationError(Exception):
    """A token or envelope that cannot be used; the reason is in the message."""


def _ms(t: dt.datetime) -> int:
    return int(t.timestamp() * 1000)


def _dt(ms: int) -> dt.datetime:
    return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc)


@dataclass
class IntentEnvelope:
    """What a person authorizes an agent to do, signed with the person's key."""

    principal: str            # the person's SPIFFE ID
    audience: str             # the agent's SPIFFE ID
    purpose: str
    actions: List[str]
    per_action_max_minor: int
    budget_minor: int
    currency: str
    not_after: int            # ms since the epoch
    signature: bytes = field(default=b"", repr=False)

    def fields(self) -> Dict[str, Any]:
        return {"principal": self.principal, "audience": self.audience,
                "purpose": self.purpose, "actions": sorted(self.actions),
                "per_action_max_minor": self.per_action_max_minor,
                "budget_minor": self.budget_minor, "currency": self.currency,
                "not_after": self.not_after}

    def encoded(self) -> bytes:
        return dag_cbor(self.fields())

    @property
    def cid(self) -> str:
        return cid_str(cid_of_bytes(self.encoded()))

    def sign(self, key: Ed25519PrivateKey) -> "IntentEnvelope":
        self.signature = key.sign(ENVELOPE_CONTEXT + self.encoded())
        return self

    def verify(self, public_key: bytes) -> bool:
        return keys.verify(public_key, self.signature, ENVELOPE_CONTEXT + self.encoded())

    def to_json(self) -> Dict[str, Any]:
        return {"cid": self.cid, "envelope": self.fields(), "signature": b64(self.signature)}

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "IntentEnvelope":
        return cls(**d["envelope"], signature=unb64(d["signature"]))


APPROVAL_CONTEXT = b"aeos/approval/v0\n"


@dataclass
class Approval:
    """A person's signed answer to an escalated call, bound to that exact call.

    `escalation` is the CID of the policy decision that escalated the call; `tool` and
    `args_sha256` repeat what was asked, so the approval cannot be used for anything else.
    """

    escalation: str
    approver: str             # the person's SPIFFE ID
    decision: str             # "approve" or "reject"
    tool: str
    args_sha256: bytes
    time: int                 # ms since the epoch
    signature: bytes = field(default=b"", repr=False)

    def fields(self) -> Dict[str, Any]:
        return {"escalation": self.escalation, "approver": self.approver,
                "decision": self.decision, "tool": self.tool,
                "args_sha256": self.args_sha256, "time": self.time}

    def message(self) -> bytes:
        return APPROVAL_CONTEXT + dag_cbor(self.fields())

    def sign(self, key: Ed25519PrivateKey) -> "Approval":
        self.signature = key.sign(self.message())
        return self

    def verify(self, public_key: bytes) -> bool:
        return keys.verify(public_key, self.signature, self.message())

    def to_json(self) -> Dict[str, Any]:
        return {**self.fields(), "args_sha256": self.args_sha256.hex(),
                "signature": b64(self.signature)}

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "Approval":
        return cls(escalation=d["escalation"], approver=d["approver"], decision=d["decision"],
                   tool=d["tool"], args_sha256=bytes.fromhex(d["args_sha256"]),
                   time=int(d["time"]), signature=unb64(d["signature"]))


class Authority:
    """The authorization service that mints capability tokens (Biscuit root key)."""

    def __init__(self, private_key: Optional[bytes] = None) -> None:
        self.keypair = KeyPair.from_private_key(
            PrivateKey.from_bytes(private_key, Algorithm.Ed25519)) if private_key else KeyPair()

    @property
    def public_key(self) -> bytes:
        return bytes(self.keypair.public_key.to_bytes())

    def private_bytes(self) -> bytes:
        return bytes(self.keypair.private_key.to_bytes())

    def mint(self, envelope: IntentEnvelope, principal_key: bytes) -> Biscuit:
        """A token for the envelope's audience, after checking the person's signature."""
        if not envelope.verify(principal_key):
            raise DelegationError("the intent envelope's signature does not verify against "
                                  f"the key of {envelope.principal}")
        return BiscuitBuilder(
            "intent({intent}); principal({principal});"
            "check if subject($s), $s == {subject} || $s.starts_with({prefix});"
            "check if tool($t), {actions}.contains($t);"
            "check if amount($a), $a <= {max};"
            "check if time($t), $t <= {not_after};",
            {"intent": envelope.cid, "principal": envelope.principal,
             "subject": envelope.audience, "prefix": envelope.audience + "/",
             "actions": set(envelope.actions),
             "max": envelope.per_action_max_minor,
             "not_after": _dt(envelope.not_after)}).build(self.keypair.private_key)


def attenuate(token: Biscuit, *, subject: Optional[str] = None,
              actions: Optional[Iterable[str]] = None, max_minor: Optional[int] = None,
              not_after: Optional[int] = None) -> Biscuit:
    """Append a block of further checks; the result allows at most what `token` allows."""
    checks, params = [], {}
    if subject is not None:
        checks.append("check if subject({subject});")
        params["subject"] = subject
    if actions is not None:
        checks.append("check if tool($t), {actions}.contains($t);")
        params["actions"] = set(actions)
    if max_minor is not None:
        checks.append("check if amount($a), $a <= {max};")
        params["max"] = max_minor
    if not_after is not None:
        checks.append("check if time($t), $t <= {not_after};")
        params["not_after"] = _dt(not_after)
    return token.append(BlockBuilder("".join(checks), params))


def token_sha256(token_bytes: bytes) -> bytes:
    return hashlib.sha256(token_bytes).digest()


_PLAIN = (("check if subject", "the token was issued to a different agent"),
          ("check if tool", "the token does not cover this tool"),
          ("check if amount", "the amount is above the token's limit"),
          ("check if time", "the token has expired"))


def _plain(err: AuthorizationError) -> List[str]:
    text = str(err)
    failed = re.findall(r"Check n°\d+ in block n°(\d+): (check if \w+)", text)
    issued, added = [], []
    for block, check in failed:
        for prefix, plain in _PLAIN:
            if check.startswith(prefix):
                (issued if block == "0" else added).append(plain)
    if len(added) > 1:
        added = [", and ".join(added) + " (both are checks a holder added)"
                 if len(added) == 2 else "; ".join(added) + " (checks a holder added)"]
    elif added:
        added = [added[0] + " (a check a holder added)"]
    return issued + added or [text]


def money(minor: int, currency: str) -> str:
    """An amount in minor units as text, for two-decimal currencies such as USD."""
    return f"{currency} {minor / 100:,.2f}"


@dataclass
class Decision:
    allowed: bool
    reasons: List[str]
    intent: Optional[str]
    principal: Optional[str]
    facts: Dict[str, Any]


def authorize(token_bytes: bytes, authority_key: bytes, *, subject: str, tool: str,
              amount: int, at: int) -> Decision:
    """Check one tool call against a token. `at` is the call's time in ms."""
    facts = {"subject": subject, "tool": tool, "amount": amount, "time": at}
    try:
        token = Biscuit.from_bytes(token_bytes,
                                   PublicKey.from_bytes(authority_key, Algorithm.Ed25519))
    except Exception:
        return Decision(False, ["the token is not signed by the trusted authority or is "
                                "damaged"], None, None, facts)
    az = AuthorizerBuilder(
        "subject({subject}); tool({tool}); amount({amount}); time({time});"
        "allow if intent($i);",
        # Biscuit times are whole seconds; rounding up never lets a token outlive its expiry.
        {"subject": subject, "tool": tool, "amount": amount,
         "time": _dt(-(-at // 1000) * 1000)}).build(token)
    intent = [f.terms[0] for f in az.query(Rule("q($i) <- intent($i)"))]
    principal = [f.terms[0] for f in az.query(Rule("q($p) <- principal($p)"))]
    try:
        az.authorize()
        return Decision(True, [], intent[0] if intent else None,
                        principal[0] if principal else None, facts)
    except AuthorizationError as e:
        return Decision(False, _plain(e), intent[0] if intent else None,
                        principal[0] if principal else None, facts)


class Budget:
    """Spending against each intent envelope's total budget, metered by the gateway.

    The gateway reserves a call's amount when it allows the call and releases it if the
    call does not run. Reserving under a lock stops simultaneous calls from overspending
    together. The budget lives in one gateway's memory: a restart resets it.
    """

    def __init__(self) -> None:
        self.spent: Dict[str, int] = {}
        self._lock = threading.Lock()

    def reserve(self, envelope: IntentEnvelope, amount: int) -> Optional[str]:
        """Reserve `amount`, or return why the budget does not allow it."""
        with self._lock:
            spent = self.spent.get(envelope.cid, 0)
            if spent + amount > envelope.budget_minor:
                return ("this payment would bring spending under the intent to "
                        f"{money(spent + amount, envelope.currency)}, above its budget of "
                        f"{money(envelope.budget_minor, envelope.currency)}")
            self.spent[envelope.cid] = spent + amount
            return None

    def release(self, envelope: IntentEnvelope, amount: int) -> None:
        with self._lock:
            self.spent[envelope.cid] = self.spent.get(envelope.cid, 0) - amount


def call_amount(arguments: Dict[str, Any]) -> int:
    """The amount a call moves, in minor units; 0 for calls that move no money, and -1
    when the amount is not a whole, non-negative number."""
    v = arguments.get(AMOUNT_ARGUMENT, 0)
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else -1


def parse_token(text: str) -> Optional[bytes]:
    """Token bytes from the base64url text an agent sends, or None if it is not base64url."""
    t = text.strip()
    try:
        return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
    except ValueError:
        return None
