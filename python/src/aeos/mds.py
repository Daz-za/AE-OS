"""Turn a FIDO Metadata Service (MDS3) BLOB into an authenticator trust file.

The FIDO Alliance publishes the metadata of certified authenticators as one signed JSON Web
Token, the MDS3 BLOB (https://mds3.fidoalliance.org/). `aeos authenticator-trust` reads a BLOB
the deployer has downloaded, checks its signature and its certificate chain against the FIDO
root certificate the deployer gives, and writes the `aeos-authenticator-trust/v1` file that
`aeos audit --authenticators` and a gateway's passkey directory use. Nothing here touches the
network; certificate revocation lists are not fetched.

An entry is kept when it names a FIDO2 model (`aaguid`) or a FIDO U2F one (attestation
certificate key identifiers) and has attestation root certificates, and none of its status
reports withdraws trust (a compromise, a user verification bypass, or a revocation). A kept
model is **device-bound** only when its key protection includes `secure_element` and not
`software` (`remote_handle`, which U2F keys list because they hand the relying party a
wrapped key, is allowed), and its latest status report is a FIDO certification
(`FIDO_CERTIFIED` or `FIDO_CERTIFIED_L1` and above). A key held only in a TPM or a phone's
trusted execution environment (`tee`) is never device-bound: those are platform
authenticators, not hardware security keys.

A BLOB whose next update date has passed is refused unless the deployer allows a stale one,
and the trust file records the BLOB's serial number (`mds_blob_no`) so that an import never
replaces a newer BLOB's file with an older one.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import utils

from . import attestation

WITHDRAWN = frozenset({"USER_VERIFICATION_BYPASS", "ATTESTATION_KEY_COMPROMISE",
                       "USER_KEY_REMOTE_COMPROMISE", "USER_KEY_PHYSICAL_COMPROMISE",
                       "REVOKED"})
CERTIFIED = frozenset({"FIDO_CERTIFIED", "FIDO_CERTIFIED_L1", "FIDO_CERTIFIED_L1plus",
                       "FIDO_CERTIFIED_L2", "FIDO_CERTIFIED_L2plus", "FIDO_CERTIFIED_L3",
                       "FIDO_CERTIFIED_L3plus"})
# JOSE algorithms the BLOB may be signed with, as the COSE numbers attestation.py checks
# the length of a JOSE ECDSA signature (r || s, each the curve's size) per COSE algorithm
_ECDSA_LEN = {-7: 64, -35: 96, -36: 132}
_JOSE = {"ES256": -7, "ES384": -35, "ES512": -36, "RS256": -257, "RS384": -258,
         "RS512": -259, "PS256": -37, "PS384": -38, "PS512": -39}


class MetadataError(ValueError):
    """A BLOB that cannot be trusted or read; the message says why."""


def _b64url(part: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except ValueError:
        raise MetadataError("the BLOB is not a JSON Web Token") from None


def load_root(data: bytes) -> x509.Certificate:
    """The FIDO root certificate, as PEM or DER."""
    try:
        if b"-----BEGIN" in data:
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)
    except ValueError:
        raise MetadataError("the root certificate is not PEM or DER X.509") from None


def verify_blob(blob: bytes, root: x509.Certificate, now_ms: int) -> Dict[str, Any]:
    """The payload of a BLOB whose signature verifies with a certificate that chains to
    `root` at `now_ms`; MetadataError otherwise."""
    parts = blob.strip().split(b".")
    if len(parts) != 3:
        raise MetadataError("the BLOB is not a JSON Web Token")
    try:
        header = json.loads(_b64url(parts[0].decode("ascii")))
        payload = json.loads(_b64url(parts[1].decode("ascii")))
    except (UnicodeDecodeError, ValueError):
        raise MetadataError("the BLOB's header or payload is not JSON") from None
    alg = _JOSE.get(str(header.get("alg"))) if isinstance(header, dict) else None
    x5c = header.get("x5c") if isinstance(header, dict) else None
    if alg is None or not isinstance(x5c, list) or not x5c:
        raise MetadataError("the BLOB's header names no supported algorithm or no x5c chain")
    try:
        chain = [base64.b64decode(c, validate=True) for c in x5c]
    except (ValueError, TypeError):
        raise MetadataError("the BLOB's x5c is not base64 DER") from None
    why = attestation.chain_problem(chain, [root], now_ms)
    if why:
        raise MetadataError(f"the BLOB's signing certificate does not stand: {why}")
    sig = _b64url(parts[2].decode("ascii"))
    if alg in _ECDSA_LEN:                     # JOSE carries r || s; convert to DER
        if len(sig) != _ECDSA_LEN[alg]:
            raise MetadataError(f"the BLOB's {header['alg']} signature is {len(sig)} bytes, "
                                f"not {_ECDSA_LEN[alg]}")
        n = len(sig) // 2
        sig = utils.encode_dss_signature(int.from_bytes(sig[:n], "big"),
                                         int.from_bytes(sig[n:], "big"))
    key = x509.load_der_x509_certificate(chain[0]).public_key()
    try:
        attestation._verify(key, alg, sig, parts[0] + b"." + parts[1])
    except attestation.AttestationError as e:
        raise MetadataError(f"the BLOB's signature does not verify: {e}") from None
    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
        raise MetadataError("the BLOB's payload has no entries")
    return payload


def _statuses(entry: Dict[str, Any]) -> List[str]:
    """The entry's status reports, oldest first (reports of one date keep their order)."""
    raw = entry.get("statusReports")
    reports = [r for r in raw if isinstance(r, dict)] if isinstance(raw, list) else []
    reports.sort(key=lambda r: str(r.get("effectiveDate", "")))
    return [str(r.get("status")) for r in reports]


def device_bound(protection: Any) -> bool:
    """Whether a metadata statement's keyProtection describes a hardware security key: a
    secure element, and no software key store. TPM and TEE keys (`hardware` with `tee`, as
    Windows Hello and phones list them) are not."""
    kinds = set(protection) if isinstance(protection, list) else set()
    return "secure_element" in kinds and "software" not in kinds


def trust_from_payload(payload: Dict[str, Any], source: str
                       ) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """The trust file for a verified payload, and counts of what was kept and left out."""
    out: List[Dict[str, Any]] = []
    counts = {"kept": 0, "device_bound": 0, "not_certified": 0, "withdrawn": 0, "unusable": 0}
    seen: set = set()
    for e in payload["entries"]:
        if not isinstance(e, dict):
            counts["unusable"] += 1
            continue
        statuses = _statuses(e)
        if WITHDRAWN & set(statuses):
            counts["withdrawn"] += 1
            continue
        raw = e.get("metadataStatement")
        st: Dict[str, Any] = raw if isinstance(raw, dict) else {}
        protected = device_bound(st.get("keyProtection"))
        certified = bool(statuses) and statuses[-1] in CERTIFIED
        aaguid = e.get("aaguid") or st.get("aaguid")
        ids = e.get("attestationCertificateKeyIdentifiers") or \
            st.get("attestationCertificateKeyIdentifiers") or []
        roots = st.get("attestationRootCertificates") or []
        entry: Dict[str, Any] = {"description": str(st.get("description", "")),
                                 "device_bound": protected and certified,
                                 "attestation_root_certificates": roots}
        if isinstance(aaguid, str) and aaguid.lower() != str(uuid.UUID(int=0)):
            entry["aaguid"] = aaguid.lower()
        if isinstance(ids, list) and ids:
            entry["attestation_certificate_key_identifiers"] = sorted(str(i).lower()
                                                                      for i in ids)
        keys = {entry.get("aaguid")} | set(entry.get("attestation_certificate_key_identifiers",
                                                     []))
        keys.discard(None)
        if not keys or not roots or keys & seen:
            counts["unusable"] += 1
            continue
        try:                                     # one bad entry never spoils the file
            attestation.AuthenticatorTrust.load(attestation.trust_doc([entry], source))
        except ValueError:
            counts["unusable"] += 1
            continue
        seen |= keys
        out.append(entry)
        counts["kept"] += 1
        counts["device_bound"] += entry["device_bound"]
        counts["not_certified"] += protected and not certified
    out.sort(key=lambda m: (m.get("aaguid") or "", m.get(
        "attestation_certificate_key_identifiers", [""])[0]))
    return attestation.trust_doc(out, source), counts


def import_blob(blob: bytes, root: bytes, now_ms: int, *, allow_stale: bool = False,
                previous: Any = None) -> Tuple[Dict[str, Any], Dict[str, int], Optional[str]]:
    """(trust file, counts, warning) for a downloaded BLOB and the FIDO root certificate.

    A BLOB whose next update date has passed, or that names none, is refused unless
    `allow_stale`, and then the warning says so. `previous` is the trust file the new one
    would replace, if any: a BLOB older than the one it was made from is refused."""
    payload = verify_blob(blob, load_root(root), now_ms)
    no = payload.get("no")
    if not isinstance(no, int) or isinstance(no, bool) or no < 0:
        raise MetadataError("the BLOB has no serial number (no)")
    before = previous.get("mds_blob_no") if isinstance(previous, dict) else None
    if isinstance(before, int) and not isinstance(before, bool) and no < before:
        raise MetadataError(f"the BLOB is no. {no}, older than no. {before}, which the trust "
                            "file you would replace was made from")
    when = payload.get("nextUpdate")
    stale = None
    try:
        due = dt.date.fromisoformat(str(when))
        today = dt.datetime.fromtimestamp(now_ms / 1000, tz=dt.timezone.utc).date()
        if due < today:
            stale = f"the BLOB's next update was due on {due}"
    except ValueError:
        stale = "the BLOB names no next update date"
    if stale and not allow_stale:
        raise MetadataError(f"{stale}; download a current one from https://mds3.fidoalliance.org/"
                            " (or allow a stale BLOB, if you must use this one)")
    source = (f"FIDO Metadata Service BLOB no. {no}, next update {when}, "
              f"sha256 {hashlib.sha256(blob.strip()).hexdigest()}")
    doc, counts = trust_from_payload(payload, source)
    doc["mds_blob_no"] = no
    return doc, counts, (stale + ", and you allowed it") if stale else None
