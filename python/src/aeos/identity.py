"""SPIFFE workload identity: a local trust domain, X.509-SVIDs and mutual TLS.

A SPIFFE ID names a workload, for example spiffe://acme.example/agent/accounts-payable.
An X.509-SVID is a short-lived certificate that carries exactly one SPIFFE ID as a URI
SAN; the workload proves the ID by holding the certificate's private key. In production
SPIRE issues SVIDs after attesting the node and the workload. Here a local TrustDomain
plays SPIRE's part (without attestation), so the demo and tests can show the rest for
real: certificate chains, 15-minute lifetimes, rotation, and mTLS in which each side
learns the other's verified SPIFFE ID.

Follows the X.509-SVID standard (github.com/spiffe/spiffe, standards/X509-SVID.md):
ECDSA P-256 leaf keys, CA=false, digitalSignature, client and server auth, one URI SAN.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SVID_TTL = dt.timedelta(minutes=15)


class IdentityError(ValueError):
    """An SVID or peer identity that must not be trusted."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_spiffe_id(uri: str) -> Tuple[str, str]:
    """Split a SPIFFE ID into (trust domain, path), checking its form."""
    u = urlparse(uri)
    if u.scheme != "spiffe" or not u.netloc or u.query or u.fragment or u.port or "@" in uri:
        raise IdentityError(f"not a SPIFFE ID: {uri}")
    if u.netloc != u.netloc.lower() or not u.path.startswith("/") or u.path.endswith("/"):
        raise IdentityError(f"not a SPIFFE ID: {uri}")
    return u.netloc, u.path


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def fingerprint(cert: x509.Certificate) -> str:
    """SHA-256 of the certificate's DER bytes, as recorded in session records."""
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


@dataclass
class SVID:
    spiffe_id: str
    chain: List[x509.Certificate]           # leaf first, then the intermediate
    key: ec.EllipticCurvePrivateKey

    @property
    def leaf(self) -> x509.Certificate:
        return self.chain[0]

    def chain_pem(self) -> bytes:
        return b"".join(pem(c) for c in self.chain)

    def key_pem(self) -> bytes:
        return self.key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())

    def write(self, folder: Path, name: str) -> Tuple[Path, Path]:
        """Write chain and key files (key readable by the owner only)."""
        folder.mkdir(parents=True, exist_ok=True)
        cert_path, key_path = folder / f"{name}.pem", folder / f"{name}.key"
        cert_path.write_bytes(self.chain_pem())
        key_path.write_bytes(self.key_pem())
        key_path.chmod(0o600)
        return cert_path, key_path


class TrustDomain:
    """A root CA (ECDSA P-384) and an intermediate (P-256) that issues SVIDs."""

    def __init__(self, name: str) -> None:
        if parse_spiffe_id(f"spiffe://{name}/x")[0] != name:
            raise IdentityError(f"invalid trust domain name: {name}")
        self.name = name
        now = _now()
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.root = self._ca(_name(f"{name} root CA"), self.root_key, self.root_key,
                             _name(f"{name} root CA"), now, dt.timedelta(days=365), 1)
        self.int_key = ec.generate_private_key(ec.SECP256R1())
        self.intermediate = self._ca(_name(f"{name} intermediate CA"), self.int_key,
                                     self.root_key, self.root.subject, now,
                                     dt.timedelta(days=1), 0)

    def save(self, folder: Path) -> None:
        """Keep the CA keys and certificates (keys readable by the owner only)."""
        folder.mkdir(parents=True, exist_ok=True)
        for name, cert, key in (("root", self.root, self.root_key),
                                ("intermediate", self.intermediate, self.int_key)):
            (folder / f"{name}.pem").write_bytes(pem(cert))
            path = folder / f"{name}.key"
            path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
            path.chmod(0o600)

    @classmethod
    def load(cls, name: str, folder: Path) -> "TrustDomain":
        """A trust domain saved earlier (see `refresh`)."""
        td = cls.__new__(cls)
        td.name = name
        td.root = x509.load_pem_x509_certificate((folder / "root.pem").read_bytes())
        td.root_key = serialization.load_pem_private_key((folder / "root.key").read_bytes(), None)
        td.intermediate = x509.load_pem_x509_certificate(
            (folder / "intermediate.pem").read_bytes())
        td.int_key = serialization.load_pem_private_key(
            (folder / "intermediate.key").read_bytes(), None)
        td.refresh(folder)
        return td

    def refresh(self, folder: Path) -> bool:
        """Replace an intermediate CA that expires within the hour, and save it."""
        now = _now()
        if self.intermediate.not_valid_after_utc - now >= dt.timedelta(hours=1):
            return False
        self.int_key = ec.generate_private_key(ec.SECP256R1())
        self.intermediate = self._ca(_name(f"{self.name} intermediate CA"), self.int_key,
                                     self.root_key, self.root.subject, now,
                                     dt.timedelta(days=1), 0)
        self.save(folder)
        return True

    def _ca(self, subject: x509.Name, key, signer, issuer: x509.Name, now: dt.datetime,
            life: dt.timedelta, path_len: int) -> x509.Certificate:
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + life)
                .add_extension(x509.BasicConstraints(ca=True, path_length=path_len), True)
                .add_extension(x509.KeyUsage(False, False, False, False, False, True, True,
                                             False, False), True)
                .add_extension(x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(f"spiffe://{self.name}")]), False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    signer.public_key()), False)
                .sign(signer, hashes.SHA384() if signer is self.root_key else hashes.SHA256()))

    def bundle_pem(self) -> bytes:
        """The trust bundle: what a relying party needs to check this domain's SVIDs."""
        return pem(self.root)

    def issue(self, spiffe_id: str, *, ttl: dt.timedelta = SVID_TTL,
              not_before: Optional[dt.datetime] = None) -> SVID:
        domain, _ = parse_spiffe_id(spiffe_id)
        if domain != self.name:
            raise IdentityError(f"{spiffe_id} is outside trust domain {self.name}")
        start = not_before or _now()
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = (x509.CertificateBuilder().subject_name(_name(spiffe_id.rsplit("/", 1)[-1]))
                .issuer_name(self.intermediate.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(start).not_valid_after(start + ttl)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.KeyUsage(True, False, True, False, True, False, False,
                                             False, False), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,
                                                      ExtendedKeyUsageOID.CLIENT_AUTH]), False)
                .add_extension(x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(spiffe_id)]), True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.int_key.public_key()), False)
                .sign(self.int_key, hashes.SHA256()))
        return SVID(spiffe_id, [leaf, self.intermediate], key)


def load_chain(data: bytes) -> List[x509.Certificate]:
    return x509.load_pem_x509_certificates(data)


def spiffe_id_of(cert: x509.Certificate) -> str:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        raise IdentityError("certificate has no SPIFFE ID") from None
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1:
        raise IdentityError("an SVID carries exactly one SPIFFE ID")
    parse_spiffe_id(uris[0])
    return uris[0]


def _valid_at(cert: x509.Certificate, at: dt.datetime) -> bool:
    return cert.not_valid_before_utc <= at <= cert.not_valid_after_utc


def verify_svid(chain: Sequence[x509.Certificate], bundle: Sequence[x509.Certificate], *,
                at: Optional[dt.datetime] = None, trust_domain: Optional[str] = None) -> str:
    """Check an X.509-SVID chain against a trust bundle at a moment; return its SPIFFE ID.

    Raises IdentityError with a plain reason when the SVID must not be trusted.
    """
    at = at or _now()
    if not chain:
        raise IdentityError("no certificate given")
    leaf = chain[0]
    sid = spiffe_id_of(leaf)
    domain, _ = parse_spiffe_id(sid)
    if trust_domain and domain != trust_domain:
        raise IdentityError(f"{sid} belongs to trust domain {domain}, not {trust_domain}")
    bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    if bc.ca:
        raise IdentityError("an SVID leaf must not be a CA certificate")
    path = list(chain)
    for cert, issuer in zip(path, path[1:]):
        try:
            cert.verify_directly_issued_by(issuer)
        except (ValueError, TypeError, InvalidSignature):
            raise IdentityError("certificate chain is broken") from None
        if not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise IdentityError("certificate chain is broken")
    top = path[-1]
    anchors = [r for r in bundle if r.subject == top.issuer or r == top]
    ok = False
    for root in anchors:
        try:
            if root != top:
                top.verify_directly_issued_by(root)
            ok = _valid_at(root, at)
        except (ValueError, TypeError, InvalidSignature):
            continue
        if ok:
            break
    if not ok:
        raise IdentityError(f"{sid} was not issued by a trusted authority")
    for cert in path:
        if not _valid_at(cert, at):
            when = at.strftime("%Y-%m-%d %H:%M:%S UTC")
            raise IdentityError(f"the SVID for {sid} was not valid at {when} (valid "
                                f"{leaf.not_valid_before_utc:%H:%M:%S} to "
                                f"{leaf.not_valid_after_utc:%H:%M:%S} UTC)")
    return sid


# ---- mutual TLS ------------------------------------------------------------------------

def _context(purpose: ssl.Purpose, svid_files: Tuple[Path, Path], bundle_file: Path
             ) -> ssl.SSLContext:
    ctx = ssl.create_default_context(purpose, cafile=str(bundle_file))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False            # SPIFFE authenticates by SPIFFE ID, not host name
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(str(svid_files[0]), str(svid_files[1]))
    return ctx


def server_context(svid_files: Tuple[Path, Path], bundle_file: Path) -> ssl.SSLContext:
    """TLS server that requires a client SVID from the trust bundle."""
    return _context(ssl.Purpose.CLIENT_AUTH, svid_files, bundle_file)


def client_context(svid_files: Tuple[Path, Path], bundle_file: Path) -> ssl.SSLContext:
    """TLS client that presents its SVID and requires the server's."""
    return _context(ssl.Purpose.SERVER_AUTH, svid_files, bundle_file)


def peer_identity(sock: ssl.SSLSocket, *, trust_domain: str,
                  expect: Optional[str] = None) -> Tuple[str, str]:
    """After the handshake, return the peer's (SPIFFE ID, certificate fingerprint).

    TLS has already checked the peer's chain against the trust bundle and its validity
    period; this reads the SPIFFE ID and checks it is in the expected trust domain.
    """
    der = sock.getpeercert(binary_form=True)
    if not der:
        raise IdentityError("the peer presented no certificate")
    leaf = x509.load_der_x509_certificate(der)
    sid = spiffe_id_of(leaf)
    domain, _ = parse_spiffe_id(sid)
    if domain != trust_domain:
        raise IdentityError(f"{sid} belongs to trust domain {domain}, not {trust_domain}")
    if expect and sid != expect:
        raise IdentityError(f"expected {expect}, but the peer is {sid}")
    return sid, fingerprint(leaf)
