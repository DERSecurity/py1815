"""A throwaway certificate authority, and certificates it signs, for TLS tests.

Made fresh in a temporary directory for each test that asks, so no key is
ever committed. Every certificate is valid for a day.
"""

from __future__ import annotations

import datetime
import ipaddress
import pathlib
import ssl
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _name(common: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


def _pem(key: ec.EllipticCurvePrivateKey, password: bytes | None) -> bytes:
    encryption = (
        serialization.NoEncryption()
        if password is None
        else serialization.BestAvailableEncryption(password)
    )
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )


@dataclass(frozen=True)
class Issued:
    """A certificate and its key, as files."""

    certificate: pathlib.Path
    key: pathlib.Path


class Authority:
    """A certificate authority that signs certificates into a directory."""

    def __init__(self, directory: pathlib.Path, name: str = "py1815 test authority") -> None:
        self.directory = directory
        self._key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.UTC)
        self._certificate = (
            x509.CertificateBuilder()
            .subject_name(_name(name))
            .issuer_name(_name(name))
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()), critical=False
            )
            .sign(self._key, hashes.SHA256())
        )
        self.file = directory / f"{name.replace(' ', '-')}.pem"
        self.file.write_bytes(self._certificate.public_bytes(serialization.Encoding.PEM))

    def issue(
        self,
        common: str,
        *,
        dns: tuple[str, ...] = (),
        ip: tuple[str, ...] = (),
        password: bytes | None = None,
    ) -> Issued:
        """Sign a certificate for ``common``, with the names given, and write both files.

        The key is encrypted with ``password`` when one is given.
        """
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.UTC)
        names: list[x509.GeneralName] = [x509.DNSName(each) for each in dns]
        names += [x509.IPAddress(ipaddress.ip_address(each)) for each in ip]
        builder = (
            x509.CertificateBuilder()
            .subject_name(_name(common))
            .issuer_name(self._certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()),
                critical=False,
            )
        )
        if names:
            builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
        certificate = builder.sign(self._key, hashes.SHA256())
        issued = Issued(self.directory / f"{common}.pem", self.directory / f"{common}.key")
        issued.certificate.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        issued.key.write_bytes(_pem(key, password))
        return issued


def server_context(authority: Authority, issued: Issued) -> ssl.SSLContext:
    """A listener's context that requires a client certificate from ``authority``."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=str(authority.file))
    context.load_cert_chain(str(issued.certificate), str(issued.key))
    context.verify_mode = ssl.CERT_REQUIRED
    return context
