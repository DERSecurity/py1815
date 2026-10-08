"""TLS for a master: the client context, made from files.

An outstation that listens with TLS usually checks the master's certificate
against an allow-list, as this library's listener does (D8), so a master
needs a certificate and its key as well as the authority that signed the
outstation's. :class:`TlsSettings` names the files
and makes the context. The key's password, when it has one, is a secret and
is never one of the settings: it is read from ``PY1815_MASTER_KEY_PASSWORD``.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import os
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, fields
from typing import Any

#: Where the password of an encrypted key is read from.
PASSWORD_VARIABLE = "PY1815_MASTER_KEY_PASSWORD"


@dataclass(frozen=True)
class TlsSettings:
    """The files of a master's TLS connection, and the name it checks.

    Every field is optional. With none given the outstation is checked
    against the system's own authorities and the master offers no
    certificate, which an outstation that requires one refuses.
    """

    #: A file of the authorities the outstation's certificate is checked
    #: against, in PEM. The system's own when None.
    ca: str | None = None
    #: The master's certificate, in PEM, with its chain if it has one.
    certificate: str | None = None
    #: The master's private key, in PEM. None when it is in ``certificate``.
    key: str | None = None
    #: The name the outstation's certificate is checked against, when it is
    #: not the host connected to.
    server_name: str | None = None

    def __post_init__(self) -> None:
        for each in fields(self):
            value = getattr(self, each.name)
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError(f"tls.{each.name} is a path or a name, as text")
        if self.key is not None and self.certificate is None:
            raise ValueError("tls.key is the key of tls.certificate; give the certificate")

    @classmethod
    def from_mapping(cls, given: Mapping[str, Any]) -> TlsSettings:
        """Return the settings named in ``given``. Raises ``ValueError`` for others."""
        known = [each.name for each in fields(cls)]
        unknown = sorted(set(given) - set(known))
        if unknown:
            raise ValueError(f"tls.{unknown[0]} is not a setting; one of {', '.join(known)}")
        return cls(**dict(given))

    def context(self) -> ssl.SSLContext:
        """Return a client context that checks the outstation and offers the certificate.

        Raises ``OSError`` for a file that cannot be read and ``ssl.SSLError``
        for one that is not what it should be.
        """
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.ca)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if self.certificate is not None:
            context.load_cert_chain(
                self.certificate, self.key, password=os.environ.get(PASSWORD_VARIABLE) or None
            )
        return context

    def describe(self) -> dict[str, Any]:
        """Return the settings as a JSON-compatible dict. It holds no secret."""
        return {each.name: getattr(self, each.name) for each in fields(self)}


__all__ = ["PASSWORD_VARIABLE", "TlsSettings"]
