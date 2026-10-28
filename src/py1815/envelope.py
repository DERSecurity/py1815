"""The message envelope DNP3 traffic records are published in.

Each DNP3 application fragment, captured from the network or reported by one
end of the association, is published as a :class:`ProtocolMessage`: an
envelope that names the protocol, the device and the time, and carries the
fragment's description as a JSON payload. :mod:`py1815.traffic` builds those
payloads and envelopes from what the outstation and the master report, so an
application can publish their traffic beside captured traffic without
converting it. This module is the envelope alone. It knows nothing of DNP3
beyond the protocol's name, and nothing in the outstation or the master depends
on it.

The envelope is a published contract shared with consumers that also ingest
other protocols. It is copied here, not imported, so the library keeps no
runtime dependency (D1). Its serialized form is the contract, as
:meth:`ProtocolMessage.to_dict` emits it:

- ``version``, ``protocol``, ``direction``, ``timestamp``, ``client_id``,
  ``forwarder_id``, ``payload``, ``source``, ``hash`` and ``is_valid`` are
  always present.
- ``destination``, ``protocol_data`` and ``validation_error`` appear only
  when set. An optional field is left out, not written as null: a consumer
  matches on presence, and adding a field is a compatible change.
- ``timestamp`` is ISO 8601 with an offset. A trailing ``Z`` is rewritten to
  ``+00:00`` on construction.
- ``hash`` is a UUIDv3 over the protocol, the client id, the timestamp and the
  payload text, so a consumer can find a message published twice without
  asking the producer.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import importlib.metadata
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

#: The leading ``X.Y.Z`` of a version string, without a PEP 440 suffix.
_RELEASE = re.compile(r"\d+\.\d+\.\d+")

#: The value consumers accept when no release version is known: the version
#: of the original wire format.
WIRE_FORMAT_VERSION = "2.0"


def wire_version() -> str:
    """Return the value for the envelope's ``version`` field.

    Consumers accept a bare semantic version or ``"2.0"`` and reject anything
    else, so the installed version is not passed through as it is. A
    development build carries a suffix such as ``0.4.0.dev1``, and a source
    tree that was never installed has no version. The release segment is used
    when there is one, and ``"2.0"`` otherwise.
    """
    try:
        installed = importlib.metadata.version("py1815")
    except importlib.metadata.PackageNotFoundError:
        return WIRE_FORMAT_VERSION
    release = _RELEASE.match(installed)
    return release.group(0) if release else WIRE_FORMAT_VERSION


_VERSION = wire_version()


class WireDirection(StrEnum):
    """Which way the message travelled, as the envelope carries it.

    ``UPSTREAM`` is from the device toward a server, ``DOWNSTREAM`` the other
    way.
    """

    UPSTREAM = "upstream"
    DOWNSTREAM = "downstream"


class Protocol(StrEnum):
    """The application protocol a message was captured from."""

    DNP3 = "dnp3"

    @classmethod
    def from_string(cls, value: str) -> Protocol:
        """Return the protocol named by a wire value, ignoring case.

        Raises:
            ValueError: If the value names no protocol this module knows.
        """
        normalized = value.lower().strip()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(f"unknown protocol: {value}")


@dataclass
class PayloadEnvelope:
    """A payload, with the content type and encoding a consumer reads it by."""

    JSON = "application/json"

    content_type: str
    data: str
    encoding: str = "utf-8"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PayloadEnvelope:
        """Wrap a dictionary as a JSON payload."""
        return cls(content_type=cls.JSON, data=json.dumps(data), encoding="utf-8")

    def to_dict(self) -> dict[str, Any] | None:
        """Return a JSON payload as a dictionary, or None when it is not one."""
        if self.content_type == self.JSON:
            result = json.loads(self.data)
            if isinstance(result, dict):
                return result
        return None

    def serialize(self) -> dict[str, str]:
        """Return the payload as the envelope carries it."""
        return {"content_type": self.content_type, "data": self.data, "encoding": self.encoding}

    @classmethod
    def deserialize(cls, data: dict[str, str]) -> PayloadEnvelope:
        """Rebuild a payload from :meth:`serialize`."""
        return cls(
            content_type=data["content_type"],
            data=data["data"],
            encoding=data.get("encoding", "utf-8"),
        )


#: Six hex pairs, colon- or hyphen-separated.
_MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


@dataclass
class NetworkEndpoint:
    """One end of the connection a message was seen on.

    ``mac`` is part of the format. A producer that sees frames sets it; this
    library sees connections, and leaves it unset.
    """

    ip: str
    port: int
    mac: str | None = None

    def __post_init__(self) -> None:
        """Accept a port given as a string, and write a MAC in one spelling.

        Raises:
            ValueError: If ``mac`` is set and is not six hex pairs.
        """
        if isinstance(self.port, str):
            self.port = int(self.port)
        if self.mac is not None:
            if not isinstance(self.mac, str) or not _MAC.match(self.mac):
                raise ValueError(
                    f"mac must be six hex pairs separated by ':' or '-', got {self.mac!r}"
                )
            self.mac = self.mac.lower().replace("-", ":")

    def to_dict(self) -> dict[str, Any]:
        """Return the endpoint as the envelope carries it, without an unset ``mac``."""
        result: dict[str, Any] = {"ip": self.ip, "port": self.port}
        if self.mac is not None:
            result["mac"] = self.mac
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NetworkEndpoint:
        """Rebuild an endpoint from :meth:`to_dict`."""
        return cls(ip=data["ip"], port=data["port"], mac=data.get("mac"))


@dataclass
class ProtocolMetadata:
    """Detail about a message beyond its payload.

    The format names many fields for other protocols. None of them applies to
    DNP3, so this class models only ``extra``, the format's free-form
    dictionary, and keeps any other key it reads in ``passthrough``, so that a
    message read and written again keeps its shape.
    """

    extra: dict[str, Any] = field(default_factory=dict)
    passthrough: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return the metadata as the envelope carries it, without empty fields."""
        result: dict[str, Any] = dict(self.passthrough)
        if self.extra:
            result["extra"] = self.extra
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProtocolMetadata:
        """Rebuild metadata from :meth:`to_dict`.

        Raises:
            TypeError: If ``extra`` is present and is not a mapping.
        """
        extra = data.get("extra")
        if extra is not None and not isinstance(extra, dict):
            raise TypeError(f"protocol_data 'extra' must be a mapping, got {type(extra).__name__}")
        passthrough = {key: value for key, value in data.items() if key != "extra"}
        return cls(extra=dict(extra or {}), passthrough=passthrough)


@dataclass
class ProtocolMessage:
    """One captured protocol message, ready to publish.

    ``payload`` may be given as a dictionary, which is stored as a JSON
    payload. The hash is computed on construction unless one is given.
    """

    protocol: Protocol
    direction: WireDirection
    client_id: str
    payload: PayloadEnvelope | dict[str, Any]
    source: NetworkEndpoint
    destination: NetworkEndpoint | None = None
    #: Names the system that produced or relayed the message, so a consumer
    #: that collects from several can tell them apart.
    forwarder_id: str = ""
    protocol_data: ProtocolMetadata = field(default_factory=ProtocolMetadata)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    hash: str = ""
    is_valid: bool = True
    validation_error: str | None = None

    def __post_init__(self) -> None:
        """Normalize the fields given as plain values, check them, and compute the hash.

        Raises:
            ValueError: If ``client_id`` is empty or ``timestamp`` is not ISO
                8601.
        """
        if isinstance(self.protocol, str):
            self.protocol = Protocol.from_string(self.protocol)
        if isinstance(self.direction, str):
            self.direction = WireDirection(self.direction)
        if isinstance(self.payload, dict):
            self.payload = PayloadEnvelope.from_dict(self.payload)
        if self.timestamp.endswith("Z"):
            self.timestamp = self.timestamp[:-1] + "+00:00"
        try:
            datetime.fromisoformat(self.timestamp)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"timestamp must be ISO 8601, such as '2026-01-15T12:00:00+00:00': {exc}"
            ) from exc
        if not self.client_id or not self.client_id.strip():
            raise ValueError("client_id must be a non-empty string")
        self.forwarder_id = self.forwarder_id.strip()
        if not self.hash:
            self.hash = self._generate_hash()

    @property
    def body(self) -> dict[str, Any] | None:
        """Return the payload as a dictionary, or None when it is not JSON."""
        assert isinstance(self.payload, PayloadEnvelope)
        return self.payload.to_dict()

    def _generate_hash(self) -> str:
        """Return the deduplication key: a UUIDv3 over the identifying fields."""
        assert isinstance(self.payload, PayloadEnvelope)
        unique = f"{self.protocol.value}:{self.client_id}:{self.timestamp}:{self.payload.data}"
        return str(uuid.uuid3(uuid.NAMESPACE_DNS, unique))

    def to_dict(self) -> dict[str, Any]:
        """Return the message in its serialized form. The module docstring states the contract."""
        assert isinstance(self.payload, PayloadEnvelope)
        result: dict[str, Any] = {
            "version": _VERSION,
            "protocol": self.protocol.value,
            "direction": self.direction.value,
            "timestamp": self.timestamp,
            "client_id": self.client_id,
            "forwarder_id": self.forwarder_id,
            "payload": self.payload.serialize(),
            "source": self.source.to_dict(),
            "hash": self.hash,
            "is_valid": self.is_valid,
        }
        if self.destination is not None:
            result["destination"] = self.destination.to_dict()
        protocol_data = self.protocol_data.to_dict()
        if protocol_data:
            result["protocol_data"] = protocol_data
        if self.validation_error:
            result["validation_error"] = self.validation_error
        return result

    def to_json(self) -> str:
        """Return the serialized form as a JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProtocolMessage:
        """Rebuild a message from its serialized form.

        ``hash`` is taken as given and not computed again: it is the
        producer's key.

        Raises:
            KeyError: If a field the contract always carries is missing.
        """
        payload = data["payload"]
        if isinstance(payload, dict) and {"content_type", "data"} <= payload.keys():
            payload = PayloadEnvelope.deserialize(payload)
        destination = data.get("destination")
        protocol_data = data.get("protocol_data")
        return cls(
            protocol=Protocol.from_string(data["protocol"]),
            direction=WireDirection(data["direction"]),
            client_id=data["client_id"],
            payload=payload,
            source=NetworkEndpoint.from_dict(data["source"]),
            destination=NetworkEndpoint.from_dict(destination) if destination else None,
            forwarder_id=data.get("forwarder_id", ""),
            protocol_data=(
                ProtocolMetadata.from_dict(protocol_data) if protocol_data else ProtocolMetadata()
            ),
            timestamp=data["timestamp"],
            hash=data.get("hash", ""),
            is_valid=data.get("is_valid", True),
            validation_error=data.get("validation_error"),
        )

    @classmethod
    def from_json(cls, raw: str | bytes) -> ProtocolMessage:
        """Rebuild a message from :meth:`to_json`."""
        return cls.from_dict(json.loads(raw))


__all__ = [
    "WIRE_FORMAT_VERSION",
    "NetworkEndpoint",
    "PayloadEnvelope",
    "Protocol",
    "ProtocolMessage",
    "ProtocolMetadata",
    "WireDirection",
    "wire_version",
]
