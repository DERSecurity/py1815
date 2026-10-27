"""Structured reports of connections, requests and protocol anomalies, for the host application.

The outstation and the master log what happens to their connections, and the
session logs a frame or a fragment it drops. A log line is for a person. A host
application that keeps a record of every connection attempt, that logs or
forwards the requests its outstation serves, or that passes protocol anomalies
to its own security monitoring, needs the same facts as fields. This module
defines those records and the type of the callable that receives each one.

- :class:`ConnectionEvent` is one thing that happened to a connection: accepted,
  refused, displaced or ended at the outstation's listener, and connected,
  failed or lost at the master. :class:`~py1815.server.OutstationServer` and
  :class:`~py1815.master.api.Outstation` take a ``connection_observer``.
- :class:`ProtocolAnomaly` is one frame, fragment or exchange the session
  dropped or gave up on, with a stable :class:`AnomalyCode` and a
  :class:`AnomalySeverity`. :class:`~py1815.session.Session` takes an
  ``anomaly_observer``.
- :class:`RequestRecord` is one request the outstation's session handled, with
  the response it sent back, or one unsolicited response it sent.
  :class:`~py1815.server.OutstationServer` and :class:`~py1815.session.Session`
  take a ``request_observer``.

Each record is a frozen dataclass of plain values, so it can be logged, queued
or converted to a dictionary with :func:`dataclasses.asdict`. The octets of a
:class:`RequestRecord` are ``bytes``; write them as hex, for example, before
converting the dictionary to JSON. The log lines are written as before; an
observer is an addition to them, not a replacement.

An observer is called on the event loop, or for a session on whatever thread
called it, and must return quickly. An observer that raises does not affect the
connection or the session: the first failure of an observer is logged with its
traceback, and later failures of the same observer are logged at DEBUG.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, TypeVar

logger = logging.getLogger(__name__)


class ConnectionRole(StrEnum):
    """Which end of the association reported a connection event."""

    #: The outstation's listener, which accepts connections.
    OUTSTATION = "outstation"
    #: The master, which makes connections.
    MASTER = "master"


class ConnectionDirection(StrEnum):
    """Which end opened the connection, seen from the end that reports it."""

    #: The remote end opened it. Every connection the outstation reports.
    INBOUND = "inbound"
    #: The reporting end opened it. Every connection the master reports.
    OUTBOUND = "outbound"


class ConnectionTransport(StrEnum):
    """What the connection is carried over."""

    TCP = "tcp"
    TLS = "tls"


class ConnectionOutcome(StrEnum):
    """What happened to a connection."""

    #: The outstation admitted the connection as the master's.
    ACCEPTED = "accepted"
    #: The outstation closed the connection without admitting it.
    REFUSED = "refused"
    #: The outstation closed an admitted connection because a newer one was
    #: admitted in its place.
    DISPLACED = "displaced"
    #: An admitted connection ended: closed by the peer, reset, timed out,
    #: failed, closed by the local application, or ended by the listener
    #: stopping.
    ENDED = "ended"
    #: The master made the connection.
    CONNECTED = "connected"
    #: The master could not make the connection.
    FAILED = "failed"
    #: The master lost a connection it had made.
    LOST = "lost"


@dataclass(frozen=True)
class Endpoint:
    """An address and port at one end of a connection."""

    host: str
    port: int

    @classmethod
    def of(cls, name: Any) -> Endpoint | None:
        """Return the endpoint of a socket name, or None when the name holds none.

        ``name`` is what ``getpeername`` or ``getsockname`` returns: a tuple
        whose first two items are the address and the port.
        """
        if isinstance(name, tuple) and len(name) >= 2:
            try:
                return cls(str(name[0]), int(name[1]))
            except (TypeError, ValueError):
                return None
        return None

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


@dataclass(frozen=True)
class ConnectionEvent:
    """One thing that happened to one connection.

    Attributes:
        role: The end that reports the event.
        direction: Which end opened the connection.
        outcome: What happened.
        transport: TCP, or TLS over TCP.
        remote: The other end. For a master's failed attempt, the host and
            port it tried.
        local: This end, or None when no socket was made.
        peer_identity: For a TLS connection, who the peer proved to be: at the
            outstation, the allow-list entry the master's certificate matched;
            at the master, the name the outstation's certificate was checked
            against, or the certificate's ``sha256:`` fingerprint when the
            context checks no name. None otherwise.
        reason: Why, in a few words, for every outcome except ``ACCEPTED`` and
            ``CONNECTED``. It holds no secret.
        name: At the master, the name the outstation was added under. None at
            the outstation.
        timestamp: When the event was reported, in seconds since the Unix
            epoch.
    """

    role: ConnectionRole
    direction: ConnectionDirection
    outcome: ConnectionOutcome
    transport: ConnectionTransport
    remote: Endpoint | None
    local: Endpoint | None = None
    peer_identity: str | None = None
    reason: str = ""
    name: str | None = None
    timestamp: float = field(default_factory=time.time)


class AnomalyCode(StrEnum):
    """What the session dropped or gave up on. The values are stable."""

    #: A frame from a master address other than the one this session serves.
    UNEXPECTED_MASTER_ADDRESS = "unexpected_master_address"
    #: A frame from an address no master can have: a reserved or broadcast
    #: address, or this outstation's own.
    INVALID_SOURCE_ADDRESS = "invalid_source_address"
    #: A frame whose frame count valid bit is set on a function that does not
    #: count frames, or clear on one that does.
    INVALID_FRAME_COUNT_VALID = "invalid_frame_count_valid"
    #: A user data frame with no data, or another link function carrying data.
    LINK_PAYLOAD_MISMATCH = "link_payload_mismatch"
    #: A transport segment out of sequence, too large, or otherwise refused.
    TRANSPORT_ERROR = "transport_error"
    #: The same, in a broadcast.
    BROADCAST_TRANSPORT_ERROR = "broadcast_transport_error"
    #: A broadcast write whose objects could not be read.
    MALFORMED_BROADCAST_WRITE = "malformed_broadcast_write"
    #: A broadcast request the outstation received and did not carry out.
    BROADCAST_NOT_ACTED_ON = "broadcast_not_acted_on"
    #: A fragment that cannot be a request: too short, not a whole message, or
    #: marked as unsolicited.
    NOT_A_REQUEST = "not_a_request"
    #: A request whose object headers could not be read.
    MALFORMED_REQUEST = "malformed_request"
    #: An unsolicited response not confirmed after every retry allowed.
    UNSOLICITED_NOT_CONFIRMED = "unsolicited_not_confirmed"


class AnomalySeverity(StrEnum):
    """How much an anomaly says about the peer, from least to most."""

    #: Expected in normal operation, and recorded for completeness.
    INFO = "info"
    #: Explained by a lossy link or a slow master as easily as by misbehavior.
    LOW = "low"
    #: A malformed frame or request: a defective or misconfigured peer, or one
    #: probing the outstation.
    MEDIUM = "medium"
    #: Traffic from an address that should not be speaking on this association.
    HIGH = "high"


#: The severity each anomaly code is reported with.
SEVERITY: Mapping[AnomalyCode, AnomalySeverity] = MappingProxyType(
    {
        AnomalyCode.UNEXPECTED_MASTER_ADDRESS: AnomalySeverity.HIGH,
        AnomalyCode.INVALID_SOURCE_ADDRESS: AnomalySeverity.HIGH,
        AnomalyCode.INVALID_FRAME_COUNT_VALID: AnomalySeverity.MEDIUM,
        AnomalyCode.LINK_PAYLOAD_MISMATCH: AnomalySeverity.MEDIUM,
        AnomalyCode.MALFORMED_BROADCAST_WRITE: AnomalySeverity.MEDIUM,
        AnomalyCode.NOT_A_REQUEST: AnomalySeverity.MEDIUM,
        AnomalyCode.MALFORMED_REQUEST: AnomalySeverity.MEDIUM,
        AnomalyCode.TRANSPORT_ERROR: AnomalySeverity.LOW,
        AnomalyCode.BROADCAST_TRANSPORT_ERROR: AnomalySeverity.LOW,
        AnomalyCode.UNSOLICITED_NOT_CONFIRMED: AnomalySeverity.LOW,
        AnomalyCode.BROADCAST_NOT_ACTED_ON: AnomalySeverity.INFO,
    }
)


@dataclass(frozen=True)
class ProtocolAnomaly:
    """One frame, fragment or exchange the session dropped or gave up on.

    Attributes:
        code: What happened.
        severity: How much it says about the peer. Always ``SEVERITY[code]``.
        message: The same text the session logs, without the ``dnp3:`` prefix.
        source: The link address the frame came from, or None when the anomaly
            concerns no single frame.
        destination: The link address the frame was sent to, or None.
        peer: The connection the octets arrived on, or the sender of a
            broadcast datagram, when the session was told. None for a session
            driven without a listener.
        timestamp: When the anomaly was reported, in seconds since the Unix
            epoch.
    """

    code: AnomalyCode
    severity: AnomalySeverity
    message: str
    source: int | None = None
    destination: int | None = None
    peer: Endpoint | None = None
    timestamp: float = field(default_factory=time.time)


@dataclass(frozen=True)
class RequestRecord:
    """One request the outstation handled, or one unsolicited response it sent.

    The session reports each request once, after it has built the response.
    That covers every function a master sends, including a confirmation, a
    request refused with an indication, a function that takes no response, a
    request repeated by a master that did not hear the answer, and a request
    sent to a broadcast address. A fragment reported as a
    :class:`ProtocolAnomaly` is not reported here as well.

    A read held back while an unsolicited response waits for its confirmation
    (D71) is reported when it is answered, with that answer, or when it is
    discarded unanswered, with no response.

    Attributes:
        peer: The connection the request arrived on, or the sender of a
            broadcast datagram, when the session was told. None for a session
            driven without a listener.
        source: The link address that sent the first fragment: the master for
            a request, this outstation for an unsolicited response.
        destination: The link address that fragment was sent to: this
            outstation or a broadcast address for a request, the master for an
            unsolicited response.
        function: The application function code of ``request``, or for an
            unsolicited response, of the response (130).
        request: The request fragment, from the application control octet to
            the last object. Empty for an unsolicited response.
        response: The response fragment sent back, from the application
            control octet to the last object, or None when nothing was sent.
            A response that spans several fragments is reported in parts: the
            first with the request, and each later one with the confirmation
            that drew it out.
        unsolicited: True for an unsolicited response, which answers no
            request. Each transmission is reported, retries included.
        timestamp: When the record was reported, in seconds since the Unix
            epoch.
    """

    peer: Endpoint | None
    source: int
    destination: int
    function: int
    request: bytes
    response: bytes | None
    unsolicited: bool = False
    timestamp: float = field(default_factory=time.time)


#: Receives each connection event.
ConnectionObserver = Callable[[ConnectionEvent], None]

#: Receives each protocol anomaly.
AnomalyObserver = Callable[[ProtocolAnomaly], None]

#: Receives each request record.
RequestObserver = Callable[[RequestRecord], None]

_Record = TypeVar("_Record")


class ObserverGuard:
    """Call an observer and keep its exceptions from reaching the caller.

    The first exception of an observer is logged with its traceback. Later
    exceptions of the same observer are logged at DEBUG, so an observer that
    fails on every record does not fill the log. A different observer starts
    over.
    """

    def __init__(self, what: str) -> None:
        """Make a guard for the observer named ``what`` in log records."""
        self._what = what
        self._failed: object | None = None

    def deliver(self, observer: Callable[[_Record], None] | None, record: _Record) -> None:
        """Call ``observer`` with ``record``, unless there is no observer."""
        if observer is None:
            return
        try:
            observer(record)
        except Exception:  # pylint: disable=broad-exception-caught
            # The observer belongs to the host application. Its failure says
            # nothing about the connection or the session, which go on.
            if self._failed is observer:
                logger.debug("dnp3: the %s failed again", self._what, exc_info=True)
            else:
                self._failed = observer
                logger.exception(
                    "dnp3: the %s failed; further failures are logged at DEBUG", self._what
                )


__all__ = [
    "SEVERITY",
    "AnomalyCode",
    "AnomalyObserver",
    "AnomalySeverity",
    "ConnectionDirection",
    "ConnectionEvent",
    "ConnectionObserver",
    "ConnectionOutcome",
    "ConnectionRole",
    "ConnectionTransport",
    "Endpoint",
    "ObserverGuard",
    "ProtocolAnomaly",
    "RequestObserver",
    "RequestRecord",
]
