"""The listener: sockets, TLS, and which connection is allowed to be the master.

Everything protocol-shaped lives in :mod:`py1815.session`. This module owns what
a socket adds -- who is permitted to connect, what happens when a second one
arrives, and when an idle one is closed.

Two rules carry the weight, and both exist because an outstation is a thing on a
network that a utility trusts to report the truth about equipment.

**Authorization precedes admission.** A TLS peer outside the allow-list is
disconnected before any session state is touched. The standard library validates
the certificate chain during the handshake and exposes the peer certificate only
once it completes, offering no callback to reject inside it, so the check runs on
the first thing the connection does. Ordering is the substance of it rather than
a detail: an admitted connection displaces the active one, so a peer authorized
too late would take the association down on its way to being refused.

**One connection is the master.** A second authorized connection displaces the
first rather than joining it, because event buffers, confirmation state and
unsolicited retry ownership belong to a master association and not to a socket.
The common cause of a second connection is a master whose socket died without a
FIN, and refusing it would leave the outstation unreachable until a timeout it
cannot observe.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import ssl
from dataclasses import dataclass

from py1815.session import Session

logger = logging.getLogger(__name__)

#: The port IANA assigns to DNP3.
DEFAULT_PORT = 20000

#: Seconds a connection may sit silent before it is closed. A master polls, so
#: silence this long means it has gone without saying so, and an abandoned
#: connection holds the association against the master that wants it back.
IDLE_TIMEOUT = 300.0

#: Octets read at a time. A frame is at most 292, so this is several.
_READ_SIZE = 4096

#: Prefix marking an allow-list entry as a certificate fingerprint rather than a
#: name.
FINGERPRINT_PREFIX = "sha256:"

#: How long a displaced connection is waited on before it is abandoned.
_CLOSE_TIMEOUT = 2.0


class PeerRefused(Exception):
    """A connection whose certificate is not on the allow-list."""


@dataclass(frozen=True)
class PeerIdentity:
    """What a peer certificate offers, kept apart by kind.

    Names and the fingerprint are separate fields rather than one set, and that
    separation is the security property rather than tidiness. A certificate's
    subject is chosen by whoever requested it; its fingerprint is not. Holding
    both in one collection let a common name of the literal text
    ``sha256:<hex>`` satisfy an entry that pinned that fingerprint -- and since
    a pinned fingerprint is readable off the certificate being protected, the
    value needed to forge the match is published by the thing it protects.
    """

    names: frozenset[str]
    fingerprint: str | None


def peer_identities(ssl_object: ssl.SSLObject) -> PeerIdentity:
    """What this peer offers for matching: its names, and its fingerprint.

    Names are the common name and the DNS entries of the subject alternative
    name. They come from the certificate the chain validated, so they are as
    trustworthy as the CA that signed it -- which is precisely why an allow-list
    is needed on top.
    """
    names: set[str] = set()

    certificate = ssl_object.getpeercert()
    if certificate:
        # The shape is checked rather than unpacked. ``getpeercert`` returns a
        # loosely structured dictionary whose nesting differs between fields,
        # and an unpack that assumed a pair would raise on the certificate that
        # did not have one -- inside the authorization path, where a raise is a
        # refusal nobody can explain.
        for field in certificate.get("subject", ()):
            for pair in field:
                if len(pair) == 2 and pair[0] == "commonName":
                    names.add(str(pair[1]))
        for entry in certificate.get("subjectAltName", ()):
            if len(entry) == 2 and entry[0] == "DNS":
                names.add(str(entry[1]))

    der = ssl_object.getpeercert(binary_form=True)
    fingerprint = FINGERPRINT_PREFIX + hashlib.sha256(der).hexdigest() if der else None

    return PeerIdentity(names=frozenset(names), fingerprint=fingerprint)


def authorize(ssl_object: ssl.SSLObject, allowed: frozenset[str]) -> str:
    """The identity this peer matched, or raise :class:`PeerRefused`.

    Each entry is matched only against its own kind: a ``sha256:`` entry against
    the certificate's fingerprint, anything else against its names. A name can
    therefore never satisfy a pinned fingerprint however it is spelled.

    Matching is exact and case-sensitive for fingerprints; names are compared
    case-insensitively, since DNS is. No wildcards: an allow-list whose entries
    can match things nobody enumerated is not an allow-list.
    """
    identity = peer_identities(ssl_object)
    lowered = {name.lower() for name in identity.names}

    for entry in allowed:
        if entry.startswith(FINGERPRINT_PREFIX):
            if identity.fingerprint is not None and entry == identity.fingerprint:
                return entry
        elif entry.lower() in lowered:
            return entry

    raise PeerRefused(
        f"peer offers names {sorted(identity.names) or ['none']} and fingerprint "
        f"{identity.fingerprint or 'none'}, none of which is allowed"
    )


def _split_bind(bind: str) -> tuple[str, int]:
    """Split ``host:port``, including the bracketed form IPv6 needs.

    ``[::1]:20000`` is how an IPv6 literal is written with a port, and splitting
    on the last colon alone leaves the brackets on the host, which then does not
    resolve.
    """
    if bind.startswith("["):
        host, _, rest = bind.partition("]")
        return host[1:], int(rest.lstrip(":"))
    host, _, port = bind.rpartition(":")
    return host or "0.0.0.0", int(port)


class _BroadcastDatagrams(asyncio.DatagramProtocol):
    """Hands datagrams to the session, which acts only on broadcasts."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def datagram_received(self, data: bytes, addr: object) -> None:
        try:
            self._session.receive_broadcast(data)
        except Exception:  # pylint: disable=broad-exception-caught
            # Nothing is owed to the sender of a datagram, and one that
            # cannot be handled must not take the listener down with it.
            logger.exception("dnp3: a broadcast datagram from %s could not be handled", addr)


class OutstationServer:
    """Serves one master association over TCP, optionally with TLS."""

    def __init__(
        self,
        session: Session,
        *,
        bind: str = f"0.0.0.0:{DEFAULT_PORT}",
        ssl_context: ssl.SSLContext | None = None,
        authorized_peers: frozenset[str] | None = None,
        idle_timeout: float = IDLE_TIMEOUT,
        broadcast_datagrams: bool = False,
    ) -> None:
        """
        Args:
            session: The association this listener serves. One session, not one
                per connection: its state belongs to the master rather than to
                the socket, so a reconnection resumes it.
            bind: ``host:port`` to listen on.
            ssl_context: Server-side TLS, or None for plaintext.
            authorized_peers: Certificate names or ``sha256:`` fingerprints
                permitted to connect. Required whenever ``ssl_context`` is given.
            idle_timeout: Seconds of silence before a connection is closed.
            broadcast_datagrams: Also listen for datagrams on the same
                port, and act on those addressed to a DNP3 broadcast
                address. A master reaching many outstations at once sends
                a broadcast this way, since a stream reaches one. Off by
                default, and refused with TLS: a datagram carries no
                certificate, so anyone who can reach the port can send
                one, and what a broadcast may do (freeze counters, set
                the time, and operate controls if the session allows it)
                is done on that say-so.

        Raises:
            ValueError: If TLS is configured without an allow-list, or with a
                context that does not require a client certificate.
        """
        if ssl_context is not None:
            # Structural rather than a caller convention. Trusting a CA alone
            # authenticates every certificate that CA ever issued, and the DNP3
            # link address arrives inside the protocol from whoever connected,
            # so it identifies rather than authorizes. Without an allow-list,
            # any CA-trusted endpoint reaching this port reads the whole fleet
            # and can displace the legitimate master.
            if not authorized_peers:
                raise ValueError(
                    "a TLS listener requires authorized_peers: trusting the CA alone "
                    "admits every certificate it ever issued"
                )
            if ssl_context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError(
                    "a TLS listener requires ssl.CERT_REQUIRED: without a client "
                    "certificate there is no identity to check against authorized_peers"
                )
        elif authorized_peers:
            # The third configuration that looks secure and is not. A plaintext
            # listener has no certificate to match, so the allow-list would be
            # stored and never consulted -- and the caller who wrote it believes
            # they have restricted who may connect. They have not: anyone may,
            # and under D7 anyone may displace the master.
            raise ValueError(
                "authorized_peers requires a TLS listener: a plaintext connection "
                "presents no certificate, so the allow-list could not be applied"
            )

        self._session = session
        self._host, self._port = _split_bind(bind)
        self._ssl = ssl_context
        self._allowed = frozenset(authorized_peers or ())
        self._idle_timeout = idle_timeout
        if broadcast_datagrams and ssl_context is not None:
            raise ValueError(
                "broadcast_datagrams cannot be combined with TLS: a datagram is "
                "unauthenticated, and would bypass the peer allow-list"
            )
        self._broadcast_datagrams = broadcast_datagrams
        self._datagrams: asyncio.DatagramTransport | None = None
        self._server: asyncio.Server | None = None
        self._active: asyncio.StreamWriter | None = None
        self._active_task: asyncio.Task[None] | None = None
        #: Admission and shutdown are serialized. Both await -- closing a
        #: displaced connection waits on its transport -- and without this a
        #: third connection arriving during that await sees no active
        #: connection, installs itself, and then the displacing one installs
        #: itself too. Two sockets would drive one session concurrently, which
        #: is the state D7 exists to make impossible.
        self._admission = asyncio.Lock()

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def connected(self) -> bool:
        return self._active is not None

    @property
    def port(self) -> int:
        """The bound port, which differs from the requested one when it was 0."""
        if self._server is None or not self._server.sockets:
            return self._port
        bound: int = self._server.sockets[0].getsockname()[1]
        return bound

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, self._host, self._port, ssl=self._ssl
        )
        logger.info(
            "dnp3 outstation listening on %s:%d (%s)",
            self._host,
            self.port,
            "TLS" if self._ssl else "plaintext",
        )
        if self._broadcast_datagrams:
            loop = asyncio.get_running_loop()
            self._datagrams, _ = await loop.create_datagram_endpoint(
                lambda: _BroadcastDatagrams(self._session),
                local_addr=(self._host, self.port),
            )

    async def stop(self) -> None:
        """Stop accepting, then end the connection in progress.

        Both halves are needed: closing the listener stops new connections and
        leaves an established one being served. Under the admission lock, so a
        connection that was mid-handshake cannot install itself afterwards.
        """
        if self._datagrams is not None:
            self._datagrams.close()
            self._datagrams = None
        async with self._admission:
            server, self._server = self._server, None
            if server is not None:
                server.close()
            await self._close_active(abort=False)
        if server is not None:
            with contextlib.suppress(Exception):
                await server.wait_closed()

    async def _close_active(self, *, abort: bool) -> None:
        """End the active connection and stop its handler.

        ``abort`` is the difference between the two callers, and they want
        opposite things.

        *Displacement aborts.* The connection being displaced is typically one
        whose socket died without a FIN, which is the case D7 names, and a
        graceful close there waits on TCP retransmission or, under TLS, on a
        shutdown that can take tens of seconds. This runs under the admission
        lock, so waiting would block the displacing connection and ``stop()``
        behind it -- letting a dead master hold the association through a second
        door, which is the door displacement exists to shut.

        *Shutdown does not.* A master connected at ``stop()`` is usually
        healthy, and aborting would discard a response already queued. The wait
        is bounded either way, so a peer that has in fact gone away costs a
        couple of seconds rather than the shutdown.

        The handler is cancelled in both cases. Closing alone leaves it blocked
        in ``read`` until the transport notices, and a handler that woke
        afterwards would go on feeding a session that now belongs to someone
        else.
        """
        writer, self._active = self._active, None
        task, self._active_task = self._active_task, None

        if writer is not None:
            if abort:
                # The lookup sits outside the suppression and the call inside
                # it. An earlier revision had both inside, which left an absent
                # transport silently skipping the abort -- the same failure the
                # getattr default before it had, wearing a different hat. Only
                # abort() itself is allowed to fail, and only because a
                # transport already closing raises from it.
                transport = writer.transport
                with contextlib.suppress(Exception):
                    transport.abort()
            writer.close()
        if task is not None and task is not asyncio.current_task():
            task.cancel()
        if writer is not None:
            # Bounded either way: an aborted transport closes promptly, and a
            # gracefully closed one belonging to a peer that has gone away must
            # not hold up a shutdown.
            with contextlib.suppress(Exception, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), timeout=_CLOSE_TIMEOUT)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")

        if self._ssl is not None:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                logger.error("dnp3: TLS listener received a connection with no TLS object")
                writer.close()
                return
            try:
                identity = authorize(ssl_object, self._allowed)
            except PeerRefused as exc:
                # Before admission, so a refused peer cannot displace the master.
                logger.warning("dnp3: refusing %s: %s", peer, exc)
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                return
            logger.info("dnp3: admitted %s as %s", peer, identity)

        try:
            async with self._admission:
                if self._server is None:
                    # The listener stopped while this connection was being
                    # authorized. Admitting it now would outlive stop().
                    logger.info("dnp3: dropping %s: the listener has stopped", peer)
                    writer.close()
                    return

                if self._active is not None:
                    logger.info("dnp3: %s displaces the connection already established", peer)
                    await self._close_active(abort=True)

                self._active = writer
                self._active_task = asyncio.current_task()
                # Framing state belongs to the socket that is gone; the
                # association's own state survives, which is what a reconnecting
                # master expects.
                self._session.connection_reset()
        except BaseException:
            # Admission runs before the serve loop, and therefore before the
            # cleanup below. A failure here -- displacing a writer whose
            # transport is missing, say -- would otherwise escape with this
            # connection's socket still open and ``_active`` already cleared by
            # ``_close_active``: a live peer the listener no longer knows it
            # has, reporting ``connected`` as False.
            #
            # Closed here, then re-raised. Failing loudly is the intent, and it
            # should not also mean leaking. Catching ``BaseException`` so that
            # cancellation during admission closes the socket too.
            if self._active is writer:
                self._active = None
                self._active_task = None
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            raise

        try:
            await self._serve(reader, writer)
        except asyncio.CancelledError:
            # Displacement cancels this handler. Re-raised so the task finishes
            # cancelled rather than appearing to have returned normally, which
            # is what anything awaiting it would otherwise be told.
            logger.debug("dnp3: connection from %s cancelled", peer)
            raise
        except (TimeoutError, ConnectionResetError, BrokenPipeError) as exc:
            logger.info("dnp3: connection from %s ended: %s", peer, exc)
        except Exception:
            # One connection's failure must not take the listener with it.
            logger.exception("dnp3: connection from %s failed", peer)
        finally:
            if self._active is writer:
                self._active = None
                self._active_task = None
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            data = await asyncio.wait_for(reader.read(_READ_SIZE), timeout=self._idle_timeout)
            if not data:
                return
            reply = self._session.receive(data)
            if reply:
                writer.write(reply)
                # Bounded like the read: a peer that connects and stops reading
                # would otherwise park this handler in drain() indefinitely,
                # holding the association -- which is what the idle timeout is
                # for, applied to only half the exchange.
                await asyncio.wait_for(writer.drain(), timeout=self._idle_timeout)
