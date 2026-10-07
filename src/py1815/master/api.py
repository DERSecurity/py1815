"""A master on a socket: the interface a script uses.

:class:`Master` holds outstations by name. :class:`Outstation` is one
association over one TCP connection, and is where the requests are. Each
request is a coroutine that returns an
:class:`~py1815.master.association.Exchange` saying what happened: a timeout
and an error indication are results, and an exception means the interface was
misused or the connection could not be made.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import deque
from collections.abc import Awaitable, Callable
from types import TracebackType
from typing import Any

from py1815.application import FunctionCode
from py1815.master.association import (
    DEFAULT_RESPONSE_TIMEOUT,
    Exchange,
    MasterAssociation,
    Unsolicited,
)
from py1815.master.operations import Operations
from py1815.master.store import Store

logger = logging.getLogger(__name__)

#: Seconds to wait for a TCP connection to be made.
DEFAULT_CONNECT_TIMEOUT = 5.0

#: Unsolicited responses kept before the oldest is dropped.
_UNSOLICITED_KEPT = 1000

_READ_SIZE = 4096


class NotConnected(ConnectionError):
    """A request was made of an outstation that has no connection."""


class Outstation(Operations[Awaitable[Exchange]]):
    """One outstation, as a master sees it: a connection, an association, a store."""

    def __init__(
        self,
        name: str,
        *,
        host: str,
        port: int = 20000,
        outstation_address: int = 1024,
        master_address: int = 1,
        response_timeout: float = DEFAULT_RESPONSE_TIMEOUT,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        confirm: bool = True,
        on_unsolicited: Callable[[Unsolicited], None] | None = None,
    ) -> None:
        """
        Args:
            name: What the caller calls this outstation.
            host: Where it listens.
            port: The port it listens on.
            outstation_address: Its link address.
            master_address: The link address this master speaks from.
            response_timeout: Seconds to wait for a response, and for each
                further fragment of one.
            connect_timeout: Seconds to wait for the connection to be made.
            confirm: Whether fragments that ask to be confirmed are. See
                :class:`~py1815.master.association.MasterAssociation`.
            on_unsolicited: Called with each unsolicited response as it
                arrives, after it has been confirmed and stored.
        """
        self.name = name
        self.host = host
        self.port = port
        self.association = MasterAssociation(
            outstation_address=outstation_address,
            master_address=master_address,
            response_timeout=response_timeout,
            confirm=confirm,
        )
        self.store = Store()
        self.on_unsolicited = on_unsolicited
        self._connect_timeout = connect_timeout
        self._unsolicited: deque[Unsolicited] = deque(maxlen=_UNSOLICITED_KEPT)
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._receiving: asyncio.Task[None] | None = None
        #: Set whenever something arrived or the connection ended, so a
        #: waiting request looks again.
        self._progress = asyncio.Event()
        #: One request at a time, in the order asked.
        self._turn = asyncio.Lock()

    # ------------------------------------------------------------ connection

    @property
    def connected(self) -> bool:
        return self._writer is not None and not self._writer.is_closing()

    @property
    def unsolicited(self) -> tuple[Unsolicited, ...]:
        """The unsolicited responses received, oldest first."""
        return tuple(self._unsolicited)

    async def connect(self) -> None:
        """Open the connection. Raises ``OSError`` if it cannot be made."""
        if self.connected:
            return
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), self._connect_timeout
            )
        except TimeoutError as exc:
            raise TimeoutError(
                f"no connection to {self.host}:{self.port} within {self._connect_timeout} s"
            ) from exc
        self.association.connection_reset()
        self.association.take()
        self._receiving = asyncio.create_task(self._receive(), name=f"dnp3-master-{self.name}")

    async def close(self) -> None:
        """Close the connection. The store and the association's counters stay."""
        receiving, self._receiving = self._receiving, None
        writer, self._writer = self._writer, None
        self._reader = None
        if receiving is not None:
            receiving.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await receiving
        if writer is not None:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
        self.association.connection_reset()
        self._progress.set()

    async def _receive(self) -> None:
        reader, writer = self._reader, self._writer
        assert reader is not None and writer is not None
        try:
            while True:
                data = await reader.read(_READ_SIZE)
                if not data:
                    logger.info("dnp3 master: %s closed the connection", self.name)
                    return
                reply = self.association.receive(data)
                if reply:
                    writer.write(reply)
                    await writer.drain()
                self._deliver_unsolicited()
                self._progress.set()
        except OSError as exc:
            logger.info("dnp3 master: connection to %s lost: %s", self.name, exc)
        finally:
            # Whatever was outstanding went with the connection. Say so, and
            # wake whoever was waiting for it.
            self.association.connection_reset()
            if self._writer is writer:
                self._writer = None
                writer.close()
            self._progress.set()

    def _deliver_unsolicited(self) -> None:
        for unsolicited in self.association.take_unsolicited():
            self.store.apply(unsolicited.objects, now=time.monotonic())
            self._unsolicited.append(unsolicited)
            if self.on_unsolicited is not None:
                try:
                    self.on_unsolicited(unsolicited)
                except Exception:  # pylint: disable=broad-exception-caught
                    # A caller's handler that raises must not end the receive
                    # loop: the connection is not at fault.
                    logger.exception(
                        "dnp3 master: the unsolicited handler for %s failed", self.name
                    )

    # -------------------------------------------------------------- requests

    async def _exchange(self, function: FunctionCode, body: bytes) -> Exchange:
        async with self._turn:
            writer = self._writer
            if writer is None or writer.is_closing():
                raise NotConnected(f"{self.name} is not connected")
            self._progress.clear()
            writer.write(self.association.request(function, body))
            # A write that fails is seen by the receive loop as well, which
            # ends the exchange as abandoned.
            with contextlib.suppress(OSError):
                await writer.drain()
            while True:
                exchange = self.association.take()
                if exchange is not None:
                    self.store.apply(exchange.objects, now=time.monotonic())
                    return exchange
                wait = self.association.expires_after()
                if wait is None:
                    # Neither outstanding nor finished: the connection was
                    # closed and reopened underneath this request.
                    raise NotConnected(f"the connection to {self.name} was reset")
                if wait <= 0:
                    self.association.expire()
                    continue
                self._progress.clear()
                # Looked at again before waiting: something may have arrived
                # between taking and clearing.
                if not self.association.busy:
                    continue
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._progress.wait(), wait)


class Master:
    """Outstations, by the names their caller gave them."""

    def __init__(self) -> None:
        self._outstations: dict[str, Outstation] = {}

    async def __aenter__(self) -> Master:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.close()

    @property
    def outstations(self) -> dict[str, Outstation]:
        """The outstations added, by name."""
        return dict(self._outstations)

    def __getitem__(self, name: str) -> Outstation:
        return self._outstations[name]

    async def add(self, name: str, *, connect: bool = True, **options: Any) -> Outstation:
        """Add an outstation and, unless told not to, connect to it.

        ``options`` are those of :class:`Outstation`. A name is used once.
        """
        if name in self._outstations:
            raise ValueError(f"an outstation named {name!r} has already been added")
        outstation = Outstation(name, **options)
        if connect:
            await outstation.connect()
        self._outstations[name] = outstation
        return outstation

    async def remove(self, name: str) -> None:
        """Close an outstation's connection and forget it."""
        outstation = self._outstations.pop(name)
        await outstation.close()

    async def close(self) -> None:
        """Close every connection."""
        outstations, self._outstations = list(self._outstations.values()), {}
        for outstation in outstations:
            await outstation.close()
