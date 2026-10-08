"""A master on a socket: the interface a script uses.

:class:`Master` holds outstations by name. :class:`Outstation` is one
association over one TCP connection, and is where the requests are. Each
request is a coroutine that returns an
:class:`~py1815.master.association.Exchange` saying what happened: a timeout
and an error indication are results, and an exception means the interface was
misused or the connection could not be made.

Each outstation also runs automatic tasks: a startup sequence on connect,
clearing the restart indication, writing the time on request, polling for
events when indicated, and reconnecting after a lost connection. Configure
them with :class:`~py1815.master.tasks.Tasks`, or pass ``manual=True`` to
disable every task and confirmation.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import replace
from types import TracebackType
from typing import Any

from py1815.application import IIN, FunctionCode
from py1815.master import requests
from py1815.master.association import (
    DEFAULT_RESPONSE_TIMEOUT,
    Exchange,
    MasterAssociation,
    Unsolicited,
)
from py1815.master.controls import Operated, Plan
from py1815.master.operations import Operations
from py1815.master.store import Store
from py1815.master.tasks import WRITING, Housekeeper, Tasks
from py1815.master.trace import RECEIVED, SENT, Trace

logger = logging.getLogger(__name__)

#: Seconds to wait for a TCP connection to be made.
DEFAULT_CONNECT_TIMEOUT = 5.0

#: Default seconds between reconnection attempts.
DEFAULT_RECONNECT = 5.0

#: Unsolicited responses kept before the oldest is dropped.
_UNSOLICITED_KEPT = 1000

_READ_SIZE = 4096


#: Seconds between log records saying an outstation is still not reachable.
RETRY_REPORT_INTERVAL = 3600.0


class RetryReport:
    """Log failed reconnection attempts without filling the log.

    The first failure is logged at INFO. Later failures are logged at DEBUG,
    with one INFO record each ``interval`` seconds that counts them. An
    outstation that is down for a day with a five-second retry then writes
    about 25 INFO records instead of 17,000.
    """

    def __init__(
        self,
        name: str,
        *,
        interval: float = RETRY_REPORT_INTERVAL,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.name = name
        self.attempts = 0
        self._interval = interval
        self._clock = clock
        self._started = clock()
        self._reported: float | None = None

    def failed(self, error: OSError) -> int:
        """Record one failed attempt, and return the level it was logged at."""
        self.attempts += 1
        now = self._clock()
        if self._reported is None or now - self._reported >= self._interval:
            self._reported = now
            level = logging.INFO
            minutes = (now - self._started) / 60
            logger.log(
                level,
                "dnp3 master: %s is not reachable (%d failed attempt(s) in %.0f min): %s",
                self.name,
                self.attempts,
                minutes,
                error,
            )
        else:
            level = logging.DEBUG
            logger.log(level, "dnp3 master: %s is still not reachable: %s", self.name, error)
        return level


class NotConnected(ConnectionError):
    """A request was made of an outstation that has no connection."""


def _address(name: Any) -> tuple[str, int] | None:
    """Return a socket's address and port, or None when the socket did not give them."""
    if isinstance(name, tuple) and len(name) >= 2:
        return str(name[0]), int(name[1])
    return None


class Outstation(Operations[Awaitable[Exchange], Awaitable[Operated]]):
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
        confirm: bool | None = None,
        tasks: Tasks | None = None,
        manual: bool = False,
        reconnect: float | None = DEFAULT_RECONNECT,
        on_unsolicited: Callable[[Unsolicited], None] | None = None,
        on_exchange: Callable[[Exchange], None] | None = None,
        on_connection: Callable[[bool], None] | None = None,
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
                Defaults to True, or False when ``manual`` is set.
            tasks: The automatic tasks to run. Defaults to ``Tasks()``, or
                ``Tasks.none()`` when ``manual`` is set.
            manual: Disable all automatic tasks and confirmations, so only
                requests the caller makes are sent. An explicit ``tasks`` or
                ``confirm`` overrides this.
            reconnect: Seconds between reconnection attempts after a
                connection is lost, or None to disable reconnection. A
                connection ended by :meth:`close` is not reopened.
            on_unsolicited: Called with each unsolicited response as it
                arrives, after it has been confirmed and stored.
            on_exchange: Called with each exchange as it ends, after its
                objects have been stored.
            on_connection: Called with True when the connection is made and
                False when it ends.
        """
        self.name = name
        self.host = host
        self.port = port
        if reconnect is not None and not (reconnect > 0 and math.isfinite(reconnect)):
            raise ValueError(f"reconnect is {reconnect}; it is a wait between attempts")
        self.association = MasterAssociation(
            outstation_address=outstation_address,
            master_address=master_address,
            response_timeout=response_timeout,
            confirm=not manual if confirm is None else confirm,
        )
        if tasks is None:
            tasks = Tasks.none() if manual else Tasks()
        self._housekeeper = Housekeeper(tasks)
        self.reconnect = reconnect
        self.store = Store()
        self.trace = Trace()
        self.on_unsolicited = on_unsolicited
        self.on_exchange = on_exchange
        self.on_connection = on_connection
        #: How the exchanges so far ended, by outcome.
        self.counts: dict[str, int] = {}
        #: The last exchange that received anything, and when it ended.
        self.last_response: Exchange | None = None
        self.last_response_at: float | None = None
        self._scanning: dict[str, asyncio.Task[None]] = {}
        self._scan_intervals: dict[str, float] = {}
        self._connect_timeout = connect_timeout
        self._unsolicited: deque[Unsolicited] = deque(maxlen=_UNSOLICITED_KEPT)
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._receiving: asyncio.Task[None] | None = None
        self._housekeeping: asyncio.Task[None] | None = None
        self._reconnecting: asyncio.Task[None] | None = None
        #: Set whenever something arrived or the connection ended, so a
        #: waiting request looks again.
        self._progress = asyncio.Event()
        #: Set when a task becomes due, to wake the task worker.
        self._attention = asyncio.Event()
        #: Set while no task is pending or running.
        self._settled = asyncio.Event()
        self._settled.set()
        #: One request at a time, in the order asked.
        self._turn = asyncio.Lock()

    # ------------------------------------------------------------ connection

    @property
    def connected(self) -> bool:
        return self._writer is not None and not self._writer.is_closing()

    @property
    def tasks(self) -> Tasks:
        """The automatic task settings for this outstation."""
        return self._housekeeper.tasks

    @property
    def tasks_due(self) -> tuple[str, ...]:
        """The pending tasks, in execution order."""
        return self._housekeeper.due

    @property
    def unsolicited(self) -> tuple[Unsolicited, ...]:
        """The unsolicited responses received, oldest first."""
        return tuple(self._unsolicited)

    async def connect(self) -> None:
        """Open the connection. Raises ``OSError`` if it cannot be made.

        Returns as soon as the connection is open. The startup tasks run
        after that; use :meth:`idle` to wait for them.

        If this is called while the master is retrying a lost connection and
        the attempt fails, the error is raised and the retries carry on.
        """
        retrying = self._reconnecting is not None
        await self._stop_reconnecting()
        try:
            await self._open()
        except OSError:
            # This call cancelled the retry worker. Start it again, so a
            # failed manual attempt does not end automatic reconnection.
            if retrying:
                self._start_reconnecting()
            raise

    async def idle(self) -> None:
        """Wait until no automatic task is pending or running.

        Returns immediately if there is none, or if the connection has ended.
        """
        await self._settled.wait()

    async def _open(self) -> None:
        if self.connected:
            return
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), self._connect_timeout
            )
        except TimeoutError as exc:
            raise TimeoutError(
                f"no connection to {self.host}:{self.port} within {self._connect_timeout} s"
            ) from exc
        self._reader, self._writer = reader, writer
        self.association.connection_reset()
        self.association.take()
        self.trace.reset(
            local=_address(writer.get_extra_info("sockname")),
            peer=_address(writer.get_extra_info("peername")),
        )
        self._receiving = asyncio.create_task(self._receive(), name=f"dnp3-master-{self.name}")
        logger.info("dnp3 master: connected to %s at %s:%d", self.name, self.host, self.port)
        self._notify_connection(True)
        # Queue the startup tasks for the new connection.
        self._housekeeper.connected()
        self._attention.clear()
        if self._housekeeper.due:
            self._settled.clear()
        self._housekeeping = asyncio.create_task(
            self._keep_house(), name=f"dnp3-master-{self.name}-tasks"
        )
        # Yield once so the task worker acquires the request lock first.
        # Requests made after this returns, including repeated scans, then
        # queue behind the startup tasks.
        await asyncio.sleep(0)
        for kind, interval in self._scan_intervals.items():
            self._start_scan(kind, interval)

    async def _stop_reconnecting(self) -> None:
        reconnecting, self._reconnecting = self._reconnecting, None
        if reconnecting is not None:
            # Wait for the cancellation, so an attempt in progress cannot
            # complete afterwards and open a second connection.
            reconnecting.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reconnecting

    def _stop_housekeeping(self) -> None:
        housekeeping, self._housekeeping = self._housekeeping, None
        if housekeeping is not None:
            housekeeping.cancel()
        # No tasks run without a connection, so release anyone in idle().
        # Set it here as well as in the worker: a worker cancelled before its
        # first run never reaches its own cleanup.
        self._settled.set()

    def _start_reconnecting(self) -> None:
        """Start the retry worker, unless reconnection is off or one is running."""
        if self.reconnect is not None and self._reconnecting is None:
            self._reconnecting = asyncio.create_task(
                self._reconnect(self.reconnect), name=f"dnp3-master-{self.name}-reconnect"
            )

    async def _reconnect(self, interval: float) -> None:
        report = RetryReport(self.name)
        while True:
            await asyncio.sleep(interval)
            try:
                await self._open()
            except OSError as exc:
                report.failed(exc)
                continue
            # The peer can close the new connection before _open() returns.
            # The receive loop does not start another worker while this one
            # is running, so keep retrying here.
            if self.connected:
                logger.info(
                    "dnp3 master: connected to %s again after %d failed attempt(s)",
                    self.name,
                    report.attempts,
                )
                self._reconnecting = None
                return
            logger.info("dnp3 master: %s closed the new connection at once", self.name)

    async def close(self) -> None:
        """Close the connection. The store and the association's counters stay."""
        await self._stop_reconnecting()
        self._stop_housekeeping()
        for task in self._scanning.values():
            task.cancel()
        self._scanning.clear()
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
                self.trace.record(RECEIVED, data)
                reply = self.association.receive(data)
                if reply:
                    self.trace.record(SENT, reply)
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
                self._stop_housekeeping()
                self._notify_connection(False)
                # The connection was lost, not closed by the caller: reconnect.
                self._start_reconnecting()
            self._progress.set()

    def _notify_connection(self, connected: bool) -> None:
        if self.on_connection is not None:
            try:
                self.on_connection(connected)
            except Exception:  # pylint: disable=broad-exception-caught
                logger.exception("dnp3 master: the connection handler for %s failed", self.name)

    def _deliver_unsolicited(self) -> None:
        for unsolicited in self.association.take_unsolicited():
            self.store.apply(unsolicited.objects, now=time.monotonic())
            self._unsolicited.append(unsolicited)
            self._note(unsolicited.iin)
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
            return await self._exchange_in_turn(function, body)

    async def _carry_out(self, plan: Plan) -> Operated:
        # One turn for the whole plan: an operate has to follow its select
        # with no other request between them, and a scan on a schedule would
        # otherwise be free to take the gap.
        async with self._turn:
            done: list[Exchange] = []
            while (step := plan.next(done)) is not None:
                done.append(await self._exchange_in_turn(*step))
            return plan.result(done)

    def _note(
        self, indications: IIN | None, answering: tuple[FunctionCode, bytes] | None = None
    ) -> None:
        """Pass a response's indications to the housekeeper and wake the worker."""
        self._housekeeper.saw(indications, answering=answering)
        if self._housekeeper.due and self._housekeeping is not None:
            self._settled.clear()
            self._attention.set()

    async def _keep_house(self) -> None:
        """Task worker: send the requests for pending tasks until disconnected."""
        try:
            while True:
                if self._housekeeper.due:
                    # Hold the request lock for the whole batch, so the
                    # startup sequence is not interleaved with other requests.
                    async with self._turn:
                        while (step := self._housekeeper.next()) is not None:
                            exchange = await self._exchange_in_turn(
                                step.function, step.body, task=step.task
                            )
                            if step.task in WRITING:
                                # A write the master made by itself is a command
                                # like any other, and goes in the log as one.
                                logger.info(
                                    "dnp3 master: automatic %s to %s: %s",
                                    step.task,
                                    self.name,
                                    exchange.outcome.value,
                                )
                self._settled.set()
                await self._attention.wait()
                self._attention.clear()
        except NotConnected:
            logger.info("dnp3 master: the tasks for %s stopped with the connection", self.name)
        except Exception:  # pylint: disable=broad-exception-caught
            # An unexpected error is a bug in this library. Log it and stop
            # the worker without dropping the connection.
            logger.exception("dnp3 master: the tasks for %s failed", self.name)
        finally:
            self._settled.set()

    async def _exchange_in_turn(
        self, function: FunctionCode, body: bytes, *, task: str | None = None
    ) -> Exchange:
        writer = self._writer
        if writer is None or writer.is_closing():
            raise NotConnected(f"{self.name} is not connected")
        self._progress.clear()
        octets = self.association.request(function, body)
        self.trace.record(SENT, octets)
        writer.write(octets)
        try:
            # A write that fails is seen by the receive loop as well, which
            # ends the exchange as abandoned.
            with contextlib.suppress(OSError):
                await writer.drain()
            while True:
                exchange = self.association.take()
                if exchange is not None:
                    if task is not None:
                        exchange = replace(exchange, task=task)
                    self._finished(exchange, body)
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
        except asyncio.CancelledError:
            # The caller cancelled while the request was in flight, for
            # example on its own timeout or when a repeated scan is
            # rescheduled. End the exchange as abandoned and record it.
            # Otherwise the association stays busy and rejects every later
            # request.
            self.association.abandon()
            given_up = self.association.take()
            if given_up is not None:
                self._finished(replace(given_up, task=task), body)
            raise

    def _finished(self, exchange: Exchange, body: bytes) -> None:
        self.store.apply(exchange.objects, now=time.monotonic())
        self._note(exchange.iin, (exchange.function, body))
        outcome = exchange.outcome.value
        self.counts[outcome] = self.counts.get(outcome, 0) + 1
        if exchange.fragments:
            self.last_response = exchange
            self.last_response_at = time.time()
        if self.on_exchange is not None:
            try:
                self.on_exchange(exchange)
            except Exception:  # pylint: disable=broad-exception-caught
                logger.exception("dnp3 master: the exchange handler for %s failed", self.name)

    # ----------------------------------------------------------------- scans

    @property
    def scan_intervals(self) -> dict[str, float]:
        """The scans being repeated, by kind, as seconds between them."""
        return dict(self._scan_intervals)

    def repeat_scan(self, kind: str, interval: float | None) -> None:
        """Repeat a scan every ``interval`` seconds, or stop repeating it with None.

        No scan is repeated unless this is called. A repeated scan waits its
        turn like any other request,
        stops when the connection ends, and starts again when it is made again.
        """
        requests.scan(kind)  # Refuses a kind that is not a scan, before anything runs.
        running = self._scanning.pop(kind, None)
        if running is not None:
            running.cancel()
        if interval is None:
            self._scan_intervals.pop(kind, None)
            return
        if not interval > 0:
            raise ValueError(f"an interval of {interval} is not a wait between scans")
        self._scan_intervals[kind] = interval
        if self.connected:
            self._start_scan(kind, interval)

    def _start_scan(self, kind: str, interval: float) -> None:
        running = self._scanning.pop(kind, None)
        if running is not None:
            running.cancel()
        self._scanning[kind] = asyncio.create_task(
            self._repeat(kind, interval), name=f"dnp3-master-{self.name}-{kind}"
        )

    async def _repeat(self, kind: str, interval: float) -> None:
        try:
            while True:
                await self.scan(kind)
                await asyncio.sleep(interval)
        except NotConnected:
            logger.info("dnp3 master: %s scan of %s stopped with the connection", kind, self.name)


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
