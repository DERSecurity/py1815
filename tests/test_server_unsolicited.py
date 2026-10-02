"""The listener drives unsolicited responses, so that a caller writes no loop.

The session does no I/O and starts no timer: something has to ask it whether
anything is due and put what it says on the wire. For a session built with
unsolicited responses on, `OutstationServer` does that, beside the loop that
reads requests, for as long as the connection that is the master lasts. For
any other session it does nothing it did not do before.

These run over real sockets on the loopback interface, with short timeouts so
that the waiting is measured in tenths of a second.
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest

from py1815 import link
from py1815.application import FunctionCode
from py1815.events import EventBuffers, EventClass
from py1815.objects import AnalogPoint
from py1815.server import OutstationServer
from py1815.session import Session
from py1815.transport import Reassembler, segment

OUTSTATION, MASTER = 1024, 1
CLASS_1 = bytes([60, 2, 0x06])
STATIC = bytes([30, 1, 0x00, 0, 0, 0x01, 0x2A, 0, 0, 0])


class Reader:
    def read(self, headers):
        return STATIC


def _frames(fragment: bytes) -> bytes:
    control = link.control_byte(
        from_master=True, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
    )
    return b"".join(link.build(control, OUTSTATION, MASTER, part) for part in segment(fragment))


def _request(function: int, body: bytes = b"", sequence: int = 0) -> bytes:
    return bytes([0xC0 | sequence, function]) + body


def _confirm_unsolicited(fragment: bytes) -> bytes:
    return _frames(bytes([0xD0 | (fragment[0] & 0x0F), FunctionCode.CONFIRM]))


class Master:
    """The master's end of one connection."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader, self.writer = reader, writer
        self._frames = link.FrameReader()
        self._reassembler = Reassembler()
        self._pending: list[bytes] = []

    @classmethod
    async def connect(cls, port: int) -> Master:
        return cls(*await asyncio.open_connection("127.0.0.1", port))

    async def send(self, octets: bytes) -> None:
        self.writer.write(octets)
        await self.writer.drain()

    async def next(self, timeout: float = 5.0) -> bytes:
        """The next whole fragment the outstation sends."""
        while not self._pending:
            data = await asyncio.wait_for(self.reader.read(4096), timeout=timeout)
            assert data, "the outstation closed the connection"
            for frame in self._frames.feed(data):
                assert (frame.destination, frame.source) == (MASTER, OUTSTATION)
                whole = self._reassembler.add(frame.payload)
                if whole is not None:
                    self._pending.append(whole)
        return self._pending.pop(0)

    async def nothing(self, seconds: float) -> None:
        """Assert that the outstation says nothing for a while."""
        if self._pending:
            raise AssertionError(f"the outstation sent {self._pending[0].hex()}")
        try:
            data = await asyncio.wait_for(self.reader.read(4096), timeout=seconds)
        except TimeoutError:
            return
        raise AssertionError(f"the outstation sent {data.hex()} or closed")

    async def until_closed(self, timeout: float = 5.0) -> list[bytes]:
        """Every fragment that arrives until the outstation ends the connection."""
        received: list[bytes] = []
        while True:
            try:
                received.append(await self.next(timeout=timeout))
            except (AssertionError, ConnectionError):
                return received

    async def close(self) -> None:
        self.writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self.writer.wait_closed(), timeout=2)


def _session(buffers: EventBuffers | None = None, **options) -> Session:
    options.setdefault("unsolicited", True)
    return Session(
        Reader(),
        events=buffers,
        outstation_address=OUTSTATION,
        master_address=MASTER,
        **options,
    )


async def _started(session: Session, **options) -> OutstationServer:
    server = OutstationServer(session, bind="127.0.0.1:0", **options)
    await server.start()
    return server


async def _announced(master: Master) -> None:
    null = await master.next()
    assert null[1] == FunctionCode.UNSOLICITED_RESPONSE and len(null) == 4
    await master.send(_confirm_unsolicited(null))


def _event(buffers: EventBuffers, index: int = 3) -> None:
    buffers.record_analog(
        index, AnalogPoint(float(index)), event_class=EventClass.CLASS_1, timestamp_ms=1
    )


@pytest.mark.asyncio
async def test_a_master_enables_a_class_and_an_event_arrives_unasked_and_is_confirmed():
    buffers = EventBuffers()
    session = _session(buffers)
    server = await _started(session)
    try:
        master = await Master.connect(server.port)
        await _announced(master)
        await master.send(_frames(_request(FunctionCode.ENABLE_UNSOLICITED, CLASS_1, 1)))
        assert await master.next() == bytes.fromhex("c1818000")

        _event(buffers)
        server.notify()
        fragment = await master.next()

        assert fragment == bytes.fromhex("f182800020031701030103000000010000000000")
        await master.send(_confirm_unsolicited(fragment))
        await master.nothing(0.3)
        assert buffers.total == 0, "retired by the confirmation"
        await master.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_the_restart_is_announced_as_soon_as_the_master_connects():
    server = await _started(_session())
    try:
        master = await Master.connect(server.port)

        assert await master.next(timeout=2) == bytes.fromhex("f0828000")
        await master.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_a_session_without_them_sends_nothing_unasked():
    buffers = EventBuffers()
    _event(buffers)
    server = await _started(_session(buffers, unsolicited=False), unsolicited_interval=0.01)
    try:
        master = await Master.connect(server.port)
        await master.nothing(0.5)

        await master.send(_frames(_request(FunctionCode.READ, bytes([60, 1, 0x06]))))
        assert (await master.next())[4:] == STATIC, "and answers as it always did"
        await master.nothing(0.3)
        await master.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_an_event_recorded_without_notify_is_found_at_the_interval():
    buffers = EventBuffers()
    server = await _started(_session(buffers), unsolicited_interval=0.05)
    try:
        master = await Master.connect(server.port)
        await _announced(master)
        await master.send(_frames(_request(FunctionCode.ENABLE_UNSOLICITED, CLASS_1, 1)))
        await master.next()

        _event(buffers)

        fragment = await master.next(timeout=2)
        assert fragment[1] == FunctionCode.UNSOLICITED_RESPONSE
        await master.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_notify_reports_at_once_whatever_the_interval():
    buffers = EventBuffers()
    server = await _started(_session(buffers), unsolicited_interval=60.0)
    try:
        master = await Master.connect(server.port)
        await _announced(master)
        await master.send(_frames(_request(FunctionCode.ENABLE_UNSOLICITED, CLASS_1, 1)))
        await master.next()

        _event(buffers)
        server.notify()

        fragment = await master.next(timeout=2)
        assert fragment[1] == FunctionCode.UNSOLICITED_RESPONSE
        await master.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_a_retry_comes_at_the_sessions_own_time_whatever_the_interval():
    server = await _started(_session(unsolicited_confirm_timeout=0.2), unsolicited_interval=60.0)
    try:
        master = await Master.connect(server.port)
        first = await master.next()
        loop = asyncio.get_running_loop()
        started = loop.time()

        again = await master.next(timeout=2)

        assert again == first, "the null response again, unconfirmed"
        assert 0.15 <= loop.time() - started < 1.5
        await master.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_a_held_read_is_answered_on_the_wire_when_the_confirmation_comes():
    buffers = EventBuffers()
    server = await _started(_session(buffers))
    try:
        master = await Master.connect(server.port)
        null = await master.next()
        await master.send(_frames(_request(FunctionCode.READ, bytes([60, 1, 0x06]), 4)))
        await master.nothing(0.2)

        await master.send(_confirm_unsolicited(null))

        answer = await master.next()
        assert answer[:2] == bytes([0xC4, FunctionCode.RESPONSE])
        assert answer[4:] == STATIC
        await master.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_a_new_connection_is_told_and_the_old_one_hears_no_more():
    buffers = EventBuffers()
    server = await _started(
        _session(buffers, unsolicited_confirm_timeout=0.1), unsolicited_interval=0.02
    )
    try:
        first = await Master.connect(server.port)
        await first.next()

        second = await Master.connect(server.port)
        assert (await second.next())[1:] == bytes([0x82, 0x80, 0]), "announced to the new master"

        # The displaced connection is closed. Whatever it had already been sent
        # is drained, and then it ends rather than going on being retried at.
        drained = await first.until_closed(timeout=2)
        assert len(drained) < 5
        assert all(fragment[1] == FunctionCode.UNSOLICITED_RESPONSE for fragment in drained)
        await second.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_the_idle_timeout_still_ends_a_silent_master():
    """What the outstation sends is not the master being present."""
    server = await _started(
        _session(unsolicited_confirm_timeout=0.05), idle_timeout=0.5, unsolicited_interval=0.02
    )
    try:
        master = await Master.connect(server.port)
        sent = await master.until_closed(timeout=3)
        assert len(sent) > 3, "retried while the connection lasted"
        assert not server.connected
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_a_failure_while_initiating_ends_the_connection_and_not_the_listener():
    session = _session()
    server = await _started(session)

    def broken() -> bytes:
        raise RuntimeError("the session could not say")

    original = session.initiate
    session.initiate = broken  # type: ignore[method-assign]
    try:
        master = await Master.connect(server.port)
        assert await master.until_closed(timeout=3) == []

        session.initiate = original  # type: ignore[method-assign]
        again = await Master.connect(server.port)
        assert (await again.next())[1] == FunctionCode.UNSOLICITED_RESPONSE
        await again.close()
    finally:
        await server.stop()


def test_an_interval_that_is_no_wait_is_refused():
    with pytest.raises(ValueError, match="unsolicited_interval"):
        OutstationServer(_session(), unsolicited_interval=0)
