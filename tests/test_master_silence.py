"""When a master goes quiet, nothing happens to what it commanded.

An outstation that relays commands to a device holds no opinion about what the
device should do when the master stops talking. The last value written stays
in force until a master writes another; whether to fall back, and to what, is
the device's own controller's to decide and never this library's. So there is
no timeout here that changes an output, and no fallback is applied.

These tests pin that. Each one commands an output, then lets time pass with no
request, in every way the library experiences silence: the session's clock
moving on, the caller's own loop continuing to poll and freeze, and the
listener closing a connection it has heard nothing on. Afterwards the binding
has been called exactly once, and the output stands where the master left it.

A timer added later, for unsolicited reporting or anything else, has to leave
these passing.
"""

from __future__ import annotations

import asyncio

import pytest
from profile_fixtures import small, units

from py1815 import link
from py1815.application import FunctionCode, QualifierCode
from py1815.control import CommandStatus
from py1815.profile import load
from py1815.profile.binding import Binding
from py1815.profile.model import Kind
from py1815.profile.outstation import DerOutstation
from py1815.profile.probe import parse_objects
from py1815.server import OutstationServer
from py1815.transport import Reassembler, segment

OUTSTATION, MASTER = 1024, 1
ALL = QualifierCode.ALL_OBJECTS
#: A 16-bit setpoint of 125 on analog output 0, which the tables scale to 12.5.
SETPOINT = bytes([41, 2, 0x17, 1, 0]) + (125).to_bytes(2, "little", signed=True) + b"\x00"
STATUS = bytes([40, 0, ALL])
A_DAY = 86_400.0


class Clock:
    """Seconds that pass only when a test says so."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Device:
    """Records every write, so a write nobody commanded cannot go unseen."""

    def __init__(self) -> None:
        self.writes: list[tuple[str, float]] = []

    def binding(self) -> Binding:
        binding = Binding()
        binding.read(Kind.AI, 1, lambda: 1500.0)
        binding.read(Kind.CTR, 0, lambda: 10.0)
        binding.output(Kind.AO, 0, lambda value: self.writes.append(("setpoint", value)))
        binding.output(Kind.BO, 0, lambda value: self.writes.append(("widget", value)))
        return binding


def _built() -> tuple[DerOutstation, Device, Clock]:
    device, clock = Device(), Clock()
    outstation = DerOutstation(
        load.resolve(small(), units(0)),
        device.binding(),
        strict=False,
        clock_ms=lambda: int(clock.now * 1000),
    )
    return outstation, device, clock


def _request(function: FunctionCode, body: bytes, sequence: int = 0) -> bytes:
    return bytes([0xC0 | sequence, function]) + body


def _status(response: bytes) -> float:
    static, _ = parse_objects(response[4:])
    (value,) = [v.value for v in static if (v.group, v.index) == (40, 0)]
    return value


class TestTheSessionAlone:
    def test_a_setpoint_outlives_any_amount_of_silence(self):
        outstation, device, clock = _built()
        session = outstation.session(clock=clock)
        response = session._handle_fragment(_request(FunctionCode.DIRECT_OPERATE, SETPOINT))
        assert CommandStatus(response[-1]) is CommandStatus.SUCCESS
        assert device.writes == [("setpoint", 12.5)]

        clock.now += A_DAY

        assert device.writes == [("setpoint", 12.5)], "nothing was written in the silence"
        assert outstation.value(Kind.AO, 0) == 12.5
        assert _status(session._handle_fragment(_request(FunctionCode.READ, STATUS, 1))) == 125

    def test_the_callers_own_loop_changes_nothing_either(self):
        """Polling for events and freezing counters go on while the master is away."""
        outstation, device, clock = _built()
        session = outstation.session(clock=clock)
        session._handle_fragment(_request(FunctionCode.DIRECT_OPERATE, SETPOINT))
        for _ in range(48):
            clock.now += A_DAY / 48
            outstation.poll()
            outstation.freeze_all()
        assert device.writes == [("setpoint", 12.5)]
        assert outstation.value(Kind.AO, 0) == 12.5

    def test_a_dropped_connection_changes_nothing(self):
        """What the listener does to a connection that has gone quiet."""
        outstation, device, clock = _built()
        session = outstation.session(clock=clock)
        session._handle_fragment(_request(FunctionCode.DIRECT_OPERATE, SETPOINT))
        clock.now += A_DAY
        session.connection_reset()
        assert device.writes == [("setpoint", 12.5)]
        assert _status(session._handle_fragment(_request(FunctionCode.READ, STATUS, 1))) == 125

    def test_a_select_left_to_expire_operates_nothing(self):
        """The one timer the session has ends a reservation. It does not act on one."""
        outstation, device, clock = _built()
        session = outstation.session(clock=clock, select_timeout=10.0)
        selected = session._handle_fragment(_request(FunctionCode.SELECT, SETPOINT))
        assert CommandStatus(selected[-1]) is CommandStatus.SUCCESS
        clock.now += A_DAY
        outstation.poll()
        assert device.writes == []
        late = session._handle_fragment(_request(FunctionCode.OPERATE, SETPOINT, 1))
        assert CommandStatus(late[-1]) is not CommandStatus.SUCCESS
        assert device.writes == [], "and the operate that arrives too late is refused"

    def test_a_latched_output_stays_latched(self):
        outstation, device, clock = _built()
        session = outstation.session(clock=clock)
        latch_on = bytes([12, 1, 0x17, 1, 0, 0x03, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        response = session._handle_fragment(_request(FunctionCode.DIRECT_OPERATE, latch_on))
        assert CommandStatus(response[-1]) is CommandStatus.SUCCESS
        clock.now += A_DAY
        outstation.poll()
        session.connection_reset()
        assert device.writes == [("widget", True)]
        assert outstation.value(Kind.BO, 0) is True


def _frames(fragment: bytes) -> bytes:
    control = link.control_byte(
        from_master=True, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
    )
    return b"".join(link.build(control, OUTSTATION, MASTER, part) for part in segment(fragment))


async def _exchange(port: int, fragment: bytes) -> tuple[bytes, asyncio.StreamReader]:
    """Send one request over a new connection and return its response and the reader."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(_frames(fragment))
    await writer.drain()
    frames, reassembler = link.FrameReader(), Reassembler()
    while True:
        data = await asyncio.wait_for(reader.read(4096), timeout=5)
        assert data, "the outstation closed the connection before answering"
        for frame in frames.feed(data):
            whole = reassembler.add(frame.payload)
            if whole is not None:
                return whole, reader


class TestThroughTheListener:
    @pytest.mark.asyncio
    async def test_an_idle_connection_is_closed_and_the_setpoint_stands(self):
        """The whole path: a master commands, says nothing, and is disconnected."""
        outstation, device, _ = _built()
        session = outstation.session(outstation_address=OUTSTATION, master_address=MASTER)
        server = OutstationServer(session, bind="127.0.0.1:0", idle_timeout=0.2)
        await server.start()
        try:
            response, reader = await _exchange(
                server.port, _request(FunctionCode.DIRECT_OPERATE, SETPOINT)
            )
            assert CommandStatus(response[-1]) is CommandStatus.SUCCESS

            closed = await asyncio.wait_for(reader.read(4096), timeout=5)
            assert closed == b"", "the listener gave up on the silent connection"
            assert device.writes == [("setpoint", 12.5)]

            again, _ = await _exchange(server.port, _request(FunctionCode.READ, STATUS, 1))
            assert _status(again) == 125
        finally:
            await server.stop()
        assert device.writes == [("setpoint", 12.5)]
