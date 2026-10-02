"""The retry timer reports. It never commands.

Unsolicited responses bring the library's first timer: a response that is not
confirmed is sent again when its time is up, and again after that. A master
that goes quiet therefore leaves the outstation doing something on a clock,
which it never did before, and `test_master_silence.py` is the promise that
none of that something touches an output. Those tests are unchanged and pass
as they are; this file holds the same promise with the feature switched on.

Three ways. The silence suite's own session tests run again here against
sessions built with unsolicited responses on, announced, every class enabled,
and the retry timer driven through every timeout the silence covers. Then
tests of the session that put a control behind a master that has stopped
answering and count the calls to the binding while the outstation retries
hundreds of times. And one through a real listener, where the timer is the
listener's own.
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest
import test_master_silence as silence
from profile_fixtures import small, units

from py1815 import link
from py1815.application import FunctionCode
from py1815.control import CommandStatus
from py1815.profile import load
from py1815.profile.binding import Binding
from py1815.profile.model import Kind
from py1815.profile.outstation import DerOutstation
from py1815.server import OutstationServer
from py1815.session import DEFAULT_UNSOLICITED_CONFIRM_TIMEOUT, Session
from py1815.transport import Reassembler, segment

OUTSTATION, MASTER = 1024, 1
TIMEOUT = DEFAULT_UNSOLICITED_CONFIRM_TIMEOUT
CLASSES = bytes([60, 2, 0x06, 60, 3, 0x06, 60, 4, 0x06])
A_DAY = 86_400.0


def _fragments(octets: bytes) -> list[bytes]:
    found, reassembler = [], Reassembler()
    for frame in link.FrameReader().feed(octets):
        whole = reassembler.add(frame.payload)
        if whole is not None:
            found.append(whole)
    return found


def _ready(session: Session) -> None:
    """Announced and confirmed, with every class enabled: a master that then goes quiet."""
    (null,) = _fragments(session.initiate())
    session._handle_fragment(bytes([0xD0 | (null[0] & 0x0F), FunctionCode.CONFIRM]))
    enabled = session._handle_fragment(bytes([0xCF, FunctionCode.ENABLE_UNSOLICITED]) + CLASSES)
    assert enabled[3] == 0


# --------------------------------------- the silence suite, with it switched on


class RetryingClock(silence.Clock):
    """The silence suite's clock, which drives the retry timer as it moves.

    Every time a test moves it on, each session built on it is asked for what
    it would send at every timeout in between, as a listener would ask. So
    the silences the suite covers are silences in which unsolicited
    responses are really being sent and really going unconfirmed.
    """

    def __init__(self) -> None:
        self.sessions: list[Session] = []
        self.asked = 0
        self.sent = 0
        self._now = 1000.0

    @property
    def now(self) -> float:
        return self._now

    @now.setter
    def now(self, value: float) -> None:
        while self._now + TIMEOUT < value:
            self._now += TIMEOUT
            self._ask()
        self._now = value
        self._ask()

    def _ask(self) -> None:
        for session in self.sessions:
            self.asked += 1
            self.sent += len(_fragments(session.initiate()))


@pytest.fixture
def retrying(monkeypatch):
    """Every session the silence suite builds has unsolicited responses on."""
    clocks: list[RetryingClock] = []
    built = DerOutstation.session

    def session(self, **options):
        options.setdefault("unsolicited", True)
        made = built(self, **options)
        clock = options.get("clock")
        if isinstance(clock, RetryingClock):
            _ready(made)
            clock.sessions.append(made)
        return made

    def clock_factory() -> RetryingClock:
        clock = RetryingClock()
        clocks.append(clock)
        return clock

    monkeypatch.setattr(DerOutstation, "session", session)
    monkeypatch.setattr(silence, "Clock", clock_factory)
    yield clocks
    assert any(clock.asked for clock in clocks), "the timer was driven"


@pytest.mark.usefixtures("retrying")
class TestTheSilenceSuiteWithUnsolicitedResponsesOn(silence.TestTheSessionAlone):
    """Every test of the silence suite's session class, run again with the timer on."""


def test_the_rerun_really_retried(retrying):
    """So that the class above cannot pass by never sending anything."""
    outstation, device, clock = silence._built()
    session = outstation.session(clock=clock)
    outstation.poll()
    session._handle_fragment(bytes([0xC0, FunctionCode.DIRECT_OPERATE]) + silence.SETPOINT)
    outstation.freeze_all()

    clock.now += A_DAY

    assert clock.sent > 1000, "a day of five-second retries"
    assert device.writes == [("setpoint", 12.5)]


# ------------------------------------------------------- the session alone


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Device:
    """A unit with a power reading that moves and two outputs that record writes."""

    def __init__(self) -> None:
        self.power = 1500.0
        self.writes: list[tuple[str, float]] = []

    def binding(self) -> Binding:
        binding = Binding()
        binding.read(Kind.AI, 1, lambda: self.power)
        binding.output(Kind.AO, 0, lambda value: self.writes.append(("setpoint", value)))
        binding.output(Kind.BO, 0, lambda value: self.writes.append(("widget", value)))
        return binding


class Guarded:
    """Wraps the outstation's control path so a call from the timer fails the test."""

    def __init__(self, inner: DerOutstation) -> None:
        self.inner = inner
        self.initiating = False
        self.calls = 0

    def select(self, controls):
        assert not self.initiating, "a control was selected from the retry path"
        self.calls += 1
        return self.inner.select(controls)

    def operate(self, controls):
        assert not self.initiating, "a control was operated from the retry path"
        self.calls += 1
        return self.inner.operate(controls)


def _built(**options) -> tuple[DerOutstation, Device, Clock, Session, Guarded]:
    device, clock = Device(), Clock()
    outstation = DerOutstation(
        load.resolve(small(), units(0)),
        device.binding(),
        strict=False,
        clock_ms=lambda: int(clock.now * 1000),
    )
    outstation.poll()
    guarded = Guarded(outstation)
    session = Session(
        outstation,
        control_provider=guarded,
        events=outstation.events,
        clock=clock,
        unsolicited=True,
        **options,
    )
    _ready(session)
    return outstation, device, clock, session, guarded


def _silence(session: Session, clock: Clock, guarded: Guarded, seconds: float) -> int:
    """Let time pass with no word from the master, as a listener would. Returns what was sent."""
    sent = 0
    end = clock.now + seconds
    while clock.now < end:
        clock.now = min(end, clock.now + TIMEOUT / 2)
        guarded.initiating = True
        try:
            sent += len(_fragments(session.initiate()))
        finally:
            guarded.initiating = False
    return sent


def _request(function: int, body: bytes = b"", sequence: int = 0) -> bytes:
    return bytes([0xC0 | sequence, function]) + body


class TestTheSessionWithTheTimerRunning:
    def test_a_setpoint_is_written_once_through_hundreds_of_retries(self):
        outstation, device, clock, session, guarded = _built()
        response = session._handle_fragment(_request(FunctionCode.DIRECT_OPERATE, silence.SETPOINT))
        assert CommandStatus(response[-1]) is CommandStatus.SUCCESS
        device.power = 2500.0
        outstation.poll()

        sent = _silence(session, clock, guarded, A_DAY / 24)

        assert sent > 600, "an hour of five-second retries, every one unconfirmed"
        assert device.writes == [("setpoint", 12.5)]
        assert guarded.calls == 1
        assert outstation.value(Kind.AO, 0) == 12.5

    def test_with_a_limit_and_a_resume_time_too(self):
        outstation, device, clock, session, guarded = _built(
            unsolicited_retries=2, unsolicited_resume=30.0
        )
        session._handle_fragment(_request(FunctionCode.DIRECT_OPERATE, silence.SETPOINT))
        device.power = 2500.0
        outstation.poll()

        sent = _silence(session, clock, guarded, A_DAY / 24)

        assert sent > 100, "series after series, each given up on"
        assert device.writes == [("setpoint", 12.5)]
        assert guarded.calls == 1

    def test_a_latch_is_operated_once(self):
        outstation, device, clock, session, guarded = _built()
        latch_on = bytes([12, 1, 0x17, 1, 0, 0x03, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        session._handle_fragment(_request(FunctionCode.DIRECT_OPERATE, latch_on))
        device.power = 2500.0
        outstation.poll()

        _silence(session, clock, guarded, A_DAY / 24)

        assert device.writes == [("widget", True)]
        assert outstation.value(Kind.BO, 0) is True

    def test_a_select_left_behind_is_never_operated(self):
        """The select expires; the retries go on; nothing acts on the reservation."""
        outstation, device, clock, session, guarded = _built()
        selected = session._handle_fragment(_request(FunctionCode.SELECT, silence.SETPOINT))
        assert CommandStatus(selected[-1]) is CommandStatus.SUCCESS
        device.power = 2500.0
        outstation.poll()

        assert _silence(session, clock, guarded, 600.0) > 50
        assert device.writes == []

        late = session._handle_fragment(_request(FunctionCode.OPERATE, silence.SETPOINT, 1))
        assert CommandStatus(late[-1]) is not CommandStatus.SUCCESS
        assert device.writes == []

    def test_a_read_held_behind_a_retry_is_answered_without_acting(self):
        """The one request the timer answers is a read, and a read is all it does."""
        outstation, device, clock, session, guarded = _built()
        session._handle_fragment(_request(FunctionCode.DIRECT_OPERATE, silence.SETPOINT))
        device.power = 2500.0
        outstation.poll()
        assert _fragments(session.initiate())
        held = session._handle_fragment(_request(FunctionCode.READ, silence.STATUS, 1))
        assert held == b""

        _silence(session, clock, guarded, 600.0)

        assert device.writes == [("setpoint", 12.5)]
        assert guarded.calls == 1

    def test_a_retried_operate_is_not_operated_again_by_the_timer(self):
        """D49 keeps a control's answer for its retry. The timer is no retry of it."""
        outstation, device, clock, session, guarded = _built()
        operate = _request(FunctionCode.DIRECT_OPERATE, silence.SETPOINT, 3)
        session._handle_fragment(operate)
        device.power = 2500.0
        outstation.poll()

        _silence(session, clock, guarded, 600.0)
        session._handle_fragment(operate)

        assert device.writes == [("setpoint", 12.5)], "the master's own retry is answered again"

    def test_a_restart_announced_into_silence_operates_nothing(self):
        _, device, clock, session, guarded = _built()
        session._handle_fragment(_request(FunctionCode.DIRECT_OPERATE, silence.SETPOINT))
        session.restart()

        assert _silence(session, clock, guarded, 600.0) > 100
        assert device.writes == [("setpoint", 12.5)]


# ------------------------------------------------------------ the listener


def _frames(fragment: bytes) -> bytes:
    control = link.control_byte(
        from_master=True, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
    )
    return b"".join(link.build(control, OUTSTATION, MASTER, part) for part in segment(fragment))


class _Wire:
    """The master's end of a connection: fragments in arrival order."""

    def __init__(self, reader: asyncio.StreamReader) -> None:
        self.reader = reader
        self.frames = link.FrameReader()
        self.reassembler = Reassembler()
        self.pending: list[bytes] = []

    async def next(self, timeout: float = 5.0) -> bytes:
        while not self.pending:
            data = await asyncio.wait_for(self.reader.read(4096), timeout=timeout)
            assert data, "the outstation closed the connection"
            for frame in self.frames.feed(data):
                whole = self.reassembler.add(frame.payload)
                if whole is not None:
                    self.pending.append(whole)
        return self.pending.pop(0)


@pytest.mark.asyncio
async def test_through_a_listener_retries_go_on_and_the_setpoint_is_written_once():
    device = Device()
    outstation = DerOutstation(load.resolve(small(), units(0)), device.binding(), strict=False)
    outstation.poll()
    session = outstation.session(
        outstation_address=OUTSTATION,
        master_address=MASTER,
        unsolicited=True,
        unsolicited_confirm_timeout=0.05,
    )
    server = OutstationServer(
        session, bind="127.0.0.1:0", idle_timeout=1.5, unsolicited_interval=0.02
    )
    await server.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        wire = _Wire(reader)
        null = await wire.next()
        writer.write(_frames(bytes([0xD0 | (null[0] & 0x0F), FunctionCode.CONFIRM])))
        writer.write(_frames(_request(FunctionCode.ENABLE_UNSOLICITED, CLASSES, 1)))
        writer.write(_frames(_request(FunctionCode.DIRECT_OPERATE, silence.SETPOINT, 2)))
        await writer.drain()

        device.power = 2500.0
        outstation.poll()
        server.notify()

        # Read until the listener gives up on a master that never answers.
        unsolicited = 0
        with contextlib.suppress(AssertionError, ConnectionError):
            while True:
                fragment = await wire.next()
                if fragment[1] == FunctionCode.UNSOLICITED_RESPONSE:
                    unsolicited += 1

        assert unsolicited > 5, "retried, unconfirmed, until the idle timeout"
        assert not writer.is_closing(), "and the close was the listener's"
        assert device.writes == [("setpoint", 12.5)]
        writer.close()
    finally:
        await server.stop()
    assert device.writes == [("setpoint", 12.5)]
