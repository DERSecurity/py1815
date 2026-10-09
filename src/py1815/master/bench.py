"""Checks of an outstation: what one is, how it is run, and what it reports.

A check is a short named procedure with a verdict. It is written once, as a
plan that yields one request at a time, so the same check runs against an
outstation on a socket and against a session in the same process. A check
fails by raising :class:`Failed` with what the outstation did, and is not
applicable when the outstation does not serve what it needs.

:class:`Bench` is what a check works with: the profile's point map, the
points the outstation serves, and the requests a check is made of. Each
request that is not answered fails the check. Nothing here knows any
particular check; the catalog is :mod:`py1815.master.checks`.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import inspect
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeVar

from py1815.control import CommandStatus
from py1815.master import controls
from py1815.master.association import Exchange
from py1815.master.controls import Command, Mode, Operated
from py1815.master.profile import (
    POINT_TYPES,
    Comparison,
    CurveWritten,
    DerProfile,
    Plan,
    Reading,
    Readings,
    address,
    carry_out,
    compare_plan,
    label,
    read_plan,
    survey_plan,
    write_curve_plan,
)
from py1815.objects import AnalogQuality
from py1815.profile.model import Address, Kind, Point

T = TypeVar("T")

#: Seconds a check waits for the outstation to reach a state it was commanded to.
DEFAULT_SETTLE = 5.0

#: Seconds between reads while a check waits.
POLL_SECONDS = 0.5

#: The flag bits of a binary point. The top bit is its state.
_BINARY_FLAGS = 0x7F


class Verdict(Enum):
    """How a check ended."""

    #: The outstation did everything the check requires.
    PASSED = "passed"
    #: The outstation did something the check does not allow.
    FAILED = "failed"
    #: The outstation does not serve what the check needs.
    NOT_APPLICABLE = "not_applicable"
    #: The check was not carried out.
    NOT_RUN = "not_run"


class Failed(Exception):
    """The outstation did something a check does not allow. The message says what."""


class Unanswered(Failed):
    """The outstation did not answer a request. Waiting and reading again will not help."""


class NotApplicable(Exception):
    """The outstation does not serve what a check needs. The message says what."""


class NoAnswer(RuntimeError):
    """The outstation answered nothing at all, so no check could be run."""


@dataclass(frozen=True)
class Pause:
    """A step of a plan that waits and sends nothing."""

    seconds: float

    def __call__(self, target: Any) -> None:
        """Do nothing: a driver that knows no waits carries on at once."""


@dataclass(frozen=True)
class Check:
    """One named procedure."""

    #: A short identifier, as in ``MON-001``.
    id: str
    title: str
    #: Whether the check writes to the outstation.
    commands: bool
    procedure: Callable[[Bench], Plan[None]]
    #: The set the check belongs to.
    group: str = "der"


@dataclass(frozen=True)
class Result:
    """How one check ended."""

    id: str
    title: str
    verdict: Verdict
    #: Why the check failed, was not applicable or was not run. Empty when it passed.
    detail: str = ""
    #: What the check saw that a reader of the report should know.
    notes: tuple[str, ...] = ()
    #: Requests the check sent.
    requests: int = 0
    seconds: float = 0.0
    #: The ids of the first and last frame of the check in the master's
    #: trace, which counts DNP3 frames from 1. None when the check sent
    #: nothing or the master keeps no trace.
    frames: tuple[int, int] | None = None
    #: The numbers of the first and last packet of the check in the capture
    #: file, counted from 1 as Wireshark counts them. A capture also holds
    #: each connection's handshake, so these are not the frame ids. None when
    #: no capture is written or the check sent nothing.
    packets: tuple[int, int] | None = None

    def describe(self) -> dict[str, Any]:
        """Return the result as a JSON-compatible dict."""
        return {
            "id": self.id,
            "title": self.title,
            "verdict": self.verdict.value,
            "detail": self.detail,
            "notes": list(self.notes),
            "requests": self.requests,
            "seconds": round(self.seconds, 3),
            "frames": None if self.frames is None else list(self.frames),
            "packets": None if self.packets is None else list(self.packets),
        }


def name(point: Point) -> str:
    """Return a point's address and name, as in ``AO87 (Charging limit)``."""
    return f"{address(point)} ({label(point)})"


def _flags(reading: Reading) -> int | None:
    """Return a reading's quality flags without a binary point's state bit."""
    if reading.flags is None:
        return None
    if reading.point.kind in (Kind.BI, Kind.BO):
        return reading.flags & _BINARY_FLAGS
    return reading.flags


class Bench:
    """What a check works with.

    Every method that sends a request is a plan: call it with ``yield from``.
    A request the outstation does not answer raises :class:`Unanswered`.
    """

    def __init__(
        self,
        profile: DerProfile,
        *,
        settle: float = DEFAULT_SETTLE,
        curves: int | None = None,
        device_profile: str | None = None,
        capture: Any = None,
    ) -> None:
        """
        Args:
            profile: The point map the outstation is checked against.
            settle: Seconds to wait for the outstation to reach a state it
                was commanded to.
            curves: How many curves the outstation stores, or None to find out
                by selecting each in turn.
            device_profile: The text of the outstation's Device Profile
                document, or None when there is none.
            capture: The :class:`~py1815.master.capture.Capture` the run's
                frames are written to, or None. Each result then gives the
                numbers of its packets in it.
        """
        self.capture = capture
        self.profile = profile
        self.map = profile.map
        self.settle = settle
        self.curves = curves
        self.device_profile = device_profile
        #: The points the outstation reported when the run began.
        self.served: frozenset[Address] = frozenset()
        #: A title for the check being run that says more than the catalog's.
        self.title: str | None = None
        self.requests = 0
        self._notes: list[str] = []
        self._afterwards: list[tuple[str, Callable[[], Plan[Any]]]] = []

    # ------------------------------------------------------------ a check's own

    def begin(self) -> None:
        """Forget what the last check noted, counted and left to be put back."""
        self.title = None
        self.requests = 0
        self._notes = []
        self._afterwards = []

    def note(self, text: str) -> None:
        """Record something the report should say about this check."""
        if text not in self._notes:
            self._notes.append(text)

    @property
    def notes(self) -> tuple[str, ...]:
        return tuple(self._notes)

    @staticmethod
    def require(holds: object, otherwise: str) -> None:
        """Fail the check with ``otherwise`` unless ``holds``."""
        if not holds:
            raise Failed(otherwise)

    def afterwards(self, what: str, plan: Callable[[], Plan[Any]]) -> None:
        """Have ``plan`` carried out when the check ends, however it ends.

        A check uses this to put back what it changed. The plans are carried
        out last one first.
        """
        self._afterwards.append((what, plan))

    def put_back(self) -> Plan[None]:
        """Carry out what the check left to be done afterwards."""
        while self._afterwards:
            what, plan = self._afterwards.pop()
            try:
                yield from plan()
            except Failed as failure:
                self.note(f"{what} could not be put back: {failure}")

    # ---------------------------------------------------------------- serving

    def supported(self, kind: Kind, index: int) -> bool:
        """Return whether the outstation serves a point."""
        return (kind, index) in self.served

    def supported_in(self, kind: Kind, indices: Sequence[int]) -> list[Point]:
        """Return the points of one kind the outstation serves among ``indices``."""
        return [self.map.point(kind, i) for i in indices if self.supported(kind, i)]

    def readback(self, output: Point) -> Point | None:
        """Return the input that reads an output back, or None when none is served."""
        mirror = self.profile.mirror(output)
        if mirror is None or mirror.address not in self.served:
            return None
        return mirror

    # ---------------------------------------------------------------- reading

    def _made(self, exchanges: Sequence[Exchange], what: str) -> None:
        self.requests += len(exchanges)
        for exchange in exchanges:
            if not exchange.fragments:
                raise Unanswered(f"the outstation did not answer {what}")

    def read(self, points: Sequence[Point]) -> Plan[Readings]:
        """Read points in one request."""
        readings: Readings = yield from read_plan(points)
        listed = ", ".join(address(point) for point in points[:4])
        more = f" and {len(points) - 4} more" if len(points) > 4 else ""
        self._made(readings.exchanges, f"a read of {listed}{more}")
        return readings

    def obtain(self, point: Point) -> Plan[Reading]:
        """Read one point and require the outstation to report it."""
        readings = yield from self.read([point])
        reading = readings.readings[0]
        self.require(reading.reported, f"{name(point)} could not be read")
        return reading

    def online(self, point: Point) -> Plan[Reading]:
        """Read a point and require it to be ONLINE with no other quality flag.

        A variation that carries no flags says the same thing.
        """
        reading = yield from self.obtain(point)
        flags = _flags(reading)
        self.require(
            flags is None or flags == AnalogQuality.ONLINE,
            f"{name(point)} is reported with flags 0x{flags or 0:02X}, and not as ONLINE alone",
        )
        return reading

    def offline(self, point: Point) -> Plan[Reading]:
        """Read a point and require it to carry a value and no quality flag at all."""
        reading = yield from self.obtain(point)
        flags = _flags(reading)
        said = "no flags, which says ONLINE" if flags is None else f"flags 0x{flags:02X}"
        self.require(flags == 0, f"{name(point)} is reported with {said}, and not as offline")
        return reading

    def state(self, point: Point) -> Plan[bool]:
        """Return a binary point's state, which is required to be ONLINE."""
        reading = yield from self.online(point)
        return bool(reading.raw)

    def value(self, point: Point) -> Plan[float]:
        """Return an analog point's value in engineering units, required to be ONLINE."""
        reading = yield from self.online(point)
        return self._engineering(reading)

    def raw(self, point: Point) -> Plan[float]:
        """Return an analog point's value in engineering units, whatever its flags say."""
        reading = yield from self.obtain(point)
        return self._engineering(reading)

    @staticmethod
    def _engineering(reading: Reading) -> float:
        value = reading.value
        if value is None or isinstance(value, bool):
            raise Failed(f"{name(reading.point)} did not report a number")
        return float(value)

    # ---------------------------------------------------------------- writing

    def _operate(self, commands: Sequence[Command], mode: Mode, what: str) -> Plan[CommandStatus]:
        operated: Operated = yield carry_out(controls.Plan(commands, mode))
        self._made(operated.exchanges, what)
        answered = operated.statuses[0]
        if answered.status is None:
            raise Failed(f"the response to {what} did not carry the control back")
        if answered.status is CommandStatus.SUCCESS and not answered.echoed:
            raise Failed(f"the response to {what} carried back a different control")
        return answered.status

    def set(self, output: Point | int, raw: int) -> Plan[CommandStatus]:
        """Direct operate one analog output with a transmitted value. Return the status."""
        index = output if isinstance(output, int) else output.index
        status = yield from self._operate(
            [controls.analog(index, raw)], Mode.DIRECT, f"a write of {raw} to AO{index}"
        )
        return status

    def latch(self, output: Point | int, on: bool) -> Plan[CommandStatus]:
        """Select and then operate a latch of one binary output. Return the status.

        The status is the select's when the outstation refused the select.
        """
        index = output if isinstance(output, int) else output.index
        status = yield from self._operate(
            [controls.binary(index, on)],
            Mode.SELECT,
            f"a latch {'on' if on else 'off'} of BO{index}",
        )
        return status

    def accepted(self, status: CommandStatus, what: str) -> None:
        """Fail the check unless the outstation accepted a control."""
        self.require(
            status is CommandStatus.SUCCESS, f"{what} was refused with status {status.name}"
        )

    def refused(self, status: CommandStatus, what: str, usual: CommandStatus) -> None:
        """Fail the check if the outstation accepted a control it is to refuse.

        A refusal with a status other than ``usual`` is noted and not failed:
        which status refuses a control is the outstation's to choose.
        """
        self.require(status is not CommandStatus.SUCCESS, f"{what} was accepted")
        if status is not usual:
            self.note(f"{what} was refused with {status.name}, where {usual.name} is usual")

    def write_curve(
        self,
        number: int,
        *,
        type: int,  # pylint: disable=redefined-builtin
        x_units: int,
        y_units: int,
        points: Sequence[Sequence[int]],
    ) -> Plan[CurveWritten]:
        """Write a curve in the profile's three steps and read it back."""
        written: CurveWritten = yield from write_curve_plan(
            self.profile, number, type=type, x_units=x_units, y_units=y_units, points=points
        )
        what = f"the write of curve {number}"
        for step in written.steps:
            self._made(step.exchanges, what)
        for read in written.readback.reads:
            self._made(read.exchanges, f"the read of curve {number}")
        return written

    def compare(self, document: str) -> Plan[Comparison]:
        """Compare what the outstation serves with a Device Profile document."""
        comparison: Comparison = yield from compare_plan(document)
        self._made(comparison.exchanges, "the reads of the points its Device Profile declares")
        return comparison

    # ---------------------------------------------------------------- waiting

    def pause(self, seconds: float) -> Plan[None]:
        """Wait, sending nothing."""
        yield Pause(seconds)

    def eventually(self, attempt: Callable[[], Plan[T]]) -> Plan[T]:
        """Carry out ``attempt`` until it does not fail, for up to the settling time.

        For what an outstation takes time to do: a read that finds it not yet
        done is made again every half second. The last failure stands. A
        request that is not answered is not made again.
        """
        waited = 0.0
        while True:
            try:
                return (yield from attempt())
            except Unanswered:
                raise
            except Failed:
                if waited >= self.settle:
                    raise
            step = min(POLL_SECONDS, self.settle - waited)
            yield from self.pause(step)
            waited += step

    def becomes(self, point: Point, state: bool, said: str) -> Plan[None]:
        """Wait until a binary point reports ``state`` ONLINE, or fail with ``said``."""

        def attempt() -> Plan[None]:
            now = yield from self.state(point)
            self.require(now is state, f"{said}: {name(point)} did not become {state}")

        yield from self.eventually(attempt)


# ---------------------------------------------------------------- the run


#: What a carrier raises when its connection is gone.
_LOST = (OSError,)


def _last_frame(target: Any) -> int | None:
    trace = getattr(target, "trace", None)
    return None if trace is None else int(trace.last_id)


def _last_packet(bench: Bench) -> int | None:
    return None if bench.capture is None else int(bench.capture.packets)


def _span(first: int | None, last: int | None) -> tuple[int, int] | None:
    """Return the numbers after ``first`` up to ``last``, or None when there are none."""
    if first is None or last is None or last <= first:
        return None
    return first + 1, last


@dataclass
class _Run:
    """The state of a run that outlives one check."""

    #: Why the rest of the checks cannot be run, once that is so.
    lost: str | None = None
    results: list[Result] = field(default_factory=list)


def run_plan(
    bench: Bench, checks: Sequence[Check], *, commanding: bool
) -> Plan[tuple[Result, ...]]:
    """Carry out checks in order, and return how each ended.

    The run begins by reading which points the outstation serves. A check
    that writes is not run unless ``commanding`` is set. When the connection
    is lost the check under way fails and the rest are not run.

    Raises :class:`NoAnswer` when the outstation does not answer the first read.
    """
    wanted = [(POINT_TYPES[point.kind], point.index) for point in bench.map.points.values()]
    try:
        survey = yield from survey_plan(wanted)
    except _LOST as error:
        raise NoAnswer(f"the connection was lost: {error}") from error
    if not survey.exchanges[0].fragments:
        raise NoAnswer("the outstation did not answer a class 0 read")
    if any(not exchange.fragments for exchange in survey.exchanges):
        # A point missing because a read went unanswered would be taken as
        # a point the outstation does not serve.
        raise NoAnswer("the outstation did not answer every read of the points it serves")
    kinds = {point_type: kind for kind, point_type in POINT_TYPES.items()}
    bench.served = frozenset(
        (kinds[point_type], index) for point_type, index in survey.served if point_type in kinds
    )

    run = _Run()
    for check in checks:
        if run.lost is not None:
            run.results.append(Result(check.id, check.title, Verdict.NOT_RUN, run.lost))
        elif check.commands and not commanding:
            run.results.append(
                Result(
                    check.id,
                    check.title,
                    Verdict.NOT_RUN,
                    "it writes to the outstation, and the run was not allowed to",
                )
            )
        else:
            run.results.append((yield from _one(bench, check, run)))
    return tuple(run.results)


def _one(bench: Bench, check: Check, run: _Run) -> Plan[Result]:
    bench.begin()
    first: int | None = yield _last_frame
    first_packet = _last_packet(bench)
    started = time.monotonic()
    verdict, detail = Verdict.PASSED, ""
    try:
        yield from check.procedure(bench)
    except NotApplicable as reason:
        verdict, detail = Verdict.NOT_APPLICABLE, str(reason)
    except Failed as failure:
        verdict, detail = Verdict.FAILED, str(failure)
    except _LOST as error:
        verdict, detail = Verdict.FAILED, f"the connection was lost: {error}"
        run.lost = "the connection was lost during an earlier check"
    if run.lost is None:
        try:
            yield from bench.put_back()
        except _LOST as error:
            said = f"the connection was lost before everything was put back: {error}"
            if verdict is Verdict.FAILED:
                # Keep why the check failed, and say this as well.
                bench.note(said)
            else:
                verdict, detail = Verdict.FAILED, said
            run.lost = "the connection was lost during an earlier check"
    last: int | None = yield _last_frame
    return Result(
        id=check.id,
        title=bench.title or check.title,
        verdict=verdict,
        detail=detail,
        notes=bench.notes,
        requests=bench.requests,
        seconds=time.monotonic() - started,
        frames=_span(first, last),
        packets=_span(first_packet, _last_packet(bench)),
    )


def drive(target: Any, plan: Plan[T], pause: Callable[[float], None]) -> T:
    """Carry out a plan on a master whose requests return at once, as a Loopback's do.

    ``pause`` is called with the seconds of each wait in the plan.
    """
    try:
        step = next(plan)
        while True:
            try:
                answer: Any = None
                if isinstance(step, Pause):
                    pause(step.seconds)
                else:
                    answer = step(target)
            except _LOST as error:
                step = plan.throw(error)
            else:
                step = plan.send(answer)
    except StopIteration as done:
        return done.value  # type: ignore[no-any-return]


async def drive_async(target: Any, plan: Plan[T], pause: Callable[[float], Awaitable[None]]) -> T:
    """Carry out a plan on a master whose requests are awaited, as an Outstation's are.

    ``pause`` is awaited with the seconds of each wait in the plan.
    """
    try:
        step = next(plan)
        while True:
            try:
                answer: Any = None
                if isinstance(step, Pause):
                    await pause(step.seconds)
                else:
                    answer = step(target)
                    if inspect.isawaitable(answer):
                        answer = await answer
            except _LOST as error:
                step = plan.throw(error)
            else:
                step = plan.send(answer)
    except StopIteration as done:
        return done.value  # type: ignore[no-any-return]


__all__ = [
    "DEFAULT_SETTLE",
    "Bench",
    "Check",
    "Failed",
    "NoAnswer",
    "NotApplicable",
    "Pause",
    "Result",
    "Unanswered",
    "Verdict",
    "drive",
    "drive_async",
    "name",
    "run_plan",
]
