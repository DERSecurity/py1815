"""The IEEE 1815.2 DER profile, from the master's side.

``py1815.profile`` resolves the profile's tables into a point map: each point's
name, units, multiplier, range and section, which output enables a function and
which input says it is supported. :class:`DerProfile` reads that map the other
way round, for a master: it finds a point by its name, groups points by what
they are for, and converts between engineering units and the numbers that
travel. :class:`Der` puts it in front of an outstation, and
:class:`LoopbackDer` in front of a :class:`~py1815.master.loopback.Loopback`.

Every operation is made of the master's own requests: a read is ``read``, and
a write is ``operate``. A write is a control, so it is sent once and never
repeated (D80): a write whose answer did not arrive is reported as not known,
and nothing follows it that depends on it.

Each operation is written once, as a plan: a generator that yields one request
at a time and is sent what came of it. A master on a socket awaits each
request and one wired to a session does not, so the two cannot come to differ.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import asyncio
import decimal
import math
import re
import weakref
from collections.abc import Awaitable, Callable, Generator, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar
from xml.etree import ElementTree

from py1815.application import IIN2Bit
from py1815.decode import DecodedObject, PointType
from py1815.master import controls
from py1815.master.association import Exchange
from py1815.master.controls import Command, Mode, Operated
from py1815.objects import AnalogQuality
from py1815.profile import curves
from py1815.profile.model import Kind, Point, PointMap

T = TypeVar("T")

#: One request of a plan: called with whatever carries requests, it returns
#: what that carrier returns, or an awaitable of it.
Step = Callable[[Any], Any]

#: An operation, one request at a time.
Plan = Generator[Step, Any, T]

#: The point type a master reads each kind of profile point as.
POINT_TYPES: dict[Kind, PointType] = {
    Kind.BI: PointType.BINARY_INPUT,
    Kind.BO: PointType.BINARY_OUTPUT,
    Kind.AI: PointType.ANALOG_INPUT,
    Kind.AO: PointType.ANALOG_OUTPUT,
    Kind.CTR: PointType.COUNTER,
}

#: The argument of ``read`` that names each kind's indices.
_READ_ARGUMENTS: dict[PointType, str] = {
    PointType.BINARY_INPUT: "binary_inputs",
    PointType.BINARY_OUTPUT: "binary_outputs",
    PointType.COUNTER: "counters",
    PointType.FROZEN_COUNTER: "frozen_counters",
    PointType.ANALOG_INPUT: "analog_inputs",
    PointType.ANALOG_OUTPUT: "analog_outputs",
}

#: Kinds in the order a group's points are listed.
_KIND_ORDER = {Kind.BO: 0, Kind.BI: 1, Kind.AO: 2, Kind.AI: 3, Kind.CTR: 4}

#: The analog output that selects which curve the curve block shows, and the
#: binary input that says whether a function names the selected curve. IEEE
#: 1815.2 gives the curve block fixed indices (clause 5.2), and lays it out as
#: clause 6.1.3 has it: the selector, the curve's type, its number of points,
#: the units of X, the units of Y, then X and Y of each point.
CURVE_SELECTOR = 244
CURVE_REFERENCED = 107

_INT32 = (-(1 << 31), (1 << 31) - 1)

_ADDRESS = re.compile(r"^\s*(BI|BO|AI|AO|CTR)\s*(\d+)\s*$", re.IGNORECASE)

#: A class number as the Device Profile schema spells it.
_CLASS_WORDS = {"none": 0, "one": 1, "two": 2, "three": 3}


def address(point: Point) -> str:
    """Return a point's address as text: its kind and index, as in ``AO87``."""
    return f"{point.kind.value}{point.index}"


def _by_address(point: Point) -> tuple[int, int]:
    return _KIND_ORDER[point.kind], point.index


def _normal(text: str) -> str:
    return " ".join(text.split()).casefold()


def _head(text: str) -> str:
    """Return the first sentence of a name: the name, where the tables add a description."""
    return " ".join(text.split()).split(". ", maxsplit=1)[0].rstrip(".")


def _places(number: float | None) -> int:
    """Return how many decimal places a number from the tables is written with."""
    if number is None:
        return 0
    exponent = decimal.Decimal(repr(float(number))).normalize().as_tuple().exponent
    return max(0, -exponent) if isinstance(exponent, int) else 0


def label(point: Point) -> str:
    """Return a point's name without the description the tables append to some."""
    return _head(point.name)


def _function_name(enable: Point) -> str:
    """Return a function's name, from the name of the output that enables it.

    ``Enable Volt-Var Control Mode`` names the function ``Volt-Var Control``.
    """
    name = _head(enable.name)
    name = re.sub(r"^enable\s+", "", name, flags=re.IGNORECASE)
    name = re.sub(r"\s+(mode|function)$", "", name, flags=re.IGNORECASE)
    return name or _head(enable.name)


def _key(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-")


def quality(flags: int | None, reported: bool = True) -> str:
    """Return what a flag octet says of a value: ``good``, ``offline``, ``comm_lost``, ``restart``.

    ``not_reported`` for a point the outstation did not report, and
    ``no_flags`` for a variation that carries no flag octet, which says
    nothing either way.
    """
    if not reported:
        return "not_reported"
    if flags is None:
        return "no_flags"
    if flags & AnalogQuality.ONLINE:
        return "good"
    if flags & AnalogQuality.COMM_LOST:
        return "comm_lost"
    if flags & AnalogQuality.RESTART:
        return "restart"
    return "offline"


# ------------------------------------------------------------------ results


@dataclass(frozen=True)
class Function:
    """One DER function, as the tables group its points."""

    #: The function's name in lower case with hyphens, as in ``volt-var-control``.
    key: str
    #: The function's name, from the output that enables it.
    name: str
    #: What the tables say its points are for, as in ``Volt-Var``.
    purpose: str
    #: The binary output that enables it.
    enable: Point
    #: The binary input that reports whether it is enabled, when the tables pair one.
    status: Point | None
    #: The binary input that says whether the outstation supports it.
    supports: Point
    #: Its other outputs: settings, each read back by the input it is paired with.
    settings: tuple[Point, ...]
    #: Its other inputs.
    inputs: tuple[Point, ...]

    @property
    def points(self) -> tuple[Point, ...]:
        """Every point of the function, outputs first, each kind in index order."""
        every = {self.enable, self.supports, *self.settings, *self.inputs}
        if self.status is not None:
            every.add(self.status)
        return tuple(sorted(every, key=_by_address))

    @property
    def curve_settings(self) -> tuple[Point, ...]:
        """The settings that name a curve by its number."""
        return tuple(
            point
            for point in self.settings
            if point.kind is Kind.AO and "curve index" in point.name.casefold()
        )


@dataclass(frozen=True)
class Reading:
    """What an outstation reported for one point of the profile."""

    point: Point
    #: The value as it travelled: a state, a count, or a transmitted number.
    #: None when the outstation did not report the point.
    raw: bool | int | float | None
    flags: int | None
    time_ms: int | None
    reported: bool

    @property
    def value(self) -> bool | int | float | None:
        """The value in engineering units: the transmitted number through the multiplier.

        A whole transmitted number is given to as many decimal places as the
        multiplier and offset have, so 4224 tenths of a volt reads 422.4 and
        not the 422.40000000000003 that binary floating point makes of it.
        """
        if self.raw is None or isinstance(self.raw, bool):
            return self.raw
        value = self.point.from_wire(self.raw)
        if isinstance(self.raw, int) and math.isfinite(value):
            return round(value, _places(self.point.multiplier) + _places(self.point.offset))
        return value

    @property
    def state(self) -> str | None:
        """A binary point's state by the name the tables give it."""
        if not isinstance(self.raw, bool) or self.point.states is None:
            return None
        return self.point.states[int(self.raw)]

    @property
    def quality(self) -> str:
        """What its flags say of it. See :func:`quality`."""
        return quality(self.flags, self.reported)


@dataclass(frozen=True)
class Readings:
    """Points read in one request, in the order they were asked for."""

    readings: tuple[Reading, ...]
    #: The read, and each range read again when the outstation refused it whole.
    exchanges: tuple[Exchange, ...]

    def __getitem__(self, name: str) -> Reading:
        """Return one reading, by the point's address or its name."""
        for reading in self.readings:
            if name.strip().upper() == address(reading.point) or _normal(name) in (
                _normal(reading.point.name),
                _normal(label(reading.point)),
            ):
                return reading
        raise KeyError(f"{name!r} was not read")


@dataclass(frozen=True)
class Setpoint:
    """One output written, and what came of it."""

    point: Point
    #: The value asked for, in engineering units, or the state of a binary output.
    requested: bool | float
    #: What travelled: a transmitted number, or the engineering value where a
    #: floating-point variation was asked for, or the state of a binary output.
    sent: bool | int | float
    status: controls.PointStatus
    #: The input that mirrors the output, read afterwards, when ``verify`` asked.
    readback: Reading | None = None

    @property
    def sent_value(self) -> bool | float:
        """What was sent, in engineering units."""
        if isinstance(self.sent, (bool, float)):
            return self.sent
        return self.point.from_wire(self.sent)

    @property
    def matches(self) -> bool | None:
        """Whether the readback is what was asked for, within one step of the multiplier.

        None when there was no readback, or the outstation did not report it.
        """
        if self.readback is None or not self.readback.reported:
            return None
        read = self.readback.value
        if isinstance(self.requested, bool) or isinstance(read, bool):
            return bool(read) == bool(self.requested)
        if read is None or not math.isfinite(float(read)):
            return False
        step = abs(self.point.multiplier) if self.point.multiplier else 1.0
        return abs(float(read) - float(self.requested)) <= step * (1 + 1e-9)


@dataclass(frozen=True)
class Written:
    """A write of outputs by name, and, when asked, what their mirrors read afterwards."""

    operated: Operated
    setpoints: tuple[Setpoint, ...]
    #: The read of the mirroring inputs, when ``verify`` asked for one.
    verification: Readings | None = None

    @property
    def accepted(self) -> bool | None:
        """Whether the outstation accepted every write: True, False, or None when not known."""
        return self.operated.accepted

    @property
    def verified(self) -> bool | None:
        """Whether every readback matched: True, False if one did not, None if not known."""
        if self.verification is None:
            return None
        matches = [setpoint.matches for setpoint in self.setpoints]
        if any(match is False for match in matches):
            return False
        if matches and all(match is True for match in matches):
            return True
        return None


@dataclass(frozen=True)
class Switched:
    """A function enabled or disabled, and what its status input then said."""

    function: Function
    #: True for an enable, False for a disable.
    enable: bool
    operated: Operated
    #: The input that reports whether the function is enabled, read afterwards.
    status: Reading | None
    #: The read of that input, or None where the tables pair none.
    readback: Readings | None

    @property
    def accepted(self) -> bool | None:
        return self.operated.accepted

    @property
    def enabled(self) -> bool | None:
        """Whether the outstation says the function is enabled. None when it did not say."""
        if self.status is None or not self.status.reported:
            return None
        return bool(self.status.raw)


@dataclass(frozen=True)
class Curve:
    """The curve the curve block shows, as the outstation reported it.

    The points are the numbers that travelled: their scaling depends on the
    units the curve declares, and the tables give the block no multiplier.
    """

    number: int | None
    type: int | None
    count: int | None
    x_units: int | None
    y_units: int | None
    points: tuple[tuple[float, float], ...]
    #: Whether a function names this curve, where the outstation says.
    referenced: bool | None
    #: The reads it took: the selector and fields, then the points.
    reads: tuple[Readings, ...]
    #: The readings of the selector and the four fields, in that order.
    fields: tuple[Reading, ...] = ()


@dataclass(frozen=True)
class CurveWritten:
    """A curve written as the profile requires, and read back."""

    number: int
    type: int
    x_units: int
    y_units: int
    points: tuple[tuple[int, int], ...]
    #: Each write made, in order: the selector, the fields, the points. A
    #: write is made only when the one before it was accepted.
    steps: tuple[Operated, ...]
    readback: Curve

    @property
    def stopped_at(self) -> str | None:
        """The step that was not accepted, by name, or None when none failed."""
        names = ("selector", "fields", "points")
        for name, step in zip(names, self.steps, strict=False):
            if step.accepted is not True:
                return name
        return None

    @property
    def accepted(self) -> bool | None:
        """True when every write was accepted, False when one was refused, None when not known."""
        for step in self.steps:
            if step.accepted is not True:
                return step.accepted
        return True

    @property
    def matches(self) -> bool:
        """Whether the curve read back is the curve written."""
        back = self.readback
        return (
            back.number == self.number
            and back.type == self.type
            and back.count == len(self.points)
            and back.x_units == self.x_units
            and back.y_units == self.y_units
            and tuple((float(x), float(y)) for x, y in self.points) == back.points
        )


@dataclass(frozen=True)
class FunctionState:
    """One function, and what the outstation says of it."""

    function: Function
    #: Whether the outstation says it supports the function. None when it did not say.
    supported: bool | None
    #: Whether the outstation says it is enabled. None when it did not say.
    enabled: bool | None


@dataclass(frozen=True)
class Functions:
    """Which functions an outstation supports and which are enabled."""

    states: tuple[FunctionState, ...]
    readings: Readings


@dataclass(frozen=True)
class Declared:
    """One point as a Device Profile document declares it."""

    type: PointType
    index: int
    name: str | None
    #: The class its events are reported in: 1, 2 or 3, 0 for none, None where not stated.
    event_class: int | None
    #: Whether a class 0 read carries it. None where not stated.
    class_0: bool | None
    #: Its deadband, in transmitted units, where stated.
    deadband: float | None


@dataclass(frozen=True)
class Comparison:
    """What an outstation serves, against what its Device Profile document declares."""

    declared: tuple[Declared, ...]
    #: Declared, and not served: no read returned it.
    absent: tuple[Declared, ...]
    #: Served, and not declared, by type and index.
    undeclared: tuple[tuple[PointType, int], ...]
    #: Served points whose presence in a class 0 read is not what is declared,
    #: each with whether the class 0 read carried it.
    class_0: tuple[tuple[Declared, bool], ...]
    #: Declared and served. A point's event class and deadband cannot be read
    #: from an outstation, so they are given as declared.
    served: tuple[Declared, ...]
    exchanges: tuple[Exchange, ...]


# ----------------------------------------------------------- the profile map


class DerProfile:
    """The point map, read for a master: names, groups, functions and scaling. No I/O."""

    def __init__(self, point_map: PointMap, *, curve_selector: int = CURVE_SELECTOR) -> None:
        """
        Args:
            point_map: The profile's points, resolved for the outstation.
            curve_selector: The analog output that selects the curve the
                curve block shows. The fields and points follow it.
        """
        self.map = point_map
        self.functions: tuple[Function, ...] = self._functions()
        self._curve_selector = curve_selector

    # ---------------------------------------------------------------- names

    def point(self, name: str, *, outputs: bool = False) -> Point:
        """Return a point by its address, as in ``AO87``, or by its name.

        A name is matched whole or by its first sentence, ignoring case and
        spacing. The tables give some names to more than one point, an output
        and the input that reads it back among them, so a name is looked for
        among the inputs first and then among the outputs, or among the
        outputs only when ``outputs`` is set. A name that still matches more
        than one point is refused, with the addresses it could mean.
        """
        given = _ADDRESS.match(name)
        if given:
            kind, index = Kind(given.group(1).upper()), int(given.group(2))
            found = self.map.get(kind, index)
            if found is None:
                raise ValueError(f"the profile has no {kind.value}{index}")
            if outputs and not kind.is_output:
                raise ValueError(f"{kind.value}{index} is an input, and is not written")
            return found
        wanted = _normal(name)
        if not wanted:
            raise ValueError("a point is named by its address or its name")
        for output_tier in (True,) if outputs else (False, True):
            candidates = [p for p in self.map.points.values() if p.kind.is_output == output_tier]
            # The whole name first, then the first sentence of it.
            for whole in (True, False):
                named = [p for p in candidates if _normal(p.name if whole else label(p)) == wanted]
                if len(named) == 1:
                    return named[0]
                if len(named) > 1:
                    listed = ", ".join(address(p) for p in sorted(named, key=_by_address))
                    raise ValueError(f"{name!r} names more than one point: {listed}")
        raise ValueError(f"the profile has no point named {name!r}")

    def function(self, name: str) -> Function:
        """Return a function by its key, name, purpose, or the address of its enable output."""
        wanted = _normal(name)
        for function in self.functions:
            if wanted in (
                function.key,
                _normal(function.name),
                _normal(function.purpose),
                _normal(address(function.enable)),
            ):
                return function
        known = ", ".join(function.key for function in self.functions) or "none"
        raise ValueError(f"the profile has no function {name!r}; it has {known}")

    def group(self, name: str) -> tuple[Point, ...]:
        """Return the points of a named group: a function, or everything of one purpose.

        A purpose is what the tables say a point is for: ``Nameplate``,
        ``Monitoring``, ``Return to Service``. A function's group is its own
        points, which may be fewer than its purpose names elsewhere.
        """
        try:
            return self.function(name).points
        except ValueError:
            pass
        wanted = _normal(name)
        found = [p for p in self.map.points.values() if p.purpose and _normal(p.purpose) == wanted]
        if not found:
            raise ValueError(f"the profile has no function or group named {name!r}")
        return tuple(sorted(found, key=_by_address))

    def mirror(self, point: Point) -> Point | None:
        """Return the input that reads an output back, or None when the tables pair none."""
        paired = point.associated
        if paired is None or paired[0].is_output:
            return None
        return self.map.get(*paired)

    # -------------------------------------------------------------- scaling

    def transmitted(self, point: Point, value: Any) -> bool | int:
        """Return an output's value as it travels: a state, or a whole transmitted number.

        A binary output takes true or false, 1 or 0, or the name the tables
        give one of its states. An analog output takes a number in engineering
        units, divided by its multiplier and rounded to the nearest whole
        number. A value outside the point's range is refused here, before
        anything is sent.
        """
        where = f"{address(point)} ({label(point)})"
        if point.kind is Kind.BO:
            if isinstance(value, bool):
                return value
            if isinstance(value, int) and value in (0, 1):
                return bool(value)
            if isinstance(value, str) and point.states is not None:
                for state, text in enumerate(point.states):
                    if _normal(value) == _normal(text):
                        return bool(state)
            states = f", or {' or '.join(repr(s) for s in point.states)}" if point.states else ""
            raise ValueError(f"{where} takes true or false{states}, not {value!r}")
        if point.kind is not Kind.AO:
            raise ValueError(f"{where} is an input, and is not written")
        if isinstance(value, bool):
            raise ValueError(f"{where} takes a number, not {value!r}")
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            # OverflowError: a JSON integer such as 10**1000 has no float.
            raise ValueError(f"{where} takes a number, not {value!r}") from None
        raw = point.to_wire(number)
        if not math.isfinite(raw):
            raise ValueError(f"{where} takes a finite number, not {value!r}")
        whole = round(raw)
        if not point.in_range(whole) or not _INT32[0] <= whole <= _INT32[1]:
            raise ValueError(f"{where}: {number:g} is outside {self.span(point)}")
        return whole

    @staticmethod
    def limits(point: Point) -> tuple[float | None, float | None]:
        """Return an analog point's range in engineering units, lowest first; None where open."""
        ends = [
            None if bound is None else point.from_wire(float(bound))
            for bound in (point.minimum, point.maximum)
        ]
        if ends[0] is not None and ends[1] is not None and ends[0] > ends[1]:
            ends.reverse()
        return ends[0], ends[1]

    @staticmethod
    def span(point: Point) -> str:
        """Return an analog point's range in engineering units, as text."""
        low, high = DerProfile.limits(point)
        units = f" {point.units}" if point.units and point.units.lower() not in ("n/a",) else ""
        lower = "no lower limit" if low is None else f"{low:g}"
        upper = "no upper limit" if high is None else f"{high:g}"
        return f"{lower} to {upper}{units}"

    # --------------------------------------------------------------- curves

    def curve_block(self) -> tuple[list[Point], list[Point]]:
        """Return the curve block's outputs and the inputs that read them back, in order.

        The selector, the four fields, then X and Y of each point. Raises
        ValueError when the map does not hold the block or its readback.
        """
        outputs: list[Point] = []
        inputs: list[Point] = []
        for offset in range(1 + curves.FIELDS + 2 * curves.MAX_POINTS):
            output = self.map.get(Kind.AO, self._curve_selector + offset)
            if output is None:
                raise ValueError(
                    f"the profile has no AO{self._curve_selector + offset}: no curve block "
                    f"starts at AO{self._curve_selector}"
                )
            readback = self.mirror(output)
            if readback is None:
                raise ValueError(f"the profile pairs no input with {address(output)}")
            outputs.append(output)
            inputs.append(readback)
        return outputs, inputs

    def referenced(self) -> Point | None:
        """Return the input that says whether a function names the selected curve, if any."""
        return self.map.get(Kind.BI, CURVE_REFERENCED)

    # ------------------------------------------------------------ functions

    def _functions(self) -> tuple[Function, ...]:
        """Find every function: a supports input and the enable output it is paired with.

        A function's points are the ones the tables give the enable output's
        purpose, under its heading, as the outstation groups them (D57).
        """
        found: list[Function] = []
        for supports in self.map.of(Kind.BI):
            if supports.enabled_by is None or supports.enabled_by not in self.map:
                continue
            enable = self.map.point(*supports.enabled_by)
            purpose = enable.purpose or ""
            status = self.mirror(enable)
            members = [
                p
                for p in self.map.points.values()
                if purpose
                and p.purpose
                and p.purpose.casefold() == purpose.casefold()
                and p.section == enable.section
                and p.address not in (enable.address, supports.address)
                and (status is None or p.address != status.address)
            ]
            ordered = sorted(members, key=_by_address)
            name = _function_name(enable)
            found.append(
                Function(
                    key=_key(name),
                    name=name,
                    purpose=purpose or name,
                    enable=enable,
                    status=status,
                    supports=supports,
                    settings=tuple(p for p in ordered if p.kind.is_output),
                    inputs=tuple(p for p in ordered if not p.kind.is_output),
                )
            )
        return tuple(found)


# ---------------------------------------------------------------- the plans


def _static(objects: Iterable[DecodedObject]) -> dict[tuple[PointType, int], DecodedObject]:
    """Return a response's objects by point, a static object before an event for it."""
    found: dict[tuple[PointType, int], DecodedObject] = {}
    for decoded in objects:
        if decoded.point is None or decoded.index is None:
            continue
        key = (decoded.point, decoded.index)
        if decoded.event and key in found and not found[key].event:
            continue
        found[key] = decoded
    return found


def _read_step(wanted: Mapping[PointType, Sequence[int]]) -> Step:
    arguments = {_READ_ARGUMENTS[kind]: sorted(set(indices)) for kind, indices in wanted.items()}
    return lambda target: target.read(**arguments)


def _runs(wanted: Mapping[PointType, Sequence[int]]) -> list[tuple[PointType, list[int]]]:
    """Return each run of consecutive indices, by type: one range header of a read (D82)."""
    runs: list[tuple[PointType, list[int]]] = []
    for kind, indices in wanted.items():
        for index in sorted(set(indices)):
            if runs and runs[-1][0] is kind and runs[-1][1][-1] == index - 1:
                runs[-1][1].append(index)
            else:
                runs.append((kind, [index]))
    return runs


def _refused(exchange: Exchange) -> bool:
    iin = exchange.iin
    return iin is not None and (
        iin.is_set(IIN2Bit.PARAM_ERROR) or iin.is_set(IIN2Bit.OBJECT_UNKNOWN)
    )


def _read_points(
    wanted: Mapping[PointType, Sequence[int]],
) -> Plan[tuple[dict[tuple[PointType, int], DecodedObject], tuple[Exchange, ...]]]:
    """Read points in one request, and a run at a time if the outstation refuses it whole.

    An outstation may refuse a whole read for one range that holds no point
    it serves, and a profile names many points an outstation may leave out.
    So a refused read is made again one range at a time, which reads every
    range that holds a point and leaves out only the ones that do not. A
    read changes nothing at the outstation, so making it again is harmless.
    """
    exchange: Exchange = yield _read_step(wanted)
    exchanges = [exchange]
    received = _static(exchange.objects)
    runs = _runs(wanted)
    if _refused(exchange) and len(runs) > 1:
        for kind, run_indices in runs:
            again: Exchange = yield _read_step({kind: run_indices})
            exchanges.append(again)
            received.update(_static(again.objects))
    return received, tuple(exchanges)


def read_plan(points: Sequence[Point]) -> Plan[Readings]:
    """Read points of the profile, and report each in engineering units.

    One request, unless the outstation refuses it whole for a range that holds
    no point it serves: then each range is read again on its own (D93).
    """
    if not points:
        raise ValueError("a read names at least one point")
    wanted: dict[PointType, list[int]] = {}
    for point in points:
        wanted.setdefault(POINT_TYPES[point.kind], []).append(point.index)

    def steps() -> Plan[Readings]:
        received, exchanges = yield from _read_points(wanted)
        readings = []
        for point in points:
            decoded = received.get((POINT_TYPES[point.kind], point.index))
            if decoded is None:
                readings.append(Reading(point, None, None, None, reported=False))
            else:
                readings.append(
                    Reading(point, decoded.value, decoded.flags, decoded.time_ms, reported=True)
                )
        return Readings(tuple(readings), exchanges)

    return steps()


def _carry_out(plan: controls.Plan) -> Step:
    # The carrier's own method, so the requests of the plan are made in one
    # turn, as an operate made directly would be.
    return lambda target: target._carry_out(plan)  # pylint: disable=protected-access


def _command(point: Point, sent: bool | int | float, variation: int | None) -> Command:
    if point.kind is Kind.BO:
        return controls.binary(point.index, bool(sent))
    return controls.analog(point.index, sent, variation)


def write_plan(
    profile: DerProfile,
    values: Mapping[str, Any],
    *,
    verify: bool = False,
    mode: Mode | str = Mode.DIRECT,
    variation: int | None = None,
) -> Plan[Written]:
    """Write outputs by name in engineering units, in one request, in the order given.

    Everything that can be wrong with the write is refused here, before any
    request is made. ``variation`` 3 or 4 sends an analog value as a float in
    engineering units, which the profile has an outstation take unscaled;
    otherwise it travels as the whole transmitted number.
    """
    if not values:
        raise ValueError("a write names at least one output")
    if variation is not None and variation not in (1, 2, 3, 4):
        raise ValueError(f"{variation!r} is not an analog output variation: 1, 2, 3 or 4")
    planned: list[tuple[Point, bool | float, bool | int | float]] = []
    for name, value in values.items():
        point = profile.point(str(name), outputs=True)
        transmitted = profile.transmitted(point, value)
        if isinstance(transmitted, bool):
            planned.append((point, transmitted, transmitted))
        elif variation in (3, 4):
            planned.append((point, float(value), float(value)))
        else:
            planned.append((point, float(value), transmitted))
    commands = [_command(point, sent, variation) for point, _requested, sent in planned]
    plan = controls.Plan(commands, mode)
    mirrors = [profile.mirror(point) for point, _requested, _sent in planned]

    def steps() -> Plan[Written]:
        operated: Operated = yield _carry_out(plan)
        verification: Readings | None = None
        if verify:
            wanted = [mirror for mirror in mirrors if mirror is not None]
            if wanted:
                verification = yield from read_plan(wanted)
        setpoints = []
        for (point, requested, sent), status, mirror in zip(
            planned, operated.statuses, mirrors, strict=True
        ):
            readback = None
            if verification is not None and mirror is not None:
                readback = next(r for r in verification.readings if r.point is mirror)
            setpoints.append(Setpoint(point, requested, sent, status, readback))
        return Written(operated, tuple(setpoints), verification)

    return steps()


def switch_plan(
    profile: DerProfile, name: str, enable: bool, *, mode: Mode | str = Mode.DIRECT
) -> Plan[Switched]:
    """Enable or disable a function, then read the input that reports whether it is enabled."""
    function = profile.function(name)
    plan = controls.Plan([controls.binary(function.enable.index, enable)], mode)

    def steps() -> Plan[Switched]:
        operated: Operated = yield _carry_out(plan)
        readback: Readings | None = None
        status: Reading | None = None
        if function.status is not None:
            readback = yield from read_plan([function.status])
            status = readback.readings[0]
        return Switched(function, enable, operated, status, readback)

    return steps()


def functions_plan(profile: DerProfile) -> Plan[Functions]:
    """Read which functions the outstation supports, and which are enabled, in one request."""
    if not profile.functions:
        raise ValueError("the profile has no functions")
    wanted: list[Point] = []
    for function in profile.functions:
        wanted.append(function.supports)
        if function.status is not None:
            wanted.append(function.status)

    def steps() -> Plan[Functions]:
        readings: Readings = yield from read_plan(wanted)
        by_point = {reading.point.address: reading for reading in readings.readings}

        def said(point: Point | None) -> bool | None:
            if point is None:
                return None
            reading = by_point[point.address]
            return bool(reading.raw) if reading.reported else None

        states = tuple(
            FunctionState(function, said(function.supports), said(function.status))
            for function in profile.functions
        )
        return Functions(states, readings)

    return steps()


def _whole(value: Any, what: str) -> int:
    """Return a curve's number, field or point value, which travels as a whole number."""
    if isinstance(value, bool):
        raise ValueError(f"{what} is a number, not {value!r}")
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"{what} is a number, not {value!r}") from None
    if not math.isfinite(number):
        raise ValueError(f"{what} is a finite number, not {value!r}")
    if not number.is_integer():
        raise ValueError(f"{what} travels as a whole number, and {value!r} is not one")
    return int(number)


def curve_plan(
    profile: DerProfile, number: int | None = None, *, mode: Mode | str = Mode.DIRECT
) -> Plan[tuple[Operated | None, Curve]]:
    """Read the curve the curve block shows, selecting curve ``number`` first when given.

    Selecting a curve writes the selector, so it is a control.
    """
    outputs, inputs = profile.curve_block()
    selection: controls.Plan | None = None
    if number is not None:
        chosen = profile.transmitted(outputs[0], _whole(number, "the curve number"))
        selection = controls.Plan([_command(outputs[0], chosen, None)], mode)

    def steps() -> Plan[tuple[Operated | None, Curve]]:
        selected: Operated | None = None
        if selection is not None:
            selected = yield _carry_out(selection)
        curve = yield from _read_curve(profile, inputs)
        return selected, curve

    return steps()


def _read_curve(profile: DerProfile, inputs: Sequence[Point]) -> Plan[Curve]:
    head = list(inputs[: 1 + curves.FIELDS])
    referenced = profile.referenced()
    first: Readings = yield from read_plan([*head, *([referenced] if referenced else [])])
    fields = first.readings[: 1 + curves.FIELDS]

    def whole(reading: Reading) -> int | None:
        value = reading.value
        if not reading.reported or value is None or isinstance(value, bool):
            return None
        return round(float(value)) if math.isfinite(float(value)) else None

    number, kind, count, x_units, y_units = (whole(reading) for reading in fields)
    shown = max(0, min(curves.MAX_POINTS, count or 0))
    reads = [first]
    values: list[float] = []
    if shown:
        second: Readings = yield from read_plan(list(inputs[1 + curves.FIELDS :][: 2 * shown]))
        reads.append(second)
        for reading in second.readings:
            value = reading.value
            values.append(float(value) if reading.reported and value is not None else math.nan)
    said = first.readings[-1] if referenced else None
    return Curve(
        number=number,
        type=kind,
        count=count,
        x_units=x_units,
        y_units=y_units,
        points=tuple(zip(values[0::2], values[1::2], strict=True)),
        referenced=None if said is None or not said.reported else bool(said.raw),
        reads=tuple(reads),
        fields=tuple(fields),
    )


def write_curve_plan(
    profile: DerProfile,
    number: Any,
    *,
    type: Any,  # pylint: disable=redefined-builtin
    x_units: Any,
    y_units: Any,
    points: Sequence[Sequence[Any]],
    mode: Mode | str = Mode.DIRECT,
) -> Plan[CurveWritten]:
    """Write a curve in the order IEEE 1815.2 clause 6.1.3 lays the block out, then read it back.

    Three writes: the selector, then the type, the number of points and the
    units of X and Y, then X and Y of each point. Each is made only when the
    one before it was accepted, since a field or a point written after a
    selector the outstation refused would change whichever curve it was
    already showing. The curve is read back whatever happened.
    """
    outputs, inputs = profile.curve_block()
    chosen = _whole(number, "the curve number")
    fields = [
        _whole(type, "the curve type"),
        len(points),
        _whole(x_units, "the units of X"),
        _whole(y_units, "the units of Y"),
    ]
    if len(points) > curves.MAX_POINTS:
        raise ValueError(f"a curve has at most {curves.MAX_POINTS} points, not {len(points)}")
    pairs: list[tuple[int, int]] = []
    for position, pair in enumerate(points, start=1):
        if not isinstance(pair, Sequence) or isinstance(pair, (str, bytes)) or len(pair) != 2:
            raise ValueError(f"point {position} of the curve is an X and a Y")
        pairs.append(
            (_whole(pair[0], f"X of point {position}"), _whole(pair[1], f"Y of point {position}"))
        )
    flat = [value for pair in pairs for value in pair]
    writes = [
        [(outputs[0], chosen)],
        list(zip(outputs[1 : 1 + curves.FIELDS], fields, strict=True)),
        list(zip(outputs[1 + curves.FIELDS :], flat, strict=False)),
    ]
    plans = [
        controls.Plan(
            [_command(point, profile.transmitted(point, value), None) for point, value in step],
            mode,
        )
        for step in writes
        if step
    ]

    def steps() -> Plan[CurveWritten]:
        done: list[Operated] = []
        for plan in plans:
            operated: Operated = yield _carry_out(plan)
            done.append(operated)
            if operated.accepted is not True:
                break
        readback = yield from _read_curve(profile, inputs)
        return CurveWritten(
            number=chosen,
            type=fields[0],
            x_units=fields[2],
            y_units=fields[3],
            points=tuple(pairs),
            steps=tuple(done),
            readback=readback,
        )

    return steps()


# ------------------------------------------------------- the device profile


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(element: ElementTree.Element, name: str) -> ElementTree.Element | None:
    return next((child for child in element if _local(child.tag) == name), None)


def _text(element: ElementTree.Element, name: str) -> str | None:
    found = _child(element, name)
    return None if found is None or found.text is None else found.text.strip()


def _class(word: str | None) -> int | None:
    return None if word is None else _CLASS_WORDS.get(word.strip().casefold())


def _included(word: str | None) -> bool | None:
    if word is None:
        return None
    return {"always": True, "never": False}.get(word.strip().casefold())


#: The point lists of a Device Profile document, the element of each point,
#: and the type a master reads it as.
_LISTS = {
    "binaryInputPoints": ("binaryInput", PointType.BINARY_INPUT),
    "binaryOutputPoints": ("binaryOutput", PointType.BINARY_OUTPUT),
    "counterPoints": ("counter", PointType.COUNTER),
    "analogInputPoints": ("analogInput", PointType.ANALOG_INPUT),
    "analogOutputPoints": ("analogOutput", PointType.ANALOG_OUTPUT),
}


def read_device_profile(text: str) -> tuple[Declared, ...]:
    """Return the points a DNP3 Device Profile document declares.

    Reads the point lists of the form :mod:`py1815.profile.device_profile`
    writes, schema version 2.12.00. A counter that declares a frozen counter
    beside it is two points. A document that declares a document type is
    refused, since nothing a Device Profile holds needs one and an entity
    declared there is how an XML document is made to expand without bound.
    """
    if "<!DOCTYPE" in text.upper():
        raise ValueError("a Device Profile document has no document type declaration")
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as error:
        raise ValueError(f"the Device Profile document is not XML: {error}") from None
    lists = next(
        (element for element in root.iter() if _local(element.tag) == "dataPointsList"), None
    )
    if lists is None:
        raise ValueError("the document has no dataPointsList, so it declares no points")
    declared: list[Declared] = []
    for section in lists:
        found = _LISTS.get(_local(section.tag))
        if found is None:
            continue
        element_name, point_type = found
        points = _child(section, "dataPoints")
        for element in points if points is not None else ():
            if _local(element.tag) != element_name:
                continue
            index_text = _text(element, "index")
            if index_text is None or not index_text.isdigit():
                raise ValueError(f"a {element_name} in the document has no index")
            index = int(index_text)
            name = _text(element, "name")
            if point_type is PointType.COUNTER:
                declared.append(
                    Declared(
                        point_type,
                        index,
                        name,
                        _class(_text(element, "counterEventClass")),
                        _included(_text(element, "countersIncludedInClass0")),
                        None,
                    )
                )
                if (_text(element, "frozenCounterExists") or "").casefold() == "true":
                    declared.append(
                        Declared(
                            PointType.FROZEN_COUNTER,
                            index,
                            name,
                            _class(_text(element, "frozenCounterEventClass")),
                            _included(_text(element, "frozenCountersIncludedInClass0")),
                            None,
                        )
                    )
                continue
            deadband = None
            data = _child(element, "dnpData")
            if data is not None and _text(data, "deadband") is not None:
                try:
                    deadband = float(_text(data, "deadband") or "")
                except ValueError:
                    deadband = None
                # NaN and infinity are not deadbands, and are not valid JSON.
                if deadband is not None and not math.isfinite(deadband):
                    deadband = None
            declared.append(
                Declared(
                    point_type,
                    index,
                    name,
                    _class(_text(element, "changeEventClass")),
                    _included(_text(element, "includedInClass0Response")),
                    deadband,
                )
            )
    return tuple(declared)


def compare_plan(document: str) -> Plan[Comparison]:
    """Compare what an outstation serves with what its Device Profile document declares.

    A class 0 read, then a read of output status, then a read of every
    declared point neither returned, by range. A point no read returned is
    absent. Whether each served point is in class 0 is checked against the
    class 0 read. A point's event class and deadband cannot be read from an
    outstation, so they are reported as declared.
    """
    declared = read_device_profile(document)
    by_point = {(entry.type, entry.index): entry for entry in declared}

    def steps() -> Plan[Comparison]:
        class_0: Exchange = yield lambda target: target.scan("class0")
        outputs: Exchange = yield lambda target: target.scan("outputs")
        carried = set(_static(class_0.objects))
        seen = carried | set(_static(outputs.objects))
        exchanges = [class_0, outputs]
        missing: dict[PointType, list[int]] = {}
        for key in by_point:
            if key not in seen:
                missing.setdefault(key[0], []).append(key[1])
        if missing:
            found, looked = yield from _read_points(missing)
            exchanges += looked
            seen |= set(found)
        absent = tuple(entry for key, entry in by_point.items() if key not in seen)
        undeclared = tuple(sorted((key for key in seen if key not in by_point), key=_order))
        served = tuple(entry for key, entry in by_point.items() if key in seen)
        misplaced = tuple(
            (entry, (entry.type, entry.index) in carried)
            for entry in served
            if entry.class_0 is not None and entry.class_0 != ((entry.type, entry.index) in carried)
        )
        return Comparison(declared, absent, undeclared, misplaced, served, tuple(exchanges))

    return steps()


def _order(key: tuple[PointType, int]) -> tuple[int, int]:
    return list(PointType).index(key[0]), key[1]


# --------------------------------------------------------------- the drivers


def run(target: Any, plan: Plan[T]) -> T:
    """Carry out a plan on a master whose requests return at once, as a Loopback's do."""
    try:
        step = next(plan)
        while True:
            step = plan.send(step(target))
    except StopIteration as done:
        return done.value  # type: ignore[no-any-return]


async def run_async(target: Any, plan: Plan[T]) -> T:
    """Carry out a plan on a master whose requests are awaited, as an Outstation's are."""
    try:
        step = next(plan)
        while True:
            outcome: Awaitable[Any] = step(target)
            step = plan.send(await outcome)
    except StopIteration as done:
        return done.value  # type: ignore[no-any-return]


#: One lock for each outstation, held for the whole of a profile operation.
_LOCKS: weakref.WeakKeyDictionary[Any, asyncio.Lock] = weakref.WeakKeyDictionary()


def _profile(point_map: PointMap | DerProfile) -> DerProfile:
    return point_map if isinstance(point_map, DerProfile) else DerProfile(point_map)


class _Operations:
    """The profile's operations, whatever carries the requests."""

    def __init__(self, target: Any, profile: PointMap | DerProfile) -> None:
        self.target = target
        self.profile = _profile(profile)

    def run(self, plan: Plan[Any]) -> Any:
        """Carry out a plan made by one of this module's plan functions."""
        raise NotImplementedError

    def read(self, *names: str, group: str | None = None) -> Any:
        """Read points by name or address, or a named group, in one request.

        Returns :class:`Readings`, in engineering units with each point's
        quality, in the order named and then the group's order.
        """
        points = [self.profile.point(name) for name in names]
        if group is not None:
            points += [p for p in self.profile.group(group) if p not in points]
        return self.run(read_plan(points))

    def write(
        self,
        values: Mapping[str, Any],
        *,
        verify: bool = False,
        mode: Mode | str = Mode.DIRECT,
        variation: int | None = None,
    ) -> Any:
        """Write outputs by name or address, in engineering units, in one request.

        Returns :class:`Written`. With ``verify`` the input that mirrors each
        output is read afterwards and compared with what was asked, within
        one step of the output's multiplier. The write is sent once.
        """
        return self.run(
            write_plan(self.profile, values, verify=verify, mode=mode, variation=variation)
        )

    def enable(self, function: str, *, mode: Mode | str = Mode.DIRECT) -> Any:
        """Enable a function, then read whether it is enabled. Returns :class:`Switched`."""
        return self.run(switch_plan(self.profile, function, True, mode=mode))

    def disable(self, function: str, *, mode: Mode | str = Mode.DIRECT) -> Any:
        """Disable a function, then read whether it is enabled. Returns :class:`Switched`."""
        return self.run(switch_plan(self.profile, function, False, mode=mode))

    def functions(self) -> Any:
        """Read which functions are supported and which enabled. Returns :class:`Functions`."""
        return self.run(functions_plan(self.profile))

    def curve(self, number: int | None = None, *, mode: Mode | str = Mode.DIRECT) -> Any:
        """Read the curve the curve block shows, selecting ``number`` first when given.

        Returns the selection's :class:`~py1815.master.controls.Operated`, or
        None, and the :class:`Curve`.
        """
        return self.run(curve_plan(self.profile, number, mode=mode))

    def write_curve(
        self,
        number: int,
        *,
        type: int,  # pylint: disable=redefined-builtin
        x_units: int,
        y_units: int,
        points: Sequence[Sequence[int]],
        mode: Mode | str = Mode.DIRECT,
    ) -> Any:
        """Write a curve: its selector, its fields, its points, then read it back.

        Returns :class:`CurveWritten`. See :func:`write_curve_plan`.
        """
        return self.run(
            write_curve_plan(
                self.profile,
                number,
                type=type,
                x_units=x_units,
                y_units=y_units,
                points=points,
                mode=mode,
            )
        )

    def compare(self, document: str) -> Any:
        """Compare what is served with a Device Profile document. Returns :class:`Comparison`."""
        return self.run(compare_plan(document))


class Der(_Operations):
    """The DER profile's operations on an outstation over a socket.

    Each operation is a coroutine. One profile operation is under way on an
    outstation at a time: a curve written by one caller cannot have its
    selector moved by another between the selector and the points.
    """

    def __init__(self, outstation: Any, profile: PointMap | DerProfile) -> None:
        """
        Args:
            outstation: A :class:`~py1815.master.api.Outstation`.
            profile: The point map it serves, or a :class:`DerProfile` made from one.
        """
        super().__init__(outstation, profile)

    async def run(self, plan: Plan[Any]) -> Any:
        lock = _LOCKS.get(self.target)
        if lock is None:
            lock = _LOCKS[self.target] = asyncio.Lock()
        async with lock:
            return await run_async(self.target, plan)


class LoopbackDer(_Operations):
    """The DER profile's operations on a :class:`~py1815.master.loopback.Loopback`, at once."""

    def run(self, plan: Plan[Any]) -> Any:
        return run(self.target, plan)


__all__ = [
    "CURVE_REFERENCED",
    "CURVE_SELECTOR",
    "Comparison",
    "Curve",
    "CurveWritten",
    "Declared",
    "Der",
    "DerProfile",
    "Function",
    "FunctionState",
    "Functions",
    "LoopbackDer",
    "Reading",
    "Readings",
    "Setpoint",
    "Switched",
    "Written",
    "address",
    "label",
    "quality",
    "read_device_profile",
]
