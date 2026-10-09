"""The checks ``py1815-master evaluate`` runs against an outstation.

The DER profile set carries out EPRI's *Test Procedure for Validating DNP
Application Note AN2018-001 in Distributed Energy Resources* (3002016144) the
way a controlling station would: read a function's points, write its
settings and read them back, enable and disable it, and edit curves through
the block all curves share. Each check is named for the identifier the
report gives its procedure: ``MON-001`` is the monitoring procedure. The
report is EPRI's and is not reproduced; the steps are described here in our
own words. Where the report and IEEE 1815.2 differ, these follow the standard.

The procedures carry no point list of their own. Which input reads an output
back, which points make up a function and which input says it is supported
come from the profile tables, and a point counts as supported when the
outstation reports it. A function the outstation says it does not support is
checked for that: it cannot be enabled and none of its points are served.

A check leaves the outstation as it found it where that is one command:
a switch, a permission, started or stopped. Settings, curves and which
functions are enabled are left as the check last wrote them, with every
function it enabled disabled again.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from py1815.control import CommandStatus
from py1815.decode import PointType
from py1815.master.bench import Bench, Check, Failed, NotApplicable, name
from py1815.master.profile import POINT_TYPES, Function, Plan, address
from py1815.profile import curves, der
from py1815.profile.model import Kind, Point

# The points the function procedures name outright. IEEE 1815.2 clause 5.2
# gives these blocks fixed indices.
METER = range(533, 557)
ALARMS = (*range(0, 10), *range(94, 106))
STATES = range(10, 23)
BI_STARTING, BI_STOPPING, BI_STARTED, BI_STOPPED = 12, 13, 14, 15
#: Connected and idle, generating, charging, off and available, off and not
#: available: a DER is in one of these and no more.
EXCLUSIVE_STATES = range(18, 23)
BI_SWITCH_MOVING = 24
CONNECT_SETTINGS = range(16, 18)
SERVICE_SETTINGS = range(6, 16)

#: The mode procedures, by the binary output that enables the function each
#: one tests.
MODES = {
    "VRT-001": 12,
    "FRT-001": 13,
    "DRCS-001": 14,
    "DVW-001": 15,
    "FW-001": 16,
    "APL-001": 17,
    "CHG-001": 18,
    "CCM-001": 19,
    "APR1-001": 20,
    "APR2-001": 21,
    "APR3-001": 22,
    "AGC-001": 23,
    "APS-001": 24,
    "VW-001": 25,
    "FWC-001": 26,
    "CVAR-001": 27,
    "FPF-001": 28,
    "VV-001": 29,
    "WV-001": 30,
    "PFC-001": 31,
    "PSIG-001": 32,
}

#: The most curves looked for when the number an outstation stores is not given.
MAX_CURVES_PROBED = 64

#: Points of a curve read to see that a refused write left it alone.
_WATCHED_POINTS = 4


@dataclass(frozen=True)
class SampleCurve:
    """A valid curve of one type, to write to an outstation."""

    type: int
    x_units: int
    y_units: int
    points: tuple[tuple[int, int], ...]


#: Two valid curves for each setting that names a curve and whose curve type
#: is known here, by the setting's analog output. Voltage is in tenths of a
#: percent of nominal, against vars or watts in tenths of a percent of rating.
#: A function that follows any other kind of curve is not given one.
SAMPLE_CURVES: dict[int, tuple[SampleCurve, SampleCurve]] = {
    der.AO_VOLT_WATT_CURVE: (
        SampleCurve(
            der.CURVE_VOLT_WATT,
            der.X_PERCENT_VOLTAGE,
            der.Y_PERCENT_MAX_WATTS,
            ((1000, 1000), (1060, 1000), (1100, 200)),
        ),
        SampleCurve(
            der.CURVE_VOLT_WATT,
            der.X_PERCENT_VOLTAGE,
            der.Y_PERCENT_MAX_WATTS,
            ((1000, 1000), (1050, 1000), (1090, 0)),
        ),
    ),
    der.AO_VOLT_VAR_CURVE: (
        SampleCurve(
            der.CURVE_VOLT_VAR,
            der.X_PERCENT_VOLTAGE,
            der.Y_PERCENT_MAX_VARS,
            ((920, 300), (980, 0), (1020, 0), (1080, -300)),
        ),
        SampleCurve(
            der.CURVE_VOLT_VAR,
            der.X_PERCENT_VOLTAGE,
            der.Y_PERCENT_MAX_VARS,
            ((900, 440), (970, 0), (1030, 0), (1100, -440)),
        ),
    ),
}


# ---------------------------------------------------------------- settings


def valid_values(point: Point) -> tuple[int, int]:
    """Return two transmitted values inside the range the tables give an output.

    They differ unless the range holds one value.
    """
    low = int(point.minimum) if point.minimum is not None else 0
    high = int(point.maximum) if point.maximum is not None else low + 100
    if high < low:
        low = high - 100
    span = min(high - low, 400)
    if span < 1:
        return low, low
    if span == 1:
        return low, high
    return low + max(1, span // 4), low + max(2, span // 2)


def _tolerance(output: Point, back: Point) -> float:
    """Return how far a readback may be from what was written: half a step of either."""
    steps = [abs(point.multiplier) if point.multiplier else 1.0 for point in (output, back)]
    return max(steps) / 2 * (1 + 1e-9)


def check_settings(
    bench: Bench, outputs: Sequence[Point], which: int, *, enabled: bool = True
) -> Plan[None]:
    """Write one set of valid values to analog outputs, and read each back.

    The value read back is compared in engineering units, since the tables
    scale an output and the input that reads it back independently. With
    ``enabled`` false the readbacks belong to a function that is disabled:
    they are required to carry the value and no ONLINE flag.
    """
    for output in outputs:
        raw = valid_values(output)[which]
        status = yield from bench.set(output, raw)
        bench.accepted(status, f"a write of {raw} to {name(output)}")
    for output in outputs:
        back = bench.readback(output)
        if back is None:
            bench.note(f"no input reads {address(output)} back, so its value was not verified")
            continue
        expected = output.from_wire(valid_values(output)[which])

        def attempt(
            output: Point = output, back: Point = back, expected: float = expected
        ) -> Plan[None]:
            reading = yield from (bench.online(back) if enabled else bench.offline(back))
            raw = reading.raw
            if raw is None or isinstance(raw, bool):
                raise Failed(f"{name(back)} did not report a number")
            read = back.from_wire(raw)
            bench.require(
                abs(read - expected) <= _tolerance(output, back),
                f"{name(back)} reads {read:g}, and {address(output)} was set to {expected:g}",
            )

        yield from bench.eventually(attempt)


def _toggle(bench: Bench, output: Point, back: Point, what: str) -> Plan[None]:
    """Latch an output to its other state and back, and see its readback follow each time."""
    initial = yield from bench.state(back)
    bench.afterwards(f"{name(output)}", lambda: bench.latch(output, initial))
    for target in (not initial, initial):
        status = yield from bench.latch(output, target)
        bench.accepted(status, f"a latch {'on' if target else 'off'} of {name(output)}")
        yield from bench.becomes(back, target, what)


# ---------------------------------------------------------- function checks


def monitoring(bench: Bench) -> Plan[None]:
    """Check that every served point of the system meter is ONLINE and in range."""
    supported = bench.supported_in(Kind.AI, METER)
    if not supported:
        raise NotApplicable("the outstation serves no point of the system meter")
    bench.note(f"{len(supported)} of the meter's {len(METER)} points are served")
    for point in supported:
        reading = yield from bench.online(point)
        raw = reading.raw
        bench.require(
            isinstance(raw, (int, float)) and not isinstance(raw, bool) and point.in_range(raw),
            f"{name(point)} reads {raw}, outside the range the tables give",
        )


def alarms(bench: Bench) -> Plan[None]:
    """Check that every served alarm is ONLINE, and note the ones that are raised."""
    supported = [bench.map.point(Kind.BI, i) for i in ALARMS if bench.supported(Kind.BI, i)]
    if not supported:
        raise NotApplicable("the outstation serves none of the alarm points")
    bench.note(f"{len(supported)} of the {len(ALARMS)} alarm points are served")
    raised = []
    for point in supported:
        if (yield from bench.state(point)):
            raised.append(address(point))
    if raised:
        bench.note(f"raised when read: {', '.join(raised)}")


def operating_states(bench: Bench) -> Plan[None]:
    """Check that every served operating state is ONLINE and that the states agree."""
    supported = bench.supported_in(Kind.BI, STATES)
    if not supported:
        raise NotApplicable("the outstation serves none of the operating state points")
    states: dict[int, bool] = {}
    for point in supported:
        states[point.index] = yield from bench.state(point)
    if BI_STARTED in states and BI_STOPPED in states:
        bench.require(
            not (states[BI_STARTED] and states[BI_STOPPED]),
            f"BI{BI_STARTED} and BI{BI_STOPPED} report started and stopped at once",
        )
    if all(index in states for index in EXCLUSIVE_STATES):
        held = [f"BI{index}" for index in EXCLUSIVE_STATES if states[index]]
        bench.require(
            len(held) == 1,
            f"one of BI{EXCLUSIVE_STATES[0]} to BI{EXCLUSIVE_STATES[-1]} is to be set, "
            f"and {', '.join(held) or 'none'} is",
        )


def connect_and_disconnect(bench: Bench) -> Plan[None]:
    """Check that the connect settings read back and the switch follows its command."""
    switch = bench.map.get(Kind.BO, der.BO_CONNECT)
    closed = None if switch is None else bench.readback(switch)
    if switch is None or closed is None:
        raise NotApplicable("the outstation serves no status of the connect switch")
    settings = bench.supported_in(Kind.AO, CONNECT_SETTINGS)
    for output in settings:
        back = bench.readback(output)
        if back is not None:
            yield from bench.online(back)
    if bench.supported(Kind.BI, BI_SWITCH_MOVING):
        yield from bench.online(bench.map.point(Kind.BI, BI_SWITCH_MOVING))

    yield from check_settings(bench, settings, 0)
    yield from check_settings(bench, settings, 1)
    yield from _toggle(bench, switch, closed, "the connect switch did not follow its command")


@dataclass(frozen=True)
class _Service:
    """The points of the start and stop procedures."""

    start: Point
    stop: Point
    may_start: Point
    may_stop: Point
    starting: Point
    stopping: Point
    started: Point
    stopped: Point


def _service(bench: Bench) -> _Service:
    outputs = (der.BO_START, der.BO_STOP, der.BO_PERMIT_START, der.BO_PERMIT_STOP)
    inputs = (BI_STARTING, BI_STOPPING, BI_STARTED, BI_STOPPED)
    missing = [f"BO{i}" for i in outputs if bench.map.get(Kind.BO, i) is None]
    missing += [f"BI{i}" for i in inputs if not bench.supported(Kind.BI, i)]
    if missing:
        raise NotApplicable(f"the outstation does not serve {', '.join(missing)}")
    return _Service(
        *(bench.map.point(Kind.BO, i) for i in outputs),
        *(bench.map.point(Kind.BI, i) for i in inputs),
    )


def _run_to(bench: Bench, points: _Service, started: bool) -> Plan[None]:
    """Start or stop the DER, and see it get there."""
    command, under_way = (
        (points.start, points.starting) if started else (points.stop, points.stopping)
    )
    word = "start" if started else "stop"
    status = yield from bench.latch(command, True)
    bench.accepted(status, f"the {word}")
    if (yield from bench.state(under_way)):
        bench.note(f"the {word} was seen under way")
    reached, left = (
        (points.started, points.stopped) if started else (points.stopped, points.started)
    )
    yield from bench.becomes(reached, True, f"the {word} did not complete")
    bench.require(not (yield from bench.state(left)), f"{name(left)} is still set after the {word}")
    bench.require(
        not (yield from bench.state(under_way)),
        f"{name(under_way)} is still set after the {word} completed",
    )


def _restore_run(bench: Bench, points: _Service, started: bool) -> None:
    """Have the DER started or stopped again when the check ends, as it was found."""

    def plan() -> Plan[None]:
        if (yield from bench.state(points.started)) is not started:
            yield from _run_to(bench, points, started)

    bench.afterwards("whether the DER is started", plan)


def service(bench: Bench) -> Plan[None]:
    """Check that the service settings read back, then stop and start the DER."""
    points = _service(bench)
    settings = bench.supported_in(Kind.AO, SERVICE_SETTINGS)
    for output in (*settings, points.start, points.stop, points.may_start, points.may_stop):
        back = bench.readback(output)
        if back is not None:
            yield from bench.online(back)

    yield from check_settings(bench, settings, 0)
    yield from check_settings(bench, settings, 1)

    for permission in (points.may_stop, points.may_start):
        back = bench.readback(permission)
        if back is None:
            bench.note(f"no input reads {address(permission)} back, so it was not exercised")
            continue
        yield from _toggle(bench, permission, back, "a permission did not follow its command")

    started = yield from bench.state(points.started)
    _restore_run(bench, points, started)
    for target in (not started, started):
        yield from _run_to(bench, points, target)
        if not target:
            # The input that reads the stop command back says the DER is stopped.
            back = bench.readback(points.stop)
            if back is not None:
                yield from bench.becomes(back, True, "the stop is not read back")


def _permission_off(bench: Bench, permission: Point) -> Plan[None]:
    """Withdraw a permission until the check ends."""
    bench.afterwards(name(permission), lambda: bench.latch(permission, True))
    status = yield from bench.latch(permission, False)
    bench.accepted(status, f"a latch off of {name(permission)}")


def start_without_permission(bench: Bench) -> Plan[None]:
    """Check that a start is refused without permission and the DER stays stopped."""
    points = _service(bench)
    started = yield from bench.state(points.started)
    _restore_run(bench, points, started)
    if started:
        yield from _run_to(bench, points, False)
    yield from _permission_off(bench, points.may_start)
    status = yield from bench.latch(points.start, True)
    bench.refused(status, "a start without permission", CommandStatus.BLOCKED)
    yield from bench.pause(min(bench.settle, 3.0))
    bench.require(
        (yield from bench.state(points.stopped)), "the DER did not stay stopped after the refusal"
    )


def stop_without_permission(bench: Bench) -> Plan[None]:
    """Check that a stop is refused without permission and the DER stays started."""
    points = _service(bench)
    started = yield from bench.state(points.started)
    _restore_run(bench, points, started)
    if not started:
        yield from _run_to(bench, points, True)
    yield from _permission_off(bench, points.may_stop)
    status = yield from bench.latch(points.stop, True)
    bench.refused(status, "a stop without permission", CommandStatus.BLOCKED)
    bench.require(
        not (yield from bench.state(points.stopping)), "a stop is under way after the refusal"
    )
    yield from bench.pause(min(bench.settle, 3.0))
    bench.require(
        (yield from bench.state(points.started)), "the DER did not stay started after the refusal"
    )
    bench.require(not (yield from bench.state(points.stopped)), "the DER stopped after the refusal")


# -------------------------------------------------------------- curve checks


@dataclass
class _Block:
    """The curve block of an outstation, and what the checks do through it."""

    bench: Bench
    #: The selector and the input that reads it back.
    selector: Point
    selected: Point
    #: The input that says whether a function names the selected curve.
    referenced: Point
    #: The outputs after the selector: four fields, then X and Y of each point.
    outputs: list[Point]
    inputs: list[Point]
    #: Each served setting that names a curve and has a sample, with its samples.
    settings: dict[int, tuple[SampleCurve, SampleCurve]] = field(default_factory=dict)
    _count: int | None = None

    def select(self, number: int) -> Plan[CommandStatus]:
        """Show one curve in the block. Return the status."""
        status = yield from self.bench.set(self.selector, number)
        return status

    def show(self, number: int) -> Plan[None]:
        """Show one curve in the block, and require the selector to read it back."""
        status = yield from self.select(number)
        self.bench.accepted(status, f"the selection of curve {number}")
        shown = yield from self.bench.value(self.selected)
        self.bench.require(
            shown == number,
            f"{name(self.selected)} reads {shown:g} after curve {number} was selected",
        )

    def define(self, number: int, sample: SampleCurve) -> Plan[None]:
        """Write a sample curve, and require it to read back as written."""
        written = yield from self.bench.write_curve(
            number,
            type=sample.type,
            x_units=sample.x_units,
            y_units=sample.y_units,
            points=sample.points,
        )
        self.bench.require(
            written.accepted is True,
            f"the {written.stopped_at} of curve {number} was not accepted",
        )
        self.bench.require(written.matches, f"curve {number} does not read back as written")

    def points(self, count: int) -> Plan[list[float]]:
        """Return the first ``count`` X and Y values of the selected curve, as transmitted."""
        values = []
        for reading_of in self.inputs[curves.FIELDS :][: 2 * count]:
            reading = yield from self.bench.online(reading_of)
            values.append(float(reading.raw or 0))
        return values

    def point_to(self, setting: int, number: int) -> Plan[CommandStatus]:
        """Have a function name a curve, or none with zero. Return the status."""
        status = yield from self.bench.set(setting, number)
        return status

    def release(self) -> Plan[None]:
        """Set every setting that names a curve to zero, so no curve is referenced."""
        named = {
            point.index
            for function in self.bench.profile.functions
            for point in function.curve_settings
            if self.bench.supported(Kind.AO, point.index)
        }
        for index in sorted(named | set(self.settings)):
            status = yield from self.point_to(index, 0)
            self.bench.accepted(status, f"a write of 0 to AO{index}")

    def count(self) -> Plan[int | None]:
        """Return how many curves the outstation stores, or None when it cannot be found.

        Each curve is selected in turn until one is refused.
        """
        if self._count is None and self.bench.curves is not None:
            self._count = self.bench.curves
        if self._count is None:
            highest = MAX_CURVES_PROBED
            if self.selector.maximum is not None:
                highest = min(highest, int(self.selector.maximum))
            for number in range(1, highest + 1):
                status = yield from self.select(number)
                if status is not CommandStatus.SUCCESS:
                    self._count = number - 1
                    break
        return self._count

    def enable_of(self, setting: int) -> Function:
        """Return the function a curve setting belongs to."""
        for function in self.bench.profile.functions:
            if any(point.index == setting for point in function.settings if point.kind is Kind.AO):
                return function
        raise NotApplicable(f"the tables give AO{setting} to no function")


def _block(bench: Bench) -> _Block:
    """Return the outstation's curve block, or say the checks of it do not apply."""
    try:
        outputs, inputs = bench.profile.curve_block()
    except ValueError as error:
        raise NotApplicable(str(error)) from None
    referenced = bench.profile.referenced()
    if referenced is None or referenced.address not in bench.served:
        raise NotApplicable("the outstation serves no input that says a curve is referenced")
    unserved = [address(p) for p in (outputs[0], inputs[0]) if p.address not in bench.served]
    if unserved:
        raise NotApplicable(f"the outstation does not serve {', '.join(unserved)}")
    block = _Block(bench, outputs[0], inputs[0], referenced, outputs[1:], inputs[1:])
    block.settings = {
        index: samples
        for index, samples in sorted(SAMPLE_CURVES.items())
        if bench.supported(Kind.AO, index)
    }
    if not block.settings:
        raise NotApplicable(
            "the outstation serves no setting that names a curve of a type with a sample"
        )
    return block


def curve_reference(bench: Bench) -> Plan[None]:
    """Check that the referenced indicator is set only for a curve a function names."""
    block = _block(bench)
    yield from block.release()
    bench.afterwards("which curves the functions name", block.release)
    for index in block.settings:
        back = bench.readback(bench.map.point(Kind.AO, index))
        if back is not None:
            named = yield from bench.raw(back)
            bench.require(named == 0, f"{name(back)} reads {named:g} after it was set to 0")

    total = yield from block.count()
    looked_at = 2 if total is None else min(total, 2)
    for number in range(1, looked_at + 1):
        yield from block.show(number)
        bench.require(
            not (yield from bench.state(block.referenced)),
            f"curve {number} is reported as referenced, and no function names it",
        )

    index, samples = next(iter(block.settings.items()))
    yield from block.define(1, samples[0])
    bench.require(
        not (yield from bench.state(block.referenced)),
        "curve 1 is reported as referenced once defined, and no function names it",
    )
    status = yield from block.point_to(index, 1)
    bench.accepted(status, f"a write of 1 to AO{index}")
    bench.require(
        (yield from bench.state(block.referenced)),
        f"curve 1 is not reported as referenced, and AO{index} names it",
    )

    # With another curve selected, the indicator is about that one.
    if looked_at >= 2:
        yield from block.show(2)
        bench.require(
            not (yield from bench.state(block.referenced)),
            "curve 2 is reported as referenced while only curve 1 is named",
        )
        yield from block.show(1)
    status = yield from block.point_to(index, 0)
    bench.accepted(status, f"a write of 0 to AO{index}")
    bench.require(
        not (yield from bench.state(block.referenced)),
        "curve 1 is still reported as referenced after the function let it go",
    )


def curve_that_does_not_exist(bench: Bench) -> Plan[None]:
    """Check that a curve beyond the last one stored cannot be selected."""
    block = _block(bench)
    total = yield from block.count()
    if total is None:
        raise NotApplicable(
            f"the outstation accepted every curve number up to {MAX_CURVES_PROBED}; "
            "say how many it stores"
        )
    if total < 1:
        raise NotApplicable("the outstation stores no curve")
    if bench.curves is None:
        bench.note(f"the outstation stores {total} curves, found by selecting each")
    yield from block.show(total)
    before = yield from bench.value(block.selected)
    status = yield from block.select(total + 1)
    bench.refused(status, f"the selection of curve {total + 1}", CommandStatus.OUT_OF_RANGE)
    after = yield from bench.value(block.selected)
    bench.require(after == before, f"{name(block.selected)} changed to {after:g} after a refusal")


def _lock_target(
    bench: Bench, block: _Block
) -> tuple[int, SampleCurve, SampleCurve, Function, Point]:
    """Return a curve setting, its samples, its function and the function's status input."""
    index, samples = next(iter(block.settings.items()))
    function = block.enable_of(index)
    status = None if function.status is None else bench.readback(function.enable)
    if status is None:
        raise NotApplicable(f"the outstation serves no input that says {function.name} is enabled")
    return index, samples[0], samples[1], function, status


def _disable_afterwards(bench: Bench, function: Function) -> None:
    bench.afterwards(f"{function.name}, left enabled", lambda: bench.latch(function.enable, False))


def curve_locking(bench: Bench) -> Plan[None]:
    """Check that a curve named by an enabled function cannot be edited."""
    block = _block(bench)
    index, sample, _other, function, enabled = _lock_target(bench, block)
    total = yield from block.count()
    if total is not None and total < 2:
        raise NotApplicable("the outstation stores fewer than two curves")
    locked, free = 1, 2

    yield from block.release()
    bench.afterwards("which curves the functions name", block.release)
    yield from block.define(locked, sample)
    status = yield from block.point_to(index, locked)
    bench.accepted(status, f"a write of {locked} to AO{index}")
    _disable_afterwards(bench, function)
    status = yield from bench.latch(function.enable, True)
    bench.accepted(status, f"the enabling of {function.name}")
    yield from bench.becomes(enabled, True, f"{function.name} was not enabled")

    yield from block.show(locked)
    bench.require(
        (yield from bench.state(block.referenced)),
        f"curve {locked} is not reported as referenced while {function.name} names it",
    )
    watched = min(_WATCHED_POINTS, len(sample.points))
    before = yield from block.points(watched)

    first_x = block.outputs[curves.FIELDS]
    first_y = block.outputs[curves.FIELDS + 1]
    for output, value in ((first_x, before[0] + 10), (first_y, before[1] + 10)):
        status = yield from bench.set(output, int(value))
        bench.refused(
            status,
            f"a write to a point of the locked curve {locked}",
            CommandStatus.AUTOMATION_INHIBIT,
        )
    for output in block.outputs[: curves.FIELDS]:
        status = yield from bench.set(output, 1)
        bench.refused(
            status,
            f"a write to a field of the locked curve {locked}",
            CommandStatus.AUTOMATION_INHIBIT,
        )
    after = yield from block.points(watched)
    bench.require(after == before, f"curve {locked} changed while it was locked")

    # Another curve is not locked by this one being in use.
    yield from block.show(free)
    status = yield from bench.set(first_x, 123)
    bench.accepted(status, f"a write to a point of curve {free}, which no function names")

    # Disabling the function releases the lock.
    status = yield from bench.latch(function.enable, False)
    bench.accepted(status, f"the disabling of {function.name}")
    yield from bench.becomes(enabled, False, f"{function.name} was not disabled")
    yield from block.show(locked)
    status = yield from bench.set(first_x, int(before[0] + 10))
    bench.accepted(
        status, f"a write to a point of curve {locked} once {function.name} was disabled"
    )
    now = yield from block.points(1)
    bench.require(now[0] == before[0] + 10, f"curve {locked} does not read back the write")


def curve_moved_under_function(bench: Bench) -> Plan[None]:
    """Check that an enabled function can move to another curve, freeing the first."""
    block = _block(bench)
    index, first, second, function, enabled = _lock_target(bench, block)
    total = yield from block.count()
    if total is not None and total < 2:
        raise NotApplicable("the outstation stores fewer than two curves")

    yield from block.release()
    bench.afterwards("which curves the functions name", block.release)
    yield from block.define(1, first)
    yield from block.define(2, second)
    status = yield from block.point_to(index, 1)
    bench.accepted(status, f"a write of 1 to AO{index}")
    _disable_afterwards(bench, function)
    status = yield from bench.latch(function.enable, True)
    bench.accepted(status, f"the enabling of {function.name}")
    yield from bench.becomes(enabled, True, f"{function.name} was not enabled")
    status = yield from block.point_to(index, 2)
    bench.accepted(status, f"a write of 2 to AO{index} while {function.name} is enabled")

    first_x = block.outputs[curves.FIELDS]
    yield from block.show(1)
    status = yield from bench.set(first_x, 111)
    bench.accepted(status, "a write to a point of curve 1, which the function left")
    yield from block.show(2)
    status = yield from bench.set(first_x, 111)
    bench.refused(
        status,
        "a write to a point of curve 2, which the function now names",
        CommandStatus.AUTOMATION_INHIBIT,
    )


def curve_type_mismatch(bench: Bench) -> Plan[None]:
    """Check that a function cannot name a curve of a type it does not follow."""
    block = _block(bench)
    kinds = {index: samples[0] for index, samples in block.settings.items()}
    pairs = [
        (one, other) for one in kinds for other in kinds if kinds[one].type != kinds[other].type
    ]
    if not pairs:
        raise NotApplicable(
            "the outstation serves no two settings that name curves of different types"
        )
    first, second = pairs[0]
    back = bench.readback(bench.map.point(Kind.AO, second))

    yield from block.release()
    bench.afterwards("which curves the functions name", block.release)
    yield from block.define(1, kinds[first])

    status = yield from block.point_to(second, 1)
    bench.refused(
        status, f"pointing AO{second} at a curve of another type", CommandStatus.NOT_SUPPORTED
    )
    if back is not None:
        named = yield from bench.raw(back)
        bench.require(named == 0, f"{name(back)} reads {named:g} after the refusal")
    status = yield from block.point_to(first, 1)
    bench.accepted(status, f"pointing AO{first} at a curve of its own type")

    # Nor can a curve be turned into another type under a function that names it.
    yield from block.show(1)
    type_field = block.outputs[curves.TYPE]
    status = yield from bench.set(type_field, kinds[second].type)
    bench.refused(
        status, "changing the type of a curve a function names", CommandStatus.NOT_SUPPORTED
    )
    status = yield from block.point_to(first, 0)
    bench.accepted(status, f"a write of 0 to AO{first}")
    status = yield from bench.set(type_field, kinds[second].type)
    bench.accepted(status, "changing the type of a curve no function names")


def curve_not_defined(bench: Bench) -> Plan[None]:
    """Check that a function cannot name a curve with no type, or one that does not exist."""
    block = _block(bench)
    index = next(iter(block.settings))
    total = yield from block.count()
    if total is None:
        raise NotApplicable(
            f"the outstation accepted every curve number up to {MAX_CURVES_PROBED}; "
            "say how many it stores"
        )
    yield from block.release()
    bench.afterwards("which curves the functions name", block.release)

    undefined = None
    for number in range(total, 0, -1):
        yield from block.show(number)
        kind = yield from bench.raw(block.inputs[curves.TYPE])
        if kind == 0:
            undefined = number
            break
    if undefined is None:
        bench.note("every curve the outstation stores has a type, so none was undefined")
    else:
        status = yield from block.point_to(index, undefined)
        bench.refused(
            status,
            f"pointing AO{index} at curve {undefined}, which has no type",
            CommandStatus.NOT_SUPPORTED,
        )
    status = yield from block.point_to(index, total + 1)
    bench.refused(
        status,
        f"pointing AO{index} at curve {total + 1}, which does not exist",
        CommandStatus.OUT_OF_RANGE,
    )


# --------------------------------------------------------------- mode checks


@dataclass
class _Mode:
    """One function's points, as the outstation serves them."""

    function: Function
    #: Analog outputs that are settings of the function and are served.
    settings: list[Point] = field(default_factory=list)
    #: Binary outputs of the function other than the one that enables it.
    switches: list[Point] = field(default_factory=list)
    #: The function's served inputs, readbacks included.
    inputs: list[Point] = field(default_factory=list)
    #: The served settings that name a curve and have a sample, with the samples.
    curves: dict[int, tuple[SampleCurve, SampleCurve]] = field(default_factory=dict)
    #: Every point the tables give the function, served or not.
    points: list[Point] = field(default_factory=list)


def _mode(bench: Bench, function: Function) -> _Mode:
    mode = _Mode(function)
    naming = {point.index for point in function.curve_settings}
    for point in (*function.settings, *function.inputs):
        mode.points.append(point)
        if point.address not in bench.served:
            continue
        if point.kind is Kind.AO:
            if point.index in SAMPLE_CURVES:
                mode.curves[point.index] = SAMPLE_CURVES[point.index]
            elif point.index in naming:
                bench.note(f"{address(point)} names a curve of a type with no sample; not written")
            else:
                mode.settings.append(point)
        elif point.kind is Kind.BO:
            mode.switches.append(point)
        else:
            mode.inputs.append(point)
    return mode


def _unsupported(bench: Bench, mode: _Mode) -> Plan[None]:
    """Check that an unsupported function cannot be enabled and serves none of its points."""
    enable = mode.function.enable
    status = yield from bench.latch(enable, True)
    if status is CommandStatus.SUCCESS:
        _disable_afterwards(bench, mode.function)
    bench.refused(status, f"the enabling of {mode.function.name}", CommandStatus.NOT_SUPPORTED)
    served = [address(point) for point in mode.points if point.address in bench.served]
    bench.require(
        not served,
        f"{mode.function.name} is reported as not supported, and the outstation serves "
        + ", ".join(served),
    )


def _all(bench: Bench, points: Sequence[Point], *, online: bool) -> Plan[None]:
    """Require each point to be ONLINE, or each to be offline, within the settling time."""

    def attempt() -> Plan[None]:
        for point in points:
            yield from (bench.online(point) if online else bench.offline(point))

    yield from bench.eventually(attempt)


def _supported(bench: Bench, mode: _Mode) -> Plan[None]:
    """Read the function's points, write its settings twice, and disable it.

    The standard has the inputs of a function that is not enabled reported
    without the ONLINE flag. So the points are read while the function is
    disabled, where they must carry their values and no ONLINE flag, and
    again once it is enabled, where they must be ONLINE.
    """
    function = mode.function
    enabled = None if function.status is None else bench.readback(function.enable)
    bench.require(
        enabled is not None,
        f"the outstation says it supports {function.name}, and serves no input that says "
        "whether it is enabled",
    )
    assert enabled is not None
    block = None
    if mode.curves:
        try:
            block = _block(bench)
        except NotApplicable as reason:
            bench.note(f"its curve was not written: {reason}")
            mode.curves = {}
    if block is not None:
        yield from block.release()
        bench.afterwards("which curves the functions name", block.release)

    if (yield from bench.state(enabled)):
        bench.note(f"{function.name} was enabled, and is left disabled")
        status = yield from bench.latch(function.enable, False)
        bench.accepted(status, f"the disabling of {function.name}")
        yield from bench.becomes(enabled, False, f"{function.name} was not disabled")
    yield from _all(bench, mode.inputs, online=False)
    yield from check_settings(bench, mode.settings, 1, enabled=False)

    _disable_afterwards(bench, function)
    status = yield from bench.latch(function.enable, True)
    bench.accepted(status, f"the enabling of {function.name}")
    yield from bench.becomes(enabled, True, f"{function.name} was not enabled")
    yield from _all(bench, mode.inputs, online=True)

    for which in (0, 1):
        yield from check_settings(bench, mode.settings, which)
        for switch in mode.switches:
            status = yield from bench.latch(switch, which == 0)
            bench.accepted(status, f"a latch of {name(switch)}")
            back = bench.readback(switch)
            if back is not None:
                yield from bench.becomes(back, which == 0, f"{address(switch)} is not read back")
        for offset, (index, samples) in enumerate(sorted(mode.curves.items())):
            assert block is not None
            number = 1 + which * len(mode.curves) + offset
            yield from block.define(number, samples[which])
            status = yield from block.point_to(index, number)
            bench.accepted(status, f"a write of {number} to AO{index}")
            back = bench.readback(bench.map.point(Kind.AO, index))
            if back is not None:
                named = yield from bench.value(back)
                bench.require(named == number, f"{name(back)} reads {named:g}, not {number}")

    status = yield from bench.latch(function.enable, False)
    bench.accepted(status, f"the disabling of {function.name}")
    yield from bench.becomes(enabled, False, f"{function.name} was not disabled")
    yield from _all(bench, mode.inputs, online=False)
    for index in mode.curves:
        assert block is not None
        status = yield from block.point_to(index, 0)
        bench.accepted(status, f"a write of 0 to AO{index}")
        back = bench.readback(bench.map.point(Kind.AO, index))
        if back is not None:
            named = yield from bench.raw(back)
            bench.require(named == 0, f"{name(back)} reads {named:g} after it was set to 0")


def mode_check(enable: int) -> Callable[[Bench], Plan[None]]:
    """Return the mode procedure for the function a binary output enables."""

    def procedure(bench: Bench) -> Plan[None]:
        function = next(
            (each for each in bench.profile.functions if each.enable.index == enable), None
        )
        if function is None:
            raise NotApplicable(f"the tables have no function enabled by BO{enable}")
        if function.supports.address not in bench.served:
            raise NotApplicable(
                f"the outstation does not serve {name(function.supports)}, which says whether "
                f"it supports {function.name}"
            )
        supported = yield from bench.state(function.supports)
        bench.title = f"{function.name}: {'supported' if supported else 'not supported'}"
        described = _mode(bench, function)
        if supported:
            yield from _supported(bench, described)
        else:
            yield from _unsupported(bench, described)

    return procedure


# ---------------------------------------------------------- the device profile


def device_profile(bench: Bench) -> Plan[None]:
    """Check that the outstation serves the points its Device Profile declares, and no others."""
    if bench.device_profile is None:
        raise NotApplicable("no Device Profile document was given")
    comparison = yield from bench.compare(bench.device_profile)
    bench.note(f"{len(comparison.served)} of {len(comparison.declared)} declared points are served")

    kinds = {point_type: kind.value for kind, point_type in POINT_TYPES.items()}

    def where(point_type: PointType, index: int) -> str:
        return f"{kinds.get(point_type, point_type.value + ' ')}{index}"

    def some(items: Sequence[str]) -> str:
        return ", ".join(items[:8]) + (f" and {len(items) - 8} more" if len(items) > 8 else "")

    problems = []
    if comparison.absent:
        absent = [where(each.type, each.index) for each in comparison.absent]
        problems.append(f"declared and not served: {some(absent)}")
    if comparison.undeclared:
        undeclared = [where(kind, index) for kind, index in comparison.undeclared]
        problems.append(f"served and not declared: {some(undeclared)}")
    if comparison.class_0:
        misplaced = [
            f"{where(each.type, each.index)} ({'in' if carried else 'not in'} class 0)"
            for each, carried in comparison.class_0
        ]
        problems.append(f"class 0 is not as declared: {some(misplaced)}")
    bench.require(not problems, "; ".join(problems))


# ----------------------------------------------------------------- the catalog

CATALOG: tuple[Check, ...] = (
    Check(
        "PROFILE-001",
        "Device Profile agrees with what is served",
        False,
        device_profile,
        "device-profile",
    ),
    Check("MON-001", "Monitoring", False, monitoring),
    Check("ALARM-001", "Alarm reporting", False, alarms),
    Check("OP-001", "Operating states", False, operating_states),
    Check("CONN-001", "Connect and disconnect", True, connect_and_disconnect),
    Check("SERV-001", "Cease to energize and return to service", True, service),
    Check("SERV-001.2", "A start without permission is refused", True, start_without_permission),
    Check("SERV-001.3", "A stop without permission is refused", True, stop_without_permission),
    Check("CURVE-001", "Curve reference indication", True, curve_reference),
    Check(
        "CURVE-001.2",
        "A curve that does not exist cannot be selected",
        True,
        curve_that_does_not_exist,
    ),
    Check("CURVE-002", "Curve locking", True, curve_locking),
    Check(
        "CURVE-002.2",
        "An enabled function can be moved to another curve",
        True,
        curve_moved_under_function,
    ),
    Check("CURVE-003", "Curve and function type mismatch", True, curve_type_mismatch),
    Check("CURVE-003.2", "A curve that is not defined or does not exist", True, curve_not_defined),
    *(
        Check(identifier, f"The function enabled by BO{enable}", True, mode_check(enable))
        for identifier, enable in MODES.items()
    ),
)


def select(wanted: Sequence[str] | None) -> tuple[Check, ...]:
    """Return the checks named, in the catalog's order, or all of them for None.

    A name is a check's identifier or a group, in any case. Raises ValueError
    for a name that is neither.
    """
    if not wanted:
        return CATALOG
    names = {each.casefold() for each in wanted}
    known = {check.id.casefold() for check in CATALOG} | {check.group for check in CATALOG}
    unknown = sorted(names - known)
    if unknown:
        raise ValueError(f"{unknown[0]!r} is not a check; see `py1815-master evaluate --list`")
    return tuple(check for check in CATALOG if check.id.casefold() in names or check.group in names)


__all__ = ["CATALOG", "MODES", "SAMPLE_CURVES", "Check", "SampleCurve", "select", "valid_values"]
