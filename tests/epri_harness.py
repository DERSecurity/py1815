"""A DER under test and the steps the DER profile test procedures are made of.

EPRI's *Test Procedure for Validating DNP Application Note AN2018-001 in
Distributed Energy Resources* (3002016144) exercises an outstation the way a
controlling station uses the DER profile: read a function's points, write its
settings, read them back, enable and disable it, and edit curves through the
one window all curves share. This module is the tester's side of that.

Which input reads an output back, which points belong to one function and
which input says a function is supported are all read from the point tables
the outstation was built from, so the procedures here carry no point list of
their own. Run against the IEEE 1815.2 tables they test the published
pairings; run against the synthetic tables in ``profile_fixtures`` they test
the same machinery where the published tables are not available.

The procedure's conformance statement, the list of which points a device
supports, is not a separate document here: a point is supported if the
outstation serves it.

Requests are built and responses parsed by the test master of
``ied_harness``, so every exchange crosses the link, transport and
application layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from ied_harness import (
    DIRECT_OPERATE,
    FLAG_ONLINE,
    OPERATE,
    Q_INDEX_16,
    Q_RANGE_16,
    SELECT,
    Obj,
    TestMaster,
    analog_output,
    crob,
    header,
)
from profile_fixtures import REAL_TABLES, paired_reference_der

from py1815.control import CommandStatus
from py1815.profile import curves, der, load
from py1815.profile.model import Composition, Kind, Point, PointMap

#: The object each kind of point is read as, with its flags.
_STATIC = {Kind.BI: (1, 2), Kind.AI: (30, 1), Kind.BO: (10, 2), Kind.AO: (40, 1)}

LATCH_ON, LATCH_OFF = 0x03, 0x04

#: Which tables the procedures run against.
TABLES = ("synthetic", "ieee-1815-2")

#: A valid curve of each type the simulated DER follows, twice over, as the
#: units of each axis and the points: voltage in tenths of a percent of
#: nominal against vars or watts in tenths of a percent of rating.
CURVES: dict[int, list[tuple[int, int, list[tuple[int, int]]]]] = {
    der.CURVE_VOLT_VAR: [
        (
            der.X_PERCENT_VOLTAGE,
            der.Y_PERCENT_MAX_VARS,
            [(920, 300), (980, 0), (1020, 0), (1080, -300)],
        ),
        (
            der.X_PERCENT_VOLTAGE,
            der.Y_PERCENT_MAX_VARS,
            [(900, 440), (970, 0), (1030, 0), (1100, -440)],
        ),
    ],
    der.CURVE_VOLT_WATT: [
        (der.X_PERCENT_VOLTAGE, der.Y_PERCENT_MAX_WATTS, [(1000, 1000), (1060, 1000), (1100, 200)]),
        (der.X_PERCENT_VOLTAGE, der.Y_PERCENT_MAX_WATTS, [(1000, 1000), (1050, 1000), (1090, 0)]),
    ],
}


def point_map(tables: str) -> PointMap:
    """The point map for one of :data:`TABLES`, skipping when it is not available."""
    if tables == "synthetic":
        return load.resolve(paired_reference_der(), Composition())
    if not REAL_TABLES.exists():
        pytest.skip("the IEEE 1815.2 point tables are not present on this machine")
    return load.load(REAL_TABLES)


@dataclass
class Mode:
    """One DER function, as the tables group its points."""

    enable: Point
    supports: Point
    #: Analog outputs that are settings of the function and are served.
    settings: list[Point] = field(default_factory=list)
    #: Binary outputs of the function other than the one that enables it.
    switches: list[Point] = field(default_factory=list)
    #: Every input of the function that is served, readbacks included, other
    #: than the one that says whether the function is enabled.
    inputs: list[Point] = field(default_factory=list)
    #: The settings that name a curve, with the curve types each accepts.
    curves: dict[int, tuple[int, ...]] = field(default_factory=dict)
    #: Every point the tables give the function, served or not.
    points: list[Point] = field(default_factory=list)


class Dut:
    """The simulated DER behind its outstation, and a master to talk to it."""

    def __init__(self, points: PointMap) -> None:
        self.map = points
        self.simulation = der.build(points)
        self.outstation = self.simulation.outstation
        self.master = TestMaster(self.outstation.session(need_time=False))
        self._served = {point.address for kind in Kind for point in self.outstation.served(kind)}

    # ------------------------------------------------- conformance statement

    def supported(self, kind: Kind, index: int) -> bool:
        """Whether the device's conformance statement would list this point."""
        return (kind, index) in self._served

    def supported_in(self, kind: Kind, indices: range) -> list[Point]:
        """The supported points of one kind within a range of indices."""
        return [self.map.point(kind, i) for i in indices if self.supported(kind, i)]

    def readback(self, output: Point) -> Point | None:
        """The input that reads an output back, if the tables pair one and it is served."""
        paired = output.associated
        if paired is None or paired[0].is_output or paired not in self._served:
            return None
        return self.map.point(*paired)

    def mode(self, enable_index: int) -> Mode | None:
        """The function enabled by a binary output, or None if the tables have no such output."""
        enable = self.map.get(Kind.BO, enable_index)
        if enable is None:
            return None
        supports = [point for point in self.map.of(Kind.BI) if point.enabled_by == enable.address]
        assert len(supports) == 1, (
            f"BO{enable_index} is paired with {len(supports)} supports inputs"
        )
        purpose = (enable.purpose or "").casefold()
        assert purpose, f"the tables give BO{enable_index} no purpose to group its points by"
        mode = Mode(enable=enable, supports=supports[0])
        following = {f.curve: f.curve_types for f in der.FUNCTIONS if f.curve is not None}
        for point in self.map.points.values():
            if (point.purpose or "").casefold() != purpose or point.section != enable.section:
                continue
            if point.address in (enable.address, supports[0].address, enable.associated):
                continue
            mode.points.append(point)
            if point.address not in self._served:
                continue
            if point.kind is Kind.AO:
                if point.index in following:
                    mode.curves[point.index] = following[point.index]
                else:
                    mode.settings.append(point)
            elif point.kind is Kind.BO:
                mode.switches.append(point)
            else:
                mode.inputs.append(point)
        return mode

    def curve_settings(self) -> dict[int, tuple[int, ...]]:
        """Every served setting that names a curve, with the types it accepts."""
        return {
            f.curve: f.curve_types
            for f in der.FUNCTIONS
            if f.curve is not None and self.supported(Kind.AO, f.curve)
        }

    # ---------------------------------------------------------------- reading

    def obtain(self, kind: Kind, index: int) -> Obj | None:
        """Read one point by its index. None when the outstation answers with an error."""
        group, variation = _STATIC[kind]
        fragment = self.master.read(header(group, variation, Q_RANGE_16, index, index)).fragment
        if fragment.is_error:
            return None
        (obtained,) = fragment.objects
        assert (obtained.group, obtained.index) == (group, index)
        return obtained

    def online(self, point: Point) -> Obj:
        """Read a point and require it to be reported ONLINE with no other quality flag."""
        obtained = self.obtain(point.kind, point.index)
        assert obtained is not None, f"{point.kind.value}{point.index} could not be obtained"
        quality = obtained.flags & 0x7F if point.kind in (Kind.BI, Kind.BO) else obtained.flags
        assert quality == FLAG_ONLINE, (
            f"{point.kind.value}{point.index} is reported with flags {obtained.flags:#04x}"
        )
        return obtained

    def offline(self, point: Point) -> Obj:
        """Read a point and require it to be sent with its value and no flag: not in effect."""
        obtained = self.obtain(point.kind, point.index)
        assert obtained is not None, f"{point.kind.value}{point.index} could not be obtained"
        quality = obtained.flags & 0x7F if point.kind in (Kind.BI, Kind.BO) else obtained.flags
        assert quality == 0, (
            f"{point.kind.value}{point.index} is reported with flags {obtained.flags:#04x}"
        )
        return obtained

    def raw(self, point: Point) -> float:
        """An analog point's value in engineering units, whatever its flags say."""
        obtained = self.obtain(point.kind, point.index)
        assert obtained is not None, f"{point.kind.value}{point.index} could not be obtained"
        return point.from_wire(obtained.value)

    def state(self, point: Point) -> bool:
        """A binary point's state, required to be ONLINE."""
        return self.online(point).state

    def value(self, point: Point) -> float:
        """An analog point's value in engineering units, required to be ONLINE."""
        return point.from_wire(self.online(point).value)

    # ---------------------------------------------------------------- writing

    def set(self, index: int, raw: int) -> CommandStatus:
        """Direct operate one analog output with a transmitted value."""
        body = analog_output(index, raw, variation=1, qualifier=Q_INDEX_16)
        (echo,) = self.master.request(DIRECT_OPERATE, body).fragment.objects
        return CommandStatus(echo.status)

    def latch(self, index: int, on: bool) -> CommandStatus:
        """Select and then operate one binary output."""
        body = crob(index, LATCH_ON if on else LATCH_OFF, qualifier=Q_INDEX_16)
        (selected,) = self.master.request(SELECT, body).fragment.objects
        if selected.status != CommandStatus.SUCCESS:
            return CommandStatus(selected.status)
        (echo,) = self.master.request(OPERATE, body).fragment.objects
        return CommandStatus(echo.status)

    def advance(self, seconds: int) -> None:
        """Let the simulated DER run for a while, a second at a time."""
        for _ in range(seconds):
            self.simulation.advance(1.0)

    # ----------------------------------------------------------------- curves

    def select_curve(self, number: int) -> CommandStatus:
        """Point the curve window at one curve."""
        return self.set(der.AO_CURVE_SELECTOR, number)

    def define_curve(self, number: int, kind: int, variant: int = 0) -> None:
        """Select a curve and give it valid settings for one curve type."""
        x_units, y_units, points = CURVES[kind][variant]
        assert self.select_curve(number) is CommandStatus.SUCCESS
        first = der.AO_CURVE_SELECTOR + 1
        writes = [
            (first + curves.TYPE, kind),
            (first + curves.X_UNITS, x_units),
            (first + curves.Y_UNITS, y_units),
        ]
        for position, (x, y) in enumerate(points):
            writes.append((first + curves.FIELDS + 2 * position, x))
            writes.append((first + curves.FIELDS + 2 * position + 1, y))
        writes.append((first + curves.POINT_COUNT, len(points)))
        for index, raw in writes:
            assert self.set(index, raw) is CommandStatus.SUCCESS, f"AO{index} refused {raw}"

    def curve_points(self, count: int) -> list[int]:
        """The first *count* X and Y values of the selected curve, as read from its inputs."""
        first = der.AI_CURVE_SELECTOR + 1 + curves.FIELDS
        return [self.online(self.map.point(Kind.AI, first + n)).value for n in range(2 * count)]

    def release_curves(self) -> None:
        """Set every function's curve number to zero, so no curve is referenced."""
        for index in self.curve_settings():
            assert self.set(index, 0) is CommandStatus.SUCCESS


def valid_values(point: Point) -> tuple[int, int]:
    """Two different transmitted values inside the range the tables give an output."""
    low = int(point.minimum) if point.minimum is not None else 0
    high = int(point.maximum) if point.maximum is not None else low + 100
    span = min(high - low, 400)
    assert span >= 1, f"{point.kind.value}{point.index} has a range of one value"
    if span == 1:
        return low, high
    return low + max(1, span // 4), low + max(2, span // 2)


def check_settings(dut: Dut, outputs: list[Point], which: int, *, enabled: bool = True) -> None:
    """Write one set of valid values to some analog outputs and read each back.

    The value read back is compared in engineering units, since the tables
    scale an output and the input that reads it back independently. With
    *enabled* false the readbacks belong to a function that is disabled, and
    are required to carry the value without the ONLINE flag.
    """
    for output in outputs:
        raw = valid_values(output)[which]
        assert output.in_range(raw)
        assert dut.set(output.index, raw) is CommandStatus.SUCCESS, (
            f"AO{output.index} refused {raw}"
        )
    for output in outputs:
        back = dut.readback(output)
        if back is None:
            continue
        expected = output.from_wire(valid_values(output)[which])
        obtained = dut.online(back) if enabled else dut.offline(back)
        assert back.from_wire(obtained.value) == pytest.approx(expected), (
            f"AI{back.index} does not read back what AO{output.index} was set to"
        )
