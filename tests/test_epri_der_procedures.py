"""EPRI's test procedure for the DER profile, carried out against the simulated DER.

Each test is one procedure of EPRI report 3002016144, *Test Procedure for
Validating DNP Application Note AN2018-001 in Distributed Energy Resources*,
and is named for the identifier the report gives it: ``test_mon_001`` is
MON-001. The report is EPRI's and is not reproduced; the steps are described
here in our own words. ``test_epri_coverage.py`` accounts for every
procedure in it.

The report was written against the application note that IEEE 1815.2 has
since replaced. Where the two differ this suite follows the standard: point
pairings come from the IEEE tables, and a write to a locked curve is refused
with the status the standard recommends.

Every procedure runs twice: against synthetic tables, which is what CI has,
and against the IEEE 1815.2 tables on a machine that holds them.
"""

from __future__ import annotations

import pytest
from epri_harness import TABLES, Dut, Mode, check_settings, point_map
from profile_fixtures import UNSUPPORTED

from py1815.control import CommandStatus
from py1815.profile import der
from py1815.profile.model import Kind

#: The mode procedures of chapter 5, by the binary output that enables the
#: function each one tests.
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

#: The procedures whose function the simulated DER implements.
IMPLEMENTED = {"APL-001", "CHG-001", "VW-001", "CVAR-001", "FPF-001", "VV-001"}

# Points the function procedures of chapter 3 name outright.
METER = range(533, 557)
ALARMS = (*range(0, 10), *range(94, 106))
STATES = range(10, 23)
BI_STARTING, BI_STOPPING, BI_STARTED, BI_STOPPED = 12, 13, 14, 15
BI_SWITCH_MOVING = 24
CONNECT_SETTINGS = range(16, 18)
SERVICE_SETTINGS = range(6, 16)


@pytest.fixture(params=TABLES)
def dut(request: pytest.FixtureRequest) -> Dut:
    return Dut(point_map(request.param))


# ------------------------------------------------------------ function tests


def test_mon_001_monitoring(dut: Dut) -> None:
    """Every supported measurement of the system meter is obtained, ONLINE and in range."""
    dut.advance(30)
    supported = dut.supported_in(Kind.AI, METER)
    assert len(supported) == len(METER), "the simulated DER serves the whole meter block"
    for point in supported:
        obtained = dut.online(point)
        assert point.in_range(obtained.value), (
            f"AI{point.index} reads {obtained.value}, outside the range the tables give"
        )
    watts, total = dut.map.point(Kind.AI, METER[4]), dut.simulation.der.watts
    assert dut.value(watts) == pytest.approx(total, abs=max(1.0, watts.multiplier or 1.0))


def test_alarm_001_alarm_reporting(dut: Dut) -> None:
    """Every supported alarm is obtained and ONLINE."""
    supported = [dut.map.point(Kind.BI, i) for i in ALARMS if dut.supported(Kind.BI, i)]
    assert len(supported) == len(ALARMS)
    for point in supported:
        assert dut.state(point) in (False, True)
    # A healthy DER at rest raises none of them.
    assert not any(dut.state(point) for point in supported[:4])


def test_alarm_001_an_alarm_that_is_raised_is_reported(dut: Dut) -> None:
    """Valid for the point means it follows the condition, not only that it reads."""
    full, too_high = dut.map.point(Kind.BI, 4), dut.map.point(Kind.BI, 5)
    assert not dut.state(full) and not dut.state(too_high)
    dut.simulation.der.state_of_charge = 100.0
    assert dut.state(full) and dut.state(too_high)


def test_op_001_operation_states(dut: Dut) -> None:
    """Every supported operating state is obtained and ONLINE, and they agree with each other."""
    supported = dut.supported_in(Kind.BI, STATES)
    assert supported
    states = {point.index: dut.state(point) for point in supported}
    assert states[BI_STARTED] and not states[BI_STOPPED]
    assert not states[BI_STARTING] and not states[BI_STOPPING]
    # Exactly one of connected-and-idle, generating, charging, off-available, off-unavailable.
    assert sum(states[index] for index in range(18, 23)) == 1


def test_conn_001_connect_and_disconnect(dut: Dut) -> None:
    """The connect settings read back what was written, and the switch follows its command."""
    switch = dut.map.point(Kind.BO, der.BO_CONNECT)
    closed = dut.readback(switch)
    assert closed is not None, "the switch status is supported, so the procedure runs in full"
    settings = dut.supported_in(Kind.AO, CONNECT_SETTINGS)
    assert len(settings) == len(CONNECT_SETTINGS)
    for output in settings:
        back = dut.readback(output)
        assert back is not None
        dut.online(back)
    if dut.supported(Kind.BI, BI_SWITCH_MOVING):
        dut.online(dut.map.point(Kind.BI, BI_SWITCH_MOVING))

    check_settings(dut, settings, 0)
    check_settings(dut, settings, 1)

    assert dut.latch(switch.index, False) is CommandStatus.SUCCESS
    assert not dut.state(closed)
    assert not dut.simulation.der.connected
    assert dut.latch(switch.index, True) is CommandStatus.SUCCESS
    assert dut.state(closed)
    assert dut.simulation.der.connected


def test_serv_001_cease_to_energize_and_return_to_service(dut: Dut) -> None:
    """The service settings read back, and stop and start are seen happening and done."""
    settings = dut.supported_in(Kind.AO, SERVICE_SETTINGS)
    assert len(settings) == len(SERVICE_SETTINGS)
    start, stop, may_start, may_stop = (
        dut.map.point(Kind.BO, index)
        for index in (der.BO_START, der.BO_STOP, der.BO_PERMIT_START, der.BO_PERMIT_STOP)
    )
    state = {
        index: dut.map.point(Kind.BI, index)
        for index in (BI_STARTING, BI_STOPPING, BI_STARTED, BI_STOPPED)
    }
    for output in (*settings, start, stop, may_start, may_stop):
        back = dut.readback(output)
        assert back is not None, f"{output.kind.value}{output.index} has no readback"
        dut.online(back)
    for point in state.values():
        dut.online(point)

    check_settings(dut, settings, 0)
    check_settings(dut, settings, 1)

    for permission in (may_stop, may_start):
        back = dut.readback(permission)
        assert back is not None
        assert dut.latch(permission.index, False) is CommandStatus.SUCCESS
        assert not dut.state(back)
        assert dut.latch(permission.index, True) is CommandStatus.SUCCESS
        assert dut.state(back)

    assert dut.latch(stop.index, True) is CommandStatus.SUCCESS
    assert dut.state(state[BI_STOPPING]), "the stop is seen under way"
    dut.advance(3)
    assert dut.state(state[BI_STOPPED]) and not dut.state(state[BI_STARTED])
    assert not dut.state(state[BI_STOPPING])
    stopped = dut.readback(stop)
    assert stopped is not None and dut.state(stopped)

    assert dut.latch(start.index, True) is CommandStatus.SUCCESS
    starting = dut.readback(start)
    assert starting is not None and dut.state(starting), "the start is seen under way"
    assert dut.state(state[BI_STARTING])
    dut.advance(3)
    assert dut.state(state[BI_STARTED]) and not dut.state(state[BI_STOPPED])
    assert not dut.state(state[BI_STARTING])


def test_serv_001_a_start_without_permission_is_refused(dut: Dut) -> None:
    assert dut.latch(der.BO_STOP, True) is CommandStatus.SUCCESS
    dut.advance(3)
    assert dut.latch(der.BO_PERMIT_START, False) is CommandStatus.SUCCESS
    assert dut.latch(der.BO_START, True) is CommandStatus.BLOCKED
    dut.advance(3)
    assert dut.state(dut.map.point(Kind.BI, BI_STOPPED))


# --------------------------------------------------------------- curve tests


def _curve_modes(dut: Dut) -> list[tuple[int, int]]:
    """Each supported curve-following setting with a curve type it accepts."""
    return [(index, types[0]) for index, types in sorted(dut.curve_settings().items())]


def test_curve_001_reference_indication(dut: Dut) -> None:
    """The referenced indicator is clear for a curve no function names, and set once one does."""
    referenced = dut.map.point(Kind.BI, der.BI_CURVE_REFERENCED)
    selected = dut.map.point(Kind.AI, der.AI_CURVE_SELECTOR)
    modes = _curve_modes(dut)
    assert len(modes) >= 2, "the simulated DER has more than one function that follows a curve"

    dut.release_curves()
    for index, _ in modes:
        back = dut.readback(dut.map.point(Kind.AO, index))
        assert back is not None and dut.raw(back) == 0

    for number in range(1, len(modes) + 1):
        assert dut.select_curve(number) is CommandStatus.SUCCESS
        assert dut.value(selected) == number
        assert not dut.state(referenced)

    assert dut.select_curve(1) is CommandStatus.SUCCESS
    assert dut.value(selected) == 1
    assert not dut.state(referenced)

    index, kind = modes[0]
    dut.define_curve(1, kind)
    assert not dut.state(referenced), "defining a curve does not make a function name it"
    assert dut.set(index, 1) is CommandStatus.SUCCESS
    assert dut.state(referenced)

    # Looking at another curve, the indicator is about that one.
    assert dut.select_curve(2) is CommandStatus.SUCCESS
    assert not dut.state(referenced)
    assert dut.select_curve(1) is CommandStatus.SUCCESS
    assert dut.set(index, 0) is CommandStatus.SUCCESS
    assert not dut.state(referenced), "and it clears when the function lets the curve go"


def test_curve_001_a_curve_that_does_not_exist_cannot_be_selected(dut: Dut) -> None:
    selected = dut.map.point(Kind.AI, der.AI_CURVE_SELECTOR)
    before = dut.value(selected)
    assert dut.select_curve(der.CURVE_COUNT + 1) is CommandStatus.OUT_OF_RANGE
    assert dut.value(selected) == before


def _enable_of(setting: int) -> int:
    (function,) = (f for f in der.FUNCTIONS if f.curve == setting)
    return function.enable


def test_curve_002_curve_locking(dut: Dut) -> None:
    """A curve named by an enabled function cannot be edited, and is left as it was."""
    referenced = dut.map.point(Kind.BI, der.BI_CURVE_REFERENCED)
    selected = dut.map.point(Kind.AI, der.AI_CURVE_SELECTOR)
    index, kind = _curve_modes(dut)[0]
    enable = dut.map.point(Kind.BO, _enable_of(index))
    enabled = dut.readback(enable)
    assert enabled is not None

    dut.release_curves()
    dut.define_curve(3, kind)
    assert dut.set(index, 3) is CommandStatus.SUCCESS
    assert dut.latch(enable.index, True) is CommandStatus.SUCCESS
    assert dut.state(enabled)

    assert dut.select_curve(3) is CommandStatus.SUCCESS
    assert dut.value(selected) == 3
    assert dut.state(referenced)
    before = dut.curve_points(4)

    first_x = der.AO_CURVE_SELECTOR + 1 + der.CURVE_FIELDS
    assert dut.set(first_x, before[0] + 10) is CommandStatus.AUTOMATION_INHIBIT
    assert dut.set(first_x + 1, before[1] + 10) is CommandStatus.AUTOMATION_INHIBIT
    for position in range(der.CURVE_FIELDS):
        locked = dut.set(der.AO_CURVE_SELECTOR + 1 + position, 1)
        assert locked is CommandStatus.AUTOMATION_INHIBIT, "its type, size and units are locked too"
    assert dut.curve_points(4) == before

    # Another curve is not locked by this one being in use.
    assert dut.select_curve(4) is CommandStatus.SUCCESS
    assert dut.set(first_x, 123) is CommandStatus.SUCCESS

    # Disabling the function releases the lock.
    assert dut.latch(enable.index, False) is CommandStatus.SUCCESS
    assert dut.select_curve(3) is CommandStatus.SUCCESS
    assert dut.set(first_x, before[0] + 10) is CommandStatus.SUCCESS
    assert dut.curve_points(1)[0] == before[0] + 10


def test_curve_002_an_enabled_function_can_be_moved_to_another_curve(dut: Dut) -> None:
    """The way to change a curve in use: prepare another and point the function at it."""
    index, kind = _curve_modes(dut)[0]
    enable = _enable_of(index)
    dut.release_curves()
    dut.define_curve(1, kind, 0)
    dut.define_curve(2, kind, 1)
    assert dut.set(index, 1) is CommandStatus.SUCCESS
    assert dut.latch(enable, True) is CommandStatus.SUCCESS
    assert dut.set(index, 2) is CommandStatus.SUCCESS
    first_x = der.AO_CURVE_SELECTOR + 1 + der.CURVE_FIELDS
    assert dut.select_curve(1) is CommandStatus.SUCCESS
    assert dut.set(first_x, 111) is CommandStatus.SUCCESS, "the curve it left is free again"
    assert dut.select_curve(2) is CommandStatus.SUCCESS
    assert dut.set(first_x, 111) is CommandStatus.AUTOMATION_INHIBIT


def test_curve_003_mode_type_mismatch(dut: Dut) -> None:
    """A function cannot be pointed at a curve of a type it does not follow."""
    (first, first_kind), (second, second_kind) = _curve_modes(dut)[:2]
    assert first_kind != second_kind
    dut.release_curves()
    dut.define_curve(5, first_kind)
    back = dut.readback(dut.map.point(Kind.AO, second))
    assert back is not None

    assert dut.set(second, 5) is CommandStatus.NOT_SUPPORTED
    assert dut.raw(back) == 0, "and the function still names no curve"
    assert dut.set(first, 5) is CommandStatus.SUCCESS, "the function it was made for accepts it"

    # Nor can a curve be turned into another type under a function that names it.
    assert dut.select_curve(5) is CommandStatus.SUCCESS
    kind_field = der.AO_CURVE_SELECTOR + 1
    assert dut.set(kind_field, second_kind) is CommandStatus.NOT_SUPPORTED
    assert dut.set(first, 0) is CommandStatus.SUCCESS
    assert dut.set(kind_field, second_kind) is CommandStatus.SUCCESS


def test_curve_003_a_curve_that_is_not_defined_or_does_not_exist(dut: Dut) -> None:
    index, _ = _curve_modes(dut)[0]
    dut.release_curves()
    assert dut.set(index, 9) is CommandStatus.NOT_SUPPORTED, "curve 9 was never given a type"
    assert dut.set(index, der.CURVE_COUNT + 1) is CommandStatus.OUT_OF_RANGE


# ---------------------------------------------------------------- mode tests


def _unsupported(dut: Dut, mode: Mode) -> None:
    """A function that is not supported says so, and cannot be enabled or set."""
    assert dut.latch(mode.enable.index, True) is CommandStatus.NOT_SUPPORTED
    served = [p for p in mode.points if dut.supported(p.kind, p.index)]
    assert not served, "a function reported as not supported serves " + ", ".join(
        f"{p.kind.value}{p.index}" for p in served
    )
    for point in mode.points[:8]:
        if point.kind.is_output:
            continue
        assert dut.obtain(point.kind, point.index) is None


def _supported(dut: Dut, mode: Mode) -> None:
    """Read the function's points, write its settings twice, and disable it.

    The procedure is written on the assumption that the function is running,
    and the standard has the inputs of a function that is not running
    reported without the ONLINE flag. So the function is enabled first, and
    the points are also read before that and after it is disabled, where
    they must still carry their values and must not be flagged ONLINE.
    """
    enabled = dut.readback(mode.enable)
    assert enabled is not None, "the enable output has a status input"
    assert mode.settings, "a supported function has settings to test"
    for output in (*mode.settings, *mode.switches):
        assert dut.readback(output) is not None, (
            f"{output.kind.value}{output.index} is served and nothing reads it back"
        )
    if mode.curves:
        dut.release_curves()

    assert not dut.state(enabled), "the status of the enable output is ONLINE while disabled"
    for point in mode.inputs:
        dut.offline(point)
    check_settings(dut, mode.settings, 1, enabled=False)

    assert dut.latch(mode.enable.index, True) is CommandStatus.SUCCESS
    assert dut.state(enabled)
    dut.advance(2)
    for point in mode.inputs:
        dut.online(point)

    def apply(which: int, first_curve: int) -> None:
        check_settings(dut, mode.settings, which)
        for switch in mode.switches:
            assert dut.latch(switch.index, which == 0) is CommandStatus.SUCCESS
            back = dut.readback(switch)
            assert back is not None and dut.state(back) is (which == 0)
        for offset, (index, types) in enumerate(sorted(mode.curves.items())):
            number = first_curve + offset
            dut.define_curve(number, types[0], which)
            assert dut.set(index, number) is CommandStatus.SUCCESS
            back = dut.readback(dut.map.point(Kind.AO, index))
            assert back is not None and dut.value(back) == number

    apply(0, 1)
    apply(1, 1 + len(mode.curves))

    assert dut.latch(mode.enable.index, False) is CommandStatus.SUCCESS
    assert not dut.state(enabled)
    for point in mode.inputs:
        dut.offline(point)
    for index in mode.curves:
        assert dut.set(index, 0) is CommandStatus.SUCCESS
        back = dut.readback(dut.map.point(Kind.AO, index))
        assert back is not None and dut.raw(back) == 0


@pytest.mark.parametrize(("procedure", "enable"), MODES.items(), ids=list(MODES))
def test_mode(dut: Dut, procedure: str, enable: int) -> None:
    """The mode procedure: supported or not, and if supported, settable and readable."""
    mode = dut.mode(enable)
    assert mode is not None, f"the tables have no function enabled by BO{enable}"
    supports = dut.online(mode.supports)
    assert mode.supports.event_class == 0, "a supports input is static data and never an event"
    assert supports.state is (procedure in IMPLEMENTED)
    if supports.state:
        _supported(dut, mode)
    else:
        _unsupported(dut, mode)


def test_the_mode_procedures_cover_every_function_the_tables_can_enable(dut: Dut) -> None:
    """So that a function added to the simulation, or to the tables, gets a procedure."""
    enables = {
        point.enabled_by[1]
        for point in dut.map.of(Kind.BI)
        if point.enabled_by is not None and point.section == dut.map.point(Kind.BO, 17).section
    }
    assert enables == set(MODES.values())
    implemented = {f.enable for f in der.FUNCTIONS}
    assert implemented == {MODES[name] for name in IMPLEMENTED}
    assert implemented.isdisjoint(UNSUPPORTED)
