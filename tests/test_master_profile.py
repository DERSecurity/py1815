"""The DER profile from the master's side: names, scaling, functions, curves, comparison.

Run against the simulated DER through a Loopback, with the requests the
profile's operations make pinned to octets written out by hand. The tables are
the synthetic ones that pair the simulated DER's points, so the tests run
where the IEEE tables are not available.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from profile_fixtures import MIRROR, SUPPORTS, UNSUPPORTED, paired_reference_der

from py1815.control import CommandStatus
from py1815.decode import PointType
from py1815.master import Loopback, controls
from py1815.master.controls import PointStatus
from py1815.master.profile import (
    CurveWritten,
    DerProfile,
    LoopbackDer,
    Reading,
    Setpoint,
    quality,
    read_device_profile,
    run,
    write_plan,
)
from py1815.profile import curves, der, device_profile, load
from py1815.profile.model import Composition, Kind, PointMap


def _changed(point_map: PointMap, kind: Kind, index: int, **changes: Any) -> PointMap:
    point = point_map.point(kind, index)
    return dataclasses.replace(
        point_map,
        points={**point_map.points, point.address: dataclasses.replace(point, **changes)},
    )


@pytest.fixture
def point_map() -> PointMap:
    """The paired tables, with the power limit's settings scaled as the profile scales them.

    AO87 and AO88 travel in tenths of a percent, 0 to 1000, as IEEE 1815.2
    gives them; their readbacks are scaled alike.
    """
    tables = load.resolve(paired_reference_der(), Composition())
    for index in (der.AO_POWER_LIMIT_CHARGING, der.AO_POWER_LIMIT_GENERATION):
        tables = _changed(tables, Kind.AO, index, multiplier=0.1, minimum=0, maximum=1000)
        tables = _changed(tables, Kind.AI, MIRROR + index, multiplier=0.1, units="Percent")
    return tables


@pytest.fixture
def simulation(point_map) -> der.Simulation:
    return der.build(point_map)


@pytest.fixture
def master(simulation, point_map) -> LoopbackDer:
    return LoopbackDer(Loopback(simulation.outstation.session()), point_map)


def _requests(exchanges) -> list[str]:
    return [exchange.request.hex(" ") for exchange in exchanges]


class Untouchable:
    """A master that fails the test if anything is asked of it."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"{name} was asked for, and nothing was to be sent")


class TestNames:
    def test_a_point_is_found_by_its_address_in_either_case(self, point_map):
        profile = DerProfile(point_map)
        assert profile.point("AO87") is point_map.point(Kind.AO, 87)
        assert profile.point(" ao87 ") is point_map.point(Kind.AO, 87)

    def test_a_point_is_found_by_its_name_ignoring_case_and_spacing(self, point_map):
        profile = DerProfile(point_map)
        assert profile.point("synthetic  ao213") is point_map.point(Kind.AO, 213)

    def test_a_point_is_found_by_the_first_sentence_of_its_name(self, point_map):
        named = _changed(point_map, Kind.AI, 147, name="Power Reference. Read from the meter.")
        assert DerProfile(named).point("power reference") is named.point(Kind.AI, 147)

    def test_a_name_shared_by_an_output_and_its_readback_finds_the_input_for_a_read(
        self, point_map
    ):
        shared = _changed(point_map, Kind.AO, 87, name="Power Limit")
        shared = _changed(shared, Kind.AI, MIRROR + 87, name="Power Limit")
        profile = DerProfile(shared)
        assert profile.point("Power Limit").address == (Kind.AI, MIRROR + 87)
        assert profile.point("Power Limit", outputs=True).address == (Kind.AO, 87)

    def test_a_name_two_points_of_one_kind_share_is_refused_with_both_addresses(self, point_map):
        shared = _changed(point_map, Kind.AO, 87, name="Limit")
        shared = _changed(shared, Kind.AO, 88, name="Limit")
        with pytest.raises(ValueError, match="AO87, AO88"):
            DerProfile(shared).point("limit", outputs=True)

    @pytest.mark.parametrize(
        ("name", "outputs", "says"),
        [
            ("AO9999", False, "has no AO9999"),
            ("Nothing at all", False, "no point named"),
            ("AI147", True, "is an input"),
            ("   ", False, "named by its address"),
        ],
    )
    def test_a_point_that_cannot_be_found_is_refused(self, point_map, name, outputs, says):
        with pytest.raises(ValueError, match=says):
            DerProfile(point_map).point(name, outputs=outputs)


class TestFunctions:
    def test_each_supports_input_and_its_enable_output_make_a_function(self, point_map):
        profile = DerProfile(point_map)
        keys = {function.key for function in profile.functions}
        assert {_key(function.name) for function in der.FUNCTIONS} <= keys
        assert len(profile.functions) == len(der.FUNCTIONS) + len(UNSUPPORTED)

    def test_a_function_holds_its_enable_status_supports_settings_and_inputs(self, point_map):
        volt_var = DerProfile(point_map).function("volt-var")
        assert volt_var.name == "volt-var"
        assert volt_var.enable.address == (Kind.BO, der.BO_ENABLE_VOLT_VAR)
        assert volt_var.status.address == (Kind.BI, MIRROR + der.BO_ENABLE_VOLT_VAR)
        assert volt_var.supports.address == (Kind.BI, SUPPORTS + der.BO_ENABLE_VOLT_VAR)
        first, last = der.AO_VOLT_VAR_FIRST, der.AO_VOLT_VAR_LAST
        assert [p.index for p in volt_var.settings] == list(range(first, last + 1))
        assert all(p.kind is Kind.AO for p in volt_var.settings)
        inputs = {p.index for p in volt_var.inputs}
        assert set(der.FUNCTIONS[-1].inputs) <= inputs
        assert {MIRROR + index for index in range(first, last + 1)} - {
            MIRROR + der.AO_VOLT_VAR_CURVE
        } <= inputs

    def test_a_point_of_the_same_purpose_under_another_heading_is_not_the_functions(
        self, point_map
    ):
        elsewhere = _changed(
            point_map, Kind.AI, der.AI_METER_FIRST, purpose="volt-var", section="Meter"
        )
        volt_var = DerProfile(elsewhere).function("volt-var")
        assert der.AI_METER_FIRST not in {point.index for point in volt_var.inputs}

    @pytest.mark.parametrize("name", ["volt-var", "VOLT-VAR", "BO29", "bo29"])
    def test_a_function_is_found_by_key_name_purpose_or_enable_address(self, point_map, name):
        assert DerProfile(point_map).function(name).enable.index == der.BO_ENABLE_VOLT_VAR

    def test_a_function_name_is_the_enable_outputs_name_without_enable_and_mode(self, point_map):
        named = _changed(point_map, Kind.BO, 29, name="Enable Volt-Var Control Mode. Some text.")
        function = DerProfile(named).function("BO29")
        assert (function.name, function.key) == ("Volt-Var Control", "volt-var-control")

    def test_a_function_that_does_not_exist_is_refused_with_those_that_do(self, point_map):
        with pytest.raises(ValueError, match="volt-watt"):
            DerProfile(point_map).function("frequency droop")

    def test_a_setting_named_as_a_curve_index_is_a_curve_setting(self, point_map):
        named = _changed(point_map, Kind.AO, der.AO_VOLT_VAR_CURVE, name="Volt-Var Curve Index")
        (setting,) = DerProfile(named).function("volt-var").curve_settings
        assert setting.index == der.AO_VOLT_VAR_CURVE

    def test_a_group_is_a_function_or_everything_of_one_purpose(self, point_map):
        profile = DerProfile(point_map)
        assert profile.group("volt-var") == profile.function("volt-var").points
        nameplate = _changed(point_map, Kind.AI, 4, purpose="Nameplate")
        nameplate = _changed(nameplate, Kind.AI, 14, purpose="Nameplate")
        assert [p.index for p in DerProfile(nameplate).group("nameplate")] == [4, 14]
        with pytest.raises(ValueError, match="no function or group"):
            profile.group("weather")


class TestScaling:
    def test_an_analog_value_is_divided_by_its_multiplier_and_rounded(self, point_map):
        profile = DerProfile(point_map)
        limit = point_map.point(Kind.AO, 87)
        assert profile.transmitted(limit, 50) == 500
        assert profile.transmitted(limit, 50.04) == 500
        assert profile.transmitted(limit, "12.5") == 125

    @pytest.mark.parametrize("value", [100.1, -0.1, 1e12])
    def test_an_analog_value_outside_the_range_is_refused_in_engineering_units(
        self, point_map, value
    ):
        limit = point_map.point(Kind.AO, 87)
        with pytest.raises(ValueError, match="outside 0 to 100"):
            DerProfile(point_map).transmitted(limit, value)

    @pytest.mark.parametrize("value", [True, "fast", None, float("nan")])
    def test_an_analog_output_takes_a_finite_number_only(self, point_map, value):
        with pytest.raises(ValueError, match="takes a"):
            DerProfile(point_map).transmitted(point_map.point(Kind.AO, 87), value)

    def test_a_binary_output_takes_a_state_by_truth_by_number_or_by_name(self, point_map):
        switch = dataclasses.replace(point_map.point(Kind.BO, 29), states=("Disable", "Enable"))
        profile = DerProfile(point_map)
        assert profile.transmitted(switch, True) is True
        assert profile.transmitted(switch, 0) is False
        assert profile.transmitted(switch, "enable") is True
        assert profile.transmitted(switch, "Disable") is False
        with pytest.raises(ValueError, match="'Disable' or 'Enable'"):
            profile.transmitted(switch, "maybe")

    @pytest.mark.parametrize(
        ("multiplier", "offset", "raw", "value"),
        [
            (0.1, 0.0, 4224, 422.4),
            (0.001, 0.0, 60012, 60.012),
            (0.25, 0.5, 3, 1.25),
            (None, 0.0, 7, 7),
        ],
    )
    def test_a_value_read_has_the_decimal_places_of_its_multiplier(
        self, point_map, multiplier, offset, raw, value
    ):
        point = dataclasses.replace(
            point_map.point(Kind.AI, 147), multiplier=multiplier, offset=offset
        )
        read = Reading(point, raw, 0x01, None, reported=True).value
        assert read == value and repr(read) == repr(value)

    @pytest.mark.parametrize(
        ("flags", "reported", "says"),
        [
            (0x01, True, "good"),
            (0x81, True, "good"),
            (0x00, True, "offline"),
            (0x04, True, "comm_lost"),
            (0x02, True, "restart"),
            (None, True, "no_flags"),
            (None, False, "not_reported"),
        ],
    )
    def test_the_flag_octet_says_the_quality(self, flags, reported, says):
        assert quality(flags, reported) == says


class TestReading:
    def test_points_are_read_by_name_in_one_request_of_ranges(self, master, point_map):
        read = master.read("BO17", "AI147", f"AI{MIRROR + 87}")
        # g10v0 17..17, then g30v0 147..147 and 10087..10087, as ranges (D82).
        assert _requests(read.exchanges) == [
            "c0 01 0a 00 00 11 11 1e 00 00 93 93 1e 00 01 67 27 67 27"
        ]
        limit = read[f"AI{MIRROR + 87}"]
        assert limit.raw == 1000 and limit.value == 100.0
        assert read["BO17"].value is False and read["BO17"].quality == "good"

    def test_a_disabled_functions_input_is_read_as_offline(self, master):
        read = master.read(group="volt-var")
        voltage = read[f"AI{der.AI_VOLT_VAR_VOLTAGE}"]
        assert voltage.reported and voltage.quality == "offline"
        assert read[f"BI{SUPPORTS + der.BO_ENABLE_VOLT_VAR}"].quality == "good"

    def test_a_read_refused_whole_is_read_again_one_range_at_a_time(self, master):
        unserved = UNSUPPORTED[0]
        read = master.read(f"BO{unserved}", "BO17")
        assert _requests(read.exchanges) == [
            f"c0 01 0a 00 00 {unserved:02x} {unserved:02x} 0a 00 00 11 11",
            f"c1 01 0a 00 00 {unserved:02x} {unserved:02x}",
            "c2 01 0a 00 00 11 11",
        ]
        assert [reading.quality for reading in read.readings] == ["not_reported", "good"]

    def test_a_read_of_one_range_is_not_made_again(self, master):
        read = master.read(f"BO{UNSUPPORTED[0]}")
        assert len(read.exchanges) == 1 and not read.readings[0].reported

    def test_a_point_not_in_the_profile_is_refused_before_anything_is_sent(self, point_map):
        with pytest.raises(ValueError, match="no AI60000"):
            LoopbackDer(Untouchable(), point_map).read("AI60000")


class TestWriting:
    def test_a_setpoint_travels_as_the_whole_transmitted_number(self, master, simulation):
        written = master.write({"AO87": 50})
        # Direct operate, g41v2 at index 87: 500, status 0.
        assert _requests(written.operated.exchanges) == ["c0 05 29 02 17 01 57 f4 01 00"]
        (setpoint,) = written.setpoints
        assert (setpoint.requested, setpoint.sent, setpoint.sent_value) == (50.0, 500, 50.0)
        assert written.accepted is True
        assert simulation.outstation.value(Kind.AO, 87) == 50.0

    def test_a_float_variation_carries_the_engineering_value(self, master, simulation):
        written = master.write({"AO87": 37.5}, variation=3)
        # g41v3: 37.5 as a single float, 0x42160000.
        assert _requests(written.operated.exchanges) == ["c0 05 29 03 17 01 57 00 00 16 42 00"]
        assert simulation.outstation.value(Kind.AO, 87) == 37.5

    def test_outputs_are_written_in_one_request_in_the_order_given(self, master):
        written = master.write({"AO88": 20, "BO17": True, "AO87": 30})
        (request,) = _requests(written.operated.exchanges)
        assert request == (
            "c0 05 29 02 17 01 58 c8 00 00 0c 01 17 01 11 03 01 00 00 00 00 00 00 00 00 00"
            " 29 02 17 01 57 2c 01 00"
        )
        assert [s.status.status for s in written.setpoints] == [CommandStatus.SUCCESS] * 3

    def test_with_verify_the_mirroring_inputs_are_read_and_compared(self, master):
        written = master.write({"AO87": 42, "BO17": True}, verify=True)
        assert _requests(written.verification.exchanges) == [
            "c1 01 01 00 01 21 27 21 27 1e 00 01 67 27 67 27"
        ]
        assert [s.readback.value for s in written.setpoints] == [42.0, True]
        assert [s.matches for s in written.setpoints] == [True, True]
        assert written.verified is True

    def test_without_verify_nothing_is_read(self, master):
        written = master.write({"AO87": 42})
        assert written.verification is None and written.verified is None
        assert len(written.operated.exchanges) == 1

    def test_a_refused_write_is_verified_as_not_matching(self, master, simulation):
        master.write({"BO0": True})  # the lockout, which refuses every other control
        written = master.write({"AO87": 42}, verify=True)
        assert written.accepted is False
        assert written.setpoints[0].status.status is CommandStatus.BLOCKED
        assert written.setpoints[0].matches is False and written.verified is False

    @pytest.mark.parametrize(
        ("values", "says"),
        [
            ({}, "at least one output"),
            ({"AO87": 101}, "outside 0 to 100"),
            ({"AI147": 1}, "is an input"),
            ({"nobody": 1}, "no point named"),
            ({"BO17": "sideways"}, "true or false"),
        ],
    )
    def test_a_write_that_cannot_be_made_is_refused_before_anything_is_sent(
        self, point_map, values, says
    ):
        with pytest.raises(ValueError, match=says):
            LoopbackDer(Untouchable(), point_map).write(values)

    def test_a_write_is_sent_once_when_its_answer_does_not_arrive(self, point_map):
        """A carrier that never hears back: the write is not made again, and the
        outcome is not known (D80)."""
        carried: list[Any] = []

        class Silent:
            def _carry_out(self, plan):
                carried.append(plan)
                return plan.result([])

            def read(self, **_wanted):
                raise AssertionError("verify was not asked for")

        written = run(Silent(), write_plan(DerProfile(point_map), {"AO87": 1}))
        assert len(carried) == 1
        assert written.accepted is False and written.operated.operated is False

    @pytest.mark.parametrize(
        ("read", "matches"),
        [(50.0, True), (50.1, True), (49.9, True), (50.2, False), (None, None)],
    )
    def test_a_readback_matches_within_one_step_of_the_multiplier(self, point_map, read, matches):
        limit = point_map.point(Kind.AO, 87)
        back = point_map.point(Kind.AI, MIRROR + 87)
        raw = None if read is None else round(read * 10)
        readback = Reading(back, raw, 0x01, None, reported=read is not None)
        status = PointStatus(controls.analog(87, 500), CommandStatus.SUCCESS, True)
        setpoint = Setpoint(limit, 50.0, 500, status, readback)
        assert setpoint.matches is matches


class TestSwitching:
    def test_enabling_latches_the_enable_output_and_reads_the_status_input(self, master):
        switched = master.enable("volt-var")
        # g12v1 at index 29: latch on, count 1. Then g1v0 at 10029.
        assert _requests(switched.operated.exchanges) == [
            "c0 05 0c 01 17 01 1d 03 01 00 00 00 00 00 00 00 00 00"
        ]
        assert _requests(switched.readback.exchanges) == ["c1 01 01 00 01 2d 27 2d 27"]
        assert switched.accepted is True and switched.enabled is True

    def test_disabling_latches_it_off_and_reads_it_back_off(self, master):
        master.enable("volt-var")
        switched = master.disable("volt-var")
        assert _requests(switched.operated.exchanges)[0].startswith("c2 05 0c 01 17 01 1d 04")
        assert switched.enabled is False

    def test_a_function_with_no_status_input_reports_enabled_as_not_known(self, point_map):
        unpaired = _changed(point_map, Kind.BO, der.BO_ENABLE_VOLT_VAR, associated=None)
        master = LoopbackDer(Loopback(der.build(unpaired).outstation.session()), unpaired)
        switched = master.enable("volt-var")
        assert switched.accepted is True and switched.enabled is None
        assert switched.readback is None

    def test_the_functions_the_simulated_der_implements_are_the_ones_supported(self, master):
        found = master.functions()
        supported = {state.function.key for state in found.states if state.supported}
        assert supported == {_key(function.name) for function in der.FUNCTIONS}
        assert not any(state.enabled for state in found.states if state.supported)
        assert len(found.readings.exchanges) == 1

    def test_an_enabled_function_is_listed_as_enabled(self, master):
        master.enable("constant-vars")
        found = {state.function.key: state for state in master.functions().states}
        assert found["constant-vars"].enabled is True
        assert found["volt-var"].enabled is False


VOLT_VAR_POINTS = [(920, 300), (980, 0), (1020, 0), (1080, -300)]


def _write_volt_var(master: LoopbackDer, number: int = 2) -> CurveWritten:
    written: CurveWritten = master.write_curve(
        number,
        type=der.CURVE_VOLT_VAR,
        x_units=der.X_PERCENT_VOLTAGE,
        y_units=der.Y_PERCENT_MAX_VARS,
        points=VOLT_VAR_POINTS[:2],
    )
    return written


class TestCurves:
    def test_a_curve_is_written_selector_then_fields_then_points(self, master, simulation):
        written = _write_volt_var(master)
        requests = [request for step in written.steps for request in _requests(step.exchanges)]
        assert requests == [
            # The selector, AO244: curve 2.
            "c0 05 29 02 17 01 f4 02 00 00",
            # AO245 to AO248: type 2, two points, X in units 129, Y in units 2.
            "c1 05 29 02 17 04 f5 02 00 00 f6 02 00 00 f7 81 00 00 f8 02 00 00",
            # AO249 to AO252: (920, 300) and (980, 0).
            "c2 05 29 02 17 04 f9 98 03 00 fa 2c 01 00 fb d4 03 00 fc 00 00 00",
        ]
        assert written.accepted is True and written.stopped_at is None
        assert simulation.der.curves.curves[2].points == [(920.0, 300.0), (980.0, 0.0)]

    def test_a_curve_is_read_back_after_it_is_written(self, master):
        written = _write_volt_var(master)
        back = written.readback
        assert [_requests(read.exchanges) for read in back.reads] == [
            # BI107, then AI328 to AI332: the selector and the fields.
            ["c3 01 01 00 00 6b 6b 1e 00 01 48 01 4c 01"],
            # AI333 to AI336: the points in use.
            ["c4 01 1e 00 01 4d 01 50 01"],
        ]
        assert (back.number, back.type, back.count) == (2, der.CURVE_VOLT_VAR, 2)
        assert (back.x_units, back.y_units) == (der.X_PERCENT_VOLTAGE, der.Y_PERCENT_MAX_VARS)
        assert back.points == ((920.0, 300.0), (980.0, 0.0))
        assert back.referenced is False and written.matches is True

    def test_nothing_follows_a_selector_the_outstation_refused(self, master, simulation):
        written = _write_volt_var(master, number=der.CURVE_COUNT + 1)
        assert len(written.steps) == 1 and written.stopped_at == "selector"
        assert written.steps[0].statuses[0].status is CommandStatus.OUT_OF_RANGE
        assert written.accepted is False and written.matches is False
        assert simulation.der.curves.curves[1].type == curves.UNDEFINED

    def test_no_point_is_written_to_a_curve_an_enabled_function_follows(self, master, simulation):
        _write_volt_var(master)
        master.write({f"AO{der.AO_VOLT_VAR_CURVE}": 2})
        master.enable("volt-var")
        changed = master.write_curve(
            2, type=der.CURVE_VOLT_VAR, x_units=129, y_units=2, points=[(900, 100)]
        )
        assert changed.stopped_at == "fields"
        assert changed.steps[1].statuses[0].status is CommandStatus.AUTOMATION_INHIBIT
        assert simulation.der.curves.curves[2].points == [(920.0, 300.0), (980.0, 0.0)]
        assert changed.readback.referenced is True and changed.matches is False

    def test_reading_a_curve_selects_it_first_only_when_a_number_is_given(self, master):
        _write_volt_var(master, number=3)
        selected, shown = master.curve()
        assert selected is None and shown.number == 3
        selected, shown = master.curve(1)
        assert _requests(selected.exchanges)[0].endswith("29 02 17 01 f4 01 00 00")
        assert (shown.number, shown.type, shown.points) == (1, curves.UNDEFINED, ())

    @pytest.mark.parametrize(
        ("changes", "says"),
        [
            ({"points": [(1, 2)] * 101}, "at most 100 points"),
            ({"points": [(1.5, 2)]}, "whole number"),
            ({"points": [(1, 2, 3)]}, "an X and a Y"),
            ({"type": "volt-var"}, "the curve type is a number"),
            ({"number": 0}, "outside 1 to"),
            ({"x_units": 999}, "outside 0 to 255"),
        ],
    )
    def test_a_curve_that_cannot_be_written_is_refused_before_anything_is_sent(
        self, point_map, changes, says
    ):
        ranged = _changed(point_map, Kind.AO, 244, minimum=1, maximum=2147483647)
        ranged = _changed(ranged, Kind.AO, 247, minimum=0, maximum=255)
        asked = {"number": 1, "type": 2, "x_units": 129, "y_units": 2, "points": [(1, 2)]}
        asked.update(changes)
        number = asked.pop("number")
        with pytest.raises(ValueError, match=says):
            LoopbackDer(Untouchable(), ranged).write_curve(number, **asked)


def _document(simulation: der.Simulation) -> str:
    outstation = simulation.outstation
    return device_profile.render(device_profile.build(outstation, outstation.session()))


class TestTheDeviceProfile:
    def test_its_points_are_read_with_class_class_0_and_deadband(self):
        text = """<?xml version="1.0"?>
<DNP3DeviceProfileDocument xmlns="http://www.dnp.org/DNP3/DeviceProfile">
 <referenceDevice><dataPointsList>
  <binaryInputPoints><dataPoints>
   <binaryInput><index>3</index><name>Alarm</name><changeEventClass>one</changeEventClass>
    <includedInClass0Response>always</includedInClass0Response></binaryInput>
  </dataPoints></binaryInputPoints>
  <counterPoints><dataPoints>
   <counter><index>0</index><name>Energy</name><countersIncludedInClass0>always</countersIncludedInClass0>
    <counterEventClass>none</counterEventClass><frozenCounterExists>true</frozenCounterExists>
    <frozenCountersIncludedInClass0>always</frozenCountersIncludedInClass0>
    <frozenCounterEventClass>three</frozenCounterEventClass></counter>
  </dataPoints></counterPoints>
  <analogInputPoints><dataPoints>
   <analogInput><index>7</index><name>Power</name><changeEventClass>two</changeEventClass>
    <includedInClass0Response>never</includedInClass0Response>
    <dnpData><deadband>50</deadband></dnpData></analogInput>
  </dataPoints></analogInputPoints>
 </dataPointsList></referenceDevice>
</DNP3DeviceProfileDocument>"""
        declared = {(entry.type, entry.index): entry for entry in read_device_profile(text)}
        assert set(declared) == {
            (PointType.BINARY_INPUT, 3),
            (PointType.COUNTER, 0),
            (PointType.FROZEN_COUNTER, 0),
            (PointType.ANALOG_INPUT, 7),
        }
        alarm = declared[(PointType.BINARY_INPUT, 3)]
        assert (alarm.name, alarm.event_class, alarm.class_0, alarm.deadband) == (
            "Alarm",
            1,
            True,
            None,
        )
        assert declared[(PointType.FROZEN_COUNTER, 0)].event_class == 3
        assert declared[(PointType.COUNTER, 0)].event_class == 0
        power = declared[(PointType.ANALOG_INPUT, 7)]
        assert (power.event_class, power.class_0, power.deadband) == (2, False, 50.0)

    @pytest.mark.parametrize(
        ("text", "says"),
        [
            ('<!DOCTYPE x [<!ENTITY a "b">]><x/>', "document type"),
            ("<unclosed>", "not XML"),
            ("<root/>", "no dataPointsList"),
            (
                "<r><dataPointsList><binaryInputPoints><dataPoints><binaryInput>"
                "<name>x</name></binaryInput></dataPoints></binaryInputPoints>"
                "</dataPointsList></r>",
                "has no index",
            ),
        ],
    )
    def test_a_document_that_cannot_be_read_is_refused(self, text, says):
        with pytest.raises(ValueError, match=says):
            read_device_profile(text)

    def test_the_document_an_outstation_writes_is_read_back_point_for_point(self, simulation):
        declared = read_device_profile(_document(simulation))
        served = sum(len(simulation.outstation.served(kind)) for kind in Kind)
        frozen = sum(1 for point in simulation.outstation.served(Kind.CTR) if point.frozen)
        assert len(declared) == served + frozen

    def test_an_outstation_matches_the_document_it_wrote(self, master, simulation):
        compared = master.compare(_document(simulation))
        assert compared.absent == () and compared.undeclared == () and compared.class_0 == ()
        assert len(compared.served) == len(compared.declared)
        assert [exchange.request.hex(" ")[3:] for exchange in compared.exchanges[:2]] == [
            "01 3c 01 06",
            "01 0a 00 06 28 00 06",
        ]

    def test_declared_and_absent_served_and_undeclared_and_class_0_are_reported(
        self, master, simulation
    ):
        text = _document(simulation)
        # One point declared that is not served, one served that is not declared,
        # and one served point declared out of class 0.
        absent = "<index>55555</index>"
        text = text.replace("<index>0</index>", absent, 1)
        moved = "<index>2</index>\n            <name>Synthetic BI2</name>"
        assert moved in text
        start = text.index(moved)
        end = text.index("</binaryInput>", start)
        text = (
            text[:start]
            + text[start:end].replace(
                "<includedInClass0Response>always", "<includedInClass0Response>never"
            )
            + text[end:]
        )

        compared = master.compare(text)

        assert [(entry.type, entry.index) for entry in compared.absent] == [
            (PointType.BINARY_INPUT, 55555)
        ]
        assert compared.undeclared == ((PointType.BINARY_INPUT, 0),)
        ((entry, carried),) = compared.class_0
        assert (entry.index, entry.class_0, carried) == (2, False, True)
        # The absent point was looked for by range, and the outstation refused it.
        assert compared.exchanges[2].request.hex(" ")[3:] == "01 01 00 01 03 d9 03 d9"


def _key(name: str) -> str:
    return name.replace("/", "-").replace(" ", "-")
