"""The builder: a map and a binding in, an outstation's answers out.

Driven through a real session wherever the behavior is one a master would see,
so the assertions are about what reaches the wire and not about the builder's
internals. The probe's parser reads the responses, which keeps the object
layouts out of the tests.
"""

from __future__ import annotations

import struct

import pytest
from profile_fixtures import analog, document, small, units

from py1815.application import FunctionCode, IIN2Bit, IINBit, QualifierCode
from py1815.control import (
    CommandStatus,
    ControlRelayOutputBlock,
    OperationType,
    TripCloseCode,
    encode_crob,
)
from py1815.events import EventClass
from py1815.profile import load
from py1815.profile.binding import Binding, Quality, Reading
from py1815.profile.model import Kind, MapError
from py1815.profile.outstation import DerOutstation
from py1815.profile.probe import parse_objects

AI, AO, BI, BO, CTR = Kind.AI, Kind.AO, Kind.BI, Kind.BO, Kind.CTR
ALL = QualifierCode.ALL_OBJECTS


class Device:
    """Something to bind to: a few values a test can move."""

    def __init__(self) -> None:
        self.alarm = False
        self.power = 1500.0
        self.voltage = 240.0
        self.energy = [10.0, 20.0, 30.0]
        self.applied: list[tuple[str, float]] = []
        self.verdict: CommandStatus | None = None

    def binding(self) -> Binding:
        binding = Binding()
        binding.read(BI, 0, lambda: self.alarm)
        binding.read(AI, 1, lambda: self.power)
        binding.read(AI, 2, lambda: self.voltage)
        binding.read(AI, 4, lambda: 7.0)
        binding.read(CTR, 0, lambda: self.energy[0])
        binding.read(CTR, 1, lambda: self.energy[1])
        binding.read(CTR, 5, lambda: self.energy[2])
        binding.output(BO, 0, lambda value: self._apply("widget", value))
        binding.output(AO, 0, lambda value: self._apply("setpoint", value))
        return binding

    def _apply(self, name: str, value: float) -> CommandStatus | None:
        if self.verdict is None:
            self.applied.append((name, value))
        return self.verdict


def _built(device: Device | None = None, **kwargs) -> tuple[DerOutstation, Device]:
    device = device or Device()
    point_map = load.resolve(small(), units(0))
    return DerOutstation(point_map, device.binding(), clock_ms=lambda: 5000, **kwargs), device


def _read(session, *headers: bytes, sequence: int = 0) -> bytes:
    return session._handle_fragment(bytes([0xC0 | sequence, FunctionCode.READ]) + b"".join(headers))


def _values(response: bytes) -> dict[tuple[int, int], float]:
    static, _ = parse_objects(response[4:])
    return {(value.group, value.index): value.value for value in static}


def _flags(response: bytes) -> dict[tuple[int, int], int | None]:
    static, _ = parse_objects(response[4:])
    return {(value.group, value.index): value.flags for value in static}


CLASS_0 = bytes([60, 1, ALL])


class TestAnIntegrityPoll:
    def test_class_0_carries_inputs_and_counters_and_no_output_status(self):
        outstation, _ = _built()
        outstation.freeze_all()
        groups = {group for group, _ in _values(_read(outstation.session(), CLASS_0))}
        assert groups == {1, 20, 21, 30}

    def test_values_travel_scaled_by_the_tables(self):
        outstation, _ = _built()
        values = _values(_read(outstation.session(), CLASS_0))
        assert values[(30, 1)] == 1500
        assert values[(30, 2)] == 2400, "240.0 volts at a multiplier of 0.1"

    def test_a_value_the_tables_fix_is_served_without_a_binding(self):
        outstation, _ = _built()
        assert _values(_read(outstation.session(), CLASS_0))[(30, 0)] == 25

    def test_the_advertisement_block_is_left_out_of_class_0(self):
        outstation, _ = _built()
        assert (30, 65000) not in _values(_read(outstation.session(), CLASS_0))

    def test_and_is_served_when_asked_for_by_group(self):
        outstation, _ = _built()
        values = _values(_read(outstation.session(), bytes([30, 0, ALL])))
        assert values[(30, 65000)] == 1000

    def test_an_unbound_optional_point_is_absent_not_zero(self):
        """A fabricated value is indistinguishable from a real one on the wire."""
        outstation, _ = _built()
        assert (1, 9) not in _values(_read(outstation.session(), CLASS_0))

    def test_a_frozen_counter_is_absent_until_its_first_freeze(self):
        outstation, _ = _built()
        session = outstation.session()
        assert not any(group == 21 for group, _ in _values(_read(session, CLASS_0)))
        outstation.freeze_all()
        values = _values(_read(session, CLASS_0, sequence=1))
        assert values[(21, 0)] == 10 and values[(21, 1)] == 20

    def test_a_long_map_is_split_into_blocks_that_fit(self):
        rows = [analog(f"Point {index}", index, event_class=3) for index in range(400)]
        point_map = load.resolve(document({"AI": rows}), units(0))
        binding = Binding()
        for index in range(400):
            binding.read(AI, index, lambda index=index: float(index))
        outstation = DerOutstation(point_map, binding, block_octets=256)
        blocks = outstation.read_blocks([header for header in _class_0_headers()])
        assert len(blocks) > 1
        assert all(len(block) <= 256 for block in blocks)
        static, _ = parse_objects(b"".join(blocks))
        assert [value.value for value in static] == list(range(400)), "nothing lost at the seams"

    def test_a_block_too_large_for_the_response_is_refused_at_wiring(self):
        outstation, _ = _built(block_octets=4096)
        with pytest.raises(ValueError):
            outstation.session(max_response=2048)


def _class_0_headers():
    from py1815.application import parse_request

    return parse_request(bytes([0xC0, FunctionCode.READ]) + CLASS_0).headers


class TestReadingByGroup:
    def test_a_range_returns_the_points_inside_it(self):
        outstation, _ = _built()
        response = _read(outstation.session(), bytes([30, 1, 0x00, 1, 2]))
        assert set(_values(response)) == {(30, 1), (30, 2)}

    def test_a_range_holding_nothing_is_a_parameter_error(self):
        """The object is known; it is the range that names nothing."""
        outstation, _ = _built()
        response = _read(outstation.session(), bytes([30, 1, 0x00, 200, 210]))
        assert response[3] & IIN2Bit.PARAM_ERROR
        assert not response[3] & IIN2Bit.OBJECT_UNKNOWN

    def test_a_range_running_past_the_last_point_is_a_parameter_error(self):
        outstation, _ = _built()
        response = _read(outstation.session(), bytes([20, 0, 0x00, 5, 6]))
        assert response[3] & IIN2Bit.PARAM_ERROR

    def test_a_range_over_a_kind_with_no_points_is_an_unknown_object(self):
        point_map = load.resolve(small(), units(0))
        session = DerOutstation(point_map, Binding(), strict=False).session()
        response = _read(session, bytes([20, 0, 0x00, 0, 0]))
        assert response[3] & IIN2Bit.OBJECT_UNKNOWN

    def test_a_range_across_a_gap_returns_what_exists(self):
        outstation, _ = _built()
        response = _read(outstation.session(), bytes([20, 0, 0x00, 0, 5]))
        assert set(_values(response)) == {(20, 0), (20, 1), (20, 5)}

    def test_output_status_is_read_by_naming_it(self):
        outstation, _ = _built()
        binary = _flags(_read(outstation.session(), bytes([10, 0, ALL])))
        assert set(binary) == {(10, 0)}

    def test_a_variation_not_offered_is_an_unknown_object(self):
        outstation, _ = _built()
        response = _read(outstation.session(), bytes([30, 5, ALL]))
        assert response[3] & IIN2Bit.OBJECT_UNKNOWN

    def test_a_group_not_served_is_an_unknown_object(self):
        outstation, _ = _built()
        assert _read(outstation.session(), bytes([110, 0, ALL]))[3] & IIN2Bit.OBJECT_UNKNOWN

    def test_the_sixteen_bit_variation_is_served_when_named(self):
        outstation, _ = _built()
        response = _read(outstation.session(), bytes([30, 2, 0x00, 1, 1]))
        assert response[4:6] == bytes([30, 2])
        assert _values(response)[(30, 1)] == 1500


def _named(response: bytes) -> list[tuple[int, int, float]]:
    """The index-prefixed objects of a response, in the order sent."""
    _, indexed = parse_objects(response[4:])
    return [(value.group, value.index, value.value) for value in indexed]


INDEX_8 = QualifierCode.UINT8_COUNT_UINT8_INDEX
INDEX_16 = QualifierCode.UINT16_COUNT_UINT16_INDEX


class TestReadingByIndex:
    """Points named one at a time. No subset level requires it; a master may still ask."""

    def test_the_points_named_come_back_in_the_order_asked(self):
        outstation, _ = _built()
        response = _read(outstation.session(), bytes([30, 1, INDEX_8, 2, 2, 1]))
        assert not response[3], "nothing is refused"
        assert _named(response) == [(30, 2, 2400), (30, 1, 1500)]
        static, _ = parse_objects(response[4:])
        assert not static, "an indexed read is not answered with a range"

    def test_the_answer_uses_the_qualifier_that_asked(self):
        outstation, _ = _built()
        narrow = _read(outstation.session(), bytes([30, 1, INDEX_8, 1, 1]))
        assert narrow[4:8] == bytes([30, 1, INDEX_8, 1])
        wide = _read(outstation.session(), bytes([30, 1, INDEX_16]) + struct.pack("<HH", 1, 1))
        assert wide[4:9] == bytes([30, 1, INDEX_16]) + struct.pack("<H", 1), "not narrowed"
        assert _named(wide) == [(30, 1, 1500)]

    def test_points_either_side_of_a_gap_are_one_request(self):
        """What a range cannot do without sending everything between."""
        outstation, _ = _built()
        response = _read(outstation.session(), bytes([20, 0, INDEX_8, 2, 0, 5]))
        assert _named(response) == [(20, 0, 10), (20, 5, 30)]

    def test_variation_zero_takes_the_default(self):
        outstation, _ = _built()
        response = _read(outstation.session(), bytes([30, 0, INDEX_8, 1, 1]))
        assert response[4:6] == bytes([30, 1])

    def test_a_point_named_twice_is_sent_twice(self):
        outstation, _ = _built()
        response = _read(outstation.session(), bytes([30, 1, INDEX_8, 2, 1, 1]))
        assert _named(response) == [(30, 1, 1500), (30, 1, 1500)]

    def test_output_status_is_read_by_index(self):
        outstation, _ = _built()
        response = _read(outstation.session(), bytes([10, 0, INDEX_8, 1, 0]))
        assert [(group, index) for group, index, _ in _named(response)] == [(10, 0)]

    def test_an_index_that_is_not_a_point_is_a_parameter_error(self):
        """A range may cross a gap. An index says a point is there, and it is not."""
        outstation, _ = _built()
        response = _read(outstation.session(), bytes([20, 0, INDEX_8, 2, 0, 3]))
        assert response[3] & IIN2Bit.PARAM_ERROR
        assert not response[3] & IIN2Bit.OBJECT_UNKNOWN
        assert len(response) == 4, "and the point that does exist is not sent on its own"

    def test_a_read_that_names_no_index_is_a_parameter_error(self):
        outstation, _ = _built()
        response = _read(outstation.session(), bytes([30, 1, INDEX_8, 0]))
        assert response[3] & IIN2Bit.PARAM_ERROR

    def test_an_index_into_a_kind_with_no_points_is_an_unknown_object(self):
        point_map = load.resolve(small(), units(0))
        session = DerOutstation(point_map, Binding(), strict=False).session()
        response = _read(session, bytes([20, 0, INDEX_8, 1, 0]))
        assert response[3] & IIN2Bit.OBJECT_UNKNOWN

    def test_a_variation_not_offered_is_still_an_unknown_object(self):
        outstation, _ = _built()
        response = _read(outstation.session(), bytes([30, 5, INDEX_8, 1, 1]))
        assert response[3] & IIN2Bit.OBJECT_UNKNOWN

    def test_a_range_and_an_index_list_share_one_request(self):
        outstation, _ = _built()
        response = _read(
            outstation.session(), bytes([30, 1, 0x00, 1, 2]), bytes([20, 0, INDEX_8, 1, 5])
        )
        assert set(_values(response)) == {(30, 1), (30, 2)}
        assert _named(response) == [(20, 5, 30)]

    def test_a_point_that_cannot_be_trusted_takes_the_variation_with_flags(self):
        """As in a range: asking for the compact form never hides a bad value."""
        point_map = load.resolve(small(), units(0))
        binding = Binding()
        binding.read(AI, 1, lambda: 1500.0)
        binding.read(AI, 2, lambda: Reading(240.0, Quality.COMM_LOST))
        outstation = DerOutstation(point_map, binding, strict=False)
        request = bytes([0xC0, FunctionCode.READ, 30, 3, INDEX_8, 2, 1, 2])
        blocks = outstation.read_blocks(_headers_of(request))
        assert [block[:4] for block in blocks] == [
            bytes([30, 3, INDEX_8, 1]),
            bytes([30, 1, INDEX_8, 1]),
        ], "a block holds one variation, so the flagged point starts its own"

    def test_a_long_list_is_split_into_blocks_that_fit(self):
        rows = [analog(f"Point {index}", index, event_class=3) for index in range(400)]
        point_map = load.resolve(document({"AI": rows}), units(0))
        binding = Binding()
        for index in range(400):
            binding.read(AI, index, lambda index=index: float(index))
        outstation = DerOutstation(point_map, binding, block_octets=256)
        asked = list(range(399, 99, -3))
        request = (
            bytes([0xC0, FunctionCode.READ, 30, 1, INDEX_16])
            + struct.pack("<H", len(asked))
            + struct.pack(f"<{len(asked)}H", *asked)
        )
        blocks = outstation.read_blocks(_headers_of(request))
        assert len(blocks) > 1
        assert all(len(block) <= 256 for block in blocks)
        _, indexed = parse_objects(b"".join(blocks))
        assert [value.index for value in indexed] == asked, "nothing lost or reordered at the seams"
        assert [value.value for value in indexed] == asked


def _headers_of(request: bytes):
    from py1815.application import parse_request

    return parse_request(request).headers


class TestQuality:
    def _one(self, reading) -> int | None:
        point_map = load.resolve(small(), units(0))
        binding = Binding()
        binding.read(AI, 2, lambda: reading)
        outstation = DerOutstation(point_map, binding, strict=False)
        return _flags(_read(outstation.session(), bytes([30, 1, 0x00, 2, 2])))[(30, 2)]

    def test_a_good_value_is_online(self):
        assert self._one(Reading(240.0)) == 0x01

    def test_a_lost_source_clears_online_and_says_why(self):
        assert self._one(Reading(240.0, Quality.COMM_LOST)) == 0x04

    def test_a_value_never_read_says_restart(self):
        assert self._one(Reading(0.0, Quality.NEVER_READ)) == 0x02

    def test_a_value_outside_the_tables_range_is_flagged(self):
        assert self._one(Reading(700.0)) == 0x01 | 0x20

    def test_a_source_that_raises_costs_one_point_not_the_response(self):
        point_map = load.resolve(small(), units(0))
        binding = Binding()

        def broken() -> float:
            raise RuntimeError("device went away")

        binding.read(AI, 1, broken)
        binding.read(AI, 2, lambda: 240.0)
        outstation = DerOutstation(point_map, binding, strict=False)
        flags = _flags(_read(outstation.session(), bytes([30, 0, 0x00, 1, 2])))
        assert flags[(30, 1)] == 0x04
        assert flags[(30, 2)] == 0x01


class TestMirrorsAndSupport:
    def test_an_input_paired_with_a_bound_output_reports_what_it_last_accepted(self):
        outstation, _ = _built()
        session = outstation.session()
        before = _flags(_read(session, bytes([30, 1, 0x00, 3, 3])))
        assert before[(30, 3)] == 0x02, "nothing written yet, so nothing to report"
        _operate(session, _analog_command(0, 125), sequence=1)
        after = _values(_read(session, bytes([30, 1, 0x00, 3, 3]), sequence=2))
        assert after[(30, 3)] == 125

    def test_an_initial_value_is_reported_before_any_write(self):
        point_map = load.resolve(small(), units(0))
        binding = Binding()
        binding.output(AO, 0, initial=12.5)
        outstation = DerOutstation(point_map, binding, strict=False)
        values = _values(_read(outstation.session(), bytes([30, 1, 0x00, 3, 3])))
        assert values[(30, 3)] == 125

    def test_a_function_is_supported_when_its_enable_output_is_bound(self):
        outstation, _ = _built()
        assert _values(_read(outstation.session(), CLASS_0))[(1, 1)] == 1

    def test_and_not_when_it_is_not(self):
        """The control: support is derived from the binding, never declared."""
        point_map = load.resolve(small(), units(0))
        outstation = DerOutstation(point_map, Binding(), strict=False)
        assert _values(_read(outstation.session(), CLASS_0))[(1, 1)] == 0


class TestWhatABuildRefuses:
    def test_an_unbound_mandatory_point(self):
        point_map = load.resolve(small(), units(0))
        with pytest.raises(MapError, match="mandatory"):
            DerOutstation(point_map, Binding())

    def test_unless_told_the_map_is_deliberately_partial(self):
        point_map = load.resolve(small(), units(0))
        DerOutstation(point_map, Binding(), strict=False)

    def test_a_binding_for_a_point_the_map_does_not_hold(self):
        point_map = load.resolve(small(), units(0))
        binding = Binding()
        binding.read(AI, 4040, lambda: 0.0)
        with pytest.raises(MapError, match="AI4040"):
            DerOutstation(point_map, binding, strict=False)

    def test_binding_one_point_twice(self):
        binding = Binding()
        binding.read(AI, 1, lambda: 0.0)
        with pytest.raises(ValueError, match="already bound"):
            binding.read(AI, 1, lambda: 1.0)

    @pytest.mark.parametrize(
        ("kind", "method"), [(AO, "read"), (BO, "read"), (AI, "output"), (CTR, "output")]
    )
    def test_binding_a_point_in_the_wrong_direction(self, kind, method):
        with pytest.raises(ValueError):
            getattr(Binding(), method)(kind, 0, lambda *_: 0.0)

    def test_a_deadband_on_anything_but_an_analog_input(self):
        with pytest.raises(ValueError):
            Binding().read(BI, 0, lambda: False, deadband=1.0)


def _control(function: FunctionCode, body: bytes, sequence: int) -> bytes:
    return bytes([0xC0 | sequence, function]) + body


def _analog_command(index: int, raw: int, variation: int = 2) -> bytes:
    value = struct.pack("<h" if variation == 2 else "<i", raw)
    return bytes([41, variation, 0x17, 1, index]) + value + b"\x00"


def _crob(index: int, block: ControlRelayOutputBlock) -> bytes:
    return bytes([12, 1, 0x17, 1, index]) + encode_crob(block)


def _operate(session, body: bytes, sequence: int = 0) -> CommandStatus:
    response = session._handle_fragment(_control(FunctionCode.DIRECT_OPERATE, body, sequence))
    return CommandStatus(response[-1])


class TestAnalogOutputs:
    def test_a_setpoint_reaches_the_binding_in_engineering_units(self):
        outstation, device = _built()
        assert _operate(outstation.session(), _analog_command(0, 125)) is CommandStatus.SUCCESS
        assert device.applied == [("setpoint", 12.5)]

    def test_a_value_outside_the_tables_range_is_refused_not_clamped(self):
        outstation, device = _built()
        status = _operate(outstation.session(), _analog_command(0, 1001))
        assert status is CommandStatus.OUT_OF_RANGE
        assert device.applied == []

    def test_the_thirty_two_bit_variation_is_accepted_too(self):
        outstation, device = _built()
        status = _operate(outstation.session(), _analog_command(0, -500, variation=1))
        assert status is CommandStatus.SUCCESS
        assert device.applied == [("setpoint", -50.0)]

    def test_a_floating_point_setpoint_is_engineering_units_already(self):
        outstation, device = _built()
        body = bytes([41, 3, 0x17, 1, 0]) + struct.pack("<f", 12.5) + b"\x00"
        assert _operate(outstation.session(), body) is CommandStatus.SUCCESS
        assert device.applied == [("setpoint", 12.5)]

    def test_a_point_with_no_binding_is_not_supported(self):
        outstation, _ = _built()
        assert _operate(outstation.session(), _analog_command(9, 1)) is CommandStatus.NOT_SUPPORTED

    def test_the_bindings_refusal_is_the_answer_and_nothing_is_stored(self):
        outstation, device = _built()
        device.verdict = CommandStatus.HARDWARE_ERROR
        session = outstation.session()
        assert _operate(session, _analog_command(0, 125)) is CommandStatus.HARDWARE_ERROR
        assert outstation.value(AO, 0) is None

    def test_the_status_reads_back_what_was_written(self):
        outstation, _ = _built()
        session = outstation.session()
        _operate(session, _analog_command(0, 125))
        values = _values(_read(session, bytes([40, 0, ALL]), sequence=1))
        assert values[(40, 0)] == 125


class TestSelectBeforeOperate:
    def test_a_select_checks_and_does_not_execute(self):
        outstation, device = _built()
        session = outstation.session()
        body = _analog_command(0, 125)
        selected = session._handle_fragment(_control(FunctionCode.SELECT, body, 0))
        assert CommandStatus(selected[-1]) is CommandStatus.SUCCESS
        assert device.applied == []
        operated = session._handle_fragment(_control(FunctionCode.OPERATE, body, 1))
        assert CommandStatus(operated[-1]) is CommandStatus.SUCCESS
        assert device.applied == [("setpoint", 12.5)]

    def test_a_select_out_of_range_is_refused_at_the_select(self):
        outstation, _ = _built()
        response = outstation.session()._handle_fragment(
            _control(FunctionCode.SELECT, _analog_command(0, 1001), 0)
        )
        assert CommandStatus(response[-1]) is CommandStatus.OUT_OF_RANGE

    def test_a_check_refuses_on_select_and_on_operate(self):
        point_map = load.resolve(small(), units(0))
        binding = Binding()
        applied: list[float] = []
        binding.output(AO, 0, applied.append, check=lambda _value: CommandStatus.BLOCKED)
        session = DerOutstation(point_map, binding, strict=False).session()
        body = _analog_command(0, 1)
        selected = session._handle_fragment(_control(FunctionCode.SELECT, body, 0))
        assert CommandStatus(selected[-1]) is CommandStatus.BLOCKED
        assert _operate(session, body, sequence=1) is CommandStatus.BLOCKED
        assert applied == []


class TestBinaryOutputsBehaveAsLatched:
    @pytest.mark.parametrize(
        ("block", "state"),
        [
            pytest.param(
                ControlRelayOutputBlock.build(OperationType.LATCH_ON), True, id="latch on"
            ),
            pytest.param(
                ControlRelayOutputBlock.build(OperationType.LATCH_OFF), False, id="latch off"
            ),
            pytest.param(
                ControlRelayOutputBlock.build(OperationType.PULSE_ON, on_time_ms=50),
                True,
                id="pulse on, pulse time ignored",
            ),
            pytest.param(
                ControlRelayOutputBlock.build(OperationType.PULSE_OFF), False, id="pulse off"
            ),
            pytest.param(
                ControlRelayOutputBlock.build(
                    OperationType.PULSE_ON, trip_close=TripCloseCode.CLOSE
                ),
                True,
                id="close",
            ),
            pytest.param(
                ControlRelayOutputBlock.build(
                    OperationType.PULSE_ON, trip_close=TripCloseCode.TRIP
                ),
                False,
                id="trip",
            ),
        ],
    )
    def test_every_operation_pair_sets_or_clears(self, block, state):
        outstation, device = _built()
        assert _operate(outstation.session(), _crob(0, block)) is CommandStatus.SUCCESS
        assert device.applied == [("widget", state)]

    def test_an_operation_that_names_no_state_is_not_supported(self):
        outstation, device = _built()
        status = _operate(outstation.session(), _crob(0, ControlRelayOutputBlock.build()))
        assert status is CommandStatus.NOT_SUPPORTED
        assert device.applied == []

    def test_the_mirror_input_follows_the_output(self):
        outstation, _ = _built()
        session = outstation.session()
        _operate(session, _crob(0, ControlRelayOutputBlock.build(OperationType.LATCH_ON)))
        assert _values(_read(session, CLASS_0, sequence=1))[(1, 2)] == 1


class TestEvents:
    def test_the_first_poll_reports_nothing(self):
        """A master learns initial values from its integrity poll."""
        outstation, _ = _built()
        assert outstation.poll() == 0
        assert outstation.events.total == 0

    def test_a_change_is_an_event_in_the_class_the_tables_give(self):
        outstation, device = _built()
        outstation.poll()
        device.alarm = True
        device.voltage = 250.0
        assert outstation.poll() == 2
        assert outstation.events.count(EventClass.CLASS_1) == 1
        assert outstation.events.count(EventClass.CLASS_2) == 1

    def test_no_change_is_no_event(self):
        outstation, _ = _built()
        outstation.poll()
        assert outstation.poll() == 0

    def test_a_deadband_holds_back_a_small_change(self):
        point_map = load.resolve(small(), units(0))
        device = Device()
        binding = Binding()
        binding.read(AI, 2, lambda: device.voltage, deadband=20)
        outstation = DerOutstation(point_map, binding, strict=False)
        outstation.poll()
        device.voltage = 241.0
        assert outstation.poll() == 0, "ten counts moved, inside a deadband of twenty"
        device.voltage = 243.0
        assert outstation.poll() == 1

    def test_a_supports_flag_never_produces_an_event(self):
        outstation, _ = _built()
        outstation.poll()
        outstation.poll()
        assert not any(event.index == 1 for event in outstation.events.peek(EventClass.CLASS_1))

    def test_analog_events_travel_untimed_in_thirty_two_bits(self):
        outstation, device = _built()
        session = outstation.session()
        outstation.poll()
        device.voltage = 250.0
        outstation.poll()
        response = _read(session, bytes([60, 3, ALL]))
        assert response[4:6] == bytes([32, 1])
        _, events = parse_objects(response[4:])
        assert [(event.index, event.value) for event in events] == [(2, 2500)]

    def test_a_control_reports_its_mirror_in_the_same_response(self):
        outstation, _ = _built()
        session = outstation.session()
        outstation.poll()
        response = session._handle_fragment(
            _control(FunctionCode.DIRECT_OPERATE, _analog_command(0, 125), 0)
        )
        assert response[2] & IINBit.CLASS_2_EVENTS


class TestFreezing:
    def _freeze(self, session, function: FunctionCode, header: bytes) -> bytes:
        return session._handle_fragment(bytes([0xC0, function]) + header)

    def test_a_freeze_copies_the_counters_and_logs_an_event_each(self):
        outstation, device = _built()
        session = outstation.session()
        self._freeze(session, FunctionCode.IMMED_FREEZE, bytes([20, 0, ALL]))
        device.energy[0] = 99.0
        values = _values(_read(session, CLASS_0, sequence=1))
        assert values[(20, 0)] == 99, "the running counter moved on"
        assert values[(21, 0)] == 10, "the frozen one did not"
        assert outstation.events.count(EventClass.CLASS_3) == 2

    def test_a_counter_with_no_frozen_twin_is_not_frozen(self):
        outstation, _ = _built()
        outstation.freeze_all()
        assert (21, 5) not in _values(_read(outstation.session(), CLASS_0))

    def test_the_freeze_time_is_the_outstations_clock(self):
        outstation, _ = _built()
        outstation.set_time(1_000_000)
        outstation.freeze_all()
        (first, *_) = outstation.events.peek(EventClass.CLASS_3)
        assert first.timestamp_ms == 1_000_000

    def test_freeze_and_clear_freezes_without_clearing(self):
        """The profile computes an interval's energy by subtracting two freezes."""
        outstation, _ = _built()
        session = outstation.session()
        response = self._freeze(session, FunctionCode.FREEZE_CLEAR, bytes([20, 0, ALL]))
        assert not response[3]
        assert _values(_read(session, CLASS_0, sequence=1))[(20, 0)] == 10

    def test_a_range_freezes_only_what_it_names(self):
        outstation, _ = _built()
        session = outstation.session()
        self._freeze(session, FunctionCode.IMMED_FREEZE, bytes([20, 0, 0x00, 1, 1]))
        values = _values(_read(session, CLASS_0, sequence=1))
        assert (21, 1) in values and (21, 0) not in values

    def test_freezing_anything_but_counters_is_an_unknown_object(self):
        outstation, _ = _built()
        response = self._freeze(
            outstation.session(), FunctionCode.IMMED_FREEZE, bytes([30, 0, ALL])
        )
        assert response[3] & IIN2Bit.OBJECT_UNKNOWN

    def test_frozen_counter_events_are_read_with_their_times(self):
        outstation, _ = _built()
        session = outstation.session()
        outstation.freeze_all()
        response = _read(session, bytes([23, 0, ALL]))
        assert response[4:6] == bytes([23, 5])
        _, events = parse_objects(response[4:])
        assert [(event.index, event.value) for event in events] == [(0, 10), (1, 20)]

    def test_an_outstation_with_no_counters_does_not_offer_to_freeze(self):
        point_map = load.resolve(small(), units(0))
        session = DerOutstation(point_map, Binding(), strict=False).session()
        response = self._freeze(session, FunctionCode.IMMED_FREEZE, bytes([20, 0, ALL]))
        assert response[3] & IIN2Bit.FUNC_NOT_SUPPORTED


class TestTheSessionItWires:
    def test_it_asks_for_the_time_until_a_master_writes_it(self):
        outstation, _ = _built()
        session = outstation.session()
        assert _read(session, CLASS_0)[2] & IINBit.NEED_TIME
        moment = 1_700_000_000_000
        session._handle_fragment(
            bytes([0xC1, FunctionCode.WRITE, 50, 1, QualifierCode.UINT8_COUNT, 1])
            + moment.to_bytes(6, "little")
        )
        assert outstation.now_ms() == moment
        assert not _read(session, CLASS_0, sequence=2)[2] & IINBit.NEED_TIME

    def test_an_outstation_with_no_outputs_is_a_monitor(self):
        point_map = load.resolve(small(), units(0))
        session = DerOutstation(point_map, Binding(), strict=False).session()
        response = session._handle_fragment(
            _control(FunctionCode.DIRECT_OPERATE, _analog_command(0, 1), 0)
        )
        assert response[3] & IIN2Bit.OBJECT_UNKNOWN

    def test_an_output_status_can_be_a_window_onto_something_else(self):
        point_map = load.resolve(small(), units(0))
        binding = Binding()
        binding.output(AO, 0, status=lambda: 33.3)
        session = DerOutstation(point_map, binding, strict=False).session()
        assert _values(_read(session, bytes([40, 0, ALL])))[(40, 0)] == 333
