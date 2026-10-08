"""The builder: a map and a binding in, an outstation's answers out.

Driven through a real session wherever the behavior is one a master would see,
so the assertions are about what reaches the wire and not about the builder's
internals. The probe's parser reads the responses, which keeps the object
layouts out of the tests.
"""

from __future__ import annotations

import dataclasses
import re
import struct

import pytest
from profile_fixtures import analog, document, row, small, units

from py1815 import link
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
from py1815.profile.coverage import Source
from py1815.profile.model import Kind, MapError
from py1815.profile.outstation import DerOutstation
from py1815.profile.policy import EventPolicy, EventRule
from py1815.profile.probe import parse_objects
from py1815.transport import Reassembler

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

    def test_a_named_point_with_nothing_to_report_is_a_parameter_error(self):
        """A frozen counter never frozen is served and has no value. Named, that is said."""
        outstation, _ = _built()
        session = outstation.session()
        response = _read(session, bytes([21, 0, INDEX_8, 1, 0]))
        assert response[3] & IIN2Bit.PARAM_ERROR
        assert not response[3] & IIN2Bit.OBJECT_UNKNOWN
        assert len(response) == 4, "an empty answer with clean indications would look complete"
        outstation.freeze_all()
        response = _read(session, bytes([21, 0, INDEX_8, 1, 0]), sequence=1)
        assert not response[3]
        assert [(group, index) for group, index, _ in _named(response)] == [(21, 0)]

    def test_it_takes_the_points_named_beside_it_with_it(self):
        """One header, one answer: a counter with a value is not sent without the other."""
        outstation, _ = _built()
        session = outstation.session()
        mixed = bytes([20, 0, INDEX_8, 1, 0]), bytes([21, 0, INDEX_8, 1, 0])
        response = _read(session, *mixed)
        assert response[3] & IIN2Bit.PARAM_ERROR and len(response) == 4

    def test_a_range_over_the_same_counter_is_still_empty_and_not_an_error(self):
        """The contrast: a range asks for whatever is there, and nothing is."""
        outstation, _ = _built()
        response = _read(outstation.session(), bytes([21, 0, 0x00, 0, 0]))
        assert not response[3] & (IIN2Bit.PARAM_ERROR | IIN2Bit.OBJECT_UNKNOWN)
        assert len(response) == 4

    @pytest.mark.parametrize(("qualifier", "fits"), [(INDEX_8, 10), (INDEX_16, 8)])
    def test_a_block_is_filled_to_the_budget_its_own_header_leaves(self, qualifier, fits):
        """The header is four octets with an eight-bit count and five with sixteen."""
        rows = [analog(f"Point {index}", index, event_class=3) for index in range(40)]
        point_map = load.resolve(document({"AI": rows}), units(0))
        binding = Binding()
        for index in range(40):
            binding.read(AI, index, lambda index=index: float(index))
        outstation = DerOutstation(point_map, binding, block_octets=64)
        width = 1 if qualifier == INDEX_8 else 2
        asked = list(range(30))
        request = (
            bytes([0xC0, FunctionCode.READ, 30, 1, qualifier])
            + len(asked).to_bytes(width, "little")
            + b"".join(index.to_bytes(width, "little") for index in asked)
        )
        blocks = outstation.read_blocks(_headers_of(request))
        assert all(len(block) <= 64 for block in blocks)
        assert int.from_bytes(blocks[0][3 : 3 + width], "little") == fits

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


def _with_policy(policy, binding: Binding | None = None) -> DerOutstation:
    """An outstation over the small map, built under an event policy."""
    point_map = load.resolve(small(), units(0))
    if binding is None:
        binding = Device().binding()
    return DerOutstation(point_map, binding, strict=False, event_policy=policy)


class TestWhatAnEventPolicyIsRefusedFor:
    """A bad policy stops the build, so it is found at startup and not in service."""

    def test_a_point_the_map_does_not_hold(self):
        with pytest.raises(MapError, match="AI4040"):
            _with_policy({"points": {"AI4040": {"class": 1}}})

    @pytest.mark.parametrize("event_class", [1.0, 2.0, 3.0])
    def test_a_class_that_is_a_float_even_a_whole_one(self, event_class):
        """``1.0 == 1``, and a float in force would break event_class()'s contract."""
        with pytest.raises(ValueError, match="1, 2 or 3"):
            _with_policy({"points": {"AI2": {"class": event_class}}})

    @pytest.mark.parametrize("section", ["defaults", "points"])
    def test_a_section_that_is_present_and_null(self, section):
        """An empty value where a mapping belongs is a mistake, not an omission."""
        with pytest.raises(ValueError, match=section):
            _with_policy({section: None})

    def test_a_section_left_out_is_no_rules(self):
        """The control for the test above: leaving a section out is allowed."""
        outstation = _with_policy({"points": {"AI2": {"class": 1}}})
        assert outstation.event_class(AI, 2) == 1

    def _counter_left_out_of_class_0(self):
        """The small map with its first counter left out of class 0 by hand.

        The loader never does this to a counter, so the map is built here: the
        point is what the builder does if a map arrives that way.
        """
        base = load.resolve(small(), units(0))
        points = dict(base.points)
        points[(CTR, 0)] = dataclasses.replace(points[(CTR, 0)], event_class=None)
        return dataclasses.replace(base, points=points)

    def test_events_for_a_counter_left_out_of_class_0(self):
        point_map = self._counter_left_out_of_class_0()
        with pytest.raises(MapError, match="class 0"):
            DerOutstation(
                point_map,
                Device().binding(),
                strict=False,
                event_policy={"points": {"CTR0": {"class": 1}}},
            )

    def test_and_a_counter_default_leaves_such_a_counter_alone(self):
        point_map = self._counter_left_out_of_class_0()
        outstation = DerOutstation(
            point_map,
            Device().binding(),
            strict=False,
            event_policy={"defaults": {"CTR": {"class": 1}}},
        )
        assert outstation.event_class(CTR, 0) == 0
        assert outstation.event_class(CTR, 1) == 1, "the counter beside it still follows"

    @pytest.mark.parametrize("event_class", [0, 4, -1, "2", 2.5, True])
    def test_a_class_outside_one_to_three(self, event_class):
        with pytest.raises(ValueError, match="1, 2 or 3"):
            _with_policy({"points": {"AI2": {"class": event_class}}})
        with pytest.raises(ValueError, match="1, 2 or 3"):
            _with_policy({"defaults": {"BI": {"class": event_class}}})

    @pytest.mark.parametrize("deadband", [-0.5, float("nan"), float("inf"), "1", True])
    def test_a_deadband_that_is_not_zero_or_more(self, deadband):
        with pytest.raises(ValueError, match="deadband"):
            _with_policy({"points": {"AI2": {"deadband": deadband}}})

    @pytest.mark.parametrize(
        "policy",
        [
            pytest.param({"points": {"BI0": {"deadband": 1.0}}}, id="a binary input"),
            pytest.param({"points": {"CTR0": {"deadband": 1.0}}}, id="a counter"),
            pytest.param({"defaults": {"BI": {"deadband": 1.0}}}, id="every binary input"),
        ],
    )
    def test_a_deadband_on_anything_but_an_analog_input(self, policy):
        with pytest.raises(ValueError, match="only an analog input"):
            _with_policy(policy)

    @pytest.mark.parametrize(
        "policy",
        [
            pytest.param({"points": {"AO0": {"class": 1}}}, id="a point"),
            pytest.param({"defaults": {"BO": {"class": 1}}}, id="a kind"),
        ],
    )
    def test_an_event_class_for_an_output(self, policy):
        with pytest.raises(ValueError, match="output"):
            _with_policy(policy)

    @pytest.mark.parametrize(
        "policy",
        [
            pytest.param({"points": {"AI2": {"clas": 1}}}, id="in a rule"),
            pytest.param({"default": {"AI": {"class": 1}}}, id="in the policy"),
            pytest.param({"points": {"XX2": {"class": 1}}}, id="a kind that is not one"),
            pytest.param({"points": {"AI": {"class": 1}}}, id="a point with no index"),
            pytest.param({"defaults": {"AI2": {"class": 1}}}, id="a point where a kind goes"),
            pytest.param({"points": {"AI2": 1}}, id="a rule that is not a mapping"),
        ],
    )
    def test_a_key_it_does_not_know(self, policy):
        """A misspelled key would otherwise be a rule that silently does nothing."""
        with pytest.raises(ValueError):
            _with_policy(policy)

    def test_a_rule_that_turns_events_off_and_names_a_class(self):
        with pytest.raises(ValueError, match="turned off"):
            _with_policy({"points": {"AI2": {"events": False, "class": 2}}})

    def test_a_class_for_a_point_left_out_of_class_0(self):
        """An event would report a change to a value the integrity poll never gave."""
        with pytest.raises(MapError, match="AI65000"):
            _with_policy({"points": {"AI65000": {"class": 3}}})

    def test_a_class_for_a_counter_with_no_frozen_twin(self):
        with pytest.raises(MapError, match="CTR5"):
            _with_policy({"points": {"CTR5": {"class": 3}}})

    def test_events_turned_on_for_a_point_nothing_gives_a_class(self):
        with pytest.raises(MapError, match="AI4"):
            _with_policy({"points": {"AI4": {"events": True}}})

    def test_a_deadband_for_a_point_that_reports_no_events(self):
        with pytest.raises(MapError, match="AI4"):
            _with_policy({"points": {"AI4": {"deadband": 1.0}}})
        off = {"defaults": {"AI": {"events": False}}, "points": {"AI2": {"deadband": 1}}}
        with pytest.raises(MapError, match="AI2"):
            _with_policy(off)

    def test_the_dataclasses_refuse_what_the_plain_form_does(self):
        with pytest.raises(ValueError, match="1, 2 or 3"):
            EventRule(event_class=4)
        with pytest.raises(ValueError, match="deadband"):
            EventRule(deadband=-1.0)
        with pytest.raises(ValueError, match="only an analog input"):
            EventPolicy(points={(BI, 0): EventRule(deadband=1.0)})
        with pytest.raises(ValueError, match="output"):
            EventPolicy(defaults={AO: EventRule(event_class=1)})

    def test_a_point_the_map_holds_and_nothing_serves_is_not_an_error(self):
        """A policy may run ahead of a binding that is still growing."""
        binding = Binding()
        binding.read(AI, 2, lambda: 240.0)
        _with_policy({"points": {"BI9": {"class": 3}, "AI1": {"deadband": 5}}}, binding)


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


class Unit:
    """A device that applies its own limit, so what is in force is not what was asked."""

    def __init__(self, limit: float = 10.0) -> None:
        self.limit = limit
        self.setpoint = 0.0
        self.asked: list[float] = []

    def apply(self, value: float) -> None:
        self.asked.append(value)
        self.setpoint = max(-self.limit, min(self.limit, value))

    def outstation(self, **kwargs) -> DerOutstation:
        binding = Binding()
        binding.output(AO, 0, self.apply, status=lambda: self.setpoint)
        return DerOutstation(load.resolve(small(), units(0)), binding, strict=False, **kwargs)


SETPOINT_STATUS = bytes([40, 0, ALL])
SETPOINT_MIRROR = bytes([30, 1, 0x00, 3, 3])


class TestWhatWasApplied:
    """A commanding outstation relays, and reports what the device put in force."""

    def test_the_status_and_the_mirror_both_report_the_applied_value(self):
        unit = Unit(limit=10.0)
        session = unit.outstation().session()
        assert _operate(session, _analog_command(0, 125)) is CommandStatus.SUCCESS
        assert unit.asked == [12.5]
        assert _values(_read(session, SETPOINT_STATUS, sequence=1))[(40, 0)] == 100
        mirror = _values(_read(session, SETPOINT_MIRROR, sequence=2))
        assert mirror[(30, 3)] == 100, "the input shows what is in force, not what was asked"

    def test_the_event_a_control_raises_carries_the_applied_value(self):
        unit = Unit(limit=10.0)
        outstation = unit.outstation()
        session = outstation.session()
        outstation.poll()
        response = session._handle_fragment(
            _control(FunctionCode.DIRECT_OPERATE, _analog_command(0, 125), 0)
        )
        assert response[2] & IINBit.CLASS_2_EVENTS
        _, events = parse_objects(_read(session, bytes([60, 3, ALL]), sequence=1)[4:])
        assert [(event.index, event.value) for event in events] == [(3, 100)]

    def test_a_change_with_no_command_behind_it_is_an_event(self):
        """How a master learns its setpoint was reduced after it was accepted."""
        unit = Unit(limit=20.0)
        outstation = unit.outstation()
        session = outstation.session()
        _operate(session, _analog_command(0, 125))
        outstation.poll()
        _read(session, bytes([60, 3, ALL]), sequence=1)
        unit.setpoint = 8.0
        assert outstation.poll() == 1
        _, events = parse_objects(_read(session, bytes([60, 3, ALL]), sequence=2)[4:])
        assert [(event.index, event.value) for event in events] == [(3, 80)]

    def test_a_status_that_cannot_be_read_says_so_on_the_mirror_too(self):
        binding = Binding()

        def gone() -> float:
            raise RuntimeError("device went away")

        binding.output(AO, 0, status=gone)
        outstation = DerOutstation(load.resolve(small(), units(0)), binding, strict=False)
        flags = _flags(_read(outstation.session(), SETPOINT_MIRROR))
        assert flags[(30, 3)] == 0x04

    def test_without_a_status_reader_the_mirror_is_still_the_last_write(self):
        outstation, _ = _built()
        session = outstation.session()
        _operate(session, _analog_command(0, 125))
        assert _values(_read(session, SETPOINT_MIRROR, sequence=1))[(30, 3)] == 125


class TestAReadOnlyOutstation:
    """Built to report and not to command: every control is refused, and says why."""

    def test_a_direct_operate_is_refused_and_nothing_is_applied(self):
        outstation, device = _built(read_only=True)
        status = _operate(outstation.session(), _analog_command(0, 125))
        assert status is CommandStatus.NOT_AUTHORIZED
        assert device.applied == []

    def test_a_latch_is_refused_too(self):
        outstation, device = _built(read_only=True)
        block = ControlRelayOutputBlock.build(OperationType.LATCH_ON)
        assert _operate(outstation.session(), _crob(0, block)) is CommandStatus.NOT_AUTHORIZED
        assert device.applied == []

    def test_a_select_is_refused_so_no_operate_is_armed(self):
        outstation, device = _built(read_only=True)
        session = outstation.session()
        selected = session._handle_fragment(
            _control(FunctionCode.SELECT, _analog_command(0, 125), 0)
        )
        assert CommandStatus(selected[-1]) is CommandStatus.NOT_AUTHORIZED
        operated = session._handle_fragment(
            _control(FunctionCode.OPERATE, _analog_command(0, 125), 1)
        )
        assert CommandStatus(operated[-1]) is not CommandStatus.SUCCESS
        assert device.applied == []

    def test_a_direct_operate_that_takes_no_response_is_not_applied_either(self):
        outstation, device = _built(read_only=True)
        response = outstation.session()._handle_fragment(
            _control(FunctionCode.DIRECT_OPERATE_NR, _analog_command(0, 125), 0)
        )
        assert response == b"" and device.applied == []

    def test_the_bindings_own_check_is_never_asked(self):
        asked: list[float] = []
        binding = Binding()
        binding.output(AO, 0, check=lambda value: asked.append(value))
        outstation = DerOutstation(
            load.resolve(small(), units(0)), binding, strict=False, read_only=True
        )
        _operate(outstation.session(), _analog_command(0, 125))
        assert asked == []

    def test_a_point_that_is_not_there_is_still_not_supported(self):
        """The refusal is about this interface. A missing point is a different fact."""
        outstation, _ = _built(read_only=True)
        assert _operate(outstation.session(), _analog_command(9, 1)) is CommandStatus.NOT_SUPPORTED

    def test_the_status_it_refuses_with_is_the_callers_to_choose(self):
        outstation, _ = _built(read_only=True, read_only_status=CommandStatus.BLOCKED_OTHER_MASTER)
        status = _operate(outstation.session(), _analog_command(0, 125))
        assert status is CommandStatus.BLOCKED_OTHER_MASTER

    def test_success_is_not_a_refusal(self):
        with pytest.raises(ValueError, match="refus"):
            _built(read_only=True, read_only_status=CommandStatus.SUCCESS)

    def test_reads_are_answered_as_before(self):
        outstation, _ = _built(read_only=True)
        values = _values(_read(outstation.session(), CLASS_0))
        assert values[(30, 1)] == 1500

    def test_the_value_in_force_is_reported_from_the_status_reader(self):
        """Another interface set it, so this one reports it and did not write it."""
        unit = Unit()
        unit.setpoint = 7.5
        session = unit.outstation(read_only=True).session()
        assert _values(_read(session, SETPOINT_STATUS))[(40, 0)] == 75
        assert _values(_read(session, SETPOINT_MIRROR, sequence=1))[(30, 3)] == 75
        assert _operate(session, _analog_command(0, 10), sequence=2) is CommandStatus.NOT_AUTHORIZED
        assert unit.asked == []

    def test_with_no_status_reader_an_initial_value_is_what_stands(self):
        binding = Binding()
        binding.output(AO, 0, initial=12.5)
        outstation = DerOutstation(
            load.resolve(small(), units(0)), binding, strict=False, read_only=True
        )
        assert _values(_read(outstation.session(), SETPOINT_STATUS))[(40, 0)] == 125

    def test_a_write_accepted_before_it_became_read_only_is_not_reported_as_in_force(self):
        """Once another interface commands, the last thing written here says nothing."""
        outstation, _ = _built()
        session = outstation.session()
        _operate(session, _analog_command(0, 125))
        assert _values(_read(session, SETPOINT_STATUS, sequence=1))[(40, 0)] == 125
        outstation.read_only = True
        assert _flags(_read(session, SETPOINT_STATUS, sequence=2))[(40, 0)] == 0x02
        assert _flags(_read(session, SETPOINT_MIRROR, sequence=3))[(30, 3)] == 0x02

    def test_the_role_can_be_given_back(self):
        outstation, device = _built(read_only=True)
        session = outstation.session()
        assert _operate(session, _analog_command(0, 125)) is CommandStatus.NOT_AUTHORIZED
        outstation.read_only = False
        assert _operate(session, _analog_command(0, 125), sequence=1) is CommandStatus.SUCCESS
        assert device.applied == [("setpoint", 12.5)]

    def test_a_role_change_spends_a_select_granted_before_it(self):
        """A select is permission given under one role. It is not carried into another."""
        outstation, device = _built()
        session = outstation.session()
        selected = session._handle_fragment(
            _control(FunctionCode.SELECT, _analog_command(0, 125), 0)
        )
        assert CommandStatus(selected[-1]) is CommandStatus.SUCCESS
        outstation.read_only = True
        outstation.read_only = False
        operated = session._handle_fragment(
            _control(FunctionCode.OPERATE, _analog_command(0, 125), 1)
        )
        assert CommandStatus(operated[-1]) is CommandStatus.NO_SELECT
        assert device.applied == []

    def test_an_operate_after_it_became_read_only_is_refused_as_read_only(self):
        """The select was good. What changed is who may command, and the answer says so."""
        outstation, device = _built(read_only_status=CommandStatus.BLOCKED_OTHER_MASTER)
        session = outstation.session()
        selected = session._handle_fragment(
            _control(FunctionCode.SELECT, _analog_command(0, 125), 0)
        )
        assert CommandStatus(selected[-1]) is CommandStatus.SUCCESS
        outstation.read_only = True
        operated = session._handle_fragment(
            _control(FunctionCode.OPERATE, _analog_command(0, 125), 1)
        )
        assert CommandStatus(operated[-1]) is CommandStatus.BLOCKED_OTHER_MASTER
        assert device.applied == []

    def test_and_that_refusal_spends_the_select(self):
        """Refused once as read-only, the select is not there to operate on afterwards."""
        outstation, device = _built()
        session = outstation.session()
        session._handle_fragment(_control(FunctionCode.SELECT, _analog_command(0, 125), 0))
        outstation.read_only = True
        session._handle_fragment(_control(FunctionCode.OPERATE, _analog_command(0, 125), 1))
        outstation.read_only = False
        operated = session._handle_fragment(
            _control(FunctionCode.OPERATE, _analog_command(0, 125), 2)
        )
        assert CommandStatus(operated[-1]) is CommandStatus.NO_SELECT
        assert device.applied == []

    def test_setting_the_role_it_already_has_spends_nothing(self):
        """The control for the test above: no change of role, and the select stands."""
        outstation, device = _built()
        session = outstation.session()
        session._handle_fragment(_control(FunctionCode.SELECT, _analog_command(0, 125), 0))
        outstation.read_only = False
        operated = session._handle_fragment(
            _control(FunctionCode.OPERATE, _analog_command(0, 125), 1)
        )
        assert CommandStatus(operated[-1]) is CommandStatus.SUCCESS
        assert device.applied == [("setpoint", 12.5)]

    def test_giving_the_role_back_does_not_restore_trust_in_an_old_write(self):
        """Another interface may have changed the value while this one only reported."""
        outstation, _ = _built()
        session = outstation.session()
        _operate(session, _analog_command(0, 125))
        outstation.read_only = True
        outstation.read_only = False
        assert _flags(_read(session, SETPOINT_STATUS, sequence=1))[(40, 0)] == 0x02
        assert _flags(_read(session, SETPOINT_MIRROR, sequence=2))[(30, 3)] == 0x02
        assert _operate(session, _analog_command(0, 100), sequence=3) is CommandStatus.SUCCESS
        assert _values(_read(session, SETPOINT_STATUS, sequence=4))[(40, 0)] == 100

    def test_counters_are_still_frozen_on_request(self):
        """A freeze changes what the outstation reports, not what the device does."""
        outstation, _ = _built(read_only=True)
        session = outstation.session()
        response = session._handle_fragment(bytes([0xC0, FunctionCode.IMMED_FREEZE, 20, 0, ALL]))
        assert not response[3]
        assert (21, 0) in _values(_read(session, bytes([21, 0, ALL]), sequence=1))


class TestEventTimestamps:
    """Events use the reading's measurement time when it provides one.

    A caller that polls a device and queues the readings knows when each value
    was measured. That is earlier than the time the outstation sees the change.
    """

    NOW = 5_000_000
    MEASURED = 4_990_000

    def _outstation(self, kind, index, reader):
        binding = Binding()
        binding.read(kind, index, reader)
        return DerOutstation(
            load.resolve(small(), units(0)), binding, strict=False, clock_ms=lambda: self.NOW
        )

    def _event_after(self, outstation, change, event_class):
        outstation.poll()
        change()
        outstation.poll()
        (event,) = outstation.events.peek(event_class)
        return event

    def test_binary_event_uses_reading_time(self):
        state = {"on": False}
        outstation = self._outstation(
            BI, 0, lambda: Reading(state["on"], timestamp_ms=self.MEASURED)
        )

        event = self._event_after(outstation, lambda: state.update(on=True), EventClass.CLASS_1)

        assert event.timestamp_ms == self.MEASURED

    def test_analog_event_uses_reading_time(self):
        state = {"volts": 240.0}
        outstation = self._outstation(
            AI, 2, lambda: Reading(state["volts"], timestamp_ms=self.MEASURED)
        )

        event = self._event_after(outstation, lambda: state.update(volts=250.0), EventClass.CLASS_2)

        assert event.timestamp_ms == self.MEASURED

    @pytest.mark.parametrize("bare", [True, False])
    def test_reading_without_time_uses_outstation_clock(self, bare):
        """A bare value and a Reading with no timestamp both mean "now"."""
        state = {"on": False}
        outstation = self._outstation(
            BI, 0, (lambda: state["on"]) if bare else (lambda: Reading(state["on"]))
        )

        event = self._event_after(outstation, lambda: state.update(on=True), EventClass.CLASS_1)

        assert event.timestamp_ms == self.NOW

    def test_reading_time_is_shifted_by_master_time_write(self):
        """A reading measured ten seconds ago is reported as ten seconds before
        the outstation's current time, after a master has written the time."""
        state = {"on": False}
        outstation = self._outstation(
            BI, 0, lambda: Reading(state["on"], timestamp_ms=self.MEASURED)
        )
        written = 1_700_000_000_000
        outstation.set_time(written)

        event = self._event_after(outstation, lambda: state.update(on=True), EventClass.CLASS_1)

        assert outstation.now_ms() == written
        assert event.timestamp_ms == written - (self.NOW - self.MEASURED)

    def test_master_reads_reading_time_in_event_response(self):
        """The binary event a master reads carries the reading's time.

        The master has written the time, so the event is sent with an absolute
        timestamp: six octets after the flags.
        """
        state = {"on": False}
        outstation = self._outstation(
            BI, 0, lambda: Reading(state["on"], timestamp_ms=self.MEASURED)
        )
        session = outstation.session()
        written = 1_700_000_000_000
        outstation.set_time(written)
        outstation.events.synchronized = True
        outstation.poll()
        state["on"] = True
        outstation.poll()

        response = _read(session, bytes([2, 2, ALL]))

        assert response[4:6] == bytes([2, 2]), "binary input events with absolute time"
        stamped = int.from_bytes(response[-6:], "little")
        assert stamped == written - (self.NOW - self.MEASURED)

    @pytest.mark.parametrize("quality", [Quality.COMM_LOST, Quality.NEVER_READ, Quality.OFFLINE])
    def test_non_good_reading_uses_outstation_clock(self, quality):
        """A reading that is not GOOD keeps its last measurement time, but the
        event is the quality change, so it is timestamped now."""
        state = {"quality": Quality.GOOD}
        outstation = self._outstation(
            BI, 0, lambda: Reading(True, state["quality"], timestamp_ms=self.MEASURED)
        )

        event = self._event_after(
            outstation, lambda: state.update(quality=quality), EventClass.CLASS_1
        )

        assert event.timestamp_ms == self.NOW


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


def _reported(session, event_class: int, sequence: int = 0) -> list[tuple[int, int]]:
    """The events a read of one class is answered with, as group and index."""
    response = _read(session, bytes([60, event_class + 1, ALL]), sequence=sequence)
    _, events = parse_objects(response[4:])
    return [(event.group, event.index) for event in events]


def _moved(policy, **kwargs) -> tuple[DerOutstation, Device]:
    """An outstation under a policy whose alarm, power and voltage have all changed."""
    device = Device()
    point_map = load.resolve(small(), units(0))
    outstation = DerOutstation(point_map, device.binding(), event_policy=policy, **kwargs)
    outstation.poll()
    device.alarm = True
    device.power = 1600.0
    device.voltage = 250.0
    outstation.poll()
    return outstation, device


class TestAnEventPolicy:
    """The class and deadband a deployment sets, seen from the master's side."""

    def test_without_one_the_tables_decide(self):
        outstation, _ = _moved(None)
        session = outstation.session()
        assert _reported(session, 1) == [(2, 0)]
        assert _reported(session, 2, sequence=1) == [(32, 2)]
        assert _reported(session, 3, sequence=2) == [(32, 1)]

    def test_an_empty_one_changes_nothing(self):
        outstation, _ = _moved({})
        session = outstation.session()
        assert _reported(session, 1) == [(2, 0)]
        assert _reported(session, 2, sequence=1) == [(32, 2)]
        assert _reported(session, 3, sequence=2) == [(32, 1)]

    def test_a_point_reports_in_the_class_it_is_given(self):
        outstation, _ = _moved({"points": {"AI2": {"class": 1}, "BI0": {"class": 3}}})
        session = outstation.session()
        assert _reported(session, 1) == [(32, 2)]
        assert _reported(session, 2, sequence=1) == []
        assert sorted(_reported(session, 3, sequence=2)) == [(2, 0), (32, 1)]

    def test_a_kind_reports_in_the_class_its_default_gives(self):
        outstation, _ = _moved({"defaults": {"AI": {"class": 1}}})
        session = outstation.session()
        assert sorted(_reported(session, 1)) == [(2, 0), (32, 1), (32, 2)]
        assert _reported(session, 2, sequence=1) == []
        assert _reported(session, 3, sequence=2) == []

    def test_a_point_named_is_an_exception_to_its_kinds_default(self):
        policy = {"defaults": {"AI": {"class": 1}}, "points": {"AI1": {"class": 2}}}
        outstation, _ = _moved(policy)
        session = outstation.session()
        assert sorted(_reported(session, 1)) == [(2, 0), (32, 2)]
        assert _reported(session, 2, sequence=1) == [(32, 1)]

    def test_events_turned_off_for_a_point_leave_it_static_only(self):
        outstation, _ = _moved({"points": {"BI0": {"events": False}}})
        session = outstation.session()
        assert _reported(session, 1) == []
        assert _reported(session, 2, sequence=1) == [(32, 2)], "the others still report"
        assert _values(_read(session, CLASS_0, sequence=2))[(1, 0)] == 1, "and it is still read"

    def test_events_turned_off_for_a_kind_and_back_on_for_one_point(self):
        policy = {
            "defaults": {"AI": {"events": False}},
            "points": {"AI2": {"events": True}, "AI1": {"class": 1}},
        }
        outstation, _ = _moved(policy)
        session = outstation.session()
        assert sorted(_reported(session, 1)) == [(2, 0), (32, 1)]
        assert _reported(session, 2, sequence=1) == [(32, 2)], "in the class the tables gave it"
        assert _reported(session, 3, sequence=2) == []

    def test_a_kinds_default_leaves_a_static_point_static(self):
        """What the tables give no events is given none by a rule for its whole kind."""
        device = Device()
        binding = Binding()
        binding.read(AI, 1, lambda: device.power)
        binding.read(AI, 4, lambda: device.power)
        outstation = _with_policy({"defaults": {"AI": {"class": 1}}}, binding)
        outstation.poll()
        device.power = 1600.0
        assert outstation.poll() == 1
        assert _reported(outstation.session(), 1) == [(32, 1)]

    def test_and_naming_the_point_gives_it_events(self):
        device = Device()
        binding = Binding()
        binding.read(AI, 4, lambda: device.power)
        outstation = _with_policy({"points": {"AI4": {"class": 2}}}, binding)
        outstation.poll()
        device.power = 1600.0
        outstation.poll()
        assert _reported(outstation.session(), 2) == [(32, 4)]

    def test_a_deadband_is_stated_in_engineering_units(self):
        """Two volts, at a multiplier of 0.1, is twenty counts on the wire."""
        device = Device()
        binding = Binding()
        binding.read(AI, 2, lambda: device.voltage)
        outstation = _with_policy({"points": {"AI2": {"deadband": 2.0}}}, binding)
        outstation.poll()
        device.voltage = 241.0
        assert outstation.poll() == 0, "one volt, inside a deadband of two"
        device.voltage = 243.0
        assert outstation.poll() == 1
        assert _reported(outstation.session(), 2) == [(32, 2)]

    def test_a_kinds_deadband_is_converted_by_each_points_own_scaling(self):
        device = Device()
        binding = Binding()
        binding.read(AI, 1, lambda: device.power)
        binding.read(AI, 2, lambda: device.voltage)
        outstation = _with_policy({"defaults": {"AI": {"deadband": 5}}}, binding)
        outstation.poll()
        device.power, device.voltage = 1504.0, 244.0
        assert outstation.poll() == 0, "four watts and four volts, each inside five"
        device.voltage = 246.0
        assert outstation.poll() == 1
        device.power = 1506.0
        assert outstation.poll() == 1

    def test_a_deadband_given_when_binding_still_holds_and_outranks_the_kinds(self):
        device = Device()
        binding = Binding()
        binding.read(AI, 2, lambda: device.voltage, deadband=20)
        outstation = _with_policy({"defaults": {"AI": {"deadband": 0.5}}}, binding)
        outstation.poll()
        device.voltage = 241.0
        assert outstation.poll() == 0, "ten counts, inside the twenty the binding gave"
        device.voltage = 243.0
        assert outstation.poll() == 1

    def test_and_a_deadband_for_the_point_by_name_outranks_the_bindings(self):
        device = Device()
        binding = Binding()
        binding.read(AI, 2, lambda: device.voltage, deadband=20)
        outstation = _with_policy({"points": {"AI2": {"deadband": 0.5}}}, binding)
        outstation.poll()
        device.voltage = 241.0
        assert outstation.poll() == 1, "ten counts, past the five the policy gave"

    def test_a_change_of_quality_is_reported_whatever_the_deadband(self):
        quality = [Quality.GOOD]
        binding = Binding()
        binding.read(AI, 2, lambda: Reading(240.0, quality[0]))
        outstation = _with_policy({"points": {"AI2": {"deadband": 100.0}}}, binding)
        outstation.poll()
        quality[0] = Quality.COMM_LOST
        assert outstation.poll() == 1

    def test_a_counters_class_is_the_one_its_freezes_are_logged_in(self):
        outstation, _ = _built(event_policy={"points": {"CTR0": {"class": 1}}})
        session = outstation.session()
        outstation.freeze_all()
        assert _reported(session, 1) == [(23, 0)]
        assert _reported(session, 3, sequence=1) == [(23, 1)]

    def test_a_counter_with_events_off_freezes_and_logs_nothing(self):
        outstation, _ = _built(event_policy={"points": {"CTR1": {"events": False}}})
        session = outstation.session()
        outstation.freeze_all()
        assert _reported(session, 3) == [(23, 0)]
        values = _values(_read(session, CLASS_0, sequence=1))
        assert values[(21, 0)] == 10 and values[(21, 1)] == 20, "both are frozen all the same"

    def test_a_control_reports_its_mirror_in_the_class_the_policy_gives(self):
        outstation, _ = _built(event_policy={"points": {"AI3": {"class": 1}}})
        session = outstation.session()
        outstation.poll()
        response = session._handle_fragment(
            _control(FunctionCode.DIRECT_OPERATE, _analog_command(0, 125), 0)
        )
        assert response[2] & IINBit.CLASS_1_EVENTS
        assert not response[2] & IINBit.CLASS_2_EVENTS

    def test_the_plain_form_and_the_dataclasses_are_one_policy(self):
        plain = EventPolicy.from_mapping(
            {
                "defaults": {"AI": {"class": 2, "deadband": 0.5}, "BI": {"events": False}},
                "points": {"AI2": {"class": 1}, "ctr0": {"class": 2}},
            }
        )
        assert plain == EventPolicy(
            defaults={
                AI: EventRule(event_class=2, deadband=0.5),
                BI: EventRule(events=False),
            },
            points={(AI, 2): EventRule(event_class=1), (CTR, 0): EventRule(event_class=2)},
        )

    def test_the_builder_takes_either(self):
        policy = EventPolicy(points={(AI, 2): EventRule(event_class=1)})
        outstation, _ = _moved(policy)
        assert sorted(_reported(outstation.session(), 1)) == [(2, 0), (32, 2)]

    def test_the_outstation_says_what_is_in_force(self):
        policy = {"defaults": {"BI": {"events": False}}, "points": {"AI2": {"deadband": 2.0}}}
        outstation = _with_policy(policy)
        assert outstation.event_class(BI, 0) == 0
        assert outstation.event_class(AI, 2) == 2
        assert outstation.event_class(AI, 4) == 0, "the tables gave it none"
        assert outstation.event_class(CTR, 0) == 3
        assert outstation.event_class(AO, 0) == 0
        assert outstation.deadband(2) == 20
        assert outstation.deadband(1) == 0


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


def _partial(*extra: tuple[Kind, int], **kwargs) -> DerOutstation:
    """A monitor of the two mandatory points, and whatever else is named."""
    binding = Binding()
    binding.read(BI, 0, lambda: False)
    binding.read(AI, 1, lambda: 1500.0)
    for kind, index in extra:
        if kind.is_output:
            binding.output(kind, index, initial=0)
        else:
            binding.read(kind, index, lambda: 240.0)
    return DerOutstation(load.resolve(small(), units(0)), binding, strict=False, **kwargs)


#: A line of the report's text that is about one point.
_POINT_LINE = re.compile(r"(AI|AO|BI|BO|CTR)\d+ ")


def _sources(report) -> dict[tuple[Kind, int], Source]:
    return {entry.point.address: entry.source for entry in report.entries}


class TestTheCoverageReport:
    """What a built outstation says about how much of the profile it serves."""

    def test_a_value_with_no_number_is_reported_offline_as_the_wire_has_it(self):
        """A source can be good and hand over NaN, which goes out with ONLINE clear."""
        point_map = load.resolve(small(), units(0))
        binding = Binding()
        binding.read(AI, 1, lambda: float("nan"))
        binding.read(AI, 2, lambda: 240.0)
        outstation = DerOutstation(point_map, binding, strict=False)
        report = outstation.coverage()
        nan, fine = report.entry(AI, 1), report.entry(AI, 2)
        assert nan.quality is Quality.GOOD, "the source said nothing was wrong"
        assert not nan.online and nan in report.offline
        assert fine.online and fine not in report.offline
        flags = _flags(_read(outstation.session(), bytes([30, 1, 0x00, 1, 2])))
        assert not flags[(30, 1)] & 0x01 and flags[(30, 2)] & 0x01, "and the wire agrees"

    def test_so_is_an_output_whose_status_has_no_number(self):
        point_map = load.resolve(small(), units(0))
        binding = Binding()
        binding.output(AO, 0, status=lambda: float("nan"))
        outstation = DerOutstation(point_map, binding, strict=False)
        entry = outstation.coverage().entry(AO, 0)
        assert entry.quality is Quality.GOOD and not entry.online
        flags = _flags(_read(outstation.session(), bytes([40, 0, ALL])))
        assert not flags[(40, 0)] & 0x01

    def test_every_point_of_the_map_is_in_it_once(self):
        outstation, _ = _built()
        addresses = [entry.point.address for entry in outstation.coverage().entries]
        assert sorted(addresses) == sorted(outstation.point_map.points)
        assert len(addresses) == len(set(addresses))

    def test_each_point_is_put_down_to_where_its_value_comes_from(self):
        outstation, _ = _built()
        sources = _sources(outstation.coverage())
        assert sources[(AI, 1)] is Source.BOUND
        assert sources[(AO, 0)] is Source.BOUND
        assert sources[(AI, 3)] is Source.MIRROR, "it reads back the bound AO0"
        assert sources[(BI, 2)] is Source.MIRROR
        assert sources[(BI, 1)] is Source.SUPPORTS
        assert sources[(AI, 0)] is Source.FIXED
        assert sources[(AI, 65000)] is Source.FIXED
        assert sources[(BI, 9)] is Source.ABSENT
        assert sources[(BO, 1)] is Source.ABSENT

    def test_a_reader_wins_over_the_output_an_input_would_mirror(self):
        outstation = _partial((AO, 0), (AI, 3))
        assert _sources(outstation.coverage())[(AI, 3)] is Source.BOUND

    @pytest.mark.parametrize("kind", list(Kind))
    def test_what_it_calls_served_is_what_the_outstation_serves(self, kind):
        """The report is read from the builder's own resolution, not worked out again."""
        outstation, _ = _built()
        served = [e.point for e in outstation.coverage().served if e.point.kind is kind]
        assert served == outstation.served(kind)

    def test_mandatory_points_are_told_apart_from_optional_ones(self):
        point_map = load.resolve(small(), units(0))
        report = DerOutstation(point_map, Binding(), strict=False).coverage()
        assert [entry.point.address for entry in report.missing] == [(BI, 0), (AI, 1)]
        assert not report.conformant
        absent_optional = [e for e in report.absent if not e.point.mandatory]
        assert absent_optional, "optional points are absent too, and are not what is missing"
        assert _partial().coverage().missing == ()
        assert _partial().coverage().conformant

    @pytest.mark.parametrize("bound", [[], [(BI, 0)], [(AI, 1)], [(BI, 0), (AI, 1)]])
    def test_conformant_is_what_a_strict_build_accepts(self, bound):
        point_map = load.resolve(small(), units(0))

        def binding() -> Binding:
            made = Binding()
            for kind, index in bound:
                made.read(kind, index, lambda: 0)
            return made

        report = DerOutstation(point_map, binding(), strict=False).coverage()
        if report.conformant:
            DerOutstation(point_map, binding())
        else:
            with pytest.raises(MapError, match="mandatory"):
                DerOutstation(point_map, binding())

    def test_a_served_point_whose_source_is_not_good_is_offline(self):
        point_map = load.resolve(small(), units(0))
        binding = Binding()
        binding.read(AI, 1, lambda: 1.0)
        binding.read(AI, 2, lambda: Reading(240.0, Quality.COMM_LOST))
        binding.read(AI, 4, lambda: Reading(0.0, Quality.OFFLINE))
        binding.output(AO, 0)
        report = DerOutstation(point_map, binding, strict=False).coverage()
        offline = {entry.point.address: entry.quality for entry in report.offline}
        assert offline == {
            (AI, 2): Quality.COMM_LOST,
            (AI, 4): Quality.OFFLINE,
            (AI, 3): Quality.NEVER_READ,
            (AO, 0): Quality.NEVER_READ,
        }, "an output never written, and the input that mirrors it, have nothing to report"
        assert report.entry(AI, 1).quality is Quality.GOOD
        assert report.entry(AI, 1).online
        assert all(entry.served for entry in report.offline)

    def test_an_absent_point_has_no_quality_and_is_not_offline(self):
        report = _partial().coverage()
        lone = report.entry(BI, 9)
        assert lone.quality is None and not lone.served and not lone.online
        assert lone not in report.offline

    def test_offline_is_how_the_point_stood_when_the_report_was_made(self):
        device = {"reachable": False}

        def voltage() -> Reading:
            return Reading(240.0, Quality.GOOD if device["reachable"] else Quality.COMM_LOST)

        binding = Binding()
        binding.read(AI, 2, voltage)
        outstation = DerOutstation(load.resolve(small(), units(0)), binding, strict=False)
        before = outstation.coverage()
        device["reachable"] = True
        after = outstation.coverage()
        assert before.entry(AI, 2).quality is Quality.COMM_LOST
        assert after.entry(AI, 2).quality is Quality.GOOD
        assert before.entry(AI, 2).source is after.entry(AI, 2).source is Source.BOUND

    def test_a_source_that_raises_is_reported_and_does_not_stop_the_report(self):
        def broken() -> float:
            raise OSError("unreachable")

        binding = Binding()
        binding.read(AI, 2, broken)
        outstation = DerOutstation(load.resolve(small(), units(0)), binding, strict=False)
        assert outstation.coverage().entry(AI, 2).quality is Quality.COMM_LOST

    def test_the_inputs_of_a_disabled_function_are_offline(self):
        tables = document(
            {
                "BO": [row("Enable Gadget", 0, purpose="Gadget", associated="BI0")],
                "BI": [
                    row("Gadget enabled", 0, event_class=1, purpose="Gadget", associated="BO0"),
                    row("Supports Gadget", 1, event_class=0, purpose="Gadget"),
                ],
                "AI": [analog("Gadget output", 0, event_class=2, purpose="Gadget")],
            }
        )
        binding = Binding()
        binding.output(BO, 0, initial=False)
        binding.read(AI, 0, lambda: 42.0)
        outstation = DerOutstation(load.resolve(tables, units(0)), binding)
        report = outstation.coverage()
        assert [entry.point.address for entry in report.offline] == [(AI, 0)]
        assert report.entry(AI, 0).quality is Quality.OFFLINE
        latch_on = ControlRelayOutputBlock.build(OperationType.LATCH_ON)
        assert _operate(outstation.session(), _crob(0, latch_on)) is CommandStatus.SUCCESS
        assert outstation.coverage().offline == ()

    def test_taking_the_report_changes_nothing_a_master_sees(self):
        outstation, device = _built()
        session = outstation.session()
        outstation.poll()
        before = _read(session, CLASS_0)
        device.power = 1600.0
        outstation.coverage()
        assert outstation.events.total == 0, "a report is not a poll: it buffers no event"
        device.power = 1500.0
        assert _read(session, CLASS_0, sequence=1)[2:] == before[2:]
        assert device.applied == []

    def test_its_text_has_one_line_for_each_point(self):
        report = _partial().coverage()
        text = report.render()
        assert str(report) == text
        lines = text.splitlines()
        for entry in report.entries:
            address = f"{entry.point.kind.value}{entry.point.index}"
            (line,) = [line for line in lines if line.split()[:1] == [address]]
            assert entry.source.value in line and entry.point.name in line
        (power,) = [line for line in lines if line.startswith("AI1 ")]
        (lone,) = [line for line in lines if line.startswith("BI9 ")]
        assert " M " in power and " M " not in lone

    def test_its_text_says_how_far_the_map_is_from_a_conformant_one(self):
        point_map = load.resolve(small(), units(0))
        short = DerOutstation(point_map, Binding(), strict=False).coverage().render()
        assert "0 of 2 mandatory" in short
        assert "BI0, AI1" in short, "the mandatory points still to bind are named"
        whole = _partial().coverage().render()
        assert "2 of 2 mandatory" in whole
        assert "BI0, AI1" not in whole and "not conformant" not in whole


class TestAPartialMapThatGrows:
    """Adding a binding entry is the whole of the change."""

    def test_one_more_reader_moves_exactly_that_point(self):
        before = _partial().coverage()
        after = _partial((AI, 2)).coverage()
        changed = after.changed_since(before)
        assert [entry.point.address for entry in changed] == [(AI, 2)]
        assert before.entry(AI, 2).source is Source.ABSENT
        assert changed[0].source is Source.BOUND
        assert len(after.served) == len(before.served) + 1
        assert len(after.absent) == len(before.absent) - 1

    def test_and_exactly_that_line_of_the_text(self):
        before = _partial().coverage().render().splitlines()
        after = _partial((AI, 2)).coverage().render().splitlines()
        moved = [line for line in set(before) ^ set(after) if _POINT_LINE.match(line)]
        assert sorted(line.split()[1] for line in moved) == ["absent", "bound"]
        assert {line.split()[0] for line in moved} == {"AI2"}

    def test_and_the_point_is_on_the_wire(self):
        assert (30, 2) not in _values(_read(_partial().session(), CLASS_0))
        grown = _partial((AI, 2)).session()
        assert _values(_read(grown, CLASS_0))[(30, 2)] == 2400
        assert _values(_read(grown, bytes([30, 0, 0x00, 2, 2]), sequence=1)) == {(30, 2): 2400}

    def test_and_nothing_else_on_the_wire_moves(self):
        before = _values(_read(_partial().session(), CLASS_0))
        after = _values(_read(_partial((AI, 2)).session(), CLASS_0))
        assert {key: value for key, value in after.items() if key != (30, 2)} == before

    def test_two_builds_of_one_binding_report_alike(self):
        assert _partial((AI, 2)).coverage() == _partial((AI, 2)).coverage()
        assert _partial((AI, 2)).coverage().changed_since(_partial((AI, 2)).coverage()) == ()

    def test_an_output_brings_the_input_that_reads_it_back(self):
        """One entry may serve more than one point, and the report says which."""
        before = _partial().coverage()
        after = _partial((AO, 0)).coverage()
        changed = {e.point.address: e.source for e in after.changed_since(before)}
        assert changed == {(AO, 0): Source.BOUND, (AI, 3): Source.MIRROR}

    def test_growing_to_the_last_mandatory_point_is_what_makes_it_conformant(self):
        binding = Binding()
        binding.read(BI, 0, lambda: False)
        point_map = load.resolve(small(), units(0))
        short = DerOutstation(point_map, binding, strict=False).coverage()
        assert [entry.point.address for entry in short.missing] == [(AI, 1)]
        binding.read(AI, 1, lambda: 0.0)
        assert DerOutstation(point_map, binding).coverage().conformant


class TestUnsolicitedResponses:
    """The profile's consumers expect outstation-initiated reporting. The
    builder passes the option through and changes nothing else for it."""

    def test_they_are_off_unless_named(self):
        outstation, _ = _built()
        assert outstation.session().facts.unsolicited is False

    def test_the_option_passes_through_with_its_settings(self):
        outstation, _ = _built()
        facts = outstation.session(
            unsolicited=True, unsolicited_confirm_timeout=3.0, unsolicited_retries=2
        ).facts
        assert facts.unsolicited is True
        assert facts.unsolicited_confirm_timeout == 3.0
        assert facts.unsolicited_retries == 2

    def test_what_poll_buffers_is_reported_once_a_master_enables_its_class(self):
        clock = [1000.0]
        outstation, device = _built()
        outstation.poll()
        session = outstation.session(unsolicited=True, clock=lambda: clock[0])
        null = _initiated(session)
        session._handle_fragment(bytes([0xD0 | (null[0] & 0x0F), FunctionCode.CONFIRM]))
        enabled = session._handle_fragment(
            bytes([0xC1, FunctionCode.ENABLE_UNSOLICITED, 60, 2, ALL, 60, 3, ALL, 60, 4, ALL])
        )
        assert enabled[3] == 0

        device.power = 2500.0
        outstation.poll()
        fragment = _initiated(session)

        assert fragment[1] == FunctionCode.UNSOLICITED_RESPONSE
        _, events = parse_objects(fragment[4:])
        assert [(event.group, event.index) for event in events] == [(32, 1)]


def _initiated(session) -> bytes:
    """The one fragment the session sends unasked."""
    found, reassembler = [], Reassembler()
    for frame in link.FrameReader().feed(session.initiate()):
        whole = reassembler.add(frame.payload)
        if whole is not None:
            found.append(whole)
    (fragment,) = found
    return fragment
