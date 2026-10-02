"""IED certification procedures, sections 8.13 to 8.26: reads of specific objects.

Binary inputs and their events, counters and frozen counters, analog inputs
and their events, requests for several objects at once, point ranges, specific
variations, and class assignment. The device is tested as a subset level 2
outstation; where the procedures let a level 2 device either do what level 3
requires or refuse it, the tests say which this one does.
"""

from __future__ import annotations

import itertools

import pytest
from ied_harness import (
    ASSIGN_CLASS,
    DEADBAND,
    ERROR_IIN,
    FLAG_ONLINE,
    FREEZE,
    FREEZE_CLEAR,
    FREEZE_CLEAR_NR,
    FREEZE_NR,
    IIN2_BAD_FUNCTION,
    IIN2_OBJECT_UNKNOWN,
    IIN2_PARAMETER,
    Q_COUNT_8,
    Q_COUNT_16,
    Q_INDEX_8,
    Q_INDEX_16,
    Q_RANGE_8,
    Q_RANGE_16,
    Dut,
    classes,
    header,
)

from py1815.profile.binding import Quality
from py1815.profile.model import Kind

RANGES = {Q_RANGE_8, Q_RANGE_16}
INDEXED = {Q_INDEX_8, Q_INDEX_16}
NO_POINTS = IIN2_OBJECT_UNKNOWN | IIN2_PARAMETER
COUNTS = pytest.mark.parametrize("qualifier", [Q_COUNT_8, Q_COUNT_16], ids=["07", "08"])


def _toggles(dut: Dut, indices: list[int]) -> list[int]:
    for index in indices:
        dut.toggle(index)
    return indices


class TestBinaryInputs:
    def test_8_13_2_2_a_device_with_no_binary_inputs(self):
        dut = Dut(binary_inputs=False)
        fragment = dut.master.read(header(1, 0)).fragment
        assert not fragment.body and fragment.iin2 & NO_POINTS

    def test_8_13_2_3_binary_inputs_report_the_pattern_applied(self):
        dut = Dut()
        dut.toggle(1)
        dut.toggle(3)
        fragment = dut.master.read(header(1, 0)).fragment
        objects = fragment.of(1)
        assert {o.variation for o in objects} <= {1, 2}
        assert {o.qualifier for o in objects} <= RANGES
        assert [o.state for o in objects] == [False, True, False, True]
        assert all(o.flags & 0x7F == FLAG_ONLINE for o in objects)
        dut.toggle(0)
        dut.toggle(1)
        again = dut.master.read(header(1, 0)).fragment.of(1)
        assert [o.state for o in again] == [True, False, False, True]

    def test_8_13_2_4_no_binary_inputs_installed(self):
        """The same answer as 8.13.2.2: the device has the type and no points of it."""
        dut = Dut(binary_inputs=False)
        assert dut.master.read(header(1, 0)).fragment.iin2 & NO_POINTS


class TestBinaryInputChanges:
    def test_8_14_2_3_all_events_with_qualifier_06(self):
        dut = Dut()
        assert dut.master.read(header(2, 0)).fragment.is_null
        made = _toggles(dut, [0, 2, 3, 0])
        fragment = dut.master.read(header(2, 0)).fragment
        events = fragment.of(2)
        assert [o.index for o in events] == made, "every one, in the order they happened"
        assert {o.qualifier for o in events} <= INDEXED
        assert all(o.flags & 0x7F == FLAG_ONLINE for o in events)
        assert fragment.con
        dut.master.confirm(fragment)
        assert dut.master.read(header(2, 0)).fragment.is_null

    @COUNTS
    def test_8_14_2_4_and_5_a_limited_quantity(self, qualifier):
        dut = Dut()
        dut.master.empty_events()
        made = _toggles(dut, [0, 1, 2, 3, 0])
        some = dut.master.read(header(2, 0, qualifier, 3)).fragment
        assert [o.index for o in some.of(2)] == made[:3]
        assert some.con and {o.qualifier for o in some.objects} <= INDEXED
        dut.master.confirm(some)
        rest = dut.master.read(header(2, 0, qualifier, 10)).fragment
        assert [o.index for o in rest.of(2)] == made[3:]
        assert rest.con
        dut.master.confirm(rest)
        assert dut.master.read(header(2, 0)).fragment.is_null

    def test_8_14_2_6_events_read_and_not_confirmed(self):
        dut = Dut()
        dut.master.empty_events()
        first = _toggles(dut, [0, 2])
        one = dut.master.read(header(2, 0), sequence=4).fragment
        assert [o.index for o in one.of(2)] == first and one.con
        dut.clock.advance(30.0)
        assert dut.master.raw(b"").silent, "no retransmission"
        two = dut.master.read(header(2, 0), sequence=5).fragment
        assert two.sequence == 5
        assert two.body == one.body, "the same application data under the new sequence number"
        dut.clock.advance(30.0)
        assert dut.master.raw(b"").silent
        more = _toggles(dut, [3])
        three = dut.master.read(header(2, 0)).fragment
        assert [o.index for o in three.of(2)] == first + more
        times = [o.time for o in three.of(2)]
        assert times == sorted(times)
        assert three.con
        dut.master.confirm(three)
        assert dut.master.read(header(2, 0)).fragment.is_null

    def test_8_14_2_7_without_time_qualifier_06(self):
        dut = Dut()
        dut.master.empty_events()
        made = _toggles(dut, [1, 2, 1])
        fragment = dut.master.read(header(2, 1)).fragment
        events = fragment.objects
        assert {(o.group, o.variation) for o in events} == {(2, 1)}, "only the variation asked for"
        assert [o.index for o in events] == made
        assert {o.qualifier for o in events} <= INDEXED
        assert fragment.con
        dut.master.confirm(fragment)
        assert dut.master.read(header(2, 0)).fragment.is_null

    @COUNTS
    def test_8_14_2_8_and_9_without_time_a_limited_quantity(self, qualifier):
        dut = Dut()
        dut.master.empty_events()
        made = _toggles(dut, [0, 1, 2, 3])
        some = dut.master.read(header(2, 1, qualifier, 2)).fragment
        assert {(o.group, o.variation) for o in some.objects} == {(2, 1)}
        assert [o.index for o in some.objects] == made[:2]
        assert some.con
        dut.master.confirm(some)
        rest = dut.master.read(header(2, 1, qualifier, 10)).fragment
        assert [o.index for o in rest.objects] == made[2:]
        dut.master.confirm(rest)
        assert dut.master.read(header(2, 0)).fragment.is_null

    def test_8_14_2_10_with_time_qualifier_06(self):
        dut = Dut()
        dut.master.empty_events()
        made = []
        for index in (0, 3, 2):
            dut.clock.advance(1.0)
            dut.toggle(index)
            made.append(index)
        fragment = dut.master.read(header(2, 2)).fragment
        events = fragment.objects
        assert {(o.group, o.variation) for o in events} == {(2, 2)}
        assert [o.index for o in events] == made
        assert {o.qualifier for o in events} <= INDEXED
        times = [o.time for o in events]
        gaps = [later - earlier for earlier, later in itertools.pairwise(times)]
        assert all(990 <= gap <= 1030 for gap in gaps), "about a second apart, as generated"
        assert fragment.con
        dut.master.confirm(fragment)
        assert dut.master.read(header(2, 0)).fragment.is_null

    @COUNTS
    def test_8_14_2_11_and_12_with_time_a_limited_quantity(self, qualifier):
        dut = Dut()
        dut.master.empty_events()
        made = _toggles(dut, [0, 1, 2, 3])
        some = dut.master.read(header(2, 2, qualifier, 3)).fragment
        assert {(o.group, o.variation) for o in some.objects} == {(2, 2)}
        assert [o.index for o in some.objects] == made[:3]
        dut.master.confirm(some)
        rest = dut.master.read(header(2, 2, qualifier, 10)).fragment
        assert [o.index for o in rest.objects] == made[3:]
        dut.master.confirm(rest)
        assert dut.master.read(header(2, 0)).fragment.is_null

    @pytest.mark.parametrize(
        "request_header",
        [
            pytest.param(header(2, 3), id="8_14_2_13_qualifier_06"),
            pytest.param(header(2, 3, Q_COUNT_8, 2), id="8_14_2_14_qualifier_07"),
            pytest.param(header(2, 3, Q_COUNT_16, 2), id="8_14_2_15_qualifier_08"),
        ],
    )
    def test_8_14_2_13_to_15_relative_time_is_not_supported(self, request_header):
        """Refused as an unknown object, which the procedure accepts and notes."""
        dut = Dut()
        dut.master.empty_events()
        _toggles(dut, [0, 1])
        fragment = dut.master.read(request_header).fragment
        assert not fragment.body
        assert fragment.iin2 & IIN2_OBJECT_UNKNOWN
        # The events were not consumed by the refusal.
        assert len(dut.master.read(header(2, 0)).fragment.of(2)) == 2

    def test_8_15_2_a_read_for_relative_time_returns_no_relative_time_objects(self):
        dut = Dut()
        dut.toggle(0)
        fragment = dut.master.read(header(2, 3)).fragment
        assert not any(
            (o.group, o.variation) in {(2, 3), (51, 1), (51, 2)} for o in fragment.objects
        )


class TestBinaryCounters:
    def test_8_16_1_2_2_a_device_with_no_counters(self):
        dut = Dut(counters=False)
        fragment = dut.master.read(header(20, 0)).fragment
        assert not fragment.body and fragment.iin2 & NO_POINTS

    def test_8_16_1_2_3_running_counters(self):
        dut = Dut()
        before = dut.master.read(header(20, 0)).fragment.of(20)
        assert {o.variation for o in before} <= {1, 2, 5, 6}
        assert {o.qualifier for o in before} <= RANGES
        assert all(o.flags in (None, FLAG_ONLINE) for o in before)
        dut.count(7)
        after = dut.master.read(header(20, 0)).fragment.of(20)
        assert [o.value for o in after] == [o.value + 7 for o in before]

    def test_8_16_1_2_4_no_counters_installed(self):
        dut = Dut(counters=False)
        assert dut.master.read(header(20, 0)).fragment.iin2 & NO_POINTS


class TestFrozenCounters:
    def _frozen(self, dut: Dut) -> list[int]:
        fragment = dut.master.read(header(21, 0)).fragment
        objects = fragment.of(21)
        assert {o.variation for o in objects} <= {1, 2, 9, 10}
        assert {o.qualifier for o in objects} <= RANGES
        assert all(o.flags in (None, FLAG_ONLINE) for o in objects)
        return [o.value for o in objects]

    def test_8_16_2_2_2_a_device_with_no_frozen_counters(self):
        dut = Dut(counters=False)
        fragment = dut.master.read(header(21, 0)).fragment
        assert not fragment.body and fragment.iin2 & NO_POINTS

    @pytest.mark.parametrize(
        ("function", "answered"),
        [
            pytest.param(FREEZE, True, id="8_16_2_2_3_freeze"),
            pytest.param(FREEZE_NR, False, id="8_16_2_2_5_freeze_no_acknowledge"),
        ],
    )
    def test_8_16_2_2_3_and_5_freeze(self, function, answered):
        dut = Dut()

        def freeze() -> None:
            reply = dut.master.request(function, header(20, 0))
            if answered:
                assert reply.fragment.is_null
            else:
                assert reply.silent

        freeze()
        recorded = self._frozen(dut)
        assert recorded == [5, 5, 5]
        dut.count(4)
        assert self._frozen(dut) == recorded, "frozen values move only on a freeze"
        freeze()
        assert self._frozen(dut) == [value + 4 for value in recorded]

    @pytest.mark.parametrize(
        ("function", "answered"),
        [
            pytest.param(FREEZE_CLEAR, True, id="8_16_2_2_4_freeze_and_clear"),
            pytest.param(FREEZE_CLEAR_NR, False, id="8_16_2_2_6_freeze_and_clear_no_acknowledge"),
        ],
    )
    def test_8_16_2_2_4_and_6_freeze_and_clear(self, function, answered):
        dut = Dut()
        dut.count(6)

        def freeze() -> None:
            reply = dut.master.request(function, header(20, 0))
            if answered:
                assert reply.fragment.is_null
            else:
                assert reply.silent

        freeze()
        assert self._frozen(dut) == [11, 11, 11], "non-zero"
        running = [o.value for o in dut.master.read(header(20, 0)).fragment.of(20)]
        assert running == [0, 0, 0], "and the running counters were cleared"
        freeze()
        assert self._frozen(dut) == [0, 0, 0], "nothing was counted since"

    def test_8_16_2_1_a_level_2_freeze_generates_no_frozen_counter_events(self):
        dut = Dut()
        dut.master.empty_events()
        dut.master.request(FREEZE, header(20, 0))
        assert dut.master.read(classes(1, 2, 3)).fragment.is_null
        assert dut.master.read(header(23, 0)).fragment.is_null

    def test_8_16_2_2_3_with_frozen_counter_events_enabled(self):
        """The branch for a device that supports frozen counter events, as the DER profile does."""
        dut = Dut(level2=False)
        dut.master.empty_events()
        assert dut.master.request(FREEZE, header(20, 0)).fragment.is_null
        fragment = dut.master.read(header(23, 0), header(21, 0)).fragment
        objects = fragment.objects
        events = [o for o in objects if o.group == 23]
        static = [o for o in objects if o.group == 21]
        assert objects == events + static, "events first, then the frozen counters"
        assert [(o.index, o.value) for o in events] == [(o.index, o.value) for o in static]
        assert fragment.con
        dut.master.confirm(fragment)
        # A second freeze makes events again, though nothing was counted.
        dut.master.request(FREEZE, header(20, 0))
        assert len(dut.master.read(header(23, 0)).fragment.of(23)) == 3


class TestBinaryCounterEvents:
    def test_8_17_2_2_counter_change_events_are_not_supported(self):
        dut = Dut()
        dut.count(5)
        dut.outstation.poll()
        fragment = dut.master.read(header(22, 0)).fragment
        assert fragment.is_null


class TestAnalogInputs:
    def test_8_18_2_2_a_device_with_no_analog_inputs(self):
        dut = Dut(analog_inputs=False)
        fragment = dut.master.read(header(30, 0)).fragment
        assert not fragment.body and fragment.iin2 & NO_POINTS

    def test_8_18_2_3_analog_inputs_report_the_values_applied(self):
        dut = Dut()
        for index, value in enumerate((250, -75, 31000, 0)):
            dut.set_analog(index, value)
        objects = dut.master.read(header(30, 0)).fragment.of(30)
        assert {o.variation for o in objects} <= {1, 2, 3, 4}
        assert {o.qualifier for o in objects} <= RANGES
        assert [o.value for o in objects] == [250, -75, 31000, 0]


class TestAnalogChangeEvents:
    def test_8_19_2_2_analog_input_change(self):
        dut = Dut()
        dut.master.empty_events()
        assert dut.master.read(header(32, 0)).fragment.is_null
        dut.set_analog(0, 500)
        fragment = dut.master.read(header(32, 0)).fragment
        (event,) = fragment.objects
        assert (event.group, event.variation) in {(32, 1), (32, 2)}
        assert (event.index, event.value) == (0, 500)
        assert event.qualifier in INDEXED and event.flags == FLAG_ONLINE
        assert fragment.con
        dut.master.confirm(fragment)
        assert dut.master.read(header(32, 0)).fragment.is_null
        dut.set_analog(0, 500 + 3 * DEADBAND)
        (moved,) = dut.master.read(header(32, 0)).fragment.objects
        assert moved.value == 500 + 3 * DEADBAND

    def test_8_19_1_a_change_inside_the_deadband_is_not_an_event(self):
        dut = Dut()
        dut.master.empty_events()
        dut.set_analog(0, 100 + DEADBAND - 1)
        assert dut.master.read(header(32, 0)).fragment.is_null

    def test_8_19_2_3_analog_change_read_and_not_confirmed(self):
        dut = Dut()
        dut.master.empty_events()
        dut.set_analog(0, 500)
        first = dut.master.read(header(32, 0)).fragment
        assert [o.value for o in first.objects] == [500] and first.con
        dut.clock.advance(30.0)
        assert dut.master.raw(b"").silent
        dut.set_analog(0, 900)
        second = dut.master.read(header(32, 0)).fragment
        assert [o.value for o in second.objects][-1] == 900, "the current value, last"
        assert len(second.objects) in (1, 2)
        assert second.con
        dut.master.confirm(second)
        assert dut.master.read(header(32, 0)).fragment.is_null

    def test_8_19_2_4_a_value_that_goes_and_comes_back(self):
        dut = Dut()
        dut.master.empty_events()
        start = dut.master.read(header(30, 0)).fragment.of(30)[0].value
        dut.set_analog(0, start + 1.5 * DEADBAND)
        gone = dut.master.read(header(32, 0)).fragment
        assert [o.value for o in gone.objects] == [start + 1.5 * DEADBAND]
        assert gone.con
        # Not confirmed; the input returns to where it began.
        dut.set_analog(0, start)
        back = dut.master.read(header(32, 0)).fragment
        assert len(back.objects) == 1, "most recent only, as the device profile states"
        assert back.objects[-1].value == start
        dut.master.confirm(back)
        assert dut.master.read(header(32, 0)).fragment.is_null


class TestMultipleReadRequests:
    def test_8_20_2_2_one_of_every_object_in_a_single_request(self):
        dut = Dut()
        dut.master.empty_events()
        dut.master.request(FREEZE, header(20, 0))
        dut.toggle(0)
        dut.step(1)
        events = [header(2, 0), header(22, 0), header(23, 0), header(32, 0)]
        static = [header(g, 0) for g in (1, 10, 20, 21, 30, 40)]
        fragment = dut.master.read(*events, *static).fragment
        assert not fragment.iin2 & ERROR_IIN
        objects = fragment.objects
        groups = [o.group for o in objects]
        last_event = max(i for i, g in enumerate(groups) if g in (2, 32))
        first_static = min(i for i, g in enumerate(groups) if g not in (2, 32))
        assert last_event < first_static, "event data before static data"
        assert set(groups) == {2, 32, 1, 10, 20, 21, 30, 40}
        assert fragment.con


class TestDoubleBitInputs:
    def test_8_21_1_double_bit_inputs_are_not_supported(self):
        dut = Dut()
        fragment = dut.master.read(header(3, 0)).fragment
        assert not fragment.body and fragment.iin2 & NO_POINTS

    def test_8_22_1_double_bit_input_changes_are_not_supported(self):
        dut = Dut()
        fragment = dut.master.read(header(4, 0)).fragment
        assert not fragment.body
        assert not fragment.iin2 & IIN2_BAD_FUNCTION


#: Each static group, the kind of point it reports, and how many the device has.
RANGED = [
    pytest.param(1, 4, {"binary_inputs": False}, id="8_23_2_1_binary_inputs"),
    pytest.param(10, 4, {"binary_outputs": False}, id="8_23_2_2_binary_output_status"),
    pytest.param(20, 3, {"counters": False}, id="8_23_2_3_counters"),
    pytest.param(21, 3, {"counters": False}, id="8_23_2_4_frozen_counters"),
    pytest.param(30, 4, {"analog_inputs": False}, id="8_23_2_5_analog_inputs"),
    pytest.param(40, 4, {"analog_outputs": False}, id="8_23_2_6_analog_output_status"),
]


class TestSpecificPointRanges:
    @pytest.mark.parametrize(("group", "count", "without"), RANGED)
    @pytest.mark.parametrize("qualifier", [Q_RANGE_8, Q_RANGE_16], ids=["00", "01"])
    def test_8_23_2_x_1_a_device_without_the_point_type(self, group, count, without, qualifier):
        dut = Dut(**without)
        fragment = dut.master.read(header(group, 0, qualifier, 0, 0)).fragment
        assert not fragment.body and fragment.is_error

    @pytest.mark.parametrize(("group", "count", "without"), RANGED)
    @pytest.mark.parametrize("qualifier", [Q_RANGE_8, Q_RANGE_16], ids=["00", "01"])
    def test_8_23_2_x_2_a_valid_range_returns_those_points_and_no_others(
        self, group, count, without, qualifier
    ):
        dut = Dut()
        dut.master.request(FREEZE, header(20, 0))
        fragment = dut.master.read(header(group, 0, qualifier, 1, 2)).fragment
        objects = fragment.objects
        assert [(o.group, o.index) for o in objects] == [(group, 1), (group, 2)]
        assert {o.qualifier for o in objects} <= RANGES
        assert not fragment.is_error

    @pytest.mark.parametrize(("group", "count", "without"), RANGED)
    def test_8_23_2_x_3_a_range_running_past_the_last_point(self, group, count, without):
        dut = Dut()
        dut.master.request(FREEZE, header(20, 0))
        fragment = dut.master.read(header(group, 0, Q_RANGE_8, count - 1, count)).fragment
        assert fragment.iin2 & IIN2_PARAMETER
        assert not fragment.iin2 & IIN2_OBJECT_UNKNOWN


class TestSpecificStaticVariations:
    """Section 8.24. A level 2 device may answer as level 3 does, or refuse."""

    def _refused(self, fragment) -> bool:
        return not fragment.body and bool(fragment.iin2 & NO_POINTS)

    def test_8_24_2_1_binary_inputs(self):
        dut = Dut()
        assert self._refused(dut.master.read(header(1, 1)).fragment), "packed format: refused"
        objects = dut.master.read(header(1, 2)).fragment.of(1)
        assert {o.variation for o in objects} == {2} and {o.qualifier for o in objects} <= RANGES
        assert all(o.flags & 0x7F == FLAG_ONLINE for o in objects)
        dut.quality[(Kind.BI, 0)] = Quality.COMM_LOST
        flagged = dut.master.read(header(1, 2)).fragment.of(1)
        assert flagged[0].variation == 2 and flagged[0].flags & 0x7F == 0x04
        assert all(o.flags & 0x7F == FLAG_ONLINE for o in flagged[1:])

    def test_8_24_2_2_double_bit_inputs(self):
        dut = Dut()
        assert self._refused(dut.master.read(header(3, 1)).fragment)

    def test_8_24_2_3_binary_output_status(self):
        dut = Dut()
        objects = dut.master.read(header(10, 2)).fragment.of(10)
        assert {o.variation for o in objects} == {2} and {o.qualifier for o in objects} <= RANGES
        assert all(o.flags == FLAG_ONLINE for o in objects)

    def test_8_24_2_4_counters(self):
        dut = Dut()
        objects = dut.master.read(header(20, 1)).fragment.of(20)
        assert {o.variation for o in objects} <= {1, 5} and {o.qualifier for o in objects} <= RANGES
        assert all(o.flags in (None, FLAG_ONLINE) for o in objects)
        for variation in (2, 5, 6):
            assert self._refused(dut.master.read(header(20, variation)).fragment), variation
        dut.quality[(Kind.CTR, 0)] = Quality.COMM_LOST
        flagged = dut.master.read(header(20, 1)).fragment.of(20)
        assert flagged[0].variation == 1 and flagged[0].flags == 0x04

    def test_8_24_2_5_frozen_counters(self):
        dut = Dut()
        dut.master.request(FREEZE, header(20, 0))
        for variation, allowed in ((1, {1, 9}), (9, {1, 9})):
            objects = dut.master.read(header(21, variation)).fragment.of(21)
            assert {o.variation for o in objects} <= allowed, variation
            assert {o.qualifier for o in objects} <= RANGES
            assert all(o.flags in (None, FLAG_ONLINE) for o in objects)
        for variation in (2, 10):
            assert self._refused(dut.master.read(header(21, variation)).fragment), variation
        dut.quality[(Kind.CTR, 0)] = Quality.COMM_LOST
        dut.master.request(FREEZE, header(20, 0))
        for variation in (1, 9):
            flagged = dut.master.read(header(21, variation)).fragment.of(21)
            assert flagged[0].variation == 1 and flagged[0].flags == 0x04, variation
            assert all(o.flags in (None, FLAG_ONLINE) for o in flagged[1:])

    @pytest.mark.parametrize(
        ("variation", "allowed"),
        [(1, {1, 3}), (2, {2, 4}), (3, {1, 3}), (4, {2, 4})],
    )
    def test_8_24_2_6_analog_inputs(self, variation, allowed):
        dut = Dut()
        objects = dut.master.read(header(30, variation)).fragment.of(30)
        assert {o.variation for o in objects} <= allowed
        assert {o.qualifier for o in objects} <= RANGES
        assert all(o.flags in (None, FLAG_ONLINE) for o in objects)
        assert [o.value for o in objects] == [100, 100, 100, 100]
        # With one point not normal, that point is reported with its flags.
        dut.quality[(Kind.AI, 0)] = Quality.COMM_LOST
        flagged = dut.master.read(header(30, variation)).fragment.of(30)
        with_flags = 1 if variation in (1, 3) else 2
        assert flagged[0].variation == with_flags and flagged[0].flags == 0x04
        assert {o.variation for o in flagged[1:]} <= allowed
        assert [o.index for o in flagged] == [0, 1, 2, 3]

    def test_8_24_2_7_analog_output_status(self):
        dut = Dut()
        sixteen = dut.master.read(header(40, 2)).fragment.of(40)
        assert {o.variation for o in sixteen} == {2} and {o.qualifier for o in sixteen} <= RANGES
        assert all(o.flags == FLAG_ONLINE for o in sixteen)
        thirty_two = dut.master.read(header(40, 1)).fragment.of(40)
        assert {o.variation for o in thirty_two} == {1}


class TestSpecificEventVariations:
    def test_8_25_2_3_counter_events(self):
        dut = Dut()
        for variation in (1, 2):
            fragment = dut.master.read(header(22, variation)).fragment
            assert not fragment.body, "none are generated, so none are returned"
            assert not fragment.iin2 & IIN2_BAD_FUNCTION

    def test_8_25_2_4_frozen_counter_events(self):
        dut = Dut()
        dut.master.request(FREEZE, header(20, 0))
        fragment = dut.master.read(header(23, 1)).fragment
        assert not fragment.body and not fragment.iin2 & IIN2_BAD_FUNCTION

    def test_8_25_2_4_frozen_counter_events_where_they_are_enabled(self):
        dut = Dut(level2=False)
        dut.master.empty_events()
        dut.master.request(FREEZE, header(20, 0))
        fragment = dut.master.read(header(23, 1)).fragment
        events = fragment.objects
        assert {(o.group, o.variation) for o in events} == {(23, 1)}
        assert [o.value for o in events] == [5, 5, 5]
        assert {o.qualifier for o in events} <= INDEXED and fragment.con

    def test_8_25_2_5_analog_input_events(self):
        dut = Dut()
        dut.master.empty_events()
        dut.set_analog(0, 40000)
        dut.set_analog(1, -40000)
        first = dut.master.read(header(32, 1)).fragment
        assert {(o.group, o.variation) for o in first.objects} == {(32, 1)}
        assert [o.value for o in first.objects] == [40000, -40000]
        assert {o.qualifier for o in first.objects} <= INDEXED
        assert all(o.flags == FLAG_ONLINE for o in first.objects)
        assert first.con
        dut.master.confirm(first)
        dut.set_analog(0, 1200)
        dut.set_analog(1, -1200)
        second = dut.master.read(header(32, 2)).fragment
        assert {(o.group, o.variation) for o in second.objects} == {(32, 2)}
        assert [o.value for o in second.objects] == [1200, -1200]
        assert second.con
        # Not confirmed: nothing is retransmitted, and the same request gets the same answer.
        dut.clock.advance(30.0)
        assert dut.master.raw(b"").silent
        again = dut.master.read(header(32, 2)).fragment
        assert again.body == second.body
        dut.master.confirm(again)
        assert dut.master.read(header(32, 0)).fragment.is_null


class TestAssignClass:
    def test_8_26_2_assign_class_is_not_implemented(self):
        """A level 2 device passes by refusing the function code."""
        dut = Dut()
        body = classes(2) + header(1, 0)
        fragment = dut.master.request(ASSIGN_CLASS, body).fragment
        assert not fragment.body
        assert fragment.iin2 & IIN2_BAD_FUNCTION

    def test_8_26_2_class_assignments_hold_without_it(self):
        """Steps 6 to 17, which need no assign class: each class reports its own."""
        dut = Dut()
        dut.master.empty_events()
        dut.toggle(0)  # class 1
        dut.toggle(2)  # class 2
        three = dut.master.read(classes(3)).fragment
        assert not three.body
        assert three.iin1 & 0x0E == 0x06, "classes 1 and 2 waiting, class 3 not"
        one = dut.master.read(classes(1)).fragment
        assert [o.index for o in one.of(2)] == [0] and one.con
        assert one.iin1 & 0x0E == 0x04, "class 2 still waiting"
        dut.master.confirm(one)
        two = dut.master.read(classes(2)).fragment
        assert [o.index for o in two.of(2)] == [2] and two.con
        assert two.iin1 & 0x0E == 0
        dut.master.confirm(two)
