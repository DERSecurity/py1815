"""Reading objects out of a response, from octets written out by hand.

Every expectation here starts from octets and the layouts in the standard, and
none from this library's encoders. A decoder checked against the encoder it
mirrors agrees with it through any mistake the two share.
"""

from __future__ import annotations

import pytest
from ied_harness import SIZES

from py1815.decode import LAYOUTS, DecodedObject, PointType, decode_objects

#: Ten billion milliseconds after the epoch, as the six octets of a DNP3 time.
TIME = 10_000_000_000
TIME_OCTETS = "00 E4 0B 54 02 00"


def _read(octets: str) -> tuple[DecodedObject, ...]:
    decoded = decode_objects(bytes.fromhex(octets))
    assert decoded.complete, decoded.problem
    return decoded.objects


def _one(octets: str) -> DecodedObject:
    (decoded,) = _read(octets)
    return decoded


class TestAnalogInputs:
    def test_32_bits_with_a_flag_over_a_range(self):
        first, second = _read("1E 01 00 05 06  01 10 27 00 00  01 F0 D8 FF FF")
        assert (first.index, first.value, first.flags) == (5, 10000, 0x01)
        assert (second.index, second.value, second.flags) == (6, -10000, 0x01)
        assert first.point is PointType.ANALOG_INPUT and not first.event
        assert first.raw == bytes.fromhex("01 10 27 00 00")

    def test_16_bits_with_a_flag(self):
        decoded = _one("1E 02 00 00 00  01 2C 01")
        assert (decoded.value, decoded.flags) == (300, 0x01)

    def test_a_variation_without_a_flag_has_none_and_not_zero(self):
        wide = _one("1E 03 00 02 02  40 E2 01 00")
        narrow = _one("1E 04 00 00 00  FE FF")
        assert (wide.index, wide.value, wide.flags) == (2, 123456, None)
        assert (narrow.value, narrow.flags) == (-2, None)

    def test_single_and_double_precision(self):
        single = _one("1E 05 00 00 00  01 00 00 C8 42")
        double = _one("1E 06 00 00 00  01 00 00 00 00 00 00 59 40")
        assert single.value == 100.0 and double.value == 100.0
        assert isinstance(single.value, float)

    def test_a_flag_other_than_online_is_kept_as_sent(self):
        # COMM_LOST and no ONLINE: the value is there and is not to be trusted.
        assert _one("1E 01 00 00 00  04 00 00 00 00").flags == 0x04

    def test_a_16_bit_range(self):
        decoded = _one("1E 02 01 E8 03 E8 03  01 07 00")
        assert (decoded.index, decoded.value) == (1000, 7)


class TestAnalogEvents:
    def test_without_time_under_an_index_each(self):
        first, second = _read("20 01 17 02  09 01 18 FC FF FF  0A 01 64 00 00 00")
        assert (first.index, first.value) == (9, -1000)
        assert (second.index, second.value) == (10, 100)
        assert first.event and first.point is PointType.ANALOG_INPUT
        assert first.time_ms is None

    def test_with_time(self):
        wide = _one(f"20 03 17 01  09  01 18 FC FF FF {TIME_OCTETS}")
        narrow = _one(f"20 04 17 01  09  01 9C FF {TIME_OCTETS}")
        assert (wide.value, wide.time_ms) == (-1000, TIME)
        assert (narrow.value, narrow.time_ms) == (-100, TIME)

    def test_floating_point_with_and_without_time(self):
        plain = _one("20 05 17 01  00  01 00 00 C8 42")
        timed = _one(f"20 07 17 01  00  01 00 00 C8 42 {TIME_OCTETS}")
        double = _one(f"20 08 17 01  00  01 00 00 00 00 00 00 59 40 {TIME_OCTETS}")
        assert plain.value == timed.value == double.value == 100.0
        assert plain.time_ms is None and timed.time_ms == double.time_ms == TIME

    def test_under_sixteen_bit_indices(self):
        decoded = _one("20 02 28 01 00  2C 01  01 05 00")
        assert (decoded.index, decoded.value) == (300, 5)


class TestBinaries:
    def test_the_state_is_the_top_bit_and_not_a_flag(self):
        on, off, restarted = _read("01 02 00 00 02  81 01 02")
        assert (on.index, on.value, on.flags) == (0, True, 0x01)
        assert (off.index, off.value, off.flags) == (1, False, 0x01)
        assert (restarted.value, restarted.flags) == (False, 0x02)
        assert on.point is PointType.BINARY_INPUT

    def test_packed_bits_run_from_the_low_bit_of_the_first_octet(self):
        bits = _read("01 01 00 00 09  05 02")
        assert [b.index for b in bits] == list(range(10))
        assert [b.value for b in bits] == [
            True,
            False,
            True,
            False,
            False,
            False,
            False,
            False,
            False,
            True,
        ]
        assert all(b.flags is None for b in bits), "a packed bit carries no quality at all"

    def test_packed_bits_under_a_16_bit_range(self):
        bits = _read("01 01 01 E8 03 EA 03  05")
        assert [(b.index, b.value) for b in bits] == [(1000, True), (1001, False), (1002, True)]

    def test_events_without_time(self):
        first, second = _read("02 01 17 02  03 81  07 01")
        assert (first.index, first.value, first.event) == (3, True, True)
        assert (second.index, second.value) == (7, False)

    def test_events_with_absolute_time(self):
        decoded = _one(f"02 02 17 01  05  81 {TIME_OCTETS}")
        assert (decoded.index, decoded.value, decoded.time_ms) == (5, True, TIME)
        assert decoded.synchronized is None, "an absolute time says nothing about the clock"

    def test_output_status_and_its_events(self):
        on, off = _read("0A 02 00 00 01  81 01")
        assert (on.value, off.value) == (True, False)
        assert on.point is PointType.BINARY_OUTPUT
        event = _one(f"0B 02 17 01  02  81 {TIME_OCTETS}")
        assert (event.index, event.value, event.event, event.time_ms) == (2, True, True, TIME)

    def test_packed_output_status(self):
        bits = _read("0A 01 00 00 01  02")
        assert [(b.value, b.point) for b in bits] == [
            (False, PointType.BINARY_OUTPUT),
            (True, PointType.BINARY_OUTPUT),
        ]


class TestRelativeTime:
    """A relative-time event counts from the common time of occurrence before it."""

    EVENTS = "02 03 17 02  01 81 0A 00  04 01 E8 03"

    def test_events_take_their_time_from_the_common_time(self):
        common, first, second = _read(f"33 01 07 01 {TIME_OCTETS}  {self.EVENTS}")
        assert (common.group, common.index, common.value) == (51, None, TIME)
        assert (first.index, first.value, first.time_ms) == (1, True, TIME + 10)
        assert (second.index, second.value, second.time_ms) == (4, False, TIME + 1000)
        assert first.synchronized is True

    def test_the_unsynchronized_form_says_the_clock_had_not_been_set(self):
        _, first, _ = _read(f"33 02 07 01 {TIME_OCTETS}  {self.EVENTS}")
        assert first.time_ms == TIME + 10
        assert first.synchronized is False

    def test_with_no_common_time_before_it_an_event_has_no_time(self):
        first, _ = _read(self.EVENTS)
        assert first.value is True
        assert first.time_ms is None and first.synchronized is None

    def test_a_second_common_time_replaces_the_first(self):
        later = "00 E8 0B 54 02 00"
        objects = _read(
            f"33 01 07 01 {TIME_OCTETS}  02 03 17 01  01 81 0A 00"
            f"  33 01 07 01 {later}  02 03 17 01  02 81 0A 00"
        )
        assert objects[1].time_ms == TIME + 10
        assert objects[3].time_ms == TIME + 1024 + 10


class TestCounters:
    def test_running_counters(self):
        wide = _one("14 01 00 00 00  01 78 56 34 12")
        narrow = _one("14 02 00 00 00  01 34 12")
        assert (wide.value, wide.flags, wide.point) == (0x12345678, 0x01, PointType.COUNTER)
        assert narrow.value == 0x1234

    def test_a_counter_is_unsigned(self):
        assert _one("14 05 00 00 00  FF FF FF FF").value == 4294967295
        assert _one("14 06 00 00 00  FF FF").value == 65535
        assert _one("14 05 00 00 00  FF FF FF FF").flags is None

    def test_frozen_counters_with_the_time_of_the_freeze(self):
        decoded = _one(f"15 05 00 01 01  01 0A 00 00 00 {TIME_OCTETS}")
        assert (decoded.index, decoded.value, decoded.time_ms) == (1, 10, TIME)
        assert decoded.point is PointType.FROZEN_COUNTER and not decoded.event

    def test_frozen_counters_without_a_flag(self):
        decoded = _one("15 09 00 00 00  0A 00 00 00")
        assert (decoded.value, decoded.flags, decoded.time_ms) == (10, None, None)

    def test_frozen_counter_events(self):
        decoded = _one(f"17 05 28 01 00  2C 01  01 0A 00 00 00 {TIME_OCTETS}")
        assert (decoded.index, decoded.value, decoded.time_ms) == (300, 10, TIME)
        assert decoded.event and decoded.point is PointType.FROZEN_COUNTER

    def test_counter_events(self):
        decoded = _one("16 01 17 01  02  01 0A 00 00 00")
        assert (decoded.index, decoded.value, decoded.event) == (2, 10, True)
        assert decoded.point is PointType.COUNTER


class TestAnalogOutputs:
    def test_status_in_each_width(self):
        assert _one("28 01 00 00 00  01 A0 86 01 00").value == 100000
        assert _one("28 02 00 00 00  01 64 00").value == 100
        assert _one("28 03 00 00 00  01 00 00 C8 42").value == 100.0
        assert _one("28 04 00 00 00  01 00 00 00 00 00 00 59 40").value == 100.0
        assert _one("28 02 00 00 00  01 64 00").point is PointType.ANALOG_OUTPUT

    def test_status_events(self):
        decoded = _one(f"2A 03 17 01  04  01 64 00 00 00 {TIME_OCTETS}")
        assert (decoded.index, decoded.value, decoded.time_ms) == (4, 100, TIME)
        assert decoded.event


class TestObjectsThatAreNotPoints:
    def test_the_time_and_date(self):
        decoded = _one(f"32 01 07 01 {TIME_OCTETS}")
        assert (decoded.index, decoded.value, decoded.point) == (None, TIME, None)

    def test_a_time_delay_in_milliseconds(self):
        assert _one("34 02 07 01  F4 01").value == 500

    def test_an_echoed_command_is_walked_past_and_what_follows_is_read(self):
        relay, analog = _read(
            "0C 01 17 01  05  03 01 64 00 00 00 00 00 00 00 00   1E 02 00 00 00  01 2C 01"
        )
        assert (relay.group, relay.index, relay.value, relay.point) == (12, 5, None, None)
        assert len(relay.raw) == 11
        assert analog.value == 300


class TestWhatCannotBeRead:
    """Reading stops, says why, and keeps what it had."""

    def test_an_unknown_group_ends_the_walk_and_keeps_what_came_before(self):
        decoded = decode_objects(bytes.fromhex("1E 02 00 00 00  01 2C 01   6E 04 00 00 00  41 42"))
        assert [o.value for o in decoded.objects] == [300]
        assert not decoded.complete
        assert "group 110 variation 4" in decoded.problem
        assert decoded.unread == bytes.fromhex("6E 04 00 00 00 41 42")

    def test_a_body_that_ends_inside_an_object(self):
        decoded = decode_objects(bytes.fromhex("1E 01 00 00 01  01 01 00 00 00"))
        assert decoded.objects == ()
        assert "ends inside group 30 variation 1" in decoded.problem
        assert decoded.unread[:3] == bytes.fromhex("1E 01 00")

    def test_a_body_that_ends_inside_a_header(self):
        decoded = decode_objects(bytes.fromhex("1E 01"))
        assert "ends inside an object header" in decoded.problem

    def test_a_range_that_ends_before_it_begins(self):
        decoded = decode_objects(bytes.fromhex("1E 02 00 05 04  01 00 00"))
        assert "5..4" in decoded.problem

    def test_a_qualifier_nothing_here_reads(self):
        decoded = decode_objects(bytes.fromhex("1E 02 5B 01 03 00 01 00 00"))
        assert "0x5B" in decoded.problem

    def test_a_point_value_with_no_index_to_say_which_point(self):
        decoded = decode_objects(bytes.fromhex("1E 02 07 01  01 2C 01"))
        assert "no index" in decoded.problem

    def test_an_empty_body_is_read_in_full(self):
        decoded = decode_objects(b"")
        assert decoded.complete and decoded.objects == ()


class TestSign:
    """An analog value is signed and a count is not, in every width."""

    @pytest.mark.parametrize(
        ("octets", "value"),
        [
            ("1E 01 00 00 00  01 FF FF FF FF", -1),
            ("1E 02 00 00 00  01 FF FF", -1),
            ("1E 03 00 00 00  00 00 00 80", -(2**31)),
            ("1E 04 00 00 00  00 80", -(2**15)),
            ("20 01 17 01 00  01 FF FF FF FF", -1),
            ("20 02 17 01 00  01 FF FF", -1),
            ("28 01 00 00 00  01 FF FF FF FF", -1),
            ("28 02 00 00 00  01 FF FF", -1),
            ("2A 01 17 01 00  01 FF FF FF FF", -1),
            ("2A 02 17 01 00  01 FF FF", -1),
        ],
    )
    def test_an_analog_value_with_its_top_bit_set_is_negative(self, octets, value):
        assert _one(octets).value == value

    @pytest.mark.parametrize(
        ("octets", "value"),
        [
            ("14 01 00 00 00  01 FF FF FF FF", 2**32 - 1),
            ("14 02 00 00 00  01 FF FF", 2**16 - 1),
            ("15 01 00 00 00  01 FF FF FF FF", 2**32 - 1),
            ("15 02 00 00 00  01 FF FF", 2**16 - 1),
            ("15 0A 00 00 00  FF FF", 2**16 - 1),
            ("16 02 17 01 00  01 FF FF", 2**16 - 1),
            ("17 01 17 01 00  01 FF FF FF FF", 2**32 - 1),
        ],
    )
    def test_a_count_with_its_top_bit_set_is_large(self, octets, value):
        assert _one(octets).value == value


class TestTheTable:
    def test_it_agrees_with_the_sizes_the_certification_harness_was_written_with(self):
        """Two tables written separately, compared wherever both have an entry."""
        shared = sorted(set(SIZES) & {key for key, layout in LAYOUTS.items() if not layout.packed})
        assert len(shared) > 30, "the two tables overlap on most of what an outstation sends"
        assert {key: LAYOUTS[key].size for key in shared} == {key: SIZES[key] for key in shared}

    @pytest.mark.parametrize(
        ("key", "size"),
        [
            ((2, 2), 7),
            ((2, 3), 3),
            ((21, 6), 9),
            ((22, 5), 11),
            ((30, 6), 9),
            ((32, 8), 15),
            ((42, 7), 11),
            ((50, 1), 6),
            ((51, 2), 6),
            ((52, 1), 2),
        ],
    )
    def test_sizes_the_standard_gives(self, key, size):
        assert LAYOUTS[key].size == size
