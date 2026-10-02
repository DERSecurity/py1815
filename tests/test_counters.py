"""Counters, frozen counters, and the events a freeze leaves behind."""

from __future__ import annotations

import struct

import pytest

from py1815.events import AnalogEvent, BinaryEvent, EventBuffers, EventClass, FrozenCounterEvent
from py1815.objects import (
    AnalogPoint,
    BinaryPoint,
    CounterPoint,
    CounterQuality,
    FrozenCounterVariation,
    counter_range,
    encode_counter,
    encode_frozen_counter,
    encode_frozen_counter_event,
    frozen_counter_range,
)


class TestTheStaticCounter:
    def test_it_is_a_flag_octet_and_thirty_two_bits(self):
        assert encode_counter(CounterPoint(0x01020304)) == b"\x01\x04\x03\x02\x01"

    def test_a_count_past_thirty_two_bits_wraps_rather_than_pinning(self):
        """A pinned counter reads as one that stopped counting."""
        assert encode_counter(CounterPoint(2**32 + 7))[1:] == struct.pack("<I", 7)

    def test_a_negative_count_is_a_bug_in_the_caller(self):
        with pytest.raises(ValueError):
            encode_counter(CounterPoint(-1))

    def test_a_range_is_group_twenty_variation_one(self):
        block = counter_range(4, [CounterPoint(1), CounterPoint(2)])
        assert block[:5] == bytes([20, 1, 0x00, 4, 5])
        assert len(block) == 5 + 2 * 5

    def test_an_empty_range_is_refused(self):
        with pytest.raises(ValueError):
            counter_range(0, [])

    def test_quality_travels_in_the_flag_octet(self):
        point = CounterPoint(1, CounterQuality.COMM_LOST)
        assert encode_counter(point)[0] == CounterQuality.COMM_LOST


class TestTheFrozenCounter:
    def test_the_timed_variation_carries_the_moment_of_the_freeze(self):
        encoded = encode_frozen_counter(CounterPoint(9), timestamp_ms=0x010203040506)
        assert encoded == b"\x01\x09\x00\x00\x00" + bytes([6, 5, 4, 3, 2, 1])

    def test_the_variation_without_a_flag_is_the_count_alone(self):
        encoded = encode_frozen_counter(CounterPoint(9), variation=FrozenCounterVariation.INT32)
        assert encoded == b"\x09\x00\x00\x00"

    @pytest.mark.parametrize(
        ("variation", "timestamp"),
        [
            pytest.param(FrozenCounterVariation.INT32_WITH_FLAG_AND_TIME, None, id="time owed"),
            pytest.param(FrozenCounterVariation.INT32_WITH_FLAG, 5, id="time not carried"),
            pytest.param(FrozenCounterVariation.INT32, 5, id="no flag, time not carried"),
        ],
    )
    def test_a_timestamp_and_a_variation_must_agree(self, variation, timestamp):
        """Both directions: a dropped time is a disagreement neither end can see."""
        with pytest.raises(ValueError):
            encode_frozen_counter(CounterPoint(1), variation=variation, timestamp_ms=timestamp)

    def test_a_range_names_group_twenty_one_and_its_variation(self):
        block = frozen_counter_range(0, [(CounterPoint(1), 10), (CounterPoint(2), 20)])
        assert block[:5] == bytes([21, 5, 0x00, 0, 1])
        assert len(block) == 5 + 2 * 11

    def test_an_untimed_range_ignores_the_freeze_times_it_was_given(self):
        block = frozen_counter_range(
            0, [(CounterPoint(1), 10)], variation=FrozenCounterVariation.INT32_WITH_FLAG
        )
        assert block == bytes([21, 1, 0x00, 0, 0]) + b"\x01\x01\x00\x00\x00"

    def test_the_event_is_flag_count_and_time(self):
        assert len(encode_frozen_counter_event(CounterPoint(1), timestamp_ms=1)) == 11


class TestFrozenCounterEvents:
    def test_every_freeze_is_an_event_even_when_the_count_did_not_move(self):
        """A frozen counter event is a log entry, not a change report."""
        buffers = EventBuffers()
        for _ in range(3):
            buffers.record_frozen_counter(0, CounterPoint(5), event_class=EventClass.CLASS_3)
        assert buffers.count(EventClass.CLASS_3) == 3

    def test_the_index_is_checked(self):
        with pytest.raises(ValueError):
            EventBuffers().record_frozen_counter(
                70000, CounterPoint(1), event_class=EventClass.CLASS_3
            )


class TestReadingOneKindAcrossClasses:
    def _mixed(self) -> EventBuffers:
        buffers = EventBuffers()
        buffers.record_analog(1, AnalogPoint(1.0), event_class=EventClass.CLASS_3)
        buffers.record_binary(2, BinaryPoint(True), event_class=EventClass.CLASS_1)
        buffers.record_analog(3, AnalogPoint(2.0), event_class=EventClass.CLASS_1)
        buffers.record_frozen_counter(4, CounterPoint(1), event_class=EventClass.CLASS_3)
        return buffers

    def test_only_that_kind_comes_back_oldest_first(self):
        """Whichever class each is in: index 1 was recorded before index 3."""
        analog = self._mixed().peek_kind(AnalogEvent)
        assert [event.index for event in analog] == [1, 3]

    def test_a_limit_is_an_upper_bound(self):
        assert len(self._mixed().peek_kind(AnalogEvent, limit=1)) == 1

    def test_a_limit_takes_the_oldest_and_not_the_highest_class(self):
        """The class 3 event came first, so it is the one a limit of one keeps."""
        (oldest,) = self._mixed().peek_kind(AnalogEvent, limit=1)
        assert oldest.index == 1

    def test_nothing_is_removed(self):
        buffers = self._mixed()
        buffers.peek_kind(BinaryEvent)
        buffers.peek_kind(FrozenCounterEvent)
        assert buffers.total == 4


class TestKeepingOnlyTheLatestAnalogEvent:
    def test_a_newer_reading_replaces_the_one_still_buffered(self):
        buffers = EventBuffers(analog_latest_only=True)
        for value in (1.0, 2.0, 3.0):
            buffers.record_analog(7, AnalogPoint(value), event_class=EventClass.CLASS_2)
        held = buffers.peek(EventClass.CLASS_2)
        assert [event.point.value for event in held] == [3.0]

    def test_the_default_keeps_every_change(self):
        buffers = EventBuffers()
        for value in (1.0, 2.0, 3.0):
            buffers.record_analog(7, AnalogPoint(value), event_class=EventClass.CLASS_2)
        assert buffers.count(EventClass.CLASS_2) == 3

    def test_other_points_are_left_alone(self):
        buffers = EventBuffers(analog_latest_only=True)
        buffers.record_analog(1, AnalogPoint(1.0), event_class=EventClass.CLASS_2)
        buffers.record_analog(2, AnalogPoint(1.0), event_class=EventClass.CLASS_2)
        buffers.record_analog(1, AnalogPoint(2.0), event_class=EventClass.CLASS_2)
        held = buffers.peek(EventClass.CLASS_2)
        # The superseded point moves behind the one that changed before it did.
        assert [(event.index, event.point.value) for event in held] == [(2, 1.0), (1, 2.0)]

    def test_binary_events_are_never_collapsed(self):
        """For a binary point the sequence is the information."""
        buffers = EventBuffers(analog_latest_only=True)
        for state in (True, False, True):
            buffers.record_binary(1, BinaryPoint(state), event_class=EventClass.CLASS_1)
        assert buffers.count(EventClass.CLASS_1) == 3

    def test_a_confirmed_event_is_not_superseded_a_second_time(self):
        """Once dropped, the next reading is a fresh event rather than a replacement."""
        buffers = EventBuffers(analog_latest_only=True)
        first = buffers.record_analog(1, AnalogPoint(1.0), event_class=EventClass.CLASS_2)
        buffers.drop([first])
        buffers.record_analog(1, AnalogPoint(2.0), event_class=EventClass.CLASS_2)
        buffers.record_analog(1, AnalogPoint(3.0), event_class=EventClass.CLASS_2)
        assert [e.point.value for e in buffers.peek(EventClass.CLASS_2)] == [3.0]

    def test_an_evicted_event_is_forgotten_too(self):
        buffers = EventBuffers(capacity=1, analog_latest_only=True)
        buffers.record_analog(1, AnalogPoint(1.0), event_class=EventClass.CLASS_2)
        buffers.record_analog(2, AnalogPoint(1.0), event_class=EventClass.CLASS_2)
        buffers.record_analog(1, AnalogPoint(2.0), event_class=EventClass.CLASS_2)
        assert [e.index for e in buffers.peek(EventClass.CLASS_2)] == [1]


class TestPriming:
    def test_a_primed_point_reports_nothing_until_it_changes(self):
        buffers = EventBuffers()
        buffers.prime_analog(1, AnalogPoint(5.0))
        buffers.prime_binary(2, BinaryPoint(True))
        assert buffers.record_analog(1, AnalogPoint(5.0), event_class=EventClass.CLASS_2) is None
        assert buffers.record_binary(2, BinaryPoint(True), event_class=EventClass.CLASS_1) is None
        assert buffers.total == 0

    def test_a_change_from_the_primed_value_is_an_event(self):
        buffers = EventBuffers()
        buffers.prime_analog(1, AnalogPoint(5.0))
        assert buffers.record_analog(1, AnalogPoint(6.0), event_class=EventClass.CLASS_2)

    def test_an_unprimed_point_reports_its_first_reading(self):
        """The control: without priming, the first reading is an event."""
        buffers = EventBuffers()
        assert buffers.record_analog(1, AnalogPoint(5.0), event_class=EventClass.CLASS_2)
