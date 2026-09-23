"""Event buffers: what counts as a change, and what happens when nobody reads.

The deadband tests are the substance. Everything else in this module is
bookkeeping; the deadband is the rule that decides whether an operator hears
about something at all.
"""

from __future__ import annotations

import pytest

from py1815.events import (
    AnalogEvent,
    BinaryEvent,
    EventBuffers,
    EventClass,
    now_ms,
)
from py1815.objects import AnalogPoint, BinaryPoint, analog_flags, binary_flags

ONLINE = analog_flags()
COMM_LOST = analog_flags(online=False, comm_lost=True)


def _buffers(**kwargs) -> EventBuffers:
    return EventBuffers(**kwargs)


def _record(buffers, index, value, flags=ONLINE, deadband=0.0, event_class=EventClass.CLASS_1):
    return buffers.record_analog(
        index,
        AnalogPoint(value, flags),
        event_class=event_class,
        deadband=deadband,
        timestamp_ms=1_700_000_000_000,
    )


class TestAnalogDeadbands:
    def test_the_first_reading_of_a_point_is_always_an_event(self):
        """There is nothing to compare against, and a master that has never
        heard the value needs it."""
        assert _record(_buffers(), 0, 10) is not None

    def test_a_change_inside_the_deadband_is_not_reported(self):
        buffers = _buffers()
        _record(buffers, 0, 10, deadband=1.0)

        assert _record(buffers, 0, 10.5, deadband=1.0) is None

    def test_a_change_beyond_the_deadband_is_reported(self):
        buffers = _buffers()
        _record(buffers, 0, 10, deadband=1.0)

        assert _record(buffers, 0, 11.5, deadband=1.0) is not None

    def test_a_change_exactly_equal_to_the_deadband_is_not_reported(self):
        """Strictly greater, so a deadband of zero still reports any movement
        and a deadband of one does not report a movement of one."""
        buffers = _buffers()
        _record(buffers, 0, 10, deadband=1.0)

        assert _record(buffers, 0, 11.0, deadband=1.0) is None

    def test_a_deadband_of_zero_reports_any_movement(self):
        buffers = _buffers()
        _record(buffers, 0, 10)

        assert _record(buffers, 0, 10.001) is not None

    def test_drift_in_small_steps_is_eventually_reported(self):
        """The comparison is against the last value reported, not the last value
        read. Against the last read, a value can walk any distance in steps that
        each fall inside the deadband and the master never hears about it."""
        buffers = _buffers()
        _record(buffers, 0, 10, deadband=1.0)

        assert _record(buffers, 0, 10.8, deadband=1.0) is None
        assert _record(buffers, 0, 11.4, deadband=1.0) is not None

    def test_points_are_tracked_separately(self):
        buffers = _buffers()
        _record(buffers, 0, 10, deadband=5.0)
        _record(buffers, 1, 100, deadband=5.0)

        assert _record(buffers, 0, 11, deadband=5.0) is None
        assert _record(buffers, 1, 50, deadband=5.0) is not None


class TestQualityChanges:
    def test_a_quality_change_is_reported_whatever_the_deadband(self):
        """A point that goes comm-lost holding the same number has not moved and
        has changed in the way that matters most."""
        buffers = _buffers()
        _record(buffers, 0, 10, deadband=1000.0)

        assert _record(buffers, 0, 10, flags=COMM_LOST, deadband=1000.0) is not None

    def test_returning_to_online_is_also_reported(self):
        buffers = _buffers()
        _record(buffers, 0, 10, flags=COMM_LOST, deadband=1000.0)

        assert _record(buffers, 0, 10, flags=ONLINE, deadband=1000.0) is not None

    def test_an_unchanged_point_reports_nothing(self):
        buffers = _buffers()
        _record(buffers, 0, 10, deadband=1.0)

        assert _record(buffers, 0, 10, deadband=1.0) is None


class TestBinaryEvents:
    def test_a_state_change_is_reported(self):
        buffers = _buffers()
        buffers.record_binary(0, BinaryPoint(state=False), event_class=EventClass.CLASS_1)

        assert (
            buffers.record_binary(0, BinaryPoint(state=True), event_class=EventClass.CLASS_1)
            is not None
        )

    def test_an_unchanged_state_reports_nothing(self):
        buffers = _buffers()
        buffers.record_binary(0, BinaryPoint(state=True), event_class=EventClass.CLASS_1)

        assert (
            buffers.record_binary(0, BinaryPoint(state=True), event_class=EventClass.CLASS_1)
            is None
        )

    def test_a_quality_change_at_the_same_state_is_reported(self):
        buffers = _buffers()
        buffers.record_binary(0, BinaryPoint(state=True), event_class=EventClass.CLASS_1)
        offline = BinaryPoint(
            state=True, flags=binary_flags(state=True, online=False, comm_lost=True)
        )

        assert buffers.record_binary(0, offline, event_class=EventClass.CLASS_1) is not None

    def test_a_state_change_counts_once(self):
        """The state travels in the flags octet, so comparing quality naively
        would see every state change as a quality change as well."""
        buffers = _buffers()
        buffers.record_binary(0, BinaryPoint(state=False), event_class=EventClass.CLASS_1)
        buffers.record_binary(0, BinaryPoint(state=True), event_class=EventClass.CLASS_1)

        assert buffers.count(EventClass.CLASS_1) == 2


class TestClasses:
    def test_events_land_in_the_class_they_are_assigned(self):
        buffers = _buffers()
        _record(buffers, 0, 1, event_class=EventClass.CLASS_1)
        _record(buffers, 1, 2, event_class=EventClass.CLASS_2)
        _record(buffers, 2, 3, event_class=EventClass.CLASS_3)

        assert [buffers.count(cls) for cls in EventClass] == [1, 1, 1]

    def test_only_classes_holding_events_are_reported(self):
        buffers = _buffers()
        _record(buffers, 0, 1, event_class=EventClass.CLASS_2)

        assert buffers.classes_with_events() == {EventClass.CLASS_2}

    def test_the_total_counts_every_class(self):
        buffers = _buffers()
        _record(buffers, 0, 1, event_class=EventClass.CLASS_1)
        _record(buffers, 1, 2, event_class=EventClass.CLASS_3)

        assert buffers.total == 2


class TestOverflow:
    def test_a_full_buffer_drops_its_oldest_event(self):
        """Dropping the newest would keep a master reading history while the
        present goes unreported."""
        buffers = _buffers(capacity=2)
        for value in (1, 2, 3):
            _record(buffers, 0, value)

        held = buffers.peek(EventClass.CLASS_1)
        assert [event.point.value for event in held] == [2, 3]

    def test_an_overflow_is_remembered_until_it_is_reported(self):
        buffers = _buffers(capacity=1)
        _record(buffers, 0, 1)
        assert not buffers.overflowed()

        _record(buffers, 0, 2)
        assert buffers.overflowed()

        buffers.clear_overflow()
        assert not buffers.overflowed()

    def test_capacity_is_per_class(self):
        buffers = _buffers(capacity=1)
        _record(buffers, 0, 1, event_class=EventClass.CLASS_1)
        _record(buffers, 1, 2, event_class=EventClass.CLASS_2)

        assert buffers.total == 2
        assert not buffers.overflowed()


class TestReadingAndConfirming:
    def test_peeking_does_not_consume(self):
        """A response that never arrives must not have taken the only copy of
        its events with it."""
        buffers = _buffers()
        _record(buffers, 0, 1)

        buffers.peek(EventClass.CLASS_1)

        assert buffers.count(EventClass.CLASS_1) == 1

    def test_a_limit_takes_the_oldest_first(self):
        buffers = _buffers()
        for value in (1, 2, 3):
            _record(buffers, 0, value)

        assert [e.point.value for e in buffers.peek(EventClass.CLASS_1, limit=2)] == [1, 2]

    def test_confirmed_events_are_dropped_and_the_rest_are_kept(self):
        buffers = _buffers()
        for value in (1, 2, 3):
            _record(buffers, 0, value)
        first_two = buffers.peek(EventClass.CLASS_1, limit=2)

        buffers.drop(first_two)

        assert [e.point.value for e in buffers.peek(EventClass.CLASS_1)] == [3]

    def test_dropping_events_of_one_class_leaves_another_alone(self):
        buffers = _buffers()
        _record(buffers, 0, 1, event_class=EventClass.CLASS_1)
        _record(buffers, 1, 2, event_class=EventClass.CLASS_2)

        buffers.drop(buffers.peek(EventClass.CLASS_1))

        assert buffers.count(EventClass.CLASS_1) == 0
        assert buffers.count(EventClass.CLASS_2) == 1


class TestTimestamps:
    def test_an_event_carries_the_time_it_was_given(self):
        buffers = _buffers()
        event = _record(buffers, 0, 10)

        assert event is not None
        assert event.timestamp_ms == 1_700_000_000_000

    def test_an_event_defaults_to_now(self):
        buffers = _buffers()
        before = now_ms()

        event = buffers.record_analog(0, AnalogPoint(10), event_class=EventClass.CLASS_1)

        assert event is not None
        assert before <= event.timestamp_ms <= now_ms()

    @pytest.mark.parametrize("kind", [AnalogEvent, BinaryEvent])
    def test_events_carry_their_index(self, kind):
        buffers = _buffers()
        if kind is AnalogEvent:
            event = buffers.record_analog(7, AnalogPoint(1), event_class=EventClass.CLASS_1)
        else:
            event = buffers.record_binary(
                7, BinaryPoint(state=True), event_class=EventClass.CLASS_1
            )

        assert event is not None
        assert event.index == 7
