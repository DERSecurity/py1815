"""Event buffers: what counts as a change, and what happens when nobody reads.

The deadband tests are the substance. Everything else in this module is
bookkeeping; the deadband is the rule that decides whether an operator hears
about something at all.
"""

from __future__ import annotations

from functools import reduce
from operator import or_

import pytest

from py1815.events import (
    _ANALOG_QUALITY_MASK,
    _BINARY_QUALITY_MASK,
    MAX_INDEX,
    AnalogEvent,
    BinaryEvent,
    EventBuffers,
    EventClass,
    now_ms,
)
from py1815.objects import (
    AnalogPoint,
    AnalogQuality,
    BinaryPoint,
    BinaryQuality,
    analog_flags,
    binary_flags,
)

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


class TestNonFiniteReadings:
    """A NaN arrives when a register was not read or a division had no
    denominator. Every comparison involving it is false, so it is handled before
    the deadband or the transition disappears entirely."""

    def test_a_reading_that_becomes_nan_is_reported(self):
        """Otherwise the encoder's REFERENCE_ERR never reaches the wire: the
        master is never told to go and look."""
        buffers = _buffers()
        _record(buffers, 0, 10, deadband=1000.0)

        assert _record(buffers, 0, float("nan"), deadband=1000.0) is not None

    def test_recovery_from_nan_to_a_real_number_is_reported(self):
        buffers = _buffers()
        _record(buffers, 0, float("nan"), deadband=1000.0)

        assert _record(buffers, 0, 10, deadband=1000.0) is not None

    def test_nan_holding_at_nan_reports_nothing(self):
        """It has not changed, and repeating it every cycle would fill the
        buffer with the same non-reading."""
        buffers = _buffers()
        _record(buffers, 0, float("nan"))

        assert _record(buffers, 0, float("nan")) is None

    def test_an_infinity_is_still_subject_to_the_deadband(self):
        """It is a number, however implausible, and it saturates on the wire."""
        buffers = _buffers()
        _record(buffers, 0, float("inf"))

        assert _record(buffers, 0, float("inf")) is None


class TestConfiguration:
    def test_a_capacity_below_one_is_refused(self):
        """It would drop from an empty buffer on the first event, and the
        IndexError would name a deque rather than the configuration."""
        with pytest.raises(ValueError, match="at least one event"):
            EventBuffers(capacity=0)

    def test_a_negative_capacity_is_refused(self):
        with pytest.raises(ValueError, match="at least one event"):
            EventBuffers(capacity=-1)


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

    def test_a_chatter_filter_change_at_the_same_state_is_reported(self):
        """Chatter is a binary-only quality bit, and it was never covered.

        It worked regardless, because the mask was built from ``AnalogQuality``
        and ``OVER_RANGE`` happens to occupy the same 0x20 bit. That is a
        coincidence of the bit layout rather than a decision, so nothing here
        was holding it up.
        """
        buffers = _buffers()
        buffers.record_binary(0, BinaryPoint(state=True), event_class=EventClass.CLASS_1)
        chattering = BinaryPoint(state=True, flags=binary_flags(state=True, chatter=True))

        assert buffers.record_binary(0, chattering, event_class=EventClass.CLASS_1) is not None


class TestQualityMasks:
    """Each mask is derived from its own enum, not from the other's bit layout.

    The behavioral tests above cannot catch a mask that drifts from its enum,
    because the two enums currently agree everywhere a test looks. These
    assertions are what fails when a bit is added to one of them.
    """

    def test_the_analog_mask_covers_every_analog_quality_bit(self):
        for bit in AnalogQuality:
            assert _ANALOG_QUALITY_MASK & bit, f"{bit.name} is not judged a quality change"

    def test_the_binary_mask_covers_every_binary_quality_bit(self):
        for bit in BinaryQuality:
            if bit is BinaryQuality.STATE:
                continue
            assert _BINARY_QUALITY_MASK & bit, f"{bit.name} is not judged a quality change"

    def test_the_binary_mask_excludes_the_state_bit(self):
        """Excluded on purpose, so that a state change counts once.

        Previously this exclusion was written as ``& ~BinaryQuality.STATE``
        against a mask built from ``AnalogQuality``, where no bit is 0x80 --
        so the term removed nothing and the guard it described was not running.
        """
        assert not _BINARY_QUALITY_MASK & BinaryQuality.STATE

    def test_the_binary_mask_claims_no_bit_binary_does_not_define(self):
        """0x40 is ``AnalogQuality.REFERENCE_ERR`` and means nothing on a
        binary point. The shared mask included it on binary flags."""
        defined = reduce(or_, BinaryQuality, 0)
        assert _BINARY_QUALITY_MASK & ~defined == 0


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


class TestAnIndexAnEventBlockCanCarry:
    """Checked when recorded, not when read.

    ``event_block`` refuses a negative or oversized index, and that refusal
    arriving at read time would take out every read of the class -- a caller's
    mistake surfacing as a protocol failure, far from the line that made it and
    with the connection as collateral.
    """

    @pytest.mark.parametrize("index", [-1, -100, MAX_INDEX + 1, 1 << 20])
    def test_an_analog_event_outside_the_range_is_refused(self, index):
        with pytest.raises(ValueError, match="is outside"):
            _buffers().record_analog(index, AnalogPoint(1.0), event_class=EventClass.CLASS_1)

    @pytest.mark.parametrize("index", [-1, -100, MAX_INDEX + 1, 1 << 20])
    def test_a_binary_event_outside_the_range_is_refused(self, index):
        with pytest.raises(ValueError, match="is outside"):
            _buffers().record_binary(index, BinaryPoint(state=True), event_class=EventClass.CLASS_1)

    @pytest.mark.parametrize("index", [0, 1, MAX_INDEX])
    def test_the_ends_of_the_range_are_accepted(self, index):
        buffers = _buffers()

        assert buffers.record_analog(index, AnalogPoint(1.0), event_class=EventClass.CLASS_1)
        assert buffers.record_binary(index, BinaryPoint(state=True), event_class=EventClass.CLASS_2)

    def test_a_refused_index_leaves_nothing_behind(self):
        """Not recorded and not half-recorded: a later reading at that index
        must not compare against a value the buffer rejected."""
        buffers = _buffers()

        with pytest.raises(ValueError):
            buffers.record_analog(-1, AnalogPoint(1.0), event_class=EventClass.CLASS_1)

        assert buffers.total == 0


class TestPeekTakesItsLimitFromTheFront:
    """The limit is what a caller asking for the few events that fit a response
    uses to avoid paying for a buffer it has no room for."""

    @staticmethod
    def _filled(count: int = 6) -> EventBuffers:
        buffers = EventBuffers(capacity=count)
        for index in range(count):
            buffers.record_analog(
                index, AnalogPoint(float(index)), event_class=EventClass.CLASS_1, timestamp_ms=1
            )
        return buffers

    def test_the_oldest_events_come_back(self):
        held = self._filled().peek(EventClass.CLASS_1, limit=2)

        assert [event.index for event in held] == [0, 1]

    def test_a_limit_of_zero_returns_none_of_them(self):
        assert self._filled().peek(EventClass.CLASS_1, limit=0) == []

    def test_a_limit_past_the_end_is_not_an_error(self):
        assert len(self._filled().peek(EventClass.CLASS_1, limit=99)) == 6

    def test_nor_is_one_past_every_end(self):
        """A limit is an upper bound rather than a promise, so a number larger
        than the buffer asks for the buffer. Python integers have no ceiling
        and the iterator underneath this does, which is a difference a caller
        should never have to know about."""
        assert len(self._filled().peek(EventClass.CLASS_1, limit=10**100)) == 6

    def test_a_negative_limit_returns_none_of_them(self):
        assert self._filled().peek(EventClass.CLASS_1, limit=-5) == []

    def test_no_limit_returns_the_class(self):
        assert len(self._filled().peek(EventClass.CLASS_1)) == 6

    def test_the_buffer_is_untouched_by_a_limited_read(self):
        buffers = self._filled()

        buffers.peek(EventClass.CLASS_1, limit=1)

        assert buffers.count(EventClass.CLASS_1) == 6
