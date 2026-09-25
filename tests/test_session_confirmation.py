"""Holding events until the master says it got them.

Section 2 of the event plan. The window between ``peek`` and ``drop`` is where
a master may fail to answer, and everything here is about what the outstation
does inside it: keep the events (D18), track one response at a time (D19),
replay a request the master repeats, and clear the overflow flag only once the
response reporting it has been acknowledged (D23).
"""

from __future__ import annotations

from py1815.application import CON_MASK, FunctionCode, IIN2Bit, IINBit, QualifierCode
from py1815.events import EventBuffers, EventClass
from py1815.objects import AnalogPoint
from py1815.session import Session

#: Group 60 variation 2 is class 1, 3 is class 2, 4 is class 3.
CLASS_VARIATION = {0: 1, 1: 2, 2: 3, 3: 4}


class Reader:
    """Static data for the class 0 reads, which are not what is under test."""

    body = bytes([30, 1, 0, 0, 0, 1, 42, 0, 0, 0])

    def read(self, headers):
        return self.body


def _session(buffers: EventBuffers | None = None) -> Session:
    return Session(Reader(), events=buffers)


def _read(event_class: int, sequence: int = 0) -> bytes:
    return bytes(
        [
            0xC0 | sequence,
            FunctionCode.READ,
            60,
            CLASS_VARIATION[event_class],
            QualifierCode.ALL_OBJECTS,
        ]
    )


def _filled(**per_class: int) -> EventBuffers:
    buffers = EventBuffers()
    index = 0
    for name, count in per_class.items():
        for _ in range(count):
            _record(buffers, index, EventClass[name.upper()])
            index += 1
    return buffers


def _confirm(sequence: int = 0) -> bytes:
    return bytes([0xC0 | sequence, FunctionCode.CONFIRM])


def _record(buffers: EventBuffers, index: int, event_class: EventClass = EventClass.CLASS_1):
    buffers.record_analog(
        index, AnalogPoint(float(index)), event_class=event_class, timestamp_ms=index + 1
    )


def _count(buffers: EventBuffers, event_class: EventClass = EventClass.CLASS_1) -> int:
    return len(buffers.peek(event_class))


class TestAnUnconfirmedResponseKeepsItsEvents:
    def test_the_next_read_returns_them_again(self):
        """D18. The master did not say it received them, so as far as this
        outstation knows it did not."""
        buffers = _filled(class_1=2)
        session = _session(buffers)

        first = session._handle_fragment(_read(1, sequence=0))
        second = session._handle_fragment(_read(1, sequence=1))

        assert first[4:] == second[4:]
        assert _count(buffers) == 2

    def test_the_response_asks_to_be_confirmed(self):
        session = _session(_filled(class_1=1))

        response = session._handle_fragment(_read(1))

        assert response[0] & CON_MASK

    def test_a_response_with_no_events_does_not(self):
        """A master answering one would be acknowledging an empty set, and the
        outstation would be waiting on a confirmation for nothing."""
        session = _session(EventBuffers())

        response = session._handle_fragment(_read(1))

        assert not response[0] & CON_MASK

    def test_nor_does_a_static_read(self):
        session = _session(_filled(class_1=1))

        response = session._handle_fragment(_read(0))

        assert not response[0] & CON_MASK


class TestAConfirmationRetiresWhatItCovers:
    def test_the_events_the_response_carried(self):
        buffers = _filled(class_1=2)
        session = _session(buffers)
        session._handle_fragment(_read(1, sequence=3))

        assert session._handle_fragment(_confirm(3)) == b"", "a confirmation is not answered"
        assert _count(buffers) == 0

    def test_and_no_others(self):
        """The read named class 1, so class 2 was never sent and has not been
        acknowledged."""
        buffers = _filled(class_1=1, class_2=2)
        session = _session(buffers)
        session._handle_fragment(_read(1))

        session._handle_fragment(_confirm(0))

        assert _count(buffers, EventClass.CLASS_1) == 0
        assert _count(buffers, EventClass.CLASS_2) == 2

    def test_not_the_events_recorded_after_the_response_went_out(self):
        """An event the master has not seen cannot be retired by an
        acknowledgement of the ones it has."""
        buffers = _filled(class_1=1)
        session = _session(buffers)
        session._handle_fragment(_read(1))
        _record(buffers, 99)

        session._handle_fragment(_confirm(0))

        remaining = buffers.peek(EventClass.CLASS_1)
        assert [event.index for event in remaining] == [99]

    def test_only_what_a_count_qualifier_let_through(self):
        """The rest of the class stayed behind, so it is still unreported."""
        buffers = _filled(class_1=4)
        session = _session(buffers)
        body = bytes([0xC0, FunctionCode.READ, 60, 2, 0x07, 2])

        session._handle_fragment(body)
        session._handle_fragment(_confirm(0))

        assert [event.index for event in buffers.peek(EventClass.CLASS_1)] == [2, 3]

    def test_the_class_indication_clears_with_them(self):
        buffers = _filled(class_1=1)
        session = _session(buffers)
        session._handle_fragment(_read(1))
        session._handle_fragment(_confirm(0))

        assert not session._handle_fragment(_read(0))[2] & IINBit.CLASS_1_EVENTS


class TestAConfirmationThatMatchesNothing:
    def test_a_different_sequence_retires_nothing(self):
        buffers = _filled(class_1=2)
        session = _session(buffers)
        session._handle_fragment(_read(1, sequence=2))

        session._handle_fragment(_confirm(5))

        assert _count(buffers) == 2

    def test_a_confirmation_with_nothing_outstanding_is_harmless(self):
        buffers = _filled(class_1=1)
        session = _session(buffers)

        assert session._handle_fragment(_confirm(0)) == b""
        assert _count(buffers) == 1

    def test_the_same_confirmation_twice_retires_one_response_worth(self):
        """The second names a sequence nothing is outstanding under. Without
        that, a duplicated confirmation would retire the events of whatever
        read happened to follow."""
        buffers = _filled(class_1=1)
        session = _session(buffers)
        session._handle_fragment(_read(1))
        session._handle_fragment(_confirm(0))
        _record(buffers, 50)
        session._handle_fragment(_read(1, sequence=0))

        session._handle_fragment(_confirm(0))
        _record(buffers, 51)
        session._handle_fragment(_confirm(0))

        assert [event.index for event in buffers.peek(EventClass.CLASS_1)] == [51]

    def test_an_outstation_with_no_buffers_ignores_one(self):
        session = _session(None)

        assert session._handle_fragment(_confirm(0)) == b""

    def test_a_confirmation_is_not_mistaken_for_a_repeated_request(self):
        """It carries the sequence of the response it confirms, so a
        retransmission check made first would replay that response instead of
        retiring its events."""
        buffers = _filled(class_1=1)
        session = _session(buffers)
        session._handle_fragment(_read(1, sequence=4))

        assert session._handle_fragment(_confirm(4)) == b""
        assert _count(buffers) == 0


class TestARepeatedRequest:
    def test_is_answered_with_the_response_it_already_built(self):
        buffers = _filled(class_1=1)
        session = _session(buffers)

        first = session._handle_fragment(_read(1, sequence=6))
        repeat = session._handle_fragment(_read(1, sequence=6))

        assert repeat == first

    def test_an_event_arriving_in_between_is_not_added_to_it(self):
        """Which is the whole of the difference between replaying and
        rebuilding. The master is about to confirm this sequence, and that
        confirmation retires the events selected for it -- an event slipped
        into the replay would be retired without ever having been sent under a
        sequence of its own."""
        buffers = _filled(class_1=1)
        session = _session(buffers)
        first = session._handle_fragment(_read(1, sequence=0))
        _record(buffers, 77)

        repeat = session._handle_fragment(_read(1, sequence=0))

        assert repeat == first
        assert _count(buffers) == 2, "and the new event is still waiting its turn"

    def test_the_replayed_response_is_the_one_the_confirmation_retires(self):
        buffers = _filled(class_1=1)
        session = _session(buffers)
        session._handle_fragment(_read(1, sequence=0))
        _record(buffers, 77)
        session._handle_fragment(_read(1, sequence=0))

        session._handle_fragment(_confirm(0))

        assert [event.index for event in buffers.peek(EventClass.CLASS_1)] == [77]

    def test_a_new_sequence_supersedes_it(self):
        """D19. One outstanding response, and the master has moved on."""
        buffers = _filled(class_1=1)
        session = _session(buffers)
        session._handle_fragment(_read(1, sequence=0))
        session._handle_fragment(_read(1, sequence=1))

        session._handle_fragment(_confirm(0))

        assert _count(buffers) == 1, "the superseded response is nobody's to confirm"

    def test_a_static_read_in_between_supersedes_it_too(self):
        """It is a request, not a retransmission, whether or not it carried
        events of its own."""
        buffers = _filled(class_1=1)
        session = _session(buffers)
        session._handle_fragment(_read(1, sequence=0))
        session._handle_fragment(_read(0, sequence=1))

        session._handle_fragment(_confirm(0))

        assert _count(buffers) == 1


class TestConnectionReset:
    def test_it_forgets_what_was_outstanding(self):
        """The socket that response went out on is gone, so no confirmation for
        it can arrive over the one that replaces it."""
        buffers = _filled(class_1=1)
        session = _session(buffers)
        session._handle_fragment(_read(1))

        session.connection_reset()
        session._handle_fragment(_confirm(0))

        assert _count(buffers) == 1

    def test_and_leaves_the_events_alone(self):
        """A reconnecting master expects the events it has not read."""
        buffers = _filled(class_1=2, class_2=1)
        session = _session(buffers)
        session._handle_fragment(_read(1))

        session.connection_reset()

        assert _count(buffers) == 2
        assert _count(buffers, EventClass.CLASS_2) == 1

    def test_a_read_after_it_returns_them(self):
        buffers = _filled(class_1=1)
        session = _session(buffers)
        session._handle_fragment(_read(1))
        session.connection_reset()

        assert session._handle_fragment(_read(1))[4:] != b""


class TestOverflowIsClearedOnlyOnceAcknowledged:
    """D23. An overflow reported in a response the master never received is an
    overflow the master never learned about."""

    @staticmethod
    def _overflowed() -> EventBuffers:
        buffers = EventBuffers(capacity=2)
        for index in range(4):
            _record(buffers, index)
        return buffers

    def test_sending_the_bit_does_not_clear_it(self):
        buffers = self._overflowed()
        session = _session(buffers)

        assert session._handle_fragment(_read(1))[3] & IIN2Bit.EVENT_BUFFER_OVERFLOW
        assert buffers.overflowed()

    def test_confirming_the_response_that_carried_it_does(self):
        buffers = self._overflowed()
        session = _session(buffers)
        session._handle_fragment(_read(1))

        session._handle_fragment(_confirm(0))

        assert not buffers.overflowed()

    def test_a_confirmation_for_another_sequence_does_not(self):
        buffers = self._overflowed()
        session = _session(buffers)
        session._handle_fragment(_read(1))

        session._handle_fragment(_confirm(7))

        assert buffers.overflowed()

    def test_a_response_that_did_not_report_it_does_not_clear_it(self):
        """The overflow happened after this response went out, so its
        confirmation says nothing about whether the master has seen the bit."""
        buffers = EventBuffers(capacity=2)
        _record(buffers, 0)
        session = _session(buffers)
        session._handle_fragment(_read(1))
        for index in range(1, 4):
            _record(buffers, index)

        session._handle_fragment(_confirm(0))

        assert buffers.overflowed()


class TestASelectionEvictedWhileTheConfirmWasInFlight:
    """D18's awkward corner. The buffer bound is the other way an event leaves,
    and the two meet here."""

    def test_the_survivors_retire_and_the_lost_one_is_simply_gone(self):
        buffers = EventBuffers(capacity=2)
        _record(buffers, 0)
        _record(buffers, 1)
        session = _session(buffers)
        session._handle_fragment(_read(1))

        _record(buffers, 2)  # evicts index 0, which the response carried

        session._handle_fragment(_confirm(0))

        assert [event.index for event in buffers.peek(EventClass.CLASS_1)] == [2]

    def test_the_overflow_flag_survives_it(self):
        """There is nothing to report beyond the bit already set, and the
        response that went out did not carry it."""
        buffers = EventBuffers(capacity=2)
        _record(buffers, 0)
        _record(buffers, 1)
        session = _session(buffers)
        session._handle_fragment(_read(1))
        _record(buffers, 2)

        session._handle_fragment(_confirm(0))

        assert buffers.overflowed()

    def test_a_wholly_evicted_selection_is_not_an_error(self):
        buffers = EventBuffers(capacity=2)
        _record(buffers, 0)
        _record(buffers, 1)
        session = _session(buffers)
        session._handle_fragment(_read(1))
        _record(buffers, 2)
        _record(buffers, 3)

        assert session._handle_fragment(_confirm(0)) == b""
        assert [event.index for event in buffers.peek(EventClass.CLASS_1)] == [2, 3]
