"""Holding events until the master says it got them.

Section 2 of the event plan. The window between ``peek`` and ``drop`` is where
a master may fail to answer, and everything here is about what the outstation
does inside it: keep the events (D18), track one response at a time (D19),
replay a request the master repeats, and clear the overflow flag only once the
response reporting it has been acknowledged (D23).
"""

from __future__ import annotations

from py1815.application import CON_MASK, UNS_MASK, FunctionCode, IIN2Bit, IINBit, QualifierCode
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


def _confirm(sequence: int = 0, unsolicited: bool = False) -> bytes:
    control = 0xC0 | sequence | (UNS_MASK if unsolicited else 0)
    return bytes([control, FunctionCode.CONFIRM])


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

    def test_a_response_carrying_the_bit_and_no_events_still_asks(self):
        """Otherwise the report cannot be retired. An overflow is cleared by a
        master acknowledging it, so a response that reports one has something
        to confirm whether or not any event fitted beside it."""
        buffers = self._overflowed()
        session = Session(Reader(), events=buffers, max_response=4)

        response = session._handle_fragment(_read(1))

        assert response[4:] == b"", "no room for a single event"
        assert response[3] & IIN2Bit.EVENT_BUFFER_OVERFLOW
        assert response[0] & CON_MASK

    def test_and_confirming_it_clears_the_flag(self):
        """The case that latched: a ceiling no event can fit under is the one
        configuration where no response would ever have carried CON, so the
        master was told for ever about a loss it was told about once."""
        buffers = self._overflowed()
        session = Session(Reader(), events=buffers, max_response=4)
        session._handle_fragment(_read(1))

        session._handle_fragment(_confirm(0))

        assert not buffers.overflowed()

    def test_a_class_zero_read_reporting_it_asks_too(self):
        """Nothing about this depends on the ceiling. A master polling static
        data is told about the overflow and can retire it."""
        buffers = self._overflowed()
        session = _session(buffers)

        response = session._handle_fragment(_read(0))

        assert response[0] & CON_MASK
        session._handle_fragment(_confirm(0))
        assert not buffers.overflowed()

    def test_but_a_response_with_neither_does_not_ask(self):
        """The rule is what there is to confirm, not a blanket CON."""
        session = _session(_filled(class_1=1))

        assert not session._handle_fragment(_read(0))[0] & CON_MASK

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


class TestARefusalSupersedesLikeAnyOtherResponse:
    """A refusal is a response. One that left the selection standing would let
    a confirmation for the response before it still retire those events, which
    is D19 holding for the work and not for the answers that decline it."""

    def test_a_control_refused_for_the_monitor_role(self):
        """This session has no control provider, so a SELECT comes back
        refused -- from a branch that used to return before the
        supersession point."""
        buffers = _filled(class_1=1)
        session = _session(buffers)
        session._handle_fragment(_read(1, sequence=0))

        refusal = session._handle_fragment(bytes([0xC1, FunctionCode.SELECT]))
        assert refusal[3] & IIN2Bit.OBJECT_UNKNOWN, "the branch under test"

        session._handle_fragment(_confirm(0))

        assert _count(buffers) == 1

    def test_a_function_this_outstation_does_not_implement(self):
        buffers = _filled(class_1=1)
        session = _session(buffers)
        session._handle_fragment(_read(1, sequence=0))

        refusal = session._handle_fragment(bytes([0xC1, FunctionCode.COLD_RESTART]))
        assert refusal[3] & IIN2Bit.FUNC_NOT_SUPPORTED

        session._handle_fragment(_confirm(0))

        assert _count(buffers) == 1


class TestAFragmentThatDidNotParse:
    """Deliberately outside the supersession above. A garbled fragment is not
    evidence the master moved on -- it is evidence something arrived damaged,
    which is when a retransmission of the held response is most likely to be
    what comes next."""

    #: A READ whose object header stops after the group octet.
    TRUNCATED = bytes([0xC1, FunctionCode.READ, 60])

    def test_it_is_answered_with_a_parameter_error(self):
        session = _session(_filled(class_1=1))

        assert session._handle_fragment(self.TRUNCATED)[3] & IIN2Bit.PARAM_ERROR

    def test_the_held_response_survives_it(self):
        buffers = _filled(class_1=1)
        session = _session(buffers)
        first = session._handle_fragment(_read(1, sequence=0))

        session._handle_fragment(self.TRUNCATED)

        assert session._handle_fragment(_read(1, sequence=0)) == first, "still replayed"

    def test_and_so_does_the_confirmation_it_is_waiting_for(self):
        buffers = _filled(class_1=1)
        session = _session(buffers)
        session._handle_fragment(_read(1, sequence=0))

        session._handle_fragment(self.TRUNCATED)
        session._handle_fragment(_confirm(0))

        assert _count(buffers) == 0


class TestADifferentRequestUnderTheSameSequence:
    """Not a retransmission. A master that reuses a sequence for a different
    question has asked a different question, and a replay would answer the one
    before it -- then have its events retired by the confirmation that
    followed, acknowledged against a response that was never sent."""

    def test_it_is_not_replayed(self):
        buffers = _filled(class_1=1)
        session = _session(buffers)
        events = session._handle_fragment(_read(1, sequence=0))

        static = session._handle_fragment(_read(0, sequence=0))

        assert static != events
        assert static[4:] == Reader.body, "answered as the static read it is"

    def test_and_it_supersedes(self):
        buffers = _filled(class_1=1)
        session = _session(buffers)
        session._handle_fragment(_read(1, sequence=0))
        session._handle_fragment(_read(0, sequence=0))

        session._handle_fragment(_confirm(0))

        assert _count(buffers) == 1


class TestAnUnsolicitedConfirmation:
    """The UNS bit tells a confirmation for an unsolicited response apart from
    one for a solicited response, and the two count sequence numbers
    separately. This outstation sends no unsolicited responses, so a
    confirmation carrying the bit names an exchange that never happened."""

    def test_it_does_not_retire_the_solicited_selection(self):
        buffers = _filled(class_1=2)
        session = _session(buffers)
        session._handle_fragment(_read(1, sequence=0))

        session._handle_fragment(_confirm(0, unsolicited=True))

        assert _count(buffers) == 2

    def test_it_is_still_answered_with_silence(self):
        session = _session(_filled(class_1=1))
        session._handle_fragment(_read(1, sequence=0))

        assert session._handle_fragment(_confirm(0, unsolicited=True)) == b""

    def test_and_leaves_the_response_confirmable_by_a_solicited_one(self):
        """Ignored, not consumed. The master's real confirmation is still to
        come, and swallowing the selection here would lose the events."""
        buffers = _filled(class_1=2)
        session = _session(buffers)
        session._handle_fragment(_read(1, sequence=0))
        session._handle_fragment(_confirm(0, unsolicited=True))

        session._handle_fragment(_confirm(0))

        assert _count(buffers) == 0


class TestOverflowLostAfterTheResponseWentOut:
    """A confirmation acknowledges the loss the confirmed response reported.
    Anything lost since is a loss the master has not been told about, and
    clearing the flag on its behalf would bury it."""

    @staticmethod
    def _read_one(sequence: int = 0) -> bytes:
        """A class 1 read asking for a single event, so the buffer keeps some."""
        return bytes([0xC0 | sequence, FunctionCode.READ, 60, 2, QualifierCode.UINT8_COUNT, 1])

    def test_a_later_eviction_keeps_the_flag_set(self):
        buffers = EventBuffers(capacity=2)
        for index in range(3):
            _record(buffers, index)  # index 0 evicted: the buffer has overflowed
        session = _session(buffers)
        assert session._handle_fragment(self._read_one())[3] & IIN2Bit.EVENT_BUFFER_OVERFLOW

        _record(buffers, 3)  # evicts an event the master has never been sent
        _record(buffers, 4)

        session._handle_fragment(_confirm(0))

        assert buffers.overflowed(), "the loss since that response is still unreported"

    def test_and_the_next_response_says_so_again(self):
        buffers = EventBuffers(capacity=2)
        for index in range(3):
            _record(buffers, index)
        session = _session(buffers)
        session._handle_fragment(self._read_one())
        _record(buffers, 3)
        session._handle_fragment(_confirm(0))

        assert session._handle_fragment(_read(1, sequence=1))[3] & IIN2Bit.EVENT_BUFFER_OVERFLOW

    def test_confirming_that_one_clears_it(self):
        """Nothing was lost between the second response and its confirmation,
        so this time the acknowledgement covers everything outstanding."""
        buffers = EventBuffers(capacity=2)
        for index in range(3):
            _record(buffers, index)
        session = _session(buffers)
        session._handle_fragment(self._read_one())
        _record(buffers, 3)
        session._handle_fragment(_confirm(0))
        session._handle_fragment(_read(1, sequence=1))

        session._handle_fragment(_confirm(1))

        assert not buffers.overflowed()

    def test_nothing_lost_in_between_still_clears_it(self):
        """The plain case, which the generation must not make stricter."""
        buffers = EventBuffers(capacity=2)
        for index in range(3):
            _record(buffers, index)
        session = _session(buffers)
        session._handle_fragment(_read(1))

        session._handle_fragment(_confirm(0))

        assert not buffers.overflowed()
