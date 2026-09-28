"""Answering across several fragments, one round trip at a time.

Sections 1 through 4 of the fragmentation plan. A multi-fragment response is a
conversation rather than one answer chopped up: the outstation sends a fragment
with `FIR` set, the master confirms it, the next follows under the next
sequence, and the last carries `FIN`.

So a confirmation becomes a request for the next fragment, which is the one
place this session answers something that is not a request.
"""

from __future__ import annotations

from py1815.application import CON_MASK, FunctionCode, QualifierCode
from py1815.events import EventBuffers, EventClass
from py1815.objects import AnalogPoint
from py1815.session import Session

FIR_MASK = 0x80
FIN_MASK = 0x40

#: Enough that no ceiling this file uses can answer it in one fragment.
MANY = 400

#: Classes 1 and 0 together: the integrity poll, and the only shape in which
#: static data and events share a response.
INTEGRITY = bytes([0xC0, FunctionCode.READ, 60, 2, 0x06, 60, 1, 0x06])


class Provider:
    """Static data, counting how often it is asked for."""

    def __init__(self, octets: int = 0) -> None:
        self.body = bytes([30, 1, 0, 0, 0, 1]) + bytes(octets) if octets else b""
        self.calls = 0

    def read(self, headers):
        self.calls += 1
        return self.body


def _filled(count: int = MANY) -> EventBuffers:
    buffers = EventBuffers(capacity=max(count, 1))
    for index in range(count):
        buffers.record_analog(
            index % 60_000,
            AnalogPoint(float(index)),
            event_class=EventClass.CLASS_1,
            timestamp_ms=1,
        )
    return buffers


def _session(buffers: EventBuffers, *, static: int = 0, **kwargs) -> tuple[Session, Provider]:
    provider = Provider(static)
    return Session(provider, events=buffers, **kwargs), provider


def _read(sequence: int = 0) -> bytes:
    return bytes([0xC0 | sequence, FunctionCode.READ, 60, 2, QualifierCode.ALL_OBJECTS])


def _confirm(sequence: int) -> bytes:
    return bytes([0xC0 | sequence, FunctionCode.CONFIRM])


def _walk(session: Session, first: bytes, limit: int = 40) -> list[bytes]:
    """Every fragment of a response, confirming each to draw out the next."""
    fragments = [first]
    while not fragments[-1][0] & FIN_MASK and len(fragments) < limit:
        nxt = session._handle_fragment(_confirm(fragments[-1][0] & 0x0F))
        if not nxt:
            break
        fragments.append(nxt)
    return fragments


class TestAResponseTooLargeForOneFragment:
    def test_the_first_fragment_opens_it(self):
        session, _ = _session(_filled())

        first = session._handle_fragment(_read())

        assert first[0] & FIR_MASK, "FIR: this is the start of a response"
        assert not first[0] & FIN_MASK, "and not the end of one"
        assert first[0] & CON_MASK, "which the master is asked to confirm"

    def test_nothing_is_retired_until_it_is_confirmed(self):
        buffers = _filled()
        session, _ = _session(buffers)

        session._handle_fragment(_read())

        assert buffers.count(EventClass.CLASS_1) == MANY

    def test_a_response_that_fits_is_unchanged(self):
        session, _ = _session(_filled(5))

        only = session._handle_fragment(_read())

        assert only[0] & FIR_MASK and only[0] & FIN_MASK
        assert session._conversation is None


class TestConfirmingDrawsOutTheNext:
    def test_the_conversation_ends(self):
        session, _ = _session(_filled())

        fragments = _walk(session, session._handle_fragment(_read()))

        assert len(fragments) > 1, "more than one fragment"
        assert fragments[-1][0] & FIN_MASK, "and the last one says so"

    def test_only_the_first_carries_fir(self):
        session, _ = _session(_filled())

        fragments = _walk(session, session._handle_fragment(_read()))

        assert [bool(f[0] & FIR_MASK) for f in fragments] == [True] + [False] * (len(fragments) - 1)

    def test_each_fragment_takes_the_next_sequence(self):
        session, _ = _session(_filled())

        fragments = _walk(session, session._handle_fragment(_read(sequence=3)))

        assert [f[0] & 0x0F for f in fragments] == list(range(3, 3 + len(fragments)))

    def test_confirming_the_last_one_ends_it(self):
        session, _ = _session(_filled())

        fragments = _walk(session, session._handle_fragment(_read()))

        assert session._handle_fragment(_confirm(fragments[-1][0] & 0x0F)) == b""
        assert session._conversation is None

    def test_each_fragment_retires_only_its_own_events(self):
        buffers = _filled()
        session, _ = _session(buffers)

        first = session._handle_fragment(_read())
        after_first = buffers.count(EventClass.CLASS_1)
        session._handle_fragment(_confirm(first[0] & 0x0F))

        assert buffers.count(EventClass.CLASS_1) < after_first
        assert buffers.count(EventClass.CLASS_1) > 0, "and not the ones still to come"

    def test_a_master_that_stops_confirming_keeps_the_rest(self):
        buffers = _filled()
        session, _ = _session(buffers)
        session._handle_fragment(_read())

        assert buffers.count(EventClass.CLASS_1) == MANY


class TestTheSequenceWraps:
    """Sixteen sequence numbers, and a conversation may use all of them."""

    def test_a_response_beginning_at_fifteen_continues_at_zero(self):
        session, _ = _session(_filled())

        fragments = _walk(session, session._handle_fragment(_read(sequence=15)))

        assert [f[0] & 0x0F for f in fragments][:3] == [15, 0, 1]

    def test_and_the_confirmation_naming_zero_is_matched(self):
        buffers = _filled()
        session, _ = _session(buffers)
        first = session._handle_fragment(_read(sequence=15))
        second = session._handle_fragment(_confirm(15))
        before = buffers.count(EventClass.CLASS_1)

        assert second[0] & 0x0F == 0
        session._handle_fragment(_confirm(0))

        assert buffers.count(EventClass.CLASS_1) < before, "its events were retired"
        assert first[0] & 0x0F == 15


class TestALostContinuation:
    """D34. The master confirms fragment n, the continuation is lost, and the
    master repeats its confirmation of n. Ignoring it stops the conversation
    dead: the master waits for a fragment that will never come and this
    outstation for a confirmation that will never arrive."""

    def test_repeating_the_confirmation_sends_it_again(self):
        session, _ = _session(_filled())
        first = session._handle_fragment(_read())
        second = session._handle_fragment(_confirm(first[0] & 0x0F))

        again = session._handle_fragment(_confirm(first[0] & 0x0F))

        assert again == second, "byte for byte"

    def test_it_retires_nothing_a_second_time(self):
        buffers = _filled()
        session, _ = _session(buffers)
        first = session._handle_fragment(_read())
        session._handle_fragment(_confirm(first[0] & 0x0F))
        after = buffers.count(EventClass.CLASS_1)

        session._handle_fragment(_confirm(first[0] & 0x0F))

        assert buffers.count(EventClass.CLASS_1) == after

    def test_the_conversation_carries_on_from_there(self):
        session, _ = _session(_filled())
        first = session._handle_fragment(_read())
        second = session._handle_fragment(_confirm(first[0] & 0x0F))
        session._handle_fragment(_confirm(first[0] & 0x0F))

        third = session._handle_fragment(_confirm(second[0] & 0x0F))

        assert third[0] & 0x0F == (second[0] & 0x0F) + 1
        assert third != second

    def test_two_confirmations_back_is_not_replayed(self):
        """The history is one sequence deep. A master that has lost two in a
        row has lost the conversation, and its next request starts another."""
        session, _ = _session(_filled())
        first = session._handle_fragment(_read())
        second = session._handle_fragment(_confirm(first[0] & 0x0F))
        session._handle_fragment(_confirm(second[0] & 0x0F))

        assert session._handle_fragment(_confirm(first[0] & 0x0F)) == b""


class TestARequestEndsTheConversation:
    """D30. The master has moved on, and the events it did not take stay
    buffered for the read it just sent."""

    def test_a_read_mid_conversation_is_answered_as_a_read(self):
        buffers = _filled()
        session, _ = _session(buffers)
        session._handle_fragment(_read())

        fresh = session._handle_fragment(_read(sequence=1))

        assert fresh[0] & FIR_MASK, "a new response, not a continuation"
        assert buffers.count(EventClass.CLASS_1) == MANY, "and nothing was retired"

    def test_and_the_old_conversation_cannot_be_continued(self):
        session, _ = _session(_filled())
        first = session._handle_fragment(_read())
        session._handle_fragment(_read(sequence=5))

        assert session._handle_fragment(_confirm(first[0] & 0x0F)) == b""

    def test_connection_reset_leaves_every_unconfirmed_event_buffered(self):
        buffers = _filled()
        session, _ = _session(buffers)
        session._handle_fragment(_read())

        session.connection_reset()

        assert buffers.count(EventClass.CLASS_1) == MANY
        assert session._conversation is None


class TestTheBound:
    """D32. Sixteen fragments, and the last sets FIN whether or not the buffer
    is empty -- otherwise an outstation whose device polls faster than its
    master confirms never finishes answering."""

    def test_a_buffer_far_larger_than_the_bound_still_ends(self):
        buffers = _filled(8000)
        session, _ = _session(buffers)

        fragments = _walk(session, session._handle_fragment(_read()))

        assert len(fragments) == 16
        assert fragments[-1][0] & FIN_MASK
        assert buffers.count(EventClass.CLASS_1) > 0, "with events still waiting"

    def test_and_the_class_bit_goes_on_asking_for_the_rest(self):
        session, _ = _session(_filled(8000))

        fragments = _walk(session, session._handle_fragment(_read()))

        assert fragments[-1][2] & 0x02, "class 1 events are still there"


class TestTheProviderIsAskedOncePerResponse:
    """D33 reads the body when the response begins and holds it until the last
    fragment. Asking again per fragment would turn one logical read into
    several against a caller that may poll a device to answer."""

    def test_however_many_fragments_it_takes(self):
        session, provider = _session(_filled(), static=100)

        fragments = _walk(session, session._handle_fragment(INTEGRITY))

        assert len(fragments) > 1
        assert provider.calls == 1

    def test_and_a_second_response_asks_again(self):
        """Under a different sequence, or it is a retransmission and D25
        replays the first answer rather than building a second."""
        session, provider = _session(_filled(5), static=100)

        session._handle_fragment(INTEGRITY)
        session._handle_fragment(bytes([0xC1]) + INTEGRITY[1:])

        assert provider.calls == 2

    def test_a_repeated_request_replays_rather_than_re_reading(self):
        """D25 one layer down: the cached answer is sent again, so the provider
        is not asked to produce a second one that might differ from it."""
        session, provider = _session(_filled(5), static=100)

        first = session._handle_fragment(INTEGRITY)
        repeat = session._handle_fragment(INTEGRITY)

        assert repeat == first
        assert provider.calls == 1


class TestABodyThatWillNotFitBesideTheLastEvents:
    """D33's awkward corner, and the one the fit argument is actually about.
    The events are done, but the body cannot ride with them -- so it takes a
    fragment of its own rather than displacing events to make room."""

    #: Enough events to fill a 2,048-octet fragment exactly, and a body far too
    #: large to follow them into it.
    EVENTS = 170
    STATIC = 1000

    def _session(self):
        return _session(_filled(self.EVENTS), static=self.STATIC)

    def test_the_events_are_not_trimmed_for_it(self):
        session, provider = self._session()

        first = session._handle_fragment(INTEGRITY)

        assert provider.body not in first, "the body is not here"
        assert not first[0] & FIN_MASK, "and the response is not over"
        assert len(first) == 2048, "the events had the whole fragment"

    def test_it_follows_in_one_of_its_own(self):
        session, provider = self._session()

        fragments = _walk(session, session._handle_fragment(INTEGRITY))

        assert len(fragments) == 2
        assert fragments[-1][0] & FIN_MASK
        assert fragments[-1][4:] == provider.body, "the body alone, and all of it"

    def test_and_the_response_still_honours_the_ceiling(self):
        """The case the mutation found: attaching the body regardless would
        send a fragment the master cannot receive."""
        session, _ = self._session()

        for fragment in _walk(session, session._handle_fragment(INTEGRITY)):
            assert len(fragment) <= 2048


def _counted(asked: int, sequence: int = 0) -> bytes:
    """A class 1 read asking for at most *asked* events, wide count."""
    return bytes(
        [0xC0 | sequence, FunctionCode.READ, 60, 2, QualifierCode.UINT16_COUNT]
    ) + asked.to_bytes(2, "little")


#: The groups an event block can carry. Anything else in a response body is the
#: provider's static data, which travels last (D33) and is not walked here.
_EVENT_GROUPS = (2, 32)


def _carried(fragments: list[bytes]) -> int:
    """How many events a whole response delivered, across all its fragments.

    Stops at the first block that is not an event group rather than walking on
    into the static body, whose objects this parser knows nothing about.
    """
    total = 0
    for fragment in fragments:
        body = fragment[4:]
        while len(body) >= 4 and body[0] in _EVENT_GROUPS:
            wide = body[2] == QualifierCode.UINT16_COUNT_UINT16_INDEX
            count = int.from_bytes(body[3:5], "little") if wide else body[3]
            header, item = (5, 13) if wide else (4, 12)
            total += count
            body = body[header + count * item :]
    return total


class TestACountIsABoundOnTheResponse:
    """Not on each fragment of it. Reapplying it whole to every continuation
    answers a request for three hundred events with as many as the buffer
    holds, three hundred at a time."""

    def test_a_count_spanning_fragments_delivers_exactly_that_many(self):
        session, _ = _session(_filled(1000))

        fragments = _walk(session, session._handle_fragment(_counted(300)))

        assert len(fragments) > 1, "it did not fit one fragment"
        assert _carried(fragments) == 300

    def test_and_the_response_ends_there(self):
        """FIN once the count is spent, with the rest still buffered -- the
        master asked for three hundred and is not owed the other seven."""
        buffers = _filled(1000)
        session, _ = _session(buffers)

        fragments = _walk(session, session._handle_fragment(_counted(300)))

        assert fragments[-1][0] & FIN_MASK
        assert buffers.count(EventClass.CLASS_1) > 0

    def test_a_count_larger_than_the_buffer_is_not_an_error(self):
        session, _ = _session(_filled(1000))

        fragments = _walk(session, session._handle_fragment(_counted(1200)))

        assert _carried(fragments) == 1000
        assert fragments[-1][0] & FIN_MASK

    def test_a_count_that_fits_one_fragment_is_unchanged(self):
        session, _ = _session(_filled(1000))

        only = session._handle_fragment(_counted(100))

        assert only[0] & FIN_MASK
        assert _carried([only]) == 100

    def test_each_header_keeps_its_own(self):
        """Two classes, two counts, and neither borrows from the other."""
        # Distinct indices per class. The deadband is keyed by point rather
        # than by class -- a point belongs to one class -- so recording the same
        # index into both would have the second call suppressed as unchanged.
        buffers = EventBuffers(capacity=2000)
        for index in range(1000):
            buffers.record_analog(
                index, AnalogPoint(float(index)), event_class=EventClass.CLASS_1, timestamp_ms=1
            )
            buffers.record_analog(
                1000 + index,
                AnalogPoint(float(index)),
                event_class=EventClass.CLASS_2,
                timestamp_ms=1,
            )
        session, _ = _session(buffers)
        request = (
            bytes([0xC0, FunctionCode.READ])
            + bytes([60, 2, QualifierCode.UINT16_COUNT])
            + (200).to_bytes(2, "little")
            + bytes([60, 3, QualifierCode.UINT16_COUNT])
            + (300).to_bytes(2, "little")
        )

        fragments = _walk(session, session._handle_fragment(request))

        assert _carried(fragments) == 500


class TestTheBoundHoldsWithABodyToDeliver:
    """The bound decides when the events stop, and the body has to travel in
    the fragment that ends the response. A body too large to follow a full
    fragment of events would otherwise defer the ending every time, and the
    bound would bound nothing."""

    def test_a_large_body_does_not_let_the_response_run_past_it(self):
        session, _ = _session(_filled(6000), static=1500)

        fragments = _walk(session, session._handle_fragment(INTEGRITY), limit=80)

        assert len(fragments) == 16, "not the forty this ran to before"
        assert fragments[-1][0] & FIN_MASK

    def test_and_the_body_still_arrives(self):
        """Stopping the events is not an excuse to drop the static data the
        same request asked for."""
        session, provider = _session(_filled(6000), static=1500)

        fragments = _walk(session, session._handle_fragment(INTEGRITY), limit=80)

        assert fragments[-1][4:].endswith(provider.body)

    def test_every_fragment_still_honours_the_ceiling(self):
        session, _ = _session(_filled(6000), static=1500)

        for fragment in _walk(session, session._handle_fragment(INTEGRITY), limit=80):
            assert len(fragment) <= 2048

    def test_a_count_above_the_bound_does_not_reduce_what_the_bound_delivers(self):
        """The refit that makes the body fit runs `_event_body` a second time
        and decrements the counts as it goes. Without putting them back first,
        the last fragment is short by whatever the discarded fit placed --
        events the master asked for and never received.

        It only shows where the count is still live at the last fragment *and*
        the budget is what cuts it there, which is a count a little above what
        the response delivers: far enough that the count does not end it, close
        enough that the double decrement drives the remainder to nothing. Hence
        the range rather than one number, and the baseline rather than a
        constant."""
        calibrate, _ = _session(_filled(6000), static=1500)
        baseline = _carried(_walk(calibrate, calibrate._handle_fragment(INTEGRITY), limit=80))

        for extra in (130, 140, 150):
            counted = (
                bytes([0xC0, FunctionCode.READ, 60, 2, QualifierCode.UINT16_COUNT])
                + (baseline + extra).to_bytes(2, "little")
                + bytes([60, 1, 0x06])
            )
            session, _ = _session(_filled(6000), static=1500)

            fragments = _walk(session, session._handle_fragment(counted), limit=80)

            assert _carried(fragments) == baseline, f"asking for {extra} more delivered fewer"


class TestALostFinalFragment:
    """The fragment most worth replaying is the one that ends the response.
    Losing it strands a master with nothing left to confirm and no way to ask
    again -- the same deadlock D34 exists to prevent, at the last step."""

    def _to_the_end(self, session, first):
        fragments = _walk(session, first)
        return fragments[-1], fragments[-2][0] & 0x0F

    def test_repeating_the_confirmation_before_it_sends_it_again(self):
        session, _ = _session(_filled())
        last, before = self._to_the_end(session, session._handle_fragment(_read()))

        again = session._handle_fragment(_confirm(before))

        assert again == last, "byte for byte"

    def test_confirming_it_ends_the_conversation(self):
        session, _ = _session(_filled())
        last, _ = self._to_the_end(session, session._handle_fragment(_read()))

        assert session._handle_fragment(_confirm(last[0] & 0x0F)) == b""
        assert session._conversation is None

    def test_and_then_there_is_nothing_left_to_replay(self):
        session, _ = _session(_filled())
        last, before = self._to_the_end(session, session._handle_fragment(_read()))
        session._handle_fragment(_confirm(last[0] & 0x0F))

        assert session._handle_fragment(_confirm(before)) == b""

    def test_a_response_of_one_fragment_holds_nothing_open(self):
        """There was never a continuation to lose, so there is nothing to keep
        for the replaying of it."""
        session, _ = _session(_filled(5))

        only = session._handle_fragment(_read())

        assert only[0] & FIN_MASK
        assert session._conversation is None
