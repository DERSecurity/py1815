"""Answering with as much as the master can receive, and no more.

A master advertises the largest fragment it will accept and sizes its receive
buffer to match. An outstation that sends past it produces a fragment the
master discards, which is worse than a short answer -- the events were readable
and now none of them arrived.

Until application-layer fragmentation lands (section 3 of the event plan) this
caps rather than splits: what does not fit stays buffered, the class indication
bits go on asking for it, and the next read brings it.
"""

from __future__ import annotations

import pytest

from py1815 import session as session_module
from py1815.application import CON_MASK, FunctionCode, IIN2Bit, IINBit, QualifierCode
from py1815.events import EventBuffers, EventClass
from py1815.objects import AnalogPoint, BinaryPoint
from py1815.session import Session

#: A full default buffer: 1,000 analog events, each eleven octets behind a
#: one-octet index.
FULL = 1000

#: What fits 2,048 octets. Four for the application header, four for the object
#: header, then twelve per event -- an index and the event -- so the largest n
#: with 8 + 12n <= 2048 is 170, and the response lands on 2,048 exactly.
FITS = 170


class Provider:
    """Static data of a size the test chooses."""

    def __init__(self, octets: int = 0) -> None:
        self.body = bytes([30, 1, 0, 0, 0, 1]) + bytes(octets) if octets else b""

    def read(self, headers):
        return self.body


def _filled(count: int = FULL) -> EventBuffers:
    buffers = EventBuffers()
    for index in range(count):
        buffers.record_analog(
            index, AnalogPoint(float(index)), event_class=EventClass.CLASS_1, timestamp_ms=1
        )
    return buffers


def _session(buffers: EventBuffers, *, max_response: int = 2048, static: int = 0) -> Session:
    return Session(Provider(static), events=buffers, max_response=max_response)


def _read(event_class: int = 1, sequence: int = 0) -> bytes:
    variation = {0: 1, 1: 2, 2: 3, 3: 4}[event_class]
    return bytes([0xC0 | sequence, FunctionCode.READ, 60, variation, QualifierCode.ALL_OBJECTS])


def _confirm(sequence: int = 0) -> bytes:
    return bytes([0xC0 | sequence, FunctionCode.CONFIRM])


class TestAFullBufferDoesNotOverrunTheMaster:
    def test_the_response_fits(self):
        """The defect this covers: nothing bounded an outgoing fragment, so a
        default buffer answered a class read with some 13,000 octets."""
        session = _session(_filled())

        assert len(session._handle_fragment(_read())) <= 2048

    def test_and_fills_it_to_the_octet(self):
        """Short of the ceiling by a whole event would be leaving room the
        master offered unused, and a read costs a round trip."""
        session = _session(_filled())

        assert len(session._handle_fragment(_read())) == 2048

    def test_the_count_says_how_many_came(self):
        session = _session(_filled())

        response = session._handle_fragment(_read())

        assert response[6] == QualifierCode.UINT8_COUNT_UINT8_INDEX
        assert response[7] == FITS

    def test_one_octet_less_carries_one_event_less(self):
        """The boundary is real rather than approximate -- the selection is
        bisected against the encoder, not estimated from a per-event cost."""
        session = _session(_filled(), max_response=2047)

        assert session._handle_fragment(_read())[7] == FITS - 1


class TestWhatDidNotFitStaysBuffered:
    def test_the_confirmation_retires_only_what_was_sent(self):
        buffers = _filled()
        session = _session(buffers)
        session._handle_fragment(_read())

        session._handle_fragment(_confirm())

        assert buffers.count(EventClass.CLASS_1) == FULL - FITS

    def test_the_next_read_brings_the_remainder(self):
        buffers = _filled()
        session = _session(buffers)
        session._handle_fragment(_read())
        session._handle_fragment(_confirm())

        following = session._handle_fragment(_read(sequence=1))

        # Fewer than the first response carried, and correctly so: these events
        # sit at indices 170 and up, which no longer fit an octet, so each costs
        # a two-octet prefix and the header widens with them. The fit follows
        # the encoding rather than a count.
        assert following[6] == QualifierCode.UINT16_COUNT_UINT16_INDEX
        assert following[7:9] == (156).to_bytes(2, "little")
        assert buffers.peek(EventClass.CLASS_1)[0].index == FITS

    def test_the_class_bit_goes_on_asking_for_it(self):
        """How the master learns to read again. Deriving the bits from the
        buffer (D22) is what makes this work without bookkeeping."""
        buffers = _filled()
        session = _session(buffers)
        session._handle_fragment(_read())
        session._handle_fragment(_confirm())

        assert session._handle_fragment(_read(0, sequence=1))[2] & IINBit.CLASS_1_EVENTS


class TestStaticDataIsPaidForFirst:
    """It cannot be trimmed -- it is the provider's answer, and this session
    cannot tell where one object in it ends. So the events are fitted to what
    is left, even though they travel in front of it (D20)."""

    #: Classes 1 and 0 in one request -- the integrity poll a real master
    #: sends, and the only shape in which static data and events share a
    #: response. A class read alone never reaches the provider.
    INTEGRITY = bytes([0xC0, FunctionCode.READ, 60, 2, 0x06, 60, 1, 0x06])

    def test_fewer_events_fit_beside_it(self):
        session = _session(_filled(), static=1000)

        response = session._handle_fragment(self.INTEGRITY)

        assert response[7] < FITS
        assert len(response) <= 2048

    def test_an_integrity_poll_still_carries_both(self):
        session = _session(_filled(), static=100)

        body = session._handle_fragment(self.INTEGRITY)[4:]

        assert body[0] == 32, "the events lead"
        assert body.endswith(Provider(100).body), "and the static data follows"

    def test_room_for_nothing_sends_no_events(self):
        """Not an error, and not a fragment with half an object in it. The
        events stay where they are and the indication bit still points at
        them."""
        session = _session(_filled(), max_response=16)

        response = session._handle_fragment(_read())

        assert response[4:] == b""
        assert not response[0] & CON_MASK, "nothing was sent, so nothing is awaited"
        assert response[2] & IINBit.CLASS_1_EVENTS


class TestARunCutShortIsWhereTheResponseEnds:
    """Not where the fitting pauses. Events are reported in the order the
    points changed, so emitting a later block that happens to fit the slack an
    earlier truncation left would hand the master a change without the changes
    that came before it."""

    #: Forty analog events at indices 300 and up -- past an octet, so each
    #: costs a two-octet prefix and the header widens -- then one binary event.
    #: At this ceiling ten analog events fit exactly, and the twelve octets
    #: left over are exactly one binary block: the one arrangement in which
    #: continuing past the cut would send something.
    CEILING = 4 + 5 + 13 * 10 + 12
    ANALOG_BLOCK = 5 + 13 * 10

    @staticmethod
    def _buffers() -> EventBuffers:
        buffers = EventBuffers()
        for index in range(300, 340):
            buffers.record_analog(
                index, AnalogPoint(float(index)), event_class=EventClass.CLASS_1, timestamp_ms=1
            )
        buffers.record_binary(
            5, BinaryPoint(state=True), event_class=EventClass.CLASS_1, timestamp_ms=2
        )
        return buffers

    def test_the_binary_event_behind_it_is_not_brought_forward(self):
        session = _session(self._buffers(), max_response=self.CEILING)

        body = session._handle_fragment(_read())[4:]

        assert body[0] == 32, "the analog run leads"
        assert len(body) == self.ANALOG_BLOCK, "and nothing follows it"

    def test_the_slack_is_left_unused_on_purpose(self):
        session = _session(self._buffers(), max_response=self.CEILING)

        response = session._handle_fragment(_read())

        assert len(response) == self.CEILING - 12
        assert response[0] & CON_MASK, "what did go out is still awaiting confirmation"


class TestABlockOneOctetOverTheCeiling:
    """The whole-block shortcut is checked against the same budget as the
    bisection below it. One octet of slack there would send a fragment the
    master cannot receive, which is the failure the ceiling exists to stop."""

    #: Ten events, narrow throughout: a four-octet header and twelve octets
    #: each. The response is 128, so a ceiling of 127 puts the whole block
    #: exactly one octet over.
    WHOLE = 4 + 12 * 10

    def test_it_is_bisected_rather_than_waved_through(self):
        session = _session(_filled(10), max_response=self.WHOLE + 3)

        response = session._handle_fragment(_read())

        assert len(response) <= self.WHOLE + 3
        assert response[7] == 9, "one event short of the block that did not fit"


class TestACeilingBelowTheHeader:
    """Four octets before a response carries anything, so a smaller ceiling is
    one nothing can honour -- including the refusal that would be given
    instead. Refused where the number is rather than logged on every response
    that overruns it."""

    @pytest.mark.parametrize("ceiling", [0, 1, 3, -1])
    def test_it_is_refused_at_construction(self, ceiling):
        with pytest.raises(ValueError, match="max_response"):
            Session(Provider(), max_response=ceiling)

    def test_room_for_a_header_and_nothing_else_is_allowed(self):
        """Useless but coherent: every answer is a null response, which is a
        configuration to honour rather than one to second-guess."""
        session = Session(Provider(), events=_filled(10), max_response=4)

        response = session._handle_fragment(_read())

        assert len(response) == 4
        assert response[2] & IINBit.CLASS_1_EVENTS, "still asking for what it cannot send"
        assert not response[0] & CON_MASK


class TestStaticDataThatWillNotFitOnItsOwn:
    """The one overrun the events cannot be fitted around, since they are
    fitted to what is left after the provider. The body is opaque here, so
    trimming it would cut an object in half -- and sending it past the ceiling
    loses the whole response and says nothing about why."""

    #: 106 octets of static data against a ceiling of sixteen.
    TOO_MUCH = 100
    CEILING = 16
    STATIC_READ = bytes([0xC0, FunctionCode.READ, 60, 1, QualifierCode.ALL_OBJECTS])
    INTEGRITY = bytes([0xC0, FunctionCode.READ, 60, 2, 0x06, 60, 1, 0x06])

    def test_the_read_is_refused_within_the_ceiling(self):
        session = _session(EventBuffers(), max_response=self.CEILING, static=self.TOO_MUCH)

        response = session._handle_fragment(self.STATIC_READ)

        assert len(response) <= self.CEILING
        assert response[3] & IIN2Bit.PARAM_ERROR
        assert response[4:] == b"", "not the body that did not fit, nor part of it"

    def test_an_integrity_poll_is_refused_the_same_way(self):
        session = _session(_filled(), max_response=self.CEILING, static=self.TOO_MUCH)

        response = session._handle_fragment(self.INTEGRITY)

        assert response[3] & IIN2Bit.PARAM_ERROR
        assert not response[0] & CON_MASK, "nothing was sent, so nothing is awaited"

    def test_and_leaves_its_events_buffered(self):
        """Nothing was recorded as outstanding, so the confirmation a confused
        master might send retires nothing and the events wait for a request
        that fits."""
        buffers = _filled()
        session = _session(buffers, max_response=self.CEILING, static=self.TOO_MUCH)
        session._handle_fragment(self.INTEGRITY)

        session._handle_fragment(_confirm())

        assert buffers.count(EventClass.CLASS_1) == FULL

    #: Six octets of object header and then the hundred, answered under a
    #: four-octet response header.
    EXACT = 4 + 6 + TOO_MUCH

    def test_static_data_that_fits_exactly_is_answered(self):
        """The boundary, so the refusal cannot be a blanket one."""
        session = _session(EventBuffers(), max_response=self.EXACT, static=self.TOO_MUCH)

        response = session._handle_fragment(self.STATIC_READ)

        assert len(response) == self.EXACT
        assert not response[3] & IIN2Bit.PARAM_ERROR

    def test_one_octet_over_is_refused(self):
        """The other side of the same boundary. A ceiling the response misses
        by one is a ceiling the response misses."""
        session = _session(EventBuffers(), max_response=self.EXACT - 1, static=self.TOO_MUCH)

        response = session._handle_fragment(self.STATIC_READ)

        assert response[3] & IIN2Bit.PARAM_ERROR
        assert response[4:] == b""


class TestTheBudgetBoundsTheWorkAndNotJustTheOctets:
    """`capacity` has no upper bound, so anything proportional to the buffer is
    proportional to a number the operator chose and a peer can make it pay on
    every read. The selection is cut to what could possibly fit before anything
    is encoded, and the buffer is asked for no more than that."""

    BIG = 20_000

    @classmethod
    def _buffers(cls) -> EventBuffers:
        buffers = EventBuffers(capacity=cls.BIG)
        for index in range(cls.BIG):
            buffers.record_analog(
                index % 60_000,
                AnalogPoint(float(index)),
                event_class=EventClass.CLASS_1,
                timestamp_ms=1,
            )
        return buffers

    @staticmethod
    def _counting(monkeypatch) -> list[int]:
        calls = [0]
        real = session_module.encode_analog_event

        def counted(*args, **kwargs):
            calls[0] += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(session_module, "encode_analog_event", counted)
        return calls

    def test_a_response_with_no_room_encodes_nothing(self, monkeypatch):
        calls = self._counting(monkeypatch)
        session = _session(self._buffers(), max_response=4)

        assert session._handle_fragment(_read())[4:] == b""
        assert calls[0] == 0, "not one event of twenty thousand"

    def test_a_full_response_encodes_about_what_it_sends(self, monkeypatch):
        calls = self._counting(monkeypatch)
        session = _session(self._buffers())

        response = session._handle_fragment(_read())

        assert len(response) == 2048
        # The bound is what could fit at the narrowest an event encodes, so it
        # runs ahead of what actually fits. Ahead by a factor, not by a buffer.
        assert calls[0] < 400, f"{calls[0]} encodings for a 2,048-octet response"

    def test_a_class_named_twice_still_fills_the_response(self):
        """The bound asks the buffer for what deduplication is about to remove
        as well as what fits. Without that the second header would come back
        short, which a small buffer never shows."""
        once = _session(self._buffers())._handle_fragment(_read())
        twice = _session(self._buffers())._handle_fragment(
            bytes([0xC0, FunctionCode.READ, 60, 2, 0x06, 60, 2, 0x06])
        )

        assert twice == once

    def test_a_capped_header_does_not_shorten_the_one_after_it(self):
        """Where forgetting the deduplication actually shows, which needs the
        first header to take enough that the second's allowance no longer
        covers both. The bound is struck at the narrowest an event encodes, so
        a small first header leaves slack that hides the mistake."""
        capped = bytes(
            [0xC0, FunctionCode.READ, 60, 2, QualifierCode.UINT8_COUNT, 100, 60, 2, 0x06]
        )

        body = _session(self._buffers())._handle_fragment(capped)[4:]

        assert body[3] == 100, "the counted header"
        second = 4 + 100 * 12
        assert body[second] == 32, "a second block follows it"
        # 840 octets left, four of them the header, twelve an event: 69. Short
        # of that means the buffer was asked for the room and not for the
        # hundred deduplication was about to take out of it.
        assert body[second + 3] == 69
        assert body[second + 4] == 100, "carrying on where the first left off"


class TestACeilingLargerThanAnyFragment:
    """No upper bound is enforced on `max_response`, so the read path has to
    survive one. The budget it derives reaches the buffer as a limit, and the
    iterator underneath that has a ceiling Python integers do not."""

    def test_a_read_is_still_answered(self):
        session = _session(_filled(20), max_response=10**100)

        response = session._handle_fragment(_read())

        assert response[7] == 20, "the whole class, since everything fits"
