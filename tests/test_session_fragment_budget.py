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

from py1815.application import CON_MASK, FunctionCode, IINBit, QualifierCode
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
