"""Reading events, and saying there are some.

Sections 1 and 4 of the event plan. Nothing here confirms anything yet: an
event leaves the buffer when the master confirms the response carrying it
(D18), and until that lands a master reading twice sees the same events twice.
The tests say so where it matters rather than asserting the interim as if it
were the destination.
"""

from __future__ import annotations

import pytest

from py1815.application import FunctionCode, IIN2Bit, IINBit, QualifierCode
from py1815.events import EventBuffers, EventClass
from py1815.objects import AnalogPoint, BinaryPoint
from py1815.session import Session

#: Group 60 variation 2 is class 1, 3 is class 2, 4 is class 3. Variation 1 is
#: class 0, which is static data and stays the provider's.
CLASS_VARIATION = {0: 1, 1: 2, 2: 3, 3: 4}


class Reader:
    """A read provider that records what it was asked for."""

    def __init__(self, body: bytes = b"\x1e\x01\x00\x00\x00\x01\x2a\x00\x00\x00") -> None:
        self.body = body
        self.headers: list = []

    def read(self, headers):
        self.headers = list(headers)
        return self.body


def _session(buffers: EventBuffers | None = None, reader: Reader | None = None):
    r = reader or Reader()
    return Session(r, events=buffers), r


def _read(*classes: int, sequence: int = 0) -> bytes:
    """A read naming one or more classes, all objects."""
    body = b""
    for cls in classes:
        body += bytes([60, CLASS_VARIATION[cls], QualifierCode.ALL_OBJECTS])
    return bytes([0xC0 | sequence, FunctionCode.READ]) + body


def _filled(**per_class: int) -> EventBuffers:
    """Buffers holding *n* analog events in each named class."""
    buffers = EventBuffers()
    index = 0
    for name, count in per_class.items():
        event_class = EventClass[name.upper()]
        for _ in range(count):
            buffers.record_analog(
                index, AnalogPoint(float(index)), event_class=event_class, timestamp_ms=1
            )
            index += 1
    return buffers


class TestAClassReadAnswersFromTheBuffers:
    #: Group 32 variation 3 is flags, an int32 and a six-octet time, and each
    #: event sits behind a one-octet index.
    EVENT_OCTETS = 1 + (1 + 4 + 6)
    HEADER_OCTETS = 4

    def test_class_one_returns_its_events_and_not_another_class(self):
        buffers = _filled(class_1=2, class_2=3)
        session, _ = _session(buffers)

        body = session._handle_fragment(_read(1))[4:]

        assert body[0] == 32
        assert body[3] == 2, "two events, not the five in the buffers"
        # The whole body, not just the first block. Checking the count alone
        # passes an outstation that answers class 1 correctly and then appends
        # every other class after it.
        assert len(body) == self.HEADER_OCTETS + 2 * self.EVENT_OCTETS

    def test_the_other_classes_are_not_appended_after_it(self):
        buffers = _filled(class_1=1, class_2=1, class_3=1)
        session, _ = _session(buffers)

        body = session._handle_fragment(_read(2))[4:]

        assert len(body) == self.HEADER_OCTETS + self.EVENT_OCTETS

    def test_two_classes_are_both_answered(self):
        session, _ = _session(_filled(class_1=1, class_2=1))

        body = session._handle_fragment(_read(1, 2))[4:]

        assert body[3] == 1
        second = 4 + (1 + 11)
        assert body[second] == 32
        assert body[second + 3] == 1

    def test_a_class_with_nothing_in_it_is_an_empty_answer(self):
        """Not an error. A master polls a class to find out whether anything
        happened, and nothing happening is one of the answers."""
        session, _ = _session(EventBuffers())

        response = session._handle_fragment(_read(1))

        assert response[1] == FunctionCode.RESPONSE
        assert response[4:] == b""

    def test_the_provider_is_not_asked_for_an_event_class(self):
        session, reader = _session(_filled(class_1=1))

        session._handle_fragment(_read(1))

        assert reader.headers == []


class TestClassZeroIsStillTheProviders:
    def test_it_reaches_the_provider(self):
        session, reader = _session(_filled(class_1=1))

        body = session._handle_fragment(_read(0))[4:]

        assert [h.variation for h in reader.headers] == [1]
        assert body == reader.body

    def test_an_integrity_poll_carries_events_before_static_data(self):
        """D20. A master applies a fragment in order, so a static value written
        after the events that led to it leaves the point where it should end
        up."""
        session, reader = _session(_filled(class_1=1))

        body = session._handle_fragment(_read(1, 0))[4:]

        assert body[0] == 32, "the event block leads"
        assert body.endswith(reader.body), "and the static data follows it"


class TestWithoutBuffers:
    """An outstation with no events configured behaves as it always has."""

    def test_a_class_one_read_goes_to_the_provider(self):
        session, reader = _session(None)

        body = session._handle_fragment(_read(1))[4:]

        assert [h.variation for h in reader.headers] == [2]
        assert body == reader.body

    def test_no_class_indications_are_set(self):
        session, _ = _session(None)

        response = session._handle_fragment(_read(0))

        assert not response[2] & IINBit.CLASS_1_EVENTS


class TestTheIndicationBits:
    """D22: derived from the buffers on every response, so they cannot drift."""

    @pytest.mark.parametrize(
        ("name", "bit", "neighbours"),
        [
            ("class_1", IINBit.CLASS_1_EVENTS, (IINBit.CLASS_2_EVENTS, IINBit.CLASS_3_EVENTS)),
            ("class_2", IINBit.CLASS_2_EVENTS, (IINBit.CLASS_1_EVENTS, IINBit.CLASS_3_EVENTS)),
            ("class_3", IINBit.CLASS_3_EVENTS, (IINBit.CLASS_1_EVENTS, IINBit.CLASS_2_EVENTS)),
        ],
    )
    def test_one_class_sets_its_own_bit_and_neither_neighbour(self, name, bit, neighbours):
        session, _ = _session(_filled(**{name: 1}))

        first = session._handle_fragment(_read(0))[2]

        assert first & bit
        assert not any(first & other for other in neighbours)

    def test_an_empty_buffer_sets_none_of_them(self):
        session, _ = _session(EventBuffers())

        first = session._handle_fragment(_read(0))[2]

        assert not first & (IINBit.CLASS_1_EVENTS | IINBit.CLASS_2_EVENTS | IINBit.CLASS_3_EVENTS)

    def test_the_bit_follows_the_buffer_rather_than_a_counter(self):
        """The point of deriving them. Dropping the events clears the bit with
        no bookkeeping in between to get wrong."""
        buffers = _filled(class_1=1)
        session, _ = _session(buffers)
        assert session._handle_fragment(_read(0))[2] & IINBit.CLASS_1_EVENTS

        buffers.drop(buffers.peek(EventClass.CLASS_1))

        assert not session._handle_fragment(_read(0))[2] & IINBit.CLASS_1_EVENTS


class TestOverflow:
    def test_a_full_buffer_reports_it(self):
        buffers = EventBuffers(capacity=1)
        for index in range(3):
            buffers.record_analog(
                index, AnalogPoint(float(index)), event_class=EventClass.CLASS_1, timestamp_ms=1
            )
        session, _ = _session(buffers)

        second = session._handle_fragment(_read(0))[3]

        assert second & IIN2Bit.EVENT_BUFFER_OVERFLOW

    def test_a_buffer_within_capacity_does_not(self):
        session, _ = _session(_filled(class_1=1))

        second = session._handle_fragment(_read(0))[3]

        assert not second & IIN2Bit.EVENT_BUFFER_OVERFLOW


class TestBinaryEventsTravelInTheirOwnBlock:
    def test_a_run_of_each_kind_becomes_two_blocks(self):
        """Ordered as the points changed rather than gathered by type:
        reordering them would tell the master a different story about when
        things happened."""
        buffers = EventBuffers()
        buffers.record_analog(0, AnalogPoint(1.0), event_class=EventClass.CLASS_1, timestamp_ms=1)
        buffers.record_binary(
            1, BinaryPoint(state=True), event_class=EventClass.CLASS_1, timestamp_ms=2
        )
        session, _ = _session(buffers)

        body = session._handle_fragment(_read(1))[4:]

        assert body[0] == 32, "analog event group"
        analog_block = 4 + (1 + 11)
        assert body[analog_block] == 2, "binary event group"


def _read_qualified(cls: int, qualifier: int, extra: bytes = b"") -> bytes:
    return bytes([0xC0, FunctionCode.READ, 60, CLASS_VARIATION[cls], qualifier]) + extra


class TestWhatQualifierAClassReadMayCarry:
    """A class is a reporting priority, not a set of points, so a start and a
    stop name nothing on one. Answering such a request with the whole buffer
    would tell a master its selection was honoured when it was ignored."""

    #: Each refused qualifier with the payload its own parse path expects.
    #: The two index-prefixed forms are read through different code -- one
    #: octet of count and index versus two -- so covering only the narrow one
    #: would let a regression accepting the wide one pass.
    @pytest.mark.parametrize(
        ("qualifier", "payload"),
        [
            (QualifierCode.UINT8_START_STOP, bytes(2)),
            (QualifierCode.UINT16_START_STOP, bytes(4)),
            (QualifierCode.UINT8_COUNT_UINT8_INDEX, bytes(1)),
            (QualifierCode.UINT16_COUNT_UINT16_INDEX, bytes(2)),
        ],
    )
    def test_a_qualifier_that_selects_nothing_is_refused(self, qualifier, payload):
        session, _ = _session(_filled(class_1=3))

        response = session._handle_fragment(_read_qualified(1, qualifier, payload))

        assert response[3] & IIN2Bit.PARAM_ERROR
        assert response[4:] == b"", "refused rather than answered with everything"

    def test_all_objects_returns_the_whole_class(self):
        session, _ = _session(_filled(class_1=3))

        body = session._handle_fragment(_read(1))[4:]

        assert body[3] == 3


class TestACountLimitsWhatComesBack:
    """ "At most this many", which is how a master paces a buffer it does not
    want in one fragment."""

    def test_fewer_than_the_buffer_holds(self):
        session, _ = _session(_filled(class_1=5))

        body = session._handle_fragment(_read_qualified(1, QualifierCode.UINT8_COUNT, bytes([2])))[
            4:
        ]

        assert body[3] == 2

    def test_a_count_larger_than_the_buffer_is_not_an_error(self):
        session, _ = _session(_filled(class_1=2))

        body = session._handle_fragment(_read_qualified(1, QualifierCode.UINT8_COUNT, bytes([50])))[
            4:
        ]

        assert body[3] == 2

    def test_a_count_of_zero_returns_nothing(self):
        session, _ = _session(_filled(class_1=3))

        response = session._handle_fragment(
            _read_qualified(1, QualifierCode.UINT8_COUNT, bytes([0]))
        )

        assert response[4:] == b""
        assert not response[3] & IIN2Bit.PARAM_ERROR, "asking for none is not an error"


class TestAClassNamedTwice:
    def test_its_events_are_not_sent_twice(self):
        """A master naming a class twice asked about it twice. Sending each
        event once per header would tell it the same change happened more than
        once."""
        session, _ = _session(_filled(class_1=2))

        body = session._handle_fragment(_read(1, 1))[4:]

        assert body[3] == 2
        assert len(body) == 4 + 2 * (1 + 11), "one block, not two"

    def test_header_order_is_the_masters(self):
        session, _ = _session(_filled(class_1=1, class_3=1))

        body = session._handle_fragment(_read(3, 1))[4:]

        # The class 3 event was recorded second, so index 1 leads if the order
        # is the master's and index 0 leads if it is the class number's.
        assert body[4] == 1
