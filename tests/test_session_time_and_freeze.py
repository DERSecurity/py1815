"""Time synchronization, freezes, and reading an event group by name.

The functions and objects the IEEE 1815.2 implementation table adds to what
the session already answered: a master writes the time and measures the delay,
freezes the counters, and may ask for binary, analog or frozen counter events
by their own group instead of by class.
"""

from __future__ import annotations

import struct

import pytest

from py1815.application import FunctionCode, IIN2Bit, IINBit, QualifierCode
from py1815.events import EventBuffers, EventClass
from py1815.objects import AnalogEventVariation, AnalogPoint, BinaryPoint, CounterPoint
from py1815.session import Session, UnknownObject

ALL = QualifierCode.ALL_OBJECTS


class Reader:
    def __init__(self) -> None:
        self.headers: list = []

    def read(self, headers):
        self.headers = list(headers)
        if any(header.group not in (60, 30) for header in headers):
            raise UnknownObject("not served")
        return b""


class Freezer:
    """A freeze provider that records what it was asked to freeze."""

    def __init__(self, known: tuple[int, ...] = (20,)) -> None:
        self.calls: list[tuple[list, bool]] = []
        self.known = known

    def freeze(self, headers, *, clear):
        if any(header.group not in self.known for header in headers):
            raise UnknownObject("not a counter")
        self.calls.append((list(headers), clear))


def _request(function: FunctionCode, body: bytes = b"", sequence: int = 0) -> bytes:
    return bytes([0xC0 | sequence, function]) + body


def _iin(response: bytes) -> tuple[int, int]:
    return response[2], response[3]


class TestWritingTheTime:
    WRITE = bytes([50, 1, QualifierCode.UINT8_COUNT, 1])

    def _session(self, **kwargs) -> tuple[Session, list[int]]:
        written: list[int] = []
        return Session(Reader(), time_sink=written.append, **kwargs), written

    def test_the_time_reaches_the_sink_in_milliseconds(self):
        session, written = self._session()
        moment = 1_800_000_000_123
        response = session._handle_fragment(
            _request(FunctionCode.WRITE, self.WRITE + moment.to_bytes(6, "little"))
        )
        assert written == [moment]
        assert not _iin(response)[1], "an accepted write reports no error"

    def test_an_accepted_write_stops_the_outstation_asking(self):
        session, _ = self._session(need_time=True)
        before = session._handle_fragment(_request(FunctionCode.READ, bytes([60, 1, ALL])))
        assert _iin(before)[0] & IINBit.NEED_TIME
        after = session._handle_fragment(
            _request(FunctionCode.WRITE, self.WRITE + bytes(6), sequence=1)
        )
        assert not _iin(after)[0] & IINBit.NEED_TIME
        assert session.need_time is False

    def test_the_outstation_does_not_ask_unless_told_to(self):
        """The control for the test above: the bit is the flag, not a constant."""
        session, _ = self._session()
        response = session._handle_fragment(_request(FunctionCode.READ, bytes([60, 1, ALL])))
        assert not _iin(response)[0] & IINBit.NEED_TIME

    def test_the_caller_can_ask_again_later(self):
        session, _ = self._session()
        session.need_time = True
        response = session._handle_fragment(_request(FunctionCode.READ, bytes([60, 1, ALL])))
        assert _iin(response)[0] & IINBit.NEED_TIME

    def test_a_time_of_the_wrong_length_is_a_parameter_error(self):
        session, written = self._session(need_time=True)
        response = session._handle_fragment(_request(FunctionCode.WRITE, self.WRITE + bytes(4)))
        assert _iin(response)[1] & IIN2Bit.PARAM_ERROR
        assert written == []
        assert session.need_time is True, "a refused write leaves the request standing"

    def test_without_a_sink_the_object_is_unknown(self):
        """An outstation with nowhere to put the time does not pretend to take it."""
        session = Session(Reader())
        response = session._handle_fragment(_request(FunctionCode.WRITE, self.WRITE + bytes(6)))
        assert _iin(response)[1] & IIN2Bit.OBJECT_UNKNOWN

    def test_without_a_sink_the_time_cannot_be_asked_for(self):
        """Asking for a time that could never be taken would be asking forever."""
        with pytest.raises(ValueError):
            Session(Reader(), need_time=True)
        session = Session(Reader())
        with pytest.raises(ValueError):
            session.need_time = True
        assert session.need_time is False

    def test_a_sink_that_raises_leaves_the_outstation_still_asking(self):
        def refuse(_moment: int) -> None:
            raise RuntimeError("clock is read-only")

        session = Session(Reader(), time_sink=refuse, need_time=True)
        with pytest.raises(RuntimeError):
            session._handle_fragment(_request(FunctionCode.WRITE, self.WRITE + bytes(6)))
        assert session.need_time is True

    def test_clearing_the_restart_bit_still_works(self):
        session, written = self._session()
        response = session._handle_fragment(
            _request(FunctionCode.WRITE, bytes([80, 1, 0x00, 7, 7, 0]))
        )
        assert not _iin(response)[0] & IINBit.DEVICE_RESTART
        assert written == []


class TestMeasuringTheDelay:
    def test_the_answer_is_one_fine_time_delay(self):
        session = Session(Reader())
        response = session._handle_fragment(_request(FunctionCode.DELAY_MEASURE))
        assert response[4:8] == bytes([52, 2, QualifierCode.UINT8_COUNT, 1])
        assert len(response) == 4 + 4 + 2

    def test_it_reports_how_long_the_request_was_held(self):
        ticks = iter([10.0, 10.25])
        session = Session(Reader(), clock=lambda: next(ticks))
        response = session._handle_fragment(_request(FunctionCode.DELAY_MEASURE))
        assert struct.unpack("<H", response[8:10])[0] == 250

    def test_a_delay_too_long_for_the_field_saturates(self):
        ticks = iter([0.0, 1000.0])
        session = Session(Reader(), clock=lambda: next(ticks))
        response = session._handle_fragment(_request(FunctionCode.DELAY_MEASURE))
        assert struct.unpack("<H", response[8:10])[0] == 0xFFFF

    def test_objects_on_a_delay_measurement_are_a_parameter_error(self):
        session = Session(Reader())
        response = session._handle_fragment(_request(FunctionCode.DELAY_MEASURE, b"\x01"))
        assert _iin(response)[1] & IIN2Bit.PARAM_ERROR


class TestFreezing:
    COUNTERS = bytes([20, 0, ALL])

    def _session(self, freezer: Freezer | None) -> Session:
        return Session(Reader(), freeze_provider=freezer)

    def test_a_freeze_reaches_the_provider_and_is_answered_empty(self):
        freezer = Freezer()
        response = self._session(freezer)._handle_fragment(
            _request(FunctionCode.IMMED_FREEZE, self.COUNTERS)
        )
        assert len(response) == 4, "a freeze returns no objects"
        assert not _iin(response)[1]
        ((headers, clear),) = freezer.calls
        assert (headers[0].group, clear) == (20, False)

    def test_freeze_and_clear_says_so(self):
        freezer = Freezer()
        self._session(freezer)._handle_fragment(_request(FunctionCode.FREEZE_CLEAR, self.COUNTERS))
        assert freezer.calls[0][1] is True

    @pytest.mark.parametrize("function", [FunctionCode.IMMED_FREEZE, FunctionCode.FREEZE_CLEAR])
    def test_without_counters_a_freeze_is_an_unsupported_function(self, function):
        response = self._session(None)._handle_fragment(_request(function, self.COUNTERS))
        assert _iin(response)[1] & IIN2Bit.FUNC_NOT_SUPPORTED

    def test_a_freeze_of_something_that_is_not_a_counter_is_an_unknown_object(self):
        freezer = Freezer()
        response = self._session(freezer)._handle_fragment(
            _request(FunctionCode.IMMED_FREEZE, bytes([30, 0, ALL]))
        )
        assert _iin(response)[1] & IIN2Bit.OBJECT_UNKNOWN
        assert freezer.calls == []

    def test_a_freeze_naming_nothing_is_a_parameter_error(self):
        freezer = Freezer()
        response = self._session(freezer)._handle_fragment(_request(FunctionCode.IMMED_FREEZE))
        assert _iin(response)[1] & IIN2Bit.PARAM_ERROR
        assert freezer.calls == []

    def test_a_malformed_freeze_is_a_parameter_error(self):
        response = self._session(Freezer())._handle_fragment(
            _request(FunctionCode.IMMED_FREEZE, bytes([20, 0, 0xFF]))
        )
        assert _iin(response)[1] & IIN2Bit.PARAM_ERROR

    @pytest.mark.parametrize(
        ("function", "clear"),
        [(FunctionCode.IMMED_FREEZE_NR, False), (FunctionCode.FREEZE_CLEAR_NR, True)],
    )
    def test_the_no_response_freezes_freeze_and_say_nothing(self, function, clear):
        freezer = Freezer()
        response = self._session(freezer)._handle_fragment(_request(function, self.COUNTERS))
        assert response == b""
        assert [call[1] for call in freezer.calls] == [clear]

    def test_a_no_response_freeze_that_cannot_be_done_is_still_silent(self):
        freezer = Freezer()
        response = self._session(freezer)._handle_fragment(
            _request(FunctionCode.IMMED_FREEZE_NR, bytes([30, 0, ALL]))
        )
        assert response == b""
        assert freezer.calls == []

    def test_without_counters_a_no_response_freeze_is_dropped(self):
        response = self._session(None)._handle_fragment(
            _request(FunctionCode.IMMED_FREEZE_NR, self.COUNTERS)
        )
        assert response == b""


def _buffers() -> EventBuffers:
    buffers = EventBuffers()
    buffers.record_binary(3, BinaryPoint(True), event_class=EventClass.CLASS_1, timestamp_ms=1)
    buffers.record_analog(5, AnalogPoint(42.0), event_class=EventClass.CLASS_2, timestamp_ms=2)
    buffers.record_frozen_counter(
        0, CounterPoint(9), event_class=EventClass.CLASS_3, timestamp_ms=3
    )
    return buffers


class TestReadingAnEventGroupByName:
    def _read(self, session: Session, group: int, variation: int = 0, sequence: int = 0) -> bytes:
        return session._handle_fragment(
            _request(FunctionCode.READ, bytes([group, variation, ALL]), sequence=sequence)
        )

    @pytest.mark.parametrize(
        ("group", "variation", "size"),
        [
            pytest.param(2, 2, 7, id="binary input events"),
            pytest.param(32, 3, 11, id="analog input events"),
            pytest.param(23, 5, 11, id="frozen counter events"),
        ],
    )
    def test_each_group_returns_its_own_kind_and_no_other(self, group, variation, size):
        response = self._read(Session(Reader(), events=_buffers()), group)
        assert response[4:8] == bytes([group, variation, 0x17, 1])
        assert len(response) == 4 + 4 + 1 + size, "one event, and nothing after it"

    def test_the_events_are_retired_by_the_confirmation(self):
        buffers = _buffers()
        session = Session(Reader(), events=buffers)
        response = self._read(session, 32)
        assert response[0] & 0x20, "a response carrying events asks to be confirmed"
        session._handle_fragment(bytes([0xC0, FunctionCode.CONFIRM]))
        assert buffers.count(EventClass.CLASS_2) == 0
        assert buffers.count(EventClass.CLASS_1) == 1, "the other kinds are untouched"

    def test_counter_change_events_are_answered_with_nothing(self):
        """The profile has the outstation buffer none and answer a null response."""
        response = self._read(Session(Reader(), events=_buffers()), 22)
        assert len(response) == 4
        assert not _iin(response)[1]

    def test_naming_the_variation_served_is_the_same_as_naming_none(self):
        session = Session(Reader(), events=_buffers())
        assert self._read(session, 32, 3)[4:6] == bytes([32, 3])

    def test_naming_a_variation_not_served_is_an_unknown_object(self):
        """Not answered in another variation: the master named the one it wanted."""
        response = self._read(Session(Reader(), events=_buffers()), 32, 7)
        assert _iin(response)[1] & IIN2Bit.OBJECT_UNKNOWN

    def test_a_count_qualifier_limits_the_answer(self):
        buffers = EventBuffers()
        for index in range(4):
            buffers.record_binary(
                index, BinaryPoint(True), event_class=EventClass.CLASS_1, timestamp_ms=1
            )
        session = Session(Reader(), events=buffers)
        response = session._handle_fragment(
            _request(FunctionCode.READ, bytes([2, 0, QualifierCode.UINT8_COUNT, 2]))
        )
        assert response[7] == 2

    def test_a_group_and_a_class_together_send_each_event_once(self):
        session = Session(Reader(), events=_buffers())
        response = session._handle_fragment(
            _request(FunctionCode.READ, bytes([60, 3, ALL]) + bytes([32, 0, ALL]))
        )
        assert response[4:].count(bytes([32, 3, 0x17])) == 1

    def test_without_buffers_the_group_is_the_providers(self):
        """An outstation with no events configured behaves as it always has."""
        reader = Reader()
        response = Session(reader)._handle_fragment(
            _request(FunctionCode.READ, bytes([32, 0, ALL]))
        )
        assert _iin(response)[1] & IIN2Bit.OBJECT_UNKNOWN
        assert [header.group for header in reader.headers] == [32]


class TestTheAnalogEventVariation:
    def _events(self) -> EventBuffers:
        buffers = EventBuffers()
        buffers.record_analog(5, AnalogPoint(42.0), event_class=EventClass.CLASS_2, timestamp_ms=9)
        return buffers

    def _class_2(self, session: Session) -> bytes:
        return session._handle_fragment(_request(FunctionCode.READ, bytes([60, 3, ALL])))

    def test_the_default_is_timed(self):
        response = self._class_2(Session(Reader(), events=self._events()))
        assert response[4:6] == bytes([32, 3])

    def test_the_untimed_variation_carries_no_timestamp(self):
        session = Session(
            Reader(), events=self._events(), analog_event_variation=AnalogEventVariation.INT32
        )
        response = self._class_2(session)
        assert response[4:6] == bytes([32, 1])
        assert response[8:] == bytes([5, 0x01]) + struct.pack("<i", 42)

    def test_a_small_budget_still_fits_the_smaller_event(self):
        """The bound on what could fit follows the variation, or events are left behind."""
        buffers = EventBuffers()
        for index in range(3):
            buffers.record_analog(
                index, AnalogPoint(1.0), event_class=EventClass.CLASS_2, timestamp_ms=1
            )
        # Room for a header and three 16-bit events of four octets each, and
        # for fewer than two of the eight-octet events the fixed bound assumed.
        session = Session(
            Reader(),
            events=buffers,
            analog_event_variation=AnalogEventVariation.INT16,
            max_response=4 + 4 + 3 * 4,
        )
        response = self._class_2(session)
        assert response[7] == 3
        assert response[0] & 0x40, "everything fitted, so the response is final"
