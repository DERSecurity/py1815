"""Answering the two questions a master asks about unsolicited responses.

D21. A session built without unsolicited responses sends none and supports
neither `ENABLE_UNSOLICITED` nor `DISABLE_UNSOLICITED`, so it refuses both with
IIN2.0, as the certification procedure expects of a device with the mode off
(IEEE 1815-2012 4.4.13 and 4.5.9).
"""

from __future__ import annotations

import pytest

from py1815.application import FunctionCode, IIN2Bit, IINBit, QualifierCode
from py1815.control import CommandStatus, decode_crob
from py1815.events import EventBuffers, EventClass
from py1815.objects import AnalogPoint
from py1815.session import Session

#: Group 60 variations 2, 3 and 4 -- classes 1, 2 and 3 -- which is the shape a
#: real master sends rather than a bare function code.
CLASSES = bytes([60, 2, 0x06, 60, 3, 0x06, 60, 4, 0x06])


class Reader:
    def read(self, headers):
        return b""


def _session(**kwargs) -> Session:
    return Session(Reader(), **kwargs)


def _request(function: int, body: bytes = b"", sequence: int = 0) -> bytes:
    return bytes([0xC0 | sequence, function]) + body


class TestBothRequestsAreRefused:
    """A session built without unsolicited responses supports neither function (D21)."""

    @pytest.mark.parametrize(
        "function",
        [FunctionCode.ENABLE_UNSOLICITED, FunctionCode.DISABLE_UNSOLICITED],
        ids=["enable", "disable"],
    )
    @pytest.mark.parametrize("body", [b"", CLASSES], ids=["bare", "naming the classes"])
    def test_the_request_is_answered_with_a_null_response_and_iin2_0(self, function, body):
        response = _session()._handle_fragment(_request(function, body))

        assert response[1] == FunctionCode.RESPONSE
        assert response[3] & IIN2Bit.FUNC_NOT_SUPPORTED
        assert response[4:] == b""

    def test_a_disable_request_naming_the_classes_is_these_octets(self):
        # Application control C3, DISABLE_UNSOLICITED (0x15), then group 60
        # variations 2, 3 and 4 with qualifier 0x06, as a master sends it.
        request = bytes.fromhex("C3 15 3C 02 06 3C 03 06 3C 04 06")
        # The answer: application control C3, RESPONSE (0x81), IIN1 with
        # DEVICE_RESTART (0x80), IIN2 with NO_FUNC_CODE_SUPPORT (0x01).
        assert _session()._handle_fragment(request) == bytes.fromhex("C3 81 80 01")

    def test_the_refusal_is_answered_under_the_sequence_the_request_arrived_on(self):
        response = _session()._handle_fragment(
            _request(FunctionCode.DISABLE_UNSOLICITED, CLASSES, sequence=7)
        )

        assert response[0] & 0x0F == 7

    def test_a_refused_disable_request_reports_the_other_indications_as_they_stand(self):
        """`DEVICE_RESTART` stands until a master clears it, and the class bits
        are derived from the buffers on every response (D22)."""
        buffers = EventBuffers()
        buffers.record_analog(0, AnalogPoint(1.0), event_class=EventClass.CLASS_1, timestamp_ms=1)
        session = _session(events=buffers)

        response = session._handle_fragment(_request(FunctionCode.DISABLE_UNSOLICITED))

        assert response[2] & IINBit.DEVICE_RESTART
        assert response[2] & IINBit.CLASS_1_EVENTS
        assert response[3] & IIN2Bit.FUNC_NOT_SUPPORTED

    def test_the_classes_a_disable_request_names_are_not_read(self):
        """The headers of the request are not a request for their contents:
        answering them from the buffers would hand a master events it never
        polled for, and then wait to have them confirmed."""
        buffers = EventBuffers()
        for index in range(3):
            buffers.record_analog(
                index, AnalogPoint(float(index)), event_class=EventClass.CLASS_1, timestamp_ms=1
            )
        session = _session(events=buffers)

        response = session._handle_fragment(_request(FunctionCode.DISABLE_UNSOLICITED, CLASSES))

        assert response[4:] == b"", "no events, though three were waiting"
        assert not response[0] & 0x20, "and nothing to confirm"
        assert buffers.count(EventClass.CLASS_1) == 3

    def test_a_session_built_with_unsolicited_responses_agrees_to_a_disable_request(self):
        session = _session(unsolicited=True)

        response = session._handle_fragment(_request(FunctionCode.DISABLE_UNSOLICITED, CLASSES))

        assert response[1] == FunctionCode.RESPONSE
        assert not response[3], "no error indication"


class TestItIsARequestLikeAnyOther:
    """A refused request is still a request, and obeys the rules the others do."""

    def test_it_clears_an_armed_select(self):
        commands = _Commands()
        session = Session(Reader(), control_provider=commands, clock=lambda: 0.0)
        session._handle_fragment(_select(sequence=0))
        assert session._select is not None

        session._handle_fragment(_request(FunctionCode.DISABLE_UNSOLICITED, sequence=5))

        assert _statuses(session._handle_fragment(_operate(sequence=1))) == [
            CommandStatus.NO_SELECT
        ]
        assert commands.operated == []

    def test_it_supersedes_an_outstanding_event_response(self):
        buffers = EventBuffers()
        buffers.record_analog(0, AnalogPoint(1.0), event_class=EventClass.CLASS_1, timestamp_ms=1)
        session = _session(events=buffers)
        session._handle_fragment(bytes([0xC0, FunctionCode.READ, 60, 2, QualifierCode.ALL_OBJECTS]))

        session._handle_fragment(_request(FunctionCode.DISABLE_UNSOLICITED, sequence=1))
        session._handle_fragment(bytes([0xC0, FunctionCode.CONFIRM]))

        assert buffers.count(EventClass.CLASS_1) == 1, "the superseded response is nobody's"


#: One CROB, latch on, status success.
LATCH_ON = bytes.fromhex("030164000000c800000000")


class _Commands:
    def __init__(self) -> None:
        self.selected: list = []
        self.operated: list = []

    def select(self, controls):
        self.selected.append(list(controls))
        return [CommandStatus.SUCCESS] * len(controls)

    def operate(self, controls):
        self.operated.append(list(controls))
        return [CommandStatus.SUCCESS] * len(controls)


def _control(function: int, sequence: int) -> bytes:
    header = bytes([12, 1, QualifierCode.UINT8_COUNT_UINT8_INDEX, 1, 0])
    return bytes([0xC0 | sequence, function]) + header + LATCH_ON


def _select(sequence: int) -> bytes:
    return _control(FunctionCode.SELECT, sequence)


def _operate(sequence: int) -> bytes:
    return _control(FunctionCode.OPERATE, sequence)


def _statuses(response: bytes) -> list[CommandStatus]:
    return [decode_crob(response[9:20]).status]
