"""Answering the two questions a master asks about unsolicited responses.

Section 5 of the event plan, and D21. This outstation sends none, which makes
the two requests different questions rather than a pair: `DISABLE` asks for a
state it is already in, and `ENABLE` asks for something it does not do.

The interoperability job is what this is for. Both peer masters send `DISABLE`
and then `ENABLE` on startup, and both refusals went into an operator's log on
every connection.
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


class TestDisableUnsolicited:
    @pytest.mark.parametrize("body", [b"", CLASSES], ids=["bare", "naming the classes"])
    def test_it_is_not_refused(self, body):
        response = _session()._handle_fragment(_request(FunctionCode.DISABLE_UNSOLICITED, body))

        assert not response[3] & IIN2Bit.FUNC_NOT_SUPPORTED

    def test_nor_is_it_answered_with_a_parameter_error(self):
        """The classes it names are accepted without being examined, because
        the answer is the same for any of them: none is being sent for."""
        response = _session()._handle_fragment(_request(FunctionCode.DISABLE_UNSOLICITED, CLASSES))

        assert not response[3] & IIN2Bit.OBJECT_UNKNOWN
        assert not response[3] & IIN2Bit.PARAM_ERROR

    def test_the_answer_is_a_null_response(self):
        response = _session()._handle_fragment(_request(FunctionCode.DISABLE_UNSOLICITED, CLASSES))

        assert response[1] == FunctionCode.RESPONSE
        assert response[4:] == b"", "nothing to report, having nothing to stop"

    def test_it_is_answered_under_the_sequence_it_arrived_on(self):
        response = _session()._handle_fragment(
            _request(FunctionCode.DISABLE_UNSOLICITED, CLASSES, sequence=7)
        )

        assert response[0] & 0x0F == 7

    def test_success_is_the_absence_of_one_bit_and_not_an_empty_field(self):
        """`DEVICE_RESTART` stands until a master clears it, and the class bits
        are derived from the buffers on every response (D22). A response
        reporting those is still a successful one, which an earlier draft of
        this section got wrong by asking for an empty indication field."""
        buffers = EventBuffers()
        buffers.record_analog(0, AnalogPoint(1.0), event_class=EventClass.CLASS_1, timestamp_ms=1)
        session = _session(events=buffers)

        response = session._handle_fragment(_request(FunctionCode.DISABLE_UNSOLICITED))

        assert response[2] & IINBit.DEVICE_RESTART
        assert response[2] & IINBit.CLASS_1_EVENTS
        assert not response[3] & IIN2Bit.FUNC_NOT_SUPPORTED

    def test_the_classes_it_names_are_not_a_selection_to_answer(self):
        """It is not a read. The classes name what to stop sending, and the
        headers of a request are not a request for their contents -- answering
        them from the buffers would hand a master events it never polled for,
        and then wait to have them confirmed."""
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

    def test_a_monitor_outstation_accepts_it_too(self):
        """It commands nothing, so it is not a control function and does not
        need a control provider to answer."""
        response = _session()._handle_fragment(_request(FunctionCode.DISABLE_UNSOLICITED))

        assert not response[3] & IIN2Bit.FUNC_NOT_SUPPORTED


class TestEnableUnsolicitedIsStillRefused:
    """The asymmetry is the point rather than an oversight. `ENABLE` asks for
    something this outstation does not do, and the honest answer is to say so."""

    @pytest.mark.parametrize("body", [b"", CLASSES], ids=["bare", "naming the classes"])
    def test_it_earns_the_unsupported_bit(self, body):
        response = _session()._handle_fragment(_request(FunctionCode.ENABLE_UNSOLICITED, body))

        assert response[3] & IIN2Bit.FUNC_NOT_SUPPORTED
        assert response[4:] == b""


class TestItIsARequestLikeAnyOther:
    """Being answered rather than refused puts it inside the rules the other
    requests obey, and both of those are easy to lose on a new branch."""

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
