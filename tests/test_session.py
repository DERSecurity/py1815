"""One master association, driven with literal frames.

Every case here feeds octets and inspects octets. Requests are assembled from
the wire outward rather than by asking the session what it expects, and the
replies are decoded by hand where the assertion is about layout.
"""

from __future__ import annotations

import pytest

from py1815 import link
from py1815.application import (
    FunctionCode,
    IIN2Bit,
    IINBit,
    ObjectHeader,
    QualifierCode,
)
from py1815.session import Session, UnknownObject

OUTSTATION = 1024
MASTER = 1

CLASS_0_READ = bytes([0xC0, FunctionCode.READ, 60, 1, QualifierCode.ALL_OBJECTS])
OBJECTS = bytes([30, 1, QualifierCode.UINT8_START_STOP, 0, 0, 0x01, 0x2A, 0x00, 0x00, 0x00])


class Recorder:
    """A read provider that answers with fixed objects and remembers the ask."""

    def __init__(self, body: bytes = OBJECTS, raises: Exception | None = None) -> None:
        self.body = body
        self.raises = raises
        self.headers: list[ObjectHeader] = []

    def read(self, headers):
        self.headers = list(headers)
        if self.raises:
            raise self.raises
        return self.body


def _session(provider: Recorder | None = None) -> tuple[Session, Recorder]:
    recorder = provider or Recorder()
    return Session(recorder, outstation_address=OUTSTATION, master_address=MASTER), recorder


def _user_data(fragment: bytes, *, confirmed: bool = False, source: int = MASTER) -> bytes:
    """A link frame carrying one transport segment holding ``fragment``."""
    function = (
        link.PrimaryFunction.CONFIRMED_USER_DATA
        if confirmed
        else link.PrimaryFunction.UNCONFIRMED_USER_DATA
    )
    control = link.control_byte(from_master=True, primary=True, function=function)
    return link.build(control, destination=OUTSTATION, source=source, payload=b"\xc0" + fragment)


def _link_only(function: link.PrimaryFunction, *, destination: int = OUTSTATION) -> bytes:
    control = link.control_byte(from_master=True, primary=True, function=function)
    return link.build(control, destination=destination, source=MASTER)


def _fragments(reply: bytes) -> list[bytes]:
    """Application fragments carried by the frames in ``reply``."""
    return [f.payload[1:] for f in link.FrameReader().feed(reply) if f.payload]


def _frames(reply: bytes) -> list[link.LinkFrame]:
    return link.FrameReader().feed(reply)


class TestLinkLayer:
    def test_a_link_status_request_is_answered(self):
        session, _ = _session()

        frames = _frames(session.receive(_link_only(link.PrimaryFunction.REQUEST_LINK_STATUS)))

        assert len(frames) == 1
        assert frames[0].function == link.SecondaryFunction.LINK_STATUS
        assert not frames[0].is_primary
        assert (frames[0].destination, frames[0].source) == (MASTER, OUTSTATION)

    def test_a_link_reset_is_acknowledged(self):
        session, _ = _session()

        frames = _frames(session.receive(_link_only(link.PrimaryFunction.RESET_LINK_STATES)))

        assert frames[0].function == link.SecondaryFunction.ACK

    def test_a_test_link_request_is_acknowledged(self):
        session, _ = _session()

        frames = _frames(session.receive(_link_only(link.PrimaryFunction.TEST_LINK_STATES)))

        assert frames[0].function == link.SecondaryFunction.ACK

    def test_an_unsupported_link_function_says_so(self):
        session, _ = _session()
        control = link.control_byte(from_master=True, primary=True, function=1)

        frames = _frames(session.receive(link.build(control, OUTSTATION, MASTER)))

        assert frames[0].function == link.SecondaryFunction.NOT_SUPPORTED

    def test_confirmed_user_data_is_acknowledged_and_answered(self):
        session, _ = _session()

        frames = _frames(session.receive(_user_data(CLASS_0_READ, confirmed=True)))

        assert frames[0].function == link.SecondaryFunction.ACK
        assert frames[1].function == link.PrimaryFunction.UNCONFIRMED_USER_DATA

    def test_unconfirmed_user_data_is_answered_without_an_ack(self):
        session, _ = _session()

        frames = _frames(session.receive(_user_data(CLASS_0_READ)))

        assert len(frames) == 1
        assert frames[0].function == link.PrimaryFunction.UNCONFIRMED_USER_DATA


class TestAddressing:
    def test_a_frame_for_another_outstation_is_ignored(self):
        session, recorder = _session()

        assert (
            session.receive(_link_only(link.PrimaryFunction.REQUEST_LINK_STATUS, destination=7))
            == b""
        )
        assert recorder.headers == []

    def test_a_frame_from_an_unexpected_master_is_ignored(self):
        """The address is not authorization, but answering a second source would
        interleave two conversations over one set of sequence numbers."""
        session, _ = _session()

        assert session.receive(_user_data(CLASS_0_READ, source=99)) == b""

    def test_a_broadcast_frame_is_accepted(self):
        session, _ = _session()
        control = link.control_byte(
            from_master=True,
            primary=True,
            function=link.PrimaryFunction.UNCONFIRMED_USER_DATA,
        )
        frame = link.build(
            control, link.Broadcast.NO_CONFIRM, MASTER, payload=b"\xc0" + CLASS_0_READ
        )

        assert _fragments(session.receive(frame))

    def test_a_secondary_frame_is_ignored(self):
        """An outstation sends unconfirmed data, so nothing is outstanding for a
        secondary frame to answer."""
        session, _ = _session()
        control = link.control_byte(
            from_master=True, primary=False, function=link.SecondaryFunction.ACK
        )

        assert session.receive(link.build(control, OUTSTATION, MASTER)) == b""


class TestReads:
    def test_a_class_poll_reaches_the_provider_and_its_objects_come_back(self):
        session, recorder = _session()

        fragment = _fragments(session.receive(_user_data(CLASS_0_READ)))[0]

        assert [h.event_class for h in recorder.headers] == [0]
        assert fragment[1] == FunctionCode.RESPONSE
        assert fragment[4:] == OBJECTS

    def test_the_response_echoes_the_request_sequence(self):
        session, _ = _session()
        request = bytes([0xC7, FunctionCode.READ, 60, 1, QualifierCode.ALL_OBJECTS])

        fragment = _fragments(session.receive(_user_data(request)))[0]

        assert fragment[0] & 0x0F == 7

    def test_a_response_is_marked_first_and_final(self):
        session, _ = _session()

        fragment = _fragments(session.receive(_user_data(CLASS_0_READ)))[0]

        assert fragment[0] & 0xC0 == 0xC0

    def test_an_unknown_object_earns_the_object_unknown_bit(self):
        session, _ = _session(Recorder(raises=UnknownObject("group 99")))

        fragment = _fragments(session.receive(_user_data(CLASS_0_READ)))[0]

        assert fragment[3] & IIN2Bit.OBJECT_UNKNOWN
        assert len(fragment) == 4

    def test_a_large_response_is_split_across_link_frames(self):
        """A fragment longer than one transport segment still reaches the wire."""
        session, _ = _session(Recorder(body=b"\x01" * 600))

        frames = _frames(session.receive(_user_data(CLASS_0_READ)))

        assert len(frames) == 3
        assert b"".join(f.payload[1:] for f in frames)[4:] == b"\x01" * 600


class TestRefusals:
    @pytest.mark.parametrize(
        "function",
        [FunctionCode.SELECT, FunctionCode.OPERATE, FunctionCode.DIRECT_OPERATE],
    )
    def test_a_control_is_refused_in_band(self, function):
        """Silence would leave a master retrying against a timeout."""
        session, _ = _session()

        fragment = _fragments(session.receive(_user_data(bytes([0xC0, function]))))[0]

        assert fragment[1] == FunctionCode.RESPONSE
        assert fragment[3] & IIN2Bit.FUNC_NOT_SUPPORTED

    def test_direct_operate_no_ack_is_dropped_rather_than_executed(self):
        """It asks for no response, so it cannot be refused in band. What must
        not happen is it being carried out."""
        session, recorder = _session()

        reply = session.receive(_user_data(bytes([0xC0, FunctionCode.DIRECT_OPERATE_NR])))

        assert reply == b""
        assert recorder.headers == []

    def test_an_unsupported_function_earns_the_function_bit(self):
        session, _ = _session()

        fragment = _fragments(
            session.receive(_user_data(bytes([0xC0, FunctionCode.COLD_RESTART])))
        )[0]

        assert fragment[3] & IIN2Bit.FUNC_NOT_SUPPORTED

    def test_an_unknown_function_code_is_refused_not_dropped(self):
        session, _ = _session()

        fragment = _fragments(session.receive(_user_data(bytes([0xC0, 0x7F, 0x01]))))[0]

        assert fragment[3] & IIN2Bit.FUNC_NOT_SUPPORTED

    def test_a_malformed_request_is_answered_on_its_own_sequence(self):
        """Answering on the wrong sequence has the master discard the answer it
        needs."""
        session, _ = _session()
        malformed = bytes([0xC5, FunctionCode.READ, 60, 1])

        fragment = _fragments(session.receive(_user_data(malformed)))[0]

        assert fragment[0] & 0x0F == 5
        assert fragment[3] & IIN2Bit.PARAM_ERROR

    def test_a_confirmation_is_accepted_silently(self):
        session, _ = _session()

        assert session.receive(_user_data(bytes([0xC0, FunctionCode.CONFIRM]))) == b""


class TestRestartIndication:
    def test_responses_carry_the_restart_bit_until_it_is_cleared(self):
        session, _ = _session()

        fragment = _fragments(session.receive(_user_data(CLASS_0_READ)))[0]

        assert fragment[2] & IINBit.DEVICE_RESTART

    def test_a_master_can_clear_it(self):
        """Group 80 index 7 is fixed by the standard rather than by the point
        map, which is why a read-only outstation still honors this write."""
        session, _ = _session()
        clear = bytes([0xC0, FunctionCode.WRITE, 80, 1, QualifierCode.UINT8_START_STOP, 7, 7, 0x00])

        cleared = _fragments(session.receive(_user_data(clear)))[0]
        later = _fragments(session.receive(_user_data(CLASS_0_READ)))[0]

        assert not cleared[2] & IINBit.DEVICE_RESTART
        assert not later[2] & IINBit.DEVICE_RESTART
        assert not session.restart_indication

    def test_another_write_is_refused_as_an_unknown_object(self):
        """WRITE itself is supported, so the master should learn that the object
        is not rather than that the function is."""
        session, _ = _session()
        write = bytes([0xC0, FunctionCode.WRITE, 50, 1, QualifierCode.UINT8_COUNT, 1]) + b"\x00" * 6

        fragment = _fragments(session.receive(_user_data(write)))[0]

        assert fragment[3] & IIN2Bit.OBJECT_UNKNOWN
        assert session.restart_indication


class TestStreamHandling:
    def test_a_request_split_across_reads_is_answered_once(self):
        session, _ = _session()
        data = _user_data(CLASS_0_READ)

        replies = [session.receive(data[i : i + 1]) for i in range(len(data))]

        assert len([r for r in replies if r]) == 1

    def test_two_requests_in_one_read_are_both_answered(self):
        session, _ = _session()

        reply = session.receive(_user_data(CLASS_0_READ) + _user_data(CLASS_0_READ))

        assert len(_fragments(reply)) == 2

    def test_a_link_reset_abandons_a_partial_fragment(self):
        """Segments from before the reset must not be completed by segments from
        after it."""
        session, _ = _session()
        control = link.control_byte(
            from_master=True,
            primary=True,
            function=link.PrimaryFunction.UNCONFIRMED_USER_DATA,
        )
        first_half = link.build(control, OUTSTATION, MASTER, payload=b"\x40" + CLASS_0_READ)

        session.receive(first_half)
        session.receive(_link_only(link.PrimaryFunction.RESET_LINK_STATES))
        rest = link.build(control, OUTSTATION, MASTER, payload=b"\x81" + b"\x00")

        assert session.receive(rest) == b""
