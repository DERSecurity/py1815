"""The master's side of a conversation, driven with frames and no socket.

The outstation here is this file: each test hands the association the frames
an outstation would send, written as the application fragment they carry, and
looks at what it sends back and what it reports.
"""

from __future__ import annotations

import pytest

from py1815 import link
from py1815.application import FunctionCode, IIN2Bit, IINBit
from py1815.decode import PointType
from py1815.master import Busy, MasterAssociation, Outcome
from py1815.master import requests as rq
from py1815.transport import Reassembler

OUTSTATION, MASTER = 1024, 1

#: One 16-bit analog input, index 0, value 300, online.
ANALOG = "1E 02 00 00 00 01 2C 01"
#: One binary input, index 0, on and online.
BINARY = "01 02 00 00 00 81"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _built(**options) -> tuple[MasterAssociation, Clock]:
    clock = Clock()
    options.setdefault("outstation_address", OUTSTATION)
    options.setdefault("master_address", MASTER)
    return MasterAssociation(clock=clock, **options), clock


def _from_outstation(
    fragment: str | bytes,
    *,
    source: int = OUTSTATION,
    destination: int = MASTER,
    function: int = link.PrimaryFunction.UNCONFIRMED_USER_DATA,
    transport: int = 0xC0,
) -> bytes:
    """A link frame from the outstation carrying one whole application fragment."""
    octets = bytes.fromhex(fragment) if isinstance(fragment, str) else fragment
    control = link.control_byte(from_master=False, primary=True, function=function)
    return link.build(control, destination, source, bytes([transport]) + octets)


def _sent(octets: bytes) -> list[tuple[link.LinkFrame, bytes]]:
    """Each frame the master sent, with the application fragment it completed, if any."""
    found, reassembler = [], Reassembler()
    for frame in link.FrameReader().feed(octets):
        fragment = reassembler.add(frame.payload) if frame.payload else None
        found.append((frame, fragment or b""))
    return found


def _fragment(octets: bytes) -> bytes:
    ((_, fragment),) = _sent(octets)
    return fragment


class TestARequest:
    def test_an_integrity_poll_on_the_wire(self):
        association, _ = _built()
        octets = association.request(FunctionCode.READ, rq.scan("integrity"))

        # Start octets, a length of 20, a control octet of DIR, PRM and
        # unconfirmed user data, then destination 1024 and source 1.
        assert octets[:8] == bytes.fromhex("05 64 14 C4 00 04 01 00")
        ((frame, fragment),) = _sent(octets)
        assert frame.from_master and frame.is_primary
        assert frame.payload[0] == 0xC0, "one segment, first and final"
        assert fragment == bytes.fromhex("C0 01 3C 02 06 3C 03 06 3C 04 06 3C 01 06")

    def test_each_request_takes_the_next_sequence_number_and_it_wraps(self):
        association, _ = _built()
        seen = []
        for _ in range(17):
            seen.append(_fragment(association.request(FunctionCode.READ, rq.scan("class0")))[0])
            association.give_up()
            association.take()
        assert seen[:3] == [0xC0, 0xC1, 0xC2]
        assert seen[15:] == [0xCF, 0xC0]

    def test_a_second_request_while_one_is_outstanding_is_misuse(self):
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("class0"))
        with pytest.raises(Busy, match="READ is still waiting"):
            association.request(FunctionCode.READ, rq.scan("class1"))

    def test_and_so_is_one_before_the_last_result_was_taken(self):
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("class0"))
        association.receive(_from_outstation("C0 81 00 00"))
        with pytest.raises(Busy, match="not been taken"):
            association.request(FunctionCode.READ, rq.scan("class1"))
        assert association.take() is not None
        association.request(FunctionCode.READ, rq.scan("class1"))

    def test_a_request_that_is_answered_by_silence_is_finished_when_it_is_sent(self):
        association, _ = _built()
        association.request(FunctionCode.IMMED_FREEZE_NR, bytes.fromhex("14 00 06"))
        exchange = association.take()
        assert exchange.outcome is Outcome.SENT
        assert not association.busy

    @pytest.mark.parametrize(
        ("options", "message"),
        [
            ({"outstation_address": 0xFFFF}, "outstation_address is 65535"),
            ({"master_address": 0xFFF0}, "master_address is 65520"),
            ({"outstation_address": 7, "master_address": 7}, "are both 7"),
            ({"response_timeout": 0}, "response_timeout is 0"),
        ],
    )
    def test_what_it_refuses_to_be_built_with(self, options, message):
        with pytest.raises(ValueError, match=message):
            MasterAssociation(**options)


class TestAResponse:
    def test_one_fragment_finishes_the_exchange(self):
        association, clock = _built()
        association.request(FunctionCode.READ, rq.scan("class0"))
        clock.now += 0.25
        reply = association.receive(_from_outstation(f"C0 81 90 00 {ANALOG}"))

        assert reply == b"", "it did not ask to be confirmed"
        exchange = association.take()
        assert exchange.outcome is Outcome.COMPLETE and exchange.complete
        assert exchange.function is FunctionCode.READ and exchange.sequence == 0
        assert exchange.request == bytes.fromhex("C0 01 3C 01 06")
        assert exchange.iin.is_set(IINBit.DEVICE_RESTART)
        (analog,) = exchange.objects
        assert (analog.point, analog.index, analog.value) == (PointType.ANALOG_INPUT, 0, 300)
        assert exchange.elapsed == pytest.approx(0.25)
        assert association.take() is None, "a result is taken once"

    def test_a_fragment_that_asks_is_confirmed_with_its_own_sequence_number(self):
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("class1"))
        reply = association.receive(_from_outstation(f"E0 81 00 00 {ANALOG}"))
        assert _fragment(reply) == bytes.fromhex("C0 00")

    def test_a_response_of_several_fragments_is_one_result(self):
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("integrity"))

        first = association.receive(_from_outstation(f"A0 81 00 00 {BINARY}"))
        assert _fragment(first) == bytes.fromhex("C0 00")
        assert association.busy and association.take() is None

        second = association.receive(_from_outstation(f"61 81 00 00 {ANALOG}"))
        assert _fragment(second) == bytes.fromhex("C1 00")

        exchange = association.take()
        assert exchange.complete and len(exchange.fragments) == 2
        assert [o.point for o in exchange.objects] == [
            PointType.BINARY_INPUT,
            PointType.ANALOG_INPUT,
        ]

    def test_an_error_indication_is_a_result(self):
        association, _ = _built()
        association.request(FunctionCode.READ, bytes.fromhex("1E 00 17 01 63"))
        association.receive(_from_outstation("C0 81 00 04"))
        exchange = association.take()
        assert exchange.complete and exchange.objects == ()
        assert exchange.iin.is_set(IIN2Bit.PARAM_ERROR)

    def test_a_fragment_under_another_sequence_number_is_dropped_and_not_confirmed(self):
        """Confirming it would retire events this master never read."""
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("class1"))
        reply = association.receive(_from_outstation(f"E5 81 00 00 {ANALOG}"))
        assert reply == b""
        assert association.busy

    def test_a_continuation_that_arrives_first_is_dropped(self):
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("class1"))
        assert association.receive(_from_outstation(f"60 81 00 00 {ANALOG}")) == b""
        assert association.busy

    def test_objects_that_cannot_all_be_read_are_reported_with_the_ones_that_were(self):
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("class0"))
        association.receive(_from_outstation(f"C0 81 00 00 {ANALOG} 6E 04 00 00 00 41"))
        exchange = association.take()
        assert exchange.complete, "the outstation answered; not all of it was understood"
        assert [o.value for o in exchange.objects] == [300]
        (undecoded,) = exchange.undecoded
        assert "group 110" in undecoded.problem
        assert undecoded.unread == bytes.fromhex("6E 04 00 00 00 41")

    def test_a_response_with_nothing_outstanding_is_dropped(self):
        association, _ = _built()
        assert association.receive(_from_outstation(f"E0 81 00 00 {ANALOG}")) == b""
        assert association.take() is None

    def test_a_fragment_split_across_frames_is_reassembled(self):
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("class0"))
        whole = bytes.fromhex(f"C0 81 00 00 {ANALOG}")
        control = link.control_byte(
            from_master=False, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
        )
        head = link.build(control, MASTER, OUTSTATION, bytes([0x40]) + whole[:5])
        tail = link.build(control, MASTER, OUTSTATION, bytes([0x81]) + whole[5:])
        both = head + tail
        # And the octets arrive split wherever the network cared to split them.
        association.receive(both[:7])
        association.receive(both[7:])
        assert [o.value for o in association.take().objects] == [300]


class TestSilence:
    def test_a_request_nobody_answers_times_out_and_says_so(self):
        association, clock = _built(response_timeout=2.0)
        association.request(FunctionCode.READ, rq.scan("class0"))
        assert association.expires_after() == pytest.approx(2.0)

        clock.now += 1.5
        assert not association.expire()
        assert association.expires_after() == pytest.approx(0.5)

        clock.now += 0.5
        assert association.expire()
        exchange = association.take()
        assert exchange.outcome is Outcome.TIMEOUT and not exchange.complete
        assert exchange.fragments == () and exchange.iin is None
        assert exchange.elapsed == pytest.approx(2.0)
        assert association.expires_after() is None

    def test_each_fragment_is_given_the_whole_wait_again(self):
        association, clock = _built(response_timeout=2.0)
        association.request(FunctionCode.READ, rq.scan("integrity"))
        clock.now += 1.5
        association.receive(_from_outstation(f"A0 81 00 00 {BINARY}"))
        assert association.expires_after() == pytest.approx(2.0)

    def test_a_response_that_stops_part_way_keeps_what_arrived(self):
        association, clock = _built(response_timeout=2.0)
        association.request(FunctionCode.READ, rq.scan("integrity"))
        association.receive(_from_outstation(f"A0 81 00 00 {BINARY}"))
        clock.now += 2.0
        assert association.expire()
        exchange = association.take()
        assert exchange.outcome is Outcome.TIMEOUT
        assert len(exchange.fragments) == 1 and len(exchange.objects) == 1

    def test_an_answer_that_arrives_after_the_wait_ended_is_dropped_unconfirmed(self):
        association, clock = _built(response_timeout=2.0)
        association.request(FunctionCode.READ, rq.scan("class1"))
        clock.now += 2.0
        association.expire()
        association.take()
        assert association.receive(_from_outstation(f"E0 81 00 00 {ANALOG}")) == b""
        assert association.take() is None

    def test_nothing_outstanding_has_nothing_to_expire(self):
        association, _ = _built()
        assert association.expires_after() is None
        assert not association.expire() and not association.give_up()

    def test_a_request_nobody_is_waiting_for_is_abandoned_and_the_next_is_made(self):
        association, _ = _built()
        first = _fragment(association.request(FunctionCode.READ, rq.scan("class0")))
        assert association.abandon() and not association.busy

        given_up = association.take()
        assert given_up.outcome is Outcome.ABANDONED and given_up.request == first
        assert not association.abandon(), "there is nothing left to give up on"

        # The next request is made as usual, under the next sequence number.
        assert _fragment(association.request(FunctionCode.READ, rq.scan("class0")))[0] == 0xC1

    def test_the_answer_to_an_abandoned_request_is_dropped_and_not_confirmed(self):
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("class0"))
        association.abandon()
        association.take()

        # It asks to be confirmed, and confirming it would retire events nobody read.
        assert association.receive(_from_outstation(f"E0 81 00 00 {ANALOG}")) == b""
        assert association.take() is None and not association.busy

    def test_a_reset_connection_abandons_what_was_outstanding(self):
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("class0"))
        association.connection_reset()
        assert association.take().outcome is Outcome.ABANDONED
        assert not association.busy

    def test_and_the_sequence_numbers_carry_on_across_it(self):
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("class0"))
        association.connection_reset()
        association.take()
        assert _fragment(association.request(FunctionCode.READ, rq.scan("class0")))[0] == 0xC1


class TestUnsolicitedResponses:
    NULL = "F0 82 80 00"

    def test_one_is_confirmed_in_its_own_series_and_delivered(self):
        association, _ = _built()
        reply = association.receive(_from_outstation(self.NULL))
        assert _fragment(reply) == bytes.fromhex("D0 00")
        (received,) = association.take_unsolicited()
        assert received.null and received.iin.is_set(IINBit.DEVICE_RESTART)
        assert association.take_unsolicited() == [], "delivered once"

    def test_one_carrying_events_is_decoded(self):
        association, _ = _built()
        association.receive(_from_outstation("F3 82 00 00 20 02 17 01 09 01 05 00"))
        (received,) = association.take_unsolicited()
        (event,) = received.objects
        assert not received.null
        assert (event.point, event.index, event.value, event.event) == (
            PointType.ANALOG_INPUT,
            9,
            5,
            True,
        )

    def test_the_same_octets_again_are_confirmed_again_and_delivered_once(self):
        """The outstation did not see the confirmation, and sent it again."""
        association, _ = _built()
        association.receive(_from_outstation(self.NULL))
        again = association.receive(_from_outstation(self.NULL))
        assert _fragment(again) == bytes.fromhex("D0 00")
        assert len(association.take_unsolicited()) == 1

    def test_the_next_one_is_new(self):
        association, _ = _built()
        association.receive(_from_outstation(self.NULL))
        association.receive(_from_outstation("F1 82 00 00 20 02 17 01 09 01 05 00"))
        assert len(association.take_unsolicited()) == 2

    def test_one_arriving_in_the_middle_of_an_exchange_leaves_it_alone(self):
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("class0"))
        reply = association.receive(_from_outstation(self.NULL))
        assert _fragment(reply) == bytes.fromhex("D0 00")
        assert association.busy

        association.receive(_from_outstation(f"C0 81 00 00 {ANALOG}"))
        assert association.take().complete
        assert len(association.take_unsolicited()) == 1

    def test_one_that_is_not_a_single_fragment_is_dropped(self):
        association, _ = _built()
        assert association.receive(_from_outstation("B0 82 80 00")) == b""
        assert association.take_unsolicited() == []


class TestByHand:
    """With confirmation turned off, nothing is sent that the caller did not ask for."""

    def test_nothing_is_confirmed(self):
        association, _ = _built(confirm=False)
        association.request(FunctionCode.READ, rq.scan("class1"))
        assert association.receive(_from_outstation(f"E0 81 00 00 {ANALOG}")) == b""
        assert association.receive(_from_outstation("F0 82 80 00")) == b""
        assert association.take().complete

    def test_and_the_caller_confirms_when_it_chooses_to(self):
        association, _ = _built(confirm=False)
        association.request(FunctionCode.READ, rq.scan("class1"))
        association.receive(_from_outstation(f"E0 81 00 00 {ANALOG}"))
        (response,) = association.take().fragments
        assert _fragment(association.confirm(response)) == bytes.fromhex("C0 00")

        association.receive(_from_outstation("F4 82 80 00"))
        (unsolicited,) = association.take_unsolicited()
        assert _fragment(association.confirm(unsolicited.response)) == bytes.fromhex("D4 00")


class TestWhoIsSpeaking:
    def test_a_frame_for_another_master_is_not_ours(self):
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("class0"))
        association.receive(_from_outstation(f"C0 81 00 00 {ANALOG}", destination=2))
        assert association.busy

    def test_a_frame_from_another_outstation_is_dropped(self):
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("class0"))
        association.receive(_from_outstation(f"C0 81 00 00 {ANALOG}", source=1025))
        assert association.busy

    def test_a_frame_marked_as_from_a_master_is_dropped(self):
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("class0"))
        control = link.control_byte(
            from_master=True, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
        )
        frame = link.build(control, MASTER, OUTSTATION, bytes.fromhex(f"C0 C0 81 00 00 {ANALOG}"))
        association.receive(frame)
        assert association.busy


class TestTheDataLink:
    """An outstation may ask things of the link, and is answered as a secondary station."""

    def _reply(self, function: int, payload: bytes = b"") -> link.LinkFrame:
        association, _ = _built()
        control = link.control_byte(from_master=False, primary=True, function=function)
        frames = link.FrameReader().feed(
            association.receive(link.build(control, MASTER, OUTSTATION, payload))
        )
        (frame,) = frames
        assert frame.from_master and not frame.is_primary
        assert (frame.destination, frame.source) == (OUTSTATION, MASTER)
        return frame

    def test_a_link_status_request_is_answered_with_the_status(self):
        frame = self._reply(link.PrimaryFunction.REQUEST_LINK_STATUS)
        assert frame.function == link.SecondaryFunction.LINK_STATUS

    def test_a_link_reset_is_acknowledged(self):
        frame = self._reply(link.PrimaryFunction.RESET_LINK_STATES)
        assert frame.function == link.SecondaryFunction.ACK

    def test_confirmed_user_data_is_acknowledged_and_taken(self):
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("class0"))
        reply = association.receive(
            _from_outstation(
                f"C0 81 00 00 {ANALOG}", function=link.PrimaryFunction.CONFIRMED_USER_DATA
            )
        )
        (frame,) = link.FrameReader().feed(reply)
        assert frame.function == link.SecondaryFunction.ACK
        assert association.take().complete

    def test_a_secondary_frame_is_an_answer_to_nothing_and_is_ignored(self):
        association, _ = _built()
        control = link.control_byte(
            from_master=False, primary=False, function=link.SecondaryFunction.ACK
        )
        assert association.receive(link.build(control, MASTER, OUTSTATION)) == b""
