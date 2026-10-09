"""Deliberate misbehavior, and that it is off until it is turned on.

A deviation makes the master break a protocol rule, so a test can see whether
an outstation rejects what the standard says it must. Each is tested two ways:
the octets it changes, against a frame written out here, and that the master
sends what the association built when the deviation is off.

Three certification procedures are reproduced through the socket master with a
deviation on: a frame with a corrupt header checksum, a frame with a corrupt
data checksum, and a segment with no first segment are each met with silence,
as IEEE 1815-2012 6.6.2.5 and clause 7 require, so an integrity poll times out;
with the deviation off the same poll completes.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from profile_fixtures import for_reference_der

from py1815 import crc, link, transport
from py1815.master import Deviations, Loopback, Outcome, Outstation
from py1815.master import deviations as dev
from py1815.master.service import Service
from py1815.profile import der, load
from py1815.profile.model import Composition
from py1815.server import OutstationServer

# A valid request frame, built as the master would: a link frame from master
# (1) to outstation (1024), carrying one transport segment (FIR and FIN set,
# sequence 0) whose fragment is an application read.
_FRAGMENT = bytes([0xC0, 0x01, 0x3C, 0x02, 0x06])  # app control, READ, class 1 all
_TRANSPORT = bytes([transport.FIR_MASK | transport.FIN_MASK | 0])  # FIR, FIN, seq 0
_PAYLOAD = _TRANSPORT + _FRAGMENT
_FRAME = link.build(0xC4, 1024, 1, _PAYLOAD)


def _valid(frame: bytes) -> link.LinkFrame:
    """Parse a frame, which raises if any checksum or length is wrong."""
    return link.parse(frame)


# ------------------------------------------------------------ the transforms


class TestTheTransforms:
    def test_a_built_frame_is_the_fixture(self):
        # The fixture parses, so the transforms start from a valid frame.
        parsed = _valid(_FRAME)
        assert parsed.payload == _PAYLOAD and parsed.destination == 1024

    def test_corrupt_header_crc_flips_only_the_header_checksum(self):
        out = dev.corrupt_header_crc(_FRAME)
        assert len(out) == len(_FRAME)
        assert out[:8] == _FRAME[:8] and out[9:] == _FRAME[9:]
        assert out[8] != _FRAME[8]
        with pytest.raises(link.LinkFrameError, match="header CRC"):
            _valid(out)

    def test_corrupt_body_crc_flips_only_the_last_octet(self):
        out = dev.corrupt_body_crc(_FRAME)
        assert out[:-1] == _FRAME[:-1] and out[-1] != _FRAME[-1]
        with pytest.raises(link.LinkFrameError, match="data block CRC"):
            _valid(out)

    def test_truncate_drops_the_last_octet(self):
        out = dev.truncate(_FRAME)
        assert out == _FRAME[:-1]
        with pytest.raises(link.LinkFrameError):
            _valid(out)

    def test_overstate_length_raises_the_length_over_the_real_size(self):
        out = dev.overstate_length(_FRAME)
        assert len(out) == len(_FRAME), "only the length octet and its checksum change"
        assert out[2] > _FRAME[2]
        # The header checksum vouches for the inflated length.
        assert crc.verify(out[: link.HEADER_SIZE])
        # Which then disagrees with how many octets the frame carries.
        with pytest.raises(link.LinkFrameError, match="length octet describes"):
            _valid(out)

    def test_break_transport_sequence_changes_the_sequence_and_keeps_the_frame_valid(self):
        out = dev.break_transport_sequence(_FRAME)
        parsed = _valid(out)  # a valid frame: only the transport header is wrong
        before = _PAYLOAD[0] & transport.SEQ_MASK
        after = parsed.payload[0] & transport.SEQ_MASK
        assert after != before
        assert parsed.payload[0] & transport.FIR_MASK, "FIR and FIN are left as they were"
        assert parsed.payload[1:] == _PAYLOAD[1:]

    def test_orphan_segment_clears_first_and_keeps_the_frame_valid(self):
        out = dev.orphan_segment(_FRAME)
        parsed = _valid(out)
        assert not parsed.payload[0] & transport.FIR_MASK
        assert parsed.payload[0] & transport.FIN_MASK, "only FIR is cleared"
        assert parsed.payload[1:] == _PAYLOAD[1:]

    def test_wrong_application_sequence_changes_only_the_application_control(self):
        out = dev.wrong_application_sequence(_FRAME)
        parsed = _valid(out)
        assert parsed.payload[0] == _PAYLOAD[0], "the transport header is unchanged"
        assert parsed.payload[1] & 0x0F != _PAYLOAD[1] & 0x0F
        assert parsed.payload[1] & 0xF0 == _PAYLOAD[1] & 0xF0, "the flags are unchanged"
        assert parsed.payload[2:] == _PAYLOAD[2:]


# ------------------------------------------------------------ the Deviations


class TestTheDeviations:
    def test_off_sends_what_it_was_given_unchanged(self):
        d = Deviations()
        assert not d.any_on() and d.on() == ()
        assert d.outbound(_FRAME, kind=dev.REQUEST) == [_FRAME]
        assert d.outbound(_FRAME, kind=dev.CONFIRM) == [_FRAME]

    def test_names_cover_every_field_and_describe_lists_them_all(self):
        d = Deviations()
        described = d.describe()
        assert set(described) == set(d.names())
        assert all(value is False for value in described.values())
        assert len(d.names()) == 10

    def test_set_turns_one_on_and_off_and_rejects_an_unknown_name(self):
        d = Deviations()
        d.set("silence", True)
        assert d.silence and d.any_on() and d.on() == ("silence",)
        d.set("silence", False)
        assert not d.any_on()
        with pytest.raises(ValueError, match="'nonsense' is not a deviation"):
            d.set("nonsense", True)

    def test_clear_turns_every_one_off(self):
        d = Deviations(silence=True, repeat_request=True, truncate=True)
        assert len(d.on()) == 3
        d.clear()
        assert d.on() == ()

    def test_on_lists_in_order(self):
        d = Deviations(truncate=True, silence=True, corrupt_body_crc=True)
        assert d.on() == ("silence", "corrupt_body_crc", "truncate")

    def test_silence_sends_nothing_either_way(self):
        d = Deviations(silence=True)
        assert d.outbound(_FRAME, kind=dev.REQUEST) == []
        assert d.outbound(_FRAME, kind=dev.CONFIRM) == []

    def test_repeat_request_sends_a_request_twice_and_leaves_a_confirmation_alone(self):
        d = Deviations(repeat_request=True)
        assert d.outbound(_FRAME, kind=dev.REQUEST) == [_FRAME, _FRAME]
        assert d.outbound(_FRAME, kind=dev.CONFIRM) == [_FRAME]

    def test_withhold_confirmation_drops_a_confirmation_and_leaves_a_request_alone(self):
        d = Deviations(withhold_confirmation=True)
        assert d.outbound(_FRAME, kind=dev.CONFIRM) == []
        assert d.outbound(_FRAME, kind=dev.REQUEST) == [_FRAME]

    def test_wrong_confirmation_sequence_changes_a_confirmation_only(self):
        d = Deviations(wrong_confirmation_sequence=True)
        assert d.outbound(_FRAME, kind=dev.REQUEST) == [_FRAME]
        (out,) = d.outbound(_FRAME, kind=dev.CONFIRM)
        assert out == dev.wrong_application_sequence(_FRAME)

    @pytest.mark.parametrize("name", Deviations._ON_REQUEST)
    def test_a_request_deviation_changes_a_request_and_not_a_confirmation(self, name):
        d = Deviations()
        d.set(name, True)
        (out,) = d.outbound(_FRAME, kind=dev.REQUEST)
        assert out != _FRAME
        assert d.outbound(_FRAME, kind=dev.CONFIRM) == [_FRAME]

    def test_a_bad_kind_is_refused(self):
        with pytest.raises(ValueError, match="not an outbound kind"):
            Deviations().outbound(_FRAME, kind="sideways")

    def test_a_request_deviation_changes_only_the_first_frame(self):
        two = _FRAME + _FRAME
        d = Deviations(corrupt_header_crc=True)
        (out,) = d.outbound(two, kind=dev.REQUEST)
        assert out[len(_FRAME) :] == _FRAME, "the second frame is untouched"
        assert out[: len(_FRAME)] == dev.corrupt_header_crc(_FRAME)


# ----------------------------------------------------- through the loopback


@pytest.fixture
def simulation() -> der.Simulation:
    return der.build(load.resolve(for_reference_der(), Composition()))


def _master(simulation: der.Simulation) -> Loopback:
    return Loopback(simulation.outstation.session(need_time=False))


#: The deviations that make a one-segment request unreadable, so the outstation
#: says nothing. Each damages the frame the association built.
_SILENCING = (
    "corrupt_header_crc",
    "corrupt_body_crc",
    "truncate",
    "overstate_length",
    "orphan_segment",
)


class TestThroughTheLoopback:
    def test_with_no_deviation_a_poll_completes(self, simulation):
        master = _master(simulation)
        assert master.integrity_poll().complete

    @pytest.mark.parametrize("name", _SILENCING)
    def test_a_corrupt_request_is_ignored_and_the_poll_times_out(self, name, simulation):
        master = _master(simulation)
        master.deviations.set(name, True)
        poll = master.integrity_poll()
        assert not poll.complete and not poll.fragments, f"{name}: the outstation answered"

    @pytest.mark.parametrize("name", _SILENCING)
    def test_the_same_request_with_the_deviation_off_completes(self, name, simulation):
        # A fresh outstation, because a damaged frame can leave the one that
        # received it resynchronizing; off, the frame the association built
        # reaches it whole.
        master = _master(simulation)
        master.deviations.set(name, True)
        master.deviations.set(name, False)
        assert master.integrity_poll().complete

    def test_breaking_the_sequence_of_a_lone_segment_is_harmless(self, simulation):
        # A request that fits one segment is a complete fragment whatever its
        # transport sequence, so the outstation reads it. The sequence matters
        # only across the segments of a longer fragment.
        master = _master(simulation)
        master.deviations.set("break_transport_sequence", True)
        assert master.integrity_poll().complete

    def test_silence_makes_every_request_time_out(self, simulation):
        master = _master(simulation)
        master.deviations.set("silence", True)
        assert not master.integrity_poll().complete
        master.deviations.set("silence", False)
        assert master.integrity_poll().complete

    def test_repeat_request_sends_the_request_twice_and_the_outstation_still_answers(
        self, simulation
    ):
        master = _master(simulation)
        session = master.session
        received: list[bytes] = []
        original = session.receive

        def spy(octets: bytes) -> bytes:
            received.append(octets)
            return original(octets)

        session.receive = spy  # type: ignore[method-assign]
        master.deviations.set("repeat_request", True)
        poll = master.integrity_poll()
        # The request reached the outstation as two frames in one delivery, and
        # the outstation answered all the same.
        assert poll.complete
        assert received[0].count(link.START) == 2, "the request was sent twice"

    def test_without_repeat_the_request_is_one_frame(self, simulation):
        master = _master(simulation)
        received: list[bytes] = []
        original = master.session.receive

        def spy(octets: bytes) -> bytes:
            received.append(octets)
            return original(octets)

        master.session.receive = spy  # type: ignore[method-assign]
        assert master.integrity_poll().complete
        assert received[0].count(link.START) == 1


# ------------------------------------------------------ over a socket


@pytest_asyncio.fixture
async def served(simulation):
    """A simulated DER on a socket, and a master connected to it that only reads."""
    server = OutstationServer(simulation.outstation.session(need_time=False), bind="127.0.0.1:0")
    await server.start()
    master = Outstation(
        "lab",
        host="127.0.0.1",
        port=server.port,
        response_timeout=0.3,
        tasks=None,
        manual=True,
        reconnect=None,
    )
    await master.connect()
    try:
        yield master
    finally:
        await master.close()
        await server.stop()


@pytest.mark.asyncio
class TestOverASocket:
    """Three certification procedures reproduced through the socket master."""

    async def test_a_corrupt_header_checksum_is_met_with_silence(self, served):
        # IEEE 1815-2012 6.6.2.5: a frame whose header CRC fails draws no answer.
        served.deviations.set("corrupt_header_crc", True)
        poll = await served.integrity_poll()
        assert poll.outcome is Outcome.TIMEOUT and not poll.fragments
        served.deviations.set("corrupt_header_crc", False)
        assert (await served.integrity_poll()).complete

    async def test_a_corrupt_data_checksum_is_met_with_silence(self, served):
        # IEEE 1815-2012 6.6.2.5: a frame whose data-block CRC fails draws no answer.
        served.deviations.set("corrupt_body_crc", True)
        poll = await served.integrity_poll()
        assert poll.outcome is Outcome.TIMEOUT and not poll.fragments
        served.deviations.set("corrupt_body_crc", False)
        assert (await served.integrity_poll()).complete

    async def test_a_segment_with_no_first_segment_is_met_with_silence(self, served):
        # IEEE 1815-2012 clause 7: reassembly refuses a continuation that begins
        # no fragment, so the request is never delivered and nothing answers.
        served.deviations.set("orphan_segment", True)
        poll = await served.integrity_poll()
        assert poll.outcome is Outcome.TIMEOUT and not poll.fragments
        served.deviations.set("orphan_segment", False)
        assert (await served.integrity_poll()).complete

    async def test_the_deviate_operation_turns_them_on_through_the_service(self, served):
        service = Service(allow_control=False)
        service.master._outstations["lab"] = served
        answer = await service.handle(
            {"op": "deviate", "outstation": "lab", "params": {"set": {"corrupt_header_crc": True}}}
        )
        assert answer["ok"]
        assert answer["result"]["on"] == ["corrupt_header_crc"]
        assert served.deviations.corrupt_header_crc
        assert (await served.integrity_poll()).outcome is Outcome.TIMEOUT
        cleared = await service.handle(
            {"op": "deviate", "outstation": "lab", "params": {"clear": True}}
        )
        assert cleared["result"]["on"] == []
        assert (await served.integrity_poll()).complete
