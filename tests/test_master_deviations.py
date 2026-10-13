"""Deliberate misbehavior, and that it is off until it is turned on.

A deviation makes the master break a protocol rule, so a test can see whether
an outstation rejects what the standard says it must. Each is tested two ways:
the octets it changes, against a frame written out here, and that the master
sends what the association built when the deviation is off.

Three faults are sent through the socket master with a deviation on: a frame
with a corrupt header checksum, a frame with a corrupt data checksum, and a
segment with no first segment are each met with silence, as IEEE 1815-2012
9.2.4.3 and 8.2.4 require, so an integrity poll times out; with the deviation
off the same poll completes. The first two are the invalid CRC procedure of
section 6.6.2 of the DNP Users Group's IED Certification Procedure.
"""

from __future__ import annotations

import dataclasses
import itertools

import pytest
import pytest_asyncio
from profile_fixtures import for_reference_der

from py1815 import crc, link, transport
from py1815.application import FunctionCode
from py1815.master import Deviations, Loopback, MasterAssociation, Outcome, Outstation
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
# The frame, written out: the header, its CRC (CA 8A), the six octets of user
# data, and their CRC (54 E0).
_FRAME = bytes.fromhex("05 64 0B C4 00 04 01 00 CA 8A C0 C0 01 3C 02 06 54 E0")

# A link acknowledgment from the master (1) to the outstation (1024): a header
# with control 0x80 (from a master, secondary, ACK) and no user data.
_LINK_ACK = bytes.fromhex("05 64 05 80 00 04 01 00 6D C7")
# An application confirmation of sequence 3: the transport header, application
# control 0xC3 (FIR, FIN, sequence 3) and function code 0x00.
_CONFIRMATION = bytes.fromhex("05 64 08 C4 00 04 01 00 9A 19 C0 C3 00 98 26")
# The same confirmation with application control 0xC4, sequence 4.
_CONFIRMATION_OF_4 = bytes.fromhex("05 64 08 C4 00 04 01 00 9A 19 C0 C4 00 F9 A1")
# The confirmation of an unsolicited response of sequence 3: application
# control 0xD3, which is 0xC3 with the UNS bit set. The CRC is B0 F9.
_UNSOLICITED_CONFIRMATION = bytes.fromhex("05 64 08 C4 00 04 01 00 9A 19 C0 D3 00 B0 F9")


def _valid(frame: bytes) -> link.LinkFrame:
    """Parse a frame, which raises if any checksum or length is wrong."""
    return link.parse(frame)


# ------------------------------------------------------------ the transforms


class TestTheTransforms:
    def test_a_built_frame_is_the_fixture(self):
        # The fixture parses, so the transforms start from a valid frame.
        parsed = _valid(_FRAME)
        assert parsed.payload == _PAYLOAD and parsed.destination == 1024
        assert link.build(0xC4, 1024, 1, _PAYLOAD) == _FRAME

    @pytest.mark.parametrize(
        ("transform", "octets"),
        [
            # The first octet of the header CRC, CA, becomes 35.
            (dev.corrupt_header_crc, "05 64 0B C4 00 04 01 00 35 8A C0 C0 01 3C 02 06 54 E0"),
            # The last octet of the data-block CRC, E0, becomes 1F.
            (dev.corrupt_body_crc, "05 64 0B C4 00 04 01 00 CA 8A C0 C0 01 3C 02 06 54 1F"),
            # The last octet is gone.
            (dev.truncate, "05 64 0B C4 00 04 01 00 CA 8A C0 C0 01 3C 02 06 54"),
            # The length octet, 0B, becomes 1B, and the header CRC is 0B F2.
            (dev.overstate_length, "05 64 1B C4 00 04 01 00 0B F2 C0 C0 01 3C 02 06 54 E0"),
            # The transport header, C0, becomes C1: sequence 1. The CRC is B3 55.
            (
                dev.break_transport_sequence,
                "05 64 0B C4 00 04 01 00 CA 8A C1 C0 01 3C 02 06 B3 55",
            ),
            # The transport header, C0, becomes 80: FIR clear. The CRC is 29 4E.
            (dev.orphan_segment, "05 64 0B C4 00 04 01 00 CA 8A 80 C0 01 3C 02 06 29 4E"),
            # The transport header, C0, becomes 40: FIN clear. The CRC is D7 F1.
            (dev.endless_series, "05 64 0B C4 00 04 01 00 CA 8A 40 C0 01 3C 02 06 D7 F1"),
            # The source address, 1, becomes 2. The header CRC is 61 3A.
            (
                dev.second_master_address,
                "05 64 0B C4 00 04 02 00 61 3A C0 C0 01 3C 02 06 54 E0",
            ),
            # The application control, C0, becomes C1: sequence 1. The CRC is 52 C3.
            (
                dev.wrong_application_sequence,
                "05 64 0B C4 00 04 01 00 CA 8A C0 C1 01 3C 02 06 52 C3",
            ),
        ],
        ids=lambda value: getattr(value, "__name__", None),
    )
    def test_a_transform_of_the_fixture_is_these_octets(self, transform, octets):
        assert transform(_FRAME) == bytes.fromhex(octets)

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

    def test_overstate_length_of_a_full_frame_drops_its_last_data_block(self):
        # A frame of 250 user-data octets has length octet 0xFF, which cannot
        # be raised. Its last data block is ten octets and a two-octet CRC.
        full = link.build(0xC4, 1024, 1, bytes(250))
        assert full[: link.HEADER_SIZE] == bytes.fromhex("05 64 FF C4 00 04 01 00 19 F1")
        out = dev.overstate_length(full)
        assert out == full[:-12], "the header is as built and the last block is gone"
        with pytest.raises(link.LinkFrameError, match="length octet describes"):
            _valid(out)

    def test_the_second_master_address_is_not_the_outstations_own(self):
        # From master 1 to outstation 2, the next address up is the
        # outstation's, so the one after it is used: 3.
        to_outstation_2 = bytes.fromhex("05 64 0B C4 02 00 01 00 83 24") + _FRAME[10:]
        assert _valid(to_outstation_2).destination == 2
        assert dev.second_master_address(to_outstation_2) == (
            bytes.fromhex("05 64 0B C4 02 00 03 00 66 3F") + _FRAME[10:]
        )

    def test_the_second_master_address_is_a_station_address(self):
        # 65519 is the highest address a station may have, so the address
        # below it is used: 65518.
        from_the_highest = bytes.fromhex("05 64 0B C4 01 00 EF FF 61 3C") + _FRAME[10:]
        assert _valid(from_the_highest).source == 65519
        assert dev.second_master_address(from_the_highest) == (
            bytes.fromhex("05 64 0B C4 01 00 EE FF 2F 97") + _FRAME[10:]
        )

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
        switches = {each.name for each in dataclasses.fields(d) if each.type == "bool"}
        assert set(d.names()) == switches

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
        assert d.outbound(_CONFIRMATION, kind=dev.CONFIRM) == []
        assert d.outbound(_FRAME, kind=dev.REQUEST) == [_FRAME]

    def test_wrong_confirmation_sequence_changes_a_confirmation_only(self):
        d = Deviations(wrong_confirmation_sequence=True)
        assert d.outbound(_FRAME, kind=dev.REQUEST) == [_FRAME]
        assert d.outbound(_CONFIRMATION, kind=dev.CONFIRM) == [_CONFIRMATION_OF_4]

    def test_withhold_confirmation_still_sends_the_link_acknowledgment(self):
        d = Deviations(withhold_confirmation=True)
        assert d.outbound(_LINK_ACK + _CONFIRMATION, kind=dev.CONFIRM) == [_LINK_ACK]

    def test_wrong_confirmation_sequence_changes_the_confirmation_after_a_link_acknowledgment(
        self,
    ):
        d = Deviations(wrong_confirmation_sequence=True)
        assert d.outbound(_LINK_ACK + _CONFIRMATION, kind=dev.CONFIRM) == [
            _LINK_ACK,
            _CONFIRMATION_OF_4,
        ]

    @pytest.mark.parametrize("name", Deviations._ON_CONFIRM)
    def test_a_link_reply_with_no_confirmation_is_sent_as_built(self, name):
        d = Deviations()
        d.set(name, True)
        assert d.outbound(_LINK_ACK, kind=dev.CONFIRM) == [_LINK_ACK]

    def test_the_confirmation_of_a_response_in_a_confirmed_link_frame_is_the_frame_changed(self):
        # An outstation that asks for a link acknowledgment and an application
        # confirmation in one frame is answered with both, the acknowledgment
        # first. The deviation has to act on the second.
        association = MasterAssociation()
        association.request(FunctionCode.READ, bytes.fromhex("3C 02 06"))
        control = link.control_byte(
            from_master=False, primary=True, function=link.PrimaryFunction.CONFIRMED_USER_DATA
        )
        # Transport FIR and FIN, then a response with FIR, FIN and CON, sequence 0.
        response = link.build(control, 1, 1024, bytes.fromhex("C0 E0 81 00 00"))
        reply = association.receive(response)
        assert reply[: len(_LINK_ACK)] == _LINK_ACK
        assert link.parse(reply[len(_LINK_ACK) :]).payload[1:] == bytes.fromhex("C0 00")

        wrong = Deviations(wrong_confirmation_sequence=True)
        acknowledgment, confirmation = wrong.outbound(reply, kind=dev.CONFIRM)
        assert acknowledgment == _LINK_ACK
        assert link.parse(confirmation).payload[1:] == bytes.fromhex("C1 00"), "sequence 1"
        assert Deviations(withhold_confirmation=True).outbound(reply, kind=dev.CONFIRM) == [
            _LINK_ACK
        ]

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
        first, second = d.outbound(two, kind=dev.REQUEST)
        assert second == _FRAME, "the second frame is untouched, and is a write of its own"
        assert first == dev.corrupt_header_crc(_FRAME)

    def test_overstate_length_changes_a_request_whose_first_frame_is_full(self):
        # A long request fills its first frame, so that frame's length octet is
        # already 0xFF. The deviation still has to send something non-conformant.
        full = link.build(0xC4, 1024, 1, bytes(250))
        d = Deviations(overstate_length=True)
        first, second = d.outbound(full + _FRAME, kind=dev.REQUEST)
        assert first == full[:-12] and second == _FRAME

    @pytest.mark.parametrize(
        "pair", list(itertools.combinations(Deviations._ON_REQUEST, 2)), ids=" and ".join
    )
    def test_two_request_deviations_on_together_change_the_request(self, pair):
        d = Deviations()
        for name in pair:
            d.set(name, True)
        assert d.outbound(_FRAME, kind=dev.REQUEST) != [_FRAME]

    def test_a_damaged_frame_still_carries_the_transport_change_made_with_it(self):
        # The orphaned segment is built while the frame's checksums verify, and
        # the data-block checksum is flipped afterwards.
        d = Deviations(orphan_segment=True, corrupt_body_crc=True)
        (out,) = d.outbound(_FRAME, kind=dev.REQUEST)
        assert out == bytes.fromhex("05 64 0B C4 00 04 01 00 CA 8A 80 C0 01 3C 02 06 29 B1")

    def test_endless_series_changes_the_last_frame_of_a_request(self):
        d = Deviations(endless_series=True)
        first, last = d.outbound(_FRAME + _FRAME, kind=dev.REQUEST)
        assert first == _FRAME and last == dev.endless_series(_FRAME)

    def test_second_master_address_changes_every_frame_of_a_request_and_of_a_reply(self):
        d = Deviations(second_master_address=True)
        other = dev.second_master_address(_FRAME)
        assert d.outbound(_FRAME + _FRAME, kind=dev.REQUEST) == [other, other]
        assert d.outbound(_LINK_ACK + _CONFIRMATION, kind=dev.CONFIRM) == [
            bytes.fromhex("05 64 05 80 00 04 02 00 C6 77"),
            bytes.fromhex("05 64 08 C4 00 04 02 00 31 A9 C0 C3 00 98 26"),
        ]

    @pytest.mark.parametrize(
        "name", ["withhold_confirmation", "late_confirmation", "wrong_confirmation_sequence"]
    )
    def test_the_confirmation_of_an_unsolicited_response_is_left_as_built(self, name):
        # These three are about a response the master asked for.
        d = Deviations()
        d.set(name, True)
        assert d.outbound(_UNSOLICITED_CONFIRMATION, kind=dev.CONFIRM) == [
            _UNSOLICITED_CONFIRMATION
        ]
        assert d.outbound(_FRAME, kind=dev.REQUEST) == [_FRAME], "and none was held back"

    def test_withhold_unsolicited_confirmation_withholds_that_one_and_no_other(self):
        d = Deviations(withhold_unsolicited_confirmation=True)
        assert d.outbound(_UNSOLICITED_CONFIRMATION, kind=dev.CONFIRM) == []
        assert d.outbound(_LINK_ACK + _UNSOLICITED_CONFIRMATION, kind=dev.CONFIRM) == [_LINK_ACK]
        assert d.outbound(_CONFIRMATION, kind=dev.CONFIRM) == [_CONFIRMATION]
        assert d.outbound(_FRAME, kind=dev.REQUEST) == [_FRAME]

    def test_the_confirmation_the_association_makes_of_an_unsolicited_response_is_told_apart(
        self,
    ):
        association = MasterAssociation()
        control = link.control_byte(
            from_master=False, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
        )
        # Transport FIR and FIN, then an unsolicited response with FIR, FIN,
        # CON and UNS, sequence 0, and no objects.
        unsolicited = link.build(control, 1, 1024, bytes.fromhex("C0 F0 82 00 00"))
        reply = association.receive(unsolicited)
        assert link.parse(reply).payload[1:] == bytes.fromhex("D0 00"), "a confirmation with UNS"
        assert Deviations(withhold_confirmation=True).outbound(reply, kind=dev.CONFIRM) == [reply]
        assert (
            Deviations(withhold_unsolicited_confirmation=True).outbound(reply, kind=dev.CONFIRM)
            == []
        )

    def test_no_more_than_a_few_confirmations_are_held_back(self):
        # Sequences 0 to 15, each confirmed and none followed by a request.
        d = Deviations(late_confirmation=True)
        confirmations = [
            link.build(0xC4, 1024, 1, bytes([0xC0, 0xC0 | sequence, 0x00]))
            for sequence in range(16)
        ]
        for confirmation in confirmations:
            assert d.outbound(confirmation, kind=dev.CONFIRM) == []
        kept = confirmations[-dev.HELD_CONFIRMATIONS :]
        assert len(kept) < len(confirmations)
        assert d.outbound(_FRAME, kind=dev.REQUEST) == [_FRAME, *kept], "the oldest were dropped"

    def test_a_late_confirmation_follows_the_next_request(self):
        d = Deviations(late_confirmation=True)
        assert d.outbound(_LINK_ACK + _CONFIRMATION, kind=dev.CONFIRM) == [_LINK_ACK]
        assert d.outbound(_FRAME, kind=dev.REQUEST) == [_FRAME, _CONFIRMATION]
        assert d.outbound(_FRAME, kind=dev.REQUEST) == [_FRAME], "it is sent once"

    def test_a_late_confirmation_can_carry_the_wrong_sequence_as_well(self):
        d = Deviations(late_confirmation=True, wrong_confirmation_sequence=True)
        assert d.outbound(_CONFIRMATION, kind=dev.CONFIRM) == []
        assert d.outbound(_FRAME, kind=dev.REQUEST) == [_FRAME, _CONFIRMATION_OF_4]

    def test_a_confirmation_held_back_is_not_sent_once_the_deviation_is_off(self):
        d = Deviations(late_confirmation=True)
        assert d.outbound(_CONFIRMATION, kind=dev.CONFIRM) == []
        d.late_confirmation = False
        assert d.outbound(_FRAME, kind=dev.REQUEST) == [_FRAME]
        d.late_confirmation = True
        assert d.outbound(_FRAME, kind=dev.REQUEST) == [_FRAME], "nor when it is on again"

    def test_clear_forgets_a_confirmation_held_back(self):
        d = Deviations(late_confirmation=True)
        d.outbound(_CONFIRMATION, kind=dev.CONFIRM)
        d.clear()
        d.late_confirmation = True
        assert d.outbound(_FRAME, kind=dev.REQUEST) == [_FRAME]

    def test_repeat_request_repeats_every_write_of_a_changed_request(self):
        d = Deviations(repeat_request=True, corrupt_header_crc=True)
        bad = dev.corrupt_header_crc(_FRAME)
        assert d.outbound(_FRAME + _FRAME, kind=dev.REQUEST) == [bad, _FRAME, bad, _FRAME]


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
    "endless_series",
    "second_master_address",
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
    """Faults an outstation has to meet with silence, sent through the socket master."""

    async def test_a_corrupt_header_checksum_is_met_with_silence(self, served):
        # A frame whose header CRC fails draws no answer: IEEE 1815-2012 9.2.4.3, and
        # the invalid CRC procedure of section 6.6.2 of the IED Certification Procedure.
        served.deviations.set("corrupt_header_crc", True)
        poll = await served.integrity_poll()
        assert poll.outcome is Outcome.TIMEOUT and not poll.fragments
        served.deviations.set("corrupt_header_crc", False)
        assert (await served.integrity_poll()).complete

    async def test_a_corrupt_data_checksum_is_met_with_silence(self, served):
        # A frame whose data-block CRC fails draws no answer, by the same two sources.
        served.deviations.set("corrupt_body_crc", True)
        poll = await served.integrity_poll()
        assert poll.outcome is Outcome.TIMEOUT and not poll.fragments
        served.deviations.set("corrupt_body_crc", False)
        assert (await served.integrity_poll()).complete

    async def test_a_segment_with_no_first_segment_is_met_with_silence(self, served):
        # IEEE 1815-2012 8.2.4, Table 8-1: reassembly discards a continuation that begins
        # no fragment, so the request is never delivered and nothing answers.
        served.deviations.set("orphan_segment", True)
        poll = await served.integrity_poll()
        assert poll.outcome is Outcome.TIMEOUT and not poll.fragments
        served.deviations.set("orphan_segment", False)
        assert (await served.integrity_poll()).complete

    async def test_a_request_from_a_second_master_is_in_the_trace_under_that_address(self, served):
        # The simulated DER answers the one master it was told of, so the
        # request draws nothing. Another outstation may answer it.
        served.deviations.set("second_master_address", True)
        poll = await served.integrity_poll()
        assert poll.outcome is Outcome.TIMEOUT
        sent = [entry for entry in served.trace.since() if entry.direction == "tx"]
        assert sent[-1].link["source"] == 2 and "problem" not in sent[-1].link
        served.deviations.set("second_master_address", False)
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

    @pytest.mark.parametrize(
        ("params", "says"),
        [
            ({"clear": "false"}, "clear is true or false"),
            ({"clear": True, "set": {"silence": True, "nonsense": True}}, "set.nonsense is not"),
            ({"clear": True, "set": {"silence": True, "repeat_request": 1}}, "set.repeat_request"),
            ({"clear": True, "set": ["silence"]}, "set is an object"),
        ],
        ids=["clear is a string", "an unknown name", "a state is a number", "set is a list"],
    )
    async def test_a_deviate_request_with_a_mistake_in_it_changes_nothing(
        self, params, says, served
    ):
        service = Service(allow_control=False)
        service.master._outstations["lab"] = served
        served.deviations.set("truncate", True)
        answer = await service.handle({"op": "deviate", "outstation": "lab", "params": params})
        assert not answer["ok"] and answer["error"]["kind"] == "request"
        assert says in answer["error"]["message"]
        assert served.deviations.on() == ("truncate",)

    @pytest.mark.parametrize(
        ("name", "problem"),
        [
            ("corrupt_header_crc", "header CRC does not match"),
            ("corrupt_body_crc", "data block CRC at octet 10 does not match"),
            ("truncate", "length octet describes"),
            ("overstate_length", "length octet describes"),
        ],
    )
    async def test_the_trace_keeps_a_frame_no_outstation_accepts(self, name, problem, served):
        served.deviations.set(name, True)
        await served.integrity_poll()
        sent = [entry for entry in served.trace.since() if entry.direction == "tx"]
        assert sent, "the deviated request is in the trace"
        for entry in sent:
            assert problem in entry.link["problem"]
            assert entry.summary.startswith("not a valid frame: ")
            with pytest.raises(link.LinkFrameError):
                _valid(entry.octets)
            assert entry.octets in served.trace.capture(), "and in the capture, as sent"

        # A short frame is not held and read as the start of the next write:
        # the next request is read as the frame the association built.
        served.deviations.set(name, False)
        after = served.trace.last_id
        await served.integrity_poll()
        following = [entry for entry in served.trace.since(after) if entry.direction == "tx"]
        assert following[0].application["function"] == "READ"
        assert "problem" not in following[0].link
