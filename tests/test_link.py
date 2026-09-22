"""DNP3 framing, tested without a socket or an outstation in sight.

What a receiver does with a frame that is malformed, truncated, preceded by
noise, or not a frame at all is the whole substance of this layer, so it is
pinned here rather than inferred from a session test.
"""

from __future__ import annotations

import pytest

from py1815 import crc
from py1815.link import (
    DATA_BLOCK_SIZE,
    HEADER_SIZE,
    MAX_FRAME,
    MAX_USER_DATA,
    START,
    Broadcast,
    FrameReader,
    LinkFrameError,
    PrimaryFunction,
    SecondaryFunction,
    block_count,
    build,
    control_byte,
    frame_size,
    is_valid_address,
    parse,
)

MASTER_REQUEST = control_byte(
    from_master=True, primary=True, function=PrimaryFunction.UNCONFIRMED_USER_DATA
)
OUTSTATION_REPLY = control_byte(
    from_master=False, primary=False, function=SecondaryFunction.LINK_STATUS
)


class TestCrc:
    def test_the_catalogue_check_value(self):
        """CRC-16/DNP over the digits 1..9 is 0xEA82.

        The one assertion here that cannot be satisfied by an implementation
        that is self-consistently wrong.
        """
        assert crc.compute(b"123456789") == 0xEA82

    def test_the_checksum_goes_out_low_octet_first(self):
        assert crc.encode(b"123456789")[-2:] == b"\x82\xea"

    def test_verify_rejects_a_block_shorter_than_its_checksum(self):
        assert not crc.verify(b"\x00\x01")


class TestWireVectors:
    """Literal frames, so the layout is pinned by something other than itself.

    Every other test in this file builds a frame and parses it back, which
    agrees with itself even if the addresses are swapped, the endianness is
    inverted, the LENGTH field counts the wrong octets or the block CRCs sit in
    the wrong place. These two vectors are the check on all of that.
    """

    #: A published RESET_LINK_STATES frame: master to outstation, destination
    #: 10, source 1. Taken from external DNP3 documentation rather than from
    #: this implementation, which is the whole point of it.
    RESET_LINK = bytes.fromhex("056405c00a000100b1ac")

    def test_the_published_reset_link_frame_is_emitted_octet_for_octet(self):
        control = control_byte(
            from_master=True, primary=True, function=PrimaryFunction.RESET_LINK_STATES
        )

        assert build(control, destination=10, source=1) == self.RESET_LINK

    def test_the_published_frame_parses_to_the_fields_it_encodes(self):
        frame = parse(self.RESET_LINK)

        assert (frame.destination, frame.source) == (10, 1)
        assert frame.function == PrimaryFunction.RESET_LINK_STATES
        assert frame.from_master and frame.is_primary
        assert frame.payload == b""

    def test_a_populated_frame_matches_its_hand_derived_octets(self):
        """Derived by hand from two independently pinned facts: the header
        layout, which the published vector above fixes, and the CRC, which the
        catalogue check value fixes. LENGTH is 9 -- five for the control octet
        and the two addresses, four for the user data -- and the data block
        carries its own CRC after it.
        """
        expected = bytes.fromhex("056409c4000401007dacc0013c0216f4")
        control = control_byte(
            from_master=True, primary=True, function=PrimaryFunction.UNCONFIRMED_USER_DATA
        )

        built = build(control, destination=1024, source=1, payload=bytes.fromhex("c0013c02"))

        assert built == expected
        frame = parse(expected)
        assert (frame.destination, frame.source) == (1024, 1)
        assert frame.payload == bytes.fromhex("c0013c02")

    def test_the_addresses_are_not_interchangeable(self):
        """The vector would pass with destination and source swapped only if
        they happened to be equal, so they are not."""
        assert build(0xC0, destination=1, source=10) != self.RESET_LINK


class TestBuildAndParse:
    def test_a_frame_round_trips(self):
        frame = build(MASTER_REQUEST, destination=1024, source=1, payload=b"payload")
        parsed = parse(frame)

        assert parsed.destination == 1024
        assert parsed.source == 1
        assert parsed.payload == b"payload"
        assert parsed.from_master
        assert parsed.is_primary
        assert parsed.function == PrimaryFunction.UNCONFIRMED_USER_DATA

    def test_a_frame_with_no_user_data_round_trips(self):
        """REQUEST_LINK_STATUS and every acknowledgement carry no data."""
        frame = build(OUTSTATION_REPLY, destination=1, source=1024)

        assert len(frame) == HEADER_SIZE
        assert parse(frame).payload == b""

    @pytest.mark.parametrize("size", [1, DATA_BLOCK_SIZE, DATA_BLOCK_SIZE + 1, MAX_USER_DATA])
    def test_payloads_round_trip_across_the_block_boundary(self, size):
        payload = bytes(range(256))[:1] * size
        assert parse(build(MASTER_REQUEST, 1, 2, payload)).payload == payload

    def test_the_largest_frame_is_292_octets(self):
        """250 octets of user data occupy 292 on the wire: 16 blocks, 16 CRCs."""
        assert block_count(MAX_USER_DATA) == 16
        assert frame_size(MAX_USER_DATA) == MAX_FRAME
        assert len(build(MASTER_REQUEST, 1, 2, b"x" * MAX_USER_DATA)) == MAX_FRAME

    def test_building_refuses_user_data_that_does_not_fit(self):
        with pytest.raises(LinkFrameError, match="at most"):
            build(MASTER_REQUEST, 1, 2, b"x" * (MAX_USER_DATA + 1))

    def test_building_refuses_an_address_wider_than_two_octets(self):
        with pytest.raises(LinkFrameError, match="two octets"):
            build(MASTER_REQUEST, 0x10000, 2)


class TestControlByte:
    def test_each_bit_reads_back(self):
        control = control_byte(
            from_master=True,
            primary=True,
            function=PrimaryFunction.CONFIRMED_USER_DATA,
            fcb=True,
            fcv=True,
        )
        frame = parse(build(control, 1, 2))

        assert frame.from_master and frame.is_primary and frame.fcb and frame.fcv
        assert frame.function == PrimaryFunction.CONFIRMED_USER_DATA

    def test_the_fcv_bit_reads_as_dfc_on_a_secondary_frame(self):
        """One bit, two names, told apart by PRM."""
        control = control_byte(
            from_master=False, primary=False, function=SecondaryFunction.ACK, fcv=True
        )
        frame = parse(build(control, 1, 2))

        assert not frame.is_primary
        assert frame.dfc

    @pytest.mark.parametrize("address", list(Broadcast))
    def test_broadcast_destinations_are_recognized(self, address):
        assert parse(build(MASTER_REQUEST, address, 1)).is_broadcast

    def test_an_ordinary_destination_is_not_broadcast(self):
        assert not parse(build(MASTER_REQUEST, 1024, 1)).is_broadcast


class TestMalformedFrames:
    def test_a_frame_shorter_than_a_header_is_refused(self):
        with pytest.raises(LinkFrameError, match="shorter than a header"):
            parse(build(MASTER_REQUEST, 1, 2)[:-1])

    def test_a_frame_without_the_start_octets_is_refused(self):
        frame = bytearray(build(MASTER_REQUEST, 1, 2))
        frame[0] = 0x06
        with pytest.raises(LinkFrameError, match="start octets"):
            parse(bytes(frame))

    def test_a_corrupt_header_is_refused(self):
        frame = bytearray(build(MASTER_REQUEST, 1, 2, b"data"))
        frame[3] ^= 0xFF
        with pytest.raises(LinkFrameError, match="header CRC"):
            parse(bytes(frame))

    def test_a_length_below_the_minimum_is_refused(self):
        """Five is the floor: the length octet counts the control byte and both
        addresses even when there is no user data."""
        header = crc.encode(START + bytes([4, MASTER_REQUEST, 1, 0, 2, 0]))
        with pytest.raises(LinkFrameError, match="below the minimum"):
            parse(header)

    def test_a_length_that_disagrees_with_the_frame_is_refused(self):
        frame = build(MASTER_REQUEST, 1, 2, b"data")
        with pytest.raises(LinkFrameError, match="length octet describes"):
            parse(frame + b"\x00")

    def test_a_corrupt_data_block_is_refused(self):
        frame = bytearray(build(MASTER_REQUEST, 1, 2, b"data"))
        frame[-1] ^= 0xFF
        with pytest.raises(LinkFrameError, match="data block CRC"):
            parse(bytes(frame))


class TestAddresses:
    @pytest.mark.parametrize("address", [0, 1, 1024, 0xFFEF])
    def test_station_addresses_are_valid(self, address):
        assert is_valid_address(address)

    @pytest.mark.parametrize("address", [0xFFF0, Broadcast.NO_CONFIRM, 0xFFFF])
    def test_reserved_addresses_are_not(self, address):
        assert not is_valid_address(address)


class TestFrameReader:
    def test_a_frame_arriving_whole_is_returned(self):
        frame = build(MASTER_REQUEST, 1, 2, b"data")
        assert [f.payload for f in FrameReader().feed(frame)] == [b"data"]

    def test_two_frames_in_one_read_are_both_returned(self):
        reader = FrameReader()
        data = build(MASTER_REQUEST, 1, 2, b"one") + build(MASTER_REQUEST, 1, 2, b"two")

        assert [f.payload for f in reader.feed(data)] == [b"one", b"two"]

    def test_a_frame_split_octet_by_octet_is_returned_once(self):
        """TCP delivers a stream, so every split has to work, not just plausible
        ones."""
        reader = FrameReader()
        frame = build(MASTER_REQUEST, 1, 2, b"split me")

        collected = []
        for index in range(len(frame)):
            collected += reader.feed(frame[index : index + 1])

        assert [f.payload for f in collected] == [b"split me"]

    def test_noise_before_a_frame_is_skipped(self):
        reader = FrameReader()
        assert [
            f.payload for f in reader.feed(b"\xff\x00\xab" + build(MASTER_REQUEST, 1, 2, b"x"))
        ] == [b"x"]

    def test_a_corrupt_header_resynchronizes_on_the_next_frame(self):
        """The length field of a header that failed its CRC is not evidence of
        anything, so the reader steps past the start octets rather than past a
        frame that may not exist."""
        reader = FrameReader()
        corrupt = bytearray(build(MASTER_REQUEST, 1, 2, b"lost"))
        corrupt[3] ^= 0xFF

        frames = reader.feed(bytes(corrupt) + build(MASTER_REQUEST, 1, 2, b"found"))

        assert [f.payload for f in frames] == [b"found"]

    def test_a_corrupt_data_block_costs_only_its_own_frame(self):
        reader = FrameReader()
        corrupt = bytearray(build(MASTER_REQUEST, 1, 2, b"lost"))
        corrupt[-1] ^= 0xFF

        frames = reader.feed(bytes(corrupt) + build(MASTER_REQUEST, 1, 2, b"found"))

        assert [f.payload for f in frames] == [b"found"]

    def test_a_trailing_start_octet_is_kept_for_the_next_read(self):
        """The two start octets can straddle a read boundary."""
        reader = FrameReader()
        frame = build(MASTER_REQUEST, 1, 2, b"straddled")

        assert reader.feed(b"\xff" + frame[:1]) == []
        assert [f.payload for f in reader.feed(frame[1:])] == [b"straddled"]

    def test_noise_alone_accumulates_nothing(self):
        reader = FrameReader()
        reader.feed(b"\xff" * 1000)

        assert [f.payload for f in reader.feed(build(MASTER_REQUEST, 1, 2, b"x"))] == [b"x"]
