"""Walking a control request, where indices interleave with objects.

A read names what it wants and stops. A control carries the objects with it, and
each is prefixed by its own index, so the two cannot be read separately -- which
is why ``parse_request`` stops at the first header and leaves the rest.

Every failure here is a failure of the fragment rather than of one object. That
is D15 rather than a preference: a truncated body may leave no complete object,
and a status has to be attached to something.
"""

from __future__ import annotations

import contextlib

import pytest

from py1815.application import RequestError, parse_object_blocks, parse_request
from py1815.control import (
    AnalogOutput,
    ControlRelayOutputBlock,
    OperationType,
    decode_control,
    object_size,
)

#: FIR, FIN, sequence 0, DIRECT_OPERATE.
DIRECT_OPERATE = "c005"
#: Group 12 variation 1, qualifier 0x17 (one-octet count, one-octet index).
CROB_HEADER_2 = "0c011702"
#: LATCH_ON, count 1, 100 ms on, 200 ms off, status SUCCESS.
LATCH_ON = "030164000000c800000000"


def _blocks(hex_fragment: str):
    return parse_object_blocks(parse_request(bytes.fromhex(hex_fragment)), object_size)


class TestObjectSizes:
    @pytest.mark.parametrize(
        ("group", "variation", "size"),
        [(12, 1, 11), (41, 1, 5), (41, 2, 3), (41, 3, 5), (41, 4, 9)],
    )
    def test_known(self, group, variation, size):
        assert object_size(group, variation) == size

    @pytest.mark.parametrize(("group", "variation"), [(12, 2), (41, 5), (30, 1), (99, 1)])
    def test_unknown_is_none_rather_than_a_guess(self, group, variation):
        assert object_size(group, variation) is None


class TestWalkingOneBlock:
    def test_two_crobs_arrive_with_their_indices(self):
        blocks = _blocks(DIRECT_OPERATE + CROB_HEADER_2 + "00" + LATCH_ON + "07" + LATCH_ON)

        assert len(blocks) == 1
        assert [index for index, _ in blocks[0].items] == [0, 7]
        assert blocks[0].header.group == 12
        assert blocks[0].header.variation == 1

    def test_the_octets_decode_to_the_control_that_was_sent(self):
        blocks = _blocks(DIRECT_OPERATE + CROB_HEADER_2 + "00" + LATCH_ON + "07" + LATCH_ON)

        _, data = blocks[0].items[0]
        control = decode_control(12, 1, data)

        assert isinstance(control, ControlRelayOutputBlock)
        assert control.operation is OperationType.LATCH_ON
        assert control.on_time_ms == 100

    def test_a_repeated_index_is_not_collapsed(self):
        """A request naming the same point twice named it twice. Collapsing here
        would answer fewer objects than were asked about, and D14 answers one
        status per object sent."""
        blocks = _blocks(DIRECT_OPERATE + CROB_HEADER_2 + "03" + LATCH_ON + "03" + LATCH_ON)

        assert [index for index, _ in blocks[0].items] == [3, 3]

    def test_a_sixteen_bit_qualifier_reads_wider_counts_and_indices(self):
        header = "0c0128" + "0100"  # qualifier 0x28, count 1 as uint16
        blocks = _blocks(DIRECT_OPERATE + header + "0401" + LATCH_ON)

        assert [index for index, _ in blocks[0].items] == [260]


class TestWalkingSeveralBlocks:
    def test_a_second_header_follows_the_first_block(self):
        analog = "2901170101" + "50c3000000"  # g41v1, qualifier 0x17, count 1, index 1
        blocks = _blocks(
            DIRECT_OPERATE + CROB_HEADER_2 + "00" + LATCH_ON + "07" + LATCH_ON + analog
        )

        assert [(b.header.group, b.header.variation) for b in blocks] == [(12, 1), (41, 1)]
        assert len(blocks[0].items) == 2
        assert len(blocks[1].items) == 1

    def test_the_second_block_decodes_as_its_own_kind(self):
        analog = "2901170101" + "50c3000000"
        blocks = _blocks(
            DIRECT_OPERATE + CROB_HEADER_2 + "00" + LATCH_ON + "07" + LATCH_ON + analog
        )

        index, data = blocks[1].items[0]
        command = decode_control(41, 1, data)

        assert index == 1
        assert isinstance(command, AnalogOutput)
        assert command.value == 50000


class TestTheFragmentIsRefusedWhenNothingCanBeAnswered:
    def test_a_body_shorter_than_its_count_declares(self):
        with pytest.raises(RequestError, match="holds fewer"):
            _blocks(DIRECT_OPERATE + CROB_HEADER_2 + "00" + LATCH_ON)

    def test_an_object_truncated_mid_way(self):
        with pytest.raises(RequestError, match="holds fewer"):
            _blocks(DIRECT_OPERATE + "0c011701" + "00" + LATCH_ON[:-4])

    def test_a_group_whose_width_is_unknown(self):
        with pytest.raises(RequestError, match="group 12 variation 9"):
            _blocks(DIRECT_OPERATE + "0c091701" + "00" + LATCH_ON)

    def test_a_qualifier_that_prefixes_no_index(self):
        """Without an index per object there is no way to tell them apart, and
        no point to attach a status to."""
        with pytest.raises(RequestError, match="prefixes no index"):
            _blocks(DIRECT_OPERATE + "0c0100" + "0001" + LATCH_ON)

    def test_a_truncated_second_header(self):
        with pytest.raises(RequestError, match="truncated"):
            _blocks(DIRECT_OPERATE + "0c011701" + "00" + LATCH_ON + "2901")

    def test_no_object_header_at_all(self):
        with pytest.raises(RequestError, match="no object header"):
            _blocks(DIRECT_OPERATE)


class TestEveryBodyLengthProducesAnAnswerOrARefusal:
    """Nothing escapes as an untyped exception.

    The session answers a master that is waiting, so a body it cannot read has
    to arrive as ``RequestError`` rather than as an IndexError from inside a
    slice.
    """

    #: From two, which is where an application header ends and this function's
    #: input begins. Anything shorter belongs to ``parse_request``.
    @pytest.mark.parametrize("length", range(2, 40))
    def test_truncating_a_valid_request_anywhere(self, length):
        full = bytes.fromhex(DIRECT_OPERATE + CROB_HEADER_2 + "00" + LATCH_ON + "07" + LATCH_ON)

        with contextlib.suppress(RequestError):
            parse_object_blocks(parse_request(full[:length]), object_size)
