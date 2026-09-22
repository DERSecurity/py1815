"""The DNP3 transport function, tested as the suspicious receiver it has to be.

Every rule here exists for a series that did not arrive as promised, so the
tests are mostly about series that do not.
"""

from __future__ import annotations

import pytest

from py1815.transport import (
    FIN_MASK,
    FIR_MASK,
    MAX_PAYLOAD,
    MAX_SEGMENT,
    SEQ_MASK,
    SEQUENCE_MODULUS,
    Reassembler,
    TransportError,
    header_byte,
    segment,
)


def _headers(segments):
    return [(bool(s[0] & FIR_MASK), bool(s[0] & FIN_MASK), s[0] & SEQ_MASK) for s in segments]


class TestSegmentation:
    def test_a_short_fragment_is_one_segment_marked_first_and_final(self):
        segments = segment(b"short", first_sequence=7)

        assert _headers(segments) == [(True, True, 7)]
        assert segments[0][1:] == b"short"

    def test_an_empty_fragment_still_produces_a_segment(self):
        """A response carrying a header and no objects is a legal thing to send,
        and returning nothing would drop it silently."""
        assert _headers(segment(b"")) == [(True, True, 0)]

    def test_a_fragment_that_exactly_fills_one_segment_is_not_split(self):
        assert len(segment(b"x" * MAX_PAYLOAD)) == 1

    def test_one_octet_more_takes_two_segments(self):
        segments = segment(b"x" * (MAX_PAYLOAD + 1))

        assert _headers(segments) == [(True, False, 0), (False, True, 1)]
        assert len(segments[0]) == MAX_SEGMENT
        assert segments[1][1:] == b"x"

    def test_sequence_numbers_wrap_at_64(self):
        segments = segment(b"x" * (MAX_PAYLOAD * 3), first_sequence=SEQ_MASK)

        assert [s[0] & SEQ_MASK for s in segments] == [63, 0, 1]

    def test_every_segment_fits_a_link_frame(self):
        assert all(len(s) <= MAX_SEGMENT for s in segment(b"x" * 5000))

    @pytest.mark.parametrize(
        ("first", "final", "sequence", "octet"),
        [
            (True, False, 1, 0x41),
            (False, True, 1, 0x81),
            (True, True, 0, 0xC0),
            (False, False, 63, 0x3F),
        ],
    )
    def test_the_header_encodes_to_the_octet_the_standard_specifies(
        self, first, final, sequence, octet
    ):
        """Literal octets, not the module's own masks.

        FIR is 0x40 here and FIN is 0x80 -- the reverse of the application
        layer. A test written against the constants would pass with the two
        swapped, which is the one mistake worth catching."""
        assert header_byte(first=first, final=final, sequence=sequence) == octet

    def test_the_segmenter_emits_that_same_octet(self):
        assert segment(b"a")[0][0] == 0xC0


class TestReassembly:
    def test_a_single_segment_completes_immediately(self):
        assert Reassembler().add(segment(b"whole")[0]) == b"whole"

    def test_a_series_completes_on_the_final_segment(self):
        fragment = bytes(range(256)) * 3
        reassembler = Reassembler()

        results = [reassembler.add(s) for s in segment(fragment)]

        assert results[:-1] == [None] * (len(results) - 1)
        assert results[-1] == fragment

    def test_the_reassembler_is_ready_again_afterwards(self):
        reassembler = Reassembler()
        for s in segment(b"x" * (MAX_PAYLOAD + 1)):
            reassembler.add(s)

        assert not reassembler.in_progress
        assert reassembler.add(segment(b"again")[0]) == b"again"

    def test_a_series_that_wraps_the_sequence_reassembles(self):
        fragment = b"y" * (MAX_PAYLOAD * 2)
        reassembler = Reassembler()

        results = [reassembler.add(s) for s in segment(fragment, first_sequence=SEQ_MASK)]

        assert results[-1] == fragment


class TestBrokenSeries:
    def test_a_continuation_without_a_first_segment_is_refused(self):
        with pytest.raises(TransportError, match="never started"):
            Reassembler().add(bytes([header_byte(first=False, final=True, sequence=3)]) + b"x")

    def test_a_gap_in_the_sequence_is_refused_and_abandons_the_series(self):
        reassembler = Reassembler()
        reassembler.add(bytes([header_byte(first=True, final=False, sequence=0)]) + b"a")

        with pytest.raises(TransportError, match="sequence is 2"):
            reassembler.add(bytes([header_byte(first=False, final=True, sequence=2)]) + b"b")

        assert not reassembler.in_progress

    def test_a_first_segment_mid_series_starts_over(self):
        """Not an error: a sender that timed out starts again, and what was held
        belongs to the series it abandoned."""
        reassembler = Reassembler()
        reassembler.add(bytes([header_byte(first=True, final=False, sequence=0)]) + b"stale")

        assert reassembler.add(segment(b"fresh")[0]) == b"fresh"

    def test_an_endless_series_is_abandoned_rather_than_accumulated(self):
        reassembler = Reassembler(max_fragment=MAX_PAYLOAD * 2)
        sequence = 0
        with pytest.raises(TransportError, match="abandoned"):
            for index in range(4):
                header = header_byte(first=index == 0, final=False, sequence=sequence)
                reassembler.add(bytes([header]) + b"x" * MAX_PAYLOAD)
                sequence = (sequence + 1) % SEQUENCE_MODULUS

        assert not reassembler.in_progress

    def test_an_empty_segment_is_refused(self):
        with pytest.raises(TransportError, match="empty"):
            Reassembler().add(b"")

    def test_a_segment_too_large_for_a_link_frame_is_refused(self):
        with pytest.raises(TransportError, match="maximum"):
            Reassembler().add(bytes([0xC0]) + b"x" * MAX_SEGMENT)

    @pytest.mark.parametrize("bad", [b"", bytes([0xC0]) + b"x" * MAX_SEGMENT])
    def test_a_malformed_segment_abandons_the_series_it_interrupted(self, bad):
        """Refusing without resetting let the next in-sequence segment append to
        data from before the malformed one, splicing two requests into one."""
        reassembler = Reassembler()
        reassembler.add(bytes([header_byte(first=True, final=False, sequence=0)]) + b"before")

        with pytest.raises(TransportError):
            reassembler.add(bad)

        assert not reassembler.in_progress
        with pytest.raises(TransportError, match="never started"):
            reassembler.add(bytes([header_byte(first=False, final=True, sequence=1)]) + b"after")

    def test_reset_discards_a_partial_fragment(self):
        """The session resets on a link restart: segments from before one must
        not be completed by segments from after it."""
        reassembler = Reassembler()
        reassembler.add(bytes([header_byte(first=True, final=False, sequence=0)]) + b"before")
        reassembler.reset()

        with pytest.raises(TransportError, match="never started"):
            reassembler.add(bytes([header_byte(first=False, final=True, sequence=1)]) + b"after")
