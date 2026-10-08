"""Tests for the request bodies the master builds, pinned to their octets."""

from __future__ import annotations

import pytest

from py1815.decode import PointType
from py1815.master import requests

AI, BI = PointType.ANALOG_INPUT, PointType.BINARY_INPUT


class TestReadPoints:
    """A read of named points uses start-stop ranges, which every outstation accepts."""

    def test_consecutive_indices_are_one_8_bit_range(self):
        # Group 30, variation 0, qualifier 0x00, start 2, stop 4.
        assert requests.read_points({AI: [2, 3, 4]}) == bytes.fromhex("1E 00 00 02 04")

    def test_separate_indices_are_one_range_each(self):
        assert requests.read_points({AI: [4, 6, 8]}) == bytes.fromhex(
            "1E 00 00 04 04  1E 00 00 06 06  1E 00 00 08 08"
        )

    def test_indices_are_sorted_and_repeats_dropped(self):
        assert requests.read_points({BI: [9, 2, 9, 3]}) == bytes.fromhex(
            "01 00 00 02 03  01 00 00 09 09"
        )

    def test_an_index_above_255_uses_the_16_bit_range(self):
        # Qualifier 0x01, start and stop as 16-bit little-endian.
        assert requests.read_points({AI: [300, 301]}) == bytes.fromhex("1E 00 01 2C 01 2D 01")

    def test_a_run_that_crosses_255_is_one_16_bit_range(self):
        assert requests.read_points({AI: [255, 256]}) == bytes.fromhex("1E 00 01 FF 00 00 01")

    def test_none_asks_for_every_point_of_the_type(self):
        assert requests.read_points({BI: None}) == bytes.fromhex("01 00 06")

    def test_types_keep_the_order_given(self):
        assert requests.read_points({AI: [1], BI: None}) == bytes.fromhex(
            "1E 00 00 01 01  01 00 06"
        )

    def test_no_index_list_qualifier_is_used(self):
        """Qualifiers 0x17 and 0x28 are optional for a Level 2 outstation."""
        body = requests.read_points({AI: list(range(0, 600, 7)), BI: [0, 4]})
        qualifiers = set()
        position = 0
        while position < len(body):
            qualifier = body[position + 2]
            qualifiers.add(qualifier)
            position += 5 if qualifier == 0x00 else 7
        assert qualifiers <= {0x00, 0x01}

    @pytest.mark.parametrize(
        "points, says",
        [
            ({}, "at least one point type"),
            ({AI: []}, "at least one index"),
            ({AI: [-1]}, "0 to 65535"),
            ({AI: [65536]}, "0 to 65535"),
        ],
    )
    def test_a_read_that_cannot_be_built_is_refused(self, points, says):
        with pytest.raises(ValueError, match=says):
            requests.read_points(points)
