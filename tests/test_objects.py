"""Static object encoding: what a master actually reads out of a response.

The interesting cases are all about a value that does not fit, and about
quality, because quality is the whole reason this interface is more honest than
the Modbus one.
"""

from __future__ import annotations

import math
import struct

import pytest

from py1815.application import (
    FunctionCode,
    QualifierCode,
    parse_request,
)
from py1815.objects import (
    GROUP_ANALOG_INPUT,
    GROUP_ANALOG_INPUT_EVENT,
    GROUP_BINARY_INPUT,
    TIME_SIZE,
    AnalogEventVariation,
    AnalogPoint,
    AnalogQuality,
    AnalogVariation,
    BinaryPoint,
    BinaryQuality,
    BinaryVariation,
    analog_flags,
    analog_range,
    binary_flags,
    binary_range,
    encode_analog,
    encode_analog_event,
    encode_binary,
    encode_binary_event,
    encode_time,
    event_block,
)


class TestAnalogEncoding:
    def test_a_32_bit_value_carries_its_flags_first(self):
        encoded = encode_analog(
            AnalogPoint(1234, AnalogQuality.ONLINE), AnalogVariation.INT32_WITH_FLAG
        )

        assert encoded[0] == AnalogQuality.ONLINE
        assert struct.unpack("<i", encoded[1:])[0] == 1234

    def test_a_16_bit_value_is_two_octets(self):
        encoded = encode_analog(AnalogPoint(-1000), AnalogVariation.INT16_WITH_FLAG)

        assert len(encoded) == 3
        assert struct.unpack("<h", encoded[1:])[0] == -1000

    def test_a_flagless_variation_carries_only_the_value(self):
        assert len(encode_analog(AnalogPoint(7), AnalogVariation.INT32)) == 4

    def test_a_float_variation_keeps_the_fraction(self):
        encoded = encode_analog(AnalogPoint(60.05), AnalogVariation.FLOAT32_WITH_FLAG)

        assert struct.unpack("<f", encoded[1:])[0] == pytest.approx(60.05)

    def test_a_value_is_rounded_rather_than_truncated(self):
        encoded = encode_analog(AnalogPoint(9.6), AnalogVariation.INT32_WITH_FLAG)

        assert struct.unpack("<i", encoded[1:])[0] == 10


class TestSaturation:
    @pytest.mark.parametrize(
        ("variation", "value", "expected"),
        [
            (AnalogVariation.INT16_WITH_FLAG, 40000, 32767),
            (AnalogVariation.INT16_WITH_FLAG, -40000, -32768),
            (AnalogVariation.INT32_WITH_FLAG, 5e9, 2**31 - 1),
        ],
    )
    def test_a_value_that_does_not_fit_saturates_and_says_so(self, variation, value, expected):
        """Writing the wrapped value would report a large export as a large
        import, which is worse than a clipped reading a master can see is
        clipped."""
        encoded = encode_analog(AnalogPoint(value), variation)
        fmt = "<h" if variation is AnalogVariation.INT16_WITH_FLAG else "<i"

        assert encoded[0] & AnalogQuality.OVER_RANGE
        assert struct.unpack(fmt, encoded[1:])[0] == expected

    def test_a_value_that_fits_is_not_marked_over_range(self):
        encoded = encode_analog(AnalogPoint(32767), AnalogVariation.INT16_WITH_FLAG)

        assert not encoded[0] & AnalogQuality.OVER_RANGE

    def test_saturation_does_not_discard_the_other_flags(self):
        point = AnalogPoint(5e9, analog_flags(online=False, comm_lost=True))
        encoded = encode_analog(point, AnalogVariation.INT32_WITH_FLAG)

        assert encoded[0] & AnalogQuality.COMM_LOST
        assert encoded[0] & AnalogQuality.OVER_RANGE
        assert not encoded[0] & AnalogQuality.ONLINE

    def test_a_float_variation_does_not_saturate_within_its_range(self):
        """The range that overflows an integer is ordinary for a float, and
        marking it would be a lie about the encoding."""
        encoded = encode_analog(AnalogPoint(5e9), AnalogVariation.FLOAT32_WITH_FLAG)

        assert not encoded[0] & AnalogQuality.OVER_RANGE

    @pytest.mark.parametrize("value", [1e39, -1e39])
    def test_a_finite_value_past_the_float32_range_saturates(self, value):
        """It is finite, so the non-finite branch does not catch it, and packing
        it raises. One absurd reading must not fail the response carrying every
        other point."""
        encoded = encode_analog(AnalogPoint(value), AnalogVariation.FLOAT32_WITH_FLAG)

        assert encoded[0] & AnalogQuality.OVER_RANGE
        assert struct.unpack("<f", encoded[1:])[0] == pytest.approx(
            math.copysign(3.4028234663852886e38, value)
        )


class TestNonFiniteReadings:
    """A connector can hand up a NaN or an infinity, and one point must not be
    able to fail the response carrying every other point."""

    @pytest.mark.parametrize(
        "variation",
        [
            AnalogVariation.INT32_WITH_FLAG,
            AnalogVariation.INT16_WITH_FLAG,
            AnalogVariation.FLOAT32_WITH_FLAG,
        ],
    )
    def test_a_nan_encodes_as_zero_and_says_it_is_untrustworthy(self, variation):
        encoded = encode_analog(AnalogPoint(float("nan")), variation)

        assert encoded[0] & AnalogQuality.REFERENCE_ERR
        assert not encoded[0] & AnalogQuality.ONLINE

    def test_a_nan_value_is_zero_on_the_wire(self):
        encoded = encode_analog(AnalogPoint(float("nan")), AnalogVariation.INT32_WITH_FLAG)

        assert struct.unpack("<i", encoded[1:])[0] == 0

    @pytest.mark.parametrize(
        ("value", "expected"), [(float("inf"), 2**31 - 1), (float("-inf"), -(2**31))]
    )
    def test_an_infinity_saturates_like_any_other_oversized_value(self, value, expected):
        encoded = encode_analog(AnalogPoint(value), AnalogVariation.INT32_WITH_FLAG)

        assert encoded[0] & AnalogQuality.OVER_RANGE
        assert struct.unpack("<i", encoded[1:])[0] == expected

    def test_an_infinity_on_a_float_variation_stays_finite(self):
        """A master parsing an IEEE infinity is a needless surprise when
        OVER_RANGE already carries the meaning."""
        encoded = encode_analog(AnalogPoint(float("inf")), AnalogVariation.FLOAT32_WITH_FLAG)
        value = struct.unpack("<f", encoded[1:])[0]

        assert encoded[0] & AnalogQuality.OVER_RANGE
        assert value == pytest.approx(3.4028234663852886e38)

    def test_a_non_finite_point_does_not_fail_the_range_around_it(self):
        """The contract is that a response survives one bad reading."""
        block = analog_range(0, [AnalogPoint(5), AnalogPoint(float("nan")), AnalogPoint(7)])

        assert len(block) == 5 + 3 * 5


class TestQualityFlags:
    def test_a_comm_lost_point_is_not_online(self):
        """The store retains the last value and the flags say it is stale, which
        is the thing Modbus cannot express."""
        flags = analog_flags(online=False, comm_lost=True)

        assert flags & AnalogQuality.COMM_LOST
        assert not flags & AnalogQuality.ONLINE

    def test_a_point_never_acquired_reports_restart(self):
        flags = analog_flags(online=False, restart=True)

        assert flags & AnalogQuality.RESTART

    def test_the_binary_state_travels_in_the_flags_octet(self):
        assert binary_flags(state=True) & BinaryQuality.STATE
        assert not binary_flags(state=False) & BinaryQuality.STATE

    def test_encoding_a_binary_point_honours_its_state(self):
        assert encode_binary(BinaryPoint(state=True))[0] & BinaryQuality.STATE
        assert not encode_binary(BinaryPoint(state=False))[0] & BinaryQuality.STATE

    def test_a_binary_state_set_in_flags_is_cleared_when_the_point_is_false(self):
        """The state has one source, and it is the field rather than the octet
        the caller happened to pass."""
        point = BinaryPoint(state=False, flags=BinaryQuality.ONLINE | BinaryQuality.STATE)

        assert not encode_binary(point)[0] & BinaryQuality.STATE


class TestRanges:
    def test_an_analog_range_is_a_header_this_layer_can_read_back(self):
        block = analog_range(4, [AnalogPoint(1), AnalogPoint(2), AnalogPoint(3)])
        header = parse_request(bytes([0xC0, FunctionCode.READ]) + block[:5]).headers[0]

        assert (header.group, header.variation) == (GROUP_ANALOG_INPUT, 1)
        assert (header.start, header.stop) == (4, 6)

    def test_a_binary_range_names_the_variation_that_carries_flags(self):
        block = binary_range(0, [BinaryPoint(state=True)])
        header = parse_request(bytes([0xC0, FunctionCode.READ]) + block[:5]).headers[0]

        assert (header.group, header.variation) == (GROUP_BINARY_INPUT, BinaryVariation.WITH_FLAGS)
        assert (header.start, header.stop) == (0, 0)

    def test_a_range_past_255_uses_the_wide_qualifier(self):
        """Device blocks sit past index 255, so this is the ordinary case."""
        block = analog_range(1009, [AnalogPoint(1)])

        assert block[2] == QualifierCode.UINT16_START_STOP

    def test_the_objects_follow_the_header_in_index_order(self):
        block = analog_range(
            0, [AnalogPoint(10), AnalogPoint(20)], variation=AnalogVariation.INT16_WITH_FLAG
        )
        objects = block[5:]

        assert struct.unpack("<h", objects[1:3])[0] == 10
        assert struct.unpack("<h", objects[4:6])[0] == 20

    def test_an_empty_range_is_refused(self):
        """A header claiming a range it does not fill would desynchronize a
        master's parse of everything after it."""
        with pytest.raises(ValueError, match="at least one point"):
            analog_range(0, [])


class TestTimeEncoding:
    def test_a_timestamp_is_six_octets_little_endian(self):
        """Six rather than eight, which is why it cannot be struct-packed."""
        encoded = encode_time(0x0102030405)

        assert encoded == bytes.fromhex("0504030201 00".replace(" ", ""))
        assert len(encoded) == TIME_SIZE

    def test_a_real_timestamp_round_trips(self):
        stamp = 1_700_000_000_000
        assert int.from_bytes(encode_time(stamp), "little") == stamp

    def test_a_time_past_the_range_is_clamped_rather_than_truncated(self):
        """The low 48 bits of a nonsense clock reading are a plausible-looking
        time in the recent past, which is worse than an obviously pinned one."""
        encoded = encode_time(2**48 + 1234)

        assert int.from_bytes(encoded, "little") == 2**48 - 1

    def test_a_negative_time_is_clamped_to_zero(self):
        assert int.from_bytes(encode_time(-5), "little") == 0


class TestEventEncoding:
    def test_a_timed_analog_event_carries_flags_value_and_time(self):
        encoded = encode_analog_event(AnalogPoint(42), timestamp_ms=1_700_000_000_000)

        assert len(encoded) == 1 + 4 + TIME_SIZE
        assert struct.unpack("<i", encoded[1:5])[0] == 42
        assert int.from_bytes(encoded[5:], "little") == 1_700_000_000_000

    def test_an_untimed_analog_event_omits_the_timestamp(self):
        encoded = encode_analog_event(
            AnalogPoint(42), variation=AnalogEventVariation.INT32, timestamp_ms=None
        )

        assert len(encoded) == 1 + 4

    def test_a_timed_variation_without_a_timestamp_is_refused(self):
        """Silently sending the epoch would be a timestamp a master believes."""
        with pytest.raises(ValueError, match="carries a timestamp"):
            encode_analog_event(AnalogPoint(42), timestamp_ms=None)

    def test_an_event_saturates_exactly_as_the_static_point_does(self):
        """An event reporting a different number from the static point it
        describes is a contradiction a master cannot resolve."""
        event = encode_analog_event(
            AnalogPoint(5e9), variation=AnalogEventVariation.INT32, timestamp_ms=None
        )
        static = encode_analog(AnalogPoint(5e9), AnalogVariation.INT32_WITH_FLAG)

        assert event == static

    def test_a_timed_binary_event_carries_its_state_and_time(self):
        encoded = encode_binary_event(BinaryPoint(state=True), timestamp_ms=1_700_000_000_000)

        assert len(encoded) == 1 + TIME_SIZE
        assert encoded[0] & BinaryQuality.STATE

    def test_an_untimed_binary_event_is_one_octet(self):
        assert len(encode_binary_event(BinaryPoint(state=False), with_time=False)) == 1


class TestEventBlocks:
    def _event(self, value):
        return encode_analog_event(
            AnalogPoint(value), variation=AnalogEventVariation.INT32, timestamp_ms=None
        )

    def test_a_block_prefixes_every_event_with_its_index(self):
        block = event_block(
            GROUP_ANALOG_INPUT_EVENT,
            AnalogEventVariation.INT32,
            [(4, self._event(10)), (9, self._event(20))],
        )

        assert block[:4] == bytes(
            [
                GROUP_ANALOG_INPUT_EVENT,
                AnalogEventVariation.INT32,
                QualifierCode.UINT8_COUNT_UINT8_INDEX,
                2,
            ]
        )
        assert block[4] == 4
        assert block[4 + 1 + 5] == 9

    def test_a_block_may_report_one_index_twice(self):
        """Events are whichever points changed, in the order they changed, so a
        point that moved twice appears twice."""
        block = event_block(
            GROUP_ANALOG_INPUT_EVENT,
            AnalogEventVariation.INT32,
            [(4, self._event(10)), (4, self._event(11))],
        )

        assert block[3] == 2
        assert block[4] == 4 and block[4 + 1 + 5] == 4

    def test_a_wide_index_takes_the_wide_qualifier(self):
        block = event_block(
            GROUP_ANALOG_INPUT_EVENT, AnalogEventVariation.INT32, [(1009, self._event(10))]
        )

        assert block[2] == QualifierCode.UINT16_COUNT_UINT16_INDEX
        assert struct.unpack("<H", block[3:5])[0] == 1
        assert struct.unpack("<H", block[5:7])[0] == 1009

    def test_an_index_past_the_16_bit_space_is_refused(self):
        with pytest.raises(ValueError, match="16-bit index"):
            event_block(
                GROUP_ANALOG_INPUT_EVENT, AnalogEventVariation.INT32, [(0x10000, self._event(1))]
            )

    def test_a_negative_index_is_refused_as_a_negative_index(self):
        """It passes an upper-bound check and then raises from to_bytes, which
        names the encoding rather than the mistake."""
        with pytest.raises(ValueError, match="negative"):
            event_block(
                GROUP_ANALOG_INPUT_EVENT, AnalogEventVariation.INT32, [(-1, self._event(1))]
            )

    def test_too_many_events_is_refused_as_a_count(self):
        """The count and the index are different limits, and saying the index is
        wrong when the count is would send someone looking in the wrong place."""
        events = [(0, self._event(1))] * (0xFFFF + 1)

        with pytest.raises(ValueError, match="exceed the largest count"):
            event_block(GROUP_ANALOG_INPUT_EVENT, AnalogEventVariation.INT32, events)

    def test_an_empty_block_is_refused(self):
        with pytest.raises(ValueError, match="at least one event"):
            event_block(GROUP_ANALOG_INPUT_EVENT, AnalogEventVariation.INT32, [])
