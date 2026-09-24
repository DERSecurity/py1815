"""Control objects on the wire, in both directions.

These are the first objects this library decodes, so the tests run both ways
against the same literal octets. A round trip would prove only that the encoder
and decoder agree with each other, which they will even when both are wrong
about the standard.
"""

from __future__ import annotations

import pytest

from py1815.control import (
    CROB_SIZE,
    AnalogOutput,
    CommandStatus,
    ControlError,
    ControlRelayOutputBlock,
    OperationType,
    TripCloseCode,
    decode_analog_output,
    decode_crob,
    encode_analog_output,
    encode_analog_output_status,
    encode_binary_output_status,
    encode_crob,
)
from py1815.objects import AnalogQuality

#: LATCH_ON, count 1, 100 ms on, 200 ms off, status SUCCESS.
LATCH_ON_OCTETS = bytes.fromhex("030164000000c800000000")


class TestCommandStatusValues:
    """The numbers are the interoperable part; the names are ours."""

    @pytest.mark.parametrize(
        ("status", "code"),
        [
            (CommandStatus.SUCCESS, 0),
            (CommandStatus.TIMEOUT, 1),
            (CommandStatus.NO_SELECT, 2),
            (CommandStatus.FORMAT_ERROR, 3),
            (CommandStatus.NOT_SUPPORTED, 4),
            (CommandStatus.ALREADY_ACTIVE, 5),
            (CommandStatus.TOO_MANY_OPS, 8),
            (CommandStatus.PROCESSING_LIMITED, 11),
            (CommandStatus.OUT_OF_RANGE, 12),
            (CommandStatus.BLOCKED_OTHER_MASTER, 17),
            (CommandStatus.DOWNSTREAM_FAIL, 18),
            (CommandStatus.NON_PARTICIPATING, 126),
            (CommandStatus.UNDEFINED, 127),
        ],
    )
    def test_code(self, status, code):
        assert int(status) == code


class TestCrobOnTheWire:
    def test_encodes_to_literal_octets(self):
        crob = ControlRelayOutputBlock.build(
            OperationType.LATCH_ON, count=1, on_time_ms=100, off_time_ms=200
        )

        assert encode_crob(crob) == LATCH_ON_OCTETS

    def test_decodes_from_the_same_octets(self):
        crob = decode_crob(LATCH_ON_OCTETS)

        assert crob.operation is OperationType.LATCH_ON
        assert crob.trip_close is TripCloseCode.NUL
        assert crob.clear is False
        assert crob.count == 1
        assert crob.on_time_ms == 100
        assert crob.off_time_ms == 200
        assert crob.status is CommandStatus.SUCCESS

    def test_a_crob_is_eleven_octets(self):
        assert len(LATCH_ON_OCTETS) == CROB_SIZE

    def test_the_control_code_packs_trip_close_and_clear_above_the_operation(self):
        """Operation in the low nibble, clear at 0x20, trip-close at bits 6-7."""
        crob = ControlRelayOutputBlock.build(
            OperationType.PULSE_ON, trip_close=TripCloseCode.TRIP, clear=True
        )

        assert crob.control_code == 0xA1
        assert encode_crob(crob)[0] == 0xA1

    @pytest.mark.parametrize("size", [0, 1, CROB_SIZE - 1, CROB_SIZE + 1])
    def test_a_wrong_length_is_refused(self, size):
        with pytest.raises(ControlError, match="11 octets"):
            decode_crob(bytes(size))


class TestTheDecoderRefusesOnlyWhatItCannotRead:
    """D14 and D15: an object that decodes is answered per index.

    Refusing an unimplemented operation or a malformed flag at the decoder would
    collapse it into a fragment-level failure and lose which point was at fault.
    """

    def test_an_unrecognized_operation_decodes(self):
        octets = bytes([0x07]) + LATCH_ON_OCTETS[1:]

        crob = decode_crob(octets)

        assert crob.operation == 7
        assert not isinstance(crob.operation, OperationType)

    def test_the_obsolete_queue_bit_decodes_and_is_visible(self):
        octets = bytes([0x03 | 0x10]) + LATCH_ON_OCTETS[1:]

        crob = decode_crob(octets)

        assert crob.queued is True
        assert crob.operation is OperationType.LATCH_ON

    def test_a_reserved_status_decodes_as_undefined(self):
        octets = LATCH_ON_OCTETS[:-1] + bytes([100])

        assert decode_crob(octets).status is CommandStatus.UNDEFINED


class TestEchoFidelity:
    """D14 echoes the object it received, with a status filled in.

    An object rebuilt from parsed fields would differ from the one that arrived
    wherever this module failed to recognize something, so the master would see
    a control it did not send.
    """

    @pytest.mark.parametrize("code", [0x00, 0x03, 0x07, 0x13, 0xA1, 0xFF])
    def test_the_control_code_survives_decode_and_re_encode(self, code):
        octets = bytes([code]) + LATCH_ON_OCTETS[1:]

        echoed = encode_crob(decode_crob(octets).with_status(CommandStatus.NOT_SUPPORTED))

        assert echoed[0] == code
        assert echoed[:-1] == octets[:-1]
        assert echoed[-1] == CommandStatus.NOT_SUPPORTED


class TestAnalogOutputCommand:
    @pytest.mark.parametrize(
        ("value", "variation", "expected"),
        [
            (50000, 1, "50c3000000"),
            (-1000, 2, "18fc00"),
            (1.5, 3, "0000c03f00"),
            (1.5, 4, "000000000000f83f00"),
        ],
    )
    def test_encodes_value_then_status(self, value, variation, expected):
        command = AnalogOutput(value=value, variation=variation)

        assert encode_analog_output(command).hex() == expected

    @pytest.mark.parametrize(
        ("octets", "variation", "value"),
        [
            ("50c3000000", 1, 50000),
            ("18fc00", 2, -1000),
            ("0000c03f00", 3, 1.5),
            ("000000000000f83f00", 4, 1.5),
        ],
    )
    def test_decodes_from_the_same_octets(self, octets, variation, value):
        command = decode_analog_output(bytes.fromhex(octets), variation)

        assert command.value == value
        assert command.variation == variation
        assert command.status is CommandStatus.SUCCESS

    def test_a_value_the_variation_cannot_hold_is_refused(self):
        """A 50 kW setpoint against a 16-bit point is the case the design
        document names as the reason Level 2 alone cannot serve the profile."""
        with pytest.raises(ControlError, match="variation 2"):
            encode_analog_output(AnalogOutput(value=50000, variation=2))

    def test_an_unknown_variation_is_refused(self):
        with pytest.raises(ControlError, match="variation 9"):
            encode_analog_output(AnalogOutput(value=1, variation=9))

    @pytest.mark.parametrize(("variation", "size"), [(1, 4), (2, 2), (3, 6), (4, 8)])
    def test_a_wrong_length_is_refused(self, variation, size):
        with pytest.raises(ControlError, match="octets"):
            decode_analog_output(bytes(size), variation)


class TestStatusObjects:
    def test_binary_output_status_carries_the_state_in_bit_seven(self):
        assert encode_binary_output_status(state=True) == bytes([0x81])
        assert encode_binary_output_status(state=False) == bytes([0x01])

    def test_analog_output_status_leads_with_flags(self):
        """The command trails its status octet and the status object leads with
        quality. A measurement carries quality first; an outcome comes last."""
        encoded = encode_analog_output_status(50000, 1, flags=AnalogQuality.ONLINE)

        assert encoded.hex() == "0150c30000"

    @pytest.mark.parametrize(
        ("value", "variation", "expected"),
        [
            (50000, 1, "0150c30000"),
            (-1000, 2, "0118fc"),
            (1.5, 3, "010000c03f"),
            (1.5, 4, "01000000000000f83f"),
        ],
    )
    def test_every_variation(self, value, variation, expected):
        assert encode_analog_output_status(value, variation).hex() == expected


class TestRawFidelityOnAnalogCommands:
    """``struct`` does not round-trip every bit pattern a float variation holds.

    Unpacking the signaling NaN ``0x7f800001`` and packing the result yields
    ``0x7fc00001``: the platform quiets it. Re-packing ``value`` to build an
    echo would therefore return octets the master did not send, which is the
    same failure the raw control code exists to prevent.
    """

    def test_a_signaling_nan_echoes_exactly_as_it_arrived(self):
        raw = bytes.fromhex("0100807f")

        command = decode_analog_output(raw + bytes([0]), variation=3)
        echoed = encode_analog_output(command.with_status(CommandStatus.NOT_SUPPORTED))

        assert echoed[:4] == raw
        assert echoed[4] == CommandStatus.NOT_SUPPORTED

    def test_a_command_built_by_a_caller_still_packs_its_value(self):
        assert encode_analog_output(AnalogOutput(value=50000, variation=1)).hex() == "50c3000000"

    def test_raw_octets_of_the_wrong_width_are_refused(self):
        with pytest.raises(ControlError, match="raw value is"):
            encode_analog_output(AnalogOutput(value=1.0, variation=1, raw_value=b"\x00\x00"))

    @pytest.mark.parametrize("value", [float("nan"), float("inf")])
    def test_a_non_finite_command_is_refused_as_a_control_error(self, value):
        """A command is an instruction, not a reading, so there is nothing to
        normalize it to -- but it leaves as ControlError like every other
        refusal here rather than as whatever ``round`` chose to raise."""
        with pytest.raises(ControlError):
            encode_analog_output(AnalogOutput(value=value, variation=1))


class TestStatusObjectsAreMeasurements:
    """A read-back point is fed by the same devices an input is, and can go NaN
    the same way. Group 40 therefore normalizes exactly as group 30 does, rather
    than emitting a non-finite value with ONLINE still set -- or letting
    ``round`` raise and fail a response carrying every other point."""

    def test_a_nan_reading_goes_out_as_zero_and_says_so(self):
        encoded = encode_analog_output_status(float("nan"), 1)

        assert not encoded[0] & AnalogQuality.ONLINE
        assert encoded[0] & AnalogQuality.REFERENCE_ERR
        assert encoded[1:] == bytes(4)

    def test_an_infinite_reading_saturates_and_says_so(self):
        encoded = encode_analog_output_status(float("inf"), 1)

        assert encoded[0] & AnalogQuality.OVER_RANGE
        assert encoded[1:].hex() == "ffffff7f"

    @pytest.mark.parametrize("variation", [1, 2, 3, 4])
    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_no_variation_raises_on_a_non_finite_reading(self, variation, value):
        assert encode_analog_output_status(value, variation)

    def test_a_value_too_large_for_the_variation_saturates(self):
        """The 50 kW setpoint against a 16-bit point again -- as a measurement
        it clamps and flags rather than refusing."""
        encoded = encode_analog_output_status(50000, 2)

        assert encoded[0] & AnalogQuality.OVER_RANGE
        assert encoded[1:].hex() == "ff7f"


class TestNonFiniteCommandsOnEveryVariation:
    """The integer variations refuse these through ``round``; the float ones
    reach ``struct.pack``, which accepts NaN and infinity without complaint. A
    command is an instruction rather than a reading, so there is nothing to
    normalize it to -- a setpoint of "not a number" is not one a device can be
    asked to hold."""

    @pytest.mark.parametrize("variation", [1, 2, 3, 4])
    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_refused(self, variation, value):
        with pytest.raises(ControlError):
            encode_analog_output(AnalogOutput(value=value, variation=variation))
