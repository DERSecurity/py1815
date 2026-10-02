"""Control objects: what a master commands, and what it is told in reply.

Everything else in this library encodes. These objects also decode, and that is
the difference that shapes the module. An input is something this outstation
asserts; a control is something a master asserts at it, arriving as octets that
may be truncated, may carry a value no point can take, and may name an operation
that does not exist. Every decoder here is total on its input or raises
:class:`ControlError`, because the alternative is an exception escaping the
session while a master waits.

**A decoder here refuses only octets it cannot read.** A CROB naming an
operation this outstation does not implement, or setting the obsolete queue bit,
decodes cleanly and is answered per object -- ``NOT_SUPPORTED`` or
``FORMAT_ERROR`` against that index. Refusing at the decoder would collapse
those into a fragment-level failure and lose which point was at fault, which is
the distinction the design's D14 and D15 exist to draw.

**The raw control code is preserved, not rebuilt.** A control is echoed back to
the master with a status filled in, so an object reassembled from parsed fields
would differ from the one that arrived wherever this module failed to recognize
something. The octet is kept and written back unchanged; the named fields are
readings of it.

Kept out of ``objects`` deliberately. The layering table in the design document
describes that module as static binary and analog *inputs*, which is what it
is; outputs travel in the other direction and answer in a different vocabulary.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from enum import IntEnum

from py1815.objects import AnalogQuality, BinaryQuality, normalize_for_wire

#: Binary output status, read back rather than commanded.
GROUP_BINARY_OUTPUT_STATUS = 10
#: Binary output command: the control relay output block.
GROUP_BINARY_OUTPUT_COMMAND = 12
#: Analog output status, read back rather than commanded.
GROUP_ANALOG_OUTPUT_STATUS = 40
#: Analog output command: the setpoint.
GROUP_ANALOG_OUTPUT_COMMAND = 41


class ControlError(Exception):
    """Octets that cannot be read as the control object they claim to be.

    Length and width only. A control that decodes and is then unacceptable is
    not this exception's business -- it is a status against an index.
    """


class CommandStatus(IntEnum):
    """What the outstation says about one control.

    The whole enumeration rather than the part this outstation returns. A
    decoder meets whatever a master sends, and a status arriving as a bare
    integer tells a reader less than one arriving with a name -- so the values
    below are defined even where nothing here produces them.

    Two are easy to reach for and wrong:

    ``PROCESSING_LIMITED`` means the operation was *not* accepted, there being
    no capacity for more activity than is already in progress. It does not mean
    accepted-but-unconfirmed. ``SUCCESS`` covers that: the standard defines it
    as "accepted, initiated, or queued", so a provider that hands the work to a
    device thread and returns is answering correctly rather than optimistically.

    ``ALREADY_ACTIVE`` concerns the point, not the association: the operation is
    already running or the point is already in the state asked for. The status
    about a competing master is ``BLOCKED_OTHER_MASTER``, which cannot arise
    here while one association is the rule.
    """

    SUCCESS = 0
    TIMEOUT = 1
    NO_SELECT = 2
    FORMAT_ERROR = 3
    NOT_SUPPORTED = 4
    ALREADY_ACTIVE = 5
    HARDWARE_ERROR = 6
    LOCAL = 7
    #: Too many *operations* -- throttled for having been asked too often. Not
    #: an object count, despite the ``TOO_MANY_OBJS`` spelling that circulates.
    #: The name is the one opendnp3 publishes, which is the one that interoperates.
    TOO_MANY_OPS = 8
    NOT_AUTHORIZED = 9
    AUTOMATION_INHIBIT = 10
    PROCESSING_LIMITED = 11
    OUT_OF_RANGE = 12
    DOWNSTREAM_LOCAL = 13
    ALREADY_COMPLETE = 14
    BLOCKED = 15
    CANCELLED = 16
    BLOCKED_OTHER_MASTER = 17
    DOWNSTREAM_FAIL = 18
    #: Deprecated. An outstation echoes it back rather than treating it as an
    #: error, per IEEE 1815-2012 5.4.11.
    NON_PARTICIPATING = 126
    UNDEFINED = 127


class OperationType(IntEnum):
    """The low nibble of a CROB's control code."""

    NUL = 0
    PULSE_ON = 1
    PULSE_OFF = 2
    LATCH_ON = 3
    LATCH_OFF = 4


class TripCloseCode(IntEnum):
    """The high two bits of a CROB's control code."""

    NUL = 0
    CLOSE = 1
    TRIP = 2
    RESERVED = 3


_OP_TYPE_MASK = 0x0F
#: Bit 4. Obsolete in IEEE 1815-2012 and required to be zero. A master that sets
#: it is asking for behavior the standard withdrew, which is a ``FORMAT_ERROR``
#: against that point rather than a reason to refuse the fragment.
_QUEUE_BIT = 0x10
_CLEAR_BIT = 0x20
_TCC_SHIFT = 6

CROB_SIZE = 11

#: Value width per analog variation, command and status alike. The status object
#: prefixes a flag octet and the command suffixes a status octet, so the group
#: decides the layout and the variation decides only this.
_ANALOG_FORMAT = {1: "<i", 2: "<h", 3: "<f", 4: "<d"}
_ANALOG_WIDTH = {1: 4, 2: 2, 3: 4, 4: 8}
_ANALOG_LIMITS = {1: (-(2**31), 2**31 - 1), 2: (-(2**15), 2**15 - 1)}
#: Where an infinite reading saturates on the single-precision variation.
_FLOAT32_MAX = 3.4028234663852886e38


@dataclass(frozen=True)
class ControlRelayOutputBlock:
    """A CROB, group 12 variation 1.

    ``control_code`` is the octet as it arrived. The operation, trip-close code
    and clear flag are readings of it rather than fields beside it, so an echo
    reproduces what the master sent even where this module does not recognize
    what that was.

    ``status`` is meaningless in a request -- a master sends ``SUCCESS`` and the
    outstation overwrites it -- and is the answer in a response.
    """

    control_code: int = 0
    count: int = 1
    on_time_ms: int = 0
    off_time_ms: int = 0
    status: CommandStatus = CommandStatus.SUCCESS

    @classmethod
    def build(
        cls,
        operation: OperationType = OperationType.NUL,
        *,
        trip_close: TripCloseCode = TripCloseCode.NUL,
        clear: bool = False,
        count: int = 1,
        on_time_ms: int = 0,
        off_time_ms: int = 0,
        status: CommandStatus = CommandStatus.SUCCESS,
    ) -> ControlRelayOutputBlock:
        """Compose one from named parts, for a caller rather than the wire."""
        code = (int(operation) & _OP_TYPE_MASK) | ((int(trip_close) & 0x03) << _TCC_SHIFT)
        if clear:
            code |= _CLEAR_BIT
        return cls(
            control_code=code,
            count=count,
            on_time_ms=on_time_ms,
            off_time_ms=off_time_ms,
            status=status,
        )

    @property
    def operation(self) -> OperationType | int:
        """The operation, or the raw nibble where it names none."""
        raw = self.control_code & _OP_TYPE_MASK
        try:
            return OperationType(raw)
        except ValueError:
            return raw

    @property
    def trip_close(self) -> TripCloseCode:
        return TripCloseCode((self.control_code >> _TCC_SHIFT) & 0x03)

    @property
    def clear(self) -> bool:
        return bool(self.control_code & _CLEAR_BIT)

    @property
    def queued(self) -> bool:
        """The obsolete queue bit. Set means the request is malformed."""
        return bool(self.control_code & _QUEUE_BIT)

    def with_status(self, status: CommandStatus) -> ControlRelayOutputBlock:
        """This control as it should be echoed, carrying *status*."""
        return ControlRelayOutputBlock(
            control_code=self.control_code,
            count=self.count,
            on_time_ms=self.on_time_ms,
            off_time_ms=self.off_time_ms,
            status=status,
        )


@dataclass(frozen=True)
class AnalogOutput:
    """An analog output command, group 41, variations 1 through 4.

    The variation travels with the value because it decides the wire width and
    the range the value has to fit. Variations 1 and 3 exceed Subset Level 2 and
    are served by agreement -- a 50 kW setpoint does not fit the 16-bit point
    Level 2 offers.
    """

    value: float
    variation: int = 1
    status: CommandStatus = CommandStatus.SUCCESS
    #: The value octets exactly as they arrived, when this came from the wire.
    #:
    #: For the same reason ``ControlRelayOutputBlock`` keeps its control code.
    #: ``struct`` does not round-trip every bit pattern a float variation can
    #: carry: unpacking the signaling NaN ``0x7f800001`` and packing the result
    #: yields ``0x7fc00001``, because the platform quiets it. Re-packing
    #: ``value`` to build an echo would therefore return octets the master did
    #: not send, which is the thing D14 forbids.
    raw_value: bytes | None = None

    def with_status(self, status: CommandStatus) -> AnalogOutput:
        """This command as it should be echoed, carrying *status*."""
        return AnalogOutput(
            value=self.value,
            variation=self.variation,
            status=status,
            raw_value=self.raw_value,
        )


def encode_crob(control: ControlRelayOutputBlock) -> bytes:
    """One CROB, eleven octets, little-endian.

    Raises on a count or duration that does not fit. These come from a caller
    building a response rather than from the wire, and a silently wrapped pulse
    duration is a relay held closed for the wrong length of time.
    """
    if not 0 <= control.control_code <= 0xFF:
        raise ControlError(f"control code is {control.control_code}; one octet is available")
    if not 0 <= control.count <= 0xFF:
        raise ControlError(f"count is {control.count}; a CROB carries one octet")
    for name, value in (("on_time_ms", control.on_time_ms), ("off_time_ms", control.off_time_ms)):
        if not 0 <= value <= 0xFFFFFFFF:
            raise ControlError(f"{name} is {value}; a CROB carries four octets")

    return struct.pack(
        "<BBIIB",
        control.control_code,
        control.count,
        control.on_time_ms,
        control.off_time_ms,
        int(control.status) & 0xFF,
    )


def decode_crob(data: bytes) -> ControlRelayOutputBlock:
    """One CROB from the wire. Length is the only thing refused here."""
    if len(data) != CROB_SIZE:
        raise ControlError(f"a CROB is {CROB_SIZE} octets and {len(data)} were given")

    code, count, on_time, off_time, status = struct.unpack("<BBIIB", data)
    return ControlRelayOutputBlock(
        control_code=code,
        count=count,
        on_time_ms=on_time,
        off_time_ms=off_time,
        status=_as_status(status),
    )


def encode_analog_output(command: AnalogOutput) -> bytes:
    """One analog output command: the value, then a status octet.

    Octets that arrived from the wire are written back unchanged rather than
    re-packed from ``value``, so an echo is the object the master sent.
    """
    if command.raw_value is not None:
        width = _width_for(command.variation)
        if len(command.raw_value) != width:
            raise ControlError(
                f"raw value is {len(command.raw_value)} octets and variation "
                f"{command.variation} is {width}"
            )
        value = command.raw_value
    else:
        value = _pack_value(command.value, command.variation, GROUP_ANALOG_OUTPUT_COMMAND)
    return value + bytes([int(command.status) & 0xFF])


def decode_analog_output(data: bytes, variation: int) -> AnalogOutput:
    """One analog output command from the wire.

    A value out of range for the *point* is not this function's business. It
    decodes whatever the variation can hold, and ``OUT_OF_RANGE`` is the
    provider's answer about the point rather than the decoder's about the
    octets.
    """
    width = _width_for(variation)
    if len(data) != width + 1:
        raise ControlError(
            f"group {GROUP_ANALOG_OUTPUT_COMMAND} variation {variation} is "
            f"{width + 1} octets and {len(data)} were given"
        )
    (value,) = struct.unpack(_ANALOG_FORMAT[variation], data[:width])
    return AnalogOutput(
        value=value,
        variation=variation,
        status=_as_status(data[width]),
        raw_value=bytes(data[:width]),
    )


def encode_binary_output_status(*, state: bool, flags: int = BinaryQuality.ONLINE) -> bytes:
    """Group 10 variation 2: one flag octet, with the state inside it.

    Variation 1 is packed and carries no quality, and is not offered here for
    the same reason the packed binary input is not: a point that has gone
    unreachable would read as a point reporting false.

    **Whether these appear in a class 0 read is the caller's to decide.** Under
    D6 this library holds no point map, so it cannot know which output points
    exist, and a ``ReadProvider`` is what chooses and encodes what a class 0
    header comes back with. Convention is that output status points do
    participate -- a master that commanded a point expects to read it back
    without asking for the group by name -- so a provider serving controls
    should include them alongside its inputs. Nothing here does it on the
    caller's behalf, and nothing here prevents it.
    """
    octet = flags | BinaryQuality.STATE if state else flags & ~BinaryQuality.STATE
    return bytes([octet & 0xFF])


def encode_analog_output_status(
    value: float, variation: int = 1, *, flags: int = AnalogQuality.ONLINE
) -> bytes:
    """Group 40: one flag octet, then the value.

    The flags lead here and trail in the command, which is not a mistake in
    either direction: a status object is a measurement and carries its quality
    first, while a command carries its outcome last.

    Being a measurement, it saturates and normalizes exactly as an analog input
    does -- a read-back point is fed by the same devices and can go NaN the same
    way. A value that does not fit the variation is clamped and marked
    ``OVER_RANGE`` rather than raising, because failing a whole response over
    one point is the outcome that handling exists to avoid.
    """
    _checked_variation(variation)
    value, flags = normalize_for_wire(value, flags)

    if variation in _ANALOG_LIMITS:
        low, high = _ANALOG_LIMITS[variation]
        raw: float | int = round(value)
        if not low <= raw <= high:
            raw = low if raw < low else high
            flags |= AnalogQuality.OVER_RANGE
    elif variation == 3 and abs(value) > _FLOAT32_MAX:
        raw = math.copysign(_FLOAT32_MAX, value)
        flags |= AnalogQuality.OVER_RANGE
    else:
        raw = value

    return bytes([flags & 0xFF]) + struct.pack(_ANALOG_FORMAT[variation], raw)


def _pack_value(value: float, variation: int, group: int) -> bytes:
    fmt = _ANALOG_FORMAT[_checked_variation(variation)]
    if variation in _ANALOG_LIMITS:
        low, high = _ANALOG_LIMITS[variation]
        try:
            raw = round(value)
        except (ValueError, OverflowError) as exc:
            # round() raises on NaN and infinity. A command is a caller's
            # instruction rather than a reading, so there is nothing to
            # normalize it to -- but it leaves as ControlError like every other
            # refusal here, not as whatever round chose.
            raise ControlError(f"{value} is not a value group {group} can carry") from exc
        if not low <= raw <= high:
            raise ControlError(f"{value} does not fit group {group} variation {variation}")
        return struct.pack(fmt, raw)
    if not math.isfinite(value):
        # struct packs NaN and infinity onto the float variations without
        # complaint, so the refusal the integer path gets from round() has to be
        # made explicit here. A command is an instruction rather than a reading:
        # there is nothing to normalize it to, and a setpoint of "not a number"
        # is not one a device can be asked to hold.
        raise ControlError(f"{value} is not a value group {group} can carry")
    try:
        return struct.pack(fmt, float(value))
    except (struct.error, OverflowError) as exc:
        raise ControlError(f"{value} does not fit group {group} variation {variation}") from exc


def _checked_variation(variation: int) -> int:
    if variation not in _ANALOG_FORMAT:
        raise ControlError(f"no analog output variation {variation}")
    return variation


def _width_for(variation: int) -> int:
    return _ANALOG_WIDTH[_checked_variation(variation)]


def _as_status(raw: int) -> CommandStatus:
    try:
        return CommandStatus(raw)
    except ValueError:
        # Reserved values exist and a master may send one. UNDEFINED is what the
        # standard reserves for exactly this, and the field is overwritten in
        # the echo regardless.
        return CommandStatus.UNDEFINED


def object_size(group: int, variation: int) -> int | None:
    """How wide one control object is, or ``None`` where none is known.

    The resolver ``application.parse_object_blocks`` needs. That layer parses
    headers and qualifiers and deliberately knows nothing below them, so the
    widths live here beside the objects they describe.
    """
    if group == GROUP_BINARY_OUTPUT_COMMAND and variation == 1:
        return CROB_SIZE
    if group == GROUP_ANALOG_OUTPUT_COMMAND:
        width = _ANALOG_WIDTH.get(variation)
        return None if width is None else width + 1
    return None


def decode_control(
    group: int, variation: int, data: bytes
) -> ControlRelayOutputBlock | AnalogOutput:
    """One control object, chosen by the group and variation carrying it.

    Raises :class:`ControlError` for a group and variation that name no control,
    which the caller has already had the chance to refuse through
    :func:`object_size` -- reaching here with one means the two disagree.
    """
    if group == GROUP_BINARY_OUTPUT_COMMAND and variation == 1:
        return decode_crob(data)
    if group == GROUP_ANALOG_OUTPUT_COMMAND and variation in _ANALOG_WIDTH:
        return decode_analog_output(data, variation)
    raise ControlError(f"group {group} variation {variation} is not a control")


def encode_control(control: ControlRelayOutputBlock | AnalogOutput) -> bytes:
    """One control object, echoed back with whatever status it now carries."""
    if isinstance(control, ControlRelayOutputBlock):
        return encode_crob(control)
    return encode_analog_output(control)
