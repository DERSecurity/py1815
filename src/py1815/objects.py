"""Static data objects: binary and analog inputs, with their quality flags.

Encoding only, and only the variations a monitor outstation serves. Events live
with the event buffer, which is a different cadence and a different qualifier.

**Values arrive scaled.** The IEEE 1815.2 tables carry a resolution for each
point, and applying it belongs to the point map; this module writes the number it
is given. That separation is what keeps the wire format testable without a map
and a map reviewable without reading an encoder.

**Integers are the baseline variation.** Floating-point analog inputs are not
DNP3 Level 2 objects -- the profile permits them by agreement between master and
outstation -- and any device offering them must offer the integer variations as
well, so the integer path is the one that is always present.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from enum import IntEnum

from py1815.application import object_header

GROUP_BINARY_INPUT = 1
GROUP_ANALOG_INPUT = 30


class BinaryQuality(IntEnum):
    """Quality bits on a binary input. The state travels in the same octet."""

    ONLINE = 0x01
    RESTART = 0x02
    COMM_LOST = 0x04
    REMOTE_FORCED = 0x08
    LOCAL_FORCED = 0x10
    CHATTER_FILTER = 0x20
    STATE = 0x80


class AnalogQuality(IntEnum):
    """Quality bits on an analog input.

    ``OVER_RANGE`` is the one this outstation sets itself: it means the value
    did not fit the variation, which is a property of the encoding rather than
    of the device.
    """

    ONLINE = 0x01
    RESTART = 0x02
    COMM_LOST = 0x04
    REMOTE_FORCED = 0x08
    LOCAL_FORCED = 0x10
    OVER_RANGE = 0x20
    REFERENCE_ERR = 0x40


class AnalogVariation(IntEnum):
    """Analog input variations, by what they put on the wire."""

    INT32_WITH_FLAG = 1
    INT16_WITH_FLAG = 2
    INT32 = 3
    INT16 = 4
    FLOAT32_WITH_FLAG = 5


class BinaryVariation(IntEnum):
    PACKED = 1
    WITH_FLAGS = 2


#: The largest magnitude a single-precision float carries, which is where an
#: infinite reading saturates to on the float variations.
_FLOAT32_MAX = 3.4028234663852886e38

_INT32_MIN, _INT32_MAX = -(2**31), 2**31 - 1
_INT16_MIN, _INT16_MAX = -(2**15), 2**15 - 1

_LIMITS = {
    AnalogVariation.INT32_WITH_FLAG: (_INT32_MIN, _INT32_MAX),
    AnalogVariation.INT32: (_INT32_MIN, _INT32_MAX),
    AnalogVariation.INT16_WITH_FLAG: (_INT16_MIN, _INT16_MAX),
    AnalogVariation.INT16: (_INT16_MIN, _INT16_MAX),
}

_FORMATS = {
    AnalogVariation.INT32_WITH_FLAG: "<i",
    AnalogVariation.INT32: "<i",
    AnalogVariation.INT16_WITH_FLAG: "<h",
    AnalogVariation.INT16: "<h",
    AnalogVariation.FLOAT32_WITH_FLAG: "<f",
}

_WITH_FLAGS = frozenset(
    {
        AnalogVariation.INT32_WITH_FLAG,
        AnalogVariation.INT16_WITH_FLAG,
        AnalogVariation.FLOAT32_WITH_FLAG,
    }
)


@dataclass(frozen=True)
class AnalogPoint:
    """One analog input as it should appear on the wire."""

    value: float
    flags: int = AnalogQuality.ONLINE


@dataclass(frozen=True)
class BinaryPoint:
    """One binary input. The state is a field here and a flag bit on the wire."""

    state: bool
    flags: int = BinaryQuality.ONLINE


def analog_flags(
    *,
    online: bool = True,
    restart: bool = False,
    comm_lost: bool = False,
    over_range: bool = False,
    reference_err: bool = False,
) -> int:
    """Compose an analog quality octet from what each bit means."""
    flags = 0
    if online:
        flags |= AnalogQuality.ONLINE
    if restart:
        flags |= AnalogQuality.RESTART
    if comm_lost:
        flags |= AnalogQuality.COMM_LOST
    if over_range:
        flags |= AnalogQuality.OVER_RANGE
    if reference_err:
        flags |= AnalogQuality.REFERENCE_ERR
    return flags


def binary_flags(
    *,
    state: bool,
    online: bool = True,
    restart: bool = False,
    comm_lost: bool = False,
    chatter: bool = False,
) -> int:
    """Compose a binary quality octet, state bit included."""
    flags = 0
    if state:
        flags |= BinaryQuality.STATE
    if online:
        flags |= BinaryQuality.ONLINE
    if restart:
        flags |= BinaryQuality.RESTART
    if comm_lost:
        flags |= BinaryQuality.COMM_LOST
    if chatter:
        flags |= BinaryQuality.CHATTER_FILTER
    return flags


def encode_analog(point: AnalogPoint, variation: AnalogVariation) -> bytes:
    """One analog input object, saturating rather than overflowing.

    A value that does not fit the variation is clamped to the nearest
    representable number and marked ``OVER_RANGE``. Non-finite values are
    handled before that rather than being allowed to raise -- see below. Raising instead would fail
    a whole response because one point moved; writing the wrapped value would
    report a large export as a large import, which is worse than either. The
    flag is what tells a master the difference, and it is the reason the
    with-flag variations are the ones to prefer.
    """
    fmt = _FORMATS[variation]
    flags = point.flags
    value = point.value

    if math.isnan(value):
        # A connector can hand up a NaN -- an unread register, a division that
        # had no denominator. There is no wire representation of "no number", so
        # it goes out as zero with ONLINE cleared and REFERENCE_ERR set, which
        # is DNP3's way of saying the value should not be trusted. Letting
        # ``round`` raise would fail the whole response over one point, which is
        # the failure this function exists to avoid.
        value = 0.0
        flags = (flags & ~AnalogQuality.ONLINE) | AnalogQuality.REFERENCE_ERR
    elif math.isinf(value):
        # An infinite reading is a magnitude nothing can represent, which is
        # what OVER_RANGE already means. It saturates like any other value too
        # large for the variation.
        value = math.copysign(_FLOAT32_MAX, value)
        flags |= AnalogQuality.OVER_RANGE

    if variation in _LIMITS:
        low, high = _LIMITS[variation]
        raw = round(value)
        if raw < low or raw > high:
            raw = low if raw < low else high
            flags |= AnalogQuality.OVER_RANGE
        encoded = struct.pack(fmt, raw)
    else:
        # A double larger than float32 can hold is finite, so the checks above
        # let it through, and packing it raises. The integer path saturates for
        # exactly this case; the float path has to as well, or one absurd
        # reading fails the response carrying every other point.
        if abs(value) > _FLOAT32_MAX:
            value = math.copysign(_FLOAT32_MAX, value)
            flags |= AnalogQuality.OVER_RANGE
        encoded = struct.pack(fmt, value)

    if variation in _WITH_FLAGS:
        return bytes([flags & 0xFF]) + encoded
    return encoded


def encode_binary(point: BinaryPoint) -> bytes:
    """One binary input with flags, which is the only variation served.

    The packed variation exists and is not offered: it carries no quality at
    all, and a device that has gone unreachable would read as a device reporting
    false.
    """
    flags = point.flags | BinaryQuality.STATE if point.state else point.flags & ~BinaryQuality.STATE
    return bytes([flags & 0xFF])


def analog_range(
    start: int,
    points: list[AnalogPoint],
    *,
    variation: AnalogVariation = AnalogVariation.INT32_WITH_FLAG,
) -> bytes:
    """An object header and its objects, covering a contiguous index range."""
    if not points:
        raise ValueError("an object range carries at least one point")
    header = object_header(GROUP_ANALOG_INPUT, variation, start=start, stop=start + len(points) - 1)
    return header + b"".join(encode_analog(point, variation) for point in points)


def binary_range(start: int, points: list[BinaryPoint]) -> bytes:
    """An object header and its objects, covering a contiguous index range."""
    if not points:
        raise ValueError("an object range carries at least one point")
    header = object_header(
        GROUP_BINARY_INPUT, BinaryVariation.WITH_FLAGS, start=start, stop=start + len(points) - 1
    )
    return header + b"".join(encode_binary(point) for point in points)
