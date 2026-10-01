"""Data objects: binary inputs, analog inputs and counters, with their flags.

Encoding only. Static objects answer a class 0 read and travel in a contiguous
range; event objects answer a class 1, 2 or 3 read and travel with an index in
front of each one, because the indices they cover are whichever ones changed.

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
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum

from py1815.application import QualifierCode, object_header

GROUP_BINARY_INPUT = 1
GROUP_BINARY_INPUT_EVENT = 2
GROUP_COUNTER = 20
GROUP_FROZEN_COUNTER = 21
GROUP_COUNTER_EVENT = 22
GROUP_FROZEN_COUNTER_EVENT = 23
GROUP_ANALOG_INPUT = 30
GROUP_ANALOG_INPUT_EVENT = 32


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


class AnalogEventVariation(IntEnum):
    """Analog input event variations.

    The timed variations are the ones worth sending: an event without a
    timestamp tells a master that a value changed and not when, which for a
    sequence of events is most of what it wanted to know.
    """

    INT32 = 1
    INT16 = 2
    INT32_WITH_TIME = 3
    INT16_WITH_TIME = 4


class BinaryEventVariation(IntEnum):
    WITHOUT_TIME = 1
    WITH_TIME = 2
    #: Milliseconds after the common time of occurrence that precedes it.
    RELATIVE_TIME = 3


#: The common time of occurrence: the time a run of relative-time events
#: counts from. Its variation says whether the clock that gave the time
#: had been set.
GROUP_COMMON_TIME = 51
COMMON_TIME_SYNCHRONIZED = 1
COMMON_TIME_UNSYNCHRONIZED = 2
#: The furthest a relative time can be from its common time.
MAX_RELATIVE_MS = 0xFFFF


#: DNP3 absolute time: milliseconds since the Unix epoch, UTC, in six octets.
#: Six rather than eight is why this cannot be ``struct.pack``-ed directly, and
#: it runs out in the year 10889, which is somebody else's problem.
TIME_SIZE = 6
_TIME_MAX = 2**48 - 1


def encode_time(timestamp_ms: int) -> bytes:
    """A DNP3 absolute timestamp, little-endian, six octets.

    A time outside the representable range is clamped rather than truncated: the
    low 48 bits of a nonsense clock reading are a plausible-looking time in the
    recent past, which is worse than an obviously pinned one.
    """
    clamped = max(0, min(int(timestamp_ms), _TIME_MAX))
    return clamped.to_bytes(TIME_SIZE, "little")


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


def normalize_for_wire(value: float, flags: int) -> tuple[float, int]:
    """A finite value and the quality that says what was done to get one.

    NaN goes out as zero with ``ONLINE`` cleared and ``REFERENCE_ERR`` set,
    which is DNP3's way of saying the value should not be trusted: a connector
    can hand up an unread register or a division that had no denominator, and
    there is no wire representation of "no number". An infinity is a magnitude
    nothing can represent, which is what ``OVER_RANGE`` already means, so it
    saturates like any other value too large for its variation.

    Shared rather than repeated. Every analog quantity this library puts on the
    wire reaches it through here, so a reading that would otherwise raise out of
    ``round`` -- failing a whole response over one point -- cannot reach the
    packer from any of them.
    """
    if math.isnan(value):
        return 0.0, (flags & ~AnalogQuality.ONLINE) | AnalogQuality.REFERENCE_ERR
    if math.isinf(value):
        return math.copysign(_FLOAT32_MAX, value), flags | AnalogQuality.OVER_RANGE
    return value, flags


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
    value, flags = normalize_for_wire(point.value, point.flags)

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


def encode_analog_event(
    point: AnalogPoint,
    *,
    variation: AnalogEventVariation = AnalogEventVariation.INT32_WITH_TIME,
    timestamp_ms: int | None = None,
) -> bytes:
    """One analog input event object.

    Saturation and the non-finite rules are the static encoder's, reused rather
    than restated: an event carrying a different number from the static point it
    reports would be a contradiction a master has no way to resolve.

    The variation decides whether a timestamp belongs, and both directions are
    refused rather than only the strict one. Handing a timestamp to an untimed
    variation used to drop it, so the caller believed it had sent a time and the
    master received an event without one -- a disagreement neither end can see.
    """
    static = _EVENT_TO_STATIC[variation]
    encoded = encode_analog(point, static)
    if variation not in _TIMED_ANALOG_EVENTS:
        if timestamp_ms is not None:
            raise ValueError(f"{variation.name} carries no timestamp and one was given")
        return encoded
    if timestamp_ms is None:
        raise ValueError(f"{variation.name} carries a timestamp and none was given")
    return encoded + encode_time(timestamp_ms)


def encode_binary_event(
    point: BinaryPoint,
    *,
    with_time: bool = True,
    timestamp_ms: int | None = None,
) -> bytes:
    """One binary input event object.

    ``with_time`` and ``timestamp_ms`` must agree, in both directions -- see
    ``encode_analog_event`` for why the loose one is refused too.
    """
    encoded = encode_binary(point)
    if not with_time:
        if timestamp_ms is not None:
            raise ValueError("an untimed binary event carries no timestamp and one was given")
        return encoded
    if timestamp_ms is None:
        raise ValueError("a timed binary event carries a timestamp and none was given")
    return encoded + encode_time(timestamp_ms)


def encode_binary_event_relative(point: BinaryPoint, relative_ms: int) -> bytes:
    """One binary input event with its time as an offset from a common time."""
    if not 0 <= relative_ms <= MAX_RELATIVE_MS:
        raise ValueError(
            f"relative time is {relative_ms} ms, outside 0..{MAX_RELATIVE_MS}; "
            "an event further off needs a common time of its own"
        )
    return encode_binary(point) + struct.pack("<H", relative_ms)


def common_time(timestamp_ms: int, *, synchronized: bool) -> bytes:
    """A common time of occurrence object, header and all."""
    variation = COMMON_TIME_SYNCHRONIZED if synchronized else COMMON_TIME_UNSYNCHRONIZED
    return bytes([GROUP_COMMON_TIME, variation, 0x07, 1]) + encode_time(timestamp_ms)


def event_block(
    group: int,
    variation: int,
    items: Sequence[tuple[int, bytes]],
    *,
    qualifier: QualifierCode | None = None,
) -> bytes:
    """An object header and its events, each prefixed by its own index.

    Events are not a range. They are whichever points changed, in the order they
    changed, so the same index can appear twice and the indices between two
    events need not have moved at all. That is why this uses a count with an
    index in front of every object rather than a start and a stop.

    The narrower qualifier is used when every index and the count fit an octet,
    for the same reason the static encoder prefers a narrow range: it is two
    octets cheaper per header and most fleets fit it.

    ``qualifier`` overrides that choice, for a block that answers one a master
    sent. An echo is the request with its statuses filled in, and a master
    checking it against what it sent compares the qualifier too; narrowing a
    sixteen-bit request to eight because its indices happened to be small is
    an echo of a request nobody made.
    """
    if not items:
        raise ValueError("an event block carries at least one event")

    count = len(items)
    if count > 0xFFFF:
        raise ValueError(f"{count} events exceed the largest count a header can carry")

    widest = max(index for index, _ in items)
    if any(index < 0 for index, _ in items):
        raise ValueError("an event index is negative")
    if widest > 0xFFFF:
        raise ValueError(f"index {widest} does not fit a 16-bit index")

    narrow = count <= 0xFF and widest <= 0xFF
    if qualifier is QualifierCode.UINT8_COUNT_UINT8_INDEX and not narrow:
        raise ValueError("the block does not fit an eight-bit count and index")
    if qualifier not in (
        None,
        QualifierCode.UINT8_COUNT_UINT8_INDEX,
        QualifierCode.UINT16_COUNT_UINT16_INDEX,
    ):
        raise ValueError(f"qualifier 0x{int(qualifier):02X} prefixes no index")

    if narrow and qualifier is not QualifierCode.UINT16_COUNT_UINT16_INDEX:
        header = bytes([group, variation, QualifierCode.UINT8_COUNT_UINT8_INDEX, count])
        prefix = 1
    else:
        header = struct.pack(
            "<BBBH", group, variation, QualifierCode.UINT16_COUNT_UINT16_INDEX, count
        )
        prefix = 2

    body = bytearray()
    for index, encoded in items:
        body += index.to_bytes(prefix, "little") + encoded
    return header + bytes(body)


#: Which static variation each event variation encodes its value as.
_EVENT_TO_STATIC = {
    AnalogEventVariation.INT32: AnalogVariation.INT32_WITH_FLAG,
    AnalogEventVariation.INT32_WITH_TIME: AnalogVariation.INT32_WITH_FLAG,
    AnalogEventVariation.INT16: AnalogVariation.INT16_WITH_FLAG,
    AnalogEventVariation.INT16_WITH_TIME: AnalogVariation.INT16_WITH_FLAG,
}

_TIMED_ANALOG_EVENTS = frozenset(
    {AnalogEventVariation.INT32_WITH_TIME, AnalogEventVariation.INT16_WITH_TIME}
)


class CounterQuality(IntEnum):
    """Flag octet bits for a counter, static or frozen.

    The low bits mean what they mean on every other point. ``ROLLOVER`` is
    defined by the standard and deprecated by it in the same breath: a master
    is told to detect a wrap from the values, so it is named here and never set.
    """

    ONLINE = 0x01
    RESTART = 0x02
    COMM_LOST = 0x04
    REMOTE_FORCED = 0x08
    LOCAL_FORCED = 0x10
    ROLLOVER = 0x20
    DISCONTINUITY = 0x40


class FrozenCounterVariation(IntEnum):
    """The static frozen counter variations this outstation writes.

    Thirty-two bits only. A counter that accumulates energy passes sixteen bits
    in an afternoon, and offering the narrow variations would be offering a
    value that is wrong more often than it is right.
    """

    INT32_WITH_FLAG = 1
    INT32_WITH_FLAG_AND_TIME = 5
    INT32 = 9


#: Group 20 variation 1, the static counter: a flag octet and 32 bits.
COUNTER_VARIATION = 1
#: Group 23 variation 5, the frozen counter event: flag, 32 bits, time.
FROZEN_COUNTER_EVENT_VARIATION = 5

#: Where a 32-bit counter wraps. A counter is a running total, so a value past
#: this is reported modulo it rather than clamped: a pinned counter reads as
#: one that stopped counting, and a wrapped one is what the master expects.
COUNTER_MODULUS = 2**32


@dataclass(frozen=True)
class CounterPoint:
    """One counter as it should appear on the wire."""

    value: int
    flags: int = CounterQuality.ONLINE


def _counter_value(point: CounterPoint) -> bytes:
    if point.value < 0:
        raise ValueError(f"a counter cannot hold {point.value}; it only counts up")
    return struct.pack("<I", int(point.value) % COUNTER_MODULUS)


def encode_counter(point: CounterPoint) -> bytes:
    """Group 20 variation 1: one flag octet, then the 32-bit count."""
    return bytes([point.flags & 0xFF]) + _counter_value(point)


def counter_range(start: int, points: Sequence[CounterPoint]) -> bytes:
    """An object header and its counters, covering a contiguous index range."""
    if not points:
        raise ValueError("an object range carries at least one point")
    header = object_header(
        GROUP_COUNTER, COUNTER_VARIATION, start=start, stop=start + len(points) - 1
    )
    return header + b"".join(encode_counter(point) for point in points)


def encode_frozen_counter(
    point: CounterPoint,
    *,
    variation: FrozenCounterVariation = FrozenCounterVariation.INT32_WITH_FLAG_AND_TIME,
    timestamp_ms: int | None = None,
) -> bytes:
    """One static frozen counter, group 21.

    The timestamp is the moment of the freeze, not of the read. It is demanded
    by the timed variation and refused by the others, for the reason
    ``encode_analog_event`` gives: a caller that believes it sent a time and a
    master that received none disagree in a way neither can see.
    """
    variation = FrozenCounterVariation(variation)
    timed = variation is FrozenCounterVariation.INT32_WITH_FLAG_AND_TIME
    if timed and timestamp_ms is None:
        raise ValueError(f"{variation.name} carries a timestamp and none was given")
    if not timed and timestamp_ms is not None:
        raise ValueError(f"{variation.name} carries no timestamp and one was given")
    value = _counter_value(point)
    if variation is FrozenCounterVariation.INT32:
        return value
    encoded = bytes([point.flags & 0xFF]) + value
    return encoded + encode_time(timestamp_ms) if timed and timestamp_ms is not None else encoded


def frozen_counter_range(
    start: int,
    points: Sequence[tuple[CounterPoint, int | None]],
    *,
    variation: FrozenCounterVariation = FrozenCounterVariation.INT32_WITH_FLAG_AND_TIME,
) -> bytes:
    """An object header and its frozen counters, each with its freeze time."""
    if not points:
        raise ValueError("an object range carries at least one point")
    variation = FrozenCounterVariation(variation)
    timed = variation is FrozenCounterVariation.INT32_WITH_FLAG_AND_TIME
    header = object_header(
        GROUP_FROZEN_COUNTER, int(variation), start=start, stop=start + len(points) - 1
    )
    return header + b"".join(
        encode_frozen_counter(point, variation=variation, timestamp_ms=frozen_at if timed else None)
        for point, frozen_at in points
    )


def encode_frozen_counter_event(point: CounterPoint, *, timestamp_ms: int) -> bytes:
    """Group 23 variation 5: flag, 32-bit count and the time of the freeze."""
    return bytes([point.flags & 0xFF]) + _counter_value(point) + encode_time(timestamp_ms)


#: Octets one analog event occupies in each variation, without its index.
ANALOG_EVENT_SIZES = {
    AnalogEventVariation.INT32: 5,
    AnalogEventVariation.INT16: 3,
    AnalogEventVariation.INT32_WITH_TIME: 5 + TIME_SIZE,
    AnalogEventVariation.INT16_WITH_TIME: 3 + TIME_SIZE,
}
