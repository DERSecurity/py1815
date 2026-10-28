"""Reading the objects a response carries.

The rest of this library writes objects; this reads them, which a master has
to do and an outstation never does. It is written from the object layouts in
the standard and not by turning the encoders in :mod:`py1815.objects` around.
An encoder and a decoder derived from one another agree with each other
whatever they get wrong, and the point of reading an outstation is to learn
what it sent.

It reads as far as it can and says where it stopped. An object's width is the
only way to find the object after it, so a group or variation that is not in
the table ends the walk. That is reported, with the octets that were not read,
and is not raised: a response that is half understood is still half of what
the outstation said.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum

from py1815.application import QualifierCode

#: The state of a binary point, in the octet that also carries its flags.
STATE_MASK = 0x80
#: The flag bits of a binary object, which are every bit but the state.
BINARY_FLAG_MASK = 0x7F

TIME_SIZE = 6

GROUP_TIME = 50
GROUP_COMMON_TIME = 51
GROUP_TIME_DELAY = 52

#: Group 51 variation 1 says the outstation's clock had been set when it
#: stamped the events that follow; variation 2 says it had not.
_COMMON_TIME_SYNCHRONIZED = {1: True, 2: False}


class PointType(Enum):
    """The kinds of point a master keeps values for."""

    BINARY_INPUT = "bi"
    BINARY_OUTPUT = "bo"
    COUNTER = "counter"
    FROZEN_COUNTER = "frozen"
    ANALOG_INPUT = "ai"
    ANALOG_OUTPUT = "ao"


class _Time(Enum):
    NONE = 0
    ABSOLUTE = 1
    #: Sixteen bits of milliseconds after the common time of occurrence.
    RELATIVE = 2


@dataclass(frozen=True)
class Layout:
    """How one object of a group and variation is laid out."""

    #: The point type the value belongs to, or None for an object that is not
    #: a point's value: a time, a command.
    point: PointType | None
    #: Whether the object reports a change and not the present value.
    event: bool = False
    #: Whether the object begins with a flag octet.
    flags: bool = True
    #: The ``struct`` format of the number after the flags, or None for a
    #: binary object, whose state is a bit of the flag octet.
    number: str | None = None
    time: _Time = _Time.NONE
    #: One bit per object and no flags: the packed binary variations.
    packed: bool = False
    #: For an object this module walks past and does not interpret.
    opaque: int = 0

    @property
    def size(self) -> int:
        """The octets one object occupies. Meaningless for a packed layout."""
        if self.opaque:
            return self.opaque
        size = 1 if self.flags else 0
        if self.number is not None:
            size += struct.calcsize(self.number)
        if self.time is _Time.ABSOLUTE:
            size += TIME_SIZE
        elif self.time is _Time.RELATIVE:
            size += 2
        return size


def _binary(point: PointType, *, event: bool = False, time: _Time = _Time.NONE) -> Layout:
    return Layout(point, event=event, time=time)


def _number(
    point: PointType,
    fmt: str,
    *,
    event: bool = False,
    flags: bool = True,
    time: _Time = _Time.NONE,
) -> Layout:
    return Layout(point, event=event, flags=flags, number=fmt, time=time)


_BI, _BO = PointType.BINARY_INPUT, PointType.BINARY_OUTPUT
_CTR, _FRZ = PointType.COUNTER, PointType.FROZEN_COUNTER
_AI, _AO = PointType.ANALOG_INPUT, PointType.ANALOG_OUTPUT
_ABS, _REL = _Time.ABSOLUTE, _Time.RELATIVE

#: Every object this module reads, by group and variation. The one table of
#: object layouts a master needs; a group or variation absent from it is one
#: the walk stops at.
LAYOUTS: dict[tuple[int, int], Layout] = {
    # Binary inputs: packed, and with flags.
    (1, 1): Layout(_BI, flags=False, packed=True),
    (1, 2): _binary(_BI),
    # Binary input events: without time, with absolute time, with relative time.
    (2, 1): _binary(_BI, event=True),
    (2, 2): _binary(_BI, event=True, time=_ABS),
    (2, 3): _binary(_BI, event=True, time=_REL),
    # Binary output status, and its events.
    (10, 1): Layout(_BO, flags=False, packed=True),
    (10, 2): _binary(_BO),
    (11, 1): _binary(_BO, event=True),
    (11, 2): _binary(_BO, event=True, time=_ABS),
    # A control relay output block, as an outstation echoes it. Walked past.
    (12, 1): Layout(None, opaque=11),
    # Counters: 32 and 16 bits, with a flag and without.
    (20, 1): _number(_CTR, "<I"),
    (20, 2): _number(_CTR, "<H"),
    (20, 5): _number(_CTR, "<I", flags=False),
    (20, 6): _number(_CTR, "<H", flags=False),
    # Frozen counters, which may also carry the time of the freeze.
    (21, 1): _number(_FRZ, "<I"),
    (21, 2): _number(_FRZ, "<H"),
    (21, 5): _number(_FRZ, "<I", time=_ABS),
    (21, 6): _number(_FRZ, "<H", time=_ABS),
    (21, 9): _number(_FRZ, "<I", flags=False),
    (21, 10): _number(_FRZ, "<H", flags=False),
    # Counter events and frozen counter events.
    (22, 1): _number(_CTR, "<I", event=True),
    (22, 2): _number(_CTR, "<H", event=True),
    (22, 5): _number(_CTR, "<I", event=True, time=_ABS),
    (22, 6): _number(_CTR, "<H", event=True, time=_ABS),
    (23, 1): _number(_FRZ, "<I", event=True),
    (23, 2): _number(_FRZ, "<H", event=True),
    (23, 5): _number(_FRZ, "<I", event=True, time=_ABS),
    (23, 6): _number(_FRZ, "<H", event=True, time=_ABS),
    # Analog inputs: integers with and without a flag, then the two floats.
    (30, 1): _number(_AI, "<i"),
    (30, 2): _number(_AI, "<h"),
    (30, 3): _number(_AI, "<i", flags=False),
    (30, 4): _number(_AI, "<h", flags=False),
    (30, 5): _number(_AI, "<f"),
    (30, 6): _number(_AI, "<d"),
    # Analog input events: each of those four numbers, without and with time.
    (32, 1): _number(_AI, "<i", event=True),
    (32, 2): _number(_AI, "<h", event=True),
    (32, 3): _number(_AI, "<i", event=True, time=_ABS),
    (32, 4): _number(_AI, "<h", event=True, time=_ABS),
    (32, 5): _number(_AI, "<f", event=True),
    (32, 6): _number(_AI, "<d", event=True),
    (32, 7): _number(_AI, "<f", event=True, time=_ABS),
    (32, 8): _number(_AI, "<d", event=True, time=_ABS),
    # Analog output status, and its events.
    (40, 1): _number(_AO, "<i"),
    (40, 2): _number(_AO, "<h"),
    (40, 3): _number(_AO, "<f"),
    (40, 4): _number(_AO, "<d"),
    # An analog output command, as an outstation echoes it: the number and a
    # status octet. Walked past.
    (41, 1): Layout(None, opaque=5),
    (41, 2): Layout(None, opaque=3),
    (41, 3): Layout(None, opaque=5),
    (41, 4): Layout(None, opaque=9),
    (42, 1): _number(_AO, "<i", event=True),
    (42, 2): _number(_AO, "<h", event=True),
    (42, 3): _number(_AO, "<i", event=True, time=_ABS),
    (42, 4): _number(_AO, "<h", event=True, time=_ABS),
    (42, 5): _number(_AO, "<f", event=True),
    (42, 6): _number(_AO, "<d", event=True),
    (42, 7): _number(_AO, "<f", event=True, time=_ABS),
    (42, 8): _number(_AO, "<d", event=True, time=_ABS),
    # The time and date, the common time of occurrence in its two forms, and
    # the time delay in seconds and in milliseconds.
    (50, 1): Layout(None, flags=False, time=_ABS),
    (51, 1): Layout(None, flags=False, time=_ABS),
    (51, 2): Layout(None, flags=False, time=_ABS),
    (52, 1): Layout(None, flags=False, number="<H"),
    (52, 2): Layout(None, flags=False, number="<H"),
}


@dataclass(frozen=True)
class DecodedObject:
    """One object out of a response."""

    group: int
    variation: int
    #: None for an object sent under a count with no index: a time.
    index: int | None
    #: A state, a count, an analog value, a number of milliseconds, or None
    #: for an object this module walks past.
    value: bool | int | float | None
    #: The flag octet, without the state bit of a binary object. None for a
    #: variation that carries no flags, which is not the same as none set.
    flags: int | None
    #: Milliseconds since the epoch, for an object that carries a time or
    #: counts from a common time of occurrence. None otherwise.
    time_ms: int | None
    #: Whether the outstation's clock had been set when it stamped a
    #: relative-time event. None where the object does not say.
    synchronized: bool | None
    point: PointType | None
    event: bool
    #: The object's own octets, without header, index or prefix.
    raw: bytes


@dataclass(frozen=True)
class Decoded:
    """What was read from a response body, and what was not."""

    objects: tuple[DecodedObject, ...]
    #: The octets from the first thing that could not be read to the end.
    unread: bytes = b""
    #: Why reading stopped there, or None if the whole body was read.
    problem: str | None = None

    @property
    def complete(self) -> bool:
        return self.problem is None


class _Stop(Exception):
    """Reading cannot continue from here. Carries the reason."""


@dataclass
class _CommonTime:
    """The common time of occurrence that relative-time events count from."""

    time_ms: int | None = None
    synchronized: bool | None = None


def _need(body: bytes, offset: int, count: int, what: str) -> None:
    if offset + count > len(body):
        raise _Stop(f"the response ends inside {what}")


def _one(
    group: int,
    variation: int,
    layout: Layout,
    index: int | None,
    data: bytes,
    common: _CommonTime,
) -> DecodedObject:
    if layout.opaque:
        return DecodedObject(group, variation, index, None, None, None, None, None, False, data)

    offset = 0
    flags: int | None = None
    value: bool | int | float | None = None
    if layout.flags:
        flags = data[0]
        offset = 1
    if layout.number is not None:
        (value,) = struct.unpack_from(layout.number, data, offset)
        offset += struct.calcsize(layout.number)
    elif layout.flags:
        # A binary object: the state shares the octet with the flags.
        value = bool(data[0] & STATE_MASK)
        flags = data[0] & BINARY_FLAG_MASK

    time_ms: int | None = None
    synchronized: bool | None = None
    if layout.time is _Time.ABSOLUTE:
        time_ms = int.from_bytes(data[offset : offset + TIME_SIZE], "little")
    elif layout.time is _Time.RELATIVE:
        relative = int.from_bytes(data[offset : offset + 2], "little")
        if common.time_ms is not None:
            time_ms = common.time_ms + relative
            synchronized = common.synchronized

    if layout.point is None and layout.time is _Time.ABSOLUTE:
        # A time object's value is the time.
        value = time_ms
        if group == GROUP_COMMON_TIME:
            synchronized = _COMMON_TIME_SYNCHRONIZED[variation]
    return DecodedObject(
        group,
        variation,
        index,
        value,
        flags,
        time_ms,
        synchronized,
        layout.point,
        layout.event,
        data,
    )


def _packed(
    group: int, variation: int, layout: Layout, start: int, count: int, data: bytes
) -> list[DecodedObject]:
    """Single-bit objects, eight to the octet, the lowest index in the lowest bit."""
    return [
        DecodedObject(
            group,
            variation,
            start + position,
            bool(data[position // 8] >> (position % 8) & 1),
            None,
            None,
            None,
            layout.point,
            layout.event,
            data[position // 8 : position // 8 + 1],
        )
        for position in range(count)
    ]


def _block(body: bytes, offset: int, common: _CommonTime) -> tuple[list[DecodedObject], int]:
    """Read one object header and the objects under it."""
    _need(body, offset, 3, "an object header")
    group, variation, raw_qualifier = body[offset : offset + 3]
    offset += 3
    layout = LAYOUTS.get((group, variation))
    if layout is None:
        raise _Stop(f"group {group} variation {variation} is not an object this library reads")
    try:
        qualifier = QualifierCode(raw_qualifier)
    except ValueError:
        raise _Stop(f"qualifier 0x{raw_qualifier:02X} is not one this library reads") from None

    objects: list[DecodedObject] = []
    if qualifier in (QualifierCode.UINT8_START_STOP, QualifierCode.UINT16_START_STOP):
        width = 2 if qualifier is QualifierCode.UINT16_START_STOP else 1
        _need(body, offset, 2 * width, "an object range")
        start = int.from_bytes(body[offset : offset + width], "little")
        stop = int.from_bytes(body[offset + width : offset + 2 * width], "little")
        offset += 2 * width
        if stop < start:
            raise _Stop(f"the range {start}..{stop} ends before it begins")
        count = stop - start + 1
        if layout.packed:
            octets = (count + 7) // 8
            _need(body, offset, octets, f"group {group} variation {variation}")
            objects = _packed(
                group, variation, layout, start, count, body[offset : offset + octets]
            )
            return objects, offset + octets
        _need(body, offset, count * layout.size, f"group {group} variation {variation}")
        for index in range(start, stop + 1):
            data = body[offset : offset + layout.size]
            objects.append(_one(group, variation, layout, index, data, common))
            offset += layout.size
        return objects, offset

    if qualifier in (
        QualifierCode.UINT8_COUNT_UINT8_INDEX,
        QualifierCode.UINT16_COUNT_UINT16_INDEX,
    ):
        if layout.packed:
            raise _Stop(f"group {group} variation {variation} cannot be sent with an index each")
        width = 2 if qualifier is QualifierCode.UINT16_COUNT_UINT16_INDEX else 1
        _need(body, offset, width, "an object count")
        count = int.from_bytes(body[offset : offset + width], "little")
        offset += width
        _need(body, offset, count * (width + layout.size), f"group {group} variation {variation}")
        for _ in range(count):
            index = int.from_bytes(body[offset : offset + width], "little")
            offset += width
            data = body[offset : offset + layout.size]
            objects.append(_one(group, variation, layout, index, data, common))
            offset += layout.size
        return objects, offset

    if qualifier in (QualifierCode.UINT8_COUNT, QualifierCode.UINT16_COUNT):
        # Objects with no index: a time, a time delay, a common time.
        if layout.packed or layout.point is not None:
            raise _Stop(
                f"group {group} variation {variation} arrived with no index to say which point"
            )
        width = 2 if qualifier is QualifierCode.UINT16_COUNT else 1
        _need(body, offset, width, "an object count")
        count = int.from_bytes(body[offset : offset + width], "little")
        offset += width
        _need(body, offset, count * layout.size, f"group {group} variation {variation}")
        for _ in range(count):
            data = body[offset : offset + layout.size]
            decoded = _one(group, variation, layout, None, data, common)
            objects.append(decoded)
            offset += layout.size
            if group == GROUP_COMMON_TIME:
                common.time_ms = decoded.time_ms
                common.synchronized = decoded.synchronized
        return objects, offset

    raise _Stop(f"qualifier 0x{raw_qualifier:02X} does not appear in a response")


def decode_objects(body: bytes) -> Decoded:
    """Every object in a response body that can be read, in the order sent.

    Reading stops at the first header or object that cannot be read, and the
    result says why and holds the octets from there on. Nothing read before
    that point is discarded: each object was complete, and the outstation
    sent it.

    A common time of occurrence applies to the relative-time events after it
    in the same body, as the standard has it, and to none before it.
    """
    objects: list[DecodedObject] = []
    common = _CommonTime()
    offset = 0
    while offset < len(body):
        try:
            block, end = _block(body, offset, common)
        except _Stop as stop:
            return Decoded(tuple(objects), bytes(body[offset:]), str(stop))
        objects.extend(block)
        offset = end
    return Decoded(tuple(objects))
