"""A short reader of the objects in an IEEE 1815.2 outstation's responses.

It was the parser of a probe that polled an outstation once; the poll is now
the master's (:mod:`py1815.master.poll`). The parser stays because tests of
the outstation read its responses with it: it is a second reading of the same
octets, written apart from :mod:`py1815.decode`, with its own table of sizes.

It reads the objects the IEEE 1815.2 profile selects and stops, saying so, at
the first it does not know: an object's width is the only way to find the one
after it.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from py1815.application import QualifierCode

#: The octets one object of each group and variation occupies.
_SIZES = {
    (1, 2): 1,
    (2, 1): 1,
    (2, 2): 7,
    (2, 3): 3,
    (10, 2): 1,
    (20, 1): 5,
    (21, 1): 5,
    (21, 5): 11,
    (21, 9): 4,
    (23, 5): 11,
    (30, 1): 5,
    (30, 2): 3,
    (32, 1): 5,
    (32, 2): 3,
    (32, 3): 11,
    (32, 4): 9,
    (40, 1): 5,
    (40, 2): 3,
}

#: The common time of occurrence that precedes binary events with relative time.
_COMMON_TIME = 51
_TIME_SIZE = 6

_SIGNED_32 = {(30, 1), (32, 1), (32, 3), (40, 1)}
_SIGNED_16 = {(30, 2), (32, 2), (32, 4), (40, 2)}
_COUNTERS = {(20, 1), (21, 1), (21, 5), (23, 5)}


class ProbeError(RuntimeError):
    """A response that could not be read."""


@dataclass(frozen=True)
class Value:
    """One object as it was read."""

    group: int
    variation: int
    index: int
    value: float
    flags: int | None


def _value(group: int, variation: int, index: int, data: bytes) -> Value:
    key = (group, variation)
    if len(data) < _SIZES[key]:
        # Checked here, once, for every object: a slice past the end of the
        # body is short and not an error, so the decoders below would otherwise
        # fail inside ``struct`` with nothing to say about the response.
        raise ProbeError("a response ends inside an object")
    if key == (21, 9):
        return Value(group, variation, index, struct.unpack_from("<I", data)[0], None)
    flags = data[0]
    if key in _SIGNED_32:
        number: float = struct.unpack_from("<i", data, 1)[0]
    elif key in _SIGNED_16:
        number = struct.unpack_from("<h", data, 1)[0]
    elif key in _COUNTERS:
        number = struct.unpack_from("<I", data, 1)[0]
    else:
        # A binary object: the state is the top bit of the flag octet.
        number = float(bool(flags & 0x80))
    return Value(group, variation, index, number, flags)


def parse_objects(body: bytes) -> tuple[list[Value], list[Value]]:
    """The static and event objects of a response body, in the order sent."""
    static: list[Value] = []
    events: list[Value] = []
    offset = 0
    while offset < len(body):
        if offset + 3 > len(body):
            raise ProbeError("a response ends inside an object header")
        group, variation, qualifier = body[offset : offset + 3]
        offset += 3
        if group == _COMMON_TIME and qualifier == QualifierCode.UINT8_COUNT:
            # The time a run of relative-time events counts from. Read past:
            # this probe reports what changed and not when.
            count = body[offset] if offset < len(body) else 0
            offset += 1 + count * _TIME_SIZE
            if offset > len(body):
                raise ProbeError("a response ends inside a common time of occurrence")
            continue
        size = _SIZES.get((group, variation))
        if size is None:
            raise ProbeError(f"group {group} variation {variation} is not one this probe reads")
        if qualifier in (QualifierCode.UINT8_START_STOP, QualifierCode.UINT16_START_STOP):
            wide = qualifier == QualifierCode.UINT16_START_STOP
            if offset + (4 if wide else 2) > len(body):
                raise ProbeError("a response ends inside an object range")
            start, stop = struct.unpack_from("<HH" if wide else "<BB", body, offset)
            offset += 4 if wide else 2
            for index in range(start, stop + 1):
                static.append(_value(group, variation, index, body[offset : offset + size]))
                offset += size
        elif qualifier in (
            QualifierCode.UINT8_COUNT_UINT8_INDEX,
            QualifierCode.UINT16_COUNT_UINT16_INDEX,
        ):
            wide = qualifier == QualifierCode.UINT16_COUNT_UINT16_INDEX
            width = 2 if wide else 1
            if offset + width > len(body):
                raise ProbeError("a response ends inside an object count")
            count = int.from_bytes(body[offset : offset + width], "little")
            offset += width
            for _ in range(count):
                if offset + width > len(body):
                    raise ProbeError("a response ends inside an object index")
                index = int.from_bytes(body[offset : offset + width], "little")
                offset += width
                events.append(_value(group, variation, index, body[offset : offset + size]))
                offset += size
        else:
            raise ProbeError(f"qualifier 0x{qualifier:02X} is not one this probe reads")
        if offset > len(body):
            raise ProbeError("a response ends inside an object")
    return static, events
