"""A probe: one integrity poll of an outstation, to see that it answers.

Not a master. It asks the one question a master asks first -- every event
class, then class 0 -- confirms each fragment, and reports what came back. It
keeps no association, retries nothing and commands nothing, which is what
makes it safe to point at anything and enough to show an outstation is alive.

It reads the objects the IEEE 1815.2 profile selects and stops, saying so, at
the first it does not know: an object's width is the only way to find the one
after it.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from dataclasses import dataclass, field

from py1815 import link
from py1815.application import (
    CON_MASK,
    FIN_MASK,
    RESPONSE_HEADER_SIZE,
    SEQ_MASK,
    FunctionCode,
    QualifierCode,
)
from py1815.transport import Reassembler, segment

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

#: Class 1, 2 and 3, then class 0: an integrity poll, events first so that a
#: static value is not overwritten by an older event.
_INTEGRITY = b"".join(
    bytes([60, variation, QualifierCode.ALL_OBJECTS]) for variation in (2, 3, 4, 1)
)


class ProbeError(RuntimeError):
    """The outstation did not answer, or answered something unreadable."""


@dataclass(frozen=True)
class Value:
    """One object as it was read."""

    group: int
    variation: int
    index: int
    value: float
    flags: int | None


@dataclass
class Poll:
    """What an integrity poll returned."""

    static: list[Value] = field(default_factory=list)
    events: list[Value] = field(default_factory=list)
    fragments: int = 0
    #: The two indication octets of the last fragment.
    indications: tuple[int, int] = (0, 0)

    def group(self, group: int) -> list[Value]:
        """Every static object of one group, in the order received."""
        return [value for value in self.static if value.group == group]

    def find(self, group: int, index: int) -> Value | None:
        """One static object by group and index, or None if it was not sent."""
        return next((v for v in self.static if v.group == group and v.index == index), None)


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


def _frames(fragment: bytes, *, outstation: int, master: int) -> bytes:
    control = link.control_byte(
        from_master=True, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
    )
    return b"".join(link.build(control, outstation, master, part) for part in segment(fragment))


async def integrity_poll(
    host: str,
    port: int,
    *,
    outstation: int = 1024,
    master: int = 1,
    timeout: float = 5.0,
) -> Poll:
    """Connect, read every class once, confirm what asks for it, and disconnect."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (TimeoutError, OSError) as exc:
        raise ProbeError(f"cannot connect to {host}:{port}: {exc}") from exc

    poll = Poll()
    frames = link.FrameReader()
    reassembler = Reassembler()

    async def fragment() -> bytes:
        while True:
            data = await asyncio.wait_for(reader.read(4096), timeout)
            if not data:
                raise ProbeError("the outstation closed the connection")
            for frame in frames.feed(data):
                whole = reassembler.add(frame.payload)
                if whole is not None:
                    return whole

    try:
        request = bytes([0xC0, FunctionCode.READ]) + _INTEGRITY
        writer.write(_frames(request, outstation=outstation, master=master))
        await writer.drain()
        while True:
            try:
                response = await fragment()
            except TimeoutError as exc:
                raise ProbeError(
                    f"no answer from {host}:{port} as outstation {outstation} to master {master}"
                ) from exc
            if len(response) < RESPONSE_HEADER_SIZE:
                raise ProbeError("a response is shorter than its own header")
            poll.fragments += 1
            poll.indications = (response[2], response[3])
            static, events = parse_objects(response[RESPONSE_HEADER_SIZE:])
            poll.static += static
            poll.events += events
            if response[0] & CON_MASK:
                confirm = bytes([0xC0 | (response[0] & SEQ_MASK), FunctionCode.CONFIRM])
                writer.write(_frames(confirm, outstation=outstation, master=master))
                await writer.drain()
            if response[0] & FIN_MASK:
                return poll
    finally:
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
