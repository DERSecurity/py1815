"""The DNP3 data link layer: frames in, frames out, and nothing above them.

This module knows about start octets, the control byte, link addresses and where
the CRCs go. It does not know what a transport segment is, what an outstation
does, or where the values come from. Kept separate because these rules are
testable without a socket, and they are stable in a way the layers above them are
not.

The frame is IEC 60870-5 FT3 as DNP3 profiles it: a ten-octet header whose last
two octets are a CRC over the other eight, followed by user data in blocks of
sixteen octets, each block followed by its own CRC. That shape is why a frame
carrying 250 octets of user data occupies 292 on the wire.

**Nothing here trusts a length field before its CRC has been checked.** A corrupt
or hostile header would otherwise size a read, and the reader would wait for
octets that are never coming while holding what it already has.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from py1815 import crc

#: Every frame begins with these two octets.
START = b"\x05\x64"

HEADER_SIZE = 10
#: The header's CRC covers the eight octets before it.
_HEADER_BODY = 8

DATA_BLOCK_SIZE = 16

#: The LENGTH octet counts the control octet, both addresses and the user data,
#: which is why an empty frame reports five rather than zero.
_LENGTH_OVERHEAD = 5
MIN_LENGTH = _LENGTH_OVERHEAD
MAX_LENGTH = 255
MAX_USER_DATA = MAX_LENGTH - _LENGTH_OVERHEAD
#: 292: the header, 250 octets of user data, and a CRC for each of its sixteen
#: blocks. The largest thing this layer will ever read or write.
MAX_FRAME = 292

MASK_DIR = 0x80
MASK_PRM = 0x40
MASK_FCB = 0x20
#: FCV on a primary frame, DFC on a secondary one. One bit, two meanings,
#: disambiguated by PRM.
MASK_FCV = 0x10
MASK_FUNC = 0x0F

#: Addresses at or above this are reserved, and the broadcast values live here.
_RESERVED_ADDRESS = 0xFFF0
MAX_ADDRESS = _RESERVED_ADDRESS - 1


class Broadcast(IntEnum):
    """Destination addresses that mean "every outstation"."""

    NO_CONFIRM = 0xFFFD
    SHALL_CONFIRM = 0xFFFE
    OPTIONAL_CONFIRM = 0xFFFF


class PrimaryFunction(IntEnum):
    """Function codes a primary station sends."""

    RESET_LINK_STATES = 0
    TEST_LINK_STATES = 2
    CONFIRMED_USER_DATA = 3
    UNCONFIRMED_USER_DATA = 4
    REQUEST_LINK_STATUS = 9


class SecondaryFunction(IntEnum):
    """Function codes a secondary station answers with."""

    ACK = 0
    NACK = 1
    LINK_STATUS = 11
    NOT_SUPPORTED = 15


class LinkFrameError(Exception):
    """A frame that cannot be parsed, with the reason it could not be.

    The reason is carried rather than logged here: this module decides what is
    malformed, and the session decides how a malformed frame is reported.
    """


@dataclass(frozen=True)
class LinkFrame:
    """One parsed frame."""

    control: int
    destination: int
    source: int
    payload: bytes

    @property
    def from_master(self) -> bool:
        """The DIR bit: set on a frame a master sent."""
        return bool(self.control & MASK_DIR)

    @property
    def is_primary(self) -> bool:
        """The PRM bit: set on a request, clear on the answer to one."""
        return bool(self.control & MASK_PRM)

    @property
    def fcb(self) -> bool:
        return bool(self.control & MASK_FCB)

    @property
    def fcv(self) -> bool:
        """FCV on a primary frame. On a secondary frame this bit is DFC."""
        return bool(self.control & MASK_FCV)

    @property
    def dfc(self) -> bool:
        """DFC on a secondary frame. On a primary frame this bit is FCV."""
        return bool(self.control & MASK_FCV)

    @property
    def function(self) -> int:
        return self.control & MASK_FUNC

    @property
    def is_broadcast(self) -> bool:
        return self.destination in tuple(Broadcast)


def control_byte(
    *,
    from_master: bool,
    primary: bool,
    function: int,
    fcb: bool = False,
    fcv: bool = False,
) -> int:
    """Assemble a control octet from what each bit means."""
    control = function & MASK_FUNC
    if from_master:
        control |= MASK_DIR
    if primary:
        control |= MASK_PRM
    if fcb:
        control |= MASK_FCB
    if fcv:
        control |= MASK_FCV
    return control


def block_count(user_data_length: int) -> int:
    """How many CRC-carrying blocks ``user_data_length`` octets occupy."""
    return -(-user_data_length // DATA_BLOCK_SIZE)


def frame_size(user_data_length: int) -> int:
    """The octets a frame carrying this much user data occupies on the wire."""
    return HEADER_SIZE + user_data_length + block_count(user_data_length) * crc.SIZE


def build(control: int, destination: int, source: int, payload: bytes = b"") -> bytes:
    """One frame, ready to send."""
    if len(payload) > MAX_USER_DATA:
        raise LinkFrameError(
            f"user data is {len(payload)} octets, and a frame carries at most {MAX_USER_DATA}"
        )
    for name, address in (("destination", destination), ("source", source)):
        if not 0 <= address <= 0xFFFF:
            raise LinkFrameError(f"{name} address {address} does not fit two octets")
    header = struct.pack(
        "<2sBBHH", START, _LENGTH_OVERHEAD + len(payload), control, destination, source
    )
    frame = bytearray(crc.encode(header))
    for start in range(0, len(payload), DATA_BLOCK_SIZE):
        frame += crc.encode(payload[start : start + DATA_BLOCK_SIZE])
    return bytes(frame)


def parse(frame: bytes) -> LinkFrame:
    """Parse one complete frame, or say why it is not one."""
    if len(frame) < HEADER_SIZE:
        raise LinkFrameError(f"frame is {len(frame)} octets, shorter than a header")
    if not frame.startswith(START):
        raise LinkFrameError("frame does not begin with the start octets")
    if not crc.verify(frame[:HEADER_SIZE]):
        raise LinkFrameError("header CRC does not match")

    length = frame[2]
    if length < MIN_LENGTH:
        raise LinkFrameError(f"length octet is {length}, below the minimum of {MIN_LENGTH}")
    user_data_length = length - _LENGTH_OVERHEAD
    expected = frame_size(user_data_length)
    if len(frame) != expected:
        raise LinkFrameError(
            f"frame is {len(frame)} octets, and its length octet describes {expected}"
        )

    control = frame[3]
    destination, source = struct.unpack("<HH", frame[4:_HEADER_BODY])

    payload = bytearray()
    offset = HEADER_SIZE
    remaining = user_data_length
    while remaining:
        size = min(remaining, DATA_BLOCK_SIZE)
        block = frame[offset : offset + size + crc.SIZE]
        if not crc.verify(block):
            raise LinkFrameError(f"data block CRC at octet {offset} does not match")
        payload += block[:size]
        offset += size + crc.SIZE
        remaining -= size

    return LinkFrame(
        control=control, destination=destination, source=source, payload=bytes(payload)
    )


def is_valid_address(address: int) -> bool:
    """Whether an address may identify a station, rather than being reserved."""
    return 0 <= address <= MAX_ADDRESS


class FrameReader:
    """Turns a byte stream into frames, and resynchronizes when it has to.

    TCP delivers a stream, not frames: one read can carry half a frame, three
    frames, or a frame followed by noise. This holds what it has and yields what
    is complete.

    **Resynchronization discards two octets, not the frame the header claims.**
    A header whose CRC fails may not be a header at all -- the start octets can
    occur inside user data of a frame whose beginning was lost -- so its length
    field is not evidence of anything. Skipping past the start octets and
    searching again recovers at the next real frame; trusting the length would
    skip into the middle of one and stay out of step.
    """

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[LinkFrame]:
        """Add received octets and return every frame they completed."""
        self._buffer += data
        frames: list[LinkFrame] = []
        while True:
            frame = self._take()
            if frame is None:
                return frames
            frames.append(frame)

    def _take(self) -> LinkFrame | None:
        while True:
            start = self._buffer.find(START)
            if start == -1:
                # Keep a single trailing octet: it may be the first half of the
                # start sequence, with its partner in the next read.
                self._buffer = self._buffer[-1:] if self._buffer[-1:] == START[:1] else bytearray()
                return None
            del self._buffer[:start]

            if len(self._buffer) < HEADER_SIZE:
                return None
            if not crc.verify(bytes(self._buffer[:HEADER_SIZE])):
                del self._buffer[: len(START)]
                continue

            length = self._buffer[2]
            if length < MIN_LENGTH:
                del self._buffer[: len(START)]
                continue

            total = frame_size(length - _LENGTH_OVERHEAD)
            if len(self._buffer) < total:
                return None

            candidate = bytes(self._buffer[:total])
            try:
                frame = parse(candidate)
            except LinkFrameError:
                # The header verified, so the frame's extent is known and a bad
                # data block only costs this frame. Dropping the whole of it
                # keeps the reader aligned on the next one.
                del self._buffer[:total]
                continue
            del self._buffer[:total]
            return frame
