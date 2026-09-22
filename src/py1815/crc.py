"""CRC-16/DNP, the checksum every DNP3 frame carries several of.

One function over bytes, with no notion of frames or blocks. The link layer
decides what gets covered; this decides what the answer is.

The parameters are CRC-16/DNP: polynomial ``0x3D65``, initial value zero,
reflected input and output, final XOR ``0xFFFF``. Reflection is why the table is
built from ``0xA6BC`` -- ``0x3D65`` with its bits reversed -- rather than from the
polynomial as written. The catalogue check value for this parameter set is
``0xEA82`` over the ASCII digits ``123456789``, and the test suite pins it: a CRC
that is wrong in a way the implementation agrees with is invisible until a real
master rejects every frame.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import struct

#: ``0x3D65`` bit-reversed, for the reflected table-driven form.
_POLYNOMIAL = 0xA6BC

_XOR_OUT = 0xFFFF

SIZE = 2


def _build_table() -> tuple[int, ...]:
    table = []
    for value in range(256):
        remainder = value
        for _ in range(8):
            if remainder & 1:
                remainder = (remainder >> 1) ^ _POLYNOMIAL
            else:
                remainder >>= 1
        table.append(remainder)
    return tuple(table)


_TABLE = _build_table()


def compute(data: bytes) -> int:
    """The CRC over ``data``."""
    remainder = 0x0000
    for byte in data:
        remainder = (remainder >> 8) ^ _TABLE[(remainder ^ byte) & 0xFF]
    return remainder ^ _XOR_OUT


def encode(data: bytes) -> bytes:
    """``data`` followed by its CRC, in the order it goes on the wire.

    Little-endian, which is the one thing about this that cannot be derived from
    the polynomial: DNP3 transmits the low octet first.
    """
    return data + struct.pack("<H", compute(data))


def verify(block: bytes) -> bool:
    """Whether ``block`` ends in a CRC that matches the rest of it."""
    if len(block) <= SIZE:
        return False
    body, checksum = block[:-SIZE], block[-SIZE:]
    carried: int = struct.unpack("<H", checksum)[0]
    return carried == compute(body)
