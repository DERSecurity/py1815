"""The requests a master reads with, as the object headers that ask for them.

Kept apart from anything that sends, so the same request is built whether it
goes over a socket or straight into a session, and so each can be pinned to
its octets in a test.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from py1815.application import (
    FunctionCode,
    QualifierCode,
    all_objects_header,
    class_header,
    object_header,
)
from py1815.decode import PointType

#: The group that holds each point type's present value.
STATIC_GROUPS: dict[PointType, int] = {
    PointType.BINARY_INPUT: 1,
    PointType.BINARY_OUTPUT: 10,
    PointType.COUNTER: 20,
    PointType.FROZEN_COUNTER: 21,
    PointType.ANALOG_INPUT: 30,
    PointType.ANALOG_OUTPUT: 40,
}

#: Variation 0 in a request: whichever variation the outstation sends by default.
DEFAULT_VARIATION = 0

#: The scans a master makes, by name, as the classes each one asks for.
SCANS: dict[str, tuple[int, ...]] = {
    # Events first, so that a present value is not overwritten by an older change.
    "integrity": (1, 2, 3, 0),
    "events": (1, 2, 3),
    "class0": (0,),
    "class1": (1,),
    "class2": (2,),
    "class3": (3,),
}


#: The scan that reads what the outputs stand at. Named apart from the scans by
#: class because it is not one: the IEEE 1815.2 profile leaves output status out
#: of class 0, so an integrity poll never returns it and it is read by its groups.
OUTPUTS = "outputs"

#: Every scan a master can be asked for by name.
SCAN_KINDS: tuple[str, ...] = (*SCANS, OUTPUTS)


#: Requests that change nothing at the outstation but what it reports and
#: when. Every other function code commands it in some way: an output, a
#: counter, its clock, its restart indication, or the device itself.
READING_FUNCTIONS = frozenset(
    {
        FunctionCode.READ,
        FunctionCode.ENABLE_UNSOLICITED,
        FunctionCode.DISABLE_UNSOLICITED,
        FunctionCode.DELAY_MEASURE,
    }
)

#: The internal indication a master clears once it has seen a restart.
DEVICE_RESTART_INDEX = 7


def write_time(milliseconds: int) -> bytes:
    """The object of a time write: milliseconds since the epoch, UTC, in 48 bits."""
    if not 0 <= milliseconds < 1 << 48:
        raise ValueError("a time is milliseconds since the epoch, in 48 bits")
    return bytes([50, 1, QualifierCode.UINT8_COUNT, 1]) + milliseconds.to_bytes(6, "little")


def clear_restart() -> bytes:
    """The object that clears the restart indication: bit 7 of the indications, written as 0."""
    return bytes(
        [80, 1, QualifierCode.UINT8_START_STOP, DEVICE_RESTART_INDEX, DEVICE_RESTART_INDEX, 0]
    )


def freeze_counters() -> bytes:
    """The header of a freeze: every counter."""
    return all_objects_header(STATIC_GROUPS[PointType.COUNTER], DEFAULT_VARIATION)


def class_scan(*classes: int) -> bytes:
    """The headers of a read of the named classes, in the order named."""
    if not classes:
        raise ValueError("a scan names at least one class")
    return b"".join(class_header(number) for number in classes)


def scan(kind: str) -> bytes:
    """The headers of a scan by name: integrity, events, class0 to class3, or outputs."""
    if kind == OUTPUTS:
        return read_points({PointType.BINARY_OUTPUT: None, PointType.ANALOG_OUTPUT: None})
    try:
        return class_scan(*SCANS[kind])
    except KeyError:
        raise ValueError(f"{kind!r} is not a scan; one of {', '.join(SCAN_KINDS)}") from None


def read_points(points: Mapping[PointType, Sequence[int] | None]) -> bytes:
    """Build the headers of a read of named points, in the default variations.

    Each point type maps to the indices wanted, or to None for every point of
    that type. Types are asked in the order given.

    Indices are sent as start-stop ranges (qualifiers 0x00 and 0x01), one
    header for each run of consecutive indices, in ascending order. A DNP3
    Subset Level 2 outstation is only required to accept ranges in a read. The
    index-list qualifiers (0x17 and 0x28) are optional at that level, and
    opendnp3 rejects them.
    """
    if not points:
        raise ValueError("a read names at least one point type")
    headers = bytearray()
    for point, indices in points.items():
        group = STATIC_GROUPS[point]
        if indices is None:
            headers += all_objects_header(group, DEFAULT_VARIATION)
            continue
        for start, stop in _runs(indices):
            headers += object_header(group, DEFAULT_VARIATION, start=start, stop=stop)
    return bytes(headers)


def _runs(indices: Sequence[int]) -> list[tuple[int, int]]:
    """Group indices into (start, stop) runs of consecutive values, ascending."""
    if not indices:
        raise ValueError("a read of a point type names at least one index")
    if min(indices) < 0 or max(indices) > 0xFFFF:
        raise ValueError("an index is 0 to 65535")
    runs: list[tuple[int, int]] = []
    for index in sorted(set(indices)):
        if runs and index == runs[-1][1] + 1:
            runs[-1] = (runs[-1][0], index)
        else:
            runs.append((index, index))
    return runs
