"""The requests a master reads with, as the object headers that ask for them.

Kept apart from anything that sends, so the same request is built whether it
goes over a socket or straight into a session, and so each can be pinned to
its octets in a test.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from py1815.application import all_objects_header, class_header, index_list_header
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


def class_scan(*classes: int) -> bytes:
    """The headers of a read of the named classes, in the order named."""
    if not classes:
        raise ValueError("a scan names at least one class")
    return b"".join(class_header(number) for number in classes)


def scan(kind: str) -> bytes:
    """The headers of a scan by name: integrity, events, or class0 to class3."""
    try:
        return class_scan(*SCANS[kind])
    except KeyError:
        raise ValueError(f"{kind!r} is not a scan; one of {', '.join(SCANS)}") from None


def read_points(points: Mapping[PointType, Sequence[int] | None]) -> bytes:
    """The headers of a read of named points, in the outstation's default variations.

    Each point type maps to the indices wanted, or to None for every point of
    that type. Types are asked in the order given and indices in the order
    given.
    """
    if not points:
        raise ValueError("a read names at least one point type")
    headers = bytearray()
    for point, indices in points.items():
        group = STATIC_GROUPS[point]
        if indices is None:
            headers += all_objects_header(group, DEFAULT_VARIATION)
        else:
            headers += index_list_header(group, DEFAULT_VARIATION, indices)
    return bytes(headers)
