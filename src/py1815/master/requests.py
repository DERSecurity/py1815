"""The requests a master reads with, as the object headers that ask for them.

Kept apart from anything that sends, so the same request is built whether it
goes over a socket or straight into a session, and so each can be pinned to
its octets in a test.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import math
import struct
from collections.abc import Callable, Mapping, Sequence

from py1815.application import (
    FunctionCode,
    QualifierCode,
    all_objects_header,
    class_header,
    index_list_header,
    object_header,
)
from py1815.attributes import (
    GROUP_DEVICE_ATTRIBUTES,
    STANDARD_SET,
    Attribute,
    DataType,
    Variation,
    attribute_block,
)
from py1815.decode import DecodedObject, PointType
from py1815.subset import SubsetLevel

#: The group that holds each point type's present value.
STATIC_GROUPS: dict[PointType, int] = {
    PointType.BINARY_INPUT: 1,
    PointType.DOUBLE_BIT_INPUT: 3,
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


#: The group of the time objects, and the variations a master writes.
TIME_GROUP = 50
ABSOLUTE_TIME = 1
LAST_RECORDED_TIME = 3


def _time_object(variation: int, milliseconds: int) -> bytes:
    if not 0 <= milliseconds < 1 << 48:
        raise ValueError("a time is milliseconds since the epoch, in 48 bits")
    return bytes([TIME_GROUP, variation, QualifierCode.UINT8_COUNT, 1]) + milliseconds.to_bytes(
        6, "little"
    )


def write_time(milliseconds: int) -> bytes:
    """The object of a time write: milliseconds since the epoch, UTC, in 48 bits."""
    return _time_object(ABSOLUTE_TIME, milliseconds)


def write_recorded_time(milliseconds: int) -> bytes:
    """The object of the write that ends the LAN procedure (IEEE 1815-2012 10.3.3.2).

    Group 50 variation 3: the time, in milliseconds since the epoch, at which
    the master sent the request to record the current time.
    """
    return _time_object(LAST_RECORDED_TIME, milliseconds)


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


def read_points(points: Mapping[PointType, Sequence[int] | None], *, ranges: bool = True) -> bytes:
    """Build the headers of a read of named points, in the default variations.

    Each point type maps to the indices wanted, or to None for every point of
    that type. Types are asked in the order given.

    With ``ranges`` the indices are sent as start-stop ranges (qualifiers 0x00
    and 0x01), one header for each run of consecutive indices, in ascending
    order. Without it every type named is asked for whole (qualifier 0x06),
    which is the only static read a Subset Level 2 outstation is required to
    parse (D82). The index-list qualifiers (0x17 and 0x28) are never used for
    a read of named points: no subset level requires them, and opendnp3
    rejects them.
    """
    if not points:
        raise ValueError("a read names at least one point type")
    headers = bytearray()
    for point, indices in points.items():
        group = STATIC_GROUPS[point]
        if indices is None or not ranges:
            if indices is not None:
                # The indices are not sent, but a bad one is still refused.
                _runs(indices)
            headers += all_objects_header(group, DEFAULT_VARIATION)
            continue
        for start, stop in _runs(indices):
            headers += object_header(group, DEFAULT_VARIATION, start=start, stop=stop)
    return bytes(headers)


def reads_ranges(level: SubsetLevel) -> bool:
    """Return whether a read of named points to an outstation of ``level`` sends ranges.

    A static read by start and stop is a Level 3 request: IEEE 1815-2012
    Table 14-3 and TB2016-003b Tables 12-3, 12-11, 12-19, 12-21, 12-27 and
    12-37 give a Level 2 outstation qualifier 0x06 only, and Table 14-4 adds
    the ranges at Level 3 (D82).
    """
    return level >= SubsetLevel.LEVEL_3


def named(points: Mapping[PointType, Sequence[int] | None]) -> Callable[[DecodedObject], bool]:
    """Return a test that keeps the static objects of the points named, and no others.

    A point type mapped to None keeps every object of that type.
    """
    wanted = {
        point: None if indices is None else frozenset(indices) for point, indices in points.items()
    }

    def keep(decoded: DecodedObject) -> bool:
        if decoded.event or decoded.point not in wanted:
            return False
        indices = wanted[decoded.point]
        return indices is None or decoded.index in indices

    return keep


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


# ------------------------------------------------- Level 3 and Level 4 requests

#: The subset level a master assumes for an outstation it is not told about.
#: Level 2 is the lowest this library implements, so a request that only a
#: higher level promises to parse is refused until the level is set. IEEE
#: 1815-2012 14.7.2 requires a master to be configurable to avoid those.
DEFAULT_LEVEL = SubsetLevel.LEVEL_2

_L2, _L3 = SubsetLevel.LEVEL_2, SubsetLevel.LEVEL_3

#: The reads TB2016-003b lists below Level 4, by group and variation: the
#: lowest level required to accept a read of every object (qualifier 0x06),
#: and of a range (0x00 and 0x01), or None where no level below 4 lists that
#: form. A row the tables give from Level 1 is listed from Level 2, the lowest
#: level this library implements. Tables 12-3, 12-5, 12-11, 12-19, 12-21,
#: 12-23, 12-25, 12-27, 12-31, 12-37, 12-49 and 12-52.
_READ_LEVELS: dict[tuple[int, int], tuple[SubsetLevel | None, SubsetLevel | None]] = {
    (1, 0): (_L2, _L3),
    (1, 1): (_L3, _L3),
    (1, 2): (_L3, _L3),
    (2, 0): (_L2, None),
    (2, 1): (_L2, None),
    (2, 2): (_L2, None),
    (2, 3): (_L2, None),
    (10, 0): (_L2, _L3),
    (10, 2): (_L3, _L3),
    (20, 0): (_L2, _L3),
    (20, 1): (_L3, _L3),
    (20, 2): (_L3, _L3),
    (20, 5): (_L3, _L3),
    (20, 6): (_L3, _L3),
    (21, 0): (_L2, _L3),
    (21, 1): (_L3, _L3),
    (21, 2): (_L3, _L3),
    (21, 9): (_L3, _L3),
    (21, 10): (_L3, _L3),
    (22, 0): (_L2, None),
    (22, 1): (_L3, None),
    (22, 2): (_L3, None),
    (23, 0): (_L3, None),
    (23, 1): (_L3, None),
    (23, 2): (_L3, None),
    (30, 0): (_L2, _L3),
    (30, 1): (_L3, _L3),
    (30, 2): (_L3, _L3),
    (30, 3): (_L3, _L3),
    (30, 4): (_L3, _L3),
    (32, 0): (_L2, None),
    (32, 1): (_L3, None),
    (32, 2): (_L3, None),
    (40, 0): (_L2, _L3),
    (40, 1): (_L3, _L3),
    (40, 2): (_L3, _L3),
    (60, 1): (_L2, None),
    (60, 2): (_L2, None),
    (60, 3): (_L2, None),
    (60, 4): (_L2, None),
    (80, 1): (None, _L3),
}

#: The group of the internal indications, which has one variation, the packed one.
INDICATIONS_GROUP = 80
PACKED_INDICATIONS = 1

#: The group of the class objects an assignment opens each set with. The
#: variation is one more than the class, and 1 turns events off
#: (IEEE 1815-2012 4.1.5.3).
CLASS_GROUP = 60

#: The analog input reporting deadbands: the group, and the struct format of
#: the value of each variation (16-bit and 32-bit unsigned, single float).
DEADBAND_GROUP = 34
DEADBAND_FORMATS: dict[int, str] = {1: "<H", 2: "<I", 3: "<f"}

#: The attributes a master may write, by variation, with the data type of each
#: (IEEE 1815-2012 Annex A.1: the maximum transmit fragment size, the location
#: name, the ID code or number, and the device name).
WRITABLE_ATTRIBUTES: dict[int, DataType] = {
    Variation.MAXIMUM_TRANSMIT_FRAGMENT_SIZE: DataType.UINT,
    Variation.LOCATION_NAME: DataType.VSTR,
    Variation.DEVICE_ID: DataType.VSTR,
    Variation.DEVICE_NAME: DataType.VSTR,
}

#: The points of an assignment: the indices wanted of each point type, or None for all of them.
AssignedPoints = Mapping[PointType, Sequence[int] | None]


class AboveSubsetLevel(ValueError):
    """A request needs a higher subset level than the outstation is set to."""


def read_group_level(
    group: int,
    variation: int = DEFAULT_VARIATION,
    *,
    ranged: bool = False,
    indexed: bool = False,
) -> SubsetLevel:
    """Return the lowest subset level that is required to accept a read.

    ``ranged`` is a read by start and stop (qualifiers 0x00 and 0x01) and
    ``indexed`` a read by a list of indices (0x17 and 0x28). Anything else
    asks for every object of the group (0x06). A read the subset tables list
    below Level 4 needs the level they give it. Every other read needs Level 4,
    the highest this master knows, so that nothing is sent that a lower level
    might not parse (D122): a read by index list, which TB2016-003b lists only
    as subset-independent, a group or variation the tables do not name, and a
    form they do not list for that variation, such as a range of events or
    group 50 variation 1 by qualifier 0x06 (Table 12-45 lists its read with
    qualifier 0x07 only, as :func:`read_time` builds it).
    """
    if indexed:
        return SubsetLevel.LEVEL_4
    levels = _READ_LEVELS.get((group, variation), (None, None))
    return levels[1 if ranged else 0] or SubsetLevel.LEVEL_4


def _byte(value: int, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
        raise ValueError(f"{what} is a whole number from 0 to 255")
    return value


def read_group(
    group: int,
    variation: int = DEFAULT_VARIATION,
    *,
    start: int | None = None,
    stop: int | None = None,
    indices: Sequence[int] | None = None,
) -> bytes:
    """Build the header of a read of one group in one variation.

    With neither a range nor indices the header asks for every object of the
    group (qualifier 0x06). ``start`` and ``stop`` ask for a range of points,
    in the narrowest start-stop qualifier (0x00 or 0x01), and ``indices`` for
    the points named, in the order given, in the narrowest index-list qualifier
    (0x17 or 0x28). Variation 0 asks for whichever the outstation sends by
    default.
    """
    _byte(group, "a group")
    _byte(variation, "a variation")
    if (start is None) != (stop is None):
        raise ValueError("a range gives both start and stop")
    if start is not None and indices is not None:
        raise ValueError("a read names a range or a list of indices, not both")
    if indices is not None:
        return index_list_header(group, variation, list(indices))
    if start is not None and stop is not None:
        return object_header(group, variation, start=start, stop=stop)
    return all_objects_header(group, variation)


def read_time() -> bytes:
    """The header of a read of the outstation's clock: group 50 variation 1, one object."""
    return bytes([TIME_GROUP, ABSOLUTE_TIME, QualifierCode.UINT8_COUNT, 1])


def read_indications(start: int = 0, stop: int = 15) -> bytes:
    """The header of a read of internal indications by index.

    Index 0 to 15 are the 16 bits of the two indication octets, IIN1.0 to
    IIN2.7 in order (IEEE 1815-2012 annex A.28).
    """
    return object_header(INDICATIONS_GROUP, PACKED_INDICATIONS, start=start, stop=stop)


def assign_class(sets: Sequence[tuple[int, AssignedPoints]]) -> bytes:
    """Build the body of an ASSIGN_CLASS request (IEEE 1815-2012 4.1.5.3).

    Each set is an event class, 1 to 3 or 0 for none, and the points whose
    events go to it, as :func:`read_points` takes them. A set opens with the
    class object for its class, group 60 variation 2 to 4, or variation 1 to
    turn events off. The points follow as headers of their static group in
    variation 0.
    """
    if not sets:
        raise ValueError("an assignment names at least one set of points")
    body = bytearray()
    for event_class, points in sets:
        if isinstance(event_class, bool) or event_class not in (0, 1, 2, 3):
            raise ValueError(f"{event_class!r} is not an event class; 1 to 3, or 0 for none")
        body += all_objects_header(CLASS_GROUP, event_class + 1)
        body += read_points(points)
    return bytes(body)


def assign_class_level(sets: Sequence[tuple[int, AssignedPoints]]) -> SubsetLevel:
    """Return the lowest level that is required to accept an assignment.

    A Level 3 outstation takes it for binary inputs, counters, frozen counters
    and analog inputs. Double-bit inputs and output status are Level 4
    (TB2016-003b Tables 12-7, 12-11 and 12-37).
    """
    level_4 = {PointType.DOUBLE_BIT_INPUT, PointType.BINARY_OUTPUT, PointType.ANALOG_OUTPUT}
    if any(point in level_4 for _, points in sets for point in points):
        return SubsetLevel.LEVEL_4
    return SubsetLevel.LEVEL_3


def write_deadbands(variation: int, values: Mapping[int, int | float]) -> bytes:
    """Build the objects of a write of analog input deadbands.

    ``values`` maps each point's index to its deadband: a whole number for
    variation 1 (16 bits) or 2 (32 bits), or a number of zero or more for
    variation 3 (single-precision float). Consecutive indices share one header,
    which carries a start-stop range (qualifier 0x00 or 0x01). The values
    follow in index order, least significant octet first.
    """
    if variation not in DEADBAND_FORMATS:
        raise ValueError(f"{variation!r} is not a deadband variation; 1, 2 or 3")
    if not values:
        raise ValueError("a write names at least one deadband")
    layout = DEADBAND_FORMATS[variation]
    body = bytearray()
    for start, stop in _runs(sorted(values)):
        body += object_header(DEADBAND_GROUP, variation, start=start, stop=stop)
        for index in range(start, stop + 1):
            body += _deadband(layout, values[index], index)
    return bytes(body)


def _deadband(layout: str, value: int | float, index: int) -> bytes:
    """Return one deadband in the format of its variation."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"the deadband of point {index} is a number")
    try:
        if layout == "<f":
            if math.isnan(value) or value < 0:
                raise ValueError("a floating-point deadband is zero or more")
            return struct.pack(layout, value)
        if int(value) != value:
            raise ValueError("an integer deadband is a whole number")
        return int(value).to_bytes(struct.calcsize(layout), "little")
    except (OverflowError, ValueError) as error:
        raise ValueError(
            f"the deadband of point {index} does not fit this variation: {error}"
        ) from None


def read_attributes(
    variation: int = Variation.ALL_ATTRIBUTES, attribute_set: int | None = None
) -> bytes:
    """The header of a read of device attributes.

    Variation 254 asks for every attribute and 255 for the list of the
    variations the outstation holds, both with no range (qualifier 0x06). Any
    other variation names one attribute, with the start-stop qualifier.
    ``attribute_set`` is the index of the attribute set (IEEE 1815-2012 5.5.2):
    0 for the outstation's own attributes. For 254 and 255 it is sent only
    when given.
    """
    _byte(variation, "a variation")
    if variation == 0:
        raise ValueError("an attribute variation is 1 to 255")
    if attribute_set is None:
        if variation in (Variation.ALL_ATTRIBUTES, Variation.LIST_OF_VARIATIONS):
            return all_objects_header(GROUP_DEVICE_ATTRIBUTES, variation)
        attribute_set = STANDARD_SET
    return object_header(
        GROUP_DEVICE_ATTRIBUTES, variation, start=attribute_set, stop=attribute_set
    )


def write_attribute(variation: int, value: int | str, attribute_set: int = STANDARD_SET) -> bytes:
    """Build the object of a write of one attribute.

    Only the variations in :data:`WRITABLE_ATTRIBUTES` are writable. The object
    is the header with the set as its range, then the data type code, the
    length and the value (IEEE 1815-2012 5.5.4). A text value is visible ASCII,
    at most 255 characters. A number takes the fewest octets of 1, 2 or 4 that
    hold it.
    """
    if variation not in WRITABLE_ATTRIBUTES:
        writable = ", ".join(str(int(each)) for each in WRITABLE_ATTRIBUTES)
        raise ValueError(
            f"attribute {variation!r} cannot be written; the writable ones are {writable}"
        )
    if WRITABLE_ATTRIBUTES[variation] == DataType.UINT:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << 32:
            raise ValueError(f"attribute {variation} is a whole number from 0 to 4294967295")
        attribute = Attribute.unsigned(value)
    else:
        if not isinstance(value, str) or not all(" " <= character <= "~" for character in value):
            raise ValueError(f"attribute {variation} is text of visible ASCII characters")
        if len(value) > 255:
            raise ValueError(f"attribute {variation} is at most 255 characters")
        attribute = Attribute(DataType.VSTR, value.encode("ascii"))
    return attribute_block(variation, attribute, index=attribute_set)
