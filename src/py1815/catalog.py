"""Every object group and variation IEEE 1815-2012 defines, by number and name.

Annex A of the standard is the object library: one subclause for each group,
and one for each variation in it. This module names them all, whether or not
this library reads or writes them, so that code that adds support for a group
starts from the standard's numbers and not from a guess. It also gives each
object's size where the standard fixes one.

The table below is written out, not read from ``conformance/ieee-1815-2012.json``,
because the library does not read that file at run time.
``tests/test_conformance.py`` diffs this table against the file, which
``scripts/extract_conformance.py`` reads from the standard, so a group,
variation, name, type or size that disagrees with the standard fails the test
suite.

Names are the standard's own headings, with its dashes written ``" - "``.
Which objects the outstation serves and the master reads is a separate
question, answered from the code that does the work by
:mod:`py1815.object_coverage`.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum

#: The variation number of a group that gives none of its own. In groups 110 to
#: 113 the variation is the length of the string, and the standard describes all
#: of them in one subclause. Group 100 is obsolete and defines no layout.
ALL = None


class ObjectKind(Enum):
    """What an object is for, as the header of its subclause names it."""

    STATIC = "Static"
    EVENT = "Event"
    COMMAND = "Cmnd"
    INFO = "Info"
    #: A file-control object that serves both purposes.
    INFO_EVENT = "Info/Event"
    #: A device attribute.
    ATTRIBUTE = "Attrib"
    #: A private data set object, which may be used for any of them.
    ANY = "Any"


class SizeKind(Enum):
    """How the standard fixes the size of an object."""

    #: A whole number of octets.
    FIXED = "fixed"
    #: Bits, packed from bit 0 of the first octet, one object per point.
    PACKED = "packed"
    #: Set by the sender: a string, a list or a body of other objects.
    VARIABLE = "variable"


@dataclass(frozen=True)
class Size:
    """The size of one object."""

    kind: SizeKind
    #: Octets for a fixed size, bits for a packed one, None for a variable one.
    amount: int | None = None

    @property
    def octets(self) -> int | None:
        """The octets of a fixed size, or None for any other."""
        return self.amount if self.kind is SizeKind.FIXED else None

    @property
    def bits(self) -> int | None:
        """The bits one object takes in a packed format, or None for any other."""
        return self.amount if self.kind is SizeKind.PACKED else None


def fixed(octets: int) -> Size:
    """A size of a whole number of octets."""
    return Size(SizeKind.FIXED, octets)


def packed(bits: int) -> Size:
    """A packed size of this many bits for each object."""
    return Size(SizeKind.PACKED, bits)


VARIABLE = Size(SizeKind.VARIABLE)
_VAR = VARIABLE


@dataclass(frozen=True)
class ObjectVariation:
    """One variation of an object group."""

    group: int
    #: The variation number, or ALL for a group that gives none of its own.
    variation: int | None
    kind: ObjectKind
    size: Size
    name: str


@dataclass(frozen=True)
class ObjectGroup:
    """One object group and the variations the standard defines for it."""

    number: int
    name: str
    variations: dict[int | None, ObjectVariation]


_ST, _EV, _CMD = ObjectKind.STATIC, ObjectKind.EVENT, ObjectKind.COMMAND
_INFO, _INFO_EV = ObjectKind.INFO, ObjectKind.INFO_EVENT
_ATTR, _ANY = ObjectKind.ATTRIBUTE, ObjectKind.ANY
_Row = tuple[int | None, ObjectKind, Size, str]


def _group(number: int, name: str, rows: list[_Row]) -> ObjectGroup:
    return ObjectGroup(
        number,
        name,
        {
            variation: ObjectVariation(number, variation, kind, size, title)
            for variation, kind, size, title in rows
        },
    )


# The standard's own order, one line to a variation.
# fmt: off
_TABLE = (
    _group(0, "device attributes", [
        (209, _ATTR, _VAR, "Device attributes - secure authentication version"),
        (210, _ATTR, _VAR,
         "Device attributes - number of security statistics per "
         "association"),
        (211, _ATTR, _VAR,
         "Device attributes - identification of support for "
         "user-specific attributes"),
        (212, _ATTR, _VAR,
         "Device attributes - number of master-defined data set "
         "prototypes"),
        (213, _ATTR, _VAR,
         "Device attributes - number of outstation-defined data set "
         "prototypes"),
        (214, _ATTR, _VAR, "Device attributes - number of master-defined data sets"),
        (215, _ATTR, _VAR, "Device attributes - number of outstation-defined data sets"),
        (216, _ATTR, _VAR,
         "Device attributes - maximum number of binary output objects "
         "per request"),
        (217, _ATTR, _VAR, "Device attributes - local timing accuracy"),
        (218, _ATTR, _VAR, "Device attributes - duration of time accuracy"),
        (219, _ATTR, _VAR, "Device attributes - support for analog output events"),
        (220, _ATTR, _VAR, "Device attributes - maximum analog output index"),
        (221, _ATTR, _VAR, "Device attributes - number of analog outputs"),
        (222, _ATTR, _VAR, "Device attributes - support for binary output events"),
        (223, _ATTR, _VAR, "Device attributes - maximum binary output index"),
        (224, _ATTR, _VAR, "Device attributes - number of binary outputs"),
        (225, _ATTR, _VAR, "Device attributes - support for frozen counter events"),
        (226, _ATTR, _VAR, "Device attributes - support for frozen counters"),
        (227, _ATTR, _VAR, "Device attributes - support for counter events"),
        (228, _ATTR, _VAR, "Device attributes - maximum counter index"),
        (229, _ATTR, _VAR, "Device attributes - number of counter points"),
        (230, _ATTR, _VAR, "Device attributes - support for frozen analog inputs"),
        (231, _ATTR, _VAR, "Device attributes - support for analog input events"),
        (232, _ATTR, _VAR, "Device attributes - maximum analog input index"),
        (233, _ATTR, _VAR, "Device attributes - number of analog input points"),
        (234, _ATTR, _VAR,
         "Device attributes - support for double-bit binary input "
         "events"),
        (235, _ATTR, _VAR, "Device attributes - maximum double-bit binary index"),
        (236, _ATTR, _VAR,
         "Device attributes - number of double-bit binary input "
         "points"),
        (237, _ATTR, _VAR, "Device attributes - support for binary input events"),
        (238, _ATTR, _VAR, "Device attributes - maximum binary input index"),
        (239, _ATTR, _VAR, "Device attributes - number of binary input points"),
        (240, _ATTR, _VAR, "Device attributes - maximum transmit fragment size"),
        (241, _ATTR, _VAR, "Device attributes - maximum receive fragment size"),
        (242, _ATTR, _VAR, "Device attributes - device manufacturer's software version"),
        (243, _ATTR, _VAR, "Device attributes - device manufacturer's hardware version"),
        (245, _ATTR, _VAR, "Device attributes - user-assigned location name"),
        (246, _ATTR, _VAR, "Device attributes - user-assigned ID code/number"),
        (247, _ATTR, _VAR, "Device attributes - user-assigned device name"),
        (248, _ATTR, _VAR, "Device attributes - device serial number"),
        (249, _ATTR, _VAR, "Device attributes - DNP3 subset and conformance"),
        (250, _ATTR, _VAR,
         "Device attributes - device manufacturer's product name and "
         "model"),
        (252, _ATTR, _VAR, "Device attributes - device manufacturer's name"),
        (254, _ATTR, fixed(0), "Device attributes - non-specific all attributes request"),
        (255, _ATTR, _VAR, "Device attributes - list of attribute variations"),
    ]),
    _group(1, "binary inputs", [
        (1, _ST, packed(1), "Binary input - packed format"),
        (2, _ST, fixed(1), "Binary input - with flags"),
    ]),
    _group(2, "binary input events", [
        (1, _EV, fixed(1), "Binary input event - without time"),
        (2, _EV, fixed(7), "Binary input event - with absolute time"),
        (3, _EV, fixed(3), "Binary input event - with relative time"),
    ]),
    _group(3, "double-bit binary inputs", [
        (1, _ST, packed(2), "Double-bit binary input - packed format"),
        (2, _ST, fixed(1), "Double-bit binary input - with flags"),
    ]),
    _group(4, "double-bit binary input events", [
        (1, _EV, fixed(1), "Double-bit binary input event - without time"),
        (2, _EV, fixed(7), "Double-bit binary input event - with absolute time"),
        (3, _EV, fixed(3), "Double-bit binary input event - with relative time"),
    ]),
    _group(10, "binary outputs", [
        (1, _ST, packed(1), "Binary output - packed format"),
        (2, _ST, fixed(1), "Binary output - output status with flags"),
    ]),
    _group(11, "binary output events", [
        (1, _EV, fixed(1), "Binary output event - status without time"),
        (2, _EV, fixed(7), "Binary output event - status with time"),
    ]),
    _group(12, "binary output commands", [
        (1, _CMD, fixed(11),
         "Binary output command - control relay output block - also "
         "known as CROB"),
        (2, _CMD, fixed(11),
         "Binary output command - pattern control block - also known "
         "as PCB"),
        (3, _CMD, packed(1), "Binary output command - pattern mask"),
    ]),
    _group(13, "binary output command events", [
        (1, _EV, fixed(1), "Binary output command event - command status without time"),
        (2, _EV, fixed(7), "Binary output command event - command status with time"),
    ]),
    _group(20, "counters", [
        (1, _ST, fixed(5), "Counter - 32-bit with flag"),
        (2, _ST, fixed(3), "Counter - 16-bit with flag"),
        (3, _ST, fixed(5), "Counter - 32-bit with flag, delta"),
        (4, _ST, fixed(3), "Counter - 16-bit with flag, delta"),
        (5, _ST, fixed(4), "Counter - 32-bit without flag"),
        (6, _ST, fixed(2), "Counter - 16-bit without flag"),
        (7, _ST, fixed(4), "Counter - 32-bit without flag, delta"),
        (8, _ST, fixed(2), "Counter - 16-bit without flag, delta"),
    ]),
    _group(21, "frozen counters", [
        (1, _ST, fixed(5), "Frozen counter - 32-bit with flag"),
        (2, _ST, fixed(3), "Frozen counter - 16-bit with flag"),
        (3, _ST, fixed(5), "Frozen counter - 32-bit with flag, delta"),
        (4, _ST, fixed(3), "Frozen counter - 16-bit with flag, delta"),
        (5, _ST, fixed(11), "Frozen counter - 32-bit with flag and time"),
        (6, _ST, fixed(9), "Frozen counter - 16-bit with flag and time"),
        (7, _ST, fixed(11), "Frozen counter - 32-bit with flag and time, delta"),
        (8, _ST, fixed(9), "Frozen counter - 16-bit with flag and time, delta"),
        (9, _ST, fixed(4), "Frozen counter - 32-bit without flag"),
        (10, _ST, fixed(2), "Frozen counter - 16-bit without flag"),
        (11, _ST, fixed(4), "Frozen counter - 32-bit without flag, delta"),
        (12, _ST, fixed(2), "Frozen counter - 16-bit without flag, delta"),
    ]),
    _group(22, "counter events", [
        (1, _EV, fixed(5), "Counter event - 32-bit with flag"),
        (2, _EV, fixed(3), "Counter event - 16-bit with flag"),
        (3, _EV, fixed(5), "Counter event - 32-bit with flag, delta"),
        (4, _EV, fixed(3), "Counter event - 16-bit with flag, delta"),
        (5, _EV, fixed(11), "Counter event - 32-bit with flag and time"),
        (6, _EV, fixed(9), "Counter event - 16-bit with flag and time"),
        (7, _EV, fixed(11), "Counter event - 32-bit with flag and time, delta"),
        (8, _EV, fixed(9), "Counter event - 16-bit with flag and time, delta"),
    ]),
    _group(23, "frozen counter events", [
        (1, _EV, fixed(5), "Frozen counter event - 32-bit with flag"),
        (2, _EV, fixed(3), "Frozen counter event - 16-bit with flag"),
        (3, _EV, fixed(5), "Frozen counter event - 32-bit with flag, delta"),
        (4, _EV, fixed(3), "Frozen counter event - 16-bit with flag, delta"),
        (5, _EV, fixed(11), "Frozen counter event - 32-bit with flag and time"),
        (6, _EV, fixed(9), "Frozen counter event - 16-bit with flag and time"),
        (7, _EV, fixed(11), "Frozen counter event - 32-bit with flag and time, delta"),
        (8, _EV, fixed(9), "Frozen counter event - 16-bit with flag and time, delta"),
    ]),
    _group(30, "analog inputs", [
        (1, _ST, fixed(5), "Analog input - 32-bit with flag"),
        (2, _ST, fixed(3), "Analog input - 16-bit with flag"),
        (3, _ST, fixed(4), "Analog input - 32-bit without flag"),
        (4, _ST, fixed(2), "Analog input - 16-bit without flag"),
        (5, _ST, fixed(5), "Analog input - single-precision, floating-point with flag"),
        (6, _ST, fixed(9), "Analog input - double-precision, floating-point with flag"),
    ]),
    _group(31, "frozen analog inputs", [
        (1, _ST, fixed(5), "Frozen analog input - 32-bit with flag"),
        (2, _ST, fixed(3), "Frozen analog input - 16-bit with flag"),
        (3, _ST, fixed(11), "Frozen analog input - 32-bit with time-of-freeze"),
        (4, _ST, fixed(9), "Frozen analog input - 16-bit with time-of-freeze"),
        (5, _ST, fixed(4), "Frozen analog input - 32-bit without flag"),
        (6, _ST, fixed(2), "Frozen analog input - 16-bit without flag"),
        (7, _ST, fixed(5), "Frozen analog input - single-precision, floating-point with flag"),
        (8, _ST, fixed(9), "Frozen analog input - double-precision, floating-point with flag"),
    ]),
    _group(32, "analog input events", [
        (1, _EV, fixed(5), "Analog input event - 32-bit without time"),
        (2, _EV, fixed(3), "Analog input event - 16-bit without time"),
        (3, _EV, fixed(11), "Analog input event - 32-bit with time"),
        (4, _EV, fixed(9), "Analog input event - 16-bit with time"),
        (5, _EV, fixed(5),
         "Analog input event - single-precision, floating-point "
         "without time"),
        (6, _EV, fixed(9),
         "Analog input event - double-precision, floating-point "
         "without time"),
        (7, _EV, fixed(11), "Analog input event - single-precision, floating-point with time"),
        (8, _EV, fixed(15), "Analog input event - double-precision, floating-point with time"),
    ]),
    _group(33, "frozen analog input events", [
        (1, _EV, fixed(5), "Frozen analog input event - 32-bit without time"),
        (2, _EV, fixed(3), "Frozen analog input event - 16-bit without time"),
        (3, _EV, fixed(11), "Frozen analog input event - 32-bit with time"),
        (4, _EV, fixed(9), "Frozen analog input event - 16-bit with time"),
        (5, _EV, fixed(5),
         "Frozen analog input event - single-precision, "
         "floating-point without time"),
        (6, _EV, fixed(9),
         "Frozen analog input event - double-precision, "
         "floating-point without time"),
        (7, _EV, fixed(11),
         "Frozen analog input event - single-precision, "
         "floating-point with time"),
        (8, _EV, fixed(15),
         "Frozen analog input event - double-precision, "
         "floating-point with time"),
    ]),
    _group(34, "analog input reporting deadbands", [
        (1, _ST, fixed(2), "Analog input reporting deadband - 16-bit"),
        (2, _ST, fixed(4), "Analog input reporting deadband - 32-bit"),
        (3, _ST, fixed(4),
         "Analog input reporting deadband - single-precision, "
         "floating-point"),
    ]),
    _group(40, "analog output status", [
        (1, _ST, fixed(5), "Analog output status - 32-bit with flag"),
        (2, _ST, fixed(3), "Analog output status - 16-bit with flag"),
        (3, _ST, fixed(5),
         "Analog output status - single-precision, floating-point "
         "with flag"),
        (4, _ST, fixed(9),
         "Analog output status - double-precision, floating-point "
         "with flag"),
    ]),
    _group(41, "analog outputs", [
        (1, _CMD, fixed(5), "Analog output - 32-bit"),
        (2, _CMD, fixed(3), "Analog output - 16-bit"),
        (3, _CMD, fixed(5), "Analog output - single-precision, floating-point"),
        (4, _CMD, fixed(9), "Analog output - double-precision, floating-point"),
    ]),
    _group(42, "analog output events", [
        (1, _EV, fixed(5), "Analog output event - 32-bit without time"),
        (2, _EV, fixed(3), "Analog output event - 16-bit without time"),
        (3, _EV, fixed(11), "Analog output event - 32-bit with time"),
        (4, _EV, fixed(9), "Analog output event - 16-bit with time"),
        (5, _EV, fixed(5),
         "Analog output event - single-precision, floating-point "
         "without time"),
        (6, _EV, fixed(9),
         "Analog output event - double-precision, floating-point "
         "without time"),
        (7, _EV, fixed(11), "Analog output event - single-precision, floating-point with time"),
        (8, _EV, fixed(15), "Analog output event - double-precision, floating-point with time"),
    ]),
    _group(43, "analog output command events", [
        (1, _EV, fixed(5), "Analog output command event - 32-bit without time"),
        (2, _EV, fixed(3), "Analog output command event - 16-bit without time"),
        (3, _EV, fixed(11), "Analog output command event - 32-bit with time"),
        (4, _EV, fixed(9), "Analog output command event - 16-bit with time"),
        (5, _EV, fixed(5),
         "Analog output command event - single-precision, "
         "floating-point without time"),
        (6, _EV, fixed(9),
         "Analog output command event - double-precision, "
         "floating-point without time"),
        (7, _EV, fixed(11),
         "Analog output command event - single-precision, "
         "floating-point with time"),
        (8, _EV, fixed(15),
         "Analog output command event - double-precision, "
         "floating-point with time"),
    ]),
    _group(50, "time and date", [
        (1, _INFO, fixed(6), "Time and date - absolute time"),
        (2, _INFO, fixed(10), "Time and date - absolute time and interval"),
        (3, _INFO, fixed(6), "Time and date - absolute time at last recorded time"),
        (4, _INFO, fixed(11), "Time and date - indexed absolute time and long interval"),
    ]),
    _group(51, "time and date common time-of-occurrences", [
        (1, _INFO, fixed(6),
         "Time and date common time-of-occurrence - absolute time, "
         "synchronized"),
        (2, _INFO, fixed(6),
         "Time and date common time-of-occurrence - absolute time, "
         "unsynchronized"),
    ]),
    _group(52, "time delays", [
        (1, _INFO, fixed(2), "Time delay - coarse"),
        (2, _INFO, fixed(2), "Time delay - fine"),
    ]),
    _group(60, "class objects", [
        (1, _INFO, fixed(0), "Class objects - Class 0 data"),
        (2, _INFO, fixed(0), "Class objects - Class 1 data"),
        (3, _INFO, fixed(0), "Class objects - Class 2 data"),
        (4, _INFO, fixed(0), "Class objects - Class 3 data"),
    ]),
    _group(70, "file-control", [
        (1, _INFO, _VAR, "File-control - file identifier - superseded"),
        (2, _INFO, _VAR, "File-control - authentication"),
        (3, _INFO, _VAR, "File-control - file command"),
        (4, _INFO_EV, _VAR, "File-control - file command status"),
        (5, _INFO_EV, _VAR, "File-control - file transport"),
        (6, _INFO_EV, _VAR, "File-control - file transport status"),
        (7, _INFO_EV, _VAR, "File-control - file descriptor"),
        (8, _INFO, _VAR, "File-control - file specification string"),
    ]),
    _group(80, "internal indications", [
        (1, _ST, packed(1), "Internal indications - packed format"),
    ]),
    _group(81, "device storage", [
        (1, _INFO, fixed(3), "Device storage - buffer fill status"),
    ]),
    _group(82, "Device Profiles", [
        (1, _INFO, _VAR, "Device Profile - functions and indexes"),
    ]),
    _group(83, "data sets", [
        (1, _ANY, _VAR, "Data set - private registration object"),
        (2, _INFO, _VAR, "Data set - private registration object descriptor"),
    ]),
    _group(85, "data set prototypes", [
        (1, _INFO, _VAR, "Data set prototype - with UUID"),
    ]),
    _group(86, "data set descriptors", [
        (1, _INFO, _VAR, "Data set descriptor - data set contents"),
        (2, _INFO, fixed(1), "Data set descriptor - characteristics"),
        (3, _INFO, _VAR, "Data set descriptor - point index attributes"),
    ]),
    _group(87, "data sets", [
        (1, _ST, _VAR, "Data set - present value"),
    ]),
    _group(88, "data set events", [
        (1, _EV, _VAR, "Data set event - snapshot"),
    ]),
    _group(90, "applications", [
        (1, _INFO, _VAR, "Application - identifier"),
    ]),
    _group(91, "status of requested operations", [
        (1, _INFO, _VAR, "Status of requested operation - active configuration"),
    ]),
    _group(100, "floating-point", [
        (ALL, _ST, _VAR,
         "Floating-point - none - general description common to all "
         "variations"),
    ]),
    _group(101, "binary-coded decimal integers", [
        (1, _ST, fixed(2), "Binary-coded decimal integer - small"),
        (2, _ST, fixed(4), "Binary-coded decimal integer - medium"),
        (3, _ST, fixed(8), "Binary-coded decimal integer - large"),
    ]),
    _group(102, "unsigned integers", [
        (1, _ST, fixed(1), "Unsigned integer - 8-bit"),
    ]),
    _group(110, "octet strings", [
        (ALL, _ST, _VAR,
         "Octet string - none - general description common to all "
         "variations"),
    ]),
    _group(111, "octet string events", [
        (ALL, _EV, _VAR,
         "Octet string event - none - general description common to "
         "all variations"),
    ]),
    _group(112, "virtual terminal output blocks", [
        (ALL, _ST, _VAR,
         "Virtual terminal output block - none - general description "
         "common to all variations"),
    ]),
    _group(113, "virtual terminal event data", [
        (ALL, _EV, _VAR,
         "Virtual terminal event data - none - general description "
         "common to all variations"),
    ]),
    _group(120, "authentication", [
        (1, _INFO, _VAR, "Authentication - challenge"),
        (2, _INFO, _VAR, "Authentication - reply"),
        (3, _INFO, fixed(6), "Authentication - Aggressive Mode request"),
        (4, _INFO, fixed(2), "Authentication - session key status request"),
        (5, _INFO, _VAR, "Authentication - session key status"),
        (6, _INFO, _VAR, "Authentication - session key change"),
        (7, _EV, _VAR, "Authentication - error"),
        (8, _INFO, _VAR, "Authentication - user certificate"),
        (9, _INFO, _VAR, "Authentication - message authentication code (MAC)"),
        (10, _INFO, _VAR, "Authentication - user status change"),
        (11, _INFO, _VAR, "Authentication - update key change request"),
        (12, _INFO, _VAR, "Authentication - update key change reply"),
        (13, _INFO, _VAR, "Authentication - update key change"),
        (14, _INFO, _VAR, "Authentication - update key change signature"),
        (15, _INFO, _VAR, "Authentication - update key change confirmation"),
    ]),
    _group(121, "security statistics", [
        (1, _ST, fixed(7), "Security statistic - 32-bit with flag"),
    ]),
    _group(122, "security statistic events", [
        (1, _EV, fixed(7), "Security statistic event - 32-bit with flag"),
        (2, _EV, fixed(13), "Security statistic event - 32-bit with flag and time"),
    ]),
)
# fmt: on

#: Every group, by number.
GROUPS: dict[int, ObjectGroup] = {group.number: group for group in _TABLE}


def objects() -> Iterator[ObjectVariation]:
    """Every variation of every group, in group and variation order."""
    for group in GROUPS.values():
        yield from group.variations.values()


def find(group: int, variation: int | None) -> ObjectVariation | None:
    """The variation the standard defines under this number, or None.

    Pass ``ALL`` for the one description of groups 100 and 110 to 113.
    """
    entry = GROUPS.get(group)
    if entry is None:
        return None
    return entry.variations.get(variation)
