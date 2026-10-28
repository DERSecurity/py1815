"""DNP3 traffic records: one JSON body per application fragment, and its envelope.

An application that embeds the outstation or the master knows every fragment
it sends and receives. This module describes each fragment as a JSON body that
follows the DNP3 traffic schema, version 1 (:data:`SCHEMA_ID`), and wraps the
body in a :class:`~py1815.envelope.ProtocolMessage`, so the application can
publish its own traffic to consumers that also take captured DNP3 traffic. It
builds the bodies from a :class:`~py1815.observers.RequestRecord` from the
outstation, and from an exchange or an unsolicited response from the master.

The schema, not any one decoder's output, defines the body (D103). It ships
with the package, and :func:`load_schema` returns it. A body describes the
fragment in IEEE 1815 terms:

- The link addresses, the application function code, the link layer's
  primary-message bit, which end sent the fragment, the application control's
  UNS bit, and a response's internal indications by name.
- The IP address and port of each end of the connection, where known.
- One entry per object header, with its qualifier, its range or count, and
  the octets of objects that are not points, such as a time write.
- Every point the fragment carries, in wire order, with its point type,
  object group and variation, the index on the wire, its value, flag octet and
  time, and the fields of a control object.

The fragment is read by this module's own walk of the object headers, written
from the object layouts of IEEE 1815-2012. It reads requests and responses,
every qualifier the standard defines, and the command objects a master sends
and an outstation echoes. A fragment it cannot read to its end is described as
rejected, with no objects and no points (:data:`REJECTED_MALFORMED`,
:data:`REJECTED_POINT_COUNT`, :data:`REJECTED_TOO_LARGE`).

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import ipaddress
import json
import math
import struct
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum, StrEnum
from importlib import resources
from typing import TYPE_CHECKING, Any

from py1815.application import UNS_MASK, build_response
from py1815.envelope import (
    NetworkEndpoint,
    Protocol,
    ProtocolMessage,
    ProtocolMetadata,
    WireDirection,
)
from py1815.observers import Endpoint, RequestRecord

if TYPE_CHECKING:
    from py1815.application import Response
    from py1815.master.association import Exchange, Unsolicited

#: The ``$id`` of the JSON Schema every body follows.
SCHEMA_ID = "https://dersec.com/schemas/dnp3-traffic/v1"

#: The body's ``schema`` field: the version of the body's shape.
SCHEMA_VERSION = 1

#: The ``apdu_rejected`` reason for a fragment that cannot be read to its end.
REJECTED_MALFORMED = "malformed"

#: The ``apdu_rejected`` reason for a fragment whose object data ends before the
#: objects an object header's range or count declares.
REJECTED_POINT_COUNT = "point_count"

#: The ``apdu_rejected`` reason for a fragment with more object headers or
#: points, or a longer header ``data``, than the schema allows.
REJECTED_TOO_LARGE = "too_large"

#: The most object headers a body lists. A fragment with more is rejected.
MAX_OBJECTS = 1024

#: The most points a body lists. A fragment with more is rejected.
MAX_POINTS = 16384

#: The most octets a header's ``data`` holds: a whole 2048-octet fragment.
MAX_DATA_OCTETS = 2048

#: The internal indication names, IIN1.0 to IIN2.7 in bit order.
IIN_BITS = (
    "broadcast",
    "class_1_events",
    "class_2_events",
    "class_3_events",
    "need_time",
    "local_control",
    "device_trouble",
    "device_restart",
    "no_func_code_support",
    "object_unknown",
    "parameter_error",
    "event_buffer_overflow",
    "already_executing",
    "config_corrupt",
    "reserved_2",
    "reserved_1",
)

#: The key, in the envelope's ``protocol_data.extra``, that says where the
#: traffic was captured, and the value for traffic seen as it happened.
CAPTURE_ORIGIN_KEY = "capture_origin"
CAPTURE_ORIGIN_LIVE = "live"

#: The key, beside it, that says how ``client_id`` was learned. Written empty.
CLIENT_ID_SOURCE_KEY = "client_id_source"

_SCHEMA_FILE = "dnp3_traffic.schema.json"

#: The primary-message bit of the frames that carry fragments. Application data
#: travels as user data, which only a primary station sends.
_PRIMARY = 1

#: The largest DNP3 time: 48 bits of milliseconds.
_MAX_TIME = (1 << 48) - 1


class Direction(StrEnum):
    """Which end sent a fragment: the master sends requests, the outstation responses."""

    REQUEST = "request"
    RESPONSE = "response"


def load_schema() -> dict[str, Any]:
    """Return the JSON Schema the bodies follow, read from the copy in this package."""
    text = (resources.files("py1815") / "schemas" / _SCHEMA_FILE).read_text(encoding="utf-8")
    schema: dict[str, Any] = json.loads(text)
    return schema


# ------------------------------------------------------------ object layouts

_BINARY = "binary"
_DOUBLE_BIT_BINARY = "double_bit_binary"
_BINARY_OUTPUT = "binary_output"
_COUNTER = "counter"
_ANALOG = "analog"
_ANALOG_DEADBAND = "analog_deadband"
_ANALOG_OUTPUT = "analog_output"
_OCTET_STRING = "octet_string"
_INTERNAL_INDICATION = "internal_indication"


class _Field(Enum):
    """One field of an object, in the order the object carries its fields."""

    #: The flag octet of a binary object, with the state in bit 7.
    FLAGS_STATE = 1
    #: The flag octet of a double-bit binary object, with the state in bits 6 and 7.
    FLAGS_DOUBLE = 2
    #: A flag octet with no state bits.
    FLAGS = 3
    #: A control status octet.
    STATUS = 4
    #: The octet of a binary output command event: the commanded state in bit 7
    #: and the control status in bits 0 to 6.
    STATE_STATUS = 5
    #: The value, in the layout's ``number`` format.
    VALUE = 6
    #: A 48-bit absolute time.
    TIME = 7
    #: Sixteen bits of milliseconds after the common time of occurrence.
    RELATIVE_TIME = 8
    #: A CROB's control code, count, on time and off time, before its status.
    CONTROL = 9
    #: The octets of an octet string, as many as the variation says.
    OCTETS = 10


#: Octets of each fixed-width field. VALUE and OCTETS depend on the layout.
_FIELD_SIZES = {
    _Field.FLAGS_STATE: 1,
    _Field.FLAGS_DOUBLE: 1,
    _Field.FLAGS: 1,
    _Field.STATUS: 1,
    _Field.STATE_STATUS: 1,
    _Field.TIME: 6,
    _Field.RELATIVE_TIME: 2,
    _Field.CONTROL: 10,
}

_CONTROL = struct.Struct("<BBII")


@dataclass(frozen=True)
class _Layout:
    """How one object of a group and variation is laid out."""

    #: The point type of the object, or None for an object that is not a point.
    kind: str | None
    fields: tuple[_Field, ...] = ()
    #: The ``struct`` format of the value, for a layout with a VALUE field.
    number: str | None = None
    #: Bits per object, for a packed variation: one bit or two per point.
    packed_bits: int = 0
    #: Octets of an object that is walked past and not read.
    opaque: int = 0

    def width(self, each: _Field, variation: int) -> int:
        """Return the octets one of this layout's fields occupies."""
        if each is _Field.VALUE:
            assert self.number is not None
            return struct.calcsize(self.number)
        if each is _Field.OCTETS:
            return variation
        return _FIELD_SIZES[each]

    def size(self, variation: int) -> int:
        """Return the octets one object occupies. Not used for a packed layout."""
        return self.opaque + sum(self.width(each, variation) for each in self.fields)


_F = _Field


def _state(kind: str, *more: _Field) -> _Layout:
    flags = _F.FLAGS_DOUBLE if kind == _DOUBLE_BIT_BINARY else _F.FLAGS_STATE
    return _Layout(kind, (flags, *more))


def _number(kind: str, number: str, *more: _Field, flags: bool = True) -> _Layout:
    leading = (_F.FLAGS,) if flags else ()
    return _Layout(kind, (*leading, _F.VALUE, *more), number)


def _status_first(number: str, *more: _Field) -> _Layout:
    return _Layout(_ANALOG_OUTPUT, (_F.STATUS, _F.VALUE, *more), number)


def _event_numbers(kind: str) -> dict[int, _Layout]:
    """Return variations 1 to 8 of an analog event group (32, 33, 42)."""
    return {
        1: _number(kind, "<i"),
        2: _number(kind, "<h"),
        3: _number(kind, "<i", _F.TIME),
        4: _number(kind, "<h", _F.TIME),
        5: _number(kind, "<f"),
        6: _number(kind, "<d"),
        7: _number(kind, "<f", _F.TIME),
        8: _number(kind, "<d", _F.TIME),
    }


def _groups(**groups: dict[int, _Layout]) -> dict[tuple[int, int], _Layout]:
    return {
        (int(group[1:]), variation): layout
        for group, variations in groups.items()
        for variation, layout in variations.items()
    }


_CROB = _Layout(_BINARY_OUTPUT, (_F.CONTROL, _F.STATUS))
_TIME_OBJECT = _Layout(None, (_F.TIME,))

#: Every object this module reads, by group and variation, from the object
#: layouts of IEEE 1815-2012. Octet strings, whose length is their variation,
#: are in ``_OCTET_GROUPS``. An object absent from both ends the walk.
_LAYOUTS: dict[tuple[int, int], _Layout] = _groups(
    # Binary inputs, packed and with flags, and their events.
    g1={1: _Layout(_BINARY, packed_bits=1), 2: _state(_BINARY)},
    g2={
        1: _state(_BINARY),
        2: _state(_BINARY, _F.TIME),
        3: _state(_BINARY, _F.RELATIVE_TIME),
    },
    # Double-bit binary inputs, two bits per point when packed, and their events.
    g3={1: _Layout(_DOUBLE_BIT_BINARY, packed_bits=2), 2: _state(_DOUBLE_BIT_BINARY)},
    g4={
        1: _state(_DOUBLE_BIT_BINARY),
        2: _state(_DOUBLE_BIT_BINARY, _F.TIME),
        3: _state(_DOUBLE_BIT_BINARY, _F.RELATIVE_TIME),
    },
    # Binary output status, its events, the CROB and the pattern control block
    # and mask, and the binary output command events.
    g10={1: _Layout(_BINARY_OUTPUT, packed_bits=1), 2: _state(_BINARY_OUTPUT)},
    g11={1: _state(_BINARY_OUTPUT), 2: _state(_BINARY_OUTPUT, _F.TIME)},
    g12={1: _CROB, 2: _CROB, 3: _Layout(_BINARY_OUTPUT, packed_bits=1)},
    g13={
        1: _Layout(_BINARY_OUTPUT, (_F.STATE_STATUS,)),
        2: _Layout(_BINARY_OUTPUT, (_F.STATE_STATUS, _F.TIME)),
    },
    # Counters, frozen counters, and their events.
    g20={
        1: _number(_COUNTER, "<I"),
        2: _number(_COUNTER, "<H"),
        5: _number(_COUNTER, "<I", flags=False),
        6: _number(_COUNTER, "<H", flags=False),
    },
    g21={
        1: _number(_COUNTER, "<I"),
        2: _number(_COUNTER, "<H"),
        5: _number(_COUNTER, "<I", _F.TIME),
        6: _number(_COUNTER, "<H", _F.TIME),
        9: _number(_COUNTER, "<I", flags=False),
        10: _number(_COUNTER, "<H", flags=False),
    },
    g22={
        1: _number(_COUNTER, "<I"),
        2: _number(_COUNTER, "<H"),
        5: _number(_COUNTER, "<I", _F.TIME),
        6: _number(_COUNTER, "<H", _F.TIME),
    },
    g23={
        1: _number(_COUNTER, "<I"),
        2: _number(_COUNTER, "<H"),
        5: _number(_COUNTER, "<I", _F.TIME),
        6: _number(_COUNTER, "<H", _F.TIME),
    },
    # Analog inputs, frozen analog inputs, and their events.
    g30={
        1: _number(_ANALOG, "<i"),
        2: _number(_ANALOG, "<h"),
        3: _number(_ANALOG, "<i", flags=False),
        4: _number(_ANALOG, "<h", flags=False),
        5: _number(_ANALOG, "<f"),
        6: _number(_ANALOG, "<d"),
    },
    g31={
        1: _number(_ANALOG, "<i"),
        2: _number(_ANALOG, "<h"),
        3: _number(_ANALOG, "<i", _F.TIME),
        4: _number(_ANALOG, "<h", _F.TIME),
        5: _number(_ANALOG, "<i", flags=False),
        6: _number(_ANALOG, "<h", flags=False),
        7: _number(_ANALOG, "<f"),
        8: _number(_ANALOG, "<d"),
    },
    g32=_event_numbers(_ANALOG),
    g33=_event_numbers(_ANALOG),
    # Analog input deadbands: unsigned 16 and 32 bits, and single precision.
    g34={
        1: _number(_ANALOG_DEADBAND, "<H", flags=False),
        2: _number(_ANALOG_DEADBAND, "<I", flags=False),
        3: _number(_ANALOG_DEADBAND, "<f", flags=False),
    },
    # Analog output status, the analog output block (value, then status), its
    # events, and the analog output command events (status, then value).
    g40={
        1: _number(_ANALOG_OUTPUT, "<i"),
        2: _number(_ANALOG_OUTPUT, "<h"),
        3: _number(_ANALOG_OUTPUT, "<f"),
        4: _number(_ANALOG_OUTPUT, "<d"),
    },
    g41={
        1: _number(_ANALOG_OUTPUT, "<i", _F.STATUS, flags=False),
        2: _number(_ANALOG_OUTPUT, "<h", _F.STATUS, flags=False),
        3: _number(_ANALOG_OUTPUT, "<f", _F.STATUS, flags=False),
        4: _number(_ANALOG_OUTPUT, "<d", _F.STATUS, flags=False),
    },
    g42=_event_numbers(_ANALOG_OUTPUT),
    g43={
        1: _status_first("<i"),
        2: _status_first("<h"),
        3: _status_first("<i", _F.TIME),
        4: _status_first("<h", _F.TIME),
        5: _status_first("<f"),
        6: _status_first("<d"),
        7: _status_first("<f", _F.TIME),
        8: _status_first("<d", _F.TIME),
    },
    # Time and date: absolute, with an interval, the last recorded time, and
    # indexed with a long interval and its units.
    g50={
        1: _TIME_OBJECT,
        2: _Layout(None, opaque=10),
        3: _TIME_OBJECT,
        4: _Layout(None, opaque=11),
    },
    # The common time of occurrence, synchronized and unsynchronized.
    g51={1: _TIME_OBJECT, 2: _TIME_OBJECT},
    # The time delay, coarse and fine.
    g52={1: _Layout(None, opaque=2), 2: _Layout(None, opaque=2)},
    # Class data: a header with no objects.
    g60={1: _Layout(None), 2: _Layout(None), 3: _Layout(None), 4: _Layout(None)},
    # The internal indications, one bit each, indexed by bit (IEEE 1815-2012 A.28).
    g80={1: _Layout(_INTERNAL_INDICATION, packed_bits=1)},
)

#: Groups whose variation is the length of each object in octets: octet
#: strings and their events, which are points, and the virtual terminal
#: output and its events, which are not.
_OCTET_GROUPS = {
    110: _Layout(_OCTET_STRING, (_F.OCTETS,)),
    111: _Layout(_OCTET_STRING, (_F.OCTETS,)),
    112: _Layout(None, (_F.OCTETS,)),
    113: _Layout(None, (_F.OCTETS,)),
}

#: Groups whose objects are points. A header of any other group carries the
#: octets that follow it as ``data``.
_POINT_GROUPS = frozenset(
    {group for (group, _), layout in _LAYOUTS.items() if layout.kind is not None}
    | {group for group, layout in _OCTET_GROUPS.items() if layout.kind is not None}
)

_GROUP_COMMON_TIME = 51
_PATTERN_BLOCK = (12, 2)
_PATTERN_MASK = (12, 3)

#: The groups of a control object, whose points carry ``command`` true.
_COMMAND_GROUPS = frozenset({12, 41})

#: Requests whose object headers are followed by no objects: read, the four
#: freezes, enable and disable unsolicited, and assign class.
_HEADER_ONLY_FUNCTIONS = frozenset({1, 7, 8, 9, 10, 20, 21, 22})

#: Freeze at time and its no-acknowledgment form carry a time-and-interval
#: object (group 50) and then headers that name the points to freeze.
_FREEZE_AT_TIME_FUNCTIONS = frozenset({11, 12})
_GROUP_TIME = 50

#: Octets of the start and stop for range specifier codes 0 to 5: indices for
#: 0 to 2, virtual addresses for 3 to 5.
_START_STOP_OCTETS = {0: 1, 1: 2, 2: 4, 3: 1, 4: 2, 5: 4}
#: Octets of the count for range specifier codes 7, 8, 9 and 11.
_COUNT_OCTETS = {7: 1, 8: 2, 9: 4, 11: 1}
#: Range specifier code 6: no range field, all objects.
_ALL_OBJECTS = 6
#: Octets of an index prefix (prefix codes 1 to 3) and of an object size
#: prefix (codes 4 to 6). Code 0 is no prefix; code 7 is reserved.
_INDEX_PREFIX_OCTETS = {1: 1, 2: 2, 3: 4}
_SIZE_PREFIX_OCTETS = {4: 1, 5: 2, 6: 4}
_RESERVED_PREFIX = 7

#: The keys of a point, in the order a body lists them.
_POINT_KEYS = (
    "type",
    "group",
    "variation",
    "index",
    "command",
    "value",
    "non_finite",
    "flags",
    "time",
    "op_type",
    "trip_close",
    "clear",
    "queue",
    "count",
    "on_time",
    "off_time",
    "status",
)


# ------------------------------------------------------------ reading a fragment


class _Rejected(Exception):
    """The fragment cannot be described. Carries the ``apdu_rejected`` reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _number_value(raw: float | int) -> tuple[float | int | None, str | None]:
    """Return a value for the body and its ``non_finite`` name, which is None when finite."""
    if isinstance(raw, float) and not math.isfinite(raw):
        if math.isnan(raw):
            return None, "nan"
        return None, "inf" if raw > 0 else "-inf"
    return raw, None


def _control_fields(data: bytes, offset: int) -> dict[str, Any]:
    """Return a CROB's control code fields, count, on time and off time."""
    code, count, on_time, off_time = _CONTROL.unpack_from(data, offset)
    return {
        "op_type": code & 0x0F,
        "trip_close": code >> 6,
        "clear": bool(code & 0x20),
        "queue": bool(code & 0x10),
        "count": count,
        "on_time": on_time,
        "off_time": off_time,
    }


class _Walk:
    """Read the object headers and objects of one fragment, after its header."""

    def __init__(self, data: bytes, *, direction: Direction, function: int) -> None:
        self.data = data
        self.offset = 0
        self.direction = direction
        self.function = function
        self.objects: list[dict[str, Any]] = []
        self.points: list[dict[str, Any]] = []
        #: The common time of occurrence that relative-time objects count from.
        self.common_time: int | None = None
        #: The fields of the last pattern control block, for the mask after it.
        self.pattern: dict[str, Any] | None = None

    def run(self) -> None:
        while self.offset < len(self.data):
            self._header()

    # ----------------------------------------------------------- primitives

    def _take(self, size: int) -> bytes:
        """Return the next ``size`` octets of a header. A header cut short is malformed."""
        if self.offset + size > len(self.data):
            raise _Rejected(REJECTED_MALFORMED)
        taken = self.data[self.offset : self.offset + size]
        self.offset += size
        return taken

    def _uint(self, size: int) -> int:
        return int.from_bytes(self._take(size), "little")

    def _need(self, size: int, unit: int) -> None:
        """Check that ``size`` octets of objects follow, in whole objects of ``unit`` octets.

        Data that ends on an object boundary, with fewer objects than the
        header declares, disagrees with the header's range or count. Data that
        ends inside an object is cut short.
        """
        left = len(self.data) - self.offset
        if left < size:
            whole = unit > 0 and left % unit == 0
            raise _Rejected(REJECTED_POINT_COUNT if whole else REJECTED_MALFORMED)

    def _carries_objects(self, group: int) -> bool:
        """Return whether objects follow a header of this group in this fragment."""
        if self.direction is Direction.RESPONSE:
            return True
        if self.function in _HEADER_ONLY_FUNCTIONS:
            return False
        if self.function in _FREEZE_AT_TIME_FUNCTIONS:
            return group == _GROUP_TIME
        return True

    # ----------------------------------------------------------- headers

    def _header(self) -> None:
        if len(self.objects) >= MAX_OBJECTS:
            raise _Rejected(REJECTED_TOO_LARGE)
        group, variation, qualifier = self._take(3)
        prefix = (qualifier >> 4) & 0x07
        code = qualifier & 0x0F
        header: dict[str, Any] = {"group": group, "variation": variation, "qualifier": qualifier}
        start: int | None = None
        number: int
        if code in _START_STOP_OCTETS:
            width = _START_STOP_OCTETS[code]
            start, stop = self._uint(width), self._uint(width)
            header["start"], header["stop"] = start, stop
            if stop < start:
                raise _Rejected(REJECTED_MALFORMED)
            number = stop - start + 1
        elif code in _COUNT_OCTETS:
            number = self._uint(_COUNT_OCTETS[code])
            header["count"] = number
        elif code == _ALL_OBJECTS:
            number = 0
        else:
            raise _Rejected(REJECTED_MALFORMED)
        self.objects.append(header)

        first = self.offset
        if prefix in _SIZE_PREFIX_OCTETS or self._carries_objects(group):
            self._objects(group, variation, prefix, start, number)
        elif prefix in _INDEX_PREFIX_OCTETS:
            # A request that names points by index: the indices and no objects.
            width = _INDEX_PREFIX_OCTETS[prefix]
            self._need(number * width, width)
            self.offset += number * width
        elif prefix != 0:
            raise _Rejected(REJECTED_MALFORMED)
        if group not in _POINT_GROUPS and self.offset > first:
            # A time write, a file command or a device attribute keeps what it
            # sets: the octets after the header, prefixes included.
            if self.offset - first > MAX_DATA_OCTETS:
                raise _Rejected(REJECTED_TOO_LARGE)
            header["data"] = self.data[first : self.offset].hex()

    def _layout(self, group: int, variation: int) -> _Layout:
        if group in _OCTET_GROUPS:
            if variation == 0:
                raise _Rejected(REJECTED_MALFORMED)
            return _OCTET_GROUPS[group]
        layout = _LAYOUTS.get((group, variation))
        if layout is None:
            raise _Rejected(REJECTED_MALFORMED)
        return layout

    def _objects(
        self, group: int, variation: int, prefix: int, start: int | None, number: int
    ) -> None:
        """Read the objects under one header."""
        if prefix == _RESERVED_PREFIX:
            raise _Rejected(REJECTED_MALFORMED)
        known = (group, variation) in _LAYOUTS or group in _OCTET_GROUPS
        if prefix in _SIZE_PREFIX_OCTETS and not known:
            # An object this module does not read, such as a file or an
            # authentication object, can still be walked past by its size.
            self._sized(prefix, number)
            return
        layout = self._layout(group, variation)
        if layout.packed_bits:
            self._packed(group, variation, layout, prefix, start, number)
            return

        size = layout.size(variation)
        index_octets = _INDEX_PREFIX_OCTETS.get(prefix, 0)
        size_octets = _SIZE_PREFIX_OCTETS.get(prefix, 0)
        unit = index_octets + size_octets + size
        self._need(number * unit, unit)
        if layout.kind is None and group != _GROUP_COMMON_TIME:
            self.offset += number * unit
            return
        for position in range(number):
            index: int | None = None
            if index_octets:
                index = self._uint(index_octets)
            elif start is not None:
                index = start + position
            if size_octets and self._uint(size_octets) != size:
                raise _Rejected(REJECTED_MALFORMED)
            data = self._take(size)
            self._object(group, variation, layout, index, data)

    def _sized(self, prefix: int, number: int) -> None:
        """Walk past objects that each carry their own size and are not points."""
        width = _SIZE_PREFIX_OCTETS[prefix]
        for _ in range(number):
            self._need(width, width)
            size = self._uint(width)
            self._need(size, 0)
            self.offset += size

    def _packed(
        self,
        group: int,
        variation: int,
        layout: _Layout,
        prefix: int,
        start: int | None,
        number: int,
    ) -> None:
        """Read objects packed one or two bits each, the lowest index in the lowest bits."""
        if prefix != 0:
            raise _Rejected(REJECTED_MALFORMED)
        bits = layout.packed_bits
        octets = (number * bits + 7) // 8
        self._need(octets, 1)
        data = self._take(octets)
        if layout.kind is None:
            return
        if start is None:
            # A point packed with no range has no index to name it by.
            raise _Rejected(REJECTED_MALFORMED)
        mask = (1 << bits) - 1
        if (group, variation) == _PATTERN_MASK:
            pattern, self.pattern = self.pattern, None
            if pattern is None:
                return
            for position in range(number):
                if data[position // 8] >> (position % 8) & 1:
                    self._add(
                        {
                            "type": layout.kind,
                            "group": group,
                            "variation": _PATTERN_BLOCK[1],
                            "index": start + position,
                            "command": True,
                            **pattern,
                        }
                    )
            return
        for position in range(number):
            bit = position * bits
            value = data[bit // 8] >> (bit % 8) & mask
            self._add(
                {
                    "type": layout.kind,
                    "group": group,
                    "variation": variation,
                    "index": start + position,
                    "command": False,
                    "value": value,
                }
            )

    # ----------------------------------------------------------- objects

    def _object(
        self, group: int, variation: int, layout: _Layout, index: int | None, data: bytes
    ) -> None:
        """Read one object: a point, a common time of occurrence or a pattern control block."""
        fields: dict[str, Any] = {}
        offset = 0
        for each in layout.fields:
            if each is _F.FLAGS_STATE:
                fields["value"] = data[offset] >> 7
                fields["flags"] = data[offset]
            elif each is _F.FLAGS_DOUBLE:
                fields["value"] = data[offset] >> 6
                fields["flags"] = data[offset]
            elif each is _F.FLAGS:
                fields["flags"] = data[offset]
            elif each is _F.STATUS:
                fields["status"] = data[offset]
            elif each is _F.STATE_STATUS:
                fields["value"] = data[offset] >> 7
                fields["status"] = data[offset] & 0x7F
            elif each is _F.VALUE:
                assert layout.number is not None
                (raw,) = struct.unpack_from(layout.number, data, offset)
                value, non_finite = _number_value(raw)
                fields["value"] = value
                if non_finite is not None:
                    fields["non_finite"] = non_finite
            elif each is _F.TIME:
                fields["time"] = int.from_bytes(data[offset : offset + 6], "little")
            elif each is _F.RELATIVE_TIME:
                relative = int.from_bytes(data[offset : offset + 2], "little")
                if self.common_time is not None and self.common_time + relative <= _MAX_TIME:
                    fields["time"] = self.common_time + relative
            elif each is _F.CONTROL:
                fields.update(_control_fields(data, offset))
            elif each is _F.OCTETS:
                fields["value"] = data[offset : offset + variation].hex()
            offset += layout.width(each, variation)

        if group == _GROUP_COMMON_TIME:
            self.common_time = fields["time"]
            return
        if (group, variation) == _PATTERN_BLOCK:
            self.pattern = fields
            return
        if index is None:
            # A point sent under a count, with no index prefix, cannot be named.
            raise _Rejected(REJECTED_MALFORMED)
        self._add(
            {
                "type": layout.kind,
                "group": group,
                "variation": variation,
                "index": index,
                "command": group in _COMMAND_GROUPS,
                **fields,
            }
        )

    def _add(self, point: dict[str, Any]) -> None:
        if len(self.points) >= MAX_POINTS:
            raise _Rejected(REJECTED_TOO_LARGE)
        self.points.append({key: point[key] for key in _POINT_KEYS if key in point})


# ------------------------------------------------------------------- bodies


def _iin(first: int, second: int) -> list[str]:
    """Return the names of the internal indication bits set, in bit order."""
    octets = first | second << 8
    return [name for bit, name in enumerate(IIN_BITS) if octets >> bit & 1]


def _ip(host: str) -> str | None:
    """Return a host as an IP address in its canonical form, or None when it is not one.

    An IPv6 zone (``%eth0``) is dropped: it names an interface on the host
    that saw the connection, not part of the address.
    """
    try:
        return str(ipaddress.ip_address(host.split("%", 1)[0]))
    except ValueError:
        return None


def _put_endpoint(body: dict[str, Any], end: str, endpoint: Endpoint | None) -> None:
    if endpoint is None:
        return
    address = _ip(endpoint.host)
    if address is not None:
        body[f"{end}_ip"] = address
    if 0 <= endpoint.port <= 0xFFFF:
        body[f"{end}_port"] = endpoint.port


def fragment_body(
    fragment: bytes,
    *,
    direction: Direction | str,
    source: int,
    destination: int,
    sender: Endpoint | None = None,
    receiver: Endpoint | None = None,
) -> dict[str, Any]:
    """Return the body for one application fragment, request or response.

    Args:
        fragment: The application fragment, from the application control octet
            to the last object.
        direction: ``"request"`` for a fragment the master sent,
            ``"response"`` for one the outstation sent, an unsolicited response
            included. A response is read with its internal indications.
        source: The link address of the station that sent the fragment.
        destination: The link address it was sent to.
        sender: The sender's end of the connection, for ``source_ip`` and
            ``source_port``. Left out of the body when None.
        receiver: The receiver's end, for ``destination_ip`` and
            ``destination_port``.

    Raises:
        ValueError: If the fragment is shorter than a control octet and a
            function code, or ``direction`` names neither direction.
    """
    direction = Direction(direction)
    if len(fragment) < 2:
        raise ValueError("a fragment holds at least an application control octet and a function")
    function = fragment[1]
    body: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "source_address": source,
        "destination_address": destination,
        "function_code": function,
        "prm": _PRIMARY,
        "direction": direction.value,
        "unsolicited": bool(fragment[0] & UNS_MASK),
    }
    _put_endpoint(body, "source", sender)
    _put_endpoint(body, "destination", receiver)
    header = 2
    if direction is Direction.RESPONSE:
        if len(fragment) < 4:
            body.update(objects=[], points=[], apdu_rejected=REJECTED_MALFORMED)
            return body
        body["iin"] = _iin(fragment[2], fragment[3])
        header = 4
    walk = _Walk(bytes(fragment[header:]), direction=direction, function=function)
    try:
        walk.run()
    except _Rejected as rejected:
        # Values read from object data that cannot be trusted cannot be
        # trusted either, so a rejected fragment reports none.
        body.update(objects=[], points=[], apdu_rejected=rejected.reason)
        return body
    body["objects"] = walk.objects
    body["points"] = walk.points
    return body


def record_bodies(
    record: RequestRecord, *, outstation: Endpoint | None = None
) -> list[dict[str, Any]]:
    """Return the bodies of one request record: the request, then the response.

    An unsolicited response gives one body, and a request that was not
    answered gives the request alone. ``outstation`` is this outstation's end
    of the connection, for a record that does not carry one in ``local``.
    """
    master_end = record.peer
    outstation_end = outstation or record.local
    if record.unsolicited:
        assert record.response is not None
        return [
            fragment_body(
                record.response,
                direction=Direction.RESPONSE,
                source=record.source,
                destination=record.destination,
                sender=outstation_end,
                receiver=master_end,
            )
        ]
    bodies = [
        fragment_body(
            record.request,
            direction=Direction.REQUEST,
            source=record.source,
            destination=record.destination,
            sender=master_end,
            receiver=outstation_end,
        )
    ]
    if record.response is not None:
        bodies.append(
            fragment_body(
                record.response,
                direction=Direction.RESPONSE,
                source=record.destination,
                destination=record.source,
                sender=outstation_end,
                receiver=master_end,
            )
        )
    return bodies


def _fragment(response: Response) -> bytes:
    return build_response(
        control=response.control, iin=response.iin, body=response.body, function=response.function
    )


def exchange_bodies(
    exchange: Exchange,
    *,
    master_address: int,
    outstation_address: int,
    master: Endpoint | None = None,
    outstation: Endpoint | None = None,
) -> list[dict[str, Any]]:
    """Return the bodies of one master exchange: the request, then each response fragment.

    ``master`` and ``outstation`` are the two ends of the master's connection.
    The request is described once, however many times it was sent again.
    """
    destination = outstation_address if exchange.broadcast is None else int(exchange.broadcast)
    bodies = [
        fragment_body(
            exchange.request,
            direction=Direction.REQUEST,
            source=master_address,
            destination=destination,
            sender=master,
            receiver=outstation,
        )
    ]
    bodies.extend(
        fragment_body(
            _fragment(response),
            direction=Direction.RESPONSE,
            source=outstation_address,
            destination=master_address,
            sender=outstation,
            receiver=master,
        )
        for response in exchange.fragments
    )
    return bodies


def unsolicited_body(
    unsolicited: Unsolicited,
    *,
    master_address: int,
    outstation_address: int,
    master: Endpoint | None = None,
    outstation: Endpoint | None = None,
) -> dict[str, Any]:
    """Return the body of one unsolicited response the master received."""
    return fragment_body(
        _fragment(unsolicited.response),
        direction=Direction.RESPONSE,
        source=outstation_address,
        destination=master_address,
        sender=outstation,
        receiver=master,
    )


# ------------------------------------------------------------------ envelopes


def envelope(
    body: dict[str, Any],
    *,
    outstation: Endpoint,
    at: float,
    forwarder_id: str = "",
    capture_origin: str = CAPTURE_ORIGIN_LIVE,
) -> ProtocolMessage:
    """Return the envelope that carries one body.

    The envelope names the outstation: ``source`` is its address and port and
    ``client_id`` its link address, the source address of a response and the
    destination address of a request. ``direction`` is ``upstream`` for every
    fragment, whichever end sent it.

    Args:
        body: A body from :func:`fragment_body` or the functions built on it.
        outstation: The outstation's address and port.
        at: When the fragment was sent, in seconds since the Unix epoch.
        forwarder_id: Names the system publishing the message.
        capture_origin: Where the traffic was captured; ``"live"`` for
            traffic seen as it happened.
    """
    if body.get("direction") == Direction.RESPONSE:
        link_address = body.get("source_address")
    else:
        link_address = body.get("destination_address")
    return ProtocolMessage(
        protocol=Protocol.DNP3,
        direction=WireDirection.UPSTREAM,
        client_id=str(link_address if link_address is not None else 0),
        payload=body,
        source=NetworkEndpoint(ip=outstation.host, port=outstation.port),
        forwarder_id=forwarder_id,
        protocol_data=ProtocolMetadata(
            extra={
                CAPTURE_ORIGIN_KEY: capture_origin.strip() or CAPTURE_ORIGIN_LIVE,
                CLIENT_ID_SOURCE_KEY: "",
            }
        ),
        timestamp=datetime.fromtimestamp(at, UTC).isoformat(),
    )


def _known(outstation: Endpoint | None) -> Endpoint:
    if outstation is None:
        raise ValueError(
            "the outstation's address is not known; give it as outstation= to build an envelope"
        )
    return outstation


def record_messages(
    record: RequestRecord,
    *,
    outstation: Endpoint | None = None,
    forwarder_id: str = "",
    capture_origin: str = CAPTURE_ORIGIN_LIVE,
) -> list[ProtocolMessage]:
    """Return the envelopes of one request record, stamped with the record's time.

    Raises:
        ValueError: If the record has no ``local`` address and no
            ``outstation`` is given.
    """
    endpoint = _known(outstation or record.local)
    return [
        envelope(
            body,
            outstation=endpoint,
            at=record.timestamp,
            forwarder_id=forwarder_id,
            capture_origin=capture_origin,
        )
        for body in record_bodies(record, outstation=endpoint)
    ]


def exchange_messages(
    exchange: Exchange,
    *,
    master_address: int,
    outstation_address: int,
    outstation: Endpoint,
    master: Endpoint | None = None,
    at: float | None = None,
    forwarder_id: str = "",
    capture_origin: str = CAPTURE_ORIGIN_LIVE,
) -> list[ProtocolMessage]:
    """Return the envelopes of one master exchange.

    ``at`` is when the exchange ended, now if not given. The responses are
    stamped with it, and the request with the time it was first sent.
    """
    ended = time.time() if at is None else at
    bodies = exchange_bodies(
        exchange,
        master_address=master_address,
        outstation_address=outstation_address,
        master=master,
        outstation=outstation,
    )
    return [
        envelope(
            body,
            outstation=outstation,
            at=ended - exchange.elapsed if number == 0 else ended,
            forwarder_id=forwarder_id,
            capture_origin=capture_origin,
        )
        for number, body in enumerate(bodies)
    ]


def unsolicited_message(
    unsolicited: Unsolicited,
    *,
    master_address: int,
    outstation_address: int,
    outstation: Endpoint,
    master: Endpoint | None = None,
    at: float | None = None,
    forwarder_id: str = "",
    capture_origin: str = CAPTURE_ORIGIN_LIVE,
) -> ProtocolMessage:
    """Return the envelope of one unsolicited response, stamped ``at`` or now."""
    body = unsolicited_body(
        unsolicited,
        master_address=master_address,
        outstation_address=outstation_address,
        master=master,
        outstation=outstation,
    )
    return envelope(
        body,
        outstation=outstation,
        at=time.time() if at is None else at,
        forwarder_id=forwarder_id,
        capture_origin=capture_origin,
    )


__all__ = [
    "CAPTURE_ORIGIN_KEY",
    "CAPTURE_ORIGIN_LIVE",
    "CLIENT_ID_SOURCE_KEY",
    "IIN_BITS",
    "MAX_DATA_OCTETS",
    "MAX_OBJECTS",
    "MAX_POINTS",
    "REJECTED_MALFORMED",
    "REJECTED_POINT_COUNT",
    "REJECTED_TOO_LARGE",
    "SCHEMA_ID",
    "SCHEMA_VERSION",
    "Direction",
    "envelope",
    "exchange_bodies",
    "exchange_messages",
    "fragment_body",
    "load_schema",
    "record_bodies",
    "record_messages",
    "unsolicited_body",
    "unsolicited_message",
]
