"""Device attributes, object group 0: encode, decode, read and write.

Every attribute is an object of its own variation that carries its data type
code, a length octet and a value (IEEE 1815-2012 5.5.4). The data type codes
are the ones of the consolidated table in TB2017-007a. This module knows those
layouts and the rules for reading and writing them, and nothing about where an
outstation gets a value from: the owner of a :class:`DeviceAttributes` store
decides that, and the session answers reads and writes from it.

Only attribute set 0, the one the DNP Users Group defines, exists here
(IEEE 1815-2012 5.5.1). A read of any other set is refused.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import importlib.metadata
import struct
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, fields
from enum import IntEnum

from py1815.application import (
    RESPONSE_HEADER_SIZE,
    ObjectHeader,
    QualifierCode,
    object_header,
    parse_header,
)

GROUP_DEVICE_ATTRIBUTES = 0

#: The only attribute set this library has: the one the DNP Users Group
#: defines (IEEE 1815-2012 5.5.1).
STANDARD_SET = 0

#: The most octets of text a configured or written string may hold. Each
#: attribute travels in one block of a response, and this keeps the largest
#: such block well inside the smallest fragment an outstation is configured
#: with.
MAX_TEXT = 128

#: Bit 0 of an attribute's property octet in the list of variations: set when a
#: master may write the attribute (IEEE 1815-2012 A.1.44).
_WRITABLE = 0x01


class DataType(IntEnum):
    """The attribute data type codes of Table 11-4 as revised by TB2017-007a."""

    NONE = 0
    VSTR = 1
    UINT = 2
    INT = 3
    FLT = 4
    OSTR = 5
    BSTR = 6
    DNP3TIME = 7
    UNCD = 8
    U8BS8LIST = 254
    U8BS8EXLIST = 255


class Variation(IntEnum):
    """The attribute variations of set 0 that the standard requires at Subset Level 4."""

    SECURE_AUTHENTICATION_VERSION = 209
    SECURITY_STATISTICS_PER_ASSOCIATION = 210
    USER_SPECIFIC_ATTRIBUTE_SETS = 211
    MASTER_DATA_SET_PROTOTYPES = 212
    OUTSTATION_DATA_SET_PROTOTYPES = 213
    MASTER_DATA_SETS = 214
    OUTSTATION_DATA_SETS = 215
    MAXIMUM_BINARY_OUTPUT_OBJECTS = 216
    LOCAL_TIMING_ACCURACY = 217
    DURATION_OF_TIMING_ACCURACY = 218
    ANALOG_OUTPUT_EVENTS = 219
    MAXIMUM_ANALOG_OUTPUT_INDEX = 220
    ANALOG_OUTPUT_COUNT = 221
    BINARY_OUTPUT_EVENTS = 222
    MAXIMUM_BINARY_OUTPUT_INDEX = 223
    BINARY_OUTPUT_COUNT = 224
    FROZEN_COUNTER_EVENTS = 225
    FROZEN_COUNTERS = 226
    COUNTER_EVENTS = 227
    MAXIMUM_COUNTER_INDEX = 228
    COUNTER_COUNT = 229
    FROZEN_ANALOG_INPUTS = 230
    ANALOG_INPUT_EVENTS = 231
    MAXIMUM_ANALOG_INPUT_INDEX = 232
    ANALOG_INPUT_COUNT = 233
    DOUBLE_BIT_INPUT_EVENTS = 234
    MAXIMUM_DOUBLE_BIT_INPUT_INDEX = 235
    DOUBLE_BIT_INPUT_COUNT = 236
    BINARY_INPUT_EVENTS = 237
    MAXIMUM_BINARY_INPUT_INDEX = 238
    BINARY_INPUT_COUNT = 239
    MAXIMUM_TRANSMIT_FRAGMENT_SIZE = 240
    MAXIMUM_RECEIVE_FRAGMENT_SIZE = 241
    SOFTWARE_VERSION = 242
    HARDWARE_VERSION = 243
    LOCATION_NAME = 245
    DEVICE_ID = 246
    DEVICE_NAME = 247
    SERIAL_NUMBER = 248
    SUBSET_AND_CONFORMANCE = 249
    PRODUCT_NAME_AND_MODEL = 250
    MANUFACTURER_NAME = 252
    #: Only in a request: every attribute of a set in one response.
    ALL_ATTRIBUTES = 254
    #: The list of the variations a set holds, and which of them can be written.
    LIST_OF_VARIATIONS = 255


#: The variations a request may name that are never an attribute of their own.
_SPECIAL = frozenset({Variation.ALL_ATTRIBUTES, Variation.LIST_OF_VARIATIONS})

#: The attributes a session holds for itself, because their values are the
#: session's: how many binary outputs a request may carry, and the two fragment
#: sizes. A store never holds them.
SESSION_VARIATIONS = (
    Variation.MAXIMUM_BINARY_OUTPUT_OBJECTS,
    Variation.MAXIMUM_TRANSMIT_FRAGMENT_SIZE,
    Variation.MAXIMUM_RECEIVE_FRAGMENT_SIZE,
)


def describe(variation: int) -> str:
    """Return the variation's name as a sentence, such as ``Counter count``."""
    try:
        return Variation(variation).name.replace("_", " ").capitalize()
    except ValueError:
        return f"Device attribute {variation}"


class UnknownVariation(LookupError):
    """The attribute variation is not one this outstation has, or cannot be written."""


class BadParameter(ValueError):
    """The request names a set, a qualifier or a value that is not acceptable."""


@dataclass(frozen=True)
class Attribute:
    """One attribute: its data type code and the octets of its value."""

    code: int
    data: bytes

    def __post_init__(self) -> None:
        extended = self.code == DataType.U8BS8EXLIST
        if extended and not 256 <= len(self.data) <= 511:
            raise ValueError("an extended list holds 256 to 511 octets")
        if not extended and len(self.data) > 255:
            raise ValueError("an attribute value holds at most 255 octets")

    @classmethod
    def text(cls, value: str) -> Attribute:
        """Return a visible-ASCII string, data type VSTR.

        Raises:
            ValueError: The string is longer than :data:`MAX_TEXT` or holds a
                character that is not a visible ASCII character or a space.
        """
        octets = value.encode("ascii") if value.isascii() else b""
        if (
            not value.isascii()
            or len(octets) > MAX_TEXT
            or any(not 0x20 <= octet <= 0x7E for octet in octets)
        ):
            raise ValueError(
                f"text of at most {MAX_TEXT} visible ASCII characters is required, not {value!r}"
            )
        return cls(DataType.VSTR, octets)

    @classmethod
    def unsigned(cls, value: int) -> Attribute:
        """Return an unsigned integer in the fewest of 1, 2, 4 or 8 octets."""
        if value < 0 or value >= 2**64:
            raise ValueError(f"{value} is not an unsigned integer of 64 bits or fewer")
        size = next(size for size in (1, 2, 4, 8) if value < 1 << (8 * size))
        return cls(DataType.UINT, value.to_bytes(size, "little"))

    @classmethod
    def flag(cls, value: bool) -> Attribute:
        """Return a Boolean: an INT of one octet that is 1 for true and 0 for false."""
        return cls(DataType.INT, bytes([1 if value else 0]))

    @classmethod
    def variation_list(cls, properties: Mapping[int, bool]) -> Attribute:
        """Return the list of variations, each with its writable bit (A.1.44).

        Data type U8BS8LIST while the list fits the length octet, and
        U8BS8EXLIST once it does not.
        """
        data = b"".join(
            bytes([variation, _WRITABLE if writable else 0])
            for variation, writable in sorted(properties.items())
        )
        return cls(DataType.U8BS8LIST if len(data) <= 255 else DataType.U8BS8EXLIST, data)

    def encode(self) -> bytes:
        """Return the data type code, the length octet and the value."""
        length = len(self.data) - 256 if self.code == DataType.U8BS8EXLIST else len(self.data)
        return bytes([self.code, length]) + self.data

    @property
    def value(self) -> int | float | str | bytes | tuple[tuple[int, bool], ...] | None:
        """The value as Python holds it, or None where the data type or length does not decode.

        A string, an integer, a float, the pairs of a list of variations as
        ``(variation, writable)``, or the octets of an octet string. A Boolean
        is an integer, as the standard defines it.
        """
        code, data = self.code, self.data
        if code in (DataType.VSTR, DataType.UNCD):
            return data.decode("ascii" if code == DataType.VSTR else "utf-8", errors="replace")
        if code == DataType.OSTR:
            return bytes(data)
        if code in (DataType.U8BS8LIST, DataType.U8BS8EXLIST) and len(data) % 2 == 0:
            return tuple((data[i], bool(data[i + 1] & _WRITABLE)) for i in range(0, len(data), 2))
        if code == DataType.FLT and len(data) in (4, 8):
            # A float is 4 or 8 octets and no other size (TB2017-007a).
            number: float = struct.unpack("<f" if len(data) == 4 else "<d", data)[0]
            return number
        if code in (DataType.UINT, DataType.INT, DataType.BSTR, DataType.DNP3TIME) and data:
            return int.from_bytes(data, "little", signed=code == DataType.INT)
        return None


def parse_attribute(data: bytes, offset: int = 0) -> tuple[Attribute, int]:
    """Read one attribute at ``offset`` and return it with the offset after it.

    Raises:
        ValueError: The octets end before the length the attribute states.
    """
    if offset + 2 > len(data):
        raise ValueError("an attribute is cut short before its length")
    code, length = data[offset], data[offset + 1]
    if code == DataType.U8BS8EXLIST:
        length += 256
    end = offset + 2 + length
    if end > len(data):
        raise ValueError(f"an attribute of {length} octets is cut short")
    return Attribute(code, bytes(data[offset + 2 : end])), end


def attribute_block(variation: int, attribute: Attribute, *, index: int = STANDARD_SET) -> bytes:
    """Return one attribute as a response block: its header, then its octets.

    The list of variations goes under qualifier 0x17 with a count of 1, as
    IEEE 1815-2012 5.5.6.2 requires. Every other attribute goes under a range
    that holds the index only, as the example in 5.5.5 does.
    """
    if variation == Variation.LIST_OF_VARIATIONS:
        header = bytes(
            [GROUP_DEVICE_ATTRIBUTES, variation, QualifierCode.UINT8_COUNT_UINT8_INDEX, 1, index]
        )
    else:
        header = object_header(GROUP_DEVICE_ATTRIBUTES, variation, start=index, stop=index)
    return header + attribute.encode()


def _sets(header: ObjectHeader) -> tuple[int, ...]:
    """The attribute sets a read header names, or why it names none."""
    if header.qualifier is QualifierCode.ALL_OBJECTS:
        if header.variation not in _SPECIAL:
            raise BadParameter(
                f"variation {header.variation} is read by set number, not with qualifier 0x06"
            )
        return (STANDARD_SET,)
    if (
        header.qualifier in (QualifierCode.UINT8_START_STOP, QualifierCode.UINT16_START_STOP)
        and header.start is not None
        and header.stop is not None
    ):
        named = tuple(range(header.start, header.stop + 1))
        if named != (STANDARD_SET,):
            raise BadParameter(f"there is no attribute set {header.start}..{header.stop}")
        return named
    raise BadParameter(f"qualifier 0x{int(header.qualifier):02X} does not select an attribute set")


def read_blocks(
    headers: Sequence[ObjectHeader], view: Mapping[int, Attribute], writable: Collection[int]
) -> list[bytes]:
    """Return the response blocks for a read of group 0, one attribute to a block.

    Args:
        headers: The read's object headers, each of group 0.
        view: Every attribute of set 0 that the outstation has, by variation.
            It holds neither variation 254 nor variation 255.
        writable: The variations in ``view`` a master may write.

    Variation 254 returns every attribute in ascending order, and never itself
    or the list (TB2016-003b note a to Table 12-1). A set that does not exist is
    a parameter error; an attribute the outstation lacks is an unknown object.

    Raises:
        UnknownVariation: A header names a variation that is not in ``view``.
        BadParameter: A header names a set that does not exist, or a qualifier
            that selects none.
    """
    blocks: list[bytes] = []
    for header in headers:
        sets = _sets(header)
        if header.variation == Variation.ALL_ATTRIBUTES:
            blocks += [
                attribute_block(variation, view[variation], index=index)
                for index in sets
                for variation in sorted(view)
            ]
        elif header.variation == Variation.LIST_OF_VARIATIONS:
            listing = Attribute.variation_list({v: v in writable for v in view})
            blocks += [attribute_block(header.variation, listing, index=index) for index in sets]
        elif header.variation in view:
            blocks += [
                attribute_block(header.variation, view[header.variation], index=index)
                for index in sets
            ]
        else:
            raise UnknownVariation(f"attribute variation {header.variation} is not offered")
    return blocks


def parse_writes(first: ObjectHeader, body: bytes) -> list[tuple[int, Attribute]]:
    """Return every attribute a write request carries, as ``(variation, attribute)``.

    ``first`` and ``body`` are what :func:`~py1815.application.parse_request`
    gives for a write: the first object header, and the octets after it, which
    hold its object, then any further headers each followed by its object.

    Raises:
        UnknownVariation: A header names an object that is not an attribute.
        BadParameter: A header does not name set 0 under a range, or an object
            is cut short.
        py1815.application.RequestError: A header after the first cannot be read.
    """
    writes: list[tuple[int, Attribute]] = []
    header, offset = first, 0
    while True:
        if header.group != GROUP_DEVICE_ATTRIBUTES:
            raise UnknownVariation(f"group {header.group} cannot be written with an attribute")
        if (
            header.qualifier
            not in (QualifierCode.UINT8_START_STOP, QualifierCode.UINT16_START_STOP)
            or header.start != STANDARD_SET
            or header.stop != STANDARD_SET
        ):
            raise BadParameter("an attribute is written to set 0, with qualifier 0x00 or 0x01")
        try:
            attribute, offset = parse_attribute(body, offset)
        except ValueError as error:
            raise BadParameter(str(error)) from None
        writes.append((header.variation, attribute))
        if offset >= len(body):
            return writes
        header, offset = parse_header(body, offset)


@dataclass(frozen=True)
class DeviceInformation:  # pylint: disable=too-many-instance-attributes
    """What an outstation says about itself in its device attributes.

    Each text is at most :data:`MAX_TEXT` visible ASCII characters. The
    constructor raises ``ValueError``, naming the field, for one that is not.
    """

    #: Variation 252, the manufacturer's name.
    manufacturer: str = "Not stated"
    #: Variation 250, the product name and model.
    product: str = "py1815 DER outstation"
    #: Variation 242. Empty means this library's version.
    software_version: str = ""
    #: Variation 243.
    hardware_version: str = "Not applicable (software)"
    #: Variation 248.
    serial_number: str = ""
    #: Variation 245. A master may write it.
    location_name: str = ""
    #: Variation 246. A master may write it.
    device_id: str = ""
    #: Variation 247. A master may write it.
    device_name: str = ""
    #: Variation 217, in microseconds: the worst-case error of the time the
    #: outstation gives its events. The default is one second, a figure a host
    #: clock holds to without a time source the library can vouch for.
    timing_accuracy_us: int = 1_000_000

    def __post_init__(self) -> None:
        for each in fields(self):
            value = getattr(self, each.name)
            if each.name == "timing_accuracy_us":
                if isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFF:
                    raise ValueError(f"{each.name} must be a whole number from 0 to 4294967295")
                continue
            try:
                Attribute.text(value)
            except ValueError as error:
                raise ValueError(f"{each.name}: {error}") from None

    def software(self) -> str:
        """Return the stated software version, or this library's own."""
        return software_version(self.software_version)


def software_version(stated: str) -> str:
    """Return ``stated``, or this library's own version when it is empty."""
    if stated:
        return stated
    try:
        return f"py1815 {importlib.metadata.version('py1815')}"
    except importlib.metadata.PackageNotFoundError:
        return "py1815"


class DeviceAttributes:
    """The attributes of set 0 an outstation holds, and the ones a master may write.

    The store keeps the values the owner gave it and the ones a master has
    written since. A written value lasts as long as this object: it is not
    kept across a restart of the process, and :meth:`reset` returns every
    attribute to the value it was given. The standard does not require a
    written attribute to survive a reset of any kind (IEEE 1815-2012 5.5.8).

    The session adds the three attributes that are its own: the fragment sizes
    and the limit on binary outputs in a request. A store holds none of them.
    """

    def __init__(
        self,
        attributes: Mapping[int, Attribute],
        *,
        writable: Iterable[int] = (),
        min_fragment: int = RESPONSE_HEADER_SIZE,
    ) -> None:
        """
        Args:
            attributes: Every attribute of set 0 the owner supplies, by variation.
            writable: The variations a master may write. Each has to be in
                ``attributes`` and has to hold text.
            min_fragment: The smallest maximum transmit fragment size, in octets,
                a master may write to the session. The owner sets it to what
                its largest response block needs.
        """
        for variation in attributes:
            if variation in _SPECIAL or variation in SESSION_VARIATIONS:
                raise ValueError(f"attribute variation {variation} is not the store's to hold")
        self._initial = dict(attributes)
        self._values = dict(attributes)
        self._writable = frozenset(writable)
        for variation in self._writable:
            if variation not in self._initial:
                raise ValueError(f"writable attribute variation {variation} is not supplied")
            if self._initial[variation].code != DataType.VSTR:
                raise ValueError(f"writable attribute variation {variation} does not hold text")
        self.min_fragment = min_fragment

    @property
    def writable(self) -> frozenset[int]:
        """The variations a master may write."""
        return self._writable

    def snapshot(self) -> dict[int, Attribute]:
        """Return every attribute now, by variation."""
        return dict(self._values)

    def check(self, variation: int, attribute: Attribute) -> None:
        """Raise unless ``attribute`` may be written to ``variation``.

        Raises:
            UnknownVariation: The variation is not one a master may write.
            BadParameter: The data type is not the attribute's, or the text is
                not visible ASCII of at most :data:`MAX_TEXT` characters.
        """
        if variation not in self._writable:
            raise UnknownVariation(f"attribute variation {variation} cannot be written")
        if attribute.code != DataType.VSTR:
            raise BadParameter(f"attribute variation {variation} holds text")
        try:
            Attribute.text(attribute.data.decode("ascii", errors="replace"))
        except ValueError as error:
            raise BadParameter(str(error)) from None

    def write(self, writes: Sequence[tuple[int, Attribute]]) -> None:
        """Store every written attribute, or none of them when any is not acceptable."""
        for variation, attribute in writes:
            self.check(variation, attribute)
        for variation, attribute in writes:
            self._values[variation] = attribute

    def reset(self) -> None:
        """Return every attribute to the value it was given."""
        self._values = dict(self._initial)
