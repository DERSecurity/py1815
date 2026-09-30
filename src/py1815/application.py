"""The DNP3 application layer: request headers in, response headers out.

This module reads the shape of a request -- the application control octet, the
function code, and the object headers that say what is being asked for -- and
writes the shape of a response. It knows nothing about what any group means, how
wide a point is, or where the values come from. Object semantics belong to the
module that owns the point map; this one owns the envelope.

**Where it stops is deliberate.** A request that carries object data is parsed as
far as its first object header. Walking past that means knowing how many octets
each group and variation occupies, which is the point map's knowledge, and a
parser that guessed would misread the second header of every write. Requests that
carry no object data -- a READ, an unsolicited enable, an assign-class -- are
parsed in full, and those are the whole of the read path.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import IntEnum

#: Application control octet. Note the order against the transport function's
#: header, where FIN is 0x80 and FIR is 0x40: the two layers assign the same two
#: names to opposite bits, and reading one layer's constants into the other
#: produces a fragment that looks well formed and is inverted.
FIR_MASK = 0x80
FIN_MASK = 0x40
CON_MASK = 0x20
UNS_MASK = 0x10
SEQ_MASK = 0x0F

#: Application sequence numbers wrap at 16, unlike the transport function's 64.
SEQUENCE_MODULUS = SEQ_MASK + 1

#: Control octet and function code.
REQUEST_HEADER_SIZE = 2
#: Application control, function code and the two indication octets. What a
#: response costs before it carries anything.
RESPONSE_HEADER_SIZE = 4

#: Group 60 is the class-data group: one variation per class.
CLASS_GROUP = 60
CLASS_VARIATIONS = {1: 0, 2: 1, 3: 2, 4: 3}


class FunctionCode(IntEnum):
    """Function codes, including the ones this outstation refuses.

    The refused ones are named rather than left as integers because answering
    "function not supported" is a different thing from failing to recognize the
    request at all, and the log line should be able to say which.
    """

    CONFIRM = 0x00
    READ = 0x01
    WRITE = 0x02
    SELECT = 0x03
    OPERATE = 0x04
    DIRECT_OPERATE = 0x05
    DIRECT_OPERATE_NR = 0x06
    IMMED_FREEZE = 0x07
    IMMED_FREEZE_NR = 0x08
    FREEZE_CLEAR = 0x09
    FREEZE_CLEAR_NR = 0x0A
    FREEZE_AT_TIME = 0x0B
    FREEZE_AT_TIME_NR = 0x0C
    COLD_RESTART = 0x0D
    WARM_RESTART = 0x0E
    INITIALIZE_DATA = 0x0F
    INITIALIZE_APPLICATION = 0x10
    START_APPLICATION = 0x11
    STOP_APPLICATION = 0x12
    SAVE_CONFIGURATION = 0x13
    ENABLE_UNSOLICITED = 0x14
    DISABLE_UNSOLICITED = 0x15
    ASSIGN_CLASS = 0x16
    DELAY_MEASURE = 0x17
    RECORD_CURRENT_TIME = 0x18
    OPEN_FILE = 0x19
    CLOSE_FILE = 0x1A
    DELETE_FILE = 0x1B
    GET_FILE_INFO = 0x1C
    AUTHENTICATE_FILE = 0x1D
    ABORT_FILE = 0x1E
    ACTIVATE_CONFIG = 0x1F
    AUTH_REQUEST = 0x20
    AUTH_REQUEST_NO_ACK = 0x21
    RESPONSE = 0x81
    UNSOLICITED_RESPONSE = 0x82
    AUTH_RESPONSE = 0x83


#: Requests whose object headers are self-delimiting: the header says what to
#: read or which classes to act on, and no object data follows it. Every other
#: function carries objects whose widths this module does not know.
HEADER_ONLY_FUNCTIONS = frozenset(
    {
        FunctionCode.READ,
        FunctionCode.ENABLE_UNSOLICITED,
        FunctionCode.DISABLE_UNSOLICITED,
        FunctionCode.ASSIGN_CLASS,
    }
)

#: Functions whose object headers this module parses. A recognized function
#: outside this set is returned with its payload untouched, exactly as an
#: unrecognized one is: a file-transfer or secure-authentication request carries
#: qualifiers this module does not accept, and raising on them would answer
#: "parameter error" to a request whose real answer is "function not supported".
#: Which of those a master hears is the difference between it retrying with a
#: different qualifier and it stopping.
_PARSED_FUNCTIONS = HEADER_ONLY_FUNCTIONS | {
    FunctionCode.WRITE,
    FunctionCode.SELECT,
    FunctionCode.OPERATE,
    FunctionCode.DIRECT_OPERATE,
    FunctionCode.DIRECT_OPERATE_NR,
}


class QualifierCode(IntEnum):
    """Qualifiers this outstation accepts in a request.

    The high nibble is the index or size prefix and the low nibble is the range
    specifier, which is why these values are not contiguous.
    """

    UINT8_START_STOP = 0x00
    UINT16_START_STOP = 0x01
    ALL_OBJECTS = 0x06
    UINT8_COUNT = 0x07
    UINT16_COUNT = 0x08
    UINT8_COUNT_UINT8_INDEX = 0x17
    UINT16_COUNT_UINT16_INDEX = 0x28


#: Index widths for the qualifiers that prefix each object with one.
_INDEX_WIDTHS = {
    QualifierCode.UINT8_COUNT_UINT8_INDEX: 1,
    QualifierCode.UINT16_COUNT_UINT16_INDEX: 2,
}


class IINBit(IntEnum):
    """Internal indication bits, by the octet each lives in."""

    BROADCAST = 0x01
    CLASS_1_EVENTS = 0x02
    CLASS_2_EVENTS = 0x04
    CLASS_3_EVENTS = 0x08
    NEED_TIME = 0x10
    LOCAL_CONTROL = 0x20
    DEVICE_TROUBLE = 0x40
    DEVICE_RESTART = 0x80


class IIN2Bit(IntEnum):
    """The second internal indication octet: what went wrong with this request."""

    FUNC_NOT_SUPPORTED = 0x01
    OBJECT_UNKNOWN = 0x02
    PARAM_ERROR = 0x04
    EVENT_BUFFER_OVERFLOW = 0x08
    ALREADY_EXECUTING = 0x10
    CONFIG_CORRUPT = 0x20


@dataclass(frozen=True)
class IIN:
    """The two internal indication octets a response carries."""

    first: int = 0
    second: int = 0

    def __or__(self, other: IIN) -> IIN:
        return IIN(self.first | other.first, self.second | other.second)

    def is_set(self, bit: IINBit | IIN2Bit) -> bool:
        octet = self.first if isinstance(bit, IINBit) else self.second
        return bool(octet & bit)

    def to_bytes(self) -> bytes:
        return bytes([self.first & 0xFF, self.second & 0xFF])


@dataclass(frozen=True)
class AppControl:
    """The application control octet."""

    fir: bool = True
    fin: bool = True
    con: bool = False
    uns: bool = False
    sequence: int = 0

    @classmethod
    def from_byte(cls, octet: int) -> AppControl:
        return cls(
            fir=bool(octet & FIR_MASK),
            fin=bool(octet & FIN_MASK),
            con=bool(octet & CON_MASK),
            uns=bool(octet & UNS_MASK),
            sequence=octet & SEQ_MASK,
        )

    def to_byte(self) -> int:
        octet = self.sequence % SEQUENCE_MODULUS
        if self.fir:
            octet |= FIR_MASK
        if self.fin:
            octet |= FIN_MASK
        if self.con:
            octet |= CON_MASK
        if self.uns:
            octet |= UNS_MASK
        return octet


@dataclass(frozen=True)
class ObjectHeader:
    """One object header: what is being asked for, and over what range."""

    group: int
    variation: int
    qualifier: QualifierCode
    start: int | None = None
    stop: int | None = None
    count: int | None = None
    #: The indices an index-prefixed qualifier names, when they are contiguous.
    #: A request carrying object data interleaves them with the objects, so they
    #: are read only where nothing follows them -- see :func:`parse_request`.
    indices: tuple[int, ...] | None = None

    @property
    def is_class_request(self) -> bool:
        return self.group == CLASS_GROUP and self.variation in CLASS_VARIATIONS

    @property
    def event_class(self) -> int | None:
        """The class this header names, or None if it does not name one."""
        if not self.is_class_request:
            return None
        return CLASS_VARIATIONS[self.variation]


class RequestError(Exception):
    """A request that cannot be parsed, and the indication bit that says so.

    Carrying the bit is what lets the session answer a malformed request
    correctly without re-deriving why it was malformed. A qualifier this
    outstation does not implement is a parameter error; a group it does not know
    is an unknown object. Those are different answers, and a master acts on the
    difference.
    """

    def __init__(self, reason: str, bit: IIN2Bit = IIN2Bit.PARAM_ERROR) -> None:
        super().__init__(reason)
        self.bit = bit


@dataclass(frozen=True)
class Request:
    """One parsed request fragment."""

    control: AppControl
    function: int
    headers: tuple[ObjectHeader, ...] = ()
    #: Object data this module did not consume, for a function that carries some.
    body: bytes = b""
    known_function: FunctionCode | None = field(default=None, compare=False)


def _parse_header(
    fragment: bytes, offset: int, *, indices_follow: bool
) -> tuple[ObjectHeader, int]:
    if offset + 3 > len(fragment):
        raise RequestError("object header is truncated")
    group, variation, raw_qualifier = fragment[offset : offset + 3]
    offset += 3

    try:
        qualifier = QualifierCode(raw_qualifier)
    except ValueError as exc:
        raise RequestError(
            f"qualifier 0x{raw_qualifier:02X} is not one this outstation accepts"
        ) from exc

    start = stop = count = None
    if qualifier is QualifierCode.UINT8_START_STOP:
        if offset + 2 > len(fragment):
            raise RequestError("range field is truncated")
        start, stop = fragment[offset], fragment[offset + 1]
        offset += 2
    elif qualifier is QualifierCode.UINT16_START_STOP:
        if offset + 4 > len(fragment):
            raise RequestError("range field is truncated")
        start, stop = struct.unpack("<HH", fragment[offset : offset + 4])
        offset += 4
    elif qualifier in (QualifierCode.UINT8_COUNT, QualifierCode.UINT8_COUNT_UINT8_INDEX):
        if offset + 1 > len(fragment):
            raise RequestError("count field is truncated")
        count = fragment[offset]
        offset += 1
    elif qualifier in (QualifierCode.UINT16_COUNT, QualifierCode.UINT16_COUNT_UINT16_INDEX):
        if offset + 2 > len(fragment):
            raise RequestError("count field is truncated")
        count = struct.unpack("<H", fragment[offset : offset + 2])[0]
        offset += 2

    if start is not None and stop is not None and stop < start:
        raise RequestError(f"range {start}..{stop} ends before it begins")

    indices: tuple[int, ...] | None = None
    if indices_follow and qualifier in _INDEX_WIDTHS and count is not None:
        width = _INDEX_WIDTHS[qualifier]
        span = count * width
        if offset + span > len(fragment):
            raise RequestError("index list is truncated")
        raw = fragment[offset : offset + span]
        indices = tuple(raw) if width == 1 else struct.unpack(f"<{count}H", raw)
        offset += span

    return ObjectHeader(group, variation, qualifier, start, stop, count, indices), offset


def parse_request(fragment: bytes) -> Request:
    """Parse a request fragment, or say why it is not one."""
    if len(fragment) < REQUEST_HEADER_SIZE:
        raise RequestError("fragment is shorter than an application header")

    control = AppControl.from_byte(fragment[0])
    function = fragment[1]
    try:
        known: FunctionCode | None = FunctionCode(function)
    except ValueError:
        known = None

    if known is FunctionCode.CONFIRM:
        if len(fragment) > REQUEST_HEADER_SIZE:
            raise RequestError("a confirmation carries no objects")
        return Request(control, function, known_function=known)

    if known is None or known not in _PARSED_FUNCTIONS:
        # Two cases, one answer. Nothing here knows an unrecognized function's
        # body layout, and a recognized function this module does not parse is
        # in the same position. Reading either's first octets as an object
        # header invents a structure and then refuses the request for failing to
        # have it. The answer a master is owed is "function not supported", and
        # producing that needs the request parsed rather than rejected. The
        # payload travels untouched in ``body``, and ``known_function`` travels
        # with it so a refusal can name what it refused.
        return Request(control, function, body=fragment[REQUEST_HEADER_SIZE:], known_function=known)

    headers: list[ObjectHeader] = []
    offset = REQUEST_HEADER_SIZE
    header_only = known in HEADER_ONLY_FUNCTIONS
    while offset < len(fragment):
        # In a request carrying no object data, an index-prefixed qualifier is
        # followed by its index list and nothing else, so the list is read here.
        # In one that carries objects, each index prefixes its own object and
        # the two interleave -- which is why parsing stops at the first header
        # there rather than walking a list that is not contiguous.
        header, offset = _parse_header(fragment, offset, indices_follow=header_only)
        headers.append(header)
        if not header_only:
            break

    return Request(
        control=control,
        function=function,
        headers=tuple(headers),
        body=fragment[offset:],
        known_function=known,
    )


@dataclass(frozen=True)
class ObjectBlock:
    """One object header and the indexed objects that followed it."""

    header: ObjectHeader
    #: ``(index, octets)`` in the order they arrived. An index may repeat: a
    #: request naming the same point twice is a request naming it twice, and
    #: collapsing that here would answer fewer objects than were asked about.
    items: tuple[tuple[int, bytes], ...]


def parse_object_blocks(
    request: Request, size_of: Callable[[int, int], int | None]
) -> tuple[ObjectBlock, ...]:
    """Walk a request whose objects interleave with their indices.

    ``parse_request`` stops at the first header for such a request and leaves
    the remainder in ``body``, because the indices do not form a list that can
    be read ahead of the objects. This walks that remainder: for each header,
    ``count`` objects each prefixed by its own index, then the next header.

    ``size_of`` answers how wide one object of a group and variation is, and
    ``None`` where it knows of none. The layer is kept ignorant of object
    formats deliberately -- it parses headers and qualifiers and nothing below
    them -- so the caller supplies the only thing it cannot know.

    Every failure here is a failure of the fragment rather than of one object,
    and that is not a stylistic choice. A truncated body, a count that disagrees
    with the octets present, or a width nothing recognizes may leave no complete
    object at all, and a status has to be attached to something. Raising
    :class:`RequestError` is what tells the caller to refuse the fragment rather
    than to answer per index.

    No object count is imposed. A fragment is already bounded, and eleven octets
    plus an index is the smallest control a request can carry, so the ceiling is
    the one the transport already sets.
    """
    if not request.headers:
        raise RequestError("a request carrying objects has no object header")

    blocks: list[ObjectBlock] = []
    header = request.headers[0]
    body = request.body
    offset = 0

    while True:
        width = _INDEX_WIDTHS.get(header.qualifier)
        if width is None:
            raise RequestError(
                f"qualifier 0x{int(header.qualifier):02X} prefixes no index, so the "
                "objects after it cannot be told apart"
            )
        if header.count is None:
            raise RequestError("an index-prefixed qualifier carries no count")

        size = size_of(header.group, header.variation)
        if size is None:
            raise RequestError(
                f"no object of group {header.group} variation {header.variation} is known, "
                "so its width cannot be read"
            )

        items: list[tuple[int, bytes]] = []
        for _ in range(header.count):
            end = offset + width + size
            if end > len(body):
                raise RequestError(
                    f"group {header.group} variation {header.variation} declares "
                    f"{header.count} objects and the body holds fewer"
                )
            items.append(
                (
                    int.from_bytes(body[offset : offset + width], "little"),
                    bytes(body[offset + width : end]),
                )
            )
            offset = end

        blocks.append(ObjectBlock(header=header, items=tuple(items)))

        if offset == len(body):
            return tuple(blocks)
        header, offset = _parse_header(body, offset, indices_follow=False)


def object_header(group: int, variation: int, *, start: int, stop: int) -> bytes:
    """An object header covering a contiguous range, in the narrowest qualifier.

    Narrowest rather than always 16-bit because a master reads the qualifier to
    size the range field, and a one-octet range is two octets cheaper in every
    response that fits it -- which, for a fleet served in blocks, is most of them.
    """
    if stop < start:
        raise ValueError(f"range {start}..{stop} ends before it begins")
    if start < 0 or stop > 0xFFFF:
        raise ValueError(f"range {start}..{stop} does not fit a 16-bit index")
    if stop <= 0xFF:
        return bytes([group, variation, QualifierCode.UINT8_START_STOP, start, stop])
    return struct.pack("<BBBHH", group, variation, QualifierCode.UINT16_START_STOP, start, stop)


def build_response(
    *,
    control: AppControl,
    iin: IIN,
    body: bytes = b"",
    function: FunctionCode = FunctionCode.RESPONSE,
) -> bytes:
    """One response fragment, ready for the transport function."""
    return bytes([control.to_byte(), function, *iin.to_bytes()]) + body


def null_response(*, sequence: int, iin: IIN) -> bytes:
    """A response carrying indications and no objects.

    The answer to a request that was understood and produced nothing to say --
    a refusal, an acknowledged write, an empty class poll.
    """
    return build_response(
        control=AppControl(fir=True, fin=True, sequence=sequence),
        iin=iin,
    )
