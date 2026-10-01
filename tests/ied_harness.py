"""A test master and a device under test, for the conformance procedures.

The DNP Users Group's IED certification procedures are written as a dialog:
the tester sends a request with a stated link control octet, function code and
qualifier, and checks what comes back. This module is the tester's side of
that dialog, built on nothing but the framing helpers: requests are assembled
octet by octet, and responses are parsed here, not by the code under test.

It drives a :class:`~py1815.session.Session` through ``receive``, so every
request crosses the data link, transport and application layers exactly as it
would arrive from a socket, with no socket to wait on.

The device under test is a small outstation with a few points of every kind,
whose inputs the tests move directly. Its point table is invented here.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from profile_fixtures import analog, document, row

from py1815 import crc, link
from py1815.control import CommandStatus
from py1815.profile import load
from py1815.profile.binding import Binding, Quality, Reading
from py1815.profile.model import Composition, Kind
from py1815.profile.outstation import DerOutstation
from py1815.session import Session
from py1815.transport import Reassembler, segment

OUTSTATION = 1024
MASTER = 1

# Function codes, by the names the procedures use.
CONFIRM, READ, WRITE, SELECT, OPERATE, DIRECT_OPERATE, DIRECT_OPERATE_NR = 0, 1, 2, 3, 4, 5, 6
FREEZE, FREEZE_NR, FREEZE_CLEAR, FREEZE_CLEAR_NR = 7, 8, 9, 10
COLD_RESTART, ASSIGN_CLASS, DELAY_MEASURE = 13, 22, 23
RESPONSE = 0x81

# Qualifier codes.
Q_RANGE_8, Q_RANGE_16, Q_ALL, Q_COUNT_8, Q_COUNT_16, Q_INDEX_8, Q_INDEX_16 = (
    0x00,
    0x01,
    0x06,
    0x07,
    0x08,
    0x17,
    0x28,
)

# Internal indications: (octet, mask).
IIN1_BROADCAST, IIN1_CLASS_1, IIN1_CLASS_2, IIN1_CLASS_3 = 0x01, 0x02, 0x04, 0x08
IIN1_NEED_TIME, IIN1_LOCAL, IIN1_TROUBLE, IIN1_RESTART = 0x10, 0x20, 0x40, 0x80
IIN2_BAD_FUNCTION, IIN2_OBJECT_UNKNOWN, IIN2_PARAMETER, IIN2_OVERFLOW = 0x01, 0x02, 0x04, 0x08
ERROR_IIN = IIN2_BAD_FUNCTION | IIN2_OBJECT_UNKNOWN | IIN2_PARAMETER

FLAG_ONLINE = 0x01

#: The octets one object occupies, by group and variation.
SIZES = {
    (1, 2): 1,
    (2, 1): 1,
    (2, 2): 7,
    (2, 3): 3,
    (10, 2): 1,
    (12, 1): 11,
    (20, 1): 5,
    (20, 2): 3,
    (20, 5): 4,
    (20, 6): 2,
    (21, 1): 5,
    (21, 2): 3,
    (21, 5): 11,
    (21, 9): 4,
    (21, 10): 2,
    (22, 1): 5,
    (22, 2): 3,
    (23, 1): 5,
    (23, 2): 3,
    (23, 5): 11,
    (30, 1): 5,
    (30, 2): 3,
    (30, 3): 4,
    (30, 4): 2,
    (32, 1): 5,
    (32, 2): 3,
    (32, 3): 11,
    (32, 4): 9,
    (40, 1): 5,
    (40, 2): 3,
    (41, 1): 5,
    (41, 2): 3,
    (41, 3): 5,
    (41, 4): 9,
    (50, 1): 6,
    (51, 1): 6,
    (51, 2): 6,
    (52, 1): 2,
    (52, 2): 2,
}

_NO_FLAG = {(20, 5), (20, 6), (21, 9), (21, 10), (30, 3), (30, 4)}
_COMMANDS = {12, 41}
_SIGNED = {30: True, 32: True, 40: True, 41: True}
_WIDTH_FORMAT = {1: "b", 2: "h", 4: "i"}


@dataclass(frozen=True)
class Obj:
    """One object out of a response."""

    group: int
    variation: int
    qualifier: int
    index: int | None
    raw: bytes

    @property
    def flags(self) -> int | None:
        """The flag octet, or None for a variation that carries none."""
        if (self.group, self.variation) in _NO_FLAG or self.group in (*_COMMANDS, 50, 51, 52):
            return None
        return self.raw[0]

    @property
    def state(self) -> bool:
        """A binary object's state bit."""
        return bool(self.raw[0] & 0x80)

    @property
    def value(self) -> int:
        """The object's number: a count, an analog value or a time."""
        key = (self.group, self.variation)
        if self.group in (50, 51, 52):
            return int.from_bytes(self.raw[: SIZES[key]], "little")
        if self.group == 41:
            fmt = {1: "<i", 2: "<h", 3: "<f", 4: "<d"}[self.variation]
            return int(struct.unpack_from(fmt, self.raw)[0])
        start = 0 if key in _NO_FLAG else 1
        width = (
            {5: 4, 3: 2, 4: 4, 2: 2, 11: 4, 9: 2}[SIZES[key]] if key not in _NO_FLAG else SIZES[key]
        )
        chunk = self.raw[start : start + width]
        return int.from_bytes(chunk, "little", signed=self.group in _SIGNED)

    @property
    def status(self) -> int:
        """A command object's status octet."""
        return self.raw[-1]

    @property
    def time(self) -> int | None:
        """The timestamp a timed variation carries, in milliseconds."""
        if (self.group, self.variation) in {(2, 2), (21, 5), (23, 5), (32, 3), (32, 4)}:
            return int.from_bytes(self.raw[-6:], "little")
        return None


def parse_objects(body: bytes) -> list[Obj]:
    """Every object in a response body, in the order sent."""
    objects: list[Obj] = []
    offset = 0
    while offset < len(body):
        group, variation, qualifier = body[offset : offset + 3]
        offset += 3
        size = SIZES[(group, variation)]
        if qualifier in (Q_RANGE_8, Q_RANGE_16):
            wide = qualifier == Q_RANGE_16
            start, stop = struct.unpack_from("<HH" if wide else "<BB", body, offset)
            offset += 4 if wide else 2
            for index in range(start, stop + 1):
                objects.append(
                    Obj(group, variation, qualifier, index, body[offset : offset + size])
                )
                offset += size
        elif qualifier in (Q_INDEX_8, Q_INDEX_16):
            width = 2 if qualifier == Q_INDEX_16 else 1
            count = int.from_bytes(body[offset : offset + width], "little")
            offset += width
            for _ in range(count):
                index = int.from_bytes(body[offset : offset + width], "little")
                offset += width
                objects.append(
                    Obj(group, variation, qualifier, index, body[offset : offset + size])
                )
                offset += size
        elif qualifier == Q_COUNT_8:
            count = body[offset]
            offset += 1
            for _ in range(count):
                objects.append(Obj(group, variation, qualifier, None, body[offset : offset + size]))
                offset += size
        else:
            raise AssertionError(
                f"response uses qualifier 0x{qualifier:02X}, which no test expects"
            )
        assert offset <= len(body), "a response ends inside an object"
    return objects


@dataclass
class Fragment:
    """One application fragment of a response."""

    octets: bytes

    @property
    def fir(self) -> bool:
        return bool(self.octets[0] & 0x80)

    @property
    def fin(self) -> bool:
        return bool(self.octets[0] & 0x40)

    @property
    def con(self) -> bool:
        return bool(self.octets[0] & 0x20)

    @property
    def uns(self) -> bool:
        return bool(self.octets[0] & 0x10)

    @property
    def sequence(self) -> int:
        return self.octets[0] & 0x0F

    @property
    def function(self) -> int:
        return self.octets[1]

    @property
    def iin1(self) -> int:
        return self.octets[2]

    @property
    def iin2(self) -> int:
        return self.octets[3]

    @property
    def body(self) -> bytes:
        return self.octets[4:]

    @property
    def objects(self) -> list[Obj]:
        return parse_objects(self.body)

    @property
    def is_null(self) -> bool:
        """A response carrying no objects and no error indication."""
        return self.function == RESPONSE and not self.body and not self.iin2 & ERROR_IIN

    @property
    def is_error(self) -> bool:
        return bool(self.iin2 & ERROR_IIN)

    def of(self, group: int) -> list[Obj]:
        return [obj for obj in self.objects if obj.group == group]


@dataclass
class Reply:
    """Everything the outstation sent back for one transmission."""

    raw: bytes
    frames: list[link.LinkFrame] = field(default_factory=list)
    #: Transport segments, as (FIN, FIR, sequence) and their payload.
    segments: list[tuple[bool, bool, int, bytes]] = field(default_factory=list)
    fragments: list[Fragment] = field(default_factory=list)

    @property
    def silent(self) -> bool:
        """Nothing at all was sent: no link frame, no response."""
        return not self.raw

    @property
    def link_controls(self) -> list[int]:
        return [frame.control for frame in self.frames]

    @property
    def fragment(self) -> Fragment:
        assert len(self.fragments) == 1, f"expected one fragment, got {len(self.fragments)}"
        return self.fragments[0]


class TestMaster:
    """The tester's side of the dialog."""

    __test__ = False

    def __init__(self, session: Session, *, outstation: int = OUTSTATION, master: int = MASTER):
        self.session = session
        self.outstation = outstation
        self.master = master
        self.sequence = 0
        self._reassembler = Reassembler(max_fragment=65536)

    # ------------------------------------------------------------ sending

    def raw(self, octets: bytes) -> Reply:
        """Send octets exactly as given and collect whatever comes back."""
        out = self.session.receive(octets)
        reply = Reply(raw=out)
        reader = link.FrameReader()
        for frame in reader.feed(out):
            reply.frames.append(frame)
            if frame.payload:
                header = frame.payload[0]
                reply.segments.append(
                    (bool(header & 0x80), bool(header & 0x40), header & 0x3F, frame.payload[1:])
                )
                whole = self._reassembler.add(frame.payload)
                if whole is not None:
                    reply.fragments.append(Fragment(whole))
        return reply

    def frame(self, control: int, payload: bytes = b"", *, destination: int | None = None) -> bytes:
        """One link frame with the control octet given verbatim."""
        return link.build(
            control, self.outstation if destination is None else destination, self.master, payload
        )

    def frames(
        self, fragment: bytes, *, control: int = 0xC4, destination: int | None = None
    ) -> bytes:
        return b"".join(
            self.frame(control, part, destination=destination) for part in segment(fragment)
        )

    def link(self, control: int, *, destination: int | None = None) -> Reply:
        """A link-layer frame with no user data."""
        return self.raw(self.frame(control, destination=destination))

    def request(
        self,
        function: int,
        body: bytes = b"",
        *,
        sequence: int | None = None,
        control: int = 0xC4,
        destination: int | None = None,
    ) -> Reply:
        """One application request, under the next sequence number unless one is named."""
        if sequence is None:
            sequence = self.sequence
        self.sequence = (sequence + 1) % 16
        fragment = bytes([0xC0 | sequence, function]) + body
        return self.raw(self.frames(fragment, control=control, destination=destination))

    def read(self, *headers: bytes, **options: Any) -> Reply:
        return self.request(READ, b"".join(headers), **options)

    def confirm(self, fragment: Fragment) -> Reply:
        """Confirm a fragment, under its own sequence number."""
        return self.raw(self.frames(bytes([0xC0 | fragment.sequence, CONFIRM])))

    def confirm_sequence(self, sequence: int) -> Reply:
        return self.raw(self.frames(bytes([0xC0 | sequence, CONFIRM])))

    def poll(self, *headers: bytes, confirm: bool = True) -> list[Fragment]:
        """A read followed to its end, confirming each fragment that asks."""
        reply = self.read(*headers)
        fragments = list(reply.fragments)
        while fragments and confirm and fragments[-1].con:
            more = self.confirm(fragments[-1])
            if not more.fragments:
                break
            fragments += more.fragments
        return fragments

    def empty_events(self) -> None:
        """Read and confirm every class until nothing is waiting."""
        for _ in range(64):
            fragments = self.poll(classes(1, 2, 3))
            if all(not fragment.body for fragment in fragments):
                return
        raise AssertionError("the outstation never ran out of events")


# ------------------------------------------------------------ request parts


def header(group: int, variation: int, qualifier: int = Q_ALL, *range_or_count: int) -> bytes:
    """An object header: all objects, a count, or a start and stop."""
    head = bytes([group, variation, qualifier])
    if qualifier == Q_ALL:
        return head
    if qualifier == Q_COUNT_8:
        return head + bytes([range_or_count[0]])
    if qualifier == Q_COUNT_16:
        return head + struct.pack("<H", range_or_count[0])
    if qualifier == Q_RANGE_8:
        return head + bytes(range_or_count)
    return head + struct.pack("<HH", *range_or_count)


def classes(*numbers: int, qualifier: int = Q_ALL, count: int = 0) -> bytes:
    """Class headers, in the order named. Class 0 is variation 1."""
    return b"".join(
        header(60, number + 1, qualifier, *([count] if qualifier != Q_ALL else []))
        for number in numbers
    )


def crob(
    index: int,
    code: int = 0x03,
    *,
    qualifier: int = Q_INDEX_8,
    count: int = 1,
    on: int = 100,
    off: int = 200,
    status: int = 0,
) -> bytes:
    """One control relay output block behind its index."""
    return _indexed(
        12, 1, qualifier, [(index, struct.pack("<BBIIB", code, count, on, off, status))]
    )


def crobs(indices: list[int], code: int = 0x03, *, qualifier: int = Q_INDEX_16) -> bytes:
    payload = struct.pack("<BBIIB", code, 1, 100, 200, 0)
    return _indexed(12, 1, qualifier, [(index, payload) for index in indices])


def analog_output(
    index: int, value: int, *, variation: int = 2, qualifier: int = Q_INDEX_8, status: int = 0
) -> bytes:
    fmt = {1: "<i", 2: "<h"}[variation]
    return _indexed(41, variation, qualifier, [(index, struct.pack(fmt, value) + bytes([status]))])


def analog_outputs(pairs: list[tuple[int, int]], *, qualifier: int = Q_INDEX_16) -> bytes:
    return _indexed(41, 2, qualifier, [(i, struct.pack("<h", v) + b"\x00") for i, v in pairs])


def _indexed(group: int, variation: int, qualifier: int, items: list[tuple[int, bytes]]) -> bytes:
    wide = qualifier == Q_INDEX_16
    out = bytes([group, variation, qualifier]) + (
        struct.pack("<H", len(items)) if wide else bytes([len(items)])
    )
    for index, payload in items:
        out += (struct.pack("<H", index) if wide else bytes([index])) + payload
    return out


def corrupt_header_crc(frame: bytes) -> bytes:
    """The same frame with its header checksum wrong."""
    return frame[:8] + bytes([frame[8] ^ 0xFF]) + frame[9:]


def corrupt_body_crc(frame: bytes) -> bytes:
    """The same frame with the checksum of its first data block wrong."""
    return frame[:-1] + bytes([frame[-1] ^ 0xFF])


def with_start(frame: bytes, first: int, second: int) -> bytes:
    """The same frame with other start octets and a header checksum to match."""
    head = bytes([first, second]) + frame[2:8]
    return crc.encode(head) + frame[10:]


# ---------------------------------------------------------- device under test

#: The points the device under test serves. Indices are consecutive from zero
#: so that range requests have something to select and something to miss.
BINARY_INPUTS = {0: 1, 1: 1, 2: 2, 3: 3}
ANALOG_INPUTS = {0: 1, 1: 2, 2: 3, 3: 2}
BINARY_OUTPUTS = (0, 1, 2, 3)
ANALOG_OUTPUTS = (0, 1, 2, 3)
COUNTERS = (0, 1, 2)
DEADBAND = 10


#: The one analog output that holds more than sixteen bits.
WIDE_OUTPUT = 3


def _tables(extra_analogs: int = 0) -> dict[str, Any]:
    measures = dict(ANALOG_INPUTS)
    more = range(len(ANALOG_INPUTS), len(ANALOG_INPUTS) + extra_analogs)
    measures.update(dict.fromkeys(more, 3))
    return document(
        {
            "BI": [row(f"Input {i}", i, event_class=cls) for i, cls in BINARY_INPUTS.items()],
            "BO": [row(f"Output {i}", i) for i in BINARY_OUTPUTS],
            "AI": [analog(f"Measure {i}", i, event_class=cls) for i, cls in measures.items()],
            "AO": [
                analog(
                    f"Setpoint {i}",
                    i,
                    minimum=-(2**31) if i == WIDE_OUTPUT else -30000,
                    maximum=2**31 - 1 if i == WIDE_OUTPUT else 30000,
                )
                for i in ANALOG_OUTPUTS
            ],
            "CTR": [row(f"Count {i}", i, frozen=True, frozen_event_class=3) for i in COUNTERS],
        }
    )


class Clock:
    """Time the tests move by hand: seconds for the session, milliseconds for stamps."""

    def __init__(self) -> None:
        self.seconds = 1000.0

    def __call__(self) -> float:
        return self.seconds

    def ms(self) -> int:
        return int(self.seconds * 1000)

    def advance(self, seconds: float) -> None:
        self.seconds += seconds


class Dut:
    """The device under test: an outstation, its session, and the inputs behind it."""

    def __init__(
        self,
        *,
        level2: bool = True,
        binary_outputs: bool = True,
        analog_outputs: bool = True,
        counters: bool = True,
        binary_inputs: bool = True,
        analog_inputs: bool = True,
        capacity: int = 50,
        extra_analogs: int = 0,
        block_octets: int = 1024,
        **session_options: Any,
    ) -> None:
        self.clock = Clock()
        self.binary = dict.fromkeys(BINARY_INPUTS, False)
        self.analog = dict.fromkeys(range(len(ANALOG_INPUTS) + extra_analogs), 100.0)
        self.counts = dict.fromkeys(COUNTERS, 5)
        self.quality: dict[tuple[Kind, int], Quality] = {}
        #: Every operation that reached the device, as (kind, index, value).
        self.operated: list[tuple[str, int, float]] = []
        self.restarts = 0

        binding = Binding()
        if binary_inputs:
            for index in BINARY_INPUTS:
                binding.read(Kind.BI, index, self._reader(Kind.BI, self.binary, index))
        if analog_inputs:
            for index in self.analog:
                binding.read(
                    Kind.AI, index, self._reader(Kind.AI, self.analog, index), deadband=DEADBAND
                )
        if counters:
            for index in COUNTERS:
                binding.read(Kind.CTR, index, self._reader(Kind.CTR, self.counts, index))
        if binary_outputs:
            for index in BINARY_OUTPUTS:
                binding.output(Kind.BO, index, self._writer("BO", index), initial=False)
        if analog_outputs:
            for index in ANALOG_OUTPUTS:
                binding.output(Kind.AO, index, self._writer("AO", index), initial=0.0)

        self.outstation = DerOutstation(
            load.resolve(_tables(extra_analogs), Composition()),
            binding,
            strict=False,
            event_capacity=capacity,
            block_octets=block_octets,
            clock_ms=self.clock.ms,
            level2=level2,
        )
        session_options.setdefault("need_time", False)
        session_options.setdefault("clock", self.clock)
        self.session = self.outstation.session(**session_options)
        self.master = TestMaster(self.session)
        self.outstation.poll()

    def _reader(self, kind: Kind, values: dict[int, Any], index: int) -> Any:
        def read() -> Reading:
            return Reading(values[index], self.quality.get((kind, index), Quality.GOOD))

        return read

    def _writer(self, kind: str, index: int) -> Any:
        def write(value: float) -> CommandStatus | None:
            self.operated.append((kind, index, value))
            return None

        return write

    # ------------------------------------------------------------ stimulus

    def toggle(self, index: int) -> None:
        """Change one binary input and let the outstation notice."""
        self.clock.advance(0.01)
        self.binary[index] = not self.binary[index]
        self.outstation.poll()

    def step(self, index: int, by: float = 5 * DEADBAND) -> None:
        """Move one analog input by more than its deadband."""
        self.clock.advance(0.01)
        self.analog[index] += by
        self.outstation.poll()

    def set_analog(self, index: int, value: float) -> None:
        self.clock.advance(0.01)
        self.analog[index] = value
        self.outstation.poll()

    def count(self, by: int = 3) -> None:
        """Add to every counter."""
        for index in self.counts:
            self.counts[index] += by

    def restart(self) -> None:
        """Cycle power: a new session over the same device, as a restart leaves it."""
        self.session.restart()
        self.master = TestMaster(self.session)

    def clear_restart(self) -> None:
        self.master.request(WRITE, header(80, 1, Q_RANGE_8, 7, 7) + b"\x00")
