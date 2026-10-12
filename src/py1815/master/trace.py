"""The record of an exchange: every frame, with what it says.

A trace is what a person reads to see what two stations said to each other.
Each frame that was sent or received is kept with its time and its direction,
its octets, and a reading of them one layer at a time: the data link, the
transport function, and, on the frame that completes a fragment, the
application layer.

The reading is for people. Nothing in the master acts on it, so a frame it
describes badly is a display fault and never a protocol one.

A trace also knows which connection each frame crossed and the addresses of
its two ends, so it can be exported as a pcap file (:meth:`Trace.capture`) or
written to one as it is recorded (:class:`Recorder`), for a dissector to read.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import time
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from py1815 import link
from py1815.application import (
    IIN,
    RESPONSE_FUNCTIONS,
    AppControl,
    FunctionCode,
    IIN2Bit,
    IINBit,
    RequestError,
    parse_header_list,
)
from py1815.decode import decode_objects
from py1815.master.capture import DNP3_PORT, Address, Capture, Stream, ipv4
from py1815.transport import FIN_MASK, FIR_MASK, SEQ_MASK, Reassembler, TransportError

#: Frames kept before the oldest is dropped.
DEFAULT_CAPACITY = 5000

SENT, RECEIVED = "tx", "rx"

_CLASS_NAMES = {1: "class 0", 2: "class 1", 3: "class 2", 4: "class 3"}

#: Requests whose body is object headers and nothing else, so the headers can
#: be listed without knowing any object's width.
_HEADER_ONLY = frozenset(
    {
        FunctionCode.READ,
        FunctionCode.IMMED_FREEZE,
        FunctionCode.IMMED_FREEZE_NR,
        FunctionCode.FREEZE_CLEAR,
        FunctionCode.FREEZE_CLEAR_NR,
        FunctionCode.ENABLE_UNSOLICITED,
        FunctionCode.DISABLE_UNSOLICITED,
    }
)


def iin_names(iin: IIN) -> list[str]:
    """The indications that are set, by name, first octet first."""
    names = [bit.name for bit in IINBit if iin.first & bit]
    return names + [bit.name for bit in IIN2Bit if iin.second & bit]


@dataclass(frozen=True)
class Entry:
    """One frame, as sent or received."""

    #: Counts up from 1 for the life of the trace, and is never reused.
    id: int
    #: Seconds since the epoch.
    at: float
    #: ``"tx"`` for a frame this master sent, ``"rx"`` for one it received.
    direction: str
    octets: bytes
    #: The data link layer's reading of the frame.
    link: dict[str, Any]
    #: The transport header, when the frame carries user data.
    transport: dict[str, Any] | None
    #: The application fragment, on the frame that completed one.
    application: dict[str, Any] | None
    #: One line that says what the frame is.
    summary: str
    #: The connection the frame crossed: 1 for the trace's first, counting up
    #: with each new one, and 0 for a frame recorded before any.
    connection: int = 0


def _link(frame: link.LinkFrame) -> dict[str, Any]:
    functions: type[link.PrimaryFunction] | type[link.SecondaryFunction]
    functions = link.PrimaryFunction if frame.is_primary else link.SecondaryFunction
    try:
        function = functions(frame.function).name
    except ValueError:
        function = f"function {frame.function}"
    return {
        "from_master": frame.from_master,
        "primary": frame.is_primary,
        "function": function,
        "destination": frame.destination,
        "source": frame.source,
        "user_data": len(frame.payload),
    }


def _groups(body: bytes) -> tuple[list[str], str | None]:
    """A response's objects, as one phrase per group and variation."""
    decoded = decode_objects(body)
    counts = Counter(
        (decoded_object.group, decoded_object.variation) for decoded_object in decoded.objects
    )
    phrases = [
        f"g{group}v{variation} x{count}" for (group, variation), count in sorted(counts.items())
    ]
    return phrases, decoded.problem


def _headers(function: FunctionCode, body: bytes) -> list[str]:
    """A request's object headers, as one phrase each, where they can be read."""
    if function not in _HEADER_ONLY or not body:
        return []
    try:
        headers = parse_header_list(body)
    except RequestError:
        return []
    phrases = []
    for header in headers:
        if header.group == 60 and header.variation in _CLASS_NAMES:
            phrases.append(_CLASS_NAMES[header.variation])
        elif header.indices is not None:
            listed = ", ".join(str(index) for index in header.indices[:8])
            more = ", ..." if len(header.indices) > 8 else ""
            phrases.append(f"g{header.group}v{header.variation} [{listed}{more}]")
        elif header.start is not None:
            phrases.append(f"g{header.group}v{header.variation} {header.start}..{header.stop}")
        else:
            phrases.append(f"g{header.group}v{header.variation} all")
    return phrases


def _application(fragment: bytes) -> dict[str, Any]:
    control = AppControl.from_byte(fragment[0])
    try:
        function: FunctionCode | None = FunctionCode(fragment[1])
    except ValueError:
        function = None
    read: dict[str, Any] = {
        "fir": control.fir,
        "fin": control.fin,
        "con": control.con,
        "uns": control.uns,
        "sequence": control.sequence,
        "function": function.name if function is not None else f"function 0x{fragment[1]:02X}",
        "octets": len(fragment),
    }
    if function in RESPONSE_FUNCTIONS and len(fragment) >= 4:
        read["iin"] = iin_names(IIN(fragment[2], fragment[3]))
        read["objects"], problem = _groups(fragment[4:])
        if problem is not None:
            read["problem"] = problem
    elif function is not None:
        read["objects"] = _headers(function, fragment[2:])
    return read


def _summary(
    frame: dict[str, Any], transport: dict[str, Any] | None, application: dict[str, Any] | None
) -> str:
    if application is not None:
        words = [application["function"], f"seq {application['sequence']}"]
        if application["con"]:
            words.append("CON")
        if not (application["fir"] and application["fin"]):
            words.append(
                "first" if application["fir"] else "final" if application["fin"] else "middle"
            )
        text = " ".join(words)
        if application.get("iin"):
            text += " [" + ", ".join(application["iin"]) + "]"
        if application.get("objects"):
            text += ": " + ", ".join(application["objects"])
        return text
    if transport is not None:
        return f"segment {transport['sequence']} of a fragment still arriving"
    return str(frame["function"])


class Trace:
    """Frames, in the order they crossed the wire."""

    def __init__(
        self, *, capacity: int = DEFAULT_CAPACITY, clock: Callable[[], float] = time.time
    ) -> None:
        self._entries: deque[Entry] = deque(maxlen=capacity)
        self._clock = clock
        self._next = 1
        self._readers = {SENT: link.FrameReader(), RECEIVED: link.FrameReader()}
        self._reassemblers = {SENT: Reassembler(), RECEIVED: Reassembler()}
        self._connection = 0
        self._endpoints: dict[int, tuple[Address | None, Address | None]] = {}
        #: Called with each entry as it is recorded.
        self.listeners: list[Callable[[Entry], None]] = []

    def record(self, direction: str, octets: bytes) -> list[Entry]:
        """Take octets that were sent or received, and keep each frame in them.

        Received octets arrive split wherever the network split them, so a
        frame is recorded when its last octet has arrived and not before.
        """
        recorded = []
        for frame in self._readers[direction].feed(octets):
            entry = self._entry(direction, frame)
            self._entries.append(entry)
            recorded.append(entry)
            for listener in list(self.listeners):
                listener(entry)
        return recorded

    def _entry(self, direction: str, frame: link.LinkFrame) -> Entry:
        described = _link(frame)
        transport: dict[str, Any] | None = None
        application: dict[str, Any] | None = None
        carries_data = frame.is_primary and frame.function in (
            link.PrimaryFunction.UNCONFIRMED_USER_DATA,
            link.PrimaryFunction.CONFIRMED_USER_DATA,
        )
        if carries_data and frame.payload:
            header = frame.payload[0]
            transport = {
                "fir": bool(header & FIR_MASK),
                "fin": bool(header & FIN_MASK),
                "sequence": header & SEQ_MASK,
            }
            try:
                fragment = self._reassemblers[direction].add(frame.payload)
            except TransportError as error:
                transport["problem"] = str(error)
                fragment = None
            if fragment is not None and len(fragment) >= 2:
                application = _application(fragment)
        entry_id, self._next = self._next, self._next + 1
        return Entry(
            id=entry_id,
            at=self._clock(),
            direction=direction,
            octets=link.build(frame.control, frame.destination, frame.source, frame.payload),
            link=described,
            transport=transport,
            application=application,
            summary=_summary(described, transport, application),
            connection=self._connection,
        )

    @property
    def last_id(self) -> int:
        """The id of the newest frame recorded, or 0 when none has been."""
        return self._next - 1

    def since(self, after: int = 0) -> list[Entry]:
        """Every entry kept whose id is greater than ``after``, oldest first."""
        return [entry for entry in self._entries if entry.id > after]

    def clear(self) -> None:
        """Forget the frames kept. Ids carry on from where they were."""
        self._entries.clear()

    def reset(self, *, local: Address | None = None, peer: Address | None = None) -> None:
        """Start a new connection: forget half a frame and half a fragment.

        Args:
            local: This master's address and port on the new connection.
            peer: The outstation's address and port.
        """
        self._readers = {SENT: link.FrameReader(), RECEIVED: link.FrameReader()}
        for reassembler in self._reassemblers.values():
            reassembler.reset()
        self._connection += 1
        # Keep the endpoints of the connections a kept frame crossed, and of
        # the new one, and no others. A connection that closed before any
        # frame would otherwise stay here for as long as the master runs.
        needed = {entry.connection for entry in self._entries}
        for connection in [number for number in self._endpoints if number not in needed]:
            del self._endpoints[connection]
        self._endpoints[self._connection] = (local, peer)

    def endpoints(self, connection: int) -> tuple[Address | None, Address | None]:
        """Return this master's and the outstation's address on a connection.

        Either is None where it is not known: for frames recorded before any
        connection, and for a connection whose addresses were not given.
        """
        return self._endpoints.get(connection, (None, None))

    def capture(self, *, after: int = 0, port: int = DNP3_PORT) -> bytes:
        """Return the frames kept as a pcap file.

        Args:
            after: Only frames whose id is greater.
            port: The outstation's port, for a connection whose addresses are
                not known.
        """
        capture = Capture()
        recorder = Recorder(capture, self, port=port)
        for entry in self.since(after):
            recorder.record(entry)
        recorder.close()
        return capture.pcap()

    def __len__(self) -> int:
        return len(self._entries)


#: Where a connection whose addresses are not known is placed in a capture.
PLACEHOLDER_ADDRESS = "127.0.0.1"

#: The first client port used for a connection whose own port is not known.
#: Each connection takes the next one, so each is a stream of its own.
PLACEHOLDER_PORT = 41000


class Recorder:
    """Write a trace's frames into a capture, one TCP connection per connection.

    Give :meth:`record` each entry in order, or add it to the trace's
    ``listeners`` to write frames as they are recorded. A connection's
    handshake is written before its first frame, and its FIN exchange when a
    frame of the next connection arrives or :meth:`close` is called, at the
    time of its last frame.

    A frame is one TCP segment. An address that is not IPv4, or that is not
    known, is written as ``127.0.0.1``; a port that is not known is ``port``
    for the outstation and one from 41000 up for the master.
    """

    def __init__(self, capture: Capture, trace: Trace, *, port: int = DNP3_PORT) -> None:
        """
        Args:
            capture: Where the packets go.
            trace: The trace the entries come from, for each connection's addresses.
            port: The outstation's port, for a connection whose addresses are
                not known.
        """
        self._capture = capture
        self._trace = trace
        self._port = port
        self._stream: Stream | None = None
        self._connection: int | None = None
        self._generation = capture.generation
        self._last = 0.0

    def record(self, entry: Entry) -> None:
        """Write one entry, opening a new connection first when it crossed one.

        Before each entry the capture may start a new file. A connection that
        was open in the old file then starts again with a handshake in the new
        one, so each file reads on its own. The old file has no FIN for it.
        """
        self._capture.boundary()
        if self._capture.generation != self._generation:
            self._generation = self._capture.generation
            self._stream = None
            self._connection = None
        if self._stream is None or entry.connection != self._connection:
            self.close()
            self._stream = self._open(entry.connection, entry.at)
            self._connection = entry.connection
        if entry.direction == SENT:
            self._stream.sent(entry.octets, entry.at)
        else:
            self._stream.received(entry.octets, entry.at)
        self._last = entry.at

    def close(self) -> None:
        """Write the FIN exchange of the open connection, if there is one.

        A connection opened in a file the capture has since rotated away from
        is forgotten instead: its FIN packets would land in the new file with
        no handshake before them.
        """
        if self._stream is not None and self._capture.generation == self._generation:
            self._stream.close(self._last)
        self._stream = None
        self._connection = None

    def abandon(self) -> None:
        """Forget the open connection without writing anything more."""
        self._stream = None
        self._connection = None

    def _open(self, connection: int, at: float) -> Stream:
        local, peer = self._trace.endpoints(connection)
        fallback = PLACEHOLDER_PORT + connection % (0x10000 - PLACEHOLDER_PORT)
        client = _address(local, fallback)
        server = _address(peer, self._port)
        stream = self._capture.stream(client=client, server=server)
        stream.open(at)
        return stream


def _address(given: Address | None, port: int) -> Address:
    if given is None:
        return PLACEHOLDER_ADDRESS, port
    host, known = given[0], given[1]
    return ipv4(host) or PLACEHOLDER_ADDRESS, known
