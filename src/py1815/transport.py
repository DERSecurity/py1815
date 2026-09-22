"""The DNP3 transport function: one application fragment across several frames.

The smallest layer in the protocol -- a single octet of header carrying FIR, FIN
and a six-bit sequence number -- and the one with the most ways to be subtly
wrong, because every rule it enforces is about what to do with a series that did
not arrive as promised.

Segmentation is deterministic and reassembly is suspicious. A receiver that
accepted segments in any order, or kept accumulating them, would hand the
application layer fragments assembled out of two different requests, or hold
memory for a series whose sender has gone away.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

FIN_MASK = 0x80
FIR_MASK = 0x40
SEQ_MASK = 0x3F

#: Sequence numbers wrap at 64.
SEQUENCE_MODULUS = SEQ_MASK + 1

#: A segment is the header octet plus its payload, and fits one link frame's
#: user data.
MAX_SEGMENT = 250
MAX_PAYLOAD = MAX_SEGMENT - 1

#: Octets a reassembly may accumulate before it is abandoned. Matches the
#: reference implementation's default receive buffer: large enough for any
#: request this outstation answers, small enough that an endless series of
#: non-final segments costs little.
DEFAULT_MAX_FRAGMENT = 2048


class TransportError(Exception):
    """A segment that breaks a rule of the transport function.

    Raised rather than swallowed so the session can report it. Every case leaves
    the reassembler empty: a series that broke its own sequence cannot be
    continued, and continuing it is how two requests become one fragment.
    """


def header_byte(*, first: bool, final: bool, sequence: int) -> int:
    """Assemble a transport header octet."""
    header = sequence % SEQUENCE_MODULUS
    if first:
        header |= FIR_MASK
    if final:
        header |= FIN_MASK
    return header


def segment(fragment: bytes, *, first_sequence: int = 0) -> list[bytes]:
    """Split an application fragment into segments, in the order they are sent.

    An empty fragment still produces one segment. It is a legal thing to send --
    a response can carry a header and no objects -- and returning nothing would
    silently drop it.
    """
    chunks = [fragment[i : i + MAX_PAYLOAD] for i in range(0, len(fragment), MAX_PAYLOAD)] or [b""]
    segments = []
    for index, chunk in enumerate(chunks):
        header = header_byte(
            first=index == 0,
            final=index == len(chunks) - 1,
            sequence=first_sequence + index,
        )
        segments.append(bytes([header]) + chunk)
    return segments


class Reassembler:
    """Collects segments into application fragments."""

    def __init__(self, *, max_fragment: int = DEFAULT_MAX_FRAGMENT) -> None:
        self._max_fragment = max_fragment
        self._buffer = bytearray()
        self._expected: int | None = None

    @property
    def in_progress(self) -> bool:
        return self._expected is not None

    def reset(self) -> None:
        """Abandon any partial fragment.

        The session calls this when the association restarts: segments from
        before a link reset must not be completed by segments from after one.
        """
        self._buffer = bytearray()
        self._expected = None

    def add(self, tpdu: bytes) -> bytes | None:
        """Accept one segment, returning the fragment it completed, if any."""
        # Reset before refusing, not after. These two checks fire before any
        # state is touched, and leaving a partial series in place let the next
        # segment carrying the expected sequence append to data from before the
        # malformed one -- splicing two requests into one fragment, which is
        # exactly what the rest of this class exists to prevent.
        if not tpdu:
            self.reset()
            raise TransportError("segment is empty")
        if len(tpdu) > MAX_SEGMENT:
            self.reset()
            raise TransportError(f"segment is {len(tpdu)} octets, and the maximum is {MAX_SEGMENT}")

        header = tpdu[0]
        first = bool(header & FIR_MASK)
        final = bool(header & FIN_MASK)
        sequence = header & SEQ_MASK
        payload = tpdu[1:]

        if first:
            # A FIR arriving mid-series is not an error: it is the sender
            # starting again, which is exactly what it does after a timeout.
            # Anything already held belongs to the abandoned series.
            self._buffer = bytearray()
        else:
            if self._expected is None:
                self.reset()
                raise TransportError("segment continues a series that was never started")
            if sequence != self._expected:
                expected = self._expected
                self.reset()
                raise TransportError(f"segment sequence is {sequence}, and {expected} was expected")

        if len(self._buffer) + len(payload) > self._max_fragment:
            self.reset()
            raise TransportError(f"fragment exceeds {self._max_fragment} octets and was abandoned")

        self._buffer += payload
        if final:
            fragment = bytes(self._buffer)
            self.reset()
            return fragment

        self._expected = (sequence + 1) % SEQUENCE_MODULUS
        return None
