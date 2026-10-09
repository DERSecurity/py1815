"""Named ways the master breaks a protocol rule on purpose, for testing an outstation.

An evaluation tool has to be able to do the wrong thing and say exactly what it
did, so a test can see whether an outstation rejects what the standard says it
must. The certification procedures already send malformed frames to a session
in this process; this module gives each kind of misbehavior one name and one
implementation, usable over a socket against a device on a bench as well.

A deviation is applied to the octets the association produced, on their way to
the channel. The association's own code has no branch that does the wrong
thing, so the conformant path cannot be bent by a flag left on: with every
deviation off, :meth:`Deviations.outbound` returns what it was given,
unchanged. Each is off until it is turned on, and turning one on changes only
what the master sends, never what it expects back.

The frame-level deviations work on whole link frames, so they are built and
corrupted here rather than reaching into the association or the link layer.
Nothing here does I/O: a transform takes octets and returns octets, and is
tested against frames written out by hand.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

from dataclasses import dataclass

from py1815 import crc, link, transport

#: What an outbound write is: a request the master initiated, or a confirmation
#: it is sending in reply to something the outstation sent. A deviation names
#: which it acts on, because confirming wrongly and sending a bad request are
#: different faults.
REQUEST = "request"
CONFIRM = "confirm"
KINDS = (REQUEST, CONFIRM)

#: The highest value a frame's length octet can hold.
_MAX_LENGTH = 0xFF


def _split(octets: bytes) -> list[bytes]:
    """Split a run of octets into whole link frames, trusting their length octets.

    The association's output is well formed, so the length octet of each frame
    says where the next begins. A run that does not divide into frames is
    returned as one piece, so a deviation given something unexpected changes
    nothing it does not understand.
    """
    frames: list[bytes] = []
    offset = 0
    while offset + link.HEADER_SIZE <= len(octets):
        length = octets[offset + 2]
        user_data = length - link.MIN_LENGTH
        if user_data < 0:
            break
        size = link.frame_size(user_data)
        frame = octets[offset : offset + size]
        if len(frame) != size:
            break
        frames.append(frame)
        offset += size
    if offset != len(octets) or not frames:
        return [octets]
    return frames


def _rebuild(frame: bytes, payload: bytes) -> bytes:
    """Return ``frame`` with new user data, with every checksum recomputed.

    Used by the deviations that change the transport or application header,
    which sit inside the user data: the result is a frame whose checksums all
    verify and whose header does not, so what the deviation changed is the only
    thing wrong with it.
    """
    parsed = link.parse(frame)
    return link.build(parsed.control, parsed.destination, parsed.source, payload)


def corrupt_header_crc(frame: bytes) -> bytes:
    """Flip the frame's header checksum, so the outstation cannot trust the header."""
    return frame[:8] + bytes([frame[8] ^ 0xFF]) + frame[9:]


def corrupt_body_crc(frame: bytes) -> bytes:
    """Flip the checksum of the frame's last data block."""
    return frame[:-1] + bytes([frame[-1] ^ 0xFF])


def truncate(frame: bytes) -> bytes:
    """Drop the frame's last octet, so it is shorter than its length octet says."""
    return frame[:-1] if frame else frame


def overstate_length(frame: bytes) -> bytes:
    """Raise the length octet above the frame's real size, header checksum recomputed.

    The outstation reads a length its header checksum vouches for, then finds
    fewer octets than it was promised.
    """
    if len(frame) < link.HEADER_SIZE or frame[2] >= _MAX_LENGTH:
        return frame
    header = bytearray(frame[:8])
    header[2] = min(_MAX_LENGTH, header[2] + 16)
    return crc.encode(bytes(header)) + frame[link.HEADER_SIZE :]


def break_transport_sequence(frame: bytes) -> bytes:
    """Change the transport sequence number, so the segment lands out of order."""
    parsed = link.parse(frame)
    if not parsed.payload:
        return frame
    header = parsed.payload[0]
    sequence = (header + 1) % transport.SEQUENCE_MODULUS
    changed = (header & ~transport.SEQ_MASK) | sequence
    return _rebuild(frame, bytes([changed]) + parsed.payload[1:])


def orphan_segment(frame: bytes) -> bytes:
    """Clear the first-segment bit, so a lone segment looks like a continuation."""
    parsed = link.parse(frame)
    if not parsed.payload:
        return frame
    return _rebuild(frame, bytes([parsed.payload[0] & ~transport.FIR_MASK]) + parsed.payload[1:])


def wrong_application_sequence(frame: bytes) -> bytes:
    """Change the application sequence number of the fragment the frame carries.

    For a confirmation, this is confirming a sequence the outstation did not
    send, which must not retire the events it was waiting to have confirmed.
    """
    parsed = link.parse(frame)
    if len(parsed.payload) < 2:
        return frame
    control = parsed.payload[1]
    sequence = (control + 1) % 16
    changed = (control & 0xF0) | sequence
    return _rebuild(frame, parsed.payload[:1] + bytes([changed]) + parsed.payload[2:])


@dataclass
class Deviations:
    """The deviations a master has turned on, and the transform they make.

    Off by default. :meth:`outbound` is called with the octets the association
    produced and returns the octets to send in their place: the same octets
    when nothing is on, a corrupted frame, the request twice, or nothing at
    all.
    """

    #: Send nothing at all, in either direction.
    silence: bool = False
    #: Send each request twice, octet for octet.
    repeat_request: bool = False
    #: Flip the header checksum of each request frame.
    corrupt_header_crc: bool = False
    #: Flip a data-block checksum of each request frame.
    corrupt_body_crc: bool = False
    #: Drop the last octet of each request frame.
    truncate: bool = False
    #: Claim a length larger than the request frame carries.
    overstate_length: bool = False
    #: Send each request with its transport sequence number out of order.
    break_transport_sequence: bool = False
    #: Send each request as a continuation segment with no first segment.
    orphan_segment: bool = False
    #: Withhold every confirmation the master would send.
    withhold_confirmation: bool = False
    #: Confirm a sequence number the outstation did not send.
    wrong_confirmation_sequence: bool = False

    #: Deviations that act on a request the master initiated.
    _ON_REQUEST = (
        "corrupt_header_crc",
        "corrupt_body_crc",
        "truncate",
        "overstate_length",
        "break_transport_sequence",
        "orphan_segment",
    )
    #: Deviations that act on a confirmation the master sends in reply.
    _ON_CONFIRM = ("withhold_confirmation", "wrong_confirmation_sequence")

    @classmethod
    def names(cls) -> tuple[str, ...]:
        """Every deviation's name, in the order they are listed."""
        return (
            "silence",
            "repeat_request",
            *cls._ON_REQUEST,
            *cls._ON_CONFIRM,
        )

    def any_on(self) -> bool:
        """Whether any deviation is on."""
        return any(getattr(self, name) for name in self.names())

    def on(self) -> tuple[str, ...]:
        """The names of the deviations that are on, in order."""
        return tuple(name for name in self.names() if getattr(self, name))

    def set(self, name: str, state: bool) -> None:
        """Turn a deviation on or off by name. Raises ``ValueError`` for an unknown name."""
        if name not in self.names():
            raise ValueError(f"{name!r} is not a deviation; one of {', '.join(self.names())}")
        setattr(self, name, bool(state))

    def clear(self) -> None:
        """Turn every deviation off."""
        for name in self.names():
            setattr(self, name, False)

    def describe(self) -> dict[str, bool]:
        """Every deviation and whether it is on, as a JSON-compatible dict."""
        return {name: bool(getattr(self, name)) for name in self.names()}

    def outbound(self, octets: bytes, *, kind: str) -> list[bytes]:
        """Return the frames to send in place of ``octets``.

        ``kind`` is :data:`REQUEST` or :data:`CONFIRM`. The list is empty when
        the master is to send nothing, holds the octets twice for a repeated
        request, and otherwise holds one frame, changed or unchanged. With
        every deviation off it is ``[octets]``.
        """
        if kind not in KINDS:
            raise ValueError(f"{kind!r} is not an outbound kind; one of {', '.join(KINDS)}")
        if self.silence:
            return []
        if kind == CONFIRM:
            if self.withhold_confirmation:
                return []
            if self.wrong_confirmation_sequence:
                return [self._each(octets, wrong_application_sequence)]
            return [octets]
        changed = octets
        for name in self._ON_REQUEST:
            if getattr(self, name):
                changed = self._each(changed, globals()[name])
        if self.repeat_request:
            return [changed, changed]
        return [changed]

    @staticmethod
    def _each(octets: bytes, transform: object) -> bytes:
        """Apply a frame transform to the first frame of a request, the rest unchanged.

        A request is almost always one frame; a long one is several, and the
        deviation changes the first, which is where a transport or header fault
        is seen first.
        """
        frames = _split(octets)
        frames[0] = transform(frames[0])  # type: ignore[operator]
        return b"".join(frames)


__all__ = [
    "CONFIRM",
    "KINDS",
    "REQUEST",
    "Deviations",
    "break_transport_sequence",
    "corrupt_body_crc",
    "corrupt_header_crc",
    "orphan_segment",
    "overstate_length",
    "truncate",
    "wrong_application_sequence",
]
