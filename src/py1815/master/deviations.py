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

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

from py1815 import crc, link, transport
from py1815.application import UNS_MASK, FunctionCode

#: What an outbound write is: a request the master initiated, or a confirmation
#: it is sending in reply to something the outstation sent. A deviation names
#: which it acts on, because confirming wrongly and sending a bad request are
#: different faults.
REQUEST = "request"
CONFIRM = "confirm"
KINDS = (REQUEST, CONFIRM)

#: The highest value a frame's length octet can hold.
_MAX_LENGTH = 0xFF

#: Confirmations ``late_confirmation`` holds back before the oldest is dropped.
#: A response is confirmed once and the next request sends what is held, so
#: more than a few are held only when something is wrong.
HELD_CONFIRMATIONS = 8

#: What a frame confirms, when it carries an application confirmation.
_SOLICITED, _UNSOLICITED = "solicited", "unsolicited"


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
    which sit inside the user data. Every checksum of the result verifies, so
    the changed header is the only thing wrong with the frame.
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
    """Make the length octet describe more user data than the frame carries.

    The length octet is raised and the header checksum recomputed, so the
    outstation reads a length its header checksum vouches for, then finds
    fewer octets than it was promised. A length octet already at its highest
    value cannot be raised, so that frame loses its last data block and keeps
    its header as built.
    """
    if len(frame) < link.HEADER_SIZE:
        return frame
    if frame[2] >= _MAX_LENGTH:
        block = link.DATA_BLOCK_SIZE + crc.SIZE
        return frame[: -((len(frame) - link.HEADER_SIZE) % block or block)]
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


def endless_series(frame: bytes) -> bytes:
    """Clear the final-segment bit, so the series the segment belongs to never ends.

    The outstation is left assembling a fragment whose last segment does not
    come. A new first segment ends that (IEEE 1815-2012 8.2.4, Table 8-1).
    """
    parsed = link.parse(frame)
    if not parsed.payload:
        return frame
    return _rebuild(frame, bytes([parsed.payload[0] & ~transport.FIN_MASK]) + parsed.payload[1:])


def second_master_address(frame: bytes) -> bytes:
    """Change the frame's source address to another master's, header checksum recomputed.

    The address is the next one above the master's own that is a station
    address and is not the outstation's. Whether an outstation answers a
    master it was not told of is its own choice, which its Device Profile
    states, so a response to this is addressed to that other master.
    """
    if len(frame) < link.HEADER_SIZE:
        return frame
    destination = int.from_bytes(frame[4:6], "little")
    source = int.from_bytes(frame[6:8], "little")
    other = next(
        candidate
        for candidate in (source + 1, source + 2, source - 1, source - 2)
        if link.is_valid_address(candidate) and candidate != destination
    )
    return crc.encode(frame[:6] + other.to_bytes(2, "little")) + frame[link.HEADER_SIZE :]


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


def _confirms(frame: bytes) -> str | None:
    """Return which kind of response a link frame confirms, or None when it confirms none.

    The association can answer one frame with a link-layer reply and an
    application confirmation together. A frame with no user data, or with
    another function code after its transport and application control octets,
    is not a confirmation. The UNS bit of the application control octet says
    that the response confirmed was unsolicited.
    """
    try:
        payload = link.parse(frame).payload
    except link.LinkFrameError:
        return None
    if len(payload) < 3 or payload[2] != FunctionCode.CONFIRM:
        return None
    return _UNSOLICITED if payload[1] & UNS_MASK else _SOLICITED


#: Which frames of a request a deviation changes.
_FIRST, _LAST, _EVERY = "first", "last", "every"

#: The deviations that change a request frame, in the order they are applied
#: when several are on, and the frames each changes. The ones that rewrite the
#: transport header parse the frame, so they run while its checksums still
#: verify. The header checksum is flipped last, after the deviations that
#: recompute it.
_REQUEST_TRANSFORMS: tuple[tuple[str, Callable[[bytes], bytes], str], ...] = (
    ("break_transport_sequence", break_transport_sequence, _FIRST),
    ("orphan_segment", orphan_segment, _FIRST),
    ("endless_series", endless_series, _LAST),
    ("second_master_address", second_master_address, _EVERY),
    ("overstate_length", overstate_length, _FIRST),
    ("corrupt_body_crc", corrupt_body_crc, _FIRST),
    ("truncate", truncate, _FIRST),
    ("corrupt_header_crc", corrupt_header_crc, _FIRST),
)


@dataclass
class Deviations:
    """The deviations a master has turned on, and the transform they make.

    Off by default. :meth:`outbound` is called with the octets the association
    produced and returns the writes to make in their place: the same octets
    when nothing is on, a corrupted frame, the request twice, or nothing at
    all.
    """

    #: Send nothing at all, in either direction.
    silence: bool = False
    #: Send each request twice, octet for octet.
    repeat_request: bool = False
    #: Send every frame from another master's address.
    second_master_address: bool = False
    #: Flip the header checksum of the first frame of each request.
    corrupt_header_crc: bool = False
    #: Flip the last data-block checksum of the first frame of each request.
    corrupt_body_crc: bool = False
    #: Drop the last octet of the first frame of each request.
    truncate: bool = False
    #: Claim a length larger than the first frame of each request carries.
    overstate_length: bool = False
    #: Send the first segment of each request with a transport sequence
    #: number that is out of order.
    break_transport_sequence: bool = False
    #: Send the first segment of each request as a continuation, so the
    #: request has no first segment.
    orphan_segment: bool = False
    #: Send the last segment of each request with its final bit clear, so
    #: the series never ends.
    endless_series: bool = False
    #: Withhold the confirmation of every solicited response.
    withhold_confirmation: bool = False
    #: Send the confirmation of each solicited response after the master's
    #: next request, and not when the response arrives.
    late_confirmation: bool = False
    #: Confirm a solicited response with a sequence number the outstation did
    #: not send.
    wrong_confirmation_sequence: bool = False
    #: Withhold the confirmation of every unsolicited response.
    withhold_unsolicited_confirmation: bool = False

    #: Confirmations held back by ``late_confirmation`` until the next request.
    _held: deque[bytes] = field(
        default_factory=lambda: deque(maxlen=HELD_CONFIRMATIONS),
        init=False,
        repr=False,
        compare=False,
    )

    #: Deviations that act on a request the master initiated.
    _ON_REQUEST = (
        "corrupt_header_crc",
        "corrupt_body_crc",
        "truncate",
        "overstate_length",
        "break_transport_sequence",
        "orphan_segment",
        "endless_series",
    )
    #: Deviations that act on a confirmation the master sends in reply.
    _ON_CONFIRM = (
        "withhold_confirmation",
        "late_confirmation",
        "wrong_confirmation_sequence",
        "withhold_unsolicited_confirmation",
    )

    @classmethod
    def names(cls) -> tuple[str, ...]:
        """Every deviation's name, in the order they are listed."""
        return (
            "silence",
            "repeat_request",
            "second_master_address",
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
        """Turn every deviation off, and forget any confirmation held back."""
        for name in self.names():
            setattr(self, name, False)
        self._held.clear()

    def describe(self) -> dict[str, bool]:
        """Every deviation and whether it is on, as a JSON-compatible dict."""
        return {name: bool(getattr(self, name)) for name in self.names()}

    def outbound(self, octets: bytes, *, kind: str) -> list[bytes]:
        """Return the writes to make in place of ``octets``.

        ``kind`` is :data:`REQUEST` or :data:`CONFIRM`. The list is empty when
        the master is to send nothing, and is ``[octets]`` with every
        deviation off. A deviation that changes a frame returns each link
        frame as a write of its own, so a trace can keep the changed frame
        apart from the others. A request deviation changes the first frame,
        except ``endless_series``, which changes the last, and
        ``second_master_address``, which changes every frame. A confirmation
        deviation acts on each frame that carries an application confirmation
        of the kind it names, solicited or unsolicited, and leaves the other
        kind and a link-layer reply as built. A repeated request holds its
        writes twice. A confirmation held back by ``late_confirmation``
        follows the next request.
        """
        if kind not in KINDS:
            raise ValueError(f"{kind!r} is not an outbound kind; one of {', '.join(KINDS)}")
        if not self.late_confirmation:
            # A confirmation held while the deviation was on is not sent once it is off.
            self._held.clear()
        if self.silence:
            return []
        if kind == CONFIRM:
            return self._confirmation(octets)
        changes = [
            (transform, which)
            for name, transform, which in _REQUEST_TRANSFORMS
            if getattr(self, name)
        ]
        writes = self._change(octets, changes) if changes else [octets]
        if self.repeat_request:
            writes = writes * 2
        if self._held:
            writes = writes + list(self._held)
            self._held.clear()
        return writes

    def _confirmation(self, octets: bytes) -> list[bytes]:
        """Return the writes to make in place of what the association sends in reply."""
        deviating = (
            self.withhold_confirmation
            or self.late_confirmation
            or self.wrong_confirmation_sequence
            or self.withhold_unsolicited_confirmation
            or self.second_master_address
        )
        if not deviating:
            return [octets]
        writes = []
        for frame in _split(octets):
            if self.second_master_address:
                frame = second_master_address(frame)
            confirmed = _confirms(frame)
            if confirmed is None:
                # A link-layer reply sent with the confirmation is not a
                # confirmation, and is sent as built.
                writes.append(frame)
                continue
            if confirmed == _UNSOLICITED:
                # The other confirmation deviations are about a response the
                # master asked for, and leave this confirmation as built.
                if not self.withhold_unsolicited_confirmation:
                    writes.append(frame)
                continue
            if self.withhold_confirmation:
                continue
            if self.wrong_confirmation_sequence:
                frame = wrong_application_sequence(frame)
            if self.late_confirmation:
                self._held.append(frame)
            else:
                writes.append(frame)
        return writes

    @staticmethod
    def _change(octets: bytes, changes: list[tuple[Callable[[bytes], bytes], str]]) -> list[bytes]:
        """Return the link frames of ``octets``, changed by each transform in turn.

        A request is almost always one frame. A long request is several, and
        a deviation changes the first, which is where a transport or header
        fault is seen first, unless it is one that names the last frame or
        every frame.
        """
        frames = _split(octets)
        for transform, which in changes:
            if which == _EVERY:
                frames = [transform(frame) for frame in frames]
            else:
                position = 0 if which == _FIRST else -1
                frames[position] = transform(frames[position])
        return frames


__all__ = [
    "CONFIRM",
    "HELD_CONFIRMATIONS",
    "KINDS",
    "REQUEST",
    "Deviations",
    "break_transport_sequence",
    "corrupt_body_crc",
    "corrupt_header_crc",
    "endless_series",
    "orphan_segment",
    "overstate_length",
    "second_master_address",
    "truncate",
    "wrong_application_sequence",
]
