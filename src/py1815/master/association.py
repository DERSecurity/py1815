"""One master association: octets in, octets out.

The mirror of :mod:`py1815.session`. It holds what is true of a conversation
with one outstation, seen from the master's end: the request that is
outstanding, the fragments of its response so far, the sequence numbers of the
two series, and what arrived that nobody asked for. It does no I/O and starts
no timer. Its owner hands it the octets that arrived and writes the octets it
returns, and time is a clock that is read when a method is called.

That is what lets a test drive it against a :class:`~py1815.session.Session`
in one process, through as much protocol time as it likes, with no socket and
no sleep.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from py1815 import link
from py1815.application import (
    IIN,
    SEQUENCE_MODULUS,
    FunctionCode,
    Response,
    ResponseError,
    build_confirm,
    build_request,
    parse_response,
)
from py1815.decode import Decoded, DecodedObject, decode_objects
from py1815.transport import SEQUENCE_MODULUS as TRANSPORT_SEQUENCE_MODULUS
from py1815.transport import Reassembler, TransportError, segment

logger = logging.getLogger(__name__)

#: Seconds to wait for a response, or for the next fragment of one.
DEFAULT_RESPONSE_TIMEOUT = 5.0


class Busy(RuntimeError):
    """A request was made while another was still waiting for its response.

    Misuse and not a protocol outcome: one association carries one request at
    a time, and its owner is what makes a second one wait.
    """


class Outcome(Enum):
    """How an exchange ended."""

    #: The response arrived, to its final fragment.
    COMPLETE = "complete"
    #: Nothing more arrived in time. Whatever did arrive is still in the result.
    TIMEOUT = "timeout"
    #: The request was one that takes no response, and was sent.
    SENT = "sent"
    #: The connection was reset while the request was outstanding.
    ABANDONED = "abandoned"


@dataclass(frozen=True)
class Exchange:
    """One request and everything that came back for it.

    A timeout and an error indication are results, not exceptions: what an
    outstation did with a request is the thing a caller asked to know.
    """

    function: FunctionCode
    sequence: int
    #: The request fragment, as sent.
    request: bytes
    outcome: Outcome
    #: Each response fragment, in the order received.
    fragments: tuple[Response, ...] = ()
    #: The objects of every fragment, in the order sent.
    objects: tuple[DecodedObject, ...] = ()
    #: Fragments whose objects could not all be read, each with the reason
    #: and the octets left unread.
    undecoded: tuple[Decoded, ...] = ()
    #: Seconds from the request being built to the exchange ending.
    elapsed: float = 0.0

    @property
    def complete(self) -> bool:
        return self.outcome is Outcome.COMPLETE

    @property
    def iin(self) -> IIN | None:
        """The indications of the last fragment received, or None if none was."""
        return self.fragments[-1].iin if self.fragments else None


@dataclass(frozen=True)
class Unsolicited:
    """An unsolicited response, as received."""

    response: Response
    objects: tuple[DecodedObject, ...]
    undecoded: Decoded | None = None

    @property
    def iin(self) -> IIN:
        return self.response.iin

    @property
    def null(self) -> bool:
        """Whether it carried no objects: the announcement of a restart."""
        return not self.response.body


@dataclass
class _Pending:
    function: FunctionCode
    sequence: int
    request: bytes
    started: float
    #: When the wait for the next fragment ends.
    deadline: float
    fragments: list[Response] = field(default_factory=list)
    objects: list[DecodedObject] = field(default_factory=list)
    undecoded: list[Decoded] = field(default_factory=list)
    #: The application sequence number the next fragment has to carry.
    expected: int = 0


#: Requests that are answered by silence. Sending one completes the exchange.
NO_RESPONSE_FUNCTIONS = frozenset(
    {
        FunctionCode.CONFIRM,
        FunctionCode.DIRECT_OPERATE_NR,
        FunctionCode.IMMED_FREEZE_NR,
        FunctionCode.FREEZE_CLEAR_NR,
        FunctionCode.FREEZE_AT_TIME_NR,
    }
)


class MasterAssociation:
    """The master's side of one conversation with one outstation.

    Driven by three calls. :meth:`request` returns the octets of a request to
    send. :meth:`receive` takes what arrived and returns what to send back,
    which is a confirmation or nothing. :meth:`expire` is called when the time
    :meth:`expires_after` gave has passed, and ends an exchange that is not
    going to finish. A finished exchange is collected with :meth:`take`, and
    unsolicited responses with :meth:`take_unsolicited`.
    """

    def __init__(
        self,
        *,
        outstation_address: int = 1024,
        master_address: int = 1,
        response_timeout: float = DEFAULT_RESPONSE_TIMEOUT,
        confirm: bool = True,
        max_fragment: int = 2048,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """
        Args:
            outstation_address: The link address of the outstation spoken to.
                A frame from any other source is dropped.
            master_address: This master's own link address.
            response_timeout: Seconds to wait for a response, and then for
                each further fragment of one that is not finished.
            confirm: Whether a fragment that asks to be confirmed is. Turn it
                off to drive an outstation by hand: nothing is then sent that
                the caller did not ask for, and :meth:`confirm` sends one.
            max_fragment: The largest response fragment that will be
                reassembled, in octets.
            clock: A monotonic clock in seconds.
        """
        for name, address in (
            ("outstation_address", outstation_address),
            ("master_address", master_address),
        ):
            if not link.is_valid_address(address):
                raise ValueError(
                    f"{name} is {address}; a device address is 0 to {link.MAX_ADDRESS}"
                )
        if outstation_address == master_address:
            raise ValueError(
                f"outstation_address and master_address are both {master_address}; "
                "the two ends of an association have different addresses"
            )
        if not response_timeout > 0:
            raise ValueError(f"response_timeout is {response_timeout}; it is a wait")
        self._outstation_address = outstation_address
        self._master_address = master_address
        self._response_timeout = response_timeout
        self._confirm = confirm
        self._clock = clock
        self._frames = link.FrameReader()
        self._reassembler = Reassembler(max_fragment=max_fragment)
        #: The next request's application sequence number.
        self._sequence = 0
        #: The transport sequence number the next segment sent takes.
        self._transport_sequence = 0
        self._pending: _Pending | None = None
        self._finished: Exchange | None = None
        self._unsolicited: list[Unsolicited] = []
        #: The last unsolicited fragment, octet for octet, for telling one
        #: sent again from one that is new.
        self._last_unsolicited: bytes | None = None

    # ------------------------------------------------------------ properties

    @property
    def outstation_address(self) -> int:
        return self._outstation_address

    @property
    def master_address(self) -> int:
        return self._master_address

    @property
    def busy(self) -> bool:
        """Whether a request is waiting for its response."""
        return self._pending is not None

    # --------------------------------------------------------------- sending

    def request(self, function: FunctionCode, body: bytes = b"") -> bytes:
        """Begin an exchange, and return the octets that carry its request.

        Raises :class:`Busy` while another request is outstanding, and while
        a finished exchange has not been collected with :meth:`take`: the
        result of one request is not overwritten by the next.
        """
        if self._pending is not None:
            raise Busy(f"{self._pending.function.name} is still waiting for its response")
        if self._finished is not None:
            raise Busy("the last exchange has not been taken")
        sequence = self._sequence
        self._sequence = (sequence + 1) % SEQUENCE_MODULUS
        fragment = build_request(function, sequence=sequence, body=body)
        now = self._clock()
        if function in NO_RESPONSE_FUNCTIONS:
            self._finished = Exchange(function, sequence, fragment, Outcome.SENT)
        else:
            self._pending = _Pending(
                function=function,
                sequence=sequence,
                request=fragment,
                started=now,
                deadline=now + self._response_timeout,
                expected=sequence,
            )
        return self._send(fragment)

    def confirm(self, response: Response) -> bytes:
        """The octets that confirm a response fragment, for an owner that
        turned automatic confirmation off."""
        return self._send(
            build_confirm(sequence=response.control.sequence, unsolicited=response.unsolicited)
        )

    def _send(self, fragment: bytes) -> bytes:
        control = link.control_byte(
            from_master=True, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
        )
        out = bytearray()
        segments = segment(fragment, first_sequence=self._transport_sequence)
        self._transport_sequence = (
            self._transport_sequence + len(segments)
        ) % TRANSPORT_SEQUENCE_MODULUS
        for tpdu in segments:
            out += link.build(
                control,
                destination=self._outstation_address,
                source=self._master_address,
                payload=tpdu,
            )
        return bytes(out)

    # ------------------------------------------------------------- receiving

    def receive(self, data: bytes) -> bytes:
        """Take octets from the outstation, and return octets to send back."""
        out = bytearray()
        for frame in self._frames.feed(data):
            out += self._handle_frame(frame)
        return bytes(out)

    def _handle_frame(self, frame: link.LinkFrame) -> bytes:
        if frame.destination != self._master_address:
            logger.debug("dnp3 master: frame for %d is not ours", frame.destination)
            return b""
        if frame.source != self._outstation_address:
            logger.warning(
                "dnp3 master: dropping frame from unexpected outstation address %d", frame.source
            )
            return b""
        if frame.from_master:
            logger.warning("dnp3 master: dropping a frame marked as sent by a master")
            return b""
        if not frame.is_primary:
            # An answer to a link request. This master sends user data that
            # asks for no link acknowledgment, so there is nothing to match.
            return b""

        function = frame.function
        if function == link.PrimaryFunction.UNCONFIRMED_USER_DATA:
            return self._handle_segment(frame.payload)
        if function == link.PrimaryFunction.CONFIRMED_USER_DATA:
            # Acknowledged and taken. A frame sent again because the
            # acknowledgment was lost carries a fragment already taken, and
            # the rules for fragments below drop it: a response nothing is
            # waiting for, or an unsolicited one repeated octet for octet.
            return self._link_reply(link.SecondaryFunction.ACK) + self._handle_segment(
                frame.payload
            )
        if function in (
            link.PrimaryFunction.RESET_LINK_STATES,
            link.PrimaryFunction.TEST_LINK_STATES,
        ):
            return self._link_reply(link.SecondaryFunction.ACK)
        if function == link.PrimaryFunction.REQUEST_LINK_STATUS:
            return self._link_reply(link.SecondaryFunction.LINK_STATUS)
        return self._link_reply(link.SecondaryFunction.NOT_SUPPORTED)

    def _link_reply(self, function: link.SecondaryFunction) -> bytes:
        control = link.control_byte(from_master=True, primary=False, function=function)
        return link.build(
            control, destination=self._outstation_address, source=self._master_address
        )

    def _handle_segment(self, tpdu: bytes) -> bytes:
        try:
            fragment = self._reassembler.add(tpdu)
        except TransportError as exc:
            logger.warning("dnp3 master: transport error: %s", exc)
            return b""
        if fragment is None:
            return b""
        return self._handle_fragment(fragment)

    def _handle_fragment(self, fragment: bytes) -> bytes:
        try:
            response = parse_response(fragment)
        except ResponseError as exc:
            logger.warning("dnp3 master: fragment dropped: %s", exc)
            return b""
        if response.unsolicited:
            return self._handle_unsolicited(response, fragment)
        return self._handle_solicited(response)

    def _handle_unsolicited(self, response: Response, fragment: bytes) -> bytes:
        # An unsolicited response is one fragment, complete in itself.
        if not (response.control.fir and response.control.fin):
            logger.warning("dnp3 master: unsolicited response that is not one fragment dropped")
            return b""
        if fragment == self._last_unsolicited:
            # The same octets under the same sequence number: the outstation
            # did not see the confirmation and sent it again. Confirmed again
            # and not delivered again.
            logger.info("dnp3 master: unsolicited response repeated; confirmed again")
        else:
            self._last_unsolicited = bytes(fragment)
            decoded = decode_objects(response.body)
            self._unsolicited.append(
                Unsolicited(response, decoded.objects, None if decoded.complete else decoded)
            )
        if response.control.con and self._confirm:
            return self.confirm(response)
        return b""

    def _handle_solicited(self, response: Response) -> bytes:
        pending = self._pending
        if pending is None:
            logger.info(
                "dnp3 master: response with sequence %d and nothing outstanding; dropped",
                response.control.sequence,
            )
            return b""
        first = not pending.fragments
        if response.control.fir != first or response.control.sequence != pending.expected:
            # Not the fragment this exchange is waiting for: a late answer to
            # a request already given up on, or a series out of order. It is
            # not confirmed, since confirming it would retire events this
            # master never read.
            logger.warning(
                "dnp3 master: fragment with sequence %d%s is not the one awaited (%d%s); dropped",
                response.control.sequence,
                " first" if response.control.fir else "",
                pending.expected,
                " first" if first else "",
            )
            return b""

        decoded = decode_objects(response.body)
        pending.fragments.append(response)
        pending.objects.extend(decoded.objects)
        if not decoded.complete:
            pending.undecoded.append(decoded)
        now = self._clock()
        out = b""
        if response.control.con and self._confirm:
            out = self.confirm(response)
        if response.control.fin:
            self._finish(Outcome.COMPLETE, now)
        else:
            pending.expected = (response.control.sequence + 1) % SEQUENCE_MODULUS
            pending.deadline = now + self._response_timeout
        return out

    # ------------------------------------------------------------------ time

    def expires_after(self) -> float | None:
        """Seconds until the outstanding request times out, or None if none is."""
        if self._pending is None:
            return None
        return max(0.0, self._pending.deadline - self._clock())

    def expire(self) -> bool:
        """End the outstanding exchange if its time has passed. Says whether it did."""
        pending = self._pending
        if pending is None:
            return False
        now = self._clock()
        if now < pending.deadline:
            return False
        logger.info(
            "dnp3 master: %s timed out after %d fragment(s)",
            pending.function.name,
            len(pending.fragments),
        )
        self._finish(Outcome.TIMEOUT, now)
        return True

    def give_up(self) -> bool:
        """End the outstanding exchange now, as a timeout. Says whether one was.

        For an owner that knows nothing more is coming without waiting to find
        out: one wired straight to a session in the same process, where an
        outstation that has not answered by the time the call returns is not
        going to.
        """
        if self._pending is None:
            return False
        self._finish(Outcome.TIMEOUT, self._clock())
        return True

    def _finish(self, outcome: Outcome, now: float) -> None:
        pending = self._pending
        assert pending is not None
        self._pending = None
        self._finished = Exchange(
            function=pending.function,
            sequence=pending.sequence,
            request=pending.request,
            outcome=outcome,
            fragments=tuple(pending.fragments),
            objects=tuple(pending.objects),
            undecoded=tuple(pending.undecoded),
            elapsed=now - pending.started,
        )

    # --------------------------------------------------------------- results

    def take(self) -> Exchange | None:
        """The exchange that finished, once. None while it has not."""
        finished, self._finished = self._finished, None
        return finished

    def take_unsolicited(self) -> list[Unsolicited]:
        """The unsolicited responses received since this was last called."""
        received, self._unsolicited = self._unsolicited, []
        return received

    def connection_reset(self) -> None:
        """Forget what a dead connection left behind.

        Half a frame and half a fragment mean nothing to the connection that
        replaces the one they arrived on. A request that was outstanding is
        ended as abandoned: its response, if one was coming, went with the
        connection. The sequence numbers carry on, since they belong to the
        association and not to the socket.
        """
        self._frames = link.FrameReader()
        self._reassembler.reset()
        self._last_unsolicited = None
        if self._pending is not None:
            self._finish(Outcome.ABANDONED, self._clock())


__all__ = [
    "DEFAULT_RESPONSE_TIMEOUT",
    "NO_RESPONSE_FUNCTIONS",
    "Busy",
    "Exchange",
    "MasterAssociation",
    "Outcome",
    "Unsolicited",
]
