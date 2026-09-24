"""One master association: octets in, octets out, no socket in sight.

The session owns everything that is true of a conversation rather than of a
frame -- which master it is talking to, where the transport reassembly has got
to, whether the restart indication is still outstanding -- and it owns it per
association rather than per connection, because that is what DNP3 state belongs
to.

Kept free of I/O on purpose. :meth:`Session.receive` takes the octets that
arrived and returns the octets to send, so every rule below is testable against
literal frames with no listener, no TLS and no event loop.

**What it refuses, it refuses out loud.** A control function gets a response
carrying IIN2.1 rather than silence, because a master that times out learns
nothing and retries.

The exceptions are the function codes IEEE 1815-2012 Table 4-2 defines as taking
no reply, each described there as "same as function code N but outstation shall
not send a response". They are dropped and reported in the log rather than
answered, and they are recognized from the function code octet before the
fragment is parsed, because a master that asked for no response is not listening
for a parse error either. A refusal contract written only in terms of returned
statuses would leave the functions that return nothing as the ones an
implementation executes by omission.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Protocol

from py1815 import link
from py1815.application import (
    IIN,
    REQUEST_HEADER_SIZE,
    AppControl,
    FunctionCode,
    IIN2Bit,
    IINBit,
    ObjectHeader,
    QualifierCode,
    Request,
    RequestError,
    build_response,
    null_response,
    parse_request,
)
from py1815.transport import Reassembler, TransportError, segment

logger = logging.getLogger(__name__)

#: Group 80 variation 1, index 7: the internal indication a master writes to
#: clear the restart bit. Fixed by the standard rather than by the point map,
#: which is why it is the one write a read-only outstation still honors -- an
#: outstation that never cleared it would flag every response it ever sent.
RESTART_GROUP = 80
RESTART_VARIATION = 1
RESTART_INDEX = 7

#: Controls, which this outstation does not hold the role to execute.
_CONTROL_FUNCTIONS = frozenset(
    {
        FunctionCode.SELECT,
        FunctionCode.OPERATE,
        FunctionCode.DIRECT_OPERATE,
        FunctionCode.DIRECT_OPERATE_NR,
    }
)

#: The function codes IEEE 1815-2012 Table 4-2 defines as taking no reply, each
#: described there as "same as function code N but outstation shall not send a
#: response". The obligation is on the function code rather than on whether the
#: outstation implements what was asked: a master that sent one of these is not
#: listening for an answer, so a refusal addressed to it is a fragment arriving
#: outside any conversation.
#:
#: Refusing out loud is this outstation's rule everywhere else, and this is the
#: stated exception to it. That makes the set worth naming rather than leaving
#: as one special case, because the cost of missing a member is silent
#: non-conformance on a function nobody tests by hand.
_NO_RESPONSE_FUNCTIONS = frozenset(
    {
        FunctionCode.DIRECT_OPERATE_NR,
        FunctionCode.IMMED_FREEZE_NR,
        FunctionCode.FREEZE_CLEAR_NR,
        FunctionCode.FREEZE_AT_TIME_NR,
        FunctionCode.AUTH_REQUEST_NO_ACK,
    }
)

#: Functions this outstation answers. Everything else earns IIN2.1.
_SUPPORTED_FUNCTIONS = frozenset({FunctionCode.CONFIRM, FunctionCode.READ, FunctionCode.WRITE})


class UnknownObject(Exception):
    """Raised by a read provider for a group or range it does not serve."""


class ReadProvider(Protocol):
    """Where the objects in a response come from.

    A Protocol rather than the adapter class, so the session is testable against
    a recorder and so the dependency reads as "something that answers a read"
    rather than "the point store". It is synchronous by contract: a master is
    waiting on the response, and a device round-trip inside one is a protocol
    timeout waiting to happen.
    """

    def read(self, headers: Sequence[ObjectHeader]) -> bytes: ...


class Session:
    """The protocol state of one master association."""

    def __init__(
        self,
        provider: ReadProvider,
        *,
        outstation_address: int = 1024,
        master_address: int = 1,
        max_fragment: int = 2048,
    ) -> None:
        """
        Args:
            provider: Answers reads with encoded objects.
            outstation_address: This outstation's link address. Frames addressed
                elsewhere are dropped rather than answered.
            master_address: The master this association serves. A frame from any
                other source is dropped: the address is not authorization, but
                answering an unexpected one would interleave two conversations
                over one set of sequence numbers.
            max_fragment: Reassembly ceiling for a received fragment.
        """
        self._provider = provider
        self._outstation_address = outstation_address
        self._master_address = master_address
        self._frames = link.FrameReader()
        self._reassembler = Reassembler(max_fragment=max_fragment)
        #: Set until a master clears it. Every response says so until then,
        #: which is how a master knows to re-read what it had cached.
        self._restart = True

    @property
    def restart_indication(self) -> bool:
        return self._restart

    def connection_reset(self) -> None:
        """Forget what a dead connection left behind, and nothing more.

        Framing state is per connection: half a frame and half a fragment mean
        nothing to the socket that replaces the one they arrived on, and
        completing them with octets from the new connection would splice two
        conversations. Everything else belongs to the association and survives
        -- a reconnecting master expects the restart indication it has not
        cleared, and the events it has not read.
        """
        self._frames = link.FrameReader()
        self._reassembler.reset()

    def receive(self, data: bytes) -> bytes:
        """Handle received octets, returning the octets to send back."""
        out = bytearray()
        for frame in self._frames.feed(data):
            out += self._handle_frame(frame)
        return bytes(out)

    def _handle_frame(self, frame: link.LinkFrame) -> bytes:
        if not self._addressed_to_us(frame):
            return b""

        if not frame.is_primary:
            # A secondary frame is an answer to something we sent. An outstation
            # sends unconfirmed data, so there is nothing outstanding for one to
            # answer, and treating it as a request would put this side into the
            # role of the master.
            logger.debug("dnp3: ignoring secondary link frame from %d", frame.source)
            return b""

        function = frame.function
        if function == link.PrimaryFunction.REQUEST_LINK_STATUS:
            return self._link_reply(link.SecondaryFunction.LINK_STATUS)
        if function == link.PrimaryFunction.RESET_LINK_STATES:
            # A link reset abandons whatever the transport function was holding.
            # Segments from before the reset must not be completed by segments
            # from after it.
            self._reassembler.reset()
            return self._link_reply(link.SecondaryFunction.ACK)
        if function == link.PrimaryFunction.TEST_LINK_STATES:
            return self._link_reply(link.SecondaryFunction.ACK)

        if function not in (
            link.PrimaryFunction.CONFIRMED_USER_DATA,
            link.PrimaryFunction.UNCONFIRMED_USER_DATA,
        ):
            return self._link_reply(link.SecondaryFunction.NOT_SUPPORTED)

        reply = bytearray()
        if function == link.PrimaryFunction.CONFIRMED_USER_DATA:
            reply += self._link_reply(link.SecondaryFunction.ACK)

        try:
            fragment = self._reassembler.add(frame.payload)
        except TransportError as exc:
            logger.warning("dnp3: transport error from %d: %s", frame.source, exc)
            return bytes(reply)

        if fragment is None:
            return bytes(reply)
        return bytes(reply) + self._send(self._handle_fragment(fragment))

    def _addressed_to_us(self, frame: link.LinkFrame) -> bool:
        if frame.destination != self._outstation_address and not frame.is_broadcast:
            logger.debug("dnp3: frame for %d is not ours", frame.destination)
            return False
        if frame.source != self._master_address:
            logger.warning("dnp3: dropping frame from unexpected master address %d", frame.source)
            return False
        return True

    def _link_reply(self, function: link.SecondaryFunction) -> bytes:
        control = link.control_byte(from_master=False, primary=False, function=function)
        return link.build(
            control, destination=self._master_address, source=self._outstation_address
        )

    def _send(self, fragment: bytes) -> bytes:
        """Wrap an application fragment in transport segments and link frames."""
        if not fragment:
            return b""
        control = link.control_byte(
            from_master=False, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
        )
        out = bytearray()
        for tpdu in segment(fragment):
            out += link.build(
                control,
                destination=self._master_address,
                source=self._outstation_address,
                payload=tpdu,
            )
        return bytes(out)

    def _indications(self, extra: IIN | None = None) -> IIN:
        iin = IIN(first=IINBit.DEVICE_RESTART) if self._restart else IIN()
        return iin | extra if extra else iin

    def _handle_fragment(self, fragment: bytes) -> bytes:
        if len(fragment) >= REQUEST_HEADER_SIZE and fragment[1] in _NO_RESPONSE_FUNCTIONS:
            # Resolved from the function code octet, before the parse. The
            # obligation these codes carry is on the function code and not on
            # what the outstation implements, and by the same reasoning not on
            # whether the fragment parsed either: a master that asked for no
            # response is not listening for a parse error any more than for a
            # refusal. Deciding after the parse meant a malformed
            # DIRECT_OPERATE_NR -- the one member of the set whose body this
            # module walks -- was answered with PARAM_ERROR.
            logger.warning(
                "dnp3: dropping %s; it asks for no response", FunctionCode(fragment[1]).name
            )
            return b""

        try:
            request = parse_request(fragment)
        except RequestError as exc:
            logger.warning("dnp3: malformed request: %s", exc)
            # The sequence number is the one field a malformed fragment still
            # yields, and answering on the wrong one would have the master
            # discard the answer it needs.
            sequence = fragment[0] & 0x0F if fragment else 0
            return null_response(sequence=sequence, iin=self._indications(IIN(second=exc.bit)))

        known = request.known_function
        sequence = request.control.sequence

        if known in _CONTROL_FUNCTIONS:
            logger.info("dnp3: refusing control function %s: monitor role", known.name)
            return null_response(
                sequence=sequence,
                iin=self._indications(IIN(second=IIN2Bit.FUNC_NOT_SUPPORTED)),
            )

        if known is FunctionCode.CONFIRM:
            # Nothing is outstanding to confirm until unsolicited responses
            # exist. Accepted silently rather than refused: a confirmation is
            # not a request, and answering one would be a fragment the master
            # never asked for.
            return b""

        if known not in _SUPPORTED_FUNCTIONS:
            return null_response(
                sequence=sequence,
                iin=self._indications(IIN(second=IIN2Bit.FUNC_NOT_SUPPORTED)),
            )

        if known is FunctionCode.WRITE:
            return self._handle_write(request)
        return self._handle_read(request)

    def _handle_read(self, request: Request) -> bytes:
        try:
            body = self._provider.read(request.headers)
        except UnknownObject as exc:
            logger.info("dnp3: read refused: %s", exc)
            return null_response(
                sequence=request.control.sequence,
                iin=self._indications(IIN(second=IIN2Bit.OBJECT_UNKNOWN)),
            )
        return build_response(
            control=AppControl(fir=True, fin=True, sequence=request.control.sequence),
            iin=self._indications(),
            body=body,
        )

    def _handle_write(self, request: Request) -> bytes:
        """The only write a monitor outstation honors: clearing the restart bit.

        Everything else is refused as an unknown object rather than as an
        unsupported function, because WRITE itself is supported and the master
        should learn that this object is not.
        """
        sequence = request.control.sequence
        if self._is_restart_write(request):
            self._restart = False
            logger.info("dnp3: restart indication cleared by master")
            return null_response(sequence=sequence, iin=self._indications())

        return null_response(
            sequence=sequence, iin=self._indications(IIN(second=IIN2Bit.OBJECT_UNKNOWN))
        )

    @staticmethod
    def _is_restart_write(request: Request) -> bool:
        if not request.headers:
            return False
        header = request.headers[0]
        return (
            header.group == RESTART_GROUP
            and header.variation == RESTART_VARIATION
            and header.qualifier
            in (QualifierCode.UINT8_START_STOP, QualifierCode.UINT16_START_STOP)
            and header.start == RESTART_INDEX
            and header.stop == RESTART_INDEX
        )
