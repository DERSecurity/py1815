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
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from py1815 import control as control_objects
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
    parse_object_blocks,
    parse_request,
)
from py1815.control import (
    AnalogOutput,
    CommandStatus,
    ControlError,
    ControlRelayOutputBlock,
)

# Controls echo in the same shape events do -- a count with an index in front of
# every object -- so the encoder is the same one, named for the first caller
# rather than for the format.
from py1815.objects import event_block as indexed_block
from py1815.transport import Reassembler, TransportError, segment

logger = logging.getLogger(__name__)

#: Group 80 variation 1, index 7: the internal indication a master writes to
#: clear the restart bit. Fixed by the standard rather than by the point map,
#: which is why it is the one write a read-only outstation still honors -- an
#: outstation that never cleared it would flag every response it ever sent.
RESTART_GROUP = 80
RESTART_VARIATION = 1
RESTART_INDEX = 7

#: Controls that carry objects and are answered.
#:
#: ``DIRECT_OPERATE_NR`` is absent on purpose. It executes like the rest and
#: says nothing, which is a different path rather than a different entry in this
#: set -- see ``_handle_fragment``.
_CONTROL_FUNCTIONS = frozenset(
    {
        FunctionCode.SELECT,
        FunctionCode.OPERATE,
        FunctionCode.DIRECT_OPERATE,
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
_SUPPORTED_FUNCTIONS = frozenset(
    {FunctionCode.CONFIRM, FunctionCode.READ, FunctionCode.WRITE} | _CONTROL_FUNCTIONS
)

#: How long a select stays armed. Ten seconds is opendnp3's default and the
#: middle of what implementations use; the standard leaves it to the outstation.
DEFAULT_SELECT_TIMEOUT = 10.0


class UnknownObject(Exception):
    """Raised by a read provider for a group or range it does not serve."""


@dataclass(frozen=True)
class Control:
    """One control, as it reached the provider.

    ``index`` is the point and nothing more. Under D6 this library holds no
    point map: what index 7 means is the caller's to know, and the object is
    handed over decoded but uninterpreted.
    """

    #: Which object header this arrived under. Two headers naming the same
    #: group and variation are two blocks, and the echo reproduces them as two
    #: -- a request is echoed, not tidied.
    block: int
    group: int
    variation: int
    index: int
    #: The object's octets exactly as they arrived. Select matching compares
    #: these rather than the decoded objects, because the comparison has to be
    #: exact and float equality is not -- two NaN setpoints are never equal, so
    #: a select carrying one could never be operated.
    raw: bytes
    command: ControlRelayOutputBlock | AnalogOutput


class ControlProvider(Protocol):
    """What can be commanded, and what it says about being commanded.

    Synchronous by contract, like :class:`ReadProvider` and for the same reason:
    a master is timing this, and a device round-trip inside the window is a
    protocol timeout waiting to happen. That is not a compromise the answers
    have to hide. ``SUCCESS`` is defined by the standard as "accepted,
    initiated, or queued", so a provider that hands the work to a device thread
    and returns has answered correctly.

    Both methods return one status per control, in the order received.
    Returning a different number of statuses is a programming error and is
    treated as one.
    """

    def select(self, controls: Sequence[Control]) -> Sequence[CommandStatus]:
        """Whether each control *could* be operated. Nothing is executed."""
        ...

    def operate(self, controls: Sequence[Control]) -> Sequence[CommandStatus]: ...


@dataclass
class _ArmedSelect:
    """What a select left behind for the operate that may follow."""

    #: ``(group, variation, index, octets)`` per control, in order received.
    key: tuple[tuple[int, int, int, bytes], ...]
    at: float


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
        control_provider: ControlProvider | None = None,
        outstation_address: int = 1024,
        master_address: int = 1,
        max_fragment: int = 2048,
        select_timeout: float = DEFAULT_SELECT_TIMEOUT,
        clock: Callable[[], float] = time.monotonic,
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
            control_provider: Executes controls. Without one this outstation
                monitors and does not command, and every control function is
                refused as unsupported -- which is a truthful answer rather than
                a degraded one.
            select_timeout: How long a select stays armed for the operate that
                follows it.
            clock: Monotonic source for that timeout. Injectable so expiry can
                be tested without waiting for it.
        """
        self._provider = provider
        self._controls = control_provider
        self._select_timeout = select_timeout
        self._clock = clock
        self._select: _ArmedSelect | None = None
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

        An armed select is the exception among the things that could survive,
        and is discarded here per D12. It is a reservation held for the operate
        that was about to follow on the socket that just died; honouring it
        across a reconnect would let an operate arrive over a connection the
        select never crossed.
        """
        self._frames = link.FrameReader()
        self._reassembler.reset()
        self._select = None

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
        if len(fragment) >= REQUEST_HEADER_SIZE and fragment[1] == FunctionCode.DIRECT_OPERATE_NR:
            # Table 4-2: "same as function code 5 but outstation shall not send
            # a response". Same as function code 5 -- so it operates, and says
            # nothing. Carved out of the set below rather than added to it,
            # because the other four are dropped unexecuted and this one is not.
            #
            # Silence survives a body that does not parse, which is the case
            # that early branch exists for: a master that asked for no response
            # is not listening for a parse error either.
            self._operate_unacknowledged(fragment)
            return b""

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

        if known in _CONTROL_FUNCTIONS and self._controls is None:
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

        if known in _CONTROL_FUNCTIONS:
            return self._handle_control(request, known)
        if known is FunctionCode.WRITE:
            return self._handle_write(request)
        return self._handle_read(request)

    def _operate_unacknowledged(self, fragment: bytes) -> None:
        """Execute a DIRECT_OPERATE_NR and tell nobody, including on failure."""
        if self._controls is None:
            logger.info("dnp3: dropping DIRECT_OPERATE_NR: monitor role")
            return
        try:
            controls = self._decode_controls(parse_request(fragment))
        except (RequestError, ControlError) as exc:
            # Nowhere to send a refusal. Logged so an operator can see a master
            # is sending something this outstation cannot read, which is the
            # only signal available on a function that answers nothing.
            logger.warning("dnp3: unreadable DIRECT_OPERATE_NR dropped: %s", exc)
            return
        # Checked here too. A provider that miscounts is a programming error
        # wherever it happens, and answering nothing is not a reason to hold
        # this path to a weaker contract than the one beside it.
        statuses = _checked(self._controls.operate(controls), controls)
        logger.info(
            "dnp3: DIRECT_OPERATE_NR executed %d control(s): %s",
            len(controls),
            ", ".join(status.name for status in statuses),
        )

    def _handle_control(self, request: Request, known: FunctionCode) -> bytes:
        sequence = request.control.sequence
        assert self._controls is not None  # refused above when absent

        try:
            controls = self._decode_controls(request)
        except (RequestError, ControlError) as exc:
            # D15. A fragment that does not parse may leave no complete object,
            # and a per-object status has to be attached to something.
            logger.warning("dnp3: control request refused: %s", exc)
            return null_response(
                sequence=sequence, iin=self._indications(IIN(second=IIN2Bit.PARAM_ERROR))
            )

        if known is FunctionCode.SELECT:
            statuses = _checked(self._controls.select(controls), controls)
            # D16: the request received, not the objects that succeeded. The
            # operate a master sends next is the request it already sent.
            self._select = _ArmedSelect(key=_match_key(controls), at=self._clock())
        elif known is FunctionCode.OPERATE:
            statuses = self._operate_after_select(controls)
        else:
            statuses = _checked(self._controls.operate(controls), controls)

        return build_response(
            control=AppControl(fir=True, fin=True, sequence=sequence),
            iin=self._indications(),
            body=_echo(controls, statuses),
        )

    def _operate_after_select(self, controls: Sequence[Control]) -> list[CommandStatus]:
        armed = self._select
        if armed is None:
            return [CommandStatus.NO_SELECT] * len(controls)
        if self._clock() - armed.at > self._select_timeout:
            self._select = None
            return [CommandStatus.TIMEOUT] * len(controls)
        if armed.key != _match_key(controls):
            # Left armed rather than consumed. D12 spends a select on the
            # operate that matches it, and a master that sent the wrong one
            # still has the one it was granted.
            return [CommandStatus.NO_SELECT] * len(controls)
        self._select = None
        assert self._controls is not None
        return _checked(self._controls.operate(controls), controls)

    def _decode_controls(self, request: Request) -> list[Control]:
        controls: list[Control] = []
        for ordinal, block in enumerate(parse_object_blocks(request, control_objects.object_size)):
            for index, data in block.items:
                controls.append(
                    Control(
                        block=ordinal,
                        group=block.header.group,
                        variation=block.header.variation,
                        index=index,
                        raw=data,
                        command=control_objects.decode_control(
                            block.header.group, block.header.variation, data
                        ),
                    )
                )
        if not controls:
            raise RequestError("a control request carries no controls")
        return controls

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


def _checked(
    statuses: Sequence[CommandStatus], controls: Sequence[Control]
) -> list[CommandStatus]:
    """One status per control, or the programming error that says otherwise.

    The provider contract in one place rather than at each call site, so a path
    that answers nothing is held to it as firmly as one that answers a master.
    """
    answered = list(statuses)
    if len(answered) != len(controls):
        raise ValueError(
            f"the control provider answered {len(answered)} of {len(controls)} controls"
        )
    return answered


def _match_key(controls: Sequence[Control]) -> tuple[tuple[int, int, int, bytes], ...]:
    """What an operate has to reproduce to spend the select it follows.

    The octets rather than the decoded objects. The comparison has to be exact,
    and float equality is not: two NaN setpoints never compare equal, so a
    select carrying one could never be operated at all.

    The block a control arrived under is deliberately absent. That is framing
    rather than instruction: an operate that carried the same objects under a
    different header boundary is still asking for the same points to move, and
    refusing it would fail a master over a detail the standard does not make
    part of the command.
    """
    return tuple((c.group, c.variation, c.index, c.raw) for c in controls)


def _echo(controls: Sequence[Control], statuses: Sequence[CommandStatus]) -> bytes:
    """The request back, one status per object, in the order it arrived (D14).

    The request's own header boundaries are kept. Splitting on the group and
    variation instead would merge two headers that named the same group into
    one block carrying twice the count -- a tidier response than the request,
    and not the request. A master that sent two headers is answered with two.
    """
    body = b""
    run: list[tuple[int, bytes]] = []
    block = group = variation = -1

    for item, status in zip(controls, statuses, strict=True):
        if item.block != block:
            if run:
                body += indexed_block(group, variation, run)
            block, group, variation, run = item.block, item.group, item.variation, []
        run.append((item.index, control_objects.encode_control(item.command.with_status(status))))

    if run:
        body += indexed_block(group, variation, run)
    return body
