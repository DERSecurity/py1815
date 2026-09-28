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
from dataclasses import dataclass, field
from typing import Protocol

from py1815 import control as control_objects
from py1815 import link
from py1815.application import (
    IIN,
    REQUEST_HEADER_SIZE,
    RESPONSE_HEADER_SIZE,
    SEQUENCE_MODULUS,
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
from py1815.events import AnalogEvent, Event, EventBuffers, EventClass
from py1815.objects import (
    GROUP_ANALOG_INPUT_EVENT,
    GROUP_BINARY_INPUT_EVENT,
    AnalogEventVariation,
    BinaryEventVariation,
    encode_analog_event,
    encode_binary_event,
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

#: The two fragments that do not end an armed select's exchange. An OPERATE
#: because spending a select is what it is for. A CONFIRM because it is not a
#: request at all -- it is the second half of an exchange this outstation
#: started, and it carries the sequence of the response it acknowledges rather
#: than a new one, so a master may legitimately send SELECT, then a confirmation
#: for an earlier response, then the OPERATE.
_KEEPS_A_SELECT = frozenset({FunctionCode.OPERATE, FunctionCode.CONFIRM})

#: Functions this outstation answers. Everything else earns IIN2.1.
_SUPPORTED_FUNCTIONS = frozenset(
    {
        FunctionCode.CONFIRM,
        FunctionCode.READ,
        FunctionCode.WRITE,
        FunctionCode.DISABLE_UNSOLICITED,
    }
    | _CONTROL_FUNCTIONS
)

#: How long a select stays armed. Ten seconds is opendnp3's default and the
#: middle of what implementations use; the standard leaves it to the outstation.
DEFAULT_SELECT_TIMEOUT = 10.0

#: The classes a read can ask for that come from the buffers. Class 0 is static
#: data and is the provider's, which is why ``event_class`` returning 0 is not
#: the same as it returning None.
_EVENT_CLASSES = frozenset({EventClass.CLASS_1, EventClass.CLASS_2, EventClass.CLASS_3})

#: Which indication bit says a class has something waiting.
_CLASS_BITS = {
    EventClass.CLASS_1: IINBit.CLASS_1_EVENTS,
    EventClass.CLASS_2: IINBit.CLASS_2_EVENTS,
    EventClass.CLASS_3: IINBit.CLASS_3_EVENTS,
}

#: The variations events are reported in. Timed, because an event without a
#: timestamp tells a master that a value changed and not when -- which, for the
#: sequence a master reads events to obtain, is most of what it wanted.
_ANALOG_EVENT_VARIATION = AnalogEventVariation.INT32_WITH_TIME
_BINARY_EVENT_VARIATION = BinaryEventVariation.WITH_TIME

#: The qualifiers a class read may carry. ``ALL_OBJECTS`` asks for everything
#: the class holds; the count qualifiers ask for at most that many, which is how
#: a master paces a buffer it does not want in one fragment.
#:
#: A range is not among them. Class objects have no indices to range over -- a
#: class is a reporting priority, not a set of points -- so a start and a stop
#: name nothing, and honouring one would mean inventing a meaning for it.
#: The fewest octets an event can occupy on the wire: a one-octet index prefix
#: in front of a binary event with time, which is a flag octet and a six-octet
#: timestamp. Nothing encodes smaller, so the remaining budget divided by this
#: is an upper bound on how many events could still fit -- and a bound that can
#: be taken before anything is encoded.
_MIN_EVENT_OCTETS = 8

#: The most fragments one response may take. A count rather than an octet
#: budget or a deadline (D32), and sixteen because that is one full trip through
#: the application sequence space -- a conversation reaching it has spent every
#: sequence number once. A full default buffer is about seven fragments at the
#: default ceiling, so this carries one twice that size and still stops a buffer
#: that fills as fast as it drains.
_MAX_FRAGMENTS = 16

#: The most events one object header can count, and so the most one block can
#: carry. Beyond it the encoder refuses, which is a bug report rather than a
#: response, so a run longer than this is split into several blocks.
_MAX_BLOCK_EVENTS = 0xFFFF

_CLASS_QUALIFIERS = frozenset(
    {
        QualifierCode.ALL_OBJECTS,
        QualifierCode.UINT8_COUNT,
        QualifierCode.UINT16_COUNT,
    }
)


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
    #: The function code that carried it. D13 promises a provider the
    #: function alongside the object, and the three that reach
    #: ``operate`` are not interchangeable: a provider may want to audit
    #: a select differently from the operate that spends it, and
    #: ``DIRECT_OPERATE_NR`` is one no master is waiting on.
    function: FunctionCode
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
    #: The application sequence the select arrived under. The operate that
    #: spends it has to be the next one, which is how a stale selection is told
    #: apart from the request it was granted for.
    sequence: int


@dataclass(frozen=True)
class _Outstanding:
    """A response carrying events, waiting for the master to confirm it."""

    #: The application sequence it went out under. The confirmation that
    #: retires these events has to name it (D18).
    sequence: int
    #: The events themselves, not their ids. ``EventBuffers.drop`` matches on
    #: identity, and an id kept while its event is freed can be reused by an
    #: unrelated one -- which is the failure its docstring warns about. Holding
    #: the objects keeps them alive, so the ids stay theirs for as long as this
    #: selection is outstanding, whether or not the buffer still has them.
    events: tuple[Event, ...]
    #: The request this answered, octet for octet. A repeat is recognised by
    #: what was asked and not by the sequence alone: a master that reuses a
    #: sequence for a different request has not retransmitted anything, and
    #: replaying an event response to, say, an operate would answer a question
    #: nobody asked -- and leave its events acknowledged by the confirmation
    #: that followed.
    request: bytes
    #: The response as it was sent, for a master that did not receive it.
    fragment: bytes
    #: The overflow generation this response reported, or ``None`` if it
    #: carried no overflow bit. D23 clears the flag when such a response is
    #: confirmed rather than when it is sent, because an overflow reported into
    #: a void is one the master never learned about -- and the generation is
    #: what keeps that from clearing a later loss too. A boolean here would
    #: acknowledge every eviction up to the moment of the confirmation, not the
    #: ones the confirmed response actually reported.
    reported_overflow: int | None


@dataclass
class _Conversation:
    """What a multi-fragment response needs that outlives one fragment.

    Separate from ``_Outstanding``, which is per fragment and is replaced every
    time one goes out. Held there, the provider's body would be discarded by the
    very replacement that sends the fragment after it.
    """

    #: The class headers to peek again for each continuation. A continuation
    #: reads the buffer as it then stands (D29), so what it needs is the
    #: question rather than the answer.
    headers: tuple[ObjectHeader, ...]
    #: The provider's body, read once when the response began and sent with the
    #: last fragment (D33).
    static: bytes
    #: What each header has left to send, for the headers that named a count.
    #: A count qualifier is "at most this many" of the *response*, not of each
    #: fragment of it, so it is decremented as the conversation goes rather
    #: than reapplied whole every time.
    counts: list[int | None] = field(default_factory=list)
    #: How many fragments have gone out, against ``_MAX_FRAGMENTS`` (D32). The
    #: fragment carrying the body is not counted: a response that reached the
    #: bound must still answer the static half of the request it was given.
    fragments: int = 1
    #: The sequence of the fragment the master last confirmed. A confirmation
    #: repeating it means the continuation was lost, and is answered by sending
    #: that continuation again (D34).
    previous: int | None = None
    #: Whether the last fragment has gone out. It is kept for one more round
    #: rather than discarded, because the fragment most worth replaying is the
    #: one that ends the response: losing it strands a master that has nothing
    #: left to confirm and no way to ask again.
    finished: bool = False


class ReadProvider(Protocol):
    """Where the objects in a response come from.

    A Protocol rather than the adapter class, so the session is testable against
    a recorder and so the dependency reads as "something that answers a read"
    rather than "the point store". It is synchronous by contract: a master is
    waiting on the response, and a device round-trip inside one is a protocol
    timeout waiting to happen.
    """

    def read(self, headers: Sequence[ObjectHeader]) -> bytes:
        """The encoded objects a response carries, headers included.

        The bytes returned are forwarded to the master unchanged, so each run of
        objects needs the object header that describes it -- see
        ``application.object_header``. A provider that serves controls decides
        for itself whether its group 10 and 40 status points answer a class 0
        read; convention says they do, and under D6 this library holds no point
        map with which to decide otherwise.
        """
        ...


class Session:
    """The protocol state of one master association."""

    def __init__(
        self,
        provider: ReadProvider,
        *,
        control_provider: ControlProvider | None = None,
        events: EventBuffers | None = None,
        outstation_address: int = 1024,
        master_address: int = 1,
        max_fragment: int = 2048,
        max_response: int = 2048,
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
            max_response: Ceiling for a response this outstation builds. A
                separate number from ``max_fragment`` because they are separate
                things: one is the largest request this outstation will piece
                back together, the other the largest fragment the master on the
                far end can receive. A master advertises its own, and sending
                past it is a fragment discarded rather than a response. It must
                leave room for a response header.

                Until application-layer fragmentation lands, a read caps rather
                than splits: events that do not fit stay buffered and come back
                on the next read, which the class indication bits go on asking
                for. Static data is not trimmed -- it is the provider's answer
                and this session cannot tell where one object ends.

                A control request whose echo would not fit is refused before
                anything is dispatched, because a control that executes and
                cannot report is worse than one that never ran.
            control_provider: Executes controls. Without one this outstation
                monitors and does not command, and every control function is
                refused as unsupported -- which is a truthful answer rather than
                a degraded one.
            events: Where class 1, 2 and 3 events are read from. The caller
                records into it as its device polls and the session never
                records: a deadband is measured against the last value reported
                rather than the previous reading, so it needs history between
                requests, and under D6 this library does not know which index is
                which point.

                The session does write, on one occasion. A confirmation retires
                the events the response it acknowledges carried, and clears the
                overflow the same response reported, so a caller reading the
                buffer after handling a fragment may find both changed. Nothing
                else here mutates it. Without a buffer, a class 1 to 3 read
                reaches the provider like any other.
            select_timeout: How long a select stays armed for the operate that
                follows it.
            clock: Monotonic source for that timeout. Injectable so expiry can
                be tested without waiting for it.
        """
        self._provider = provider
        self._controls = control_provider
        self._events = events
        self._select_timeout = select_timeout
        self._clock = clock
        self._select: _ArmedSelect | None = None
        self._outstanding: _Outstanding | None = None
        self._conversation: _Conversation | None = None
        self._outstation_address = outstation_address
        self._master_address = master_address
        self._frames = link.FrameReader()
        self._reassembler = Reassembler(max_fragment=max_fragment)
        if max_response < RESPONSE_HEADER_SIZE:
            # A response is four octets before it carries anything, so a smaller
            # ceiling is one nothing can honour -- every answer this outstation
            # gives would break it, including the refusal it would give instead.
            # Refused at construction, where the number is, rather than logged
            # on each response that overruns it.
            raise ValueError(
                f"max_response is {max_response}; a response header alone is "
                f"{RESPONSE_HEADER_SIZE} octets"
            )
        self._max_response = max_response
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
        self._outstanding = None
        self._conversation = None

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
        iin = iin | self._event_indications()
        return iin | extra if extra else iin

    def _event_indications(self) -> IIN:
        """Which classes have events waiting, and whether any were lost.

        Derived on every response rather than tracked alongside the buffers
        (D22). A master polling on indications never asks for events it is not
        told about, so a bit that drifts from the buffer is an outstation whose
        data is invisible -- and deriving it makes drift impossible rather than
        unlikely.
        """
        if self._events is None:
            return IIN()
        first = 0
        for event_class in self._events.classes_with_events():
            first |= _CLASS_BITS[event_class]
        second = IIN2Bit.EVENT_BUFFER_OVERFLOW if self._events.overflowed() else 0
        return IIN(first=first, second=second)

    def _handle_fragment(self, fragment: bytes) -> bytes:
        if len(fragment) < REQUEST_HEADER_SIZE or fragment[1] not in _KEEPS_A_SELECT:
            # Anything the master sends other than the operate that spends a
            # select ends the exchange that select belongs to (D12). Sited here,
            # above every early return, because siting it lower is what left the
            # refusals and the no-response functions holding a reservation open
            # across traffic the master had plainly moved on from.
            #
            # Decided on the function code octet rather than after the parse, so
            # that a fragment too damaged to read clears it too. That is the
            # opposite of what a damaged fragment does to the outstanding event
            # response, and deliberately: replaying a response costs nothing if
            # the guess is wrong, while holding a control reservation open
            # through noise can authorise an operate the master never selected.
            # An unreadable fragment claiming to be an OPERATE keeps it, which
            # is the corrupted-retransmission case worth keeping it for.
            self._select = None

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

        if known is FunctionCode.CONFIRM:
            # Answered with silence rather than a fragment: a confirmation is
            # not a request, and replying to one would be traffic the master
            # never asked for. Still checked ahead of the retransmission branch
            # below, which the octet comparison there would now settle on its
            # own -- the order is what keeps it settled if that comparison is
            # ever loosened back to the sequence number.
            if request.control.uns:
                # The UNS bit is what tells a confirmation for an unsolicited
                # response apart from one for a solicited response, and the two
                # count sequence numbers separately. This outstation sends no
                # unsolicited responses at all, so a confirmation carrying the
                # bit names an exchange that never happened -- and answering it
                # from the solicited selection would retire events on the
                # strength of a number from a different counter.
                logger.info(
                    "dnp3: ignoring an unsolicited confirmation; none was sent (sequence %d)",
                    sequence,
                )
                return b""
            return self._confirm(sequence)

        if self._outstanding is not None and self._outstanding.request == fragment:
            # A master that did not receive a response repeats the request,
            # octet for octet. It is replayed rather than rebuilt, so that the
            # master ends up holding the fragment whose events its confirmation
            # will retire -- rebuilding would answer with whatever the buffer
            # holds now, and the confirmation that followed would name a set of
            # events that was never sent under it (D25).
            logger.info("dnp3: replaying the response for sequence %d", sequence)
            return self._outstanding.fragment

        # Every other request supersedes what was outstanding (D19): the master
        # has moved on, and the events go back to being unreported rather than
        # waiting for a confirmation that would now be two requests late.
        #
        # A response only partly sent ends here too, with its unsent events
        # still buffered and the class bits still asking for them (D30). There
        # is no remainder to discard, since none is held -- only the fact that
        # more was coming, and the provider's body held for the last fragment.
        #
        # Sited above every remaining return so that it covers the refusals as
        # well as the work. A refusal is a response like any other, and one that
        # left the selection standing would let a confirmation for the response
        # before it still retire those events.
        #
        # Two paths are deliberately outside it. The functions returning above
        # send nothing at all, so there is no response for a confirmation to be
        # late against. And a fragment that did not parse is not evidence the
        # master moved on -- it is evidence something arrived garbled, which is
        # when a retransmission of the held response is most likely to be what
        # comes next, and discarding the cache on noise would throw it away
        # exactly then.
        self._outstanding = None
        self._conversation = None

        if known in _CONTROL_FUNCTIONS and self._controls is None:
            logger.info("dnp3: refusing control function %s: monitor role", known.name)
            return null_response(
                sequence=sequence,
                iin=self._indications(IIN(second=IIN2Bit.FUNC_NOT_SUPPORTED)),
            )

        if known not in _SUPPORTED_FUNCTIONS:
            return null_response(
                sequence=sequence,
                iin=self._indications(IIN(second=IIN2Bit.FUNC_NOT_SUPPORTED)),
            )

        if known in _CONTROL_FUNCTIONS:
            return self._handle_control(request, known)

        if known is FunctionCode.DISABLE_UNSOLICITED:
            return self._disable_unsolicited(request)

        if known is FunctionCode.WRITE:
            return self._handle_write(request)
        return self._handle_read(request, fragment)

    def _disable_unsolicited(self, request: Request) -> bytes:
        """Agree, having nothing to stop (D21).

        The asymmetry with ``ENABLE_UNSOLICITED`` is the point. This outstation
        sends no unsolicited responses, so it is already in the state this
        request asks for, and refusing it answers a question the master did not
        ask. ``ENABLE`` asks for something this outstation does not do, and
        saying so is the honest answer rather than the matching one.

        Nothing is recorded. There is no state to enter that is not already the
        state, and a flag tracking it would be one a sending path does not yet
        exist to read. When unsolicited responses land, this becomes the place
        that flag is written, and the answer given here does not change.

        The classes named in the request are accepted without being examined,
        because the answer is the same for any of them: none is being sent for.

        Success is the absence of ``FUNC_NOT_SUPPORTED`` rather than an empty
        indication field. ``DEVICE_RESTART`` stands until a master clears it,
        and D22 and D23 put the class and overflow bits there on their own
        terms -- a response reporting those is still a successful one.
        """
        logger.info(
            "dnp3: DISABLE_UNSOLICITED accepted; none are sent (%d header(s))",
            len(request.headers),
        )
        return null_response(sequence=request.control.sequence, iin=self._indications())

    def _operate_unacknowledged(self, fragment: bytes) -> None:
        """Execute a DIRECT_OPERATE_NR and tell nobody, including on failure."""
        if self._controls is None:
            logger.info("dnp3: dropping DIRECT_OPERATE_NR: monitor role")
            return
        try:
            controls = self._decode_controls(
                parse_request(fragment), FunctionCode.DIRECT_OPERATE_NR
            )
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
            controls = self._decode_controls(request, known)
        except (RequestError, ControlError) as exc:
            # D15. A fragment that does not parse may leave no complete object,
            # and a per-object status has to be attached to something.
            logger.warning("dnp3: control request refused: %s", exc)
            return null_response(
                sequence=sequence, iin=self._indications(IIN(second=IIN2Bit.PARAM_ERROR))
            )

        # Measured before anything is dispatched, and refused rather than
        # attempted. A control response is the request echoed with a status per
        # object, so a master that cannot receive it executes the controls and
        # then learns nothing about them -- and a master that learns nothing
        # about an operate is a master that may send it again. Refusing costs a
        # rejected request; proceeding risks a breaker cycled twice.
        #
        # The statuses here are a probe, not an answer. An object's encoding is
        # a fixed size for its type and the status sits inside it, so the echo
        # measures the same whichever status is used.
        echo = _echo(controls, [CommandStatus.SUCCESS] * len(controls))
        if RESPONSE_HEADER_SIZE + len(echo) > self._max_response:
            logger.warning(
                "dnp3: refusing %s: its echo of %d octets exceeds the %d the master can receive",
                known.name,
                RESPONSE_HEADER_SIZE + len(echo),
                self._max_response,
            )
            return null_response(
                sequence=sequence, iin=self._indications(IIN(second=IIN2Bit.PARAM_ERROR))
            )

        if known is FunctionCode.SELECT:
            statuses = _checked(self._controls.select(controls), controls)
            if any(status is CommandStatus.SUCCESS for status in statuses):
                # D16 arms the request received rather than the objects that
                # succeeded, so that the operate a master sends next -- which is
                # the request it already sent -- still matches. That reasoning
                # runs out when nothing succeeded: there is no operate this
                # select could authorise, and arming it would let a point the
                # outstation refused to select be executed by the operate that
                # followed.
                self._select = _ArmedSelect(
                    key=_match_key(controls), at=self._clock(), sequence=sequence
                )
            else:
                self._select = None
        elif known is FunctionCode.OPERATE:
            statuses = self._operate_after_select(controls, sequence)
        else:
            statuses = _checked(self._controls.operate(controls), controls)

        return build_response(
            control=AppControl(fir=True, fin=True, sequence=sequence),
            iin=self._indications(),
            body=_echo(controls, statuses),
        )

    def _operate_after_select(
        self, controls: Sequence[Control], sequence: int
    ) -> list[CommandStatus]:
        armed = self._select
        if armed is None:
            return [CommandStatus.NO_SELECT] * len(controls)
        if self._clock() - armed.at > self._select_timeout:
            self._select = None
            return [CommandStatus.TIMEOUT] * len(controls)
        if sequence != (armed.sequence + 1) % SEQUENCE_MODULUS:
            # The operate has to be the request after the select. Matching on
            # the objects alone let a selection outlive whatever came between:
            # select, then a read, then an operate carrying the same objects
            # would execute on the strength of a selection the master had
            # already moved on from.
            self._select = None
            return [CommandStatus.NO_SELECT] * len(controls)
        if armed.key != _match_key(controls):
            # Left armed rather than consumed. D12 spends a select on the
            # operate that matches it, and a master that sent the wrong one
            # still has the one it was granted.
            return [CommandStatus.NO_SELECT] * len(controls)
        self._select = None
        assert self._controls is not None
        return _checked(self._controls.operate(controls), controls)

    def _decode_controls(self, request: Request, function: FunctionCode) -> list[Control]:
        controls: list[Control] = []
        for ordinal, block in enumerate(parse_object_blocks(request, control_objects.object_size)):
            for index, data in block.items:
                controls.append(
                    Control(
                        function=function,
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

    def _handle_read(self, request: Request, fragment: bytes) -> bytes:
        sequence = request.control.sequence
        event_headers, static_headers = self._split_read(request.headers)

        unusable = [h for h in event_headers if h.qualifier not in _CLASS_QUALIFIERS]
        if unusable:
            # Refused rather than answered with everything the class holds. A
            # master that asked for a selection and received the whole buffer
            # has been told its request was honoured when it was ignored, which
            # is the shape of failure D9 exists to rule out.
            logger.info(
                "dnp3: class read refused: qualifier 0x%02X selects nothing on a class",
                int(unusable[0].qualifier),
            )
            return null_response(
                sequence=sequence,
                iin=self._indications(IIN(second=IIN2Bit.PARAM_ERROR)),
            )

        static = b""
        if static_headers or not event_headers:
            try:
                static = self._provider.read(static_headers)
            except UnknownObject as exc:
                logger.info("dnp3: read refused: %s", exc)
                return null_response(
                    sequence=sequence,
                    iin=self._indications(IIN(second=IIN2Bit.OBJECT_UNKNOWN)),
                )

        if len(static) + RESPONSE_HEADER_SIZE > self._max_response:
            # Decided on the body alone, before any fragment is built. It
            # travels with the last one (D33), so a body too large for a
            # fragment is a request this outstation cannot answer however many
            # fragments it sends -- the refusal is not a property of the
            # fragment it would have ridden in.
            #
            # Refused rather than truncated: the provider's body is opaque here
            # and cutting it at an arbitrary octet would hand the master half an
            # object.
            #
            # And refused rather than sent. A fragment past the ceiling is one
            # the master discards, so sending it loses the whole response and
            # says nothing about why; four octets carrying PARAM_ERROR arrive,
            # and a master that knows its request was too large can narrow it.
            # This is the same answer the control path gives for the same
            # reason.
            logger.warning(
                "dnp3: refusing read: static data of %d octets exceeds the %d the master "
                "can receive",
                len(static) + RESPONSE_HEADER_SIZE,
                self._max_response,
            )
            # Returned before anything is recorded as outstanding: no events
            # were sent, so none are awaiting a confirmation and all of them
            # stay buffered for the read that follows.
            return null_response(
                sequence=sequence, iin=self._indications(IIN(second=IIN2Bit.PARAM_ERROR))
            )

        conversation = _Conversation(
            headers=tuple(event_headers),
            static=static,
            counts=[header.count for header in event_headers],
        )
        body, selected, final = self._fragment(conversation)

        iin = self._indications()
        overflowed = (
            self._events.overflow_generation
            if self._events is not None and iin.second & IIN2Bit.EVENT_BUFFER_OVERFLOW
            else None
        )
        # ``CON`` where there is something to confirm, which is the events and
        # also the overflow. A report of lost data is retired by the master
        # acknowledging it (D23), so a response that carries the bit and no
        # events still has to ask -- otherwise the one configuration where no
        # event ever fits is the one where the flag can never clear, and the
        # master is told for ever about a loss it was told about once.
        confirmable = bool(selected) or overflowed is not None or not final
        response = build_response(
            control=AppControl(fir=True, fin=final, con=confirmable, sequence=sequence),
            iin=iin,
            body=body,
        )
        if confirmable:
            self._outstanding = _Outstanding(
                sequence=sequence,
                request=fragment,
                events=tuple(selected),
                fragment=response,
                reported_overflow=overflowed,
            )
        self._conversation = self._retained(conversation, final)
        return response

    @staticmethod
    def _retained(conversation: _Conversation, final: bool) -> _Conversation | None:
        """The conversation to carry forward, if any.

        A finished one is kept when it had continuations, so that D34 can
        replay its *last* fragment -- the one whose loss leaves a master with
        nothing left to confirm and no way to ask again. It is discarded on the
        confirmation that follows, or by the next request (D30).
        """
        if not final:
            return conversation
        if conversation.previous is None:
            # One fragment, so there was never a continuation to lose.
            return None
        conversation.finished = True
        return conversation

    def _fragment(self, conversation: _Conversation) -> tuple[bytes, list[Event], bool]:
        """One fragment of a read's answer: octets, its events, and whether it ends.

        Events are fitted to the whole budget, not to what is left after the
        provider's body. The body travels with the last fragment (D33), so
        reserving room for it in every fragment would hold back a fragment's
        worth of events for something arriving several round trips later.

        Which leaves three ways a response ends, and the third is the one that
        is easy to miss:

        - the events are done and the body fits beside them, so it rides along;
        - the events are done and it does not, so it takes a fragment of its
          own rather than displacing events to make room;
        - the fragment bound is reached with events still waiting, and *then*
          the body has to travel here whether it fits or not. That case refits
          against a reserved budget, because a body too large to follow a full
          fragment of events would otherwise defer the ending every time.
        """
        whole = self._max_response - RESPONSE_HEADER_SIZE
        if not conversation.headers:
            return conversation.static, [], True

        if conversation.fragments > _MAX_FRAGMENTS:
            # Past the bound, which the events have already spent. This is the
            # one extra fragment D32 allows for the body, and it carries
            # nothing else -- a response that reached the bound is not owed
            # more events, but it is still owed the static data it asked for.
            return conversation.static, [], True

        body, selected, complete = self._event_body(
            conversation.headers, conversation.counts, whole
        )

        # Whether another fragment could carry anything this one could not. An
        # incomplete answer that placed no events is not progress -- nothing
        # fits, so no continuation would do better, and a conversation would be
        # sixteen empty fragments. That case ends here, which is D27's cap.
        more = not complete and bool(selected)
        at_bound = conversation.fragments >= _MAX_FRAGMENTS
        fits = len(body) + len(conversation.static) <= whole

        if at_bound:
            # The events stop here whatever they did. Asking only when the
            # *budget* cut them short left the bound bypassed by a device
            # recording a batch between every confirmation: each fragment
            # answered its buffer in full, the body never fit beside it, and the
            # response never ended.
            if more:
                logger.info(
                    "dnp3: ending a response at %d fragments with events still buffered",
                    conversation.fragments,
                )
            return (body + conversation.static, selected, True) if fits else (body, selected, False)

        if more:
            return body, selected, False

        # The events are done, so the body travels now (D33) -- unless it will
        # not fit beside them, in which case it takes a fragment of its own
        # rather than displacing events to make room. The next call finds no
        # events left and sends the body alone.
        if fits:
            return body + conversation.static, selected, True
        return body, selected, False

    def _confirm(self, sequence: int) -> bytes:
        """Retire the events the confirmed response carried.

        A confirmation naming anything other than the outstanding sequence
        retires nothing. It is late, duplicated, or for a response this
        outstation has already superseded, and in each case the events it names
        are not the ones the master has just acknowledged.

        Events evicted while the confirmation was in flight are simply gone:
        ``drop`` skips what it cannot find, so the survivors retire and the
        overflow bit already set is the whole of the report (D18).

        Those evictions are also why the overflow is acknowledged by generation
        rather than by flag. The master has confirmed the loss this response
        reported; anything lost since is a loss it has not been told about, and
        clearing the flag on its behalf would bury it.
        """
        conversation = self._conversation
        if conversation is not None and sequence == conversation.previous:
            # The continuation was lost (D34). Sending it again is the only
            # answer that moves: its events were retired when this confirmation
            # first arrived, so there is nothing to retire and nothing to
            # rebuild it from. Without this the master waits for a fragment
            # that will never come and this outstation for a confirmation that
            # will never arrive.
            logger.info("dnp3: re-sending the fragment after sequence %d", sequence)
            return self._outstanding.fragment if self._outstanding is not None else b""

        if self._events is None:
            return b""
        pending = self._outstanding
        if pending is None or pending.sequence != sequence:
            logger.info("dnp3: ignoring a confirmation for sequence %d", sequence)
            return b""

        self._events.drop(pending.events)
        if pending.reported_overflow == self._events.overflow_generation:
            # ``None`` never matches a generation, which is how a response that
            # carried no overflow bit declines to clear one.
            self._events.clear_overflow()
        self._outstanding = None

        if conversation is None or conversation.finished:
            # The response is over. The conversation was held only so that its
            # last fragment could be replayed, and this confirmation is the
            # acknowledgement that made that unnecessary.
            self._conversation = None
            return b""
        conversation.previous = sequence
        conversation.fragments += 1
        return self._continue(conversation, (sequence + 1) % SEQUENCE_MODULUS, fragment=b"")

    def _continue(self, conversation: _Conversation, sequence: int, fragment: bytes) -> bytes:
        """The next fragment of a response the master has asked to see the rest of.

        A confirmation is the only thing that produces one, which is why this is
        the one place the session answers something that is not a request. Under
        D18 a confirmation already moves the state machine on by retiring what it
        acknowledges; sending what comes next is the same transition.
        """
        body, selected, final = self._fragment(conversation)
        iin = self._indications()
        overflowed = (
            self._events.overflow_generation
            if self._events is not None and iin.second & IIN2Bit.EVENT_BUFFER_OVERFLOW
            else None
        )
        response = build_response(
            # ``FIR`` is false on every fragment but the first: this is the same
            # response continuing, not a new one.
            #
            # ``CON`` on every one of them, including a last fragment carrying
            # nothing but the provider's body. It has no events to retire, but
            # it is the step of an exchange the master is walking through, and
            # its confirmation is the only signal that the response arrived
            # whole. Leaving it clear also left nothing cached to replay, so
            # losing it deadlocked the exchange in exactly the way D34 exists to
            # prevent -- the master repeats its confirmation and is answered
            # with silence.
            control=AppControl(fir=False, fin=final, con=True, sequence=sequence),
            iin=iin,
            body=body,
        )
        self._outstanding = _Outstanding(
            sequence=sequence,
            request=fragment,
            events=tuple(selected),
            fragment=response,
            reported_overflow=overflowed,
        )
        self._conversation = self._retained(conversation, final)
        return response

    def _split_read(
        self, headers: Sequence[ObjectHeader]
    ) -> tuple[list[ObjectHeader], list[ObjectHeader]]:
        """The headers this session answers from the buffers, and the rest.

        Without buffers nothing is split: a class 1 to 3 read goes to the
        provider exactly as it did before, so an outstation with no events
        configured behaves as it always has.
        """
        if self._events is None:
            return [], list(headers)
        events = [h for h in headers if h.event_class in _EVENT_CLASSES]
        static = [h for h in headers if h.event_class not in _EVENT_CLASSES]
        return events, static

    def _event_body(
        self, headers: Sequence[ObjectHeader], counts: list[int | None], budget: int
    ) -> tuple[bytes, list[Event], bool]:
        """The event objects the named classes are holding.

        Events lead the response, before any static data beside them (D20): a
        master applies a fragment in order, and a static value written after the
        events that led to it leaves the point at the value it should end up
        holding.

        A class with nothing in it is not an error. An empty answer is a normal
        outcome for a master polling to find out whether anything happened.

        Nothing is dropped here, which is why the selection comes back beside
        the octets. An event leaves the buffer when the master confirms the
        response carrying it (D18), so a master that reads and never confirms
        sees the same events on its next read.

        ``budget`` is the octets left for events. What does not fit is left in
        the buffer and left out of the returned selection, so the confirmation
        that follows retires only what was actually sent and the class
        indication bits go on asking for the rest (D27).

        It also bounds the work, not just the octets: the selection is cut to
        what could possibly fit before anything is encoded, so a small response
        over a large buffer costs the response rather than the buffer.

        The third return says whether the budget is what stopped it. A count
        qualifier stopping it does not count: a master that asked for at most so
        many has been answered in full, and a response that carried on would be
        sending events it declined.

        ``counts`` is what each header still has coming, and is decremented by
        what actually went out. A count is a bound on the response rather than
        on each fragment of it: reapplying it whole to every continuation would
        answer a request for three hundred events with as many as the buffer
        held, three hundred at a time.
        """
        assert self._events is not None
        body = b""
        #: Identities already in this response. A master naming a class twice
        #: asked about it twice, and sending an event once per header would tell
        #: it the same change happened more than once.
        emitted: set[int] = set()
        #: Whether the budget, rather than the master's own count, is what
        #: stopped this short. It is what decides `FIN`.
        truncated = False
        #: How many of each class have gone into this response already. Only
        #: needed because it is what the deduplication below will discard, so
        #: the buffer has to be asked for that many more than could fit.
        taken: dict[int, int] = {}
        sent: list[Event] = []

        # Header order rather than class order: a master that asked for class 3
        # before class 1 gets them back that way, and the count on each header
        # belongs to that header rather than to the class.
        for index, header in enumerate(headers):
            if header.event_class is None:
                continue
            limit = counts[index]
            if limit is not None and limit <= 0:
                # Already answered in full by an earlier fragment. Skipped to
                # save the peek rather than for the answer: the slice below
                # would take nothing from it anyway.
                continue
            # Asked for only what could possibly still fit, so that a small
            # response over a large buffer costs the response rather than the
            # buffer. Without this the whole class was copied, scanned for
            # duplicates and encoded, and `_fitting` then discarded nearly all
            # of it -- a four-octet response over fifty thousand events cost
            # fifty thousand encodings. `capacity` has no upper bound, so that
            # is work proportional to a number the operator chose, repeated on
            # every read a peer sends.
            #
            # A strict upper bound rather than an estimate: nothing encodes
            # smaller than `_MIN_EVENT_OCTETS` and a block costs a header on
            # top, so nothing that would have fitted is left behind here.
            #
            # Plus what deduplication is about to remove. A class named twice
            # has its earlier events at the front of the buffer -- every
            # selection takes from the front -- so asking for that many more is
            # what keeps the second header from coming back short.
            room = max(0, (budget - len(body)) // _MIN_EVENT_OCTETS)
            already = taken.get(header.event_class, 0)
            # One past what could fit, so that "there is more behind this" is a
            # fact rather than an inference from having filled the room exactly.
            held = self._events.peek(EventClass(header.event_class), limit=already + room + 1)

            selected = [event for event in held if id(event) not in emitted]
            if len(selected) > room:
                if limit is None or limit > room:
                    truncated = True
                selected = selected[:room]
            if limit is not None:
                # A count qualifier is "at most this many", which is how a
                # master paces a buffer it does not want in one fragment.
                selected = selected[:limit]
            emitted.update(id(event) for event in selected)
            taken[header.event_class] = already + len(selected)
            #: What this header had sent before this fragment touched it, so the
            #: count can be decremented by what went out rather than by what was
            #: selected -- the encoder may take fewer than the budget allowed.
            before = len(sent)

            # The cursor walks `selected` alongside the blocks, because
            # `_encoded` partitions it into consecutive runs and a run cut short
            # by the budget has to record the events it actually carried.
            cursor = 0
            for group, variation, items in _encoded(selected):
                # Split at the largest count a header can carry. A buffer wide
                # enough to hold more than this of one type in a row is legal --
                # capacity has no upper bound -- and encoding it as one block
                # would raise out of request handling rather than answer.
                for start in range(0, len(items), _MAX_BLOCK_EVENTS):
                    chunk = items[start : start + _MAX_BLOCK_EVENTS]
                    fitted, block = _fitting(group, variation, chunk, budget - len(body))
                    body += block
                    sent += selected[cursor : cursor + fitted]
                    cursor += fitted
                    if fitted < len(chunk):
                        # The budget cut this block short, so the response is
                        # not complete however the rest of it looks.
                        if limit is not None:
                            counts[index] = limit - (len(sent) - before)
                        return body, sent, False

            if limit is not None:
                counts[index] = limit - (len(sent) - before)
        return body, sent, not truncated

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


def _checked(statuses: Sequence[CommandStatus], controls: Sequence[Control]) -> list[CommandStatus]:
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


def _fitting(
    group: int, variation: int, items: Sequence[tuple[int, bytes]], budget: int
) -> tuple[int, bytes]:
    """The longest prefix of a block that fits a budget, and its octets.

    Found by bisection over the encoder rather than by arithmetic on the header
    layout. A block's size is not a fixed cost per event: the qualifier widens
    when the count passes an octet or an index does, and duplicating that rule
    here would be a second copy to keep in step with the first. Bisection is
    sound because the size never falls as events are added -- the count only
    grows and the widest index is a maximum over a growing set.
    """
    whole = indexed_block(group, variation, list(items))
    if len(whole) <= budget:
        return len(items), whole

    low, high, best, encoded = 1, len(items), 0, b""
    while low <= high:
        middle = (low + high) // 2
        block = indexed_block(group, variation, list(items[:middle]))
        if len(block) <= budget:
            best, encoded = middle, block
            low = middle + 1
        else:
            high = middle - 1
    return best, encoded


def _encoded(events: Sequence[Event]) -> list[tuple[int, int, list[tuple[int, bytes]]]]:
    """Events grouped into the blocks they travel in, in the order they happened.

    Consecutive events of one kind share a block. The order is the buffer's --
    which is the order the points changed -- so a run of analog events
    interrupted by a binary one becomes three blocks rather than two, because
    reordering them into two would tell the master a different story about when
    things happened.
    """
    blocks: list[tuple[int, int, list[tuple[int, bytes]]]] = []
    for event in events:
        if isinstance(event, AnalogEvent):
            group, variation = GROUP_ANALOG_INPUT_EVENT, int(_ANALOG_EVENT_VARIATION)
            encoded = encode_analog_event(
                event.point,
                variation=_ANALOG_EVENT_VARIATION,
                timestamp_ms=event.timestamp_ms,
            )
        else:
            group, variation = GROUP_BINARY_INPUT_EVENT, int(_BINARY_EVENT_VARIATION)
            encoded = encode_binary_event(
                event.point, with_time=True, timestamp_ms=event.timestamp_ms
            )
        if blocks and blocks[-1][0] == group and blocks[-1][1] == variation:
            blocks[-1][2].append((event.index, encoded))
        else:
            blocks.append((group, variation, [(event.index, encoded)]))
    return blocks
