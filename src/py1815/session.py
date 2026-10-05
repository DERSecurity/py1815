"""One master association: octets in, octets out, no socket in sight.

The session owns everything that is true of a conversation rather than of a
frame -- which master it is talking to, where the transport reassembly has got
to, whether the restart indication is still outstanding -- and it owns it per
association rather than per connection, because that is what DNP3 state belongs
to.

Kept free of I/O on purpose. :meth:`Session.receive` takes the octets that
arrived and returns the octets to send, so every rule below is testable against
literal frames with no listener, no TLS and no event loop.

An outstation that reports without being asked needs a second way in, since
nothing arrives to answer. :meth:`Session.initiate` is that: the owner calls
it, and it returns the octets that are due by the clock or by what has been
recorded, which is usually none. :meth:`Session.initiate_after` says how long
until it is worth calling again. The session still starts no timer and writes
to nothing. Unsolicited responses are off unless a session is built with
them on, and a session built without them answers exactly as it did before
they existed (D69 to D71 in the design notes).

**What it refuses, it refuses out loud.** A control function gets a response
carrying IIN2.0 rather than silence, because a master that times out learns
nothing and retries.

The exceptions are the function codes IEEE 1815-2012 Table 4-2 defines as taking
no reply, each described there as "same as function code N but outstation shall
not send a response". They are dropped and reported in the log rather than
answered, and they are recognized from the function code octet before the
fragment is parsed, because a master that asked for no response is not listening
for a parse error either. A refusal contract written only in terms of returned
statuses would leave the functions that return nothing as the ones an
implementation executes by omission.

Three more silences follow from what a request is, not from Table 4-2 (D59 and
D62 in the design notes). A fragment that is not a whole request is discarded:
too short to hold an application header, not both first and final, or
carrying the unsolicited bit when it is not a confirmation. A link frame whose
length contradicts its function is dropped before it reaches the application
layer. And a function the caller disabled is dropped unexecuted when it is one
that never takes a response, since refusing it out loud would answer a master
that asked for no answer. Everything else that is refused gets a response.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import logging
import struct
import time
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from typing import Protocol, runtime_checkable

from py1815 import control as control_objects
from py1815 import link
from py1815.application import (
    CLASS_GROUP,
    CON_MASK,
    FIN_MASK,
    FIR_MASK,
    IIN,
    REQUEST_HEADER_SIZE,
    RESPONSE_HEADER_SIZE,
    SEQUENCE_MODULUS,
    UNS_MASK,
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
    parse_header_list,
    parse_object_blocks,
    parse_request,
)
from py1815.control import (
    AnalogOutput,
    CommandStatus,
    ControlError,
    ControlRelayOutputBlock,
)
from py1815.events import (
    AnalogEvent,
    BinaryEvent,
    Event,
    EventBuffers,
    EventClass,
    FrozenCounterEvent,
)
from py1815.objects import (
    ANALOG_EVENT_SIZES,
    FROZEN_COUNTER_EVENT_VARIATION,
    GROUP_ANALOG_INPUT_EVENT,
    GROUP_BINARY_INPUT_EVENT,
    GROUP_COUNTER_EVENT,
    GROUP_FROZEN_COUNTER_EVENT,
    MAX_RELATIVE_MS,
    TIME_SIZE,
    AnalogEventVariation,
    BinaryEventVariation,
    common_time,
    encode_analog_event,
    encode_binary_event,
    encode_binary_event_relative,
    encode_counter,
    encode_frozen_counter_event,
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

#: Group 50 variation 1: the absolute time a master writes to set the clock.
TIME_GROUP = 50
TIME_VARIATION = 1
#: The time a master says its request to record the current time was sent.
LAST_RECORDED_TIME_VARIATION = 3

#: Group 52 variation 2: the fine time delay a delay measurement and a cold
#: restart are answered with, in milliseconds.
TIME_DELAY_GROUP = 52
TIME_DELAY_FINE_VARIATION = 2

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

#: Functions this outstation answers. Everything else earns IIN2.0.
_SUPPORTED_FUNCTIONS = frozenset(
    {
        FunctionCode.CONFIRM,
        FunctionCode.READ,
        FunctionCode.WRITE,
        FunctionCode.DISABLE_UNSOLICITED,
        FunctionCode.DELAY_MEASURE,
    }
    | _CONTROL_FUNCTIONS
)

#: The freezes, answered and not. Supported only by an outstation that was
#: given something to freeze (D45): without one there are no counters, and
#: accepting a freeze of nothing would tell a master its log had begun.
#:
#: The two freeze-at-time functions are absent. They schedule a freeze rather
#: than perform one, and no profile this library serves asks for them.
_FREEZE_FUNCTIONS = frozenset({FunctionCode.IMMED_FREEZE, FunctionCode.FREEZE_CLEAR})
_FREEZE_NR_FUNCTIONS = frozenset({FunctionCode.IMMED_FREEZE_NR, FunctionCode.FREEZE_CLEAR_NR})

#: Every function that is never answered, whatever comes of it.
_SILENT_FUNCTIONS = (
    _NO_RESPONSE_FUNCTIONS | _FREEZE_NR_FUNCTIONS | frozenset({FunctionCode.DIRECT_OPERATE_NR})
)
_CLEARING_FREEZES = frozenset({FunctionCode.FREEZE_CLEAR, FunctionCode.FREEZE_CLEAR_NR})

#: How long a fragment that asked for confirmation waits for it. A
#: confirmation arriving later is for a response this outstation has given up
#: on: its events stay buffered and the rest of a multi-fragment response is
#: not sent, so a master that took too long asks again and loses nothing.
DEFAULT_CONFIRM_TIMEOUT = 10.0

#: The variations an event group may be read in by name (D46). Zero asks for
#: this session's default. Group 22, counter change events, is never
#: buffered, so its entries are variations that are answered with nothing.
_EVENT_VARIATIONS: dict[int, frozenset[int]] = {
    GROUP_BINARY_INPUT_EVENT: frozenset({0, 1, 2, 3}),
    GROUP_ANALOG_INPUT_EVENT: frozenset({0, 1, 2, 3, 4}),
    GROUP_FROZEN_COUNTER_EVENT: frozenset({0, 1, 5}),
    GROUP_COUNTER_EVENT: frozenset({0, 1, 2}),
}

#: Requests whose repetition, octet for octet, is a retry and not a second
#: instruction: the answer is sent again and the action is not taken again.
_ACT_ONCE = frozenset(
    {
        FunctionCode.OPERATE,
        FunctionCode.DIRECT_OPERATE,
        FunctionCode.IMMED_FREEZE,
        FunctionCode.FREEZE_CLEAR,
    }
)

#: How long a select stays armed. Ten seconds is opendnp3's default and the
#: middle of what implementations use; the standard leaves it to the outstation.
DEFAULT_SELECT_TIMEOUT = 10.0

#: The classes a read can ask for that come from the buffers. Class 0 is static
#: data and is the provider's, which is why ``event_class`` returning 0 is not
#: the same as it returning None.
_EVENT_CLASSES = frozenset({EventClass.CLASS_1, EventClass.CLASS_2, EventClass.CLASS_3})

#: The class object, group 60, that names each event class: variation 2 is
#: class 1, and so on. What a request to enable or disable unsolicited
#: responses carries, and what an unsolicited response selects its events by.
_CLASS_VARIATIONS = {
    EventClass.CLASS_1: 2,
    EventClass.CLASS_2: 3,
    EventClass.CLASS_3: 4,
}

#: How long an unsolicited response waits to be confirmed before it is sent
#: again. The standard has the setting cover at least one second to one
#: minute and names no default; five seconds is in common use.
DEFAULT_UNSOLICITED_CONFIRM_TIMEOUT = 5.0

#: How many times an unsolicited response carrying events is sent again when
#: it is not confirmed, where None is without limit. Without limit is what
#: the DNP Users Group's guidance on default settings recommends (AN2015-001),
#: on the grounds that delivering what it reports is the outstation's job.
DEFAULT_UNSOLICITED_RETRIES: int | None = None

#: How long after the retries of one unsolicited response are spent before
#: another is started with nothing else to prompt it.
DEFAULT_UNSOLICITED_RESUME = 60.0

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

_TIMED_ANALOG_EVENTS = frozenset(
    {AnalogEventVariation.INT32_WITH_TIME, AnalogEventVariation.INT16_WITH_TIME}
)

#: The event groups a master may read by name instead of by class, and the
#: kind of event each one selects (D46). Group 22 is the counter change event,
#: which this outstation never buffers: reading it is answered, with nothing,
#: because an empty answer is what a group with no events in it holds.
_EVENT_GROUPS: dict[int, type | None] = {
    GROUP_BINARY_INPUT_EVENT: BinaryEvent,
    GROUP_ANALOG_INPUT_EVENT: AnalogEvent,
    GROUP_FROZEN_COUNTER_EVENT: FrozenCounterEvent,
    GROUP_COUNTER_EVENT: None,
}

#: The qualifiers a class read may carry. ``ALL_OBJECTS`` asks for everything
#: the class holds; the count qualifiers ask for at most that many, which is how
#: a master paces a buffer it does not want in one fragment.
#:
#: A range is not among them. Class objects have no indices to range over -- a
#: class is a reporting priority, not a set of points -- so a start and a stop
#: name nothing, and honoring one would mean inventing a meaning for it.
#: The fewest octets an event occupies on the wire in the default variations: a
#: one-octet index prefix in front of a binary event with time, which is a flag
#: octet and a six-octet timestamp. The budget divided by the smallest event a
#: request could be answered with is an upper bound on how many could fit --
#: and a bound that can be taken before anything is encoded.
_MIN_EVENT_OCTETS = 8

#: Octets one event occupies without its index, by group and variation.
_EVENT_SIZES: dict[tuple[int, int], int] = {
    (GROUP_BINARY_INPUT_EVENT, 1): 1,
    (GROUP_BINARY_INPUT_EVENT, 2): 1 + TIME_SIZE,
    (GROUP_BINARY_INPUT_EVENT, 3): 3,
    (GROUP_FROZEN_COUNTER_EVENT, 1): 5,
    (GROUP_FROZEN_COUNTER_EVENT, 5): 5 + TIME_SIZE,
    **{
        (GROUP_ANALOG_INPUT_EVENT, int(variation)): size
        for variation, size in ANALOG_EVENT_SIZES.items()
    },
}

#: The most *event-carrying* fragments one response may take. A response may
#: run to one more than this, carrying the provider's body alone, when that body
#: will not fit beside the last of the events (D32 and D33) -- the bound stops
#: the events rather than the answer, and a read that asked for static data is
#: still owed it.
#:
#: A count rather than an octet budget or a deadline (D32), and sixteen because
#: that is one full trip through the application sequence space -- a conversation
#: reaching it has spent every sequence number once. A full default buffer is
#: about seven fragments at the default ceiling, so this carries one twice that
#: size and still stops a buffer that fills as fast as it drains.
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


@dataclass
class _Block:
    """One run of events that share an object header."""

    group: int
    variation: int
    members: list[tuple[Event, int, bytes]]
    #: Octets that have to come before the block in the same fragment: the
    #: common time of occurrence that relative times count from.
    prefix: bytes = b""
    #: The time that common time carries, for relative-time blocks.
    base: int | None = None
    #: Whether the clock behind the block's times had been set.
    synchronized: bool = True


def _well_formed(fragment: bytes) -> bool:
    """Whether a fragment could be a request at all.

    It has to hold an application header. A request fits one fragment, so it
    is both the first and the last of its message. And the unsolicited bit
    belongs to the confirmation of an unsolicited response and to nothing
    else a master sends.
    """
    if len(fragment) < REQUEST_HEADER_SIZE:
        return False
    control, function = fragment[0], fragment[1]
    if control & (FIR_MASK | FIN_MASK) != FIR_MASK | FIN_MASK:
        return False
    return not (control & UNS_MASK and function != FunctionCode.CONFIRM)


class ParameterError(Exception):
    """Raised by a provider for a group it serves, asked for points it does not hold.

    A different answer from :class:`UnknownObject` on the wire: the object was
    understood and the range was not, which a master corrects by changing the
    range, where an unknown object is one it should stop asking for.
    """


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
    #: The qualifier of the header this arrived under, which the echo has to
    #: reproduce (D14). None, for a control built by hand, leaves the echo to
    #: choose the narrowest that fits.
    qualifier: QualifierCode | None = None


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


@dataclass(frozen=True)
class SessionFacts:
    """What a session is configured to do, for something that has to describe it.

    A device profile document states an outstation's limits and options. Read
    from the session itself, those statements cannot drift from the session
    that is actually serving; kept beside it in a second place, they would.
    """

    outstation_address: int
    #: The one master this session serves, or None when it serves whichever
    #: master speaks first on a connection.
    master_address: int | None
    #: The largest request fragment that will be reassembled, in octets.
    max_request: int
    #: The largest response fragment that will be sent, in octets.
    max_response: int
    #: Seconds a select stays armed for its operate.
    select_timeout: float
    #: The most fragments one response may run to while it carries events.
    max_event_fragments: int
    controls: bool
    freezes: bool
    time_write: bool
    asks_for_time: bool
    #: Whether classes 1 to 3 are answered from event buffers.
    events: bool
    #: Events each class holds, when there are buffers.
    event_capacity: int | None
    analog_latest_only: bool
    binary_event_variation: int
    analog_event_variation: int
    #: Seconds a fragment waits to be confirmed, or None for no limit.
    confirm_timeout: float | None = None
    cold_restart: bool = False
    #: Whether a control sent to a broadcast address is operated.
    broadcast_controls: bool = False
    #: Function codes turned off by configuration, and refused as unsupported.
    disabled_functions: frozenset[int] = frozenset()
    #: Whether unsolicited responses are on: the initial null response is
    #: sent, and a master may enable reporting by class.
    unsolicited: bool = False
    #: Seconds an unsolicited response waits to be confirmed before it is
    #: sent again.
    unsolicited_confirm_timeout: float = DEFAULT_UNSOLICITED_CONFIRM_TIMEOUT
    #: Times an unsolicited response carrying events is sent again, or None
    #: for no limit.
    unsolicited_retries: int | None = DEFAULT_UNSOLICITED_RETRIES
    #: Seconds after the retries are spent before reporting starts again
    #: unprompted, or None for never.
    unsolicited_resume: float | None = DEFAULT_UNSOLICITED_RESUME


class FreezeProvider(Protocol):
    """What can be frozen. Counters, in every profile this library serves.

    Synchronous, like the other providers and for the same reason. The session
    passes the object headers the master named and whether it asked for the
    counters to be cleared afterwards; what a header selects, and whether a
    clear is honored, are the caller's to decide (D45).
    """

    def freeze(self, headers: Sequence[ObjectHeader], *, clear: bool) -> None:
        """Freeze what *headers* name, or raise :class:`UnknownObject`."""
        ...


@dataclass
class _ArmedSelect:
    """What a select left behind for the operate that may follow."""

    #: ``(group, variation, qualifier, index, octets)`` per control, in order received.
    key: tuple[tuple[int, int, int | None, int, bytes], ...]
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
    #: The request this answered, octet for octet. A repeat is recognized by
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
    #: When it was sent, by the session's clock: what a confirmation is late against.
    at: float = 0.0
    #: Whether it told the master a broadcast had been received, in the mode
    #: where the indication stands until that telling is confirmed.
    broadcast: bool = False


@dataclass(frozen=True)
class _Unsolicited:
    """An unsolicited response, waiting for the master to confirm it.

    Kept apart from :class:`_Outstanding` because the two are separate
    exchanges with separate sequence numbers, and both can be waiting at
    once: a request that is not a read is answered while an unsolicited
    response is still unconfirmed, and that answer may ask for a confirmation
    of its own.
    """

    #: The unsolicited sequence it went out under. Its confirmation carries
    #: the unsolicited bit and this number, and no other retires it.
    sequence: int
    #: The events it carried, held as :class:`_Outstanding` holds them and
    #: for the same reason. Empty for the initial null response.
    events: tuple[Event, ...]
    #: The response as it was sent. A retry that would be the same octet for
    #: octet goes out under the same sequence number; one that differs takes
    #: the next (D70).
    fragment: bytes
    #: The overflow generation it reported, or None if it carried no
    #: overflow bit, as on a solicited response (D23).
    reported_overflow: int | None
    #: When it was last sent, by the session's clock.
    at: float
    #: How many times it has been sent again since the first.
    retries: int
    #: Whether it is the null response that announces a restart, which is
    #: retried without limit and until whose confirmation no events are sent.
    null: bool
    #: Whether it told the master a broadcast had been received.
    broadcast: bool = False


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
    #: What the provider returned, as the blocks it falls into and in the order
    #: it returned them, read once when the response began (D33). One element
    #: for a provider that answers in octets, since this library will not divide
    #: what it cannot see the seams of; as many as the provider gave for one
    #: that implements `read_blocks`.
    #:
    #: Consumed from the front as the response goes, so this is what is still
    #: owed. A deque rather than a list: taking the front of a list shifts
    #: everything behind it, so a provider answering a large point map in many
    #: small blocks would pay for the whole remainder on every block it sent.
    #: That is work proportional to a number the caller chose, which is the
    #: same reason `peek` slices while it walks rather than after.
    static: deque[bytes]
    #: Whether any of it has gone out. Once it has, the response is in its
    #: static half and takes no more events: D20 orders a response as a whole,
    #: not each fragment of it, and an event placed after static data already
    #: sent would leave the master holding a reading older than the event that
    #: superseded it -- which is the ordering the rule exists to get right.
    sending_static: bool = False
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


@runtime_checkable
class BlockReadProvider(Protocol):
    """A read provider that says where its objects end.

    Optional, and deliberately a second method rather than a change to the
    first (D35). Replacing `read` would be a breaking change for every caller,
    including the ones whose point maps fit a fragment and who would gain
    nothing from it -- and it would have this library holding a list of the
    caller's objects rather than a body it forwards, which is closer to knowing
    the point map than D6 wants to be.

    A provider that implements this has its static data split across the
    fragments of a response; one that does not is answered under D31, where a
    body too large for a single fragment is refused.
    """

    def read_blocks(self, headers: Sequence[ObjectHeader]) -> Sequence[bytes]:
        """The same objects `read` would return, as the blocks they fall into.

        Each element is an object header and the objects it describes, exactly
        as `read` would have concatenated them. The split points are the
        caller's: this library never divides one of them, so a block larger
        than a fragment is refused as a whole body would be. That moves the
        boundary rather than removing it.
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
        master_address: int | None = 1,
        max_fragment: int = 2048,
        max_response: int = 2048,
        select_timeout: float = DEFAULT_SELECT_TIMEOUT,
        clock: Callable[[], float] = time.monotonic,
        freeze_provider: FreezeProvider | None = None,
        time_sink: Callable[[int], None] | None = None,
        need_time: bool = False,
        analog_event_variation: AnalogEventVariation = _ANALOG_EVENT_VARIATION,
        confirm_timeout: float | None = DEFAULT_CONFIRM_TIMEOUT,
        restart_handler: Callable[[], int] | None = None,
        broadcast_controls: bool = False,
        disabled_functions: Iterable[int] = (),
        unsolicited: bool = False,
        unsolicited_confirm_timeout: float = DEFAULT_UNSOLICITED_CONFIRM_TIMEOUT,
        unsolicited_retries: int | None = DEFAULT_UNSOLICITED_RETRIES,
        unsolicited_resume: float | None = DEFAULT_UNSOLICITED_RESUME,
    ) -> None:
        """
        Args:
            provider: Answers reads with encoded objects.
            outstation_address: This outstation's link address. Frames addressed
                elsewhere are dropped rather than answered.
            master_address: The master this association serves. A frame from any
                other source is dropped: the address is not authorization, but
                answering an unexpected one would interleave two conversations
                over one set of sequence numbers. None serves a master that is
                not known in advance: the first address to speak on a
                connection is the master for as long as that connection
                lasts, and a new connection may bring another (D64). Without
                transport security that means any peer able to reach the
                listener can read, and command if controls are bound.
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
            freeze_provider: Freezes counters. Without one the freeze functions
                are refused as unsupported, which for an outstation holding no
                counters is the truthful answer (D45).
            time_sink: Receives the time a master writes, in milliseconds since
                the Unix epoch, UTC. Without one a time write is refused as an
                unknown object. What the caller does with the time is its own:
                a device whose clock is disciplined elsewhere may record the
                write and apply nothing (D44).
            need_time: Whether to ask the master for the time from the first
                response, through the indication bit that says so. Cleared by
                an accepted time write; settable again through the property of
                the same name when the caller's clock has drifted.
            analog_event_variation: The variation analog input events are
                reported in. Timed by default, because the timestamp is most
                of what a master reads events for; a profile that fixes
                another -- IEEE 1815.2 selects the 32-bit variation without
                time -- names it here.
            confirm_timeout: Seconds a fragment that asked for confirmation
                waits for it, or None to wait indefinitely. A confirmation
                arriving later retires nothing and continues nothing.
            restart_handler: Makes cold restart available. Called when a
                master asks for one; it starts whatever a restart is for this
                device and returns the milliseconds the master should wait.
                The session answers with that delay and then stands as it
                does at startup. Without a handler the function is refused,
                which is how it is disabled.
            broadcast_controls: Whether a direct operate addressed to every
                outstation is carried out. Off by default: a broadcast is
                answered by nobody, so nothing reports how the control went.
                Freezes and writes sent to a broadcast address are always
                honored.
            disabled_functions: Function codes this outstation is
                configured not to accept, though it implements them. Each
                is refused exactly as a function it never implemented:
                with the unsupported indication, or with silence for a
                function that takes no response or arrives as a
                broadcast. An outstation with no use for a function is
                safer not accepting it. Confirm cannot be disabled; a
                response that asks for confirmation would never be done.
            unsolicited: Whether this outstation reports without being
                asked. Off by default, and off means off: nothing is sent
                that was not requested, a request to enable unsolicited
                responses is refused as unsupported, and every answer is
                what it was before the option existed. On, the session
                announces a restart with a null unsolicited response,
                accepts a master enabling and disabling reporting for
                classes 1 to 3, and reports the events of an enabled class
                as they are buffered. None of that is sent by the session
                itself: its owner calls :meth:`initiate` and writes what
                comes back, which :class:`~py1815.server.OutstationServer`
                does. Turn it on for a master that confirms unsolicited
                responses. While one is unconfirmed a read is held back,
                so a master that ignores them has every read answered up
                to ``unsolicited_confirm_timeout`` late (D71).
            unsolicited_confirm_timeout: Seconds an unsolicited response
                waits for its confirmation before it is sent again.
            unsolicited_retries: How many times an unsolicited response
                carrying events is sent again when it is not confirmed.
                None, the default, is without limit. The null response
                that announces a restart is retried without limit whatever
                this says.
            unsolicited_resume: Seconds after the retries are spent before
                reporting is tried again with nothing to prompt it. A new
                event, a request from the master or a new connection
                starts it again sooner. None leaves it to those three.
                The events are kept either way, and a class poll reads
                them.
        """
        self._provider = provider
        self._controls = control_provider
        self._events = events
        self._select_timeout = select_timeout
        self._clock = clock
        self._select: _ArmedSelect | None = None
        self._outstanding: _Outstanding | None = None
        self._conversation: _Conversation | None = None
        for name, address in (
            ("outstation_address", outstation_address),
            ("master_address", master_address),
        ):
            if address is None:
                continue
            if not 0 <= address <= link.MAX_ADDRESS:
                # The addresses above this are the protocol's own: the
                # broadcast addresses, the self-address and a reserved
                # range. A device assigned one would answer, or be
                # answered, as every device at once.
                raise ValueError(
                    f"{name} is {address}; a device address is 0 to {link.MAX_ADDRESS}"
                )
        if outstation_address == master_address:
            raise ValueError(
                f"outstation_address and master_address are both {master_address}; "
                "the two ends of an association have different addresses"
            )
        self._outstation_address = outstation_address
        self._master_address = master_address
        #: The master being served now: the configured one, or the address
        #: that spoke first on this connection, or nobody yet.
        self._peer: int | None = master_address
        self._frames = link.FrameReader()
        self._reassembler = Reassembler(max_fragment=max_fragment)
        self._max_fragment = max_fragment
        if max_response < RESPONSE_HEADER_SIZE:
            # A response is four octets before it carries anything, so a smaller
            # ceiling is one nothing can honor -- every answer this outstation
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
        self._freezer = freeze_provider
        self._time_sink = time_sink
        if need_time and time_sink is None:
            # An outstation that asks for the time has to be able to take
            # it. One that could not would ask in every response, forever.
            raise ValueError("need_time asks a master for the time and no time_sink is given")
        self._need_time = need_time
        self._analog_event_variation = AnalogEventVariation(analog_event_variation)
        self._confirm_timeout = confirm_timeout
        self._restart_handler = restart_handler
        self._broadcast_controls = broadcast_controls
        self._disabled = frozenset(int(function) for function in disabled_functions)
        if FunctionCode.CONFIRM in self._disabled:
            raise ValueError("the confirm function cannot be disabled")
        #: When a request to record the current time arrived, by this
        #: session's clock, until the write that uses it.
        self._recorded_at: float | None = None
        self._need_time_at_start = need_time
        if need_time and events is not None:
            # A session that asks for the time has a clock nobody has set. One
            # that does not ask says nothing about the clock, so the buffers
            # keep whatever the caller told them: a clock waiting on its first
            # network sync is unset whether or not a master is asked.
            events.synchronized = False
        #: The data link's secondary station state: whether the master has
        #: reset the link, and the frame count bit the next confirmed frame
        #: has to carry.
        self._link_reset = False
        self._expected_fcb = True
        #: The broadcast address a request last arrived under, until a
        #: response has told the master so.
        self._broadcast: link.Broadcast | None = None
        self._broadcast_reassembler = Reassembler(max_fragment=max_fragment)
        #: Who sent the broadcast segments being reassembled. Segments from two
        #: sources are not one fragment, which matters once any address may be
        #: heard: half a request from one and half from another must not run.
        self._broadcast_source: int | None = None
        #: The last request that acted, and its answer, for a retry (D49).
        self._acted: tuple[bytes, bytes] | None = None
        #: A select being repeated, held across the reset every request makes.
        self._repeated_select: _ArmedSelect | None = None

        if unsolicited:
            if confirm_timeout is None:
                # Nothing unsolicited is sent while a solicited response
                # waits to be confirmed. With no limit on that wait, one
                # master that never confirms a read would silence
                # unsolicited reporting for good.
                raise ValueError(
                    "unsolicited responses wait for a solicited confirmation to arrive or "
                    "time out, so they need a confirm_timeout"
                )
            if not unsolicited_confirm_timeout > 0:
                raise ValueError(
                    f"unsolicited_confirm_timeout is {unsolicited_confirm_timeout}; "
                    "a retry needs a wait before it"
                )
            if unsolicited_retries is not None and unsolicited_retries < 0:
                raise ValueError(
                    f"unsolicited_retries is {unsolicited_retries}; it is a count, or None "
                    "for no limit"
                )
            if unsolicited_resume is not None and not unsolicited_resume > 0:
                raise ValueError(
                    f"unsolicited_resume is {unsolicited_resume}; it is a wait, or None "
                    "to wait for an event or the master"
                )
        self._unsolicited = unsolicited
        self._unsolicited_timeout = unsolicited_confirm_timeout
        self._unsolicited_retries = unsolicited_retries
        self._unsolicited_resume = unsolicited_resume
        #: The classes a master has enabled since the last restart. Empty at
        #: startup: a master enables what it wants.
        self._enabled: set[EventClass] = set()
        #: The master those classes are enabled for: the one being served,
        #: or the one last served while a session that takes any master
        #: waits to hear who is on the new connection.
        self._enabled_for: int | None = master_address
        #: Whether the null response that announces a restart has been
        #: confirmed. Until it has, no events are sent unsolicited.
        self._announced = False
        #: The unsolicited response awaiting confirmation, if one is.
        self._awaited: _Unsolicited | None = None
        #: The sequence number the next unsolicited response takes, unless it
        #: repeats the last one octet for octet. A series of its own, apart
        #: from the one requests and their answers count in.
        self._unsolicited_sequence = 0
        #: A read that arrived while an unsolicited response was unconfirmed,
        #: held until that is settled one way or the other (D71).
        self._deferred: bytes | None = None
        #: Whether the retries ran out and reporting is waiting for a reason
        #: to start again: when it gives up waiting, and how many events had
        #: been recorded when it began to.
        self._resting = False
        self._rest_until: float | None = None
        self._rest_mark = 0

    @property
    def restart_indication(self) -> bool:
        return self._restart

    def restart(self) -> None:
        """Stand as this session does at startup.

        For a device that has restarted, whether a master asked for it or the
        power went. The restart indication is set again, the time is asked
        for again if it was at startup, and every exchange in flight is
        forgotten, the data link's included. Buffered events are the
        caller's: a device that keeps them across a restart leaves them, and
        one that does not hands this session a new buffer.

        With unsolicited responses on, a restart is announced again with a
        null response, and no class is enabled until a master enables it:
        what was enabled before the restart is not carried across it.
        """
        # A restart forgets what was in flight on the connection, and not who
        # is on it: a master that commanded the restart is owed the answer,
        # and goes on being served on the connection it is still using.
        peer = self._peer
        self.connection_reset()
        self._peer = peer
        self._enabled.clear()
        self._announced = False
        self._restart = True
        self._need_time = self._need_time_at_start
        self._broadcast = None
        self._recorded_at = None
        if self._need_time and self._events is not None:
            self._events.synchronized = False

    def abandon_select(self) -> None:
        """Forget an armed select, so the operate it was granted for finds none.

        For a control provider whose ability to command changed after the
        select was granted, such as an outstation that became read-only and
        then was given control back. A select is permission given under the
        conditions of the moment it was granted, and an operate arriving after
        those changed has to ask again.
        """
        self._select = None
        self._repeated_select = None

    @property
    def facts(self) -> SessionFacts:
        """This session's configuration, as it stands now."""
        events = self._events
        return SessionFacts(
            outstation_address=self._outstation_address,
            master_address=self._master_address,
            max_request=self._max_fragment,
            max_response=self._max_response,
            select_timeout=self._select_timeout,
            max_event_fragments=_MAX_FRAGMENTS,
            controls=self._controls is not None,
            freezes=self._freezer is not None,
            time_write=self._time_sink is not None,
            asks_for_time=self._need_time,
            events=events is not None,
            event_capacity=None if events is None else events.capacity,
            analog_latest_only=events is not None and events.analog_latest_only,
            binary_event_variation=int(_BINARY_EVENT_VARIATION),
            analog_event_variation=int(self._analog_event_variation),
            confirm_timeout=self._confirm_timeout,
            cold_restart=self._restart_handler is not None,
            broadcast_controls=self._broadcast_controls,
            disabled_functions=self._disabled,
            unsolicited=self._unsolicited,
            unsolicited_confirm_timeout=self._unsolicited_timeout,
            unsolicited_retries=self._unsolicited_retries,
            unsolicited_resume=self._unsolicited_resume,
        )

    @property
    def unsolicited_classes(self) -> frozenset[EventClass]:
        """The classes a master has enabled unsolicited reporting for.

        Empty after a restart, and always empty for a session built without
        unsolicited responses. A session that takes any master empties it
        when a different master is the first to speak on a new connection:
        what one master enabled is not sent to another.
        """
        return frozenset(self._enabled)

    @property
    def need_time(self) -> bool:
        """Whether responses are asking the master to write the time."""
        return self._need_time

    @need_time.setter
    def need_time(self, wanted: bool) -> None:
        if wanted and self._time_sink is None:
            raise ValueError("need_time asks a master for the time and no time_sink is given")
        self._need_time = bool(wanted)

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
        that was about to follow on the socket that just died; honoring it
        across a reconnect would let an operate arrive over a connection the
        select never crossed.

        An unsolicited response in flight is forgotten the same way, with
        the read that was waiting behind it. Its events stay buffered, and
        the next :meth:`initiate` reports them over the new connection. What
        a master enabled survives, as does whether the restart has been
        announced: both are the association's. A session that takes any
        master sends nothing until a master speaks on the new connection,
        and keeps what was enabled only if it is the same one.
        """
        self._awaited = None
        self._deferred = None
        self._resting = False
        self._frames = link.FrameReader()
        self._reassembler.reset()
        self._broadcast_reassembler.reset()
        self._broadcast_source = None
        self._select = None
        self._outstanding = None
        self._conversation = None
        self._acted = None
        # A master taken from the first frame belonged to the connection that
        # carried it. The next connection may be a different master, or the
        # same one restarted under another address.
        self._peer = self._master_address
        # A new connection is a new data link: the master resets it before
        # sending anything that counts frames.
        self._link_reset = False
        self._expected_fcb = True

    def receive(self, data: bytes) -> bytes:
        """Handle received octets, returning the octets to send back."""
        out = bytearray()
        for frame in self._frames.feed(data):
            out += self._handle_frame(frame)
        return bytes(out)

    # --------------------------------------------- outstation-initiated traffic

    def initiate(self) -> bytes:
        """The octets to send that no request asked for, if any are due.

        The second way into the session, for traffic the outstation starts.
        It returns an unsolicited response when one is due: the null response
        that announces a restart, the events of a class the master enabled,
        or either of those again because its confirmation did not arrive in
        time. It also returns the answer to a read that was held back behind
        an unsolicited response whose confirmation never came. Usually it
        returns nothing.

        The owner calls it when a connection is made, after it records
        events, after :meth:`receive`, and when the time
        :meth:`initiate_after` gave has passed, and writes what comes back to
        the master. Calling it more often than that costs little and sends
        nothing extra. A session built without unsolicited responses returns
        nothing, always.

        Like everything else here it does no I/O and starts no timer: time is
        the injected clock, read when this is called. And it reports, which
        is all it does. Nothing on this path calls a control provider or
        changes an output, however long a master stays silent (D71).
        """
        now = self._clock()
        wait = self._initiate_wait(now)
        if wait is None or wait > 0:
            return b""
        awaited = self._awaited
        if awaited is None:
            return self._send(self._unsolicited_response(now))
        return self._unconfirmed(awaited, now)

    def initiate_after(self) -> float | None:
        """Seconds until :meth:`initiate` is next worth calling for the time alone.

        Zero when something is due now. None when nothing is waiting on the
        clock, so only a recorded event, something received, or a new
        connection can give :meth:`initiate` anything to send; an owner calls
        it after each of those whatever this said. A call to :meth:`initiate`
        that returns nothing although this said zero means nothing could be
        sent, and is not a reason to call again at once.
        """
        return self._initiate_wait(self._clock())

    def _unsolicited_destination(self) -> int | None:
        """The link address unsolicited responses go to, or None for nowhere.

        The one place that answers "where does this go" for traffic nobody
        asked for. A response to a request can always go back to whoever
        asked. An unsolicited response has no request to take an address
        from, so with no master known there is nowhere to send it and
        nothing is sent. That is the master being served: the configured one,
        or for a session built to serve any master, the one that spoke first
        on this connection. Such a session answers here with nobody until a
        master has spoken, and again from the moment the connection ends.
        """
        return self._peer

    def _initiate_wait(self, now: float) -> float | None:
        """How long until something is due: zero for now, None for not by the clock."""
        if not self._unsolicited or self._unsolicited_destination() is None:
            return None
        awaited = self._awaited
        if awaited is not None:
            remaining = awaited.at + self._unsolicited_timeout - now
            if remaining > 0:
                return remaining
            # A retry is unsolicited traffic like the first transmission, and
            # waits for a solicited response to be settled as that did. A read
            # held behind it never waits here: holding it ended any solicited
            # response, and every request that could start another discards
            # the read.
            return self._solicited_wait(now)
        if not self._has_news():
            return None
        held = self._solicited_wait(now)
        if held > 0:
            return held
        if self._announced and self._is_resting(now):
            return None if self._rest_until is None else self._rest_until - now
        return 0.0

    def _solicited_wait(self, now: float) -> float:
        """Seconds a solicited response still has to be confirmed in, or zero.

        Nothing unsolicited is sent while a solicited response is waiting for
        its confirmation: not a first transmission and not a retry. A master
        walking through a response it asked for is not interrupted, and the
        events in that response are not offered a second way while the first
        is undecided. The wait ends when the confirmation arrives or its time
        runs out (D51), whichever is first.
        """
        pending = self._outstanding
        if pending is None or self._confirm_timeout is None:
            return 0.0
        return max(0.0, pending.at + self._confirm_timeout - now)

    def _has_news(self) -> bool:
        """Whether there is anything an unsolicited response would carry.

        The restart, until its announcement is confirmed. After that, any
        event in a class the master enabled. An event recorded before its
        class was enabled counts: enabling a class is asking for what it
        holds, and what a poll already retired is no longer there to count.
        """
        if not self._announced:
            return True
        events = self._events
        return events is not None and any(events.count(cls) for cls in self._enabled)

    def _is_resting(self, now: float) -> bool:
        """Whether reporting has stopped and nothing has yet said to start again.

        It stops when the retries run out, or when the oldest event will not
        fit a fragment. A new event ends the rest, as does the time set for
        it. A request from the master and a new connection end it where they
        arrive.
        """
        if not self._resting:
            return False
        if self._events is not None and self._events.recorded != self._rest_mark:
            return False
        return self._rest_until is None or now < self._rest_until

    def _unsolicited_response(self, now: float, previous: _Unsolicited | None = None) -> bytes:
        """Build an unsolicited response, record it as awaited, and return its fragment.

        Built from the buffers as they stand, whether this is a first
        transmission or a retry (D70). ``previous`` is the response being
        retried. If what is built now matches it octet for octet it is the
        same response sent again, and keeps its sequence number; if anything
        differs, in the events or in the indications, it is a new response
        and takes the next one. A master tells the two apart exactly that
        way: the same number means the same octets.

        Nothing is returned, and nothing is awaited, when there turns out to
        be nothing to say: the class was disabled, the events were evicted,
        or none of them fits a fragment.
        """
        selected: list[Event] = []
        body = b""
        null = not self._announced
        if not null:
            classes = sorted(self._enabled)
            if self._events is not None and classes:
                headers = [
                    ObjectHeader(CLASS_GROUP, _CLASS_VARIATIONS[cls], QualifierCode.ALL_OBJECTS)
                    for cls in classes
                ]
                # The same selection, order, blocking and fit to the fragment
                # a class poll gets, because it is the same code: one
                # fragment's worth, oldest first (D27 and D52). What does not
                # fit follows once this is confirmed.
                body, selected, _ = self._event_body(
                    headers, [None] * len(headers), self._max_response - RESPONSE_HEADER_SIZE
                )
            if not selected:
                self._awaited = None
                if self._has_news():
                    # There are events, and the oldest will not fit a fragment:
                    # a ceiling D27 allows. Trying again at every call would
                    # build the same nothing, so this waits, as it does when
                    # the retries run out, for something to change.
                    self._rest(now, None)
                return b""

        if self._outstanding is not None:
            # A solicited response whose time to be confirmed has run out,
            # or this would not have been reached. It is given up on here
            # and not left for a late confirmation to find, because the
            # events it carried may be about to go out again in this one.
            self._abandon()

        iin = self._indications(reporting=selected)
        overflowed = (
            self._events.overflow_generation
            if self._events is not None and iin.second & IIN2Bit.EVENT_BUFFER_OVERFLOW
            else None
        )

        def build(sequence: int) -> bytes:
            return build_response(
                # One fragment, always: first and final. And always asking
                # to be confirmed, with events or without.
                control=AppControl(fir=True, fin=True, con=True, uns=True, sequence=sequence),
                iin=iin,
                body=body,
                function=FunctionCode.UNSOLICITED_RESPONSE,
            )

        if previous is not None and build(previous.sequence) == previous.fragment:
            sequence = previous.sequence
        else:
            sequence = self._unsolicited_sequence
            self._unsolicited_sequence = (sequence + 1) % SEQUENCE_MODULUS
        response = build(sequence)
        self._awaited = _Unsolicited(
            sequence=sequence,
            events=tuple(selected),
            fragment=response,
            reported_overflow=overflowed,
            at=now,
            retries=0 if previous is None else previous.retries + 1,
            null=null,
            broadcast=self._broadcast is not None,
        )
        self._resting = False
        logger.info(
            "dnp3: sending unsolicited sequence %d (%s, attempt %d)",
            sequence,
            "null" if null else f"{len(selected)} event(s)",
            self._awaited.retries + 1,
        )
        return response

    def _unconfirmed(self, awaited: _Unsolicited, now: float) -> bytes:
        """What follows an unsolicited response whose confirmation did not come.

        With a read held behind it, the read is answered and the response is
        not retried: its events go back to being unreported, and the read may
        well be the master asking for them. Reporting starts again afterwards
        if anything is left to report.

        Otherwise it is sent again, until the retries allowed have been
        spent. After that the outstation stops, keeps the events, and waits
        for a reason to start again. The null response is the exception: it
        is sent again for as long as it takes.
        """
        deferred, self._deferred = self._deferred, None
        if deferred is not None:
            logger.info(
                "dnp3: unsolicited sequence %d not confirmed; answering the read held behind it",
                awaited.sequence,
            )
            self._awaited = None
            out = self._send(self._handle_fragment(deferred))
            wait = self._initiate_wait(now)
            if wait is not None and wait <= 0:
                out += self._send(self._unsolicited_response(now))
            return out

        limit = self._unsolicited_retries
        if not awaited.null and limit is not None and awaited.retries >= limit:
            logger.warning(
                "dnp3: unsolicited sequence %d not confirmed after %d retries; "
                "its events stay buffered",
                awaited.sequence,
                awaited.retries,
            )
            self._awaited = None
            self._rest(now, self._unsolicited_resume)
            return b""
        return self._send(self._unsolicited_response(now, previous=awaited))

    def _rest(self, now: float, resume: float | None) -> None:
        """Stop reporting until an event, the master, a connection or *resume* seconds."""
        self._resting = True
        self._rest_until = None if resume is None else now + resume
        self._rest_mark = self._events.recorded if self._events is not None else 0

    def _confirm_unsolicited(self, sequence: int) -> bytes:
        """Retire what the confirmed unsolicited response carried.

        Only the response most recently sent can be confirmed, and only under
        its own sequence number. One naming an earlier response is late: that
        response has been replaced, and what it carried is in the one that
        replaced it, still unacknowledged.

        There is no deadline of its own on this, unlike a solicited
        confirmation (D51). A master does not time an unsolicited response
        out; it confirms on receipt. So a confirmation naming the response
        last sent means that response arrived, however long it took, and
        its events are retired.

        The read held behind the response, if there is one, is answered now
        and as though it had only just arrived, after the events are retired
        so that it does not report them again.
        """
        awaited = self._awaited
        if awaited is None or awaited.sequence != sequence:
            logger.info("dnp3: ignoring an unsolicited confirmation for sequence %d", sequence)
            return b""
        if awaited.broadcast:
            self._broadcast = None
        if self._events is not None:
            self._events.drop(awaited.events)
            if awaited.reported_overflow == self._events.overflow_generation:
                self._events.clear_overflow()
        if awaited.null:
            self._announced = True
        self._awaited = None
        deferred, self._deferred = self._deferred, None
        if deferred is None:
            return b""
        return self._handle_fragment(deferred)

    def _handle_frame(self, frame: link.LinkFrame) -> bytes:
        if not self._addressed_to_us(frame):
            return b""

        if not frame.is_primary:
            logger.debug("dnp3: ignoring secondary link frame from %d", frame.source)
            return b""

        function = frame.function
        # The frame count valid bit belongs on the two functions that count
        # frames and on no other. A frame carrying it wrongly is one whose
        # control octet cannot be trusted, and it is met with silence.
        counted = function in (
            link.PrimaryFunction.CONFIRMED_USER_DATA,
            link.PrimaryFunction.TEST_LINK_STATES,
        )
        if frame.fcv != counted:
            logger.warning(
                "dnp3: dropping link function %d: frame count valid bit is %s", function, frame.fcv
            )
            return b""

        carries_data = function in (
            link.PrimaryFunction.CONFIRMED_USER_DATA,
            link.PrimaryFunction.UNCONFIRMED_USER_DATA,
        )
        if bool(frame.payload) != carries_data:
            # User data with nothing in it, or a link function with data
            # behind it: the length and the function disagree, and a frame
            # that contradicts itself is not acted on.
            logger.warning(
                "dnp3: dropping link function %d carrying %d octet(s)",
                function,
                len(frame.payload),
            )
            return b""

        if frame.is_broadcast:
            # Nothing is ever sent in answer to a broadcast, at any layer: every
            # outstation that heard it would answer at once. Only user data that
            # asks for no link confirmation is processed at all.
            if function == link.PrimaryFunction.UNCONFIRMED_USER_DATA:
                self._receive_broadcast(frame)
            return b""

        if function == link.PrimaryFunction.REQUEST_LINK_STATUS:
            return self._link_reply(link.SecondaryFunction.LINK_STATUS)
        if function == link.PrimaryFunction.RESET_LINK_STATES:
            self._reassembler.reset()
            self._link_reset = True
            self._expected_fcb = True
            return self._link_reply(link.SecondaryFunction.ACK)
        if function == link.PrimaryFunction.TEST_LINK_STATES:
            if not self._link_reset:
                return b""
            if frame.fcb == self._expected_fcb:
                self._expected_fcb = not self._expected_fcb
            return self._link_reply(link.SecondaryFunction.ACK)

        if function not in (
            link.PrimaryFunction.CONFIRMED_USER_DATA,
            link.PrimaryFunction.UNCONFIRMED_USER_DATA,
        ):
            return self._link_reply(link.SecondaryFunction.NOT_SUPPORTED)

        reply = bytearray()
        if function == link.PrimaryFunction.CONFIRMED_USER_DATA:
            if not self._link_reset:
                # Confirmed data counts frames, and there is no count to check
                # it against until the master has reset the link.
                logger.info("dnp3: dropping confirmed user data: the link has not been reset")
                return b""
            reply += self._link_reply(link.SecondaryFunction.ACK)
            if frame.fcb != self._expected_fcb:
                # The frame already accepted, sent again because its
                # confirmation was lost. Confirmed again and not acted on again.
                return bytes(reply)
            self._expected_fcb = not self._expected_fcb

        try:
            fragment = self._reassembler.add(frame.payload)
        except TransportError as exc:
            logger.warning("dnp3: transport error from %d: %s", frame.source, exc)
            return bytes(reply)

        if fragment is None:
            return bytes(reply)
        return bytes(reply) + self._send(self._handle_fragment(fragment))

    def receive_broadcast(self, data: bytes) -> None:
        """Handle octets from a channel that carries broadcasts and nothing else.

        For a listener that hears broadcasts apart from the master's own
        connection, as a datagram socket beside a stream does. Only frames
        addressed to a broadcast address are acted on; anything else arriving
        this way is dropped, since it could not be answered here and is not
        from the connection this session trusts.
        """
        for frame in link.FrameReader().feed(data):
            if frame.is_broadcast:
                self._handle_frame(frame)

    def _receive_broadcast(self, frame: link.LinkFrame) -> None:
        """Act on a broadcast request, and remember to say one was received (D50)."""
        if frame.source != self._broadcast_source:
            if self._broadcast_source is not None:
                logger.info(
                    "dnp3: broadcast from %d abandons one in progress from %d",
                    frame.source,
                    self._broadcast_source,
                )
            self._broadcast_reassembler.reset()
            self._broadcast_source = frame.source
        try:
            fragment = self._broadcast_reassembler.add(frame.payload)
        except TransportError as exc:
            logger.warning("dnp3: transport error in a broadcast: %s", exc)
            return
        if fragment is None:
            return
        self._broadcast = link.Broadcast(frame.destination)
        # A request from the master, like any other, ends an armed select.
        self._select = None
        # And the wait of a read held behind an unsolicited response.
        self._deferred = None
        # And a rest after the retries ran out: a master that speaks, by
        # broadcast or otherwise, is a reason to start reporting again.
        self._resting = False
        if len(fragment) < REQUEST_HEADER_SIZE:
            return
        function = fragment[1]
        if function in self._disabled:
            logger.info("dnp3: broadcast function 0x%02X not acted on: disabled", function)
        elif function == FunctionCode.RECORD_CURRENT_TIME:
            if self._time_sink is not None and len(fragment) == REQUEST_HEADER_SIZE:
                self._recorded_at = self._clock()
        elif function in _FREEZE_FUNCTIONS | _FREEZE_NR_FUNCTIONS:
            if self._freezer is not None:
                self._freeze_unacknowledged(fragment)
        elif function in (FunctionCode.DIRECT_OPERATE, FunctionCode.DIRECT_OPERATE_NR):
            if self._broadcast_controls:
                self._operate_unacknowledged(fragment)
            else:
                logger.info("dnp3: broadcast control not operated: broadcast controls are off")
        elif function == FunctionCode.WRITE:
            try:
                self._handle_write(parse_request(fragment))
            except RequestError as exc:
                logger.warning("dnp3: unreadable broadcast write dropped: %s", exc)
        else:
            logger.info("dnp3: broadcast function 0x%02X noted and not acted on", function)

    def _addressed_to_us(self, frame: link.LinkFrame) -> bool:
        if frame.destination != self._outstation_address and not frame.is_broadcast:
            logger.debug("dnp3: frame for %d is not ours", frame.destination)
            return False
        if self._peer is not None:
            if frame.source != self._peer:
                logger.warning(
                    "dnp3: dropping frame from unexpected master address %d", frame.source
                )
                return False
            return True
        # No master yet, and none configured: the first to speak is the one.
        # It still has to be an address a master could have.
        if not link.is_valid_address(frame.source) or frame.source == self._outstation_address:
            logger.warning(
                "dnp3: dropping frame from address %d, which no master has", frame.source
            )
            return False
        if not frame.is_broadcast:
            # A broadcast is addressed to everyone and answered by no one, so
            # it opens no conversation and settles nothing about who is here.
            self._peer = frame.source
            logger.info("dnp3: serving master address %d on this connection", frame.source)
            if self._enabled and frame.source != self._enabled_for:
                # Enabling a class is one master asking to be told. The master
                # here now is another, which asked for nothing and may not be
                # one that confirms a report, so it starts with none enabled.
                logger.info(
                    "dnp3: master %d did not enable unsolicited reporting; classes disabled",
                    frame.source,
                )
                self._enabled.clear()
            self._enabled_for = frame.source
        return True

    @property
    def master_address(self) -> int | None:
        """The master being served: the configured one, or the one on this connection.

        None while a session that takes any master has not yet heard from one.
        """
        return self._peer

    def _destination(self) -> int:
        """Where a frame this outstation sends is addressed."""
        if self._peer is None:
            # Everything sent answers something received, and what is received
            # from a master names it first. Reaching here is a defect.
            raise RuntimeError("the session has a frame to send and no master to send it to")
        return self._peer

    def _link_reply(self, function: link.SecondaryFunction) -> bytes:
        control = link.control_byte(from_master=False, primary=False, function=function)
        return link.build(control, destination=self._destination(), source=self._outstation_address)

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
                destination=self._destination(),
                source=self._outstation_address,
                payload=tpdu,
            )
        return bytes(out)

    def _indications(self, extra: IIN | None = None, reporting: Sequence[Event] = ()) -> IIN:
        first = int(IINBit.DEVICE_RESTART) if self._restart else 0
        if self._need_time:
            first |= IINBit.NEED_TIME
        if self._broadcast is not None:
            first |= IINBit.BROADCAST
        iin = IIN(first=first) | self._event_indications(reporting)
        return iin | extra if extra else iin

    def _event_indications(self, reporting: Sequence[Event] = ()) -> IIN:
        """Which classes have events waiting, and whether any were lost.

        Derived on every response rather than tracked alongside the buffers
        (D22). A master polling on indications never asks for events it is not
        told about, so a bit that drifts from the buffer is an outstation whose
        data is invisible -- and deriving it makes drift impossible rather than
        unlikely.

        ``reporting`` is what the response being built carries. Those events
        are still buffered, since nothing leaves before it is confirmed, but
        they are not *waiting*: the bit says there is more to fetch, and a
        class whose every event is in this response has no more.
        """
        if self._events is None:
            return IIN()
        first = 0
        for event_class in self._events.classes_with_events(reporting):
            first |= _CLASS_BITS[event_class]
        second = IIN2Bit.EVENT_BUFFER_OVERFLOW if self._events.overflowed() else 0
        return IIN(first=first, second=second)

    def _handle_fragment(self, fragment: bytes) -> bytes:
        response = self._dispatch_fragment(fragment)
        if response and self._broadcast is not None:
            response = self._report_broadcast(response, fragment)
        return response

    def _report_broadcast(self, response: bytes, fragment: bytes) -> bytes:
        """Finish telling the master a broadcast arrived (D50).

        The indication is already in the response. What is left depends on the
        address the broadcast used. Under the one that asks for no
        confirmation, having said it once is enough. Under the others the
        response asks to be confirmed, and the indication stands until it is,
        so a response that went missing does not take the news with it.
        """
        if self._broadcast is link.Broadcast.NO_CONFIRM:
            self._broadcast = None
            return response
        if not response[0] & CON_MASK:
            response = bytes([response[0] | CON_MASK]) + response[1:]
        pending = self._outstanding
        if pending is not None and pending.fragment[0] & 0x0F == response[0] & 0x0F:
            self._outstanding = replace(pending, fragment=response, broadcast=True)
        else:
            self._outstanding = _Outstanding(
                sequence=response[0] & 0x0F,
                events=(),
                request=fragment,
                fragment=response,
                reported_overflow=None,
                at=self._clock(),
                broadcast=True,
            )
        return response

    def _dispatch_fragment(self, fragment: bytes) -> bytes:
        self._repeated_select = self._select
        #: When this request reached the application layer, which is where a
        #: delay measurement counts from.
        started = self._clock()
        if not _well_formed(fragment):
            # Too short to hold an application header, or marked as part
            # of a longer message, or as an unsolicited exchange this
            # outstation never began. A request is one whole fragment, so
            # none of these is a request, and what is not a request is not
            # answered. It still ends a select, like anything else a
            # master sends in place of the operate.
            logger.warning(
                "dnp3: dropping a fragment that is not a request: %s", fragment[:2].hex()
            )
            self._select = None
            return b""
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
            # through noise can authorize an operate the master never selected.
            # An unreadable fragment claiming to be an OPERATE keeps it, which
            # is the corrupted-retransmission case worth keeping it for.
            self._select = None

        if fragment[1] in self._disabled and fragment[1] in _SILENT_FUNCTIONS:
            logger.info("dnp3: dropping function 0x%02X: disabled by configuration", fragment[1])
            self._abandon()
            return b""

        if len(fragment) >= REQUEST_HEADER_SIZE and fragment[1] == FunctionCode.DIRECT_OPERATE_NR:
            # Table 4-2: "same as function code 5 but outstation shall not send
            # a response". Same as function code 5 -- so it operates, and says
            # nothing. Carved out of the set below rather than added to it,
            # because the other four are dropped unexecuted and this one is not.
            #
            # Silence survives a body that does not parse, which is the case
            # that early branch exists for: a master that asked for no response
            # is not listening for a parse error either.
            self._abandon()
            self._operate_unacknowledged(fragment)
            return b""

        if (
            len(fragment) >= REQUEST_HEADER_SIZE
            and fragment[1] in _FREEZE_NR_FUNCTIONS
            and self._freezer is not None
        ):
            # The same carve-out, for the same reason: "same as function code
            # 7" is a freeze that happens and is not reported.
            self._abandon()
            self._freeze_unacknowledged(fragment)
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
            self._abandon()
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
            if request.control.uns and not self._unsolicited:
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
            if request.control.uns:
                # With unsolicited responses on, the bit sends the
                # confirmation to the unsolicited exchange and nowhere else.
                # The solicited selection is still not touched by it.
                return self._confirm_unsolicited(sequence)
            return self._confirm(sequence)

        if self._acted is not None and self._acted[0] == fragment:
            # The request this outstation last acted on, sent again unchanged:
            # a retry by a master that did not hear the answer. It is given
            # the answer again, and the action is not taken again (D49).
            logger.info("dnp3: repeating the answer for sequence %d without acting", sequence)
            return self._acted[1]
        self._acted = None

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
        # One path is deliberately outside it: a fragment that did not parse is
        # not evidence the master moved on. It is evidence something arrived
        # garbled, which is when a retransmission of the held response is most
        # likely to be what comes next, and discarding the cache on noise would
        # throw it away exactly then.
        #
        # The functions that ask for no response used to be outside it too, on
        # the grounds that they send nothing for a confirmation to be late
        # against. That was true of a single held response and false as soon as
        # responses could span fragments: one arriving mid-conversation left the
        # rest of an abandoned read to be drawn out by the next confirmation.
        # They call `_abandon` above instead.
        self._abandon()

        if request.function in self._disabled:
            logger.info(
                "dnp3: refusing function 0x%02X: disabled by configuration", request.function
            )
            return null_response(
                sequence=sequence,
                iin=self._indications(IIN(second=IIN2Bit.FUNC_NOT_SUPPORTED)),
            )

        if known is FunctionCode.READ and self._awaited is not None:
            # A read is not answered while an unsolicited response waits to be
            # confirmed (D71). The events in that response are neither
            # reported nor unreported until the master says which, and a read
            # answered now would have to guess: send them again, or leave
            # them out and hope. So the read is held, and answered when the
            # confirmation arrives or the wait for it ends. A second read
            # arriving meanwhile replaces the first, and any other request
            # discards it, which `_abandon` has just done.
            logger.info(
                "dnp3: holding the read at sequence %d until unsolicited sequence %d is settled",
                sequence,
                self._awaited.sequence,
            )
            self._deferred = fragment
            return b""

        if known in _CONTROL_FUNCTIONS and self._controls is None:
            logger.info("dnp3: refusing control function %s: monitor role", known.name)
            # Answered as an unknown object, not an unsupported function.
            # The function codes are ones every outstation knows; what a
            # monitor lacks is anything for them to act on, and a master is
            # told so in the terms the certification procedures expect of
            # a device with no outputs.
            return null_response(
                sequence=sequence,
                iin=self._indications(IIN(second=IIN2Bit.OBJECT_UNKNOWN)),
            )

        if (
            known not in _SUPPORTED_FUNCTIONS
            and not (known in _FREEZE_FUNCTIONS and self._freezer is not None)
            and not (known is FunctionCode.COLD_RESTART and self._restart_handler is not None)
            and not (known is FunctionCode.RECORD_CURRENT_TIME and self._time_sink is not None)
            and not (known is FunctionCode.ENABLE_UNSOLICITED and self._unsolicited)
        ):
            # Same indication either way; the log is where the two differ. A
            # named function is one the standard assigns and this outstation
            # does not implement, and an unrecognized code is one the standard
            # does not assign, which is the case worth a second look.
            if known is None:
                logger.info("dnp3: refusing function 0x%02X: unrecognized", request.function)
            else:
                logger.info("dnp3: refusing function %s: not implemented", known.name)
            return null_response(
                sequence=sequence,
                iin=self._indications(IIN(second=IIN2Bit.FUNC_NOT_SUPPORTED)),
            )

        if known in _CONTROL_FUNCTIONS:
            return self._acting(fragment, known, self._handle_control(request, known))

        if known is FunctionCode.COLD_RESTART:
            return self._cold_restart(request)

        if known is FunctionCode.ENABLE_UNSOLICITED:
            return self._set_unsolicited(request, enable=True)

        if known is FunctionCode.DISABLE_UNSOLICITED:
            if self._unsolicited:
                return self._set_unsolicited(request, enable=False)
            return self._disable_unsolicited(request)

        if known in _FREEZE_FUNCTIONS:
            return self._acting(fragment, known, self._handle_freeze(request, known))

        if known is FunctionCode.DELAY_MEASURE:
            return self._delay_measure(request, started)

        if known is FunctionCode.RECORD_CURRENT_TIME:
            if request.body:
                return null_response(
                    sequence=sequence, iin=self._indications(IIN(second=IIN2Bit.PARAM_ERROR))
                )
            # The first half of time synchronization over a network: note
            # when this arrived. The master then writes when it sent it,
            # and the difference is how long ago that was. A second
            # request before the write replaces the first.
            self._recorded_at = started
            return null_response(sequence=sequence, iin=self._indications())

        if known is FunctionCode.WRITE:
            return self._handle_write(request)
        return self._handle_read(request, fragment)

    def _acting(self, fragment: bytes, known: FunctionCode, response: bytes) -> bytes:
        """Remember a request that acted, so its retry does not act again (D49)."""
        if known in _ACT_ONCE:
            self._acted = (fragment, response)
        return response

    def _cold_restart(self, request: Request) -> bytes:
        """Answer with how long the restart takes, then stand as at startup."""
        assert self._restart_handler is not None
        sequence = request.control.sequence
        if request.body:
            return null_response(
                sequence=sequence, iin=self._indications(IIN(second=IIN2Bit.PARAM_ERROR))
            )
        delay_ms = min(0xFFFF, max(0, int(self._restart_handler())))
        response = build_response(
            control=AppControl(fir=True, fin=True, con=False, sequence=sequence),
            iin=self._indications(),
            body=bytes([TIME_DELAY_GROUP, TIME_DELAY_FINE_VARIATION, QualifierCode.UINT8_COUNT, 1])
            + struct.pack("<H", delay_ms),
        )
        logger.info("dnp3: cold restart requested; restarting in %d ms", delay_ms)
        self.restart()
        return response

    def _disable_unsolicited(self, request: Request) -> bytes:
        """Agree, having nothing to stop (D21).

        The asymmetry with ``ENABLE_UNSOLICITED`` is the point. This outstation
        sends no unsolicited responses, so it is already in the state this
        request asks for, and refusing it answers a question the master did not
        ask. ``ENABLE`` asks for something this outstation does not do, and
        saying so is the honest answer rather than the matching one.

        Nothing is recorded. There is no state to enter that is not already the
        state. This is the answer of a session built without unsolicited
        responses, and only of one: with them on, the request goes to
        ``_set_unsolicited``, which examines what it names (D69).

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

    def _set_unsolicited(self, request: Request, *, enable: bool) -> bytes:
        """Turn unsolicited reporting on or off for the classes a master names (D69).

        The request names classes 1 to 3 with the class object and the
        qualifier that means all of it, and is answered with a null response.
        Anything else is refused out loud and changes nothing, including the
        classes named beside it: a request half applied would leave a master
        unsure what it had enabled. Another object, class 0 among them, is an
        object this function does not apply to. A class named with a count or
        a range is a parameter that means nothing here, as is a request that
        names nothing at all.

        Enabling a class that holds no events is accepted, and so is
        disabling one that was never enabled. Neither is an error; they are
        how a master puts the outstation in a known state.

        Disabling stops events of that class being sent unsolicited from
        here on. It discards nothing: the events stay buffered for a poll.
        An unsolicited response already sent is still confirmed in the
        ordinary way if its confirmation arrives; if it does not, what is
        sent in its place is built from the classes still enabled.
        """
        sequence = request.control.sequence
        name = "ENABLE_UNSOLICITED" if enable else "DISABLE_UNSOLICITED"
        named: list[EventClass] = []
        for header in request.headers:
            if header.event_class not in _EVENT_CLASSES:
                logger.info(
                    "dnp3: %s refused: group %d variation %d is not an event class",
                    name,
                    header.group,
                    header.variation,
                )
                return null_response(
                    sequence=sequence, iin=self._indications(IIN(second=IIN2Bit.OBJECT_UNKNOWN))
                )
            if header.qualifier is not QualifierCode.ALL_OBJECTS:
                logger.info(
                    "dnp3: %s refused: qualifier 0x%02X selects nothing on a class",
                    name,
                    int(header.qualifier),
                )
                return null_response(
                    sequence=sequence, iin=self._indications(IIN(second=IIN2Bit.PARAM_ERROR))
                )
            named.append(EventClass(header.event_class))
        if not named:
            return null_response(
                sequence=sequence, iin=self._indications(IIN(second=IIN2Bit.PARAM_ERROR))
            )
        if enable:
            self._enabled.update(named)
        else:
            self._enabled.difference_update(named)
        logger.info(
            "dnp3: %s for class(es) %s; now enabled: %s",
            name,
            ", ".join(str(int(cls)) for cls in named),
            ", ".join(str(int(cls)) for cls in sorted(self._enabled)) or "none",
        )
        return null_response(sequence=sequence, iin=self._indications())

    def _handle_freeze(self, request: Request, known: FunctionCode) -> bytes:
        """Freeze what the request names, and say only whether it could (D45).

        A freeze has no objects to return: the frozen values are read
        afterwards, as static frozen counters or as the events the freeze
        buffered. So the answer is a null response, and the indications are the
        whole of it.
        """
        assert self._freezer is not None
        sequence = request.control.sequence
        try:
            headers = parse_header_list(request.body)
        except RequestError as exc:
            logger.warning("dnp3: malformed %s: %s", known.name, exc)
            return null_response(sequence=sequence, iin=self._indications(IIN(second=exc.bit)))
        if not headers:
            # A freeze that names nothing freezes nothing, and agreeing to it
            # would leave a master believing a log entry exists.
            return null_response(
                sequence=sequence, iin=self._indications(IIN(second=IIN2Bit.PARAM_ERROR))
            )
        try:
            self._freezer.freeze(headers, clear=known in _CLEARING_FREEZES)
        except (UnknownObject, ParameterError) as exc:
            logger.info("dnp3: %s refused: %s", known.name, exc)
            bit = IIN2Bit.PARAM_ERROR if isinstance(exc, ParameterError) else IIN2Bit.OBJECT_UNKNOWN
            return null_response(sequence=sequence, iin=self._indications(IIN(second=bit)))
        logger.info("dnp3: %s executed (%d header(s))", known.name, len(headers))
        return null_response(sequence=sequence, iin=self._indications())

    def _freeze_unacknowledged(self, fragment: bytes) -> None:
        """Execute a freeze that asks for no response, and tell nobody."""
        assert self._freezer is not None
        known = FunctionCode(fragment[1])
        try:
            headers = parse_header_list(fragment[REQUEST_HEADER_SIZE:])
        except RequestError as exc:
            logger.warning("dnp3: unreadable %s dropped: %s", known.name, exc)
            return
        if not headers:
            logger.warning("dnp3: %s naming nothing dropped", known.name)
            return
        try:
            self._freezer.freeze(headers, clear=known in _CLEARING_FREEZES)
        except (UnknownObject, ParameterError) as exc:
            logger.info("dnp3: %s dropped: %s", known.name, exc)
            return
        logger.info("dnp3: %s executed (%d header(s))", known.name, len(headers))

    def _delay_measure(self, request: Request, started: float) -> bytes:
        """Report how long this outstation held the request (D44).

        A master measures the round trip, subtracts this, and halves what is
        left to learn the one-way delay it should add to the time it writes
        next. The figure is the time between the request reaching the
        application layer and this response being built, which over TCP is
        close to nothing; reporting it honestly is what keeps the master's
        arithmetic right on a link where it is not.
        """
        sequence = request.control.sequence
        if request.body:
            # A delay measurement is a function code and nothing else.
            return null_response(
                sequence=sequence, iin=self._indications(IIN(second=IIN2Bit.PARAM_ERROR))
            )
        held_ms = min(0xFFFF, max(0, round((self._clock() - started) * 1000)))
        body = bytes(
            [TIME_DELAY_GROUP, TIME_DELAY_FINE_VARIATION, QualifierCode.UINT8_COUNT, 1]
        ) + struct.pack("<H", held_ms)
        return build_response(
            control=AppControl(fir=True, fin=True, con=False, sequence=sequence),
            iin=self._indications(),
            body=body,
        )

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
            statuses = self._provider_statuses(self._controls.select, controls)
            if any(status is CommandStatus.SUCCESS for status in statuses):
                # D16 arms the request received rather than the objects that
                # succeeded, so that the operate a master sends next -- which is
                # the request it already sent -- still matches. That reasoning
                # runs out when nothing succeeded: there is no operate this
                # select could authorize, and arming it would let a point the
                # outstation refused to select be executed by the operate that
                # followed.
                key = _match_key(controls)
                repeated = self._repeated_select
                # The same select under the same sequence number is the master
                # trying again, not selecting again, and the time it has to
                # operate runs from the select it first sent.
                retry = (
                    repeated is not None and repeated.key == key and repeated.sequence == sequence
                )
                self._select = _ArmedSelect(
                    key=key,
                    at=repeated.at if retry and repeated is not None else self._clock(),
                    sequence=sequence,
                )
            else:
                self._select = None
        elif known is FunctionCode.OPERATE:
            statuses = self._operate_after_select(controls, sequence)
        else:
            statuses = self._provider_statuses(self._controls.operate, controls)

        # A point that cannot be controlled is a request naming something that
        # is not there, which the indications say as well as the status does.
        refused = any(status is CommandStatus.NOT_SUPPORTED for status in statuses)
        return build_response(
            control=AppControl(fir=True, fin=True, sequence=sequence),
            iin=self._indications(IIN(second=IIN2Bit.PARAM_ERROR) if refused else None),
            body=_echo(controls, statuses),
        )

    @staticmethod
    def _provider_statuses(
        method: Callable[[Sequence[Control]], Sequence[CommandStatus]],
        controls: Sequence[Control],
    ) -> list[CommandStatus]:
        """Ask the provider about the controls that arrived well formed.

        A control's status field is the outstation's to fill in; a request
        carries zero there. One that arrives carrying anything else is not
        handed to the provider at all, and is answered as a format error.
        """
        sound = [c for c in controls if c.command.status is CommandStatus.SUCCESS]
        answers = iter(_checked(method(sound), sound)) if sound else iter(())
        return [
            next(answers)
            if control.command.status is CommandStatus.SUCCESS
            else CommandStatus.FORMAT_ERROR
            for control in controls
        ]

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
        return self._provider_statuses(self._controls.operate, controls)

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
                        qualifier=block.header.qualifier,
                    )
                )
        if not controls:
            raise RequestError("a control request carries no controls")
        return controls

    def _handle_read(self, request: Request, fragment: bytes) -> bytes:
        sequence = request.control.sequence
        if not request.headers:
            # A read names what it reads. One naming nothing is malformed,
            # and an empty answer would say it had been carried out.
            return null_response(
                sequence=sequence, iin=self._indications(IIN(second=IIN2Bit.PARAM_ERROR))
            )
        event_headers, static_headers = self._split_read(request.headers)

        unusable = [h for h in event_headers if h.qualifier not in _CLASS_QUALIFIERS]
        if unusable:
            # Refused rather than answered with everything the class holds. A
            # master that asked for a selection and received the whole buffer
            # has been told its request was honored when it was ignored, which
            # is the shape of failure D9 exists to rule out.
            logger.info(
                "dnp3: class read refused: qualifier 0x%02X selects nothing on a class",
                int(unusable[0].qualifier),
            )
            return null_response(
                sequence=sequence,
                iin=self._indications(IIN(second=IIN2Bit.PARAM_ERROR)),
            )

        static: list[bytes] = []
        if static_headers or not event_headers:
            try:
                static = self._static_blocks(static_headers)
            except (UnknownObject, ParameterError) as exc:
                logger.info("dnp3: read refused: %s", exc)
                bit = (
                    IIN2Bit.PARAM_ERROR
                    if isinstance(exc, ParameterError)
                    else IIN2Bit.OBJECT_UNKNOWN
                )
                return null_response(sequence=sequence, iin=self._indications(IIN(second=bit)))

        oversized = max((len(block) for block in static), default=0)
        if oversized + RESPONSE_HEADER_SIZE > self._max_response:
            # Decided before any fragment is built, and on the largest single
            # block rather than on the total. Blocks travel after the events and
            # may span fragments (D35), so a body larger than one fragment is
            # answerable; a *block* larger than one is not, however many
            # fragments follow.
            #
            # Refused rather than truncated. A provider that answers in octets
            # gives one block this library cannot see the seams of, and one that
            # answers in blocks has already said where they are -- cutting
            # either at an arbitrary octet would hand the master half an object.
            #
            # And refused rather than sent. A fragment past the ceiling is one
            # the master discards, so sending it loses the whole response and
            # says nothing about why; four octets carrying PARAM_ERROR arrive,
            # and a master that knows its request was too large can narrow it.
            # This is the same answer the control path gives for the same
            # reason.
            logger.warning(
                "dnp3: refusing read: a static block of %d octets exceeds the %d the master "
                "can receive",
                oversized + RESPONSE_HEADER_SIZE,
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
            static=deque(static),
            counts=[header.count for header in event_headers],
        )
        body, selected, final = self._fragment(conversation)

        iin = self._indications(reporting=selected)
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
                at=self._clock(),
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

        Once the events are done -- or the bound has stopped them -- the static
        data follows them, as much of it as fits. A provider answering in octets
        gives one block, so that is all of it or none of it, and none means it
        travels in the fragment after this one rather than displacing events to
        make room here (D33). A provider answering in blocks may have its data
        spread over as many fragments as it takes (D35).

        The response ends when the events are done and nothing static is still
        owed. Reserving room for the body in an earlier fragment instead would
        answer a mixed read with fewer events than the same read without a body,
        which is what D33 exists to prevent.
        """
        whole = self._max_response - RESPONSE_HEADER_SIZE

        if (
            conversation.fragments > _MAX_FRAGMENTS
            or conversation.sending_static
            or not conversation.headers
        ):
            # No events to place: the read named none, the bound has spent them
            # all, or the static half of the response has begun and the events
            # are behind it now.
            body = self._take_static(conversation, whole)
            return body, [], not conversation.static

        body, selected, complete = self._event_body(
            conversation.headers, conversation.counts, whole
        )

        # Whether another fragment could carry anything this one could not. An
        # incomplete answer that placed no events is not progress -- nothing
        # fits, so no continuation would do better, and a conversation would be
        # sixteen empty fragments. That case ends here, which is D27's cap.
        more = not complete and bool(selected)
        at_bound = conversation.fragments >= _MAX_FRAGMENTS

        if more and not at_bound:
            return body, selected, False

        if more:
            # The events stop here whatever they did. Asking only when the
            # *budget* cut them short left the bound bypassed by a device
            # recording a batch between every confirmation: each fragment
            # answered its buffer in full, the body never fit beside it, and the
            # response never ended.
            logger.info(
                "dnp3: ending a response at %d fragments with events still buffered",
                conversation.fragments,
            )

        # The events are done, so the static data follows them (D20 and D33) --
        # as much of it as fits, which for a provider answering in octets is all
        # of it or none. What does not fit travels in the fragments after this
        # one rather than displacing events to make room here (D33).
        body += self._take_static(conversation, whole - len(body))
        return body, selected, not conversation.static

    def _take_static(self, conversation: _Conversation, room: int) -> bytes:
        """As many of the provider's blocks as fit, in the order it gave them.

        Stops at the first that does not rather than looking past it for a
        smaller one. The provider's order is the answer's order, and a response
        that reordered its objects would be telling the master something the
        provider did not say.
        """
        body = b""
        while conversation.static and len(conversation.static[0]) <= room - len(body):
            body += conversation.static.popleft()
        if body:
            conversation.sending_static = True
        return body

    def _static_blocks(self, headers: Sequence[ObjectHeader]) -> list[bytes]:
        """What the provider answers with, as the blocks it falls into.

        One block for a provider that answers in octets: this library will not
        divide what it cannot see the seams of, so that body travels whole or
        the read is refused (D31). As many as it gives for a provider that
        implements ``read_blocks``, which is how a point map too large for one
        fragment reaches a master at all (D35).
        """
        provider = self._provider
        if isinstance(provider, BlockReadProvider):
            return [bytes(block) for block in provider.read_blocks(headers) if block]
        body = provider.read(headers)
        return [body] if body else []

    def _abandon(self) -> None:
        """Forget the response in flight, because the master has moved on.

        Both halves together: the fragment awaiting confirmation and the
        conversation that would draw out the rest of it. Leaving either is a
        master that sent something else and is answered, several requests
        later, with the remainder of a read it has stopped waiting for.
        """
        self._outstanding = None
        self._conversation = None
        # A read held behind an unsolicited response goes with it: the master
        # sent something else, and is not waiting for that answer any more.
        self._deferred = None
        # And a master that speaks is a reason to start reporting again.
        self._resting = False

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

        pending = self._outstanding
        if pending is None or pending.sequence != sequence:
            logger.info("dnp3: ignoring a confirmation for sequence %d", sequence)
            return b""

        # Guarding the retiring rather than the whole method. A confirmation
        # moves a conversation on whether or not there are events in it: a
        # provider answering in blocks (D35) can spread static data over several
        # fragments with no buffers configured at all, and returning here left
        # such a response stuck after its first fragment.
        if self._confirm_timeout is not None and self._clock() - pending.at > self._confirm_timeout:
            # Too late (D51). This outstation gave up on that fragment: its
            # events stay buffered for the next read and whatever was to
            # follow it is not sent, which is what a master that timed out
            # itself expects to find.
            logger.info("dnp3: confirmation for sequence %d arrived too late", sequence)
            self._abandon()
            return b""

        if pending.broadcast:
            self._broadcast = None
        if self._events is not None:
            self._events.drop(pending.events)
            if pending.reported_overflow == self._events.overflow_generation:
                # ``None`` never matches a generation, which is how a response
                # that carried no overflow bit declines to clear one.
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
        iin = self._indications(reporting=selected)
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
            # whole.
            #
            # Leaving it clear also left nothing cached to replay, so losing
            # such a fragment deadlocked the exchange in exactly the way D34
            # exists to prevent -- the master repeats its confirmation and is
            # answered with silence.
            #
            # Unconditional here, where `_handle_read` computes `confirmable`,
            # and the difference is the conversation rather than the content: a
            # response that fits one fragment and carries nothing to retire
            # needs no confirmation, while the last fragment of a conversation
            # does even when it carries the same nothing.
            control=AppControl(fir=False, fin=final, con=True, sequence=sequence),
            iin=iin,
            body=body,
        )
        self._outstanding = _Outstanding(
            at=self._clock(),
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
        events = [h for h in headers if self._reads_events(h)]
        static = [h for h in headers if not self._reads_events(h)]
        return events, static

    def _reads_events(self, header: ObjectHeader) -> bool:
        """Whether a read header is answered from the buffers (D46).

        A class header is. So is an event group named directly, in any
        variation this session can write for it, or in variation 0, which asks
        for the default. A variation it cannot write is left to the provider,
        which does not serve it, so the master hears that the object is
        unknown and never receives a variation it did not name.
        """
        if header.event_class in _EVENT_CLASSES:
            return True
        if header.event_class is not None:
            return False
        return header.variation in _EVENT_VARIATIONS.get(header.group, ())

    def _held(self, header: ObjectHeader, limit: int) -> list[Event]:
        """The oldest events a header selects, without removing them."""
        assert self._events is not None
        if header.event_class is not None:
            return self._events.peek(EventClass(header.event_class), limit=limit)
        kind = _EVENT_GROUPS[header.group]
        return [] if kind is None else self._events.peek_kind(kind, limit=limit)

    def _event_body(
        self, headers: Sequence[ObjectHeader], counts: list[int | None], budget: int
    ) -> tuple[bytes, list[Event], bool]:
        """The event objects the named headers select, oldest first.

        Events lead the response, before any static data beside them (D20): a
        master applies a fragment in order, and a static value written after the
        events that led to it leaves the point at the value it should end up
        holding.

        Nothing selected is an ordinary outcome, for a master polling to find
        out whether anything happened.

        Nothing is dropped here, which is why the selection comes back beside
        the octets. An event leaves the buffer when the master confirms the
        response carrying it (D18), so a master that reads and never confirms
        sees the same events on its next read.

        **Selected by header, sent in the order they happened (D52).** Each
        header picks its events, up to its own count; what was picked is then
        sent oldest first whichever header picked it. A master reading three
        classes at once is asking what happened, and two changes of a binary
        point's neighbors reported out of order tell it something that did not.

        ``budget`` is the octets left for events. What does not fit is left in
        the buffer and left out of the returned selection, so the confirmation
        that follows retires only what was actually sent and the class
        indication bits go on asking for the rest (D27). The newest are the
        ones left behind, so what a later fragment carries still follows what
        this one did.

        It also bounds the work, not just the octets: the selection is cut to
        what could possibly fit before anything is encoded, so a small response
        over a large buffer costs the response and not the buffer.

        The third return says whether the budget is what stopped it. A count
        qualifier stopping it does not count: a master that asked for at most so
        many has been answered in full, and a response that carried on would be
        sending events it declined.

        ``counts`` is what each header still has coming, and is decremented by
        what actually went out. A count is a bound on the response, not on each
        fragment of it: reapplying it whole to every continuation would answer
        a request for three hundred events with as many as the buffer held,
        three hundred at a time.
        """
        assert self._events is not None
        #: Identities already picked. A master naming a class twice, or a class
        #: and a group that overlap it, asked about those events twice, and
        #: sending one once per header would report the same change twice.
        picked: set[int] = set()
        #: Whether the budget, not the master's own count, is what stopped
        #: this short. It is what decides `FIN`.
        truncated = False
        chosen: list[tuple[Event, int]] = []
        # A strict upper bound on how many events could fit at all: nothing
        # these headers select encodes smaller, and a block costs a header
        # on top, so nothing that would have fitted is left behind here.
        room = max(0, budget // self._smallest_event(headers))

        # Header order: the count on each header belongs to that header.
        for index, header in enumerate(headers):
            limit = counts[index]
            if limit is not None and limit <= 0:
                # Already answered in full by an earlier fragment.
                continue
            remaining = room - len(chosen)
            # Asked for only what could still fit, plus what the overlap check
            # is about to discard, plus one: so that "there is more behind
            # this" is a fact and not an inference from having filled the room.
            held = self._held(header, len(picked) + remaining + 1)
            selected = [event for event in held if id(event) not in picked]
            if len(selected) > remaining:
                if limit is None or limit > remaining:
                    truncated = True
                selected = selected[:remaining]
            if limit is not None:
                # A count qualifier is "at most this many", which is how a
                # master paces a buffer it does not want in one fragment.
                selected = selected[:limit]
            picked.update(id(event) for event in selected)
            chosen += [(event, index) for event in selected]

        chosen.sort(key=lambda pair: pair[0].order)

        body = b""
        sent: list[Event] = []
        used = [0] * len(headers)

        def settle(complete: bool) -> tuple[bytes, list[Event], bool]:
            for index, taken in enumerate(used):
                limit = counts[index]
                if limit is not None:
                    counts[index] = limit - taken
            return body, sent, complete

        for block in self._event_blocks(chosen, headers):
            group, variation, members = block.group, block.variation, block.members
            # Split at the largest count a header can carry. A buffer wide
            # enough to hold more than this of one type in a row is legal --
            # capacity has no upper bound -- and encoding it as one block
            # would raise out of request handling instead of answering.
            for start in range(0, len(members), _MAX_BLOCK_EVENTS):
                chunk = members[start : start + _MAX_BLOCK_EVENTS]
                items = [(event.index, encoded) for event, _, encoded in chunk]
                # What must precede the block goes with it or not at all: a
                # common time with no events behind it says nothing, and
                # relative times with no common time before them in the same
                # fragment cannot be read.
                room_left = budget - len(body) - len(block.prefix)
                fitted, octets = _fitting(group, variation, items, room_left)
                if fitted:
                    body += block.prefix + octets
                for event, index, _ in chunk[:fitted]:
                    sent.append(event)
                    used[index] += 1
                if fitted < len(chunk):
                    # The budget cut this block short, so the response is not
                    # complete however the rest of it looks.
                    return settle(False)
        return settle(not truncated)

    def _smallest_event(self, headers: Sequence[ObjectHeader]) -> int:
        """The fewest octets one event these headers select could occupy, index included.

        A class header is answered in the default variations, so the
        smallest of those; a group named with a variation is answered in
        that one. Taken per request because the smallest variation there
        is, a binary event without time, is a quarter the size of the
        default, and bounding every read by it would have a full response
        encode four times what it can send.
        """
        defaults = min(
            _MIN_EVENT_OCTETS,
            1 + _EVENT_SIZES[(GROUP_ANALOG_INPUT_EVENT, int(self._analog_event_variation))],
        )
        if self._events is not None and self._events.holds_unsynchronized:
            # Those travel with relative time, which is smaller than the default.
            defaults = min(defaults, 1 + _EVENT_SIZES[(GROUP_BINARY_INPUT_EVENT, 3)])
        smallest = defaults
        for header in headers:
            if header.event_class is None and header.variation:
                named = _EVENT_SIZES.get((header.group, header.variation))
                if named is not None:
                    smallest = min(smallest, 1 + named)
        return smallest

    def _event_blocks(
        self, chosen: Sequence[tuple[Event, int]], headers: Sequence[ObjectHeader]
    ) -> list[_Block]:
        """Events grouped into the blocks they travel in, in the order given.

        Consecutive events of one group and variation share a block. A run of
        analog events interrupted by a binary one is three blocks and not two,
        because reordering them into two would tell the master a different
        story about when things happened.

        The variation is the one the selecting header named, or the session's
        default where it named none: a class header, or variation 0.

        **A binary event stamped before the clock was set travels with
        relative time.** An absolute time is a claim that the clock was right,
        so such an event is sent as an offset from a common time of occurrence
        marked unsynchronized, whatever timed variation was asked for. A
        master that names the relative variation gets it for every event,
        behind a common time that says which kind of clock stamped them. A
        relative time is sixteen bits, so a run is broken, and given a new
        common time, when an event falls outside that reach or the clock's
        state changes.
        """
        blocks: list[_Block] = []
        for event, index in chosen:
            header = headers[index]
            named = header.variation if header.event_class is None else 0
            prefix = b""
            base: int | None = None
            synchronized = True
            if isinstance(event, AnalogEvent):
                group = GROUP_ANALOG_INPUT_EVENT
                analog = AnalogEventVariation(named) if named else self._analog_event_variation
                variation = int(analog)
                encoded = encode_analog_event(
                    event.point,
                    variation=analog,
                    timestamp_ms=event.timestamp_ms if analog in _TIMED_ANALOG_EVENTS else None,
                )
            elif isinstance(event, FrozenCounterEvent):
                group = GROUP_FROZEN_COUNTER_EVENT
                variation = named or FROZEN_COUNTER_EVENT_VARIATION
                encoded = (
                    encode_frozen_counter_event(event.point, timestamp_ms=event.timestamp_ms)
                    if variation == FROZEN_COUNTER_EVENT_VARIATION
                    else encode_counter(event.point)
                )
            else:
                group = GROUP_BINARY_INPUT_EVENT
                variation = named or int(_BINARY_EVENT_VARIATION)
                synchronized = event.synchronized
                if variation == BinaryEventVariation.WITH_TIME and not synchronized:
                    variation = int(BinaryEventVariation.RELATIVE_TIME)
                if variation == BinaryEventVariation.RELATIVE_TIME:
                    last = blocks[-1] if blocks else None
                    if (
                        last is not None
                        and last.group == group
                        and last.variation == variation
                        and last.synchronized == synchronized
                        and last.base is not None
                        and 0 <= event.timestamp_ms - last.base <= MAX_RELATIVE_MS
                    ):
                        base = last.base
                    else:
                        base = event.timestamp_ms
                        prefix = common_time(base, synchronized=synchronized)
                    encoded = encode_binary_event_relative(event.point, event.timestamp_ms - base)
                else:
                    timed = variation == BinaryEventVariation.WITH_TIME
                    encoded = encode_binary_event(
                        event.point,
                        with_time=timed,
                        timestamp_ms=event.timestamp_ms if timed else None,
                    )
            last = blocks[-1] if blocks else None
            if (
                last is not None
                and last.group == group
                and last.variation == variation
                and not prefix
                and last.synchronized == synchronized
            ):
                last.members.append((event, index, encoded))
            else:
                blocks.append(
                    _Block(group, variation, [(event, index, encoded)], prefix, base, synchronized)
                )
        return blocks

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

        if self._time_sink is not None and self._is_time_write(request):
            if len(request.body) != TIME_SIZE:
                return null_response(
                    sequence=sequence, iin=self._indications(IIN(second=IIN2Bit.PARAM_ERROR))
                )
            # Handed over before the indication clears, so a sink that raises
            # leaves this outstation still asking for the time it did not get.
            self._time_sink(int.from_bytes(request.body, "little"))
            self._time_was_set()
            logger.info("dnp3: time written by master")
            return null_response(sequence=sequence, iin=self._indications())

        if self._time_sink is not None and self._is_time_write(
            request, LAST_RECORDED_TIME_VARIATION
        ):
            if len(request.body) != TIME_SIZE or self._recorded_at is None:
                # The time written is when a request to record the time
                # was sent. With no such request received there is nothing
                # to measure from, and the clock is left alone.
                return null_response(
                    sequence=sequence, iin=self._indications(IIN(second=IIN2Bit.PARAM_ERROR))
                )
            elapsed_ms = max(0, round((self._clock() - self._recorded_at) * 1000))
            self._time_sink(int.from_bytes(request.body, "little") + elapsed_ms)
            self._recorded_at = None
            self._time_was_set()
            logger.info("dnp3: time written by master, %d ms after it was recorded", elapsed_ms)
            return null_response(sequence=sequence, iin=self._indications())

        # A write naming nothing is malformed; one naming an object this
        # outstation does not take a write of is an unknown object.
        bit = IIN2Bit.OBJECT_UNKNOWN if request.headers else IIN2Bit.PARAM_ERROR
        return null_response(sequence=sequence, iin=self._indications(IIN(second=bit)))

    def _time_was_set(self) -> None:
        """A master has written the time: stop asking, and trust the clock from here."""
        self._need_time = False
        if self._events is not None:
            self._events.synchronized = True

    @staticmethod
    def _is_time_write(request: Request, variation: int = TIME_VARIATION) -> bool:
        """Whether this writes one time object: the time now, or the last recorded time."""
        if not request.headers:
            return False
        header = request.headers[0]
        return (
            header.group == TIME_GROUP
            and header.variation == variation
            and header.qualifier is QualifierCode.UINT8_COUNT
            and header.count == 1
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


def _match_key(
    controls: Sequence[Control],
) -> tuple[tuple[int, int, int | None, int, bytes], ...]:
    """What an operate has to reproduce to spend the select it follows.

    The octets rather than the decoded objects. The comparison has to be exact,
    and float equality is not: two NaN setpoints never compare equal, so a
    select carrying one could never be operated at all.

    The block a control arrived under is deliberately absent. That is framing
    rather than instruction: an operate that carried the same objects under a
    different header boundary is still asking for the same points to move, and
    refusing it would fail a master over a detail the standard does not make
    part of the command.

    The qualifier is present. An operate has to match its select in object,
    variation, qualifier and data, and one that names the same point with a
    different index size is not the request that was selected.
    """
    return tuple(
        (
            c.group,
            c.variation,
            None if c.qualifier is None else int(c.qualifier),
            c.index,
            c.raw,
        )
        for c in controls
    )


def _echo(controls: Sequence[Control], statuses: Sequence[CommandStatus]) -> bytes:
    """The request back, one status per object, in the order it arrived (D14).

    The request's own header boundaries are kept. Splitting on the group and
    variation instead would merge two headers that named the same group into
    one block carrying twice the count -- a tidier response than the request,
    and not the request. A master that sent two headers is answered with two.

    The qualifier is kept for the same reason. A master that sent sixteen-bit
    indices is answered with sixteen-bit indices however small they are: one
    widely deployed master stack sends every control that way and rejects an
    echo narrowed to eight as a response it does not recognize.
    """
    body = b""
    run: list[tuple[int, bytes]] = []
    block = group = variation = -1
    qualifier: QualifierCode | None = None

    for item, status in zip(controls, statuses, strict=True):
        if item.block != block:
            if run:
                body += indexed_block(group, variation, run, qualifier=qualifier)
            block, group, variation, run = item.block, item.group, item.variation, []
            qualifier = item.qualifier
        run.append((item.index, control_objects.encode_control(item.command.with_status(status))))

    if run:
        body += indexed_block(group, variation, run, qualifier=qualifier)
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
