# Design

Why this library is shaped the way it is. Decisions are numbered so they can be referred to and
argued with.

## Scope

An outstation, targeting DNP3 Subset Level 2 over TCP and TLS. Serial is out of scope; a master
is out of scope. Both could be added, and neither is needed by what this was built for.

**Where Level 2 and the IEEE 1815.2 DER profile disagree, the profile wins and the divergence
is named.** They are not fully compatible targets. Floating-point analog inputs are not Level 2
objects, and the profile permits them by agreement between master and outstation rather than
requiring them. Control objects are sharper still: 32-bit analog outputs exceed Level 2, and a
50 kW real power value overflows a 16-bit point, so the profile cannot be served inside Level 2
once controls are in scope. Level 2 is therefore the floor, and every object served above it
belongs in the device profile document as an agreed extension.

## Decisions

**D1 -- Pure Python, standard library only.** No native extension, no bindings, no compiled
dependency. *Trade-off:* more code to own and slower than a compiled stack, against running
anywhere CPython runs -- including embedded targets with no toolchain -- and upgrading with the
interpreter instead of waiting for a wheel.

**D2 -- Integer analog variations are the baseline; floating point is offered by agreement.**
Floating-point analog inputs are not Level 2 objects, and per the rules of DNP3 any device
supporting them must support the integer variations as well. *Trade-off:* both representations
are implemented rather than one, against a default the profile does not permit.

**D3 -- A value that does not fit its variation saturates and sets `OVER_RANGE`,** keeping the
other quality bits. *Trade-off:* the master reads a clipped number, against either failing an
entire response because one point moved or wrapping the value, which would report a large export
as a large import. Non-finite values are handled before saturation: a NaN encodes as zero with
`ONLINE` cleared and `REFERENCE_ERR` set, since there is no wire representation of "no number",
and an infinity saturates like any other magnitude that does not fit.

**D4 -- Quality travels in the flag octet, and timestamps are the source's.** A point whose
device has gone unreachable keeps its last value with `ONLINE` cleared and `COMM_LOST` set,
rather than disappearing or reading as zero. A consumer must be able to tell a fresh reading
from a retained one, and arrival time cannot tell it.

**D5 -- The packed binary variation is not offered.** It carries no quality octet, so an
unreachable device would read as a device reporting `false`.

**D6 -- The library does not embed a point map and does not scale values.** It defines the map
format and reads a table supplied by the caller. *Trade-off:* one more step for a deployment
that only wants the standard map, against a library whose runtime holds no table it would have
to license. The IEEE 1815.2 point tables are distributed without charge, but under terms that
forbid redistributing them in any form, so the repository carries the extractor that reads them
and not the file it produces; the predecessor profile's tables are published by EPRI under a
license that permits redistribution with notice. The runtime treats both the same way, as data a
caller loads.

**D7 -- One active master association at a time.** Event buffers, confirmation state and
unsolicited retry ownership belong to an association, not to a socket. A new connection from an
authorized peer displaces the existing one rather than joining it, because the common cause is a
master whose socket died without a FIN, and refusing the new connection would leave the
outstation unreachable until a timeout it cannot observe. *Trade-off:* two masters cannot read
the same outstation concurrently; run two outstations for that.

**D8 -- TLS requires an explicit peer allow-list,** by subject name or certificate fingerprint,
and the listener refuses to start without one. Trusting a CA alone authenticates every
certificate that CA ever issued, and the DNP3 link address arrives inside the protocol from
whoever connected, so it identifies rather than authorizes. The check runs immediately after the
handshake and before any session is admitted, because under D7 an admitted connection displaces
the active one.

**D9 -- What is refused is refused out loud.** A function this outstation does not implement
receives a response carrying `FUNC_NOT_SUPPORTED` rather than silence, because a master that
times out learns nothing and retries. A control sent to an outstation with no outputs is
refused out loud too, with the indication **D53** chooses for it.

The exceptions are the function codes the standard defines as taking no reply. IEEE 1815-2012
Table 4-2 describes each as "same as function code N but outstation shall not send a response":
`DIRECT OPERATE NO ACK` (0x06), `IMMEDIATE FREEZE NO ACK` (0x08), `FREEZE AND CLEAR NO ACK`
(0x0A), `FREEZE AT TIME NO ACK` (0x0C) and `AUTHENTICATION REQUEST NO ACK` (0x21). Each is
dropped without execution and reported in the log. The obligation is on the function code rather
than on whether this outstation implements what was asked, so refusing one out loud would send a
fragment to a master that is not listening for it.

Stating the exception separately matters twice over. A refusal contract written only in terms of
returned statuses leaves the functions that return nothing as the ones an implementation could
execute by omission. And a contract that names one of them leaves the other four looking like
ordinary refusals -- which is exactly what they were until the interoperability sweep walked the
function code space and found them answering.

**D10 -- Controls reach the device through a synchronous `ControlProvider`,** mirroring
`ReadProvider`. The session stays synchronous, so it keeps doing no I/O and stays pinned against
literal frames.

This is conformant rather than a compromise, which is worth saying because it reads like one. The
standard defines `SUCCESS` as "accepted, initiated, or queued" -- queuing is one of the things
success means. A provider that hands the control to a device thread and returns is answering
correctly. What it must not do is block: a device round-trip inside the window a master is timing
is a protocol timeout waiting to happen, which is why `ReadProvider` is synchronous too.

**D11 -- Select state lives in the session, not in the provider.** Selecting is protocol
bookkeeping: the provider is asked whether it *could* operate, and the session remembers that it
said yes. A provider written by a caller should not have to reimplement matching and expiry to be
conformant, and under D7 there is one association, so there is exactly one select to track.

**D12 -- A select is invalidated by anything that makes it ambiguous.** It expires after a
configurable timeout, ten seconds by default; it is consumed by the operate that matches it and
left alone by one that does not, since a master that sent the wrong operate still holds the
reservation it was granted; a second select replaces the first; and `connection_reset` discards
it, because a reservation held for an operate on a socket that died must not be honored over the
connection that replaced it.

Any fragment other than the operate that spends it also ends the exchange it belongs to. Two
mechanisms enforce that rather than one: the operate has to arrive on the sequence after the
select, *and* an intervening fragment clears the selection. Either alone leaves a gap. The
sequence rule binds only a master that numbers its requests in order, and a master that reuses a
number walks through it to an operate the outstation never granted; the clearing rule covers
whatever a master sends under any numbering at all.

The clearing is decided on the function code octet, above every other branch, because siting it
lower is what let the refusals, the functions that answer nothing, and the unreadable fragments
hold a reservation open across traffic the master had plainly moved on from. Deciding it there
also means a fragment too damaged to parse clears the selection -- the opposite of what damage
does to a held event response, and deliberately. Replaying a response costs nothing if the guess
is wrong, while holding a control reservation open through noise can authorize an operate the
master never selected.

Two fragments are excluded. An OPERATE, because spending a select is what it is for, and because
a damaged one is the corrupted retransmission a reservation is worth keeping for. And a CONFIRM,
because it is not a request: it is the second half of an exchange this outstation started, and it
carries the sequence of the response it acknowledges rather than a new one, so a master may
legitimately confirm an earlier read between its select and its operate.

**D13 -- The control point map belongs to the caller, as with reads.** Under D6 this library does
not know that index 7 is a power setpoint, and it does not scale. A control arrives at the
provider as an index, a decoded object and the function that carried it.

**D14 -- A complete control is answered per object, echoed in request order.** A request naming
four points where one is unsupported returns four objects with three successes and one
`NOT_SUPPORTED`, not a single refusal for the fragment. The echo is of the request rather than a
tidier version of it: the objects come back as they arrived, two headers naming the same group
are answered with two headers, and each header keeps the qualifier it arrived under. A request
sent with sixteen-bit indices is echoed with sixteen-bit indices however small they are; an
echo narrowed to eight is one a master comparing it against its request rejects, having
executed the control.

That last part is why the decoders keep raw octets rather than rebuilding from parsed fields.
`struct` does not round-trip every bit pattern a float variation can carry -- unpacking the
signaling NaN `0x7f800001` and packing the result yields `0x7fc00001` -- so an echo built from
parsed values would return octets the master did not send.

**D15 -- A request that does not parse is refused at the fragment, not per object.** A truncated
body, a count that disagrees with the octets present, or an index width that contradicts the
qualifier may leave no complete object to echo, and a status has to be attached to something.
Those produce a null response carrying `PARAM_ERROR`. An object that parses completely and is then
invalid is echoed with `FORMAT_ERROR` under D14.

**D16 -- A select arms the request it received, not the objects that succeeded.** A four-point
select can return three successes and one refusal, which a master meets on any map with a
read-only index. The operate it sends next is the request it already sent, so matching against the
subset it was never told about would reject its own unchanged request. Each object is answered on
its merits again at operate, so an index that failed at select fails again, and no subset
bookkeeping exists to get wrong.

Matching compares the object octets rather than the decoded objects. That is exact, which the
standard requires, and it sidesteps float equality: two NaN setpoints never compare equal, so a
select carrying one could otherwise never be operated at all. The header boundary is deliberately
excluded -- it is framing rather than instruction, and an operate carrying the same objects under
a different boundary is still asking for the same points to move.

Two limits on that, both found after the first implementation and both places where arming the
request received was too generous rather than too strict.

**A select that selected nothing arms nothing.** The reasoning above -- that the master will
resend what it sent -- only holds while there is an operate the select could authorize. Where
every object came back refused there is none, and arming it would let a point the outstation
declined to select be executed by the operate that followed. One success is enough; the refused
objects are answered on their own merits again at operate.

**The operate has to be the request after the select.** Matching on the objects and the clock let
a selection outlive whatever came between: a select, a read, then an operate carrying the same
objects would execute on the strength of a selection the master had already moved on from. The
application sequence the select arrived under is recorded, the operate must carry the next one,
and any other request in between discards the selection outright. Both, because either alone
leaves a gap -- a sequence can line up across an intervening request, and a master can skip
sequences without sending one.


**D17 -- The caller owns the buffers and records into them; the session never does.** The caller
constructs `EventBuffers`, records into it as its device polls, and hands it to `Session`, which
calls `peek`, `overflowed`, `classes_with_events` and `overflow_generation`, and -- on a
confirmation -- `drop` and `clear_overflow`. The two read alongside `overflowed` are what the
indication bits are derived from and what keeps a later loss from being cleared by an earlier
acknowledgement; naming a shorter list would imply a narrower dependency than there is.

The session's only writes are those two, and both are a master acknowledging what it was sent. An
earlier wording of this decision said the session only reads, which stopped being true when
confirmation landed and survived in a docstring until review caught it.

Recording cannot happen inside a request. A deadband is measured against the last value *reported*,
not the previous reading, so it needs history between requests rather than during one -- and under
**D6** this library does not know which index is which point or when it moved. An `EventProvider`
asked for events when a read arrives would have to own a buffer anyway, so the indirection would buy
nothing and hide where the state lives.

**D18 -- A confirmation is what the outstation retires an event *for*. The buffer bound is the other
way one leaves.** A response carrying events sets `CON`, and the events stay until the matching
`CONFIRM` arrives. `peek` selects, `drop` retires, and the gap between them is the window a master
might fail to answer in.

This is why `EventBuffers.drop` matches on identity rather than equality, and why it is load-bearing
that the events are still buffered while the confirm is outstanding.

A master that never confirms gets the same events again on its next read, until the buffer fills.
`_ClassBuffer.add` evicts the oldest at capacity and raises the overflow flag, so continued
recording can remove an unconfirmed event before the master ever sees it a second time. That is not
a hole in this decision, it is the decision the buffer already made: unbounded retention for a
master that has gone quiet is how an outstation runs out of memory, and the overflow bit exists to
say that data was lost rather than to pretend it was not.

The two interact where a pending selection is evicted. `drop` skips events it cannot find, so a
confirmation retires whatever survived and silently ignores what did not, which is the right outcome
-- there is nothing to retire and nothing to report beyond the overflow bit already set. That case
is covered by tests of its own rather than assumed away: a selection does not always outlive the
wait, and an implementation written as though it does is one eviction from being wrong.

**D19 -- One outstanding response at a time, and a new request replaces it.** Under **D7** there is
one association, so there is one unconfirmed response to track. A read arriving while one is
outstanding supersedes it: the master has evidently moved on, and a confirmation arriving afterwards
would name a response that is no longer the current one.

A refusal counts. An unsupported function or a control sent to a monitor-role outstation is a
response like any other, and leaving the selection standing across one would let a confirmation for
the response *before* it still retire those events. The first draft of this decision was written as
though only the requests that do work superseded, and the implementation followed it -- which put
two refusal branches on the wrong side of the line.

One thing is outside it, and stays outside it: a fragment that did not parse. That is not evidence
the master moved on; it is evidence something arrived damaged, which is exactly when a
retransmission of the held response is the likely next thing to arrive. Discarding the cache on
noise would throw it away at the one moment it is most wanted.

The functions that ask for no response were outside it too, on the grounds that they send nothing
for a later confirmation to be late against. That held while one response was held at a time and
stopped holding as soon as a response could span fragments: one arriving mid-conversation left the
remainder of an abandoned read to be drawn out by the next confirmation, retiring events the master
had stopped waiting for. They end a response like any other request now.

**D20 -- Class 0 is static and classes 1 to 3 are events, answered in one response.** The integrity
poll a real master sends names all four. Static objects come from the `ReadProvider` as they do
today; event objects come from the buffers; both travel in one response, events first.

Events first because a master applies them in order: a static value written after the events that
led to it leaves the point at its current value, which is what the master should end up holding.

**D21 -- `DISABLE_UNSOLICITED` succeeds; `ENABLE_UNSOLICITED` is still refused.** The asymmetry is
the point. An outstation that sends no unsolicited responses is already in the state `DISABLE` asks
for, so refusing it answers a question the master did not ask. `ENABLE` asks for something this
outstation does not do, and saying so is the honest answer.

This halves the warnings a real master's startup produces -- the roadmap's complaint -- without
implementing anything that sends.

This remains the answer of a session built without unsolicited responses, which is the
default. One built with them takes both requests by class instead (D69).

**D22 -- The class-event indication bits are derived from the buffers, not tracked separately.**
`IIN1.1`, `1.2` and `1.3` say which classes have events waiting. A master polling on indications
never asks for events it is not told about, so a bit that drifts from the buffer is an outstation
whose data is invisible. Deriving them on each response makes drift impossible rather than unlikely.

**D23 -- Overflow is reported until a master has seen it.** `IIN2.3` is set while
`EventBuffers.overflowed()` is true, and `clear_overflow` runs once the response carrying the bit is
confirmed -- not when it is sent. An overflow reported in a response the master never received is an
overflow the master never learned about.

Confirmed, and nothing lost since. A confirmation acknowledges the loss *that response* reported, so
what is compared is the count of events the buffer has dropped -- not a flag, which reads the same
after one eviction and after a hundred. If more were evicted while the confirmation was in flight,
the flag stands and the next response reports it again, because that later loss is one the master
has not been told about.

A *read* response reporting one therefore sets `CON` whether or not any event travels with it. The
bit is the thing being acknowledged, so such a response has something to confirm on its own account.
Without that, a ceiling under which no event fits -- which **D27** explicitly allows -- is a
configuration where no read ever asks for a confirmation, and the flag latches: the master is told
for ever about a loss it was told about once. The same holds for a master that polls only class 0.

Every other response carries the bit without asking. A refusal, a write, a control echo and
`DISABLE_UNSOLICITED` all report the overflow, because the indications are derived on every response
and a master should learn of a loss as soon as it speaks to the outstation -- but none of them is a
place an acknowledgement belongs, and none needs to be. *Any* read retires the report, class 0
included, as the paragraph above says: the line is between a master that reads and one that does
not, not between one that reads events and one that reads static data. A master that never reads at
all has nothing to retire, and nothing it would do with the answer.

**D24 -- `ASSIGN_CLASS` stays refused.** A class is assigned when the caller records the event, and
under **D6** this library holds no point map for a master to reassign. Accepting the request would
mean either ignoring it or inventing the map the design exists to keep out.

**D25 -- A repeated request is replayed, not rebuilt, and a repeat is one that matches octet for
octet.** A master that did not receive a response repeats the request. The outstation holds the
request beside the response it produced and the events it selected, and when the same octets arrive
again it sends that response back unchanged.

The comparison is against the request and not against the sequence number alone. A master that
reuses a sequence for a *different* question has retransmitted nothing, and answering it from the
cache would reply to the question before it -- then have those events retired by the confirmation
that followed, acknowledged against a response the master never asked for.

The two shapes differ only when an event arrives in between, and that is the case that decides it.
The confirmation which follows retires the events the response was built from, so a rebuilt response
carrying an event the first did not would have that event retired under a sequence it was never sent
under -- reported once, acknowledged once, and gone, except that the master's copy of the exchange
and the outstation's disagree about which events the sequence covered. Replaying keeps the two in
step at the cost of the newer event waiting for the next read, which is the delay a retransmission
implies anyway.

The cache this needs is not extra machinery. Confirmation has to record which events went out under
which sequence regardless, and the fragment is one more field beside them.

This was decided without the text of the standard, which was not available. **IEEE 1815** may
specify the behavior outright, and if it turns out to say rebuild, switching is deleting the
`fragment` field and re-dispatching the request -- the sequence and the event selection stay either
way. The decision is recorded as a soft one for that reason.

**D26 -- A confirmation carrying `UNS` is ignored.** The bit distinguishes a confirmation for an
unsolicited response from one for a solicited response, and the two count sequence numbers
separately. This outstation sends no unsolicited responses, so a confirmation carrying the bit names
an exchange that never happened, and retiring the solicited selection on the strength of a number
from a different counter would delete events the master has not acknowledged.

Ignored rather than consumed: the master's real confirmation may still be coming, and swallowing the
selection here would lose the events instead of merely mistiming them. This is the same asymmetry as
**D21** -- an outstation that does not send unsolicited responses answers questions about them by
declining to act, not by pretending the exchange exists.

A session built with unsolicited responses on sends such a confirmation to its unsolicited exchange,
and still never to the solicited selection (D70).

**D27 -- Every fragment is fitted to what the master can receive.** ``max_response`` is its own
number rather than the reassembly ceiling ``max_fragment``: one is the largest request this
outstation will piece back together, the other the largest fragment the master on the far end can
accept, and a master advertises its own. Sending past it is not a long response but a discarded one
-- the events were readable and then none of them arrived.

Each fragment is filled with events up to that ceiling. Static data follows them rather than being
paid for first (**D33**), so a read that asks for both is not answered with fewer events than the
same read without a body.

This decision was written when a response was one fragment, and said so. **D28** made it a
conversation; what survives here is the ceiling, applied to each fragment of one.

A provider body that overruns the ceiling on its own is the one case the events cannot be fitted
around, and the read is refused with `PARAM_ERROR` rather than sent. Sending it past the ceiling
loses the whole response -- the master discards the fragment -- and says nothing about why; four
octets that arrive and name the problem let a master narrow its request. Nothing is recorded as
outstanding on that path, so the events stay buffered for the read that fits.

What does not fit is left in the buffer and left out of the selection, so the confirmation retires
only what was actually sent and the class indication bits go on asking for the rest. A master that
reads again gets it.

The fit is found by bisecting the encoder rather than by arithmetic on the header layout, because a
block's size is not a fixed cost per event -- the qualifier widens when the count passes an octet or
an index does. Bisection is sound because the size never falls as events are added.

The ceiling bounds the work and not only the octets. `capacity` has no upper bound, so anything
proportional to the buffer is proportional to a number the operator chose, paid on every read a peer
sends. The selection is therefore cut to what could possibly fit *before* anything is encoded -- the
remaining budget divided by the narrowest an event encodes, which is a strict upper bound rather
than an estimate -- and the buffer is asked for no more than that plus what the deduplication is
about to remove. A four-octet response over fifty thousand events used to cost fifty thousand
encodings; it now costs none.

That is what `peek`'s `limit` is for, and it settles the open question about it. The limit is not
how a count qualifier is answered -- a limit taken before deduplication would come back short -- it
is how a caller avoids paying for a buffer it has no room for. It has to slice while walking the
deque rather than after materializing it, or the call still costs the buffer.

This was a cap rather than a split until **D28** made a response a conversation. What survives of it
is the ceiling itself: every fragment is still fitted to what the master can receive, and a response
that runs out of fragments before it runs out of events still ends with the class indication bits
asking for the rest (**D32**). What has gone is the assumption that one fragment is all there is.

The ceiling is not only the read path's. A control response is the request echoed with a status per
object, and one that will not fit is refused *before anything is dispatched* -- a control that
executes and cannot report its outcome is worse than one that never ran, because a master that
learns nothing about an operate is a master that may send it again. The echo is measured with a
probe status, since an object's encoding is a fixed size for its type and the status sits inside it.

A ceiling below a response header is refused at construction. Every answer such an outstation could
give would break it, including the refusal it would give instead, so the number is rejected where it
is set rather than logged on each response that overruns it.

**D28 -- A confirmation that continues a response is answered with the next fragment.** `CONFIRM`
answers with nothing when nothing is outstanding or the outstanding response was the last one; when
the outstanding response has more behind it, the answer is the next fragment.

This is the one place the session answers something that is not a request, and it is worth being
explicit that it is not an exception being carved out: under **D18** a confirmation is already the
event that moves the state machine on. It retires what was sent. Sending what comes next is the same
transition.

**D29 -- Each fragment is built from the buffer as it then stands.** Not built ahead and queued, and
-- the part a first draft of this got wrong -- not carried as a remainder either.

The obvious design is for `_Outstanding` to hold the events that did not fit and for the next
fragment to come off that list. It cannot. `_Outstanding.events` holds strong references on purpose,
so that `drop` still matches what it is given after an eviction; a remainder held the same way keeps
the whole buffer alive for as long as a master is slow, which is exactly the unbounded retention
**D18** and **D27** exist to prevent. Worse, it would let an event that has since been *evicted* go
out in a later fragment, so a master would receive an event the outstation had already reported
losing.

So a continuation peeks the buffer again and takes what fits, exactly as the first fragment did.
`_Outstanding` keeps only what it sent, plus the fact that more remains. Events evicted in between
are simply gone, which is what the overflow bit is for; events recorded in between join the
response, which costs nothing and saves a round trip.

That last is true only while the response is still sending events. Once any static data has gone out
the conversation is in its static half and takes no more (**D33**), because an event placed after
static already sent would leave the master holding a reading older than the event that superseded
it. Those events wait for the next response, and the class bits go on asking for them.

That last point is why this needs a bound rather than a rule about which events belong to which
response. A buffer filling as fast as it drains would otherwise answer for ever. See **D32**.

The rule this states is not "hold nothing". A response does hold the provider's body across its
fragments (**D33**), and the difference is worth naming, because "carry nothing" and "carry one
body" are two rules, and asserting both without a reason reads as a contradiction.

What may not be held is state that **grows while it is held**, or whose staleness would put
something on the wire that is no longer true. The event remainder fails both: the buffer behind it
keeps filling as the device polls, so holding a remainder means holding against a moving target, and
an evicted event sent from it would be one the outstation has already reported losing.

The provider's answer fails neither. It is caller-sized too -- **D35** lets a provider return as many
blocks as its point map needs, and all of them are held until they are sent -- but it is a *snapshot*
taken once and consumed block by block, so it shrinks with every fragment and cannot grow. And a body
a few round trips old is a stale *reading*, which is a different thing from a false statement about
what was lost.

The distinction is therefore not size. It is that one of them is finished being produced and the
other is not.

**D30 -- A request arriving mid-sequence ends the conversation.** Under **D19** a new request
supersedes what was outstanding, and a partly-sent response is no different: the master has moved
on, and the events it did not take stay buffered for the read it just sent. The fragments already
confirmed stay retired, because they were received.

Under **D29** what is discarded is the fact that more was coming and the provider's body held for
the last fragment -- no remainder, because none is held. That makes this decision cheap to implement
and easy to get wrong in the other direction: forgetting to clear the flag would have the next
confirmation continue a response the master has already abandoned, and forgetting the body would
leave a read's answer to be delivered inside somebody else's.

**D31 -- Opaque static data is not split, and a body that does not fit is refused.**
`ReadProvider.read` returns octets, and this library cannot tell where one object inside them ends,
so there is no honest place to cut one.

That is the fallback rather than the rule -- see **D35**, which gives a provider a way to say where
its objects end. A provider that does not is answered as it always was: fragmentation lets a large
buffer of *events* reach a master, and a static read too large for one fragment is refused.

**D32 -- A response is bounded in fragments, not only in octets.** One conversation carries at most
so many, and the last of them sets `FIN` whether or not the buffer is empty -- after which the class
indication bits go on asking, which is **D27**'s cap reached later and with most of the buffer
delivered.

Reaching the bound ends the events, not the response. A read that also named class 0 still owes the
master its static data, so the provider's body goes out with `FIN` as it would have anyway
(**D33**). Stopping short of it would answer a request for static data with events and nothing else,
which is a worse failure than being chatty.

Which means the bound is on the fragments of events, and a response may carry further ones for the
static data: one for a provider answering in octets, and as many as its blocks need for one
answering in blocks (D35). Counting those against the bound would have an outstation that reached it
drop the static data instead -- the failure the paragraph above rules out, reintroduced by the
arithmetic.

A bound is needed because **D29** lets events recorded mid-conversation join it. Without one, an
outstation whose device polls faster than its master confirms never sends `FIN`, and a master that
is waiting for the end of a response is a master that never issues another request.

The bound counts the fragments that carry **events**. Static continuations are outside it, and the
difference is what the bound is for: a device can keep recording events during a conversation, so
without a bound the events never end. The provider's blocks are a finite list read once when the
response began (D33 and D35), and every static fragment consumes at least one of them, so that half
terminates by construction. Bounding it as well would mean refusing to finish answering a request
whose data the caller had already handed over.

The bound is **sixteen fragments**, and it is a count rather than an octet budget or a deadline. A
count is the one of the three that can be reasoned about from a log line, and sixteen is not
arbitrary: it is one full trip through the application sequence space, so the *events* of a response
use every sequence number at most once.

That is a statement about the event half and not about the conversation. Static continuations are
outside the bound, so a response whose provider answers in blocks can pass sixteen fragments and go
round the sequence space again -- twenty-eight fragments, with sequences 0 to 15 and then 0 to 11,
is a legitimate answer. The argument for sixteen is unaffected, because it was always an argument
about bounding events; what it does not do is characterize the whole exchange. **D34** is where that
matters. A full default buffer of a
thousand events is about seven fragments at the 2,048-octet ceiling, so sixteen leaves room for a
buffer twice that size while still stopping one that fills as fast as it drains.

An octet budget was the alternative worth weighing -- it costs the same for many small fragments as
for few large ones -- and was not taken because there is no number for it that explains itself. A
deadline was not taken because the session is clock-free apart from the select timeout, and a
response whose length depends on how fast the machine is is a response that cannot be pinned in a
test.

**D33 -- Static data travels in the last fragment.** A read naming class 0 and an event class is
answered with the provider's body after every event, not alongside the first of them.

This falls out of **D20** and is easy to get wrong: putting static data in the first fragment --
which is what the current single-fragment code does, and what a naive split would keep doing -- has
the master apply it *before* the events in the fragments that follow, so it ends up holding an event
value older than the reading the same response carried. The whole point of events-before-static is
that the static value wins.

The body is read once, when the first fragment is built, and held until the last -- the one thing a
response carries across its own fragments, which **D29** explains the shape of.

Three reasons, in increasing order of how much they matter. A response reporting two different
values for one point over its own length is a worse answer than one a moment old. The provider is
the caller's code and may poll a device to answer, so calling it once per fragment turns one logical
read into several.

And the one that decides it: a body re-read at the end might no longer fit. The response would then
be mid-conversation, already committed, with nothing good to send -- **D31**'s refusal is an answer
to a request, not to a continuation of one this outstation has already begun. Measuring the body
once, at the start, is what makes the last fragment's fit knowable from the first.

**D34 -- A confirmation naming the previous fragment re-sends the current one.** Not ignored, which
is what the rest of these decisions would otherwise have it do, and which deadlocks the
conversation.

Walk it through. The outstation sends fragment *n*, the master confirms it, the outstation retires
those events and sends *n+1*. If *n+1* is lost, the master repeats its confirmation of *n* -- and
`_confirm` matches on the *outstanding* sequence, which is now *n+1*. The repeat matches nothing, is
logged and dropped, and the outstation sends nothing. The master waits for a fragment that will
never come and the outstation waits for a confirmation that will never arrive. Neither side is wrong
and the exchange is over.

So the outstation remembers one sequence number beyond the current one: the fragment just confirmed.
A confirmation naming it replays the fragment already built and outstanding, byte for byte, and
retires nothing -- the events it named were retired when it was first confirmed. A confirmation
naming anything else still retires nothing, as **D18** has it.

This is **D25** one layer up: the same choice between replaying what was sent and rebuilding it,
answered the same way and for the same reason. Rebuilding would send a different set of events under
a sequence the master is about to confirm.

One sequence of history is enough because there is only ever one fragment outstanding, and it is
replayed as often as the master asks for it -- a continuation lost three times is sent three times.
What is not answered is a confirmation *two sequence positions old*, which names a fragment this
outstation has already seen confirmed and moved past. A master in that position has lost the
conversation rather than a fragment of it, and **D30** lets its next request start a new one.

One position of history is unambiguous locally and not globally, which **D32** makes reachable. A
conversation that passes sixteen fragments goes round the sequence space again, and a confirmation
delayed by exactly sixteen then arrives naming the number `previous` now holds -- so it is answered
with a replay rather than ignored.

That is deliberate rather than overlooked, and it is harmless: a replay retires nothing and sends
the fragment the master is owed next, so the worst case is a duplicate of something it was waiting
for. Distinguishing it would mean tracking sequences the association has actually spent, which is
machinery for a link that has already mislaid sixteen fragments' worth of ordering -- and a master
that far behind has lost the conversation, which **D30** already answers.

**D35 -- A provider may say where its objects end, and static data then splits too.** `ReadProvider`
keeps `read`, which returns octets and is the contract. Beside it, a provider may implement
`read_blocks`, returning the object blocks it would have concatenated. A provider that does gets its
static data split across fragments at a block boundary; a provider that does not is answered under
**D31**.

Optional rather than replacing `read`, and that is the whole of the decision. Replacing it would be
a breaking change before 1.0 for every caller, including the ones whose point maps fit a fragment
and who would gain nothing. It would also have this library holding a list of the caller's objects
rather than a body it forwards, which is closer to knowing the point map than **D6** wants to be.

The limit it lifts is not hypothetical. A class 0 poll over roughly 290 analog points already
exceeds the 2,048 octets a master typically advertises, which is a mid-sized site rather than a
large one. **D31** alone would refuse those reads, and an outstation that cannot answer an integrity
poll is not much of an outstation.

A block is still not split. The unit is the object block the provider hands over, so a single block
larger than a fragment is refused as **D31** refuses a body -- this moves the boundary from the
whole body to one block of it, and does not remove it.

**D36 to D43** are the DER profile's: what ships (the machinery, and of the data only what
its publisher permits), indices resolved once at load, points bound by callables, integer
variations as the baseline, support derived from binding, unbound optional points absent.
They are argued in [`planning/DER_PROFILE.md`](planning/DER_PROFILE.md), which also records
which of them are built.

**D44 -- A master's time write goes to the caller, and the session only keeps the
indication.** `Session` takes a `time_sink` and a `need_time` flag. A write of group 50
variation 1 hands the sink the time in milliseconds, UTC, and clears `IIN1.4`; without a
sink the write is refused as an unknown object, as every other write still is. What the time
means is not the session's to decide: an outstation whose clock is disciplined elsewhere may
record the write and apply nothing, and one with no clock of its own may keep an offset. The
indication is the protocol's and so it lives here; the clock is the device's and does not.
`DELAY_MEASURE` is answered with the time the request was held, which over TCP is close to
nothing and is reported honestly anyway, because the master's arithmetic depends on it.
*Trade-off:* the session cannot say whether the time was applied, against a library that
never sets a clock it does not own.

**D45 -- Freezing is the caller's, through a `FreezeProvider`, and absent one the freeze
functions stay refused.** Under **D6** this library does not know which counters exist, so a
freeze is passed on as the object headers the master named and whether it asked for a clear.
An outstation given no provider has no counters, and accepting a freeze of nothing would
tell a master a log entry exists. The two no-response freezes execute and say nothing, the
same carve-out **D9** makes for `DIRECT_OPERATE_NR`; without a provider they are dropped as
before. A frozen counter event is always recorded, never compared with the previous freeze:
it is an entry in a log, and two freezes of a counter that did not move are two entries.
The freeze-at-time functions remain refused. *Trade-off:* whether a clear is honored is the
provider's decision and invisible at this layer, against a session that would otherwise have
to own the counters.

**D46 -- An event group read by name is answered from the buffers.** A master may read
binary input events, analog input events or frozen counter events by their own group rather
than by class, and the IEEE 1815.2 implementation table requires an outstation to parse
that. Such a header selects events of its kind across every class, class 1 first, and is
confirmed and retired exactly as a class read is. It is answered in variation 0 or in the
variation this session reports; another variation is left to the provider, so the master
hears that the object is unknown rather than receiving a variation it did not name. Counter
change events are never buffered, and reading that group is answered with nothing. Without
buffers nothing changes: the header reaches the provider as it always did.
*Trade-off:* a read crossing classes has no order to offer but the classes' own;
**D52** later gave events an order of their own and uses it.

**D47 -- The analog event variation and reporting mode are the caller's to choose.** The
default stays timed, and stays every change, for the reasons **D17** gives. IEEE 1815.2
selects otherwise for analog inputs: the 32-bit variation without time, which a Level 2
master is certain to parse, and only the most recent event per point. So `Session` takes
`analog_event_variation` and `EventBuffers` takes `analog_latest_only`, and the bound on
how many events could fit a fragment follows the variation rather than assuming the timed
size. Binary and frozen counter events are never collapsed, because for those the sequence
is the information. *Trade-off:* two ways to report an analog change, against a profile
whose masters are promised one of them.

**D48 -- The Device Profile is generated from the objects it describes, and says nothing it
cannot read from them.** The point lists come from what the outstation serves, the limits
from `Session.facts`, and the implementation table from the same facts the session
dispatches on; the tests send the session every request the table lists and a sample of
what it omits. Figures that need a measurement (clock drift, response time, timestamp
error) and a conformance test result are left out, which the schema permits: an absent
element says "not stated", where a plausible default would be a claim nobody checked.
The schema and stylesheet are the DNP Users Group's and are named by the document, not
shipped with it. *Trade-off:* a sparser document than a hand-written one, against one
that cannot drift from the device.

**D49 -- A request that acts is acted on once, and its retry is answered again.** A master
that does not hear the answer to an operate, a direct operate or a freeze sends the same
request again, with the same sequence number, and cannot tell whether the first one arrived.
The session keeps the last such request and its answer; one that repeats it octet for octet
is answered from that record and nothing is done a second time. A pulse that fires twice
because a response was lost is the failure this prevents. A select is different and keeps its
own rule: a repeated select with the same sequence number is the same selection, and its
timer is not restarted, so a master cannot hold a selection open by retrying it.
*Trade-off:* a master that really does mean the same control twice must advance its
sequence number, which is what the protocol already asks of it.

**D50 -- A broadcast is acted on, never answered, and reported in the next response.**
Nothing is sent in reply to a broadcast at any layer, including a link acknowledgment. A
freeze and a time write are always carried out. A direct operate is carried out only when
the session was built with `broadcast_controls=True`, because a control that reaches every
outstation on a network at once is the caller's decision and not a default. The indication
`IIN1.0` is set in the next response to the master. Under the two addresses that ask for it
to be confirmed, that response requests a confirmation and the indication stands until one
arrives; under the address that does not, it is cleared once it has been reported.
`OutstationServer(broadcast_datagrams=True)` listens for datagrams on the listening port
and takes only broadcasts from them, since a stream reaches one outstation and a master
addressing several uses a datagram. It is off by default and refused with TLS: a datagram
carries no certificate, and would go around the allow-list **D8** requires.
*Trade-off:* a plaintext listener that enables it accepts a freeze or a time write from
anyone who can reach the port, which is why it is not the default.

**D51 -- A confirmation has a deadline, and a late one does nothing.** `confirm_timeout`,
ten seconds unless set, is how long a response waits for its confirmation. One arriving
after that retires no events and continues no multi-fragment response: the events stay
buffered for the next read. A master that timed out and moved on has, by then, no record of
what the confirmation would have acknowledged, and an outstation that honored it would drop
events the master never kept. `None` restores the old behavior of waiting indefinitely.
*Trade-off:* events are sent twice to a master that confirms slowly, against events lost to
one that gave up.

**D52 -- Events are chosen by the headers of the read and sent in the order they happened.**
Every event carries the order in which it was recorded. A read naming several classes, or
several event groups, selects what each header asks for and then sends the selection oldest
first, so a master replaying the response sees a point close before it opens if that is what
happened. This replaces the order **D46** settled for, in which a read crossing classes
took them highest class first. A header with a count takes the oldest events of its kind,
whichever class holds them.
*Trade-off:* an object header per run of same-type events rather than one per type, which
costs a few octets in a response that mixes them.

**D53 -- The indications say what is wrong with a request as precisely as the standard
allows.** Three cases were answered more coarsely than they could be:

- A control function sent to an outstation with no control provider is answered with
  `IIN2.1`, object unknown. Every outstation knows the function; what a monitor lacks is
  an output for it to act on. This narrows **D9**, which stays true of functions this
  library does not implement.
- A read whose range names no point, or runs past the last one, is answered with `IIN2.2`,
  parameter error, and a read of a type the outstation has none of with `IIN2.1`. A provider
  says which by raising `ParameterError` or `UnknownObject`.
- A control naming a point that is not installed is echoed with status 4 and `IIN2.2` is
  set as well. One arriving with a status other than zero is a format error and is not
  passed to the provider. The echo is still per object, as **D14** has it; a master that
  reads the indications before the objects reports the whole request as rejected, which
  one of the interoperability peers does, and the request was one point to begin with.

A class indication (`IIN1.1` to `IIN1.3`) is no longer set for events the response itself
carries, since a master reading it would poll again for events it is already holding.

**D54 -- The data link's secondary station keeps the frame count.** The outstation never
asks for link confirmation, but a master may, and the secondary side of that exchange has
state: confirmed user data is accepted only after the master has reset the link, the frame
count bit alternates from there, and a frame repeating the last count is acknowledged
without being handed up a second time. A frame whose count-valid bit disagrees with its
function is not answered. Before this the link layer acknowledged anything well formed,
which a master retrying over a poor link could turn into a duplicated request.
*Trade-off:* state per association in a layer that had none.

**D55 -- A DER outstation can be held to Subset Level 2 exactly.** `DerOutstation(level2=True)`
answers a variation 0 read with the variations a Level 2 master is required to parse,
reports no frozen counter events, clears counters on a freeze-and-clear, and substitutes
the flagged variation for an unflagged one whenever a point's quality is not normal, so a
master never reads a healthy-looking number from a point that is offline. IEEE 1815.2 asks
for more than Level 2 offers in places (32-bit setpoints, counters that are never cleared),
so this is a mode for testing against the subset and for masters that implement only that,
and not the default. A cold restart is supported when the session is given a
`restart_handler`; without one the function is refused, because a library cannot restart a
process it does not own.

**D56 -- Curves live in a store with the standard's three rules, and a function gets its
curve by asking.** `py1815.profile.curves.CurveStore` is the state behind the multiplexed
curve block of clause 6.1.3: the curves, which one the edit window shows, and which
function names which. It binds the block's points itself and enforces what the clause asks:
a selector naming a curve that does not exist is refused with `OUT_OF_RANGE`; a curve named
by an enabled function is locked, and a write to its type, units or points is refused with
`AUTOMATION_INHIBIT` and changes nothing; and the indicator that the selected curve is
referenced follows the functions' curve numbers. Both statuses are the ones the clause
recommends. A function's curve number is bound through `reference`, which states the curve
types the function follows and returns a callable giving its `Curve`. Pointing a function
at a curve of another type, or changing the type of a curve under a function that names it,
is refused with `NOT_SUPPORTED`; the standard names no status for that case. The values of
a curve are kept as they travel, because their scaling depends on the units the curve
declares, and the function applies it. This is what **D41** planned as a builder-owned edit
buffer, built as a store a caller binds so that a device with its own curve storage can
bind the block to that instead.
*Trade-off:* a caller wires the store to its functions itself, against a builder that would
have to know every function's curve types.

**D57 -- The inputs of a disabled function are sent without the ONLINE flag.** Clause
6.1.1 requires it: the value is still reported, marked as not in effect. A function is the
points the tables give one purpose under one heading, around an enable output paired with
a supports input, so the outstation derives the rule from the tables and a caller binds
nothing extra. Two inputs are exempt because what they say holds either way: the supports
input, and the input reporting whether the function is enabled. A quality worse than good
is never replaced, so a source that cannot be reached still says so. Enabling a function
therefore produces events for its inputs, which is how a master following events learns
the settings came into effect. `DerOutstation(disabled_offline=False)` turns the rule off,
for a controlling station that discards any value not flagged ONLINE and so could not
verify a setting before enabling the function it belongs to.
*Trade-off:* conformance by default, against masters that read the flag as "bad data".

**D58 -- Reassembly follows the updated reception table.** The DNP Users Group replaced the
transport function's reception state table after the standard was published (TB2013-003).
Two of its rows were not what this library did. A segment that repeats the one before it,
octet for octet, is a link-layer repeat: it is dropped and the series continues, where it
used to abandon the series. And a series that ends having carried no application data
hands nothing to the application layer, where it used to hand up an empty fragment. A
segment that repeats the previous sequence number with different contents still abandons
the series, as does everything else that broke it before.

**D59 -- What is not a request is not answered.** A request is one whole fragment: it
holds an application header, it is both first and final, and it does not carry the
unsolicited bit unless it is a confirmation. A fragment failing any of those is discarded
without a response, and still ends an armed select. Before this a fragment too short to
hold a header was answered with a parameter error on a sequence number read from an octet
that might not be one, and a fragment marked as the middle of a longer message was
processed as though it were whole. The same reasoning is applied one layer down: a link
frame whose length contradicts its function (user data with none, or a reset with data
behind it) is dropped. Inside a well-formed request the rule is still **D9**: a read or a
write that names no object is refused out loud, with the parameter error indication.
An outstation or master address in the range the protocol reserves, or the same address
for both, is refused when the session is built.
*Trade-off:* a master sending something badly broken gets silence and a timeout, against
an outstation that answers noise.

**D60 -- An event stamped before the clock was set is sent with relative time.** A binary
event with absolute time is a statement that the clock was right (TB2017-003). A session
that asks its master for the time has a clock nobody has set, so binary events recorded
until the time is written are marked, and are sent as offsets from a common time of
occurrence whose variation says the clock was not synchronized. Once the time is written,
events are stamped by a set clock and travel with absolute time as before. Asking for the
time again later does not unset the clock; a restart does. A master may also read the
relative-time variation by name, which the Level 2 subset requires an outstation to
answer, and then every event is sent that way behind a common time saying which kind of
clock stamped it. A relative time is sixteen bits, so a run of events gets a new common
time whenever one falls outside that reach, the clock's state changes, or a new fragment
begins. `EventBuffers.synchronized` is the state, and a caller recording its own events
can say so per event. Only a session that asks for the time clears it; one that does not
leaves it as the caller set it, since a clock can be unset for reasons of its own, such as
a network time source that has not yet answered.
*Trade-off:* a master that cannot parse the common time object cannot read events from an
outstation whose time it has not yet written; a Level 2 master is required to.

**D61 -- Time is set by either procedure, and only an outstation that can take it asks.**
Beside the write of the absolute time (**D44**), the session answers the procedure meant
for networks: a request to record the current time, then a write of when that request was
sent, to which the outstation adds the time that has passed since it arrived. The request
may be a broadcast. A write of the recorded time with no request before it is a parameter
error, and a recorded time is used once. `need_time=True` without a `time_sink` is refused
when the session is built: an outstation that asks for the time and cannot take it would
ask in every response for as long as it ran.

**D62 -- A function code can be turned off by configuration.** `Session` takes
`disabled_functions`. Each is then refused exactly as a function this library never
implemented: with the unsupported indication, or with silence where the function takes no
response or arrives as a broadcast, and in neither case acted on. The device profile
leaves out what is disabled. An outstation with no use for cold restart, or whose clock is
set some other way, is safer not accepting the function than accepting and ignoring it.
Confirm cannot be disabled.

**D63 -- A static group may be read by index, and every index named has to exist.** The
subset tables list a read with an index-prefixed qualifier as a request a master may send
and require it of an outstation at no level, so refusing it was conformant. It is answered
all the same: the profile's points sit in blocks with gaps between them, and a master that
wants three points from three blocks otherwise sends three ranges or reads everything
between. The answer is the objects named, in the order named, each behind its index, in
the qualifier the request used and not a narrower one, for the reason **D14** gives for an
echo. A point named twice is sent twice. A block holds one variation, so a point whose
flags force the flagged variation starts a block of its own, exactly as in a range.

An index that is not a served point refuses the whole header with `PARAM_ERROR`, where a
range is allowed to cross a gap and return what exists. The difference is deliberate. A
range is a master saying "whatever is in here", and it cannot know where the gaps are. An
index is a master saying a point is there, so a wrong one is an error in what the master
believes about the device, and answering with the points that do exist would bury it in a
response that looks complete. A read that names no index is the same error. So is one
that names a point with nothing to report, which today means a frozen counter that has
never been frozen: a range passes over it, and a read that named it and got back clean
indications and no object could not tell "never frozen" from "answered". The object is
known in every one of these cases, so the indication is the parameter one and not
`OBJECT_UNKNOWN`.
*Trade-off:* a master probing for which indices exist gets a refusal instead of a partial
answer, and has the range read for that.

**D64 -- A master that is not known in advance is whoever speaks first on a connection.**
`Session(master_address=None)` serves a master it was not configured for, which is the
position of an outstation shipped to a site whose controller nobody has named. The first
address to send a frame to this outstation on a connection is the master, replies go to
that address, and it holds for as long as the connection does. A frame from a second
address on the same connection is dropped, for the reason a configured master's check
already gives: one association has one set of sequence numbers, one pending
confirmation and one select awaiting its operate, and two masters would interleave over
them. A new connection starts again, so a master that restarted under a different address
is served, and what belongs to the association (the restart indication, buffered events)
is there for whoever connects, as it is for a reconnecting master under **D7**. That
answers the choice between refusing a second address and letting it displace the first:
refused within a connection, where two masters can be alive at once, and displacing
across connections, where the first is by definition gone. An address no master can have
(reserved, a broadcast address, or the outstation's own) is not taken as one, and a
broadcast names nobody, so it opens no conversation. The device profile document says
source addresses are never validated and any data link address is expected.
*Trade-off:* the address was never authorization, and without transport security this
makes plain what was already true: any peer that can reach the listener can read, and can
command if controls are bound. A deployment that needs to restrict that uses the
listener's TLS allow-list, or the network.

**D66 -- The event policy is data the caller hands over, and the library reads no file.**
The tables give each point a default event class, and what a controlling station wants
reported differs by deployment, so `DerOutstation` takes an `event_policy`: an
`EventPolicy`, or the plain mapping `EventPolicy.from_mapping` makes one from. It holds a
rule for each kind of point and exceptions for points named one at a time, and a rule may
set the class (1, 2 or 3), turn events off, and for an analog input state a deadband. The
library defines that mapping and validates it. It does not define a file format and does
not open a file: a caller that embeds the outstation already has a configuration format
and a loader for it, and a second format here would be one more thing to keep in step with
the first. JSON and YAML both load to the mapping as it stands.

Three rules decide what a policy means. For the class, a rule naming the point outranks
the rule for its kind, which outranks the tables. A kind's rule moves only the points the
tables already have reporting: a "supports" input, or a point the tables give no class,
stays static under a rule for every binary input, and is given events by naming it. For
the deadband, a rule naming the point outranks the deadband given to `Binding.read`, which
outranks the rule for its kind, so the more specific statement wins and, between two that
name the same point, the deployment's data wins over the code. A policy deadband is in
engineering units and is converted with the point's multiplier, because the person writing
the policy knows volts and not counts; the one given to `Binding.read` stays in transmitted
units, as it was. Turning events off leaves the point in class 0: it stops reporting
changes and is still read. A counter's rule governs the event each freeze logs.

A policy that cannot be right stops the build, with `ValueError` for what is wrong in
itself (a class outside 1 to 3, a negative deadband, a deadband on anything but an analog
input, a rule for an output, a key it does not know) and `MapError` for what is wrong
against the map (a point the map does not hold, events for a point left out of class 0 or
for a counter with no frozen counter, a deadband on a point that reports none). A point the
map holds and the binding does not yet serve is not an error, so a policy may be written
for the whole profile ahead of a binding that grows. The device profile document lists the
class and the deadband in force, read from the outstation and not from the tables.
*Trade-off:* a caller wanting a policy file writes the three lines that load one, against a
library that would otherwise own a format, a parser choice and a dependency for it.

**D67 -- Coverage is a report read from the built outstation, and no part of what it
answers.** `DerOutstation.coverage()` lists every point of the resolved map with where its
value comes from: bound by the caller, mirrored from a bound output, derived as a
"supports" input, fixed by the tables, or absent. These are the builder's own cases and
are recorded as it resolves them, so the report cannot disagree with the wire about which
points exist, and `conformant` is the test `strict` applies. Absent means what **D43**
means by it: nothing serves the point, a class 0 read does not carry it and a read of its
index is refused.

Offline is a different thing and is kept apart. A point that is offline is served, and is
sent with its ONLINE flag clear: its source cannot be reached, it has never been read or
written, its function is disabled (**D57**), or its source called it good and handed over a
value with no number, which goes out as zero with a reference error. That is a fact about a
moment and not about the binding, so the report asks each source once when it is made and
records the quality beside the source, and whether ONLINE went out is read from what the
wire carries and not inferred from the quality. Two reports of one outstation agree on every source and may differ in
quality. A deployment tracking growth compares sources; one asking why a master sees a
point flagged reads the quality.

Nothing that answers a master reads the report, and taking one buffers no event and
changes no output. Its text is for people and is not a format to parse: the dataclasses
are the interface.
*Trade-off:* a report costs one call to every source, and a source that is slow or counts
its reads will notice; a report that did not ask could not say which bound points are
dark, which is the half of the question a growing deployment cannot answer from its own
configuration.

**D69 -- Unsolicited responses are off unless a session is built with them, and a master
enables them by class.** `Session(unsolicited=True)` turns them on. Off is the default,
which is also what the DNP Users Group's guidance on default settings recommends
(AN2015-001), and off means a session answers exactly as it did before the option
existed: `ENABLE_UNSOLICITED` is refused as unsupported, `DISABLE_UNSOLICITED` is agreed
to (D21), and a confirmation carrying the unsolicited bit is ignored (D26). The
certification procedures put it the same way: a device with the mode off behaves like
one without the feature. When this was built, a corpus of some forty thousand framed
exchanges was run through sessions before and after the change and returned the same
octets; the existing tests of the session's answers, none of them changed, are what
hold it from here.

On, a request to enable or disable names classes 1 to 3 with the class object (group
60, variations 2 to 4) and the qualifier for all of it (0x06), and is answered with a
null response. Anything else is refused out loud and changes nothing: class 0 or
another object is an object the function does not apply to (`OBJECT_UNKNOWN`), and a
class named with a count or a range, or a request naming nothing, is a parameter error.
A request is applied whole or not at all, because a master told its request failed has
no way to learn that half of it took effect. Enabling by point, which the standard makes
optional, is not offered. Every class starts disabled after a restart, as the standard
requires, and what a master enabled survives a new connection, because it belongs to the
association (D7). An event recorded before its class was enabled is reported once it
is, unless a poll has read and confirmed it first. A broadcast enable or disable is not
acted on, which is the default the same guidance recommends.

The session still does no I/O. It gains a second entry point for traffic nobody asked
for: `initiate()` returns the octets that are due, usually none, and `initiate_after()`
says how many seconds until the clock alone could change that. Time is the injected
clock. `OutstationServer` calls them, so a caller writes no loop. Where an unsolicited
response goes is answered in one place, `_unsolicited_destination`, which names the
master being served and says nowhere, so nothing is sent, when there is none (D72).
*Trade-off:* a master that wants unsolicited reporting from an outstation it did not
configure gets `FUNC_NOT_SUPPORTED` until someone turns it on, against an outstation
that never sends anything its operator did not choose to send.

**D70 -- An unsolicited response is one fragment in a sequence series of its own, and is
rebuilt for each retry.** A session that reports unsolicited announces itself after a
restart with a null response: no objects, function 130, first and final, asking to be
confirmed, carrying the restart indication while that stands. It is sent again at every
timeout, without limit, until it is confirmed, and no events are sent unsolicited before
then. It is sent again after a restart, and to a new connection if it was never
confirmed: an outstation that waits for its master to connect sends what it has when
that connection comes (TB2016-004).

After that, events in an enabled class are sent in a response built by the code that
answers a class poll: the same selection, order, encoding and fit to the fragment
(D27, D52). It is one fragment, first and final, as the standard requires; what does not
fit follows once it is confirmed. Its events stay buffered until a confirmation carrying
the unsolicited bit and its sequence number arrives (D18). Unsolicited sequence numbers
are a series of their own, starting at zero. Only the response most recently sent can be
confirmed, and that confirmation has no deadline of its own: a master confirms an
unsolicited response on receipt, so one naming the response last sent means it arrived.

A response not confirmed within `unsolicited_confirm_timeout` (five seconds unless set)
is built again from the buffers as they then stand, for the reason D29 gives: they keep
moving, and a copy held from the first transmission would resend an event the outstation
has since reported losing. If what is built matches what was sent, octet for octet, it
goes out under the same sequence number and is an identical retry. If anything differs,
an event recorded since or an indication that changed, it takes the next number and is a
regenerated retry. The standard allows either and requires exactly that of each, since
a master tells a repeat from a new response by those two things together.

`unsolicited_retries` bounds how many times a response carrying events is sent again.
No limit is the default, as AN2015-001 recommends, since delivering what it reports is
the outstation's job. When a limit is reached the series ends, the events stay buffered
and a class poll reads them, and reporting waits for a reason to start again: a newly
recorded event, any request from the master, a new connection, or `unsolicited_resume`
seconds, sixty unless set, which `None` turns off. A buffer whose oldest event will not
fit a fragment waits the same way, because building nothing again would change nothing.
*Trade-off:* a regenerated retry can carry events the master already received in a
response whose confirmation was lost, so a master may see an event twice under two
sequence numbers. It never sees one lost, which is the failure that matters more.

**D71 -- Beside the solicited exchange, a read waits, everything else is answered, and
the timer only reports.** While an unsolicited response waits to be confirmed, a read is
held and not answered (rule 16 of the standard's unsolicited rules, as TB2015-002a
amended it, which holds a read behind the initial null response too). The confirmation
retires the response's events and then answers the read, so a poll never reports what
the unsolicited response carried. If the confirmation does not come, the read is answered
at the timeout instead of a retry: the series ends, its events go back to being
unreported, and the read is often the master asking for them. A read held behind the
null response is answered at the timeout too, and the null response is then sent again.
A second read replaces the first; any other request discards a held read, and is
answered at once without ending the wait for the unsolicited confirmation.

The other direction is rule 8: nothing unsolicited, first transmission or retry, is
sent while a solicited response waits for its confirmation. That wait ends at the
confirmation or at `confirm_timeout` (D51). If it ends by timing out, the solicited
response is given up on when the unsolicited one is sent, so a late solicited
confirmation then retires nothing. Events in flight therefore belong to one exchange at
a time and are retired once. Because the wait has to end, `unsolicited=True` with
`confirm_timeout=None` is refused when the session is built.

`initiate()` reports and does nothing else. The one request it may handle is a held
read; it never reaches a control provider, never repeats a control, and never changes an
output, however long the master is silent. `tests/test_master_silence.py` passes
unchanged, and its session tests run again with the timer on and retrying, beside tests
that count the calls to a binding through hours of unconfirmed retries. `OutstationServer`
drives `initiate()` when a connection is admitted, after each thing received, when
`notify()` is called, when the session's own time comes and every
`unsolicited_interval`; the idle timeout is still measured on what arrives, so a master
that neither polls nor confirms is disconnected as before. *Trade-off:* a master that
ignores unsolicited responses has every read answered up to the confirmation timeout
late, which is what the standard asks of the outstation and is why the feature is for a
master that uses it.

**D72 -- A session that takes any master reports to the one it is serving, and only what
that master enabled.** D64 lets a session learn its master from the first frame of a
connection, and D69 sends unsolicited responses to a master. Together the destination is
the master being served. An unsolicited response has no request to take an address from,
so a session with no configured master sends none until a master has spoken on the
connection, and none again from the moment the connection ends: the restart is announced
to the first master to speak, after its first request is answered, and not into a
connection nobody has identified themselves on.

What a master enabled belongs to that master. It stands across a new connection when the
same address is the first to speak on it, exactly as it stands for a configured master,
because a master that reconnects without a restart in between has no reason to enable
again and would otherwise stop being told with nothing to say so. When a different address
speaks first, every class is disabled. That master asked for nothing, and it may be one
that does not confirm unsolicited responses, which D71 would make pay for another
master's request with every read answered late. It enables what it wants, as a master
does after a restart. Whether the restart was announced is still the association's: once
one master has confirmed the announcement it is not sent again to the next, which sees the
restart indication in every response until one of them clears it.

An address is not an identity, and this decision does not pretend otherwise. A peer that
connects under the address of the master that enabled a class is reported to, as it would
be read by and commanded by under D64. What restricts that is what restricts everything
else about an outstation built this way: the listener's TLS allow-list, or the network.
*Trade-off:* a master that reconnects under a different address has to enable again, and
until it does its events wait in the buffers for a poll.

## Layering

Each layer is testable without the ones above it, and the session does no I/O.

- `crc` knows nothing of frames.
- `link` knows nothing of transport segments, and never trusts a length field before its
  checksum verifies. Resynchronization steps past the start octets rather than past the frame a
  failed header claims, because `0x05 0x64` can occur inside the user data of a frame whose
  beginning was lost.
- `transport` segments deterministically and reassembles suspiciously. A sequence gap, an orphan
  continuation, an oversized segment and an endless series are each refused and leave the
  reassembler empty, because continuing a broken series is how two requests become one fragment.
- `application` owns the envelope and stops where the point map begins. A request carrying
  object data is parsed as far as its first object header; walking further needs the width of
  every group and variation, which the map knows and this layer does not.
- `session` holds what is true of a conversation rather than of a frame.

## Testing

**Literal octets, not round trips.** A test that encodes with this library and decodes with it
agrees with itself through swapped addresses, inverted endianness, wrong length semantics or
misplaced block checksums. The framing suite therefore carries a published frame this
implementation reproduces octet for octet, a hand-derived populated frame, and the CRC catalog
check value -- the one assertion an implementation that is self-consistently wrong cannot
satisfy.

The two protocol layers assign FIR and FIN to opposite bits, which is the kind of detail a
self-agreeing test will never catch, so both are pinned to literal octets.

**Interoperability against other implementations.** A peer written from the same reading of the
specification shares its misreadings, so CI reads this library's outstation with a master built
on a separately developed C++ stack (`interop/`, run by the `interop` workflow). Its upstream is
end-of-life, which disqualifies it as a dependency and not as a witness: a frame it parses is a
frame that was correct when it was maintained, and the wire format has not moved. The master
runs in its own Python 3.10 environment, because that is the last interpreter it publishes
wheels for.

Additional masters are worth adding, with the caveat that two interfaces over one core is one
implementation and not two.

**What that job does not cover.** The master it uses stores point values as bare scalars and
discards the quality octet, so the interoperability run checks values and not flags. The
outstation it drives deliberately serves one point offline, and that point reads back as a
number like any other. Quality is pinned by the wire-level tests instead, and closing the gap at
this level needs a peer that exposes quality rather than a change to the harness.

**The certification procedures, section by section.** The DNP Users Group publishes the
procedures a test house follows to certify an outstation. `tests/test_ied_*.py` carries
them out against a Level 2 configuration, each test named for the section it performs,
and `tests/test_ied_coverage.py` lists every section as either tested or not applicable
with the reason. Passing them is this project's own assessment and is not a
certification, which only an authorized test house can grant.

**The DER profile's own test procedure.** EPRI published a test procedure for the
application note IEEE 1815.2 replaced. `tests/test_epri_der_procedures.py` carries it
out against the simulated DER, each test named for the procedure it performs, with the
point pairings read from the tables and not written into the tests. Where the standard
has since changed what the procedure expects, the suite follows the standard and
`tests/test_epri_coverage.py` lists each such departure with its reason.

**The corrections published since the standard.** The Users Group's technical bulletins
and application notes change or clarify what the base standard says.
`tests/test_technical_bulletins.py` checks what each asks of an outstation, named for
the document, and `tests/test_bulletin_coverage.py` lists every one as acted on or as
asking nothing of this outstation, with the reason.

## Roadmap

- ~~The TCP and TLS listener, with D7 and D8.~~ Landed.
- ~~Controls: SELECT, OPERATE, DIRECT OPERATE and DIRECT OPERATE NO ACK, with D10 through D16.~~
  Landed. The outstation commands as well as reports; output status readback is served by the
  caller's provider, per D6.
- ~~Events, classes 1 through 3, read from the buffers, confirmed, and reported through the
  indication bits, with D17 through D27.~~ Landed. `DISABLE_UNSOLICITED` is answered rather than
  refused: an outstation that sends none is already in the state the master is asking for, so
  refusing it answered a question the master did not ask.
- ~~Responses larger than one fragment, with D28 through D35.~~ Landed. A response too large to
  send at once is a conversation: the master confirms each fragment and the next follows. A provider
  may also say where its own objects end, so a point map too large for one fragment reaches a master
  rather than being refused.
- ~~Unsolicited responses: outstation-initiated traffic with its own retry timer, and
  `ENABLE_UNSOLICITED` becoming something this outstation can agree to.~~ Landed, with D69
  through D71, and off unless a session is built with `unsolicited=True`. The session gained
  a second entry point, `initiate()`, so it still does no I/O, and `OutstationServer` drives
  it. Still to do: running the interoperability masters against it, and the planning notes in
  [`planning/UNSOLICITED.md`](planning/UNSOLICITED.md) list what else was left out.
- ~~The point-map loader and an IEEE 1815.2 outstation built from it, with D36 through D47.~~
  Landed as `py1815.profile`: the loader, the builder, a simulated DER and the `py1815-der`
  command. Time synchronization, counters with freezes, and event groups read by name came
  with it, because the profile's implementation table requires them. Still planned in
  [`planning/DER_PROFILE.md`](planning/DER_PROFILE.md): curves and schedules as objects, the
  fleet layout, floating-point variations, and a published table for the predecessor profile.
- Conformance testing.

## Open

- Contribution terms: whether to require a DCO, a CLA, or neither.
- Whether the AN2018-001-derived point map ships with the first release. It carries an
  attribution obligation from the reference implementation it is derived from, which needs
  confirming before publication rather than after.
