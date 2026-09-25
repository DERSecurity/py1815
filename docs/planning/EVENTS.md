# Plan: the event path

Events are buffered and cannot be read. `EventBuffers` records them with
deadbands, overflow and confirmation handling, and `session.py` does not import
it -- a class 1, 2 or 3 read reaches the provider like any other and comes back
with whatever static data it serves. This connects the two.

## Scope

**Solicited reads only.** A master asks; the outstation answers from its
buffers and the master confirms. Unsolicited responses -- outstation-initiated
traffic with its own retry timer -- are a separate plan.

That split is not a way of deferring the awkward half. It is that unsolicited
introduces a class of risk nothing here has: a bug in a request/response path
answers wrongly, and a bug in a self-initiated one sends frames nobody asked
for, on a timer, to a master that may not be listening. The first multi-fragment
response path is enough novelty for one change.

The interoperability warnings the roadmap complains about are still addressed
here -- see **D21**. They do not require sending an unsolicited response.

## What already exists

The pattern from the controls work repeats: the layers below were built
expecting this.

- `EventBuffers` records, buffers per class, applies deadbands, reports
  overflow, and separates `peek` from `drop` -- which is exactly the shape
  confirmation needs.
- `ObjectHeader.event_class` already distinguishes class 0 from classes 1 to 3,
  so a read naming a class arrives identified.
- `AppControl` carries `fir`, `fin`, `con` and `uns`. Multi-fragment sequencing
  and the confirm request need no new parsing.
- `IINBit.CLASS_1_EVENTS`, `CLASS_2_EVENTS` and `CLASS_3_EVENTS` exist, as does
  `IIN2Bit.EVENT_BUFFER_OVERFLOW`.
- `objects.event_block` encodes an index-prefixed block, and the event
  variations and timestamps are already written and tested.

What is missing is the session: reaching the buffers, holding a response until
it is confirmed, and splitting one that does not fit.

## Decisions

Continuing from D16 in [DESIGN.md](../DESIGN.md).

**D17 -- The caller owns the buffers and the session only reads them.** The
caller constructs `EventBuffers`, records into it as its device polls, and hands
it to `Session`, which calls `peek`, `drop` and `overflowed` and never records.

Recording cannot happen inside a request. A deadband is measured against the
last value *reported*, not the previous reading, so it needs history between
requests rather than during one -- and under **D6** this library does not know
which index is which point or when it moved. An `EventProvider` asked for events
when a read arrives would have to own a buffer anyway, so the indirection would
buy nothing and hide where the state lives.

**D18 -- A confirmation is what the outstation retires an event *for*. The
buffer bound is the other way one leaves.** A response carrying events sets
`CON`, and the events stay until the matching `CONFIRM` arrives. `peek` selects,
`drop` retires, and the gap between them is the window a master might fail to
answer in.

This is why `EventBuffers.drop` matches on identity rather than equality, and
why it is load-bearing that the events are still buffered while the confirm is
outstanding.

A master that never confirms gets the same events again on its next read, until
the buffer fills. `_ClassBuffer.add` evicts the oldest at capacity and raises
the overflow flag, so continued recording can remove an unconfirmed event before
the master ever sees it a second time. That is not a hole in this decision, it
is the decision the buffer already made: unbounded retention for a master that
has gone quiet is how an outstation runs out of memory, and the overflow bit
exists to say that data was lost rather than to pretend it was not.

The two interact where a pending selection is evicted. `drop` skips events it
cannot find, so a confirmation retires whatever survived and silently ignores
what did not, which is the right outcome -- there is nothing to retire and
nothing to report beyond the overflow bit already set. The acceptance criteria
below have to cover that case rather than assume a selection outlives the wait.

**D19 -- One outstanding response at a time, and a new request replaces it.**
Under **D7** there is one association, so there is one unconfirmed response to
track. A read arriving while one is outstanding supersedes it: the master has
evidently moved on, and a confirmation arriving afterwards would name a response
that is no longer the current one.

A refusal counts. An unsupported function or a control sent to a monitor-role
outstation is a response like any other, and leaving the selection standing
across one would let a confirmation for the response *before* it still retire
those events. The first draft of this decision was written as though only the
requests that do work superseded, and the implementation followed it -- which
put two refusal branches on the wrong side of the line.

Two things are outside it, and stay outside it:

- The functions that ask for no response. They send nothing, so there is no
  response for a later confirmation to be late against.
- A fragment that did not parse. That is not evidence the master moved on; it
  is evidence something arrived damaged, which is exactly when a retransmission
  of the held response is the likely next thing to arrive. Discarding the cache
  on noise would throw it away at the one moment it is most wanted.

**D20 -- Class 0 is static and classes 1 to 3 are events, answered in one
response.** The integrity poll a real master sends names all four. Static
objects come from the `ReadProvider` as they do today; event objects come from
the buffers; both travel in one response, events first.

Events first because a master applies them in order: a static value written
after the events that led to it leaves the point at its current value, which is
what the master should end up holding.

**D21 -- `DISABLE_UNSOLICITED` succeeds; `ENABLE_UNSOLICITED` is still
refused.** The asymmetry is the point. An outstation that sends no unsolicited
responses is already in the state `DISABLE` asks for, so refusing it answers a
question the master did not ask. `ENABLE` asks for something this outstation
does not do, and saying so is the honest answer.

This halves the warnings a real master's startup produces -- the roadmap's
complaint -- without implementing anything that sends.

**D22 -- The class-event indication bits are derived from the buffers, not
tracked separately.** `IIN1.1`, `1.2` and `1.3` say which classes have events
waiting. A master polling on indications never asks for events it is not told
about, so a bit that drifts from the buffer is an outstation whose data is
invisible. Deriving them on each response makes drift impossible rather than
unlikely.

**D23 -- Overflow is reported until a master has seen it.** `IIN2.3` is set
while `EventBuffers.overflowed()` is true, and `clear_overflow` runs once the
response carrying the bit is confirmed -- not when it is sent. An overflow
reported in a response the master never received is an overflow the master never
learned about.

**D24 -- `ASSIGN_CLASS` stays refused.** A class is assigned when the caller
records the event, and under **D6** this library holds no point map for a master
to reassign. Accepting the request would mean either ignoring it or inventing
the map the design exists to keep out.

**D25 -- A repeated request is replayed, not rebuilt, and a repeat is one that
matches octet for octet.** A master that did not receive a response repeats the
request. The outstation holds the request beside the response it produced and
the events it selected, and when the same octets arrive again it sends that
response back unchanged.

The comparison is against the request and not against the sequence number alone.
A master that reuses a sequence for a *different* question has retransmitted
nothing, and answering it from the cache would reply to the question before it --
then have those events retired by the confirmation that followed, acknowledged
against a response the master never asked for.

The two shapes differ only when an event arrives in between, and that is the
case that decides it. The confirmation which follows retires the events the
response was built from, so a rebuilt response carrying an event the first did
not would have that event retired under a sequence it was never sent under --
reported once, acknowledged once, and gone, except that the master's copy of
the exchange and the outstation's disagree about which events the sequence
covered. Replaying keeps the two in step at the cost of the newer event waiting
for the next read, which is the delay a retransmission implies anyway.

The cache this needs is not extra machinery. Confirmation has to record which
events went out under which sequence regardless, and the fragment is one more
field beside them.

This was decided without the text of the standard, which was not available.
**IEEE 1815** may specify the behavior outright, and if it turns out to say
rebuild, switching is deleting the `fragment` field and re-dispatching the
request -- the sequence and the event selection stay either way. The decision is
recorded as a soft one for that reason.

**D26 -- A confirmation carrying `UNS` is ignored.** The bit distinguishes a
confirmation for an unsolicited response from one for a solicited response, and
the two count sequence numbers separately. This outstation sends no unsolicited
responses, so a confirmation carrying the bit names an exchange that never
happened, and retiring the solicited selection on the strength of a number from
a different counter would delete events the master has not acknowledged.

Ignored rather than consumed: the master's real confirmation may still be
coming, and swallowing the selection here would lose the events instead of
merely mistiming them. This is the same asymmetry as **D21** -- an outstation
that does not send unsolicited responses answers questions about them by
declining to act, not by pretending the exchange exists.

**D27 -- A response is capped to what the master can receive, and the rest
stays buffered.** ``max_response`` is its own number rather than the reassembly
ceiling ``max_fragment``: one is the largest request this outstation will piece
back together, the other the largest fragment the master on the far end can
accept, and a master advertises its own. Sending past it is not a long response
but a discarded one -- the events were readable and then none of them arrived.

Events are fitted to what is left after the application header and whatever the
provider returned. Static data is paid for first and trimmed never: it is the
provider's answer, and this session cannot tell where one object inside it ends.
Events still travel in front of it on the wire, per **D20**.

A provider body that overruns the ceiling on its own is the one case the events
cannot be fitted around, and the read is refused with `PARAM_ERROR` rather than
sent. Sending it past the ceiling loses the whole response -- the master
discards the fragment -- and says nothing about why; four octets that arrive and
name the problem let a master narrow its request. Nothing is recorded as
outstanding on that path, so the events stay buffered for the read that fits.

What does not fit is left in the buffer and left out of the selection, so the
confirmation retires only what was actually sent and the class indication bits
go on asking for the rest. A master that reads again gets it.

The fit is found by bisecting the encoder rather than by arithmetic on the
header layout, because a block's size is not a fixed cost per event -- the
qualifier widens when the count passes an octet or an index does. Bisection is
sound because the size never falls as events are added.

The ceiling bounds the work and not only the octets. `capacity` has no upper
bound, so anything proportional to the buffer is proportional to a number the
operator chose, paid on every read a peer sends. The selection is therefore cut
to what could possibly fit *before* anything is encoded -- the remaining budget
divided by the narrowest an event encodes, which is a strict upper bound rather
than an estimate -- and the buffer is asked for no more than that plus what the
deduplication is about to remove. A four-octet response over fifty thousand
events used to cost fifty thousand encodings; it now costs none.

That is what `peek`'s `limit` is for, and it settles the open question about it.
The limit is not how a count qualifier is answered -- a limit taken before
deduplication would come back short -- it is how a caller avoids paying for a
buffer it has no room for. It has to slice while walking the deque rather than
after materialising it, or the call still costs the buffer.

This is the cap section 3 replaces with a split. Until then an outstation that
answers with fewer events than it holds is correct, just chatty.

The ceiling is not only the read path's. A control response is the request
echoed with a status per object, and one that will not fit is refused *before
anything is dispatched* -- a control that executes and cannot report its outcome
is worse than one that never ran, because a master that learns nothing about an
operate is a master that may send it again. The echo is measured with a probe
status, since an object's encoding is a fixed size for its type and the status
sits inside it.

A ceiling below a response header is refused at construction. Every answer such
an outstation could give would break it, including the refusal it would give
instead, so the number is rejected where it is set rather than logged on each
response that overruns it.

## Work

### 1. Session wiring

`Session(provider, events=...)`, and `_handle_read` consulting the buffers for
any header whose `event_class` is 1, 2 or 3.

A read naming a class the buffers hold nothing for is not an error -- it is an
empty answer, which is a normal outcome a master polls for.

**Acceptance:** a class 1 read returns the class 1 events and not the class 2
ones; a read naming classes 1 and 2 returns both; a class 0 read is unchanged
and still reaches the provider.

### 2. Confirmation

The state a response leaves behind: which events were sent, and under which
sequence number. `CONFIRM` stops being a silent no-op and becomes the thing that
drops them.

The existing comment on that branch says "nothing is outstanding to confirm
until unsolicited responses exist" and will need replacing rather than editing.

**Acceptance:** events survive a response that is never confirmed and are
returned again by the next read; a confirmation retires exactly the events its
sequence number covers; a confirmation with the wrong sequence retires nothing;
`connection_reset` leaves the buffers alone but forgets what was outstanding,
since the socket carrying that response is gone.

And the eviction case from **D18**: recording past capacity while a confirm is
outstanding evicts the oldest selected event, after which the confirmation
retires the survivors, raises no error, and leaves the overflow flag set.

### 3. Multi-fragment responses

The first in this library. Events that do not fit one fragment split across
several, `FIR` on the first, `FIN` on the last, sequence incrementing, each
carrying `CON`.

**Acceptance:** a buffer larger than one fragment produces several, each
individually confirmable; the last carries `FIN`; a master that confirms only
the first keeps the rest.

This is the section most likely to need its own design pass once started. If it
proves larger than the rest combined, landing sections 1, 2 and 4 with a
single-fragment cap is a reasonable first release -- an outstation that answers
with fewer events than it holds is correct, just chatty.

### 4. Indications

Class bits from the buffers per **D22**, overflow per **D23**.

**Acceptance:** a buffer with class 2 events sets `IIN1.2` and neither
neighbour; the bits clear when the events are confirmed away; overflow survives
until the response reporting it is confirmed.

### 5. `DISABLE_UNSOLICITED`

Per **D21**. Small, and worth doing here rather than with unsolicited, because
it is the half that needs no sending.

**Acceptance:** `DISABLE_UNSOLICITED` is answered with a null response that
does *not* carry `FUNC_NOT_SUPPORTED`; `ENABLE_UNSOLICITED` still does.

Success is the absence of that bit rather than an empty indication field, which
an earlier draft of this said and which nothing could satisfy. `DEVICE_RESTART`
is set until a master clears it, and **D22** and **D23** put the class and
overflow bits there on their own terms -- a response reporting them is still a
successful one.

### 6. Interoperability

`interop/outstation.py` records events on a timer so the peers have something to
read. The C++ and Rust masters both poll classes on startup, so this is the part
of the job that has been asking for events since it was written -- the warnings
in its log are the outstation refusing the questions it was asked.

**Acceptance:** a peer reads events it did not read as static data, and the
sweep's class 1 to 3 cases return objects rather than an empty response.

### 7. Documentation

D17 through D24 into `DESIGN.md`; the roadmap entry for events narrowed to the
unsolicited half that remains; `README.md`'s status line, which currently says
the event path is not implemented; and `CHANGELOG.md`.

## Sequencing

Sections 1 and 4 together -- serving events and saying they are there are two
halves of one useful change, and either alone is a master that cannot find the
data. Then 2, which is the state machine. Then 5, which is independent and
small. Then 3, which is the largest and the one most likely to want its own
plan. Then 6.

## Open

- **Settled: what `peek`'s limit is for.** Recorded here because the answer took
  three passes to find. It is not how a count qualifier is answered -- the count
  is applied after deduplication, and a limit taken before it would leave a
  second header naming the same class short. It is how the response budget
  avoids paying for a buffer it has no room for. See **D27**.

- **Events per fragment.** A bound belongs somewhere, and as with the control
  cap it should be chosen here rather than borrowed. The fragment size already
  bounds it; a lower limit is only worth having if a reason for one appears.

- **Whether the standard agrees with D25.** Not an open design question -- the
  behavior is decided and implemented -- but the one place in this plan where
  the text would change an answer rather than confirm it. Worth re-reading the
  application layer's duplicate-request handling if a copy becomes available.
