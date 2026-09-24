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
evidently moved on, and holding a stale selection would answer the new request
with the old events.

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

- **Retransmission.** A master that does not receive a response repeats the
  request with the same sequence number. Whether to replay the previous response
  or build a fresh one from the buffer needs settling before section 2 is
  written; the two differ when an event arrives in between.
- **Events per fragment.** A bound belongs somewhere, and as with the control
  cap it should be chosen here rather than borrowed. The fragment size already
  bounds it; a lower limit is only worth having if a reason for one appears.
- **Whether `peek` needs its limit.** Still open, and an earlier edit of this
  entry claimed otherwise. Section 1 taught something about it rather than
  settling it: a class read may carry a count qualifier asking for at most that
  many events, but `peek`'s limit is *not* what answers one. The count is
  applied after deduplication, because a limit taken inside `peek` would count
  events that the deduplication then removes -- so a second header naming the
  same class would come back short of what the master asked for.

  The parameter therefore still has no caller in `src/`. Section 3 may find one
  in fragment splitting, and it should not be removed before then.
