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

The event path's decisions are **D17 through D27**, and they live in
[DESIGN.md](../DESIGN.md) with the rest. They are not repeated here: a decision
recorded twice is a decision that will be amended once.

Three of them were not in this plan when it was written and came out of review:

- **D25**, what a repeated request is answered with.
- **D26**, a confirmation carrying `UNS`.
- **D27**, the ceiling on a response and the work that goes into building one.

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

### 5. `DISABLE_UNSOLICITED` -- landed

Per **D21**. Small, and worth doing here rather than with unsolicited, because
it is the half that needs no sending.

Nothing is recorded when it is accepted. There is no state to enter that is not
already the state, and a flag tracking it would be one no sending path exists to
read. When unsolicited responses land, this becomes where that flag is written,
and the answer given here does not change.

The classes the request names are accepted without being examined, since the
answer is the same for any of them. They are emphatically not a selection to
answer: the function reaches its own branch rather than falling through to the
read path, which would hand a master events it never polled for and then wait to
have them confirmed.

**Acceptance:** `DISABLE_UNSOLICITED` is answered with a null response that
does *not* carry `FUNC_NOT_SUPPORTED`; `ENABLE_UNSOLICITED` still does.

Success is the absence of that bit rather than an empty indication field, which
an earlier draft of this said and which nothing could satisfy. `DEVICE_RESTART`
is set until a master clears it, and **D22** and **D23** put the class and
overflow bits there on their own terms -- a response reporting them is still a
successful one.

### 6. Interoperability -- half landed

`interop/outstation.py` holds events, and the function code sweep reads them:
each class on its own and an integrity poll naming all four. The sweep's traffic
is dissected by Wireshark and Suricata, so the event objects are checked on the
wire by implementations that are not this one.

**No peer master reads them yet**, which this section assumed and which is not
true. The C++ probe scans group 30 variation 1 rather than any class, and the
Rust master is configured with `EventClasses::none()` and `Classes::class0()`.
So a master's *interpretation* of an event -- reassembling a class read,
confirming it, applying the events in the order they arrived -- is still the
part nothing outside this repository has exercised.

Making one of them read events is not a configuration change. In `dnp3-rs` an
event and a static value arrive through the same handler, so a class scan added
to the Rust master would overwrite the static readings its existing assertions
depend on, ordered by where the events sit in the response. The collector has to
tell the two apart first. That is the remaining work, and it belongs with a peer
run to verify it rather than with the fixture change.

Seeded at startup rather than driven from a timer, which is what this section
originally said. The peers need something deterministic to assert against, and a
clock that keeps adding events makes every assertion a race -- a master reading
twice would see a different answer for reasons that have nothing to do with the
protocol. Liveness is not what these jobs test.

The values are deliberately unlike anything the point map holds, which is what
makes the case provable: a master reporting one of them cannot have read it as
static data.

**Acceptance:** a peer reads events it did not read as static data, and the
sweep's class 1 to 3 cases return objects rather than an empty response.

### 7. Documentation -- landed

D17 through **D27** into `DESIGN.md` -- three more than this section was written
expecting, since D25, D26 and D27 came out of review rather than out of the
plan. The roadmap entry narrowed to the unsolicited half that remains;
`README.md`'s status line, which said the event path was not implemented; and
`CHANGELOG.md`.

## Sequencing

Sections 1 and 4 together -- serving events and saying they are there are two
halves of one useful change, and either alone is a master that cannot find the
data. Then 2, which is the state machine. Then 5, which is independent and
small. Then 3, which is the largest and the one most likely to want its own
plan. Then 6.

Sections 1, 2, 4, 5 and 7 have landed, along with D25, D26 and D27, none of
which were in this plan when it was written -- they came out of review. Sections
3 and 6 remain.

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
