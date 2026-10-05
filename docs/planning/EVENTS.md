# Plan: the event path

Events are buffered and cannot be read. `EventBuffers` records them with
deadbands, overflow and confirmation handling, and `session.py` does not import
it -- a class 1, 2 or 3 read reaches the provider like any other and comes back
with whatever static data it serves. This connects the two.

## Scope

**Solicited reads only.** A master asks; the outstation answers from its
buffers and the master confirms. Unsolicited responses -- outstation-initiated
traffic with its own retry timer -- are a separate plan, now built:
[UNSOLICITED.md](UNSOLICITED.md).

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

That design pass happened, and it has its own plan:
[FRAGMENTATION.md](FRAGMENTATION.md). What is left here is the pointer. Sections
1, 2, 4 and 5 landed with the single-fragment cap of **D27**, which is what that
plan replaces.

### 4. Indications

Class bits from the buffers per **D22**, overflow per **D23**.

**Acceptance:** a buffer with class 2 events sets `IIN1.2` and neither
neighbor; the bits clear when the events are confirmed away; overflow survives
until the response reporting it is confirmed.

### 5. `DISABLE_UNSOLICITED` -- landed

Per **D21**. Small, and worth doing here rather than with unsolicited, because
it is the half that needs no sending.

Nothing is recorded when it is accepted. There is no state to enter that is not
already the state, and a flag tracking it would be one no sending path exists to
read. Unsolicited responses have since landed, and a session built with them
takes this request by class instead (D69); one built without them, the default,
answers as described here.

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

### 6. Interoperability -- landed, bar the C++ probe

`interop/outstation.py` holds events, and the function code sweep reads them:
each class on its own and an integrity poll naming all four. The sweep's traffic
is dissected by Wireshark and Suricata, so the event objects are checked on the
wire by implementations that are not this one.

**The Rust master reads them.** Three class reads of its own, after the static
one, so a class answered with another class's events fails rather than passing
as the right values under the wrong heading.

That needed less than this section assumed and more than it looked. Less,
because the master issues an *explicit* read rather than relying on a startup
scan, so `AssociationConfig` is untouched and events are simply a second read.
More, because events and static values arrive through the same handler: a class
read would have overwritten the point map the existing assertions depend on, and
would have broken the variation check, which asserts every analog header carried
g30v1. The collector is told between the reads which it is looking at, rather
than routing on a `HeaderInfo` field that cannot be checked without compiling.

`handle_binary_input` is implemented, having been an empty stub. The fixture
seeds a binary event behind the analog ones of its class, and it is what proves
a peer sees them in the order the points changed rather than gathered by type.

**The C++ probe stays static-only.** It scans a group and variation rather than
any class, and whether its bindings expose event objects at all is an open
question -- they already discard the quality octet, which is why the Rust peer
exists. One independent master reading events is the assertion worth having, and
a second adds little against that uncertainty.

**The sweep walks a conversation**, which is the other half of what a master
does with events and the half no peer covers. `dnp3-rs` reassembles and confirms
a class read inside the library, so a master asserting on the values it ends up
with says nothing about the exchange that carried them. So the sweep sends a
request and confirms each fragment itself, checking what only a walk can see:
`FIR` opening the exchange and nothing else setting it, `FIN` closing it, the
sequence advancing by one around the sequence space, a fragment that asks to be
confirmed being answered when it is, and the confirmation of the last one
drawing no further traffic. That traffic goes into the capture Wireshark and
Suricata read, so the framing of an exchange rather than of a single reply is
now checked by implementations that are not this one.

The exchange it walks is really multi-fragment, which took arranging. How much
a fragment holds is the outstation's `max_response` and no master can set it
over the wire, so the sweep's fixture is started with `--max-response 36` while
the peer jobs keep the default. Class 1 holds five events, enough that reading
it takes three fragments -- and three is the number that matters, because only
then does a fragment carry neither `FIR` nor `FIN`. At two the second fragment
is the last one, and that state never reaches the wire at all. Both numbers are
pinned in `tests/test_interop_fixture.py`, so seeding one event fewer or raising
that ceiling fails there rather than quietly downgrading what CI exercises.

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

Sections 1, 2, 4, 5, 6 and 7 have landed, along with D25, D26 and D27, none of
which were in this plan when it was written -- they came out of review. Section
3 remains, and has [a plan of its own](FRAGMENTATION.md).

Section 6 landed bar the C++ probe, which reads no class and stays that way
deliberately. What it would add is a second opinion on an assertion one
independent master already makes, against a binding whose handling of event
objects is an open question.

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
