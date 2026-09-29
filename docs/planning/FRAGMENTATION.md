# Plan: responses larger than one fragment

Section 3 of [the event plan](EVENTS.md), lifted into a plan of its own because
it is the part of that one most likely to need its own design pass, and because
what it changes is not confined to events.

Today a response is **capped**: events are fitted to what the master can
receive, what does not fit stays buffered, and the class indication bits go on
asking for it (**D27**). That is correct and chatty. This is how it becomes a
split.

## What already exists

- `transport.segment` splits an application fragment into transport segments
  with their own `FIR`/`FIN` and sequence. That is the *lower* layering and is
  not what this is about -- it divides one fragment and does not reduce it.
- `AppControl` carries `fir`, `fin` and `con`, and nothing in the encoder
  assumes a response is the first or the last.
- `_Outstanding` already records what went out under which sequence, the
  fragment itself, and the overflow generation it reported. Holding the *rest*
  of a selection beside that is a field, not a mechanism.
- `_fitting` bisects the encoder to fill a budget exactly, and returns how many
  of a block it took. Splitting is that, continued.
- `EventBuffers.drop` retires by identity, so retiring per fragment is already
  expressible.

## The shape

A multi-fragment response is not one answer chopped up and handed over at once.
It is a conversation: the outstation sends a fragment with `FIR` set and `FIN`
clear, the master confirms it, and the next fragment follows under the next
application sequence number. The last carries `FIN`.

So `Session.receive` does not start returning more octets. It returns the same
one fragment it always did, and a *confirmation* becomes a request for the next
one -- which is new. Confirmations answer with silence today.

That is the whole of the change in one sentence, and everything below is a
consequence of it.

## Decisions

Continuing from **D27** in [DESIGN.md](../DESIGN.md).

**D28 -- A confirmation that continues a response is answered with the next
fragment.** Today `CONFIRM` returns `b""`. It keeps doing so when nothing is
outstanding or the outstanding response was the last one; when the outstanding
response has more behind it, the answer is the next fragment.

This is the one place the session answers something that is not a request, and
it is worth being explicit that it is not an exception being carved out: under
**D18** a confirmation is already the event that moves the state machine on. It
retires what was sent. Sending what comes next is the same transition.

**D29 -- Each fragment is built from the buffer as it then stands.** Not built
ahead and queued, and -- the part a first draft of this plan got wrong -- not
carried as a remainder either.

The obvious design is for `_Outstanding` to hold the events that did not fit and
for the next fragment to come off that list. It cannot. `_Outstanding.events`
holds strong references on purpose, so that `drop` still matches what it is
given after an eviction; a remainder held the same way keeps the whole buffer
alive for as long as a master is slow, which is exactly the unbounded retention
**D18** and **D27** exist to prevent. Worse, it would let an event that has since
been *evicted* go out in a later fragment, so a master would receive an event the
outstation had already reported losing.

So a continuation peeks the buffer again and takes what fits, exactly as the
first fragment did. `_Outstanding` keeps only what it sent, as it does today, plus
the fact that more remains. Events evicted in between are simply gone, which is
what the overflow bit is for; events recorded in between join the response, which
costs nothing and saves a round trip.

That last point is why this needs a bound rather than a rule about which events
belong to which response. A buffer filling as fast as it drains would otherwise
answer for ever. See **D32**.

The rule this states is not "hold nothing". A response does hold the provider's
body across its fragments (**D33**), and the difference is worth naming, because
"carry nothing" and "carry one body" are two rules and a plan that asserts both
without a reason is a plan that will be read as contradicting itself.

What may not be held is state that is **the caller's to size**, or whose staleness
would put something on the wire that is no longer true. The event remainder fails
both: it is bounded only by `capacity`, which the operator chooses and this
library does not cap, and an evicted event sent from it would be one the
outstation has already reported losing. The provider's body fails neither. It is
bounded by construction -- **D31** refuses one that does not fit a single fragment,
so holding it costs at most one fragment's worth -- and a body a few round trips
old is a stale *reading*, which is a different thing from a false statement about
what was lost.

**D30 -- A request arriving mid-sequence ends the conversation.** Under **D19** a
new request supersedes what was outstanding, and a partly-sent response is no
different: the master has moved on, and the events it did not take stay buffered
for the read it just sent. The fragments already confirmed stay retired, because
they were received.

Under **D29** what is discarded is the fact that more was coming and the
provider's body held for the last fragment -- no remainder, because none is held.
That makes this decision cheap to implement and easy to get wrong in the other
direction: forgetting to clear the flag would have the next confirmation continue
a response the master has already abandoned, and forgetting the body would leave
a read's answer to be delivered inside somebody else's.

**D31 -- Opaque static data is not split, and a body that does not fit is
refused.** `ReadProvider.read` returns octets, and this library cannot tell where
one object inside them ends, so there is no honest place to cut one.

That is the fallback rather than the rule -- see **D35**, which gives a provider a
way to say where its objects end. A provider that does not is answered as it
always was: fragmentation lets a large buffer of *events* reach a master, and a
static read too large for one fragment is refused.

**D32 -- A response is bounded in fragments, not only in octets.** One
conversation carries at most so many, and the last of them sets `FIN` whether or
not the buffer is empty -- after which the class indication bits go on asking,
which is **D27**'s cap reached later and with most of the buffer delivered.

Reaching the bound ends the events, not the response. A read that also named
class 0 still owes the master its static data, so the provider's body goes out
with `FIN` as it would have anyway (**D33**). Stopping short of it would answer a
request for static data with events and nothing else, which is a worse failure
than being chatty.

Which means the bound is on the fragments of events, and a response may carry one
more than it for the body. Counting the body's fragment against the bound would
have an outstation that reached it drop the static data instead -- the failure
the paragraph above rules out, reintroduced by the arithmetic.

A bound is needed because **D29** lets events recorded mid-conversation join it.
Without one, an outstation whose device polls faster than its master confirms
never sends `FIN`, and a master that is waiting for the end of a response is a
master that never issues another request.

The bound is **sixteen fragments**, and it is a count rather than an octet budget
or a deadline. A count is the one of the three that can be reasoned about from a
log line, and sixteen is not arbitrary: it is one full trip through the
application sequence space, so a conversation that reaches it has used every
sequence number once and is starting over. A full default buffer of a thousand
events is about seven fragments at the 2,048-octet ceiling, so sixteen leaves
room for a buffer twice that size while still stopping one that fills as fast as
it drains.

An octet budget was the alternative worth weighing -- it costs the same for many
small fragments as for few large ones -- and was not taken because there is no
number for it that explains itself. A deadline was not taken because the session
is clock-free apart from the select timeout, and a response whose length depends
on how fast the machine is is a response that cannot be pinned in a test.

**D33 -- Static data travels in the last fragment.** A read naming class 0 and
an event class is answered with the provider's body after every event, not
alongside the first of them.

This falls out of **D20** and is easy to get wrong: putting static data in the
first fragment -- which is what the current single-fragment code does, and what a
naive split would keep doing -- has the master apply it *before* the events in
the fragments that follow, so it ends up holding an event value older than the
reading the same response carried. The whole point of events-before-static is
that the static value wins.

The body is read once, when the first fragment is built, and held until the last
-- the one thing a response carries across its own fragments, which **D29**
explains the shape of.

Three reasons, in increasing order of how much they matter. A response reporting
two different values for one point over its own length is a worse answer than one
a moment old. The provider is the caller's code and may poll a device to answer,
so calling it once per fragment turns one logical read into several.

And the one that decides it: a body re-read at the end might no longer fit. The
response would then be mid-conversation, already committed, with nothing good to
send -- **D31**'s refusal is an answer to a request, not to a continuation of one
this outstation has already begun. Measuring the body once, at the start, is what
makes the last fragment's fit knowable from the first.

**D34 -- A confirmation naming the previous fragment re-sends the current one.**
Not ignored, which is what the rest of this plan would otherwise do and which
deadlocks the conversation.

Walk it through. The outstation sends fragment *n*, the master confirms it, the
outstation retires those events and sends *n+1*. If *n+1* is lost, the master
repeats its confirmation of *n* -- and `_confirm` matches on the *outstanding*
sequence, which is now *n+1*. The repeat matches nothing, is logged and dropped,
and the outstation sends nothing. The master waits for a fragment that will never
come and the outstation waits for a confirmation that will never arrive. Neither
side is wrong and the exchange is over.

So the outstation remembers one sequence number beyond the current one: the
fragment just confirmed. A confirmation naming it replays the fragment already
built and outstanding, byte for byte, and retires nothing -- the events it named
were retired when it was first confirmed. A confirmation naming anything else
still retires nothing, as **D18** has it.

This is **D25** one layer up: the same choice between replaying what was sent and
rebuilding it, answered the same way and for the same reason. Rebuilding would
send a different set of events under a sequence the master is about to confirm.

One sequence of history is enough because there is only ever one fragment
outstanding. A master that loses two in a row has lost the conversation, and
**D30** lets its next request start a new one.

**D35 -- A provider may say where its objects end, and static data then splits
too.** `ReadProvider` keeps `read`, which returns octets and is the contract.
Beside it, a provider may implement `read_blocks`, returning the object blocks it
would have concatenated. A provider that does gets its static data split across
fragments at a block boundary; a provider that does not is answered under **D31**.

Optional rather than replacing `read`, and that is the whole of the decision.
Replacing it would be a breaking change before 1.0 for every caller, including
the ones whose point maps fit a fragment and who would gain nothing. It would
also have this library holding a list of the caller's objects rather than a body
it forwards, which is closer to knowing the point map than **D6** wants to be.

The limit it lifts is not hypothetical. A class 0 poll over roughly 290 analog
points already exceeds the 2,048 octets a master typically advertises, which is
a mid-sized site rather than a large one. **D31** alone would refuse those reads,
and an outstation that cannot answer an integrity poll is not much of an
outstation.

A block is still not split. The unit is the object block the provider hands over,
so a single block larger than a fragment is refused as **D31** refuses a body --
this moves the boundary from the whole body to one block of it, and does not
remove it.

## Work

### 1. Saying there is more

Two pieces of state, and conflating them is the mistake this section exists to
avoid. `_Outstanding` is **per fragment**: what was sent, for `drop` and for
replay, replaced each time a fragment goes out. A conversation needs state that
outlives it -- the provider's body for the last fragment (**D33**), the fragment
count for **D32**'s bound, the sequence just confirmed for **D34**, and the
classes the read named, since a continuation has to peek the same ones.

That belongs beside `_Outstanding` rather than inside it, or the body is
discarded by the very replacement that sends the fragment after it.

Neither records the events that did not fit (**D29**).

`FIN` goes on the fragment that finishes the response, which is not always the
one that empties the buffer. For an events-only read it is the fragment after
which the named classes hold nothing more, or the one **D32**'s bound stops at.
For a read that also named class 0 it is the fragment carrying the provider's
body -- and if that body does not fit beside the last events, it takes a fragment
of its own rather than displacing them. A response whose final fragment is
nothing but static data is correct; one that drops events to make room for it is
not.

**Acceptance:** a buffer larger than one fragment produces a first fragment with
`FIR` set, `FIN` clear and `CON` set; the events behind it are still in the
buffer and are *not* referenced by `_Outstanding`; a read whose events fit in one
fragment is unchanged, `FIN` set and nothing outstanding beyond the confirmation
it already asked for.

And the distinction **D29** rests on, which is only visible from outside as a
count: the provider is called **once per response**, not once per fragment. A
test that counts its calls is what stops a later simplification from re-reading
it and reintroducing the fit problem that decided **D33**.

### 2. Continuing on confirmation

`_confirm` retires what the fragment carried, then peeks the buffer again and
returns the next fragment rather than `b""`, under the next application sequence
-- `(sequence + 1) % SEQUENCE_MODULUS`, so a conversation crossing fifteen
continues at zero rather than storing a sixteen that no wire confirmation can
match.

**Acceptance:** confirming the first fragment yields the second; its sequence is
one past the first's; the last carries `FIN`; confirming the last yields `b""`.
A master that confirms only the first keeps the rest buffered.

And the two the sequence arithmetic decides: a response that begins at sequence
15 continues at 0, and the confirmation naming 0 is matched rather than ignored;
a response long enough to wrap twice is answered throughout.

An event evicted between two fragments is not sent in the second, and one
recorded between them is (**D29**). Both are worth a test, because the first is a
correctness claim and the second is the reason **D32** exists.

### 3. Abandonment

Per **D30**. A read, a control, anything.

**Acceptance:** a read arriving after the first fragment is answered as a read,
and the unsent remainder is back in the buffer rather than retired; a
`connection_reset` mid-sequence leaves every unconfirmed event buffered.

### 4. Retransmission across fragments

**D25** replays a repeated request octet for octet; **D34** replays the
outstanding fragment for a confirmation naming the one before it.

**Acceptance:** a confirmation repeated after its continuation was lost yields
that continuation again, byte for byte, and retires nothing a second time; the
conversation then carries on from there rather than starting over. A
confirmation naming a sequence that is neither the outstanding one nor the one
before it is still ignored.

And the case that says the history is bounded: two confirmations back is not
replayed, and the master's next request starts a new conversation (**D30**).

### 5. Mixed responses

Per **D33**. A read naming class 0 and an event class, over a buffer that does
not fit.

**Acceptance:** the static body arrives in the fragment carrying `FIN` and in no
other; every event of the response precedes it; the body is the one read when the
response began, not one read per fragment.

And the case the fit argument is about: a body that does not fit beside the last
events takes a fragment of its own, with the events before it intact rather than
trimmed to make room.

### 5b. A provider that says where its objects end -- landed

Per **D35**. `ReadProvider` gains an optional `read_blocks`; a provider that
implements it has its static data split at a block boundary, and one that does
not is answered under **D31**.

Sequenced after the rest because everything before it works without it, and
because the interesting cases are the ones where the two paths must agree: a
provider implementing both must be answered identically when its body fits one
fragment.

**Acceptance:** a provider with only `read` is unchanged in every respect, and a
body of its that will not fit is still refused; a provider with `read_blocks` has
the same body delivered across fragments instead; a single block larger than a
fragment is refused as a whole body would be, since this moves the boundary
rather than removing it; and the two providers, given the same objects and a
ceiling that fits them, produce the same octets.

Two things came out of building it. Blocks are taken in the provider's order and
the first that does not fit ends the fragment -- a smaller one behind it does not
jump the queue, because a master applies a fragment in order and the answer is
the provider's rather than a packing problem. And a confirmation had to stop
requiring event buffers to exist: static data spread over fragments is the first
multi-fragment response that can happen with no events configured at all, and
`_confirm` returned early without them, leaving such a response stuck after its
first fragment.

### 6. Interoperability

Both peer masters should read a buffer that does not fit one fragment and
reassemble it. This is the assertion that says the sequencing is right, because
neither master shares any code with this one.

### 7. Documentation

D28 onwards into `DESIGN.md`; **D27**'s "cap rather than split" paragraph
rewritten; the README status line, which this plan's landing makes wrong again;
`CHANGELOG.md`.

## Open

- **Settled: the bound is sixteen fragments**, a count rather than an octet
  budget or a deadline. See **D32** for why.
- **Settled: `ReadProvider` gains an optional block method** rather than changing
  the one it has. See **D35**.
- **Settled: a repeated confirmation.** Listed here because it was the question
  this plan opened with and because leaving it open was not safe: **D28** and
  **D29** as first written deadlock when a continuation is lost. **D34** answers
  it -- one sequence of history, replaying the outstanding fragment.

- **Whether the first fragment should be smaller than the rest.** Some masters
  size their first receive differently. Probably not, but it is the kind of thing
  the standard settles and this plan cannot.
