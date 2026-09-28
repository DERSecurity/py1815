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

**D29 -- Each fragment is built from the buffer as it then stands, and nothing
is carried between them.** Not built ahead and queued, and -- the part a first
draft of this plan got wrong -- not carried as a remainder either.

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

**D30 -- A request arriving mid-sequence ends the conversation.** Under **D19** a
new request supersedes what was outstanding, and a partly-sent response is no
different: the master has moved on, and the events it did not take stay buffered
for the read it just sent. The fragments already confirmed stay retired, because
they were received.

Under **D29** there is nothing to discard beyond the fact that more was coming,
since no remainder is held. That makes this decision cheap to implement and easy
to get wrong in the other direction -- forgetting to clear the flag would have
the next confirmation continue a response the master has already abandoned.

**D31 -- Static data is not split, and a provider body that does not fit is
still refused.** The read provider returns opaque octets and this library cannot
tell where one object inside them ends, so there is no honest place to cut.
Fragmentation therefore lets a *large buffer of events* reach a master; it does
not let a large static read do so.

That is a real limit rather than a deferral, and the README should say so. See
the open question below on whether `ReadProvider` should change shape.

**D32 -- A response is bounded in fragments, not only in octets.** One
conversation carries at most so many, and the last of them sets `FIN` whether or
not the buffer is empty -- after which the class indication bits go on asking,
which is **D27**'s cap reached later and with most of the buffer delivered.

A bound is needed because **D29** lets events recorded mid-conversation join it.
Without one, an outstation whose device polls faster than its master confirms
never sends `FIN`, and a master that is waiting for the end of a response is a
master that never issues another request. The number belongs here rather than
being borrowed; what it should be is open below.

**D33 -- Static data travels in the last fragment.** A read naming class 0 and
an event class is answered with the provider's body after every event, not
alongside the first of them.

This falls out of **D20** and is easy to get wrong: putting static data in the
first fragment -- which is what the current single-fragment code does, and what a
naive split would keep doing -- has the master apply it *before* the events in
the fragments that follow, so it ends up holding an event value older than the
reading the same response carried. The whole point of events-before-static is
that the static value wins.

The body is read once, when the first fragment is built, and held until the last.
A fresher body could be read per fragment, and is not, because a response that
reports two different values for one point over its own length is a worse answer
than one that is a moment old.

## Work

### 1. Saying there is more

`_Outstanding` records that the response is unfinished and holds the provider's
body for the last fragment (**D33**). It does *not* record the events that did
not fit (**D29**). `FIN` is set when the buffer has nothing more for the classes
the read named, or when **D32**'s bound is reached.

**Acceptance:** a buffer larger than one fragment produces a first fragment with
`FIR` set, `FIN` clear and `CON` set; the events behind it are still in the
buffer and are *not* referenced by `_Outstanding`; a read whose events fit in one
fragment is unchanged, `FIN` set and nothing outstanding beyond the confirmation
it already asked for.

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

**D25** replays a repeated request octet for octet. A repeated *confirmation*
is a different thing and needs settling -- see the open questions.

### 5. Mixed responses

Per **D33**. A read naming class 0 and an event class, over a buffer that does
not fit.

**Acceptance:** the static body arrives in the fragment carrying `FIN` and in no
other; every event of the response precedes it; the body is the one read when the
response began, not one read per fragment.

### 6. Interoperability

Both peer masters should read a buffer that does not fit one fragment and
reassemble it. This is the assertion that says the sequencing is right, because
neither master shares any code with this one.

### 7. Documentation

D28 onwards into `DESIGN.md`; **D27**'s "cap rather than split" paragraph
rewritten; the README status line, which this plan's landing makes wrong again;
`CHANGELOG.md`.

## Open

- **A repeated confirmation.** If the second fragment is lost, the master
  repeats its confirmation of the first. The outstation has already retired
  those events and moved on, so it cannot rebuild what it sent. Replaying the
  cached fragment is the obvious answer and needs the previous fragment kept for
  one more round. Whether that is one fragment of history or a sequence-keyed
  cache is the decision.
- **Whether `ReadProvider` should return blocks rather than octets.** It would
  let **D31** go away -- static data could split at an object boundary -- at the
  cost of a breaking API change and of this library knowing more about the
  caller's objects than **D6** wants it to. Worth answering explicitly rather
  than by omission.
- **What D32's bound should be.** That there is one is settled; the number is
  not. It has to be large enough that a full default buffer of a thousand events
  finishes in one conversation, and small enough that an outstation whose device
  polls faster than its master confirms still sends `FIN`. Whether it is a
  fragment count, a total octet budget, or a deadline is part of the question.
- **Whether the first fragment should be smaller than the rest.** Some masters
  size their first receive differently. Probably not, but it is the kind of thing
  the standard settles and this plan cannot.
