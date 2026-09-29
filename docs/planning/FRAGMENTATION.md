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

This plan's decisions are **D28 through D35**, and they live in
[DESIGN.md](../DESIGN.md) with the rest. They are not repeated here: a decision
recorded twice is a decision that will be amended once.

Four of them were not in this plan when it was written. **D32**'s bound and
**D35**'s optional provider method were its open questions, answered before the
implementation began. **D33** and **D34** came out of review -- where static data
travels, and what answers a master whose continuation was lost.

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

### 7. Documentation -- landed

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
