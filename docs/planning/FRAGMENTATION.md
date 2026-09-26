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

**D29 -- Each fragment is confirmed before the next is built.** Not built ahead
and queued. Two reasons, and the second is the one that matters:

- The buffer can change between fragments. Events recorded meanwhile belong to a
  later response, and events *evicted* meanwhile must not be sent from a queue
  that outlived them.
- A master that stops confirming has to leave the outstation holding one
  fragment's worth of selection, not the whole buffer. Queuing ahead reinstates
  exactly the unbounded retention **D18** and **D27** were written to avoid.

**D30 -- A request arriving mid-sequence abandons the rest.** Under **D19** a new
request supersedes what was outstanding, and a partly-sent response is no
different: the master has moved on, and the events it did not take stay
buffered for the read it just sent. The fragments already confirmed stay
retired, because they were received.

**D31 -- Static data is not split, and a provider body that does not fit is
still refused.** The read provider returns opaque octets and this library cannot
tell where one object inside them ends, so there is no honest place to cut.
Fragmentation therefore lets a *large buffer of events* reach a master; it does
not let a large static read do so.

That is a real limit rather than a deferral, and the README should say so. See
the open question below on whether `ReadProvider` should change shape.

## Work

### 1. Carrying the rest

`_Outstanding` grows the events that did not fit, and `_handle_read` stops
discarding them. `FIN` is set when nothing remains.

**Acceptance:** a buffer larger than one fragment produces a first fragment with
`FIR` set, `FIN` clear and `CON` set; the events behind it are recorded as
outstanding and are still in the buffer.

### 2. Continuing on confirmation

`_confirm` retires what the fragment carried, and returns the next fragment
rather than `b""` when there is one, under the next application sequence.

**Acceptance:** confirming the first fragment yields the second; its sequence is
one past the first's; the last carries `FIN`; confirming the last yields `b""`.
A master that confirms only the first keeps the rest buffered.

### 3. Abandonment

Per **D30**. A read, a control, anything.

**Acceptance:** a read arriving after the first fragment is answered as a read,
and the unsent remainder is back in the buffer rather than retired; a
`connection_reset` mid-sequence leaves every unconfirmed event buffered.

### 4. Retransmission across fragments

**D25** replays a repeated request octet for octet. A repeated *confirmation*
is a different thing and needs settling -- see the open questions.

### 5. Interoperability

Both peer masters should read a buffer that does not fit one fragment and
reassemble it. This is the assertion that says the sequencing is right, because
neither master shares any code with this one.

### 6. Documentation

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
- **A bound on fragments per response.** A buffer of two hundred thousand events
  is a conversation of hundreds of round trips. The buffer bound is the operator's
  and probably enough, but an outstation that never finishes answering is worth
  a thought before it is one.
- **Whether the first fragment should be smaller than the rest.** Some masters
  size their first receive differently. Probably not, but it is the kind of thing
  the standard settles and this plan cannot.
