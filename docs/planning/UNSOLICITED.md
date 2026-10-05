# Plan: unsolicited responses

Events are buffered, read by class, confirmed and retired ([EVENTS.md](EVENTS.md)), and
a response too large for one fragment is a conversation ([FRAGMENTATION.md](FRAGMENTATION.md)).
All of that answers a master that asks. This is the other half: an outstation that
reports without being asked, as the standard's unsolicited responses have it, and the
roadmap entry in [DESIGN.md](../DESIGN.md) that the event plan left for its own plan.

## Scope

**Built.** Off unless a session is built with `unsolicited=True`, and off changes no
answer. On:

- `ENABLE_UNSOLICITED` and `DISABLE_UNSOLICITED` by class (group 60 variations 2 to 4,
  qualifier 0x06), answered with a null response; anything else refused out loud and
  applied not at all.
- The initial null response after a restart, retried without limit until confirmed.
- Events of the enabled classes in unsolicited responses, one fragment each, built by
  the code that answers a class poll, retired by the matching confirmation.
- Retries at a configurable timeout, a configurable number of them or without limit,
  and a stated policy for when they run out.
- The interleaving with solicited traffic the standard's rules describe: a read held
  behind an unsolicited response, everything else answered at once, nothing unsolicited
  while a solicited response waits for its confirmation.
- A second entry point on the session, `initiate()` and `initiate_after()`, so the
  session still does no I/O, and `OutstationServer` driving it.
- The device profile document stating the configuration, the certification procedures
  of section 8.11 carried out, and TB2015-002a and TB2016-004 acted on.

**Not in scope, and recorded so it is not assumed:** see *What is not done* below.

## The state machine

The session holds two exchanges that can each be waiting at once, as the standard's
outstation state table has it: a solicited response awaiting its confirmation
(`_outstanding`, as before) and an unsolicited response awaiting its own
(`_awaited`). Beside them: the classes enabled, whether the restart has been announced,
the next unsolicited sequence number, a read held back, and whether reporting is resting
after its retries ran out.

In words, for a session built with them on:

- **Idle, restart not yet announced.** `initiate()` sends the null response and waits
  for it. A confirmation carrying the unsolicited bit and its sequence ends the wait and
  marks the restart announced. A timeout sends it again, under the same sequence if
  nothing in it changed and the next if something did (the restart indication being
  cleared, say).
- **Idle, announced.** When an enabled class holds events, nothing solicited is waiting,
  and reporting is not resting, `initiate()` sends an unsolicited response carrying them
  and waits for it. Otherwise it sends nothing.
- **Waiting for an unsolicited confirmation.** A matching confirmation retires its
  events, clears the overflow it reported, and answers a held read if there is one. A
  read is held, replacing any read held before it. Any other request is answered at once
  and discards a held read. At the timeout, a held read is answered and the series ends;
  without one, the response is rebuilt and sent again, unless its retries are spent, in
  which case the series ends and reporting rests.
- **Resting.** Nothing is sent until an event is recorded, the master sends a request, a
  connection is made, or `unsolicited_resume` seconds pass. Then it is idle again.
- **A solicited response waiting.** Nothing unsolicited is sent, first transmission or
  retry, until it is confirmed or its `confirm_timeout` passes. If it timed out it is
  given up on when the unsolicited response goes, so a late confirmation of it retires
  nothing.

A restart clears the enabled classes and the announcement. A new connection forgets the
response in flight and the read held behind it, ends a rest, and keeps the rest.

## Decisions

Continuing from D63 in [DESIGN.md](../DESIGN.md); D64 to D68 are taken by other work.

- **D69**, off unless asked for, enabled by class, and the second entry point.
- **D70**, one fragment in a series of its own, rebuilt for each retry, and what happens
  when the retries run out.
- **D71**, the interleaving with solicited traffic, and the timer that only reports.

They are argued in DESIGN.md and not repeated here.

## The standard

Written against IEEE Std 1815-2012 clauses 4.4.13, 4.6 and 5.1.1.1, the outstation
fragment state table of clause 6, TB2015-002a, TB2016-004, AN2015-001 and section 8.11
of the DNP Users Group's IED certification procedures (version 3.1 revision 1). Where
they leave a choice, the choice is a decision above. Where they disagree, the later text
was followed and the disagreement is recorded:

- Clause 4.4.13 says a disable request cancels any pending expectation of confirmation
  for an unsolicited response already sent; rule 15 of clause 4.6.6, as TB2015-002a
  rewrote it, says to wait for that confirmation or its timeout. Rule 15 is followed:
  the response sent is still confirmed in the ordinary way, and what replaces it at a
  timeout is built from the classes still enabled, which after a full disable is
  nothing.
- Section 8.11.2.1 issues a class 0 read while the initial null response is unconfirmed
  and checks it is answered. TB2015-002a has that read held until the confirmation or
  the timeout. It is held, and answered within the step's wait.
- Section 8.11.2.6, steps 14 and 15, expect a disable request refused when unsolicited
  responses are configured off. It is agreed to, as D21 decided; the test catalog lists
  this as a departure.

## What is not done

- **Interoperability.** The independent masters in `interop/` run against an outstation
  built without unsolicited responses, as before. Running one against an outstation that
  sends them, and having it confirm, is the next thing worth doing; it is the only check
  here that would come from an implementation other than this one.
- **Enabling by point.** The standard makes it optional. Only classes are accepted.
- **A broadcast enable or disable** is noted and not acted on, the default AN2015-001
  recommends.
- **Hold time and event-count triggers** (the device profile's section 1.9). An event is
  reported at the next `initiate()`, which the listener makes promptly; the profile
  states nothing for those settings.
- **UDP.** Unsolicited responses go over the TCP connection the master opened. The
  listener does not open connections of its own, which the standard allows an
  outstation not to.

## Sequencing

Built in one change, in this order: enabling and disabling with the off configuration
pinned first; the null response and the sequence series; events, confirmation and
retries; the interleaving; the listener; then the device profile, the certification
procedures and the bulletins. The interoperability run follows separately.
