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
that only wants the standard map, against a library that cannot be shared because the IEEE
1815.2 tables are distributed to DNP Users Group members rather than published.

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

**D9 -- What is refused is refused out loud.** A control function receives a response carrying
`FUNC_NOT_SUPPORTED` rather than silence, because a master that times out learns nothing and
retries.

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
it, because a reservation held for an operate on a socket that died must not be honoured over the
connection that replaced it.

Any request other than the operate that spends it also ends the exchange it belongs to -- a read,
an unreadable control, a direct operate, or a select refused before it reached the provider. Two
mechanisms enforce that rather than one: the operate has to arrive on the sequence after the
select, *and* an intervening request clears the selection. Either alone leaves a gap. The sequence
rule binds only a master that numbers its requests in order, and a master that reuses a number
walks through it to an operate the outstation never granted; the clearing rule covers requests a
master sends under any numbering at all.

**D13 -- The control point map belongs to the caller, as with reads.** Under D6 this library does
not know that index 7 is a power setpoint, and it does not scale. A control arrives at the
provider as an index, a decoded object and the function that carried it.

**D14 -- A complete control is answered per object, echoed in request order.** A request naming
four points where one is unsupported returns four objects with three successes and one
`NOT_SUPPORTED`, not a single refusal for the fragment. The echo is of the request rather than a
tidier version of it: the objects come back as they arrived, and two headers naming the same group
are answered with two headers.

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
resend what it sent -- only holds while there is an operate the select could authorise. Where
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
implementation reproduces octet for octet, a hand-derived populated frame, and the CRC catalogue
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

## Roadmap

- ~~The TCP and TLS listener, with D7 and D8.~~ Landed.
- ~~Controls: SELECT, OPERATE, DIRECT OPERATE and DIRECT OPERATE NO ACK, with D10 through D16.~~
  Landed. The outstation commands as well as reports; output status readback is served by the
  caller's provider, per D6.
- Events, classes 1 through 3, deadbands and unsolicited responses. The interoperability job
  shows why this is not optional in practice: a real master's startup sends `DISABLE_UNSOLICITED`
  and then `ENABLE_UNSOLICITED`, and this outstation refuses both. It proceeds to read normally,
  so the refusal is survivable, but it is two warnings in an operator's log on every connection.
  `DISABLE_UNSOLICITED` is worth a second look on its own: an outstation that sends none is
  already in the state the master is asking for, so refusing the request answers a question it
  did not ask.
- The point-map loader and a published table for the predecessor DER profile.
- Conformance testing.

## Open

- Contribution terms: whether to require a DCO, a CLA, or neither.
- Whether the AN2018-001-derived point map ships with the first release. It carries an
  attribution obligation from the reference implementation it is derived from, which needs
  confirming before publication rather than after.
