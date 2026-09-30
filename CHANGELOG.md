# Changelog

Notable changes to this project, newest first. Versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html): while the major
version is `0`, a minor bump may carry a breaking change and the release note
says so explicitly.

## [Unreleased]

### Added

- The normative tables of IEEE Std 1815-2012 are now checked against this
  package's own on every test run. `scripts/extract_conformance.py` reads the
  tables out of a local copy of the standard into
  `conformance/ieee-1815-2012.json`, and `tests/test_conformance.py` diffs the
  function codes, indication bits, qualifier codes and field widths against it.
  The standard is a paid document and is not in the repository;
  `conformance/README.md` covers what the checked-in tables hold and what they
  deliberately do not.
- The interoperability sweep is now checked for coverage against the function
  code table. Its cases are written out one per code, so a code nobody wrote a
  case for was simply not swept, and passed for want of anything to fail.

### Fixed

- `FunctionCode` was missing function code 31, `ACTIVATE_CONFIG`. The reply on
  the wire was already correct, because a code that is not recognized and one
  that is recognized but unimplemented are both refused with IIN2.0. What was
  wrong is that `FunctionCode` names every code so a log line can tell those two
  apart, and for 0x1F it could not.

## [0.1.0] - 2026-09-29

First release. The protocol stack, the listener, the event path and controls;
unsolicited responses and the point-map loader are not in it. The API is not
stable, and while the major version is `0` a minor bump may carry a breaking
change.

### Added

- **The protocol stack**: CRC-16/DNP, FT3 data link framing with a stream
  reader, transport segmentation and reassembly, the application layer's
  control octet, function codes, internal indications and object headers, and
  static binary and analog inputs with their quality flags. Each layer is
  testable without the ones above it, and the session does no I/O at all -- it
  takes the octets that arrived and returns the octets to send -- so behavior
  is pinned against literal frames rather than against a socket.
- **The listener**: TCP and TLS, with an explicit peer allow-list by subject
  name or certificate fingerprint. One master association at a time; admission
  is serialized, and a peer that fails authorization changes nothing about the
  association already established.
- **An interoperability suite of implementations that are not this one.** Four
  across three jobs, chosen so that no two are the same codebase in different
  clothes: a C++ master through its Python bindings, a Rust master by different
  authors that checks the quality octet and the object variation the C++
  bindings discard, and Wireshark and Suricata reading a capture of the whole
  function code sweep and verifying every checksum in it. The unit suite is
  this library marking its own homework; these jobs are the part that is not.
- **Event buffers for classes 1, 2 and 3**, with deadbands, overflow reporting
  and confirmation handling. A deadband is measured against the last value
  *reported*, not the previous reading, so a point drifting in steps smaller
  than the deadband is still eventually reported rather than never. A quality
  change generates an event whatever its magnitude, because a point that goes
  comm-lost holding the same number has changed in the way that matters most. A
  full buffer drops its oldest event and says so.
- **Event object encoding**: the timed and untimed variations of groups 2 and
  32, the six-octet timestamp, and index-prefixed event blocks. Events are not a
  range -- they are whichever points changed, in the order they changed -- so
  each carries its own index.
- **The event path: a master can now read what the buffers hold.** A read naming
  classes 1, 2 or 3 is answered from them, class 0 still reaches the read
  provider, and an integrity poll naming both gets one response with the events
  in front -- a master applies a fragment in order, so a static value written
  after the events that led to it leaves the point where it should end up.

  Events are not consumed by being read. They leave the buffer when the master
  confirms the response carrying them, so a response that never arrives has not
  taken the only copy with it, and a master that reads twice without confirming
  sees the same events twice. A confirmation retires exactly the events its
  sequence number covers; one naming any other sequence retires nothing. A
  request repeated under the same sequence is replayed octet for octet rather
  than rebuilt, so the confirmation that follows acknowledges what was actually
  sent.

  The class and overflow indication bits are derived from the buffers on every
  response rather than tracked beside them, so a bit cannot drift from what is
  waiting. Overflow is retired when the master acknowledges the read that
  reported it -- including a read that carries the bit and no events, which
  would otherwise be a report nothing could ever clear. Other responses report
  the overflow without asking to be confirmed, since a refusal or a write is not
  where an acknowledgement belongs and the next read is what retires it.
- **A ceiling on the size of a response, and on the work of building one.** A
  master sizes its receive buffer to the fragment size it advertises, so a
  response past it is discarded rather than merely long. A control request whose
  echo would not fit is refused *before* anything is dispatched, since a control
  that executes and cannot report is worse than one that never ran.

  The ceiling bounds the work too. A small response over a large buffer costs
  the response rather than the buffer.
- **An answer too large to send at once is a conversation.** The outstation
  sends what fits, the master confirms it, and the next fragment follows under
  the next sequence number until the last one says so. A confirmation is
  therefore the thing that draws out a continuation, which is the only case
  where this outstation answers something that is not a request.

  No list of unsent events is carried between the fragments. Each is built from
  the buffers as they then stand, so an event evicted while a master was slow is
  gone rather than sent from a list that outlived it, and one recorded meanwhile
  joins the answer rather than waiting for the next -- until the static data
  starts going out, after which the response takes no more events and they wait
  for the one after it.

  That needs a bound instead of a rule about which events belong where: a device
  that records faster than its master confirms would otherwise never be finished
  with, so a response carries at most sixteen fragments of events and the
  indication bits go on asking for the rest.

  A master that loses a fragment repeats the confirmation before it and is sent
  that fragment again. Without it the exchange stops dead -- the master waiting
  for something that will never arrive, the outstation for a confirmation that
  will never come.

  Static data travels at the end rather than being reserved for in every
  fragment, which would have held back a fragment's worth of readings for a body
  arriving several round trips later.
- **A provider may say where its own objects end.** `ReadProvider` keeps `read`,
  which answers in octets and stays the contract; beside it a provider may
  implement `read_blocks` and have its static data spread across the fragments
  of a response. Without it a point map too large for one fragment is refused,
  and a class 0 poll over roughly 290 analog points already exceeds what a
  master typically advertises. This library still divides nothing: the split
  points are the provider's, and a single block too large to send is refused as
  a whole body would be.
- **`DISABLE_UNSOLICITED` is answered rather than refused.** An outstation that
  sends no unsolicited responses is already in the state the request asks for,
  so refusing it answered a question the master did not ask. `ENABLE_UNSOLICITED`
  is still refused, which is the honest answer while nothing is sent.
- **Controls: this outstation commands as well as reports.** `SELECT`,
  `OPERATE`, `DIRECT_OPERATE` and `DIRECT_OPERATE NO ACK`, over control relay
  output blocks and analog output setpoints, with the output status points a
  master reads back afterwards. Given no control provider it still refuses every
  one, which is the truthful answer for an outstation that monitors rather than
  a degraded version of one that commands.

  Each control is answered on its own: a request naming four points where one is
  unsupported returns four objects with three successes and one refusal, rather
  than one verdict for the fragment. A request that cannot be parsed is refused
  whole instead, because a status has to be attached to an object and a
  truncated body may leave none.

  Select-before-operate holds the request it was given rather than the points
  that accepted it, since the operate a master sends next is the request it
  already sent. Matching compares the octets, which is exact and sidesteps the
  fact that two NaN setpoints never compare equal.

### Changed

- **`DIRECT_OPERATE NO ACK` executes rather than being dropped.** The standard
  defines it as function code 5 without a response, and it was previously
  discarded unexecuted -- correct for an outstation that could not command, and
  the worst available behavior for one that can, since a master would believe it
  had issued commands that were silently thrown away. It stays silent, including
  when its body does not parse: a master that asked for no response is not
  listening for a parse error either.
- **A displaced connection is now aborted; a connection closed at shutdown still
  closes gracefully.** The two callers want opposite things. A displaced peer is
  typically one whose socket died without a FIN, where a graceful close waits on
  TCP retransmission -- under the admission lock, which would let a dead master
  hold the association through a second door. A master connected at shutdown is
  usually healthy, and aborting would discard a response already queued.
- **Every no-response function code is met with silence before it is parsed**,
  as the standard requires.
- Quality masks are derived from their own enum per point type, rather than one
  mask built from the analog enum and adjusted by a binary bit. The binary
  chatter-filter bit was previously covered only because it shares `0x20` with
  an analog bit.

### Fixed

- An event encoder given a timestamp for an untimed variation discarded it
  silently, so the caller believed it had sent a time and the master received an
  event without one. Both directions are now refused.
- An exception during connection admission escaped without closing the arriving
  socket, leaving a live peer the listener reported as not connected.
