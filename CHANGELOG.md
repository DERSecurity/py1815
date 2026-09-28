# Changelog

Notable changes to this project, newest first. Versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html): while the major
version is `0`, a minor bump may carry a breaking change and the release note
says so explicitly.

Nothing has been released yet. Everything below is on `main` and unversioned.

## [Unreleased]

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
  response past it is discarded rather than merely long. Events are fitted to
  what is left after the provider's own objects, which are never trimmed because
  this library cannot tell where one of them ends; what does not fit stays
  buffered and the indication bits go on asking for it. A control request whose
  echo would not fit is refused *before* anything is dispatched, since a control
  that executes and cannot report is worse than one that never ran.

  The ceiling bounds the work too. A small response over a large buffer costs
  the response rather than the buffer.
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
