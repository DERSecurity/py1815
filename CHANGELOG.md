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

### Changed

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
