# Changelog

Notable changes to this project, newest first. Versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html): while the major
version is `0`, a minor bump may carry a breaking change and the release note
says so explicitly.

## [Unreleased]

Nothing yet.

## [0.2.0] - 2026-10-05

The IEEE 1815.2 DER outstation. A builder assembles one from the profile's point tables
and a binding to the device, and generates its Device Profile document. With it come
unsolicited responses, a read-only role, a master that is not known in advance, event
classes and deadbands set as data, and a report of how much of the profile is served. The
DNP3 IED certification procedures and the DER profile test procedure run in CI, and the
unit suite also runs on 32-bit ARM.

This release changes answers a master can see, and the entries under Changed say what to
do about each: `DELAY_MEASURE` is answered where it was refused (#51); several refusals
carry a more specific indication (#54); the inputs of a disabled function are sent without
`ONLINE` (#56); events stamped before the time is written carry relative time, and a
malformed fragment is discarded where it was answered (#57); and the input mirroring an
output reports the binding's `status` reader when there is one (#64).

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

- **The IEEE 1815.2-2025 DER profile's point tables can be read into a machine-readable form (#46).** `scripts/extract_profile.py` turns the standard's Profile Companion Data Point Tables, which IEEE distributes without charge alongside the standard, into `conformance/ieee-1815-2-2025.json`, and `tests/test_profile_tables.py` holds that file to the properties a loader relies on. The file itself is not in the repository: IEEE's download terms forbid redistributing the workbook or significant portions of it in any form, so it and the workbook are ignored, anyone with the workbook regenerates the file in one command, and the tests skip where it is absent. `conformance/README.md` says where to get the workbook, what the file keeps and drops, and the three places the workbook disagrees with itself.

- **DNP3 Device Profile schema documentation.** `schema/` records the IEEE Std
  1815-2012 section 14.8 XML Device Profile: the artifact set, the two schema
  versions and their easily-confused namespaces, where to obtain the files, and how
  to render an instance document. The DNP Users Group schema and stylesheet are
  copyright-reserved with no redistribution grant, so `.gitignore` now blocks them
  by name (#47).

- **Every tagged release now carries a software bill of materials, in CycloneDX 1.6 and SPDX 2.3, attached as release assets (#50).** The documents name each dependency with its version, PURL and license, so a consumer can run a vulnerability scan against the exact set resolved when this release was built instead of re-resolving the declared ranges and hoping the answer matches. The release job cross-checks the tag against the version in `pyproject.toml`, so a mismatch fails the build rather than publishing a document labeled for a release it does not describe.

- **An IEEE 1815.2 DER outstation that runs from one command (#51).** `py1815-der run` serves
  a simulated DER over the profile's own point map, natively or from the repository's
  `Dockerfile`, and `py1815-der poll` asks a running outstation for everything once. The
  profile's point tables are IEEE's and are not redistributable, so they are not in the
  package or the image: `py1815-der tables fetch` downloads them from IEEE to the machine it
  runs on. Behind the command is `py1815.profile`, which loads the tables, resolves block
  relative indices for a DER of stated composition, and builds an outstation from a
  `Binding` of callables in engineering units. Scaling, quality flags, class 0 membership,
  events, control checks and counter freezes are the builder's; a point the profile makes
  mandatory and the caller left unbound is an error at build time, and an unbound optional
  point is absent instead of zero. The workbook is read with the standard library, so the
  package still has no runtime dependencies.

- **An outstation writes its own DNP3 Device Profile document (#53).** `py1815-der profile`,
  or `device_profile.build(outstation, session)`, produces the XML Device Profile in schema
  version 2.12.00: the point lists with each point's class, range, scaling and units, the
  configuration, and the implementation table. It is read from the outstation and from the
  new `Session.facts`, so the addresses, fragment sizes, timeouts and the objects and function
  codes listed are the ones that session answers; the tests check the table against the
  session in both directions. Figures that need measuring and a conformance test result are
  left unstated. The schema is the DNP Users Group's and is not shipped: `--validate` checks
  the document against a copy you hold.

- **The DNP3 IED certification procedures run in CI (#54).** `tests/test_ied_*.py` carries
  out the DNP Users Group's certification procedure for a Subset Level 2 outstation,
  version 3.1, with each test named for the section it performs and a catalog that lists
  every section as tested or not applicable with its reason. To support it:
  `DerOutstation(level2=True)` answers as Level 2 and nothing more, `Session` takes a
  `restart_handler` for cold restart and a `confirm_timeout`, broadcast requests are acted
  on and reported in `IIN1.0`, and `OutstationServer(broadcast_datagrams=True)` accepts a
  broadcast sent as a datagram. This is a self-assessment and not a certification.

- **EPRI's test procedure for the DER profile runs in CI, and the simulated DER follows
  curves (#56).** `tests/test_epri_der_procedures.py` carries out the procedures of EPRI
  report 3002016144 against the simulated DER, with the point pairings read from the
  tables. To support it: `py1815.profile.curves.CurveStore` holds the generic curves of
  clause 6.1.3 with their selector, referenced-indicator, locking and curve-type rules;
  the simulated DER gains volt-var and volt-watt, which follow a curve of voltage; and a
  start or a stop now takes a moment, so a master sees the DER starting or stopping.

- **LAN time synchronization, relative-time events and disabling function codes (#57).**
  The session answers a request to record the current time followed by a write of the
  last recorded time (function code 24 and group 50 variation 3). Binary events can be
  read with relative time (group 2 variation 3), behind a common time of occurrence.
  `Session(disabled_functions=[...])` turns function codes off by configuration, and the
  device profile leaves them out. Tests now cover the DNP Users Group's technical
  bulletins and application notes one document at a time, with a catalog of which apply.

- **A static group may be read by index (#59).** A master that names the points it wants one
  at a time, with qualifier `0x17` or `0x28`, is answered with those objects behind their
  indices, in the order asked and the qualifier asked. The profile outstation used to refuse
  the request as an unknown object. An index that is not a served point, or that names
  a point with nothing yet to report, refuses the header with `PARAM_ERROR`. The device profile document lists the two qualifiers on every static
  read row.

- **A session can serve a master it was not configured for (#61).**
  `Session(master_address=None)` takes whichever address speaks first on a connection as the
  master and replies to it. A second address on the same connection is dropped, and a new
  connection starts again. `py1815-der run` and `profile` take `--any-master`, and the device
  profile document reports that source addresses are not validated. An address is not
  authorization: without transport security, any peer that can reach the listener can read
  from such an outstation, and command it if controls are bound.

- **The unit suite runs on 32-bit ARM in CI, and the memory a full event buffer costs is
  stated (#62).** The library is meant to run in a container on small ARM controllers, and
  nothing had been exercised where a native integer is 32 bits. A `test-arm32` job now runs
  the whole suite on Python 3.12 for `linux/arm/v7` under emulation, and `image-arm` builds
  the Docker image for `linux/arm64` and `linux/arm/v7`. The first 32-bit run passed every
  test, so the library itself is unchanged. `scripts/measure_event_memory.py` fills the
  event buffers and reports what that allocated, and `docs/der.md` gives the measured cost
  at the default `event_capacity` and how to size it down.

- **A built DER outstation reports how much of the profile it serves (#63).**
  `DerOutstation.coverage()` returns an entry for every point of the resolved map: bound,
  served without a binding (mirrored from a bound output, derived as a supports input, or
  fixed by the tables) or absent, with mandatory points told apart from optional ones and
  the quality each served point had when the report was made. `conformant` is the test
  `strict` applies, `changed_since` compares two reports, and the text rendering has a line
  per point. `py1815-der points --coverage` prints it for the simulated DER. Nothing a
  master is answered with changes.

- **An outstation can be read-only, and an output's mirror reports what was applied (#64).**
  `DerOutstation(read_only=True)` refuses every control on a bound output with
  `NOT_AUTHORIZED`, or a status named in `read_only_status`, and never calls the binding;
  reads, freezes and the time write are unaffected, and `read_only` may be changed while the
  outstation runs: a change forgets the writes already accepted, an operate arriving after it
  became read-only is refused with the same status even when its select came first, and
  giving control back withdraws any select granted before. `Session.abandon_select()` is new,
  for a provider whose ability to command changes after a select. The device profile document
  lists no control requests for it.

- **A deployment sets event classes and deadbands as data, with an event policy (#65).**
  `DerOutstation` takes `event_policy`: an `EventPolicy`, or the plain mapping
  `EventPolicy.from_mapping` makes one from, holding a rule for each kind of point and
  exceptions for points named one at a time. A rule sets the class (1, 2 or 3), turns events
  off while leaving the point in class 0, and for an analog input gives a deadband in
  engineering units, which the point's multiplier converts. A point's own rule outranks its
  kind's, which outranks the tables; `deadband=` on `Binding.read` works as before, in
  transmitted units, and sits between the two. A counter's rule governs the event each
  freeze logs. A policy naming a point the map does not hold, a class outside 1 to 3, a
  negative deadband, or a deadband on anything but an analog input stops the build.
  `outstation.event_class(kind, index)` and `outstation.deadband(index)` say what is in
  force. The library reads no policy file: the mapping is what JSON or YAML loads to, and
  loading it is the caller's. With no policy, nothing changes on the wire.

- **Unsolicited responses, off unless a session is built with them (#67).**
  `Session(unsolicited=True)` announces a restart with a null unsolicited response,
  retried until it is confirmed, takes `ENABLE_UNSOLICITED` and `DISABLE_UNSOLICITED` for
  classes 1 to 3, and reports the events of an enabled class in unsolicited responses of
  their own sequence series. Events leave the buffers only when the matching confirmation
  arrives; an unconfirmed response is sent again every `unsolicited_confirm_timeout`
  (five seconds), `unsolicited_retries` times or without limit (the default), and when
  the retries run out the events stay buffered for a poll. A read arriving while one is
  unconfirmed is held until the confirmation or the timeout, and nothing unsolicited is
  sent while a solicited response waits for its own confirmation. The session still does
  no I/O: `Session.initiate()` returns what is due and `Session.initiate_after()` says
  when to ask again, and `OutstationServer` drives both, with `notify()` to report a new
  event at once and `unsolicited_interval` as the fallback. `DerOutstation.session()`
  passes the option through and `py1815-der run --unsolicited` serves the simulated DER
  with it on. With it off nothing changes on the wire; the Device Profile document now
  states unsolicited reporting as supported and configurable, currently off, where it
  said not supported. D69 to D71 record the decisions.

- **A session that takes any master sends it unsolicited responses (#68).** A session built
  with `master_address=None` and `unsolicited=True` accepted a master's `ENABLE_UNSOLICITED`
  and then never reported, because unsolicited responses went to the configured master and
  there was none. They now go to the master being served. Nothing is sent until a master
  has spoken on the connection, the restart is announced after its first request is
  answered, and reporting stops when the connection ends. What a master enabled stands when
  the same address is first to speak on the next connection; a different address starts
  with every class disabled, so no master is sent what another enabled.
  `py1815-der run --any-master --unsolicited` serves the simulated DER this way. A session
  with a configured master behaves as before. D72 records the decision.

### Changed

- **Changelog entries are now files in `changelog.d/` rather than edits to `CHANGELOG.md` (#43).** Two pull requests adding entries used to insert at the same line under `[Unreleased]`, so they conflicted on every pair even though the entries were independent and the resolution was always "keep both". Each entry is its own file now, so there is no shared hunk to conflict on.

  `changelog.d/README.md` has the naming rules and the reasoning. A release folds the pending fragments in with `python scripts/build_changelog.py --release X.Y.Z`, which also empties `[Unreleased]` and names the fragments it consumed so they can be deleted in the same commit.

- **The implementations this library is tested against are named and credited where the
  testing is described (#48).** The README, the testing page and the interoperability
  workflow name Step Function I/O's `dnp3` crate and opendnp3 and link to them, instead of
  calling them a Rust master and a C++ master. The `dnp3` crate's license is linked where it
  was paraphrased, with a pointer to Step Function I/O for commercial licensing. opendnp3 is
  credited for the default select timeout and the `TOO_MANY_OPS` name.

- **The session answers what the IEEE 1815.2 implementation table requires (#51).** A time
  write (group 50) reaches a `time_sink` and clears the need-time indication, which is set
  with `need_time`; `DELAY_MEASURE` is answered. Counters, frozen counters and frozen counter
  events are encoded (groups 20, 21 and 23), and the freeze functions are served when the
  session is given a `FreezeProvider`; without one they are refused exactly as before. Binary,
  analog and frozen counter events can be read by their own group as well as by class.
  `Session(analog_event_variation=...)` and `EventBuffers(analog_latest_only=True)` select the
  variation and reporting mode the profile fixes for analog events. Every default is the
  previous behavior, with one exception a master can see: `DELAY_MEASURE` used to be refused
  as unsupported and is now answered.

- **Several answers are more specific than they were (#54).** A control sent to an
  outstation with no outputs is refused with `IIN2.1` (object unknown) where it used to be
  `IIN2.0`. A read whose range names no point, or runs past the last one, is refused with
  `IIN2.2`, which a provider signals by raising the new `ParameterError`. A control naming
  an uninstalled point sets `IIN2.2` beside its status. Events are sent in the order they
  happened, across classes and types, and a late confirmation (after `confirm_timeout`,
  ten seconds by default) no longer retires anything. Event groups can be read by name in
  each variation the outstation serves. Masters that matched on the old indications need
  updating.

- **The inputs of a disabled function are sent without the ONLINE flag (#56).** IEEE
  1815.2 clause 6.1.1 requires it. The value is still reported; the supports input and
  the input reporting whether the function is enabled stay ONLINE. A master that discards
  values not flagged ONLINE will stop seeing a function's setting readbacks until the
  function is enabled: pass `disabled_offline=False` to `DerOutstation` for the old
  behavior. `Quality` gains `OFFLINE`.

- **Events stamped before the time is written are sent with relative time (#57).** A
  session that asks for the time marks its binary events until a master writes it, and
  sends them behind an unsynchronized common time of occurrence where it used to send an
  absolute time from a clock nobody had set. A fragment that is not a whole request (too
  short, not both first and final, or carrying the unsolicited bit) is now discarded
  where it used to be answered, as is a link frame whose length contradicts its function.
  A read or write naming no object is a parameter error. `Session` refuses reserved
  addresses, and `need_time=True` with no `time_sink`.

- **The input that mirrors an output reports the binding's `status` reader when there is one
  (#64).** It used to report the last write this outstation accepted, so a device that applied
  a different value than the one written showed the applied value in the output status and
  the request in the mirroring input. Both now report what the device says, and the input
  raises an event when that value changes with no command behind it. Whether a function is
  enabled, which decides if its inputs are sent as in effect, follows the enable output's
  `status` reader in the same way: a function the device already had enabled is in effect
  before anything is written, and one the device turned off by itself is not. A reader that
  fails leaves the function treated as disabled. A binding with no `status` reader behaves
  as before.

- **The Device Profile document lists the event class and deadband in force (#65).** A
  point's `changeEventClass`, and a counter's `frozenCounterEventClass`, are read from the
  outstation and so follow an event policy, where they were the tables' default. Each analog
  input that reports events now also lists its deadband, in transmitted units, under
  `dnpData/deadband`; a document generated for an outstation with no policy gains those
  entries and is otherwise unchanged.

### Fixed

- `FunctionCode` was missing function code 31, `ACTIVATE_CONFIG`. The reply on
  the wire was already correct, because a code that is not recognized and one
  that is recognized but unimplemented are both refused with IIN2.0; what was
  wrong is that the enum claims to name every code the standard assigns, and
  did not. The refusal now logs which of the two it was, naming the function
  when the standard assigns it and the raw code when it does not, which is the
  distinction the enum exists to make and which nothing surfaced before.

- **A release no longer carries the "Nothing yet." placeholder into the new section (#49).** `build_changelog.py --release` folded the whole `[Unreleased]` body, placeholder included, so every release began with the placeholder and left `[Unreleased]` bare. The placeholder is stripped from what is folded and written back under `[Unreleased]`, and the release test now pins where it ends up.

- **A control is echoed with the qualifier it arrived under (#51).** The echo of a select,
  operate or direct operate was rebuilt with the narrowest qualifier that fit, so a request
  sent with sixteen-bit indices came back with eight-bit ones whenever the indices were small.
  A master that checks the echo against what it sent then reports the control as failed even
  though it executed; opendnp3, which sends every control with sixteen-bit indices, is one.
  `Control` now carries the request's qualifier and the echo reproduces it, header by header.

- **Everything placed in `schema/` is ignored, not only the names one release shipped (#52).**
  The DNP Users Group package gained an examples archive, release notes and a specification
  in another format, none of which the list of names covered, so a broad `git add` would have
  staged them. The directory is now ignored apart from its README.

- **A retried control or freeze is no longer carried out twice (#54).** A request that
  repeats the last operate, direct operate or freeze octet for octet is answered again
  from the first answer. Also fixed: the data link layer acknowledged confirmed user data
  before a link reset and passed a repeated frame up a second time; an operate was
  accepted against a select made with a different qualifier; a retried select restarted
  the select timer; a control arriving with a non-zero status was executed; a class
  indication stayed set for events the same response was carrying; and a read of a point
  type the outstation has none of returned an empty answer with no error.

- **The simulated DER reported its phase B voltage angle outside the range the tables
  give (#56).** It was sent as -120 degrees with the over-range flag set; it is now 240.

- **A repeated transport segment no longer abandons the fragment (#57).** A segment
  arriving twice, octet for octet, is dropped and the series continues, as the updated
  reception table has it. An empty fragment is no longer handed to the application
  layer. The device profile now lists the format error status the session answers with.

- **An analog output whose status has no number is sent flagged, instead of failing the read
  (#63).** A `status` reader returning NaN made the read of that output raise. It is now sent
  as zero with `ONLINE` clear and a reference error, as an analog input with no number already
  was.

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
