# Changelog

Notable changes to this project, newest first. Versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html): from 1.0.0, a
breaking change takes a new major version. Before 1.0.0, a minor bump could
carry a breaking change, and the release note says so explicitly.

## [Unreleased]

Nothing yet.

## [1.0.0] - 2026-11-12

The first stable release: from here on, a breaking change takes a new major version. It
adds Subset Levels 3 and 4. The outstation takes a subset level of 2, 3 or 4, and at Levels
3 and 4 serves what those levels add: reads by variation and by range, the time and the
internal indications, counter and frozen counter events, class assignment, floating-point
and time-stamped variations, analog input deadbands, binary and analog output events,
double-bit binary inputs and device attributes. The master is held to each outstation's
subset level and sends the Level 3 and Level 4 requests. CI runs dnp3c under revision 3.1
rev 1 of the DNP3 IED Certification Procedure at Subset Level 3, and every procedure that
runs passes. That procedure stops at Level 3, so Level 4 is implemented and tested against
the DNP Users Group subset tables, not certified. `py1815.catalog` names every object in
IEEE 1815-2012, and `python -m py1815.object_coverage` reports what the library does with
each. The project is now marked Production/Stable.

**Breaking change.** The master reads named points from an outstation set to Level 2, the
default, by asking for each point type whole and keeping the points named, where it sent
start-stop ranges (#119). A read of a point the outstation does not have now comes back
empty instead of drawing a parameter error. Set `level` to 3 or 4 for an outstation that
supports it to keep range reads. An outstation given no level answers as before, and
`level2=True` still works but warns that it is deprecated.

### Added

- **A Level 3 or 4 outstation answers four more reads.** It reads the packed binary input variation (group 1 variation 1, answered with flags), 16-bit frozen counter events (group 23 variation 2, answered in 32 bits), the current time (group 50 variation 1) and the internal indications (group 80 variation 1, indexes 0 to 15). Level 2 and the default refuse them as before. `Session` takes `time_source` and `indications_read` for the last two. The master reads group 80 variation 1 in a response. (#110)

  **A Level 3 or 4 outstation reports counter events when a counter's flags change.** A counter that loses or regains communication raises a group 22 event with its count and new flags, reported in the class of its frozen counter events by class polls, unsolicited responses and reads of group 22 variations 0, 1 and 2, all in variation 1. A change in value raises none unless the event policy turns value events on for that counter (#112); IEEE 1815-2012 11.9.5.2 and TB2016-003b Table 12-49 footnote o make them optional. The Device Profile states the counter event class and that value changes are not reported. Level 2 and the default report no counter events, as before. (#110)

- **The outstation accepts ASSIGN_CLASS at Levels 3 and 4.** A master can move binary inputs, counters, frozen counters and analog inputs between event classes, or give them class 0 to turn their events off, and every class poll after the request reflects it. Level 4 also takes the output groups. Events already buffered stay in the class they were recorded in, and a restart returns every point to its starting class. Level 2 and the default still refuse function code 22. The Device Profile lists the function for the groups the level takes. (#111)

- **A counter can report changes of its count as events, from Level 3.** An event policy rule with `"value_changes": true` has a counter raise a group 22 event when its count changes, beside the event every change of its flags raises; a `deadband` on the same rule, in engineering units, is how far the count moves from the count in the last event before the change is an event. It is off unless a rule turns it on. The Device Profile states which counters report value changes, in `reportValueChangeCounterEvents` and in each counter's `reportCounterValueChangeEvents`. (#112)

- **A Level 4 outstation serves the floating-point and time-stamped analog and counter variations (#113).** With `level=4`, a master reads analog inputs as single-precision floats (group 30 variation 5), analog output status as floats (group 40 variation 3), and analog input events as floats without and with time (group 32 variations 5 and 7), and a class poll may be answered in either float variation. A 16-bit frozen counter, and a 16-bit frozen counter event, with time are answered in 32 bits, as the other 16-bit counters are. Floating-point variations carry the value in engineering units and do not apply the point's multiplier. Below Level 4 each is an unknown object, and a session refuses a floating-point `analog_event_variation`. The Device Profile lists them.

- **A master can read and write analog input deadbands (#114).** With `level=4`, group 34 variations 1 to 3 are read by range, by index or with all objects, and written by range or by index. A written deadband replaces the configured one and decides when that input next raises an event; it is lost when the outstation restarts. Variations 1 and 2 are counts in the transmitted units and variation 3 is in engineering units. A write that names an input that is not served, or carries a negative value or one that is not a number, is refused as a parameter error and changes nothing. The master's decoder reads group 34, and the Device Profile says deadbands are set over DNP3.

- **A Level 4 outstation reports binary and analog output events, and the master decodes command events (#115).** With `level=4`, an output whose value or flags change raises a group 11 or group 42 event, starting in the class of the input paired with it, which class 1, 2 and 3 polls and reads of the group return, with overflow handling as for the inputs. An assign-class request that names group 10 or group 40 moves an output's events to another class, or turns them off with class 0, which keeps the output in class 0; assigning the paired input moves only the input, and one that names group 12 or group 41 changes nothing. Class 0 then carries the status of each output that has a class, as the subset tables require when output events are reported. Reads of groups 13 and 43 are answered with a null response, since command events are not generated. The Device Profile lists the new groups and each output's class. The master decodes groups 13 and 43. Levels 2 and 3 and the default answer as before.

- **An outstation at Subset Level 4 serves double-bit binary inputs (#116).** A point map can hold points of the new kind `DBI`; `Binding.read(Kind.DBI, index, reader)` binds one to a reader that returns its state, 0 to 3. At Level 4 the outstation answers group 3 reads in the packed variation and in the variation with flags (a point in an exception condition always takes the variation with flags), reports state and quality changes as group 4 events without time, with absolute time, or with relative time behind a common time of occurrence, and includes the points in class 0 and in class 1 to 3 reads. An assign-class request naming group 3 moves the points' events to another class or turns them off. Below Level 4 groups 3 and 4 are unknown objects. The Device Profile declares the points, and the master reads, decodes and stores them (`read(double_bit_inputs=...)`, `Store.double_bit_input`, point type `dbi` in the API). The master console shows them in a table of their own.

- **A Level 4 outstation serves device attributes, and the master reads them.** With `level` 4 the outstation answers reads of object group 0 for every attribute Level 4 requires, the list of attribute variations and the read of all attributes. It takes writes of the location name, ID code and device name, and of the maximum transmit fragment size, which changes how its responses are fragmented. Values come from the points served, the session and the `identity` settings, which gain `serial_number`, `location_name`, `device_id` and `device_name`; `timing_accuracy_us` sets the reported timing accuracy. A written value lasts until the outstation restarts. The Device Profile lists the attributes. The master's decoder and the traffic records read group 0 by the length each attribute states, and the traffic records by the size prefix where a response carries one. (#117)

- **The master is given each outstation's subset level, and sends no request above it (#118).** Set `level` to 2, 3 or 4 when adding an outstation, in the configuration file, or with `--level`. It is 2 when not given. A request above the level raises `AboveSubsetLevel` and is not sent, as IEEE 1815-2012 14.7.2 requires of a master. The console's add form has a **Subset level** field, and the Overview tab shows it. The checks of the `subset` set are not applicable below the level they need.

- **The master sends the requests of Subset Level 3 and Level 4 (#119).** `read_group` reads a group by a named variation, by a range of points or by a list of indices; `read_time` and `read_indications` read the time (group 50) and the internal indications (group 80); `assign_class` sends ASSIGN_CLASS for named points, double-bit inputs among them; `read_deadbands` and `write_deadbands` read and write analog input deadbands (group 34); `read_attributes` and `write_attribute` read and write device attributes (group 0). Each is on the Python master, in the service and its HTTP API and in the OpenAPI document, except `read_deadbands`, which is on the Python master only: the service and the HTTP API read deadbands with `read_group` on group 34. Each is refused before it is sent when the outstation is set to a lower level.

  **The console and `py1815-master evaluate` cover the requests of Subset Level 3 and Level 4 (#119).** The console's Commands tab reads by variation, by range or by list, reads the time, the internal indications, the device attributes and the deadbands, and with `--allow-control` assigns event classes and writes deadbands and attributes. The `subset` set of `py1815-master evaluate` checks what a Level 3 and a Level 4 outstation answer.

- **An object catalog names every group and variation in IEEE 1815-2012, and a command reports what the library does with each (#120).** `py1815.catalog` lists each object by group, variation, name, type and size, and `tests/test_conformance.py` checks it against Annex A as `scripts/extract_conformance.py` reads it into `conformance/ieee-1815-2012.json`. `python -m py1815.object_coverage` lists, for every variation, whether the outstation serves it, accepts it in a request and whether the master reads it, and adds the subset level when given your copy of the DNP Users Group subset tables.

### Changed

- **CI tests a locked set of development dependencies, and the release SBOM says so (#107).** `uv.lock` pins the versions CI installs, so a new upstream release cannot change what CI tests until a Dependabot pull request updates the lock. The package still has no runtime dependencies and the lock does not ship. Set up a development environment with `uv sync --extra dev`. When a release has runtime dependencies, its SBOM records their resolution as `tested-lock`: the versions the lock pins and the test suite runs against, which a consumer resolving the ranges may not get. A release with none, as this package is today, has an SBOM that says it has no runtime dependencies.

- **The outstation takes a subset level of 2, 3 or 4.** Set it with `DerOutstation(level=...)`, `"level"` in the configuration file or `--level` on the command line; the Device Profile reports the level. `level2=True`, `"level2": true` and `--level2` still mean level 2, and the keyword warns that it is deprecated. (#109)

- **A Level 3 outstation reports frozen counters and frozen counter events without time.** A read of frozen counters that names no variation is answered in variation 1, and class polls and unsolicited responses carry frozen counter events in variation 1, as Tables 12-21 and 12-25 list for Level 3. Level 4 and the default keep the variations with time. `Session` takes `frozen_counter_event_variation` to choose. (#110)

- **The dnp3c conformance run is held at Subset Level 3.** CI runs revision 3.1 rev 1 of the IED certification procedures with dnp3c against a Level 3 configuration of the outstation, in place of the Level 2 run, and `compliance/` keeps the report of that run. The device reports counter events, with value changes turned on by its event policy, frozen counter events and class assignment. The unit suite carries out the procedures Level 3 requires at Level 3 as well as at Level 2: unsolicited responses, frozen counter events, point ranges, specific variations and class assignment. (#112)

- **A read of named points to an outstation set to Level 2 asks for each point type whole (#119).** IEEE 1815-2012 Table 14-3 and TB2016-003b give a Level 2 outstation static reads with qualifier 0x06 only; reads by range are Level 3. So `read(...)`, the service's `read`, the console's **Read points** and the DER profile's reads now ask an outstation set to Level 2, the default, for every point of each type named, and return only the points named. An outstation set to Level 3 or 4 is still asked by ranges of indices. A read of a point the outstation does not have now comes back empty from a Level 2 outstation, where a range read drew a parameter error. Set `level` to 3 or 4 for an outstation that supports it to keep the smaller requests.

### Fixed

- **A freeze-and-clear clears the counters at Levels 3 and 4, as at Level 2.** TB2016-003b Table 12-19 requires it of every subset level, so an outstation given a level now clears on function codes 9 and 10. Only an outstation given no level, which serves the IEEE 1815.2 profile, keeps its counters through a freeze-and-clear. (#112)

### Security

- **Dependabot now proposes every new dependency release, not only security fixes (#107).** A weekly pull request per ecosystem groups the minor and patch releases of the locked Python dependencies, the GitHub Actions, the container base image and the Rust interop peers. Each major release gets its own pull request.

## [0.4.0] - 2026-10-28

Traffic records. The outstation reports each request it handles to a request observer, and
`py1815.traffic` describes outstation and master traffic as DNP3 traffic records under
version 1 of the DNP3 traffic schema, a copy of which ships in the package. The DNP3 guide
shows the octets it describes. Nothing in this release changes what the outstation answers
or what the master sends.

### Added

- **`OutstationServer` and `Session` take a `request_observer`, called with a
  `RequestRecord` for each request the outstation handles and each unsolicited
  response it sends (#104).** The record carries both ends of the connection the
  request arrived on, the link addresses, the function code, the request octets
  and the response sent back, so an application embedding the outstation can log
  or forward the traffic it serves. A read held behind an unsolicited response
  is reported when it is answered, or with no response when it is discarded,
  including when its connection ends or the listener stops. Frames the session
  drops are still reported as anomalies and are not reported again.

  **`py1815.traffic` describes the outstation's request records and the master's
  exchanges and unsolicited responses as DNP3 traffic records: one JSON body per
  application fragment, defined by version 1 of the DNP3 traffic schema, in a
  message envelope (#104).** An application can publish its own traffic beside
  traffic captured from the network without conversion code. A body lists every
  object header with its qualifier and range, and every point in wire order with
  its wire index, value, flag octet and time, command objects and command events
  included, with a CROB's control code as fields, the internal indications by
  name, and the IP address and port of each end of the connection. A write of
  the internal indications gives a point per bit, and a header of a group whose
  objects are not points, such as a time write, carries its octets as `data`. A copy of the
  schema ships in the package (`py1815.traffic.load_schema()`), and every body is
  valid against it. A fragment that cannot be read to its end is marked
  `apdu_rejected` (`malformed`, `point_count`, or `too_large` beyond the schema's
  bounds) and lists no objects or points. The envelope type is in
  `py1815.envelope`, with no new dependency. The master's `Outstation.connection`
  gives the two ends of the connection to fill a body.

### Changed

- **The DNP3 guide shows the octets it describes: two worked frames, the link
  function codes, the qualifier codes, the quality flags and the control relay
  output block (#96).** The page is written for someone reading a frame and
  showed none, so every layout had to be reconstructed from prose. One of the two
  frames runs past sixteen octets of user data, so its block checksum lands in
  the middle of a field, which is the case a parser gets wrong.

## [0.3.0] - 2026-10-16

A master, and the outstation held to an independent conformance run. `py1815.master` polls,
reads named points, commands outputs, synchronizes time, takes unsolicited responses, runs
startup tasks, speaks TLS, and serves a JSON API and a web console; it reads an IEEE 1815.2
DER by its profile, and `py1815-master evaluate` runs named checks against an outstation,
deviations among them. Connections and protocol anomalies are reported to an observer. CI
runs Step Function I/O's dnp3c under revision 3.1 rev 1 of the DNP3 IED Certification
Procedure at Subset Level 2, every procedure that runs passes, and the report is kept in
`compliance/`. The project is now marked Beta.

**Breaking changes.** This release changes what the outstation answers, what the master
sends, and two names, and the entry for each says what to do about it. The outstation acts
on a broadcast sent as confirmed user data (#93); refuses a disable request when built
without unsolicited responses (#97); refuses a read of group 21 and a freeze when its
counters do not freeze (#100); refuses a control relay output block with the clear bit set,
where it carried out the operation (#102); and stamps an event with the time its reading
gives (#75). The master runs a startup sequence when it connects, where it sent nothing
(#78); sends a disable request at startup only when it is set to use unsolicited reporting
(#98); and sends named reads as start-stop ranges (#81). `der.AO_POWER_LIMIT_MAXIMUM` is
replaced by `der.AO_POWER_LIMIT_GENERATION` and `der.AO_POWER_LIMIT_CHARGING` (#73), and
`py1815.profile.probe` keeps only its object parser (#86).

### Added

- **A master for exercising outstations, in a first version that reads (#70).**
  `py1815.master` is the other end of the conversation: `Master` and `Outstation` over a
  socket, and `Loopback` wired straight to a `Session` in one process. It polls by class,
  reads named points by type and index, confirms the fragments that ask, takes unsolicited
  responses, and keeps the last value of every point in a store. Each request returns an
  `Exchange` with every fragment received and every object decoded, and a timeout or an
  error indication is a result and not an exception. `MasterAssociation` holds the protocol
  and does no I/O, as the session does none. `py1815.decode` reads the objects a response
  carries, from the standard's layouts and not from this library's encoders, and stops with
  a reason at one it does not know. `application` gains `build_request`, `build_confirm`,
  `parse_response` and the headers a read is made of. It does not command an output,
  reconnect, or speak TLS yet; `docs/planning/MASTER.md` is the plan. D73 to D76 record the
  decisions.

- **The master as a service, and a web console on it (#71).** `py1815-master console` serves
  a console for a DNP3 master in a browser: each outstation's points by type with their
  flags named, scans and reads with their results, events as they arrive, and the traffic
  with each frame read layer by layer beside its octets. `--demo` starts a simulated
  IEEE 1815.2 DER beside it, and `--profile` names an outstation's points from the profile and
  lets the console show the points of the profile it has not reported. An enumerated point is named without the values it lists, which
  are shown beside it on request. The console holds no logic. It speaks to
  `py1815.master.service`, whose operations are JSON: each is a route, `POST /api/<operation>`,
  described in an OpenAPI document served at `/openapi.json` and built from one description
  that a test holds the service to. `py1815-master serve` offers the same operations a line at
  a time over a local socket for a test rig. The console is tested in a headless browser,
  where one is installed. The Dockerfile gains a `master` target, an image of the master with
  its API and console, and `compose.yaml` runs it beside the simulated DER: `docker compose up`
  fetches the point tables, starts the outstation, and starts the master connected to it. The console listens on this machine unless
  given a token, refuses a request from a page it did not serve, and loads nothing from the
  network. `Outstation` gains `trace`, the record of every frame; `repeat_scan`, for a scan
  on a schedule; `scan("outputs")`, which reads the output status an integrity poll leaves
  out; and `enable_unsolicited` and `disable_unsolicited`. Neither the service nor
  the console adds a dependency. D77 and D78 record the decisions.

- **The master commands outputs (#76).** `operate` sends controls to binary and analog
  outputs by direct operate, by select and then operate, or by direct operate with no
  acknowledgment, and returns a status for each control with whether the outstation echoed
  it unchanged. After a select the operate is sent only if every control was accepted, and
  nothing is ever sent twice: a response that does not arrive is reported as not known.
  `write_time`, `clear_restart`, `freeze` and `restart` are the other requests a master
  makes. The JSON service has an operation and a route for each, described in the OpenAPI
  document, and refuses all of them as `not_allowed` unless started with `--allow-control`,
  along with a `request` by any function code that is not a read. `status` reports which.

- **The console operates outputs (#77).** Started with `--allow-control`, the Commands tab
  has a form that commands a binary or an analog output by select and operate, direct
  operate, or direct operate with no acknowledgment, and buttons that write the time, clear
  the restart indication and freeze the counters. The result says whether the outstation
  accepted, refused, was never asked to operate, or did not say, with its status for the
  control. Each row of the output tables has a button that opens the form filled in, and
  the output's status is read back afterwards. The top of the page says whether it is read
  only or commanding. Without the flag the controls are greyed out and the service refuses
  them. The compose file starts the console able to command the simulated DER beside it.

- **The master runs automatic tasks, and is configured from one JSON file (#78).**
  On connect, and when an outstation reports a restart, the master disables unsolicited
  reporting and runs an integrity poll. It also clears the restart indication, writes the
  time when asked, polls for events when a response indicates some, runs an integrity poll
  after an event buffer overflow, and can enable unsolicited reporting. Each task can be
  disabled through `Tasks`, and `manual=True` disables them all along with confirmations.
  No task operates an output, and no task is triggered by the response to its own request.
  A lost connection is reopened every `reconnect` seconds. `idle()` waits for pending
  tasks, and an exchange sent by a task names it in `task`. `Loopback` takes `tasks` and
  has `start()`. The JSON service takes `tasks`, `manual` and `reconnect` in `add`, has an
  `idle` operation, and reports each outstation's tasks. The console shows which tasks are
  enabled and logs each run.

  Every `py1815-master` setting can be kept in a JSON file: `--config FILE` loads it,
  command-line flags override it, and `py1815-master config` prints the complete
  configuration for editing. Unknown settings and wrong types are reported with their
  location. New flags: `--config`, `--manual`, `--unsolicited` and `--reconnect`.

- **The DER outstation is configured from one JSON file (#80).** Every `py1815-der`
  setting can be kept in a JSON file: `--config FILE` loads it on `run`, `points` and
  `profile`, command-line flags override it, and `py1815-der config` prints the complete
  configuration for editing. Unknown settings and wrong types are reported with their
  location. The file also sets things that had no flag before: the event policy, event
  capacity, response size, select, confirm and idle timeouts, read-only and Level 2
  operation. New flags: `--config`, `--read-only`, `--level2`, `--event-capacity`,
  `--max-response`, `--select-timeout` and `--idle-timeout`. `der.build` passes extra
  keyword arguments to `DerOutstation`.

- **The master is tested against outstations this project did not write (#81).** Two new
  interoperability jobs read and command an opendnp3 (C++) outstation and a `dnp3` crate
  (Rust) outstation with the master on every pull request. They check decoded values,
  quality flags, multi-fragment responses, events, unsolicited responses and the automatic
  tasks, and they check each control and the time write against what the outstation logged
  it received.

- **The master saves its traffic as a pcap file, and the dissectors read what it sends (#83).**
  A trace exports itself as a capture that Wireshark, tshark and Suricata read as it is: each
  frame a TCP segment at the time it crossed, each connection a stream of its own between its
  real addresses. The service's new `capture` operation returns that file, the console's Traffic
  tab has a Save capture button, and `--capture FILE` on `py1815-master console` and `serve`
  (`capture` in the configuration file) writes every frame to a file as it crosses the wire.
  The writer is `py1815.master.capture`, moved from the interoperability scripts, which use it
  too. The interoperability workflow's parsers job now also has the master read an outstation
  and write a capture, which both dissectors read with the master's requests and confirmations
  counted as well as the outstation's responses.

- **The master speaks the IEEE 1815.2 DER profile, and the console has a DER tab (#84).**
  `py1815.master.profile` gives an outstation with a profile its points by name and in
  engineering units: `Der(outstation, point_map)` reads points or a named group (the
  nameplate, monitoring, one function), writes outputs scaled through each point's
  multiplier and refused before sending when out of range, enables and disables a
  function and reads whether it is enabled, writes a curve selector, fields and points in
  the order clause 6.1.3 requires and reads it back, lists the functions the outstation
  supports and which are enabled, and compares what it serves with a DNP3 Device Profile
  document. `verify=True` reads each mirroring input afterwards and checks it within one
  step of the multiplier. Writes are controls: sent once, and refused by a service that
  does not command. The service has a `der.*` operation for each, described in the
  OpenAPI document, and `--device-profile FILE` (or `device_profile` in the configuration)
  gives an outstation the document to compare with. The console's DER tab shows the
  nameplate, monitoring, each supported function with its settings and an enable switch,
  the curve as a plot and a table, and the comparison. `console --demo` gives the
  simulated DER the Device Profile document it publishes.

- **The master is ready to run for days (#85).** The capture file rotates by size
  (`--capture-max-mb`, `--capture-keep`), and `--log-file` writes a rotating log file
  (`--log-max-mb`, `--log-keep`, `--log-level`); every setting is also in the configuration
  file. The log records what the master was started with, each connection made and lost,
  and every command sent to an outstation with the points and values asked for and whether
  it was accepted; a command refused for lack of `--allow-control` is logged as a warning. An
  outstation that stays unreachable is logged once when the retries begin and then once an
  hour, instead of at every attempt.

- **The master retries reads, speaks TLS, broadcasts, sets the clock by either procedure,
  waits for conditions, and has a blocking interface (#86).** A read that times out with
  nothing received is sent again `read_retries` times under its own sequence number, none by
  default; nothing else is ever sent again. `Outstation` connects over TLS when given an
  `ssl.SSLContext`, and `py1815.master.tls.TlsSettings` makes one from a CA file, a
  certificate and a key, whose password is read from `PY1815_MASTER_KEY_PASSWORD`.
  `connect(wait=...)` and `Master.add(wait=...)` keep trying a first connection for as long as
  asked. `broadcast()` sends any request to 0xFFFD, 0xFFFE or 0xFFFF. `synchronize_time()`
  sets the clock by the LAN or the non-LAN procedure of IEEE 1815-2012 10.3.3, and the time
  task can use either (`time_procedure`). An outstation's tasks can be changed after it is
  added, and a poll whose response still says events are waiting is followed at once by up
  to `event_follow_ups` more. `wait_for()` waits for a condition on the store, an event or
  an indication. `py1815.master.sync.Master` is the same master for a script with no event
  loop. The JSON service gains `set_tasks`, `wait_for`, `synchronize_time` and `broadcast`,
  `connect` takes `wait`, and `add` takes `read_retries` and `tls`; the configuration file
  and the command line gain `read_retries`, `tls` and the task settings, with
  `--read-retries` and `--tls-ca`, `--tls-certificate`, `--tls-key` and `--tls-server-name`.
  `py1815-master poll` runs one integrity poll and prints what came back.

- **`py1815-master evaluate` checks an IEEE 1815.2 DER and reports a verdict for each check
  (#87).** It carries out EPRI's test procedure for the DER profile against any outstation,
  over a socket: the meter, alarm and operating state points, the connect switch, stop and
  start with their permissions, the curve block, and each of the 21 functions, supported or
  not. A further check compares what the outstation serves with its Device Profile document.
  Without `--allow-control` only the checks that read are run. `--report` writes the report
  as JSON, `--capture` writes the traffic, and each result names its frames in that capture.
  The settings are in the configuration file under `evaluate`, with a flag for each.
  `py1815.master.evaluate` runs the same checks from Python, and a check of your own is a
  function that takes a `Bench`. See
  [Evaluating an outstation](https://dersecurity.github.io/py1815/master-evaluate/).

- **The master can break a protocol rule on purpose, to test how an outstation answers what the standard says it must refuse (#89).** A deviation is named and off by default, and is applied to the octets the master built on their way out, so with every one off the master stays conformant. The ten are `silence`, `repeat_request`, `corrupt_header_crc`, `corrupt_body_crc`, `truncate`, `overstate_length`, `break_transport_sequence`, `orphan_segment`, `withhold_confirmation` and `wrong_confirmation_sequence`. Set them in Python on `outstation.deviations`, or over the service and the console with the `deviate` operation. A frame the master damages is kept in the trace and in a capture as it was sent, with what is wrong with it. See [Misbehaving on purpose](https://dersecurity.github.io/py1815/master/#misbehaving-on-purpose).

- **`py1815-master evaluate` checks how an outstation answers a master that breaks a protocol rule (#91).** A new set of checks, `deviation`, sends a read in a frame with a bad header checksum, a bad data checksum, a missing octet or an overstated length, as a segment with no first segment, and as a series whose final segment never comes, and requires that each draws no answer and that the outstation answers a well-formed read afterwards. Three more read the outstation's events while withholding the confirmation, confirming the wrong sequence number, or confirming after the next request, and require the same events again. These checks write nothing to the outstation. They are run only with `--allow-deviations`, or `evaluate.allow_deviations` in the configuration file, and are reported as not run without it. See [The deviation set](https://dersecurity.github.io/py1815/master-evaluate/#the-deviation-set).

  **More deviations (#91).** `second_master_address` sends every frame from the next master address above the master's own, `late_confirmation` sends the confirmation of a solicited response after the master's next request, `endless_series` sends a request's last segment with its final bit clear, and `withhold_unsolicited_confirmation` sends no confirmation of an unsolicited response. `withhold_confirmation`, `late_confirmation` and `wrong_confirmation_sequence` act on the confirmation of a solicited response and leave the confirmation of an unsolicited one as built. They are set like the others, on `outstation.deviations` or with the `deviate` operation.

  **The console has an Evaluate tab and a Requests tab (#91).** Evaluate lists the checks by set, runs the ones chosen and fills in each verdict as its check ends, offers the report as a JSON file, opens the Traffic tab on a check's frames, and has a switch for each deviation. Requests keeps a list of requests in the browser, each a function code and its object headers, to send once or to repeat while the page is open. The service gains the operations behind the first: `checks` lists the checks, and `evaluate` runs them and sends a `check` event as each ends. See [The console](https://dersecurity.github.io/py1815/console/).

  **The Traffic tab says what is wrong with a frame the master damaged (#91).** The data link layer of such a frame shows a Problem line beside the header fields as they were written.

- **A Device Profile document can be laid out as a page to read and to print (#92).** `py1815-der profile --html FILE` also writes the document it builds as one standalone HTML page, and `py1815-der profile --from vendor.xml --html vendor.html` lays out a Device Profile XML file that already exists, from any vendor and any edition of the schema, with no outstation and no point tables. The page has the header's facts, a table of settings for each part of the configuration with each setting's capabilities, current value and methods, the implementation table, and a table of points for each point type. Printed or saved as PDF from a browser, each table's headings are repeated on every page. The layout is this library's own and not the DNP Users Group's: a label is the element's own name made readable, and a value the document does not state is left empty. A document that is not XML or not a Device Profile, that declares a document type, or that is larger than 8 MiB is refused. See [Reading the document, and printing it](https://dersecurity.github.io/py1815/der/#reading-the-document-and-printing-it).

  **The service lays a Device Profile document out, and the console shows and prints it (#92).** The `der.document` operation answers with a document as a title, header facts and sections of tables: the one sent as `document`, or the one the outstation was given with `--device-profile`. It sends nothing to the outstation, so it is allowed without `--allow-control`. The console's DER tab has a Device Profile document card that shows the outstation's document or a file from your machine, and prints it alone. The card that compares what an outstation serves with a document is now titled Device Profile comparison. From Python, `py1815.profile.device_profile_view.read` returns the same model and `page` writes it as HTML.

- **A conformance harness the project did not write runs the certification procedures, and
  every procedure that runs passes (#94).** Continuous integration runs
  [dnp3c](https://github.com/stepfunc/dnp3c) 0.2.0, Step Function I/O's conformance test
  harness, against a Subset Level 2 configuration of the outstation under revision 3.1 rev 1
  of the DNP3 IED Certification Procedure, and
  [Conformance run with dnp3c](https://dersecurity.github.io/py1815/conformance/) says how
  every procedure ends and why. None fails, none is excluded and none passes with a warning.
  The tool's report is kept in `compliance/`. The job compares each run with a record, so a
  procedure that starts to fail or starts to pass is noticed. `interop/dnp3c/`, the test
  program that links the harness, and `compliance/` are licensed under the GNU General Public
  License, version 3 only; nothing in them is part of the library, the wheel or the source
  distribution.

- **Cold restart can be turned on and off without a restart, and an outstation reports its
  frozen values (#100).** `Session.restart_handler` is a property: setting a handler turns
  cold restart on, and setting `None` turns it off, from the next request, with the master
  still connected (D55). `DerOutstation.frozen(index)` returns the value a counter held at
  its last freeze, or `None` if it was never frozen.

- **Connections and protocol anomalies are reported as records to an observer the host application gives (#101).**
  `OutstationServer` and the master's `Outstation` take a `connection_observer`, called with a
  `ConnectionEvent` for each connection accepted, refused, displaced or ended at the outstation,
  and each connection made, failed, lost or closed at the master: the endpoints, TCP or TLS, the
  identity a TLS peer proved, and the reason. `Session` takes an `anomaly_observer`, called with
  a `ProtocolAnomaly` for each frame or request it drops and each unsolicited response it gives up
  on, with a stable code, a severity and the link addresses. A host application can keep a record
  of every connection attempt and pass anomalies to its own monitoring without subclassing the
  listener. Both are optional and settable as attributes, the log lines are unchanged, an
  observer that raises does not affect the connection, and `on_connection` works as before.
  `docs/observers.md` lists the records and what produces each.

### Changed

- **DER behavior is stated as out of scope** (#72). The README, the DER page and the design notes
  now say that the functions of IEEE 1815.2 clause 6, the following of a curve (6.1.3) and
  schedules belong to the device or DER simulator bound behind the outstation. The library serves
  their points and enforces what the profile says of the points, and the simulated DER answers to
  a few functions only so the points can be seen working. No behavior changed.

- **Connecting now runs a startup sequence (#78).** `Master.add` and `Outstation.connect`
  used to send nothing. They are now followed by the startup tasks, and a lost connection
  is reopened. Pass `manual=True` to send only what is asked for, `tasks=Tasks.none()` to
  keep confirmations but no tasks, and `reconnect=None` to stay disconnected. A service
  started without `--allow-control` does not run the two tasks that write (restart clear
  and time write), so it changes nothing on an outstation it is only reading.

- **`py1815-der poll` is the master's poll, and `--connect-wait` is the service's own (#86).**
  `py1815-der poll` prints what it printed before, through the master instead of a probe of
  its own, and gains `--read-retries` and the TLS flags; an object it cannot read is reported
  in the output where the probe stopped with an error. `py1815.profile.probe` keeps only its
  object parser. `--connect-wait` now asks the service's `connect` to keep trying, once a
  second, rather than looping in the command line.

- **The outstation acts on a broadcast sent as confirmed user data (#93).** It used to act
  only on a broadcast sent as unconfirmed user data and drop the confirmed form. Every device
  is to accept and process confirmed user data, and none is to reply to a broadcast whichever
  function carries it (IEEE 1815-2012 9.2.4.1.3.6), so the request is now carried out and
  IIN1.0 is set in the next response. Nothing is sent back, as before. A confirmed broadcast
  is taken only after a link reset, and the same frame sent again is not acted on twice. A
  link reset or a link test sent to a broadcast address is still not acted on.

- **An outstation without unsolicited responses refuses a disable request (#97).** Built
  without them, which is the default, an outstation used to agree to `DISABLE_UNSOLICITED`
  while refusing `ENABLE_UNSOLICITED`. It now refuses both with IIN2.0, as the certification
  procedure expects of a device with the mode off (IED Certification Procedure 3.1 rev 1,
  8.11.2), and its Device Profile no longer lists function code 21. A master that sends a
  disable request at startup will see the refusal; build the outstation with `--unsolicited`,
  or `Session(unsolicited=True)`, for one that takes the request. An outstation built with
  unsolicited responses is not affected.

- **A master sends a disable request at startup only when it is set to use unsolicited
  reporting (#98).** The startup sequence used to begin with `DISABLE_UNSOLICITED` for every
  outstation. A master that names no class in `enable_unsolicited`, which is the default, now
  sends none, and no master sends one when an outstation reports a restart (IEEE 1815-2012
  5.1.1.2 and 5.1.1.1.2). The integrity poll is therefore the first request of a connection.
  When it reports a restart, a master that clears the restart makes the poll once more after
  clearing it, and after writing the time if the outstation asked for it, so connecting to an
  outstation that has just started takes two integrity polls. Use the `disable_unsolicited`
  operation to stop reporting that an earlier master left enabled.

- **Counter reads in a 16-bit or flagless variation are answered at 32 bits, and frozen
  counters are only the counters that freeze (#100).** A read of group 20 variation 2, 5 or 6
  is answered in variation 1, and a read of group 21 variation 2 or 10 in variation 1 or 9.
  These reads used to be refused with `OBJECT_UNKNOWN`. DNP3 IED Certification Procedure 3.1
  rev 1, 8.24.2, lets a Level 2 device refuse only its first read of a type, and accepts a
  32-bit answer from a device that keeps 32-bit values (D100). The Device Profile lists these
  reads. An outstation whose counters do not freeze now refuses a read of group 21 with
  `OBJECT_UNKNOWN`, where it answered with no objects and no error indication, refuses a
  freeze as a function it does not implement, and lists neither in its Device Profile.

### Fixed

- **The simulated DER limits generation on AO88, not AO87** (#73). The profile's tables name the two
  setpoints of the active power limit the maximum and the minimum, and the simulation took the
  first as the cap on generation. Clause 6.4.2.2 defines AO87 as a percentage of maximum charging
  power and AO88 as a percentage of maximum generation power, which is also how DNP3 application
  note AN2018-001 and EPRI's test procedure have them. A master that limited generation by
  writing AO88 found the simulation unmoved. AO87 now limits what the storage draws when
  charging. `der.AO_POWER_LIMIT_MAXIMUM` is replaced by `der.AO_POWER_LIMIT_GENERATION` and
  `der.AO_POWER_LIMIT_CHARGING`.

- **An event carries the time its reading gives (#75).** `Reading.timestamp_ms` is
  documented as when the source measured the value, and `DerOutstation.poll()` ignored it:
  every binary and analog event was stamped with the outstation's own clock, so a caller
  that supplied a measurement time saw it go nowhere. An event raised by a `GOOD` reading
  that gives a time now carries that time, moved onto the clock a master's time write sets.
  A reading of any other quality is timed when the outstation records it, since a value
  retained from a source that has gone away was not measured when the loss was seen. A
  reading that gives no time, and a binding that returns a bare value, are timed by the
  outstation as before, so nothing changes for a caller that never set the field. A master
  may now see events whose times are not in order, when a source reports late.

- **An element the console marked hidden could stay on the page (#77).** A label is laid
  out as a grid, which outranked the hidden attribute, so the box offering the profile's
  unreported points was shown for an outstation with no profile.

- **A cancelled request no longer blocks later requests (#78).** If a request was
  cancelled while waiting for its response, for example by the caller's timeout or by
  rescheduling a repeated scan, the association stayed busy. Every later request was
  rejected and the repeated scans stopped. The request is now ended as `abandoned` and
  recorded, and a late response to it is dropped without being confirmed.

- **The master reads named points in a form every outstation accepts (#81).** `read()`
  sent point indices with the index-list qualifiers (0x17 and 0x28), which a DNP3 Subset
  Level 2 outstation is not required to accept. opendnp3 rejected them, so a read of named
  points returned nothing. Indices are now sent as start-stop ranges (qualifiers 0x00 and
  0x01), one for each run of consecutive indices, in ascending order.

- **A console that fell behind no longer stops updating without saying so (#85).** A
  subscriber that fell 10,000 updates behind was dropped while its event stream stayed open,
  so the console still showed "Service running" and received nothing more until it was
  reloaded. The subscriber now stays subscribed, its waiting updates are replaced by one
  `lost` update that says how many were dropped, and the console reloads what it shows. An
  event stream that has not accepted a write for 60 seconds is closed, so the browser opens
  a new one, and the console reloads after any reconnection.

- **The IEEE 1815.2 outstation refuses a control with the clear bit set (#102).** A control
  relay output block with the clear bit set and an operation used to be carried out as if
  the bit were not there, while one with the clear bit alone was refused. The outstation does
  not support the clear bit, and IEEE 1815-2012 Annex A has a device answer `NOT_SUPPORTED`
  to a combination with the bit set that it does not support, so every such block is now
  refused, on select, operate and direct operate, and operates nothing (D101). A master that
  sets the bit out of habit should stop setting it. `ControlRelayOutputBlock` still decodes
  the bit, so a provider of its own can support it.

## [0.2.0] - 2026-10-06

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
