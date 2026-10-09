# Plan: a master, for evaluating outstations

This library is an outstation. Everything that exercises it today is either a master
somebody else wrote, run in the interoperability jobs, or a few hundred lines of
test harness that build requests by hand. Neither can be handed to a person and
neither can be driven by a script that says "enable volt-var, write this curve,
and show me what the device reports".

This plans `py1815.master`: a DNP3 master whose first purpose is to evaluate an
outstation, this one or any other, with a control API that a test drives
programmatically and a web console that a person drives by hand.

## Purpose

In priority order, because the order settles most of the design questions below.

1. **Evaluate this library's outstation.** Drive whole exchanges the way a master
   does, from a script, with every octet kept, and be able to misbehave on purpose.
2. **Evaluate any outstation.** The same tool pointed at a device on a bench:
   read everything it serves, command it, and compare what it does with what its
   device profile says.
3. **Demonstrate.** One command that starts a simulated DER, a master and a
   console in a browser, so the software can be shown working without a
   slide.

It is not a SCADA front end. It keeps no history beyond a session, raises no
alarms, has no operators or permissions, and makes no promise about hundreds of
outstations. Each of those is a product of its own, and a master built to probe
and to misbehave is the wrong base for one.

## What a master built here cannot prove

Stated first because it limits everything after it.

A master built on this library's `link`, `transport` and object code shares its
reading of the standard with the outstation. If both misread a field the same
way, they agree with each other and every test passes. [DESIGN.md](../DESIGN.md)
already makes this argument for tests that encode and decode with one library,
and `interop/sweep.py` says in its own header that requests built here prove
the outstation answers as it says, while independent masters and parsers judge
whether the octets are really DNP3.

So this master adds reach and convenience, and no independence. Three rules
follow, and they are requirements of the plan and not hopes:

- The independent masters and the independent dissectors in the interoperability
  jobs stay, and stay required. Nothing here replaces them.
- The master is itself tested against outstations this project did not write.
- Its decoders are written from the standard's tables and pinned to literal
  octets, and are not produced by inverting this library's encoders.

## What already exists

More than a first look suggests, and it changes the size of the work.

**Usable from either end, unchanged.** `crc`, `link` (frames built and parsed in
either direction, and a stream reader), `transport` (segmentation and
reassembly), the vocabulary in `application` (function codes, qualifiers,
indication bits, object headers), and the control objects in `control`, which
are encoded and decoded already because an outstation echoes them.

**Partial masters.** Each was written for one job, and between them they carry
several tables of object sizes and several response parsers:

| Where | What it does | What it lacks |
|---|---|---|
| `profile/probe.py` | One integrity poll over a socket, confirming what asks for it. Behind `py1815-der poll` | Any association: no retries, no controls, no events over time |
| `tests/ied_harness.py` | Drives a `Session` in process for the certification procedures: requests, confirmations, link frames, corrupted frames | A socket, a clock of its own, a public interface |
| `tests/epri_harness.py` | The DER profile procedures on top of the same harness | The same |
| `interop/sweep.py`, `interop/probe.py` | Every function code over a real connection, with a capture written by `py1815.master.capture` (once `interop/pcap.py`) | Anything beyond one request and its reply |

**Missing.** Parsing a response (the application layer parses requests and
builds responses, and not the reverse), decoding the objects a response
carries, the state a master keeps across an exchange, a connection that dials
out, somewhere to keep what was read, and an interface to all of it.

## Scope

**In scope.**

- TCP and TLS as a client, and an in-process connection straight to a `Session`
  with no socket and an injected clock.
- Requests: `READ` by class, by group, by range and by index; `CONFIRM`;
  `WRITE` for the restart indication and the time; `SELECT`, `OPERATE`,
  `DIRECT_OPERATE` and `DIRECT_OPERATE_NR` for binary and analog outputs; the
  freeze functions; `COLD_RESTART` and `WARM_RESTART`; `DELAY_MEASURE` and
  `RECORD_CURRENT_TIME`; `ENABLE_UNSOLICITED` and `DISABLE_UNSOLICITED`; and
  broadcast.
- Responses: a response of several fragments, confirmed as it asks; unsolicited
  responses at any time, confirmed and told apart from repeats; a null response;
  the indications on every one.
- Objects: every group and variation this library's outstation can send, and
  the ones a Subset Level 2 master is required to parse. A response carrying an
  object the master does not know is reported as far as it could be read, with
  the octets, and is not an exception.
- The behavior a conformant master has by default: its startup sequence, its
  scans, and what it does about each indication. Each can be switched off.
- A store of what was read, with quality, time and where the value came from.
- The IEEE 1815.2 DER profile on top: points by name, engineering units, the
  functions and their curves.
- One control API with three faces: Python, a JSON service, a command line.
- Deliberate misbehavior, named and off by default.
- A record of every exchange, readable and exportable as a capture.
- A web console.

**Not in scope, and recorded so it is not assumed.**

- Serial links and UDP.
- Secure Authentication. The outstation does not implement it either, and a
  master that authenticates is its own plan.
- File transfer, data sets, virtual terminal, double-bit inputs, frozen analog
  inputs and octet strings, beyond reporting that one was received.
- More than one master association to the same outstation, and multi-drop.
- Users, roles, history, alarms, trending. See *Purpose*.

## Architecture

The outstation's shape, turned around. The part that knows the protocol does no
I/O; one thing owns the socket; everything a caller can do goes through one
interface.

```
  console (browser)      scripts and tests      command line
         |                      |                     |
         +---------- JSON service ----------+         |
                          |                           |
                     Python API  <--------------------+
                          |
     tasks ----- association ----- deviations ----- trace
                          |
                       channel
                     /         \
              TCP or TLS     in process, to a Session
```

| Module | Holds | |
|---|---|---|
| `application` | `build_request`, `build_confirm`, `parse_response` and the headers of a read, beside what it had | Built |
| `decode` | The decoders, and one table of object layouts | Built |
| `master.association` | One master association: octets in, octets out, time injected. The mirror of `session` | Built |
| `master.requests`, `master.operations` | The requests as object headers, and the one list of operations every carrier shares | Built, for reading |
| `master.store` | The last value of every point, and the events in order | Built |
| `master.loopback` | A master handed straight to a `Session`, with no socket | Built |
| `master.api` | `Master` and `Outstation`: the Python interface, over TCP, with scans repeated on request | Built, without TLS or reconnection |
| `master.tasks` | The startup sequence, the scans, the reactions to indications, as data | |
| `master.deviations` | Misbehavior, applied between the association and the connection | |
| `master.trace`, `master.capture` | Every frame with its time and direction, read layer by layer; the capture writer, moved from `interop/` | Built |
| `master.service` | The JSON service: the same operations over a local socket and over HTTP | Built, for reading |
| `master.profile` | The DER profile: names, units, functions, curves | Built |
| `master.cli` | `py1815-master` | Built: `console` and `serve` |
| `master.console` | The web console's files | Built: Overview, Points, Commands, Events, Traffic, DER, Log |

## The association

`MasterAssociation` holds what is true of one conversation with one outstation,
as `Session` does from the other side.

- **One request at a time.** A request takes the next sequence number and waits
  for its response. A second request waits its turn. Controls are never sent
  while another request is outstanding, because a control whose response is
  ambiguous is a control that may be sent twice.
- **A response may be several fragments.** Each is checked for the sequence it
  should carry, confirmed when it asks, and added to the result. The exchange
  ends at the fragment marked final, or at the response timeout.
- **An unsolicited response may arrive at any time,** including in the middle of
  a solicited exchange. It is confirmed, its events go to the store, and one
  that repeats the last sequence number octet for octet is confirmed again and
  stored once.
- **A timeout is a result.** The request ends with nothing received, and the
  caller is told. Reads may be retried, a configurable number of times, with
  the same sequence number as the standard has it. Controls are not retried by
  the association at all.
- **No I/O and no timer.** `receive(octets)` returns the octets to send, and
  `due()` and `due_after()` play the part `initiate()` and `initiate_after()`
  play in the session. A test drives it against a `Session` with one clock,
  no sleep and no socket.

What a conformant master does by itself is a list of tasks and not code spread
through the association:

| Task | Runs | Default |
|---|---|---|
| Disable unsolicited, then integrity poll | On connecting, and when the outstation reports a restart | On |
| Clear the restart indication | When the outstation reports a restart | On |
| Write the time | When the outstation asks for it | On |
| Enable unsolicited for the classes configured | After startup | Off |
| Integrity poll | Every `integrity_interval` | Off |
| Event poll, classes 1 to 3 | Every `event_interval`, and when class data is indicated | Off on a schedule, on when indicated |
| Integrity poll after a buffer overflow indication | When indicated | On |

As built, the polls on a schedule are `repeat_scan` and stay off until asked
for: a tool that is pointed at a bench should not start a stream of requests
because it was connected. The rest are `py1815.master.tasks`, and the table is
otherwise as built.

## Decisions

Numbered M here. Each takes the next number in [DESIGN.md](../DESIGN.md) when
the phase that builds it lands, so two plans in flight do not claim one number.
M1 and M2 are recorded there as D73, M3 as D74 and D75, M8 as D76, M7 and
M10 as D77, the listening half of M9 as D78, M5 with the commanding half
of M9 as D80, and M4 as D81. D82, reading named points by range, came out of
the interoperability work and has no M number. D87 and D88, the capture writer
and how a capture reaches a caller, record item 7. D90 to D93 record how the DER
profile is spoken (item 10), and have no M number either.

**M1. The master lives in this package, as `py1815.master`.** A separate
distribution would need the layers below it published as a stable interface
first, and they are not. The core of it has no runtime dependency, as the rest
of the library has none. What the console needs to serve a browser is an
optional extra.

**M2. The association does no I/O,** for the reason the session does none: it
can be pinned against literal octets and driven through hours of protocol time
in a test that takes milliseconds.

**M3. Decoders are written from the standard and not from the encoders.** One
table of object layouts serves the master, and comes to serve the session, the
probe and the harnesses in place of the separate ones each holds now. Every
decoder has a test that starts from octets written out by hand, the table is
compared with the one the certification harness was written with, and where
the tables in `conformance/` state a width it is to be checked against them.

**M4. Everything the master does unasked is a task that can be turned off.**
An outstation added with `manual=True` is sent nothing a caller did not ask for: no startup
sequence, no scan, no automatic confirmation. That mode is what evaluation
needs, because a test of what an outstation does when a confirmation never
arrives cannot have the master helpfully sending one.

**M5. A control is never sent, and never sent again, unless a caller asked.**
No task commands an output. No retry repeats a control. An ambiguous outcome is
reported as ambiguous, and the caller decides, because the caller is the one
who knows whether operating twice is harmless.

**M6. Misbehavior is named, explicit and outside the association.** A deviation
is applied to what the association produced, on its way to the channel, or to
what the channel received, on its way in. The association's own code has no
branch that does the wrong thing, so the conformant path cannot be bent by a
flag left on.

**M7. One API, and nothing reaches around it.** Every operation is a method on
the Python interface. The JSON service and the command line are generated from
the same table of operations, and the console speaks only the JSON service. If
the console can do it, a test can do it, with the same words.

**M8. Every operation returns what happened, and not whether it worked.** A
result carries the request sent, each fragment received, the objects decoded,
the indications, the status of each control, how long it took, and where in
the trace it is. A timeout, an error indication and a refused control are
results. An exception means the caller misused the interface.

**M9. Commanding is off until it is turned on.** A master started from the
command line reads. Commands need `--allow-control`, the service listens on the
loopback address unless told otherwise, and a service told to listen elsewhere
requires a token. The tool will be pointed at real equipment in a lab, and the
default has to be the one nobody regrets.

**M10. The console is a client and holds no logic.** It renders what the
service reports and sends what the person asks. Scaling, sequencing a curve
write, deciding whether a readback matches: all of it is behind the API, where
it is tested without a browser.

## The control API

### In Python

```python
from py1815.master import Master

async with Master() as master:
    der = await master.add("lab-inverter", host="192.0.2.10", port=20000,
                           outstation_address=1024, master_address=1,
                           integrity_interval=60, event_interval=5)

    poll = await der.integrity_poll()
    print(poll.indications, len(poll.objects))

    answer = await der.read(analog_inputs=[4, 6, 8], binary_inputs=[31, 32])
    print(answer.analog_inputs[4].value, answer.analog_inputs[4].flags)

    result = await der.operate(analog_outputs={87: 5000}, mode="select")
    assert result.status[("ao", 87)].name == "SUCCESS"

    await der.wait_for(lambda store: store.analog_output(87).value == 5000, timeout=10)
```

`Master` owns the connections and the store. `Outstation`, which `add` returns,
is where the requests are. Both have synchronous counterparts for a script
that has no event loop.

### The operations

Each row is one method, one JSON operation and one command.

| Operation | Does |
|---|---|
| `status` | The service, and for each outstation: connected or not, addresses, last response, indications, counts of requests, timeouts and errors |
| `add`, `remove`, `list` | Outstations: host, port, both link addresses, TLS, the task intervals, which tasks run, and optionally a profile. Each has a name the caller chooses |
| `connect`, `disconnect` | The channel, without forgetting the outstation |
| `scan` | A poll by kind: `integrity`, `events`, `class0`, `class1`, `class2`, `class3`, or a group |
| `read` | Named points, by type and index, in one request: the outstation is asked and the answer returned |
| `values` | The same points from the store, with no traffic |
| `operate` | Outputs by type and index, several in one request or one request each, in the order given. `mode` is `direct`, `select` or `direct_no_ack`. Each point's status comes back |
| `freeze` | Counters, with or without clearing, with or without a response |
| `write_time`, `clear_restart` | The two writes a master makes |
| `enable_unsolicited`, `disable_unsolicited` | By class |
| `restart` | Cold or warm |
| `wait_for` | Returns when a condition on the store, an event or an indication holds, or at a timeout |
| `raw` | Sends a fragment, or a frame, exactly as given, and returns what came back |
| `deviate` | Turns a named deviation on or off |
| `trace` | The record: read it, subscribe to it, export it as a capture |
| `der.*` | The profile operations below |

A point's type is one of `bi`, `bo`, `ai`, `ao`, `counter`, `frozen`. A value
is a number or a boolean; a numeric string is accepted and converted, since
scripts that assemble requests from text send them, and anything else is
refused before a frame is built.

### The JSON service

For a caller that is not Python, or not in the same process. One JSON object
per line over a local TCP socket; the same objects over HTTP for the console,
where a request is a POST and events arrive as server-sent events.

```json
{"id": 12, "op": "read", "outstation": "lab-inverter",
 "params": {"points": {"ai": [4, 6, 8], "bi": [31, 32]}}}

{"id": 12, "ok": true, "result": {
   "indications": ["DEVICE_RESTART"],
   "points": {"ai": {"4": {"value": 50000, "flags": ["ONLINE"], "time": null}},
              "bi": {"31": {"value": true, "flags": ["ONLINE"], "time": null}}},
   "elapsed_ms": 14, "trace": [301, 302]}}

{"id": 13, "op": "operate", "outstation": "lab-inverter",
 "params": {"points": {"ao": {"87": 5000}, "bo": {"12": true}}, "mode": "direct"}}
```

A request carries an `id` the response repeats, so a caller may have several in
flight. Things that happen without being asked arrive as events on the same
connection, for a caller that subscribed: a measurement that changed, a frame
sent or received, an outstation that connected or went away, an indication that
changed.

`py1815-master serve` runs the service. A test rig starts it as a child
process, adds its outstations, and stops it with `stop`.

### What a test rig asks of a master

The API is checked against a concrete workload and not only against the
standard: a lab controller that configures a DER through a master and verifies
each setting. What that needs, and where it is met:

| Need | Met by |
|---|---|
| The master as its own process, driven over a local socket with JSON requests that carry a request identifier and name an outstation | `serve`, and the `id` and `outstation` fields |
| Start it, stop it, ask whether it is running and how each outstation stands | `serve`, `stop`, `status` |
| Add an outstation by address, port, outstation link address and master link address, with a periodic scan, and remove it | `add` with `integrity_interval`, and `remove` |
| Read a named set of analog and binary inputs by index and get their values back | `read` |
| Write a set of analog and binary outputs by index, several in one request | `operate` |
| Several writes in a fixed order: settings, then a time parameter, then a curve's selector and fields, then its points, then the enable | `operate` called in sequence, each returning before the next; or `der.write_curve` and `der.enable` |
| Read the inputs that mirror the outputs afterwards and compare | `read`, or `verify=True` on a profile write |
| A scan on demand, by kind | `scan` |
| The traffic, live, for a display | `trace` subscription |

Covering this workload is an acceptance criterion of the phase that builds the
service, with a test that plays it against the simulated DER.

## Evaluating an outstation

What makes this an evaluation tool and not only a master is that it can do the
wrong thing on request, and say exactly what it did.

| Deviation | What it shows about the outstation |
|---|---|
| Withhold a confirmation; confirm late; confirm the wrong sequence number | Whether events are retired only by the right confirmation |
| Repeat a request octet for octet | Whether a control or freeze is carried out once |
| Operate with no select; after the select timed out; with other objects; after another request | Whether the select rules hold |
| Speak from a second master address | Whether a second conversation is refused |
| Corrupt a header or body checksum; truncate a frame; send a length that contradicts the frame | Whether bad framing is met with silence |
| Break the transport sequence; send an orphan segment; send an endless series | Whether reassembly refuses what it should |
| Send a request while an unsolicited response is unconfirmed | Whether a read is held and everything else answered |
| Never confirm an unsolicited response | Whether retries stop where configured, and change no output |
| Send by broadcast | Whether it is acted on and never answered |
| Ask for a function, object or qualifier that does not exist | Whether the refusal names the right reason |
| Go silent | Whether anything happens at all |

The certification procedures and the sweep already do most of these against a
`Session`, each with its own code. The catalog gives them one name each and one
implementation, usable against a device on a bench as well as in a unit test.

**Checks.** A check is a short named procedure built from operations and
deviations, with a verdict and the trace behind it: "an integrity poll returns
every point the device profile declares", "a change of an analog input past its
deadband produces an event in its class", "a select is spent by its operate".
`py1815-master evaluate` runs a set of them against an outstation and writes a
report. The DER profile test procedure, which today runs only in process, is
the first set worth porting, because run over a socket it applies to any
IEEE 1815.2 device.

**The existing harnesses.** Each may come to use the master in place of its own
request builder and parser, one at a time, and only when the master reproduces
its exchanges octet for octet. None has to. A harness that is short and obvious
is worth something, and the certification suite's independence from new code
is worth more than tidiness.

## The DER profile

`py1815.profile` already resolves the IEEE 1815.2 point tables into a map with
names, units and multipliers, for the outstation builder. The master reads the
same map, so a script and the console can speak in the profile's terms.

| Operation | Does |
|---|---|
| `der.read` | Points by name, or a named group (nameplate, monitoring, one function), in engineering units, with quality |
| `der.write` | Outputs by name in engineering units, converted through each point's multiplier, refused if out of the point's range |
| `der.enable`, `der.disable` | A function's enable output, then the input that reports whether it is enabled |
| `der.write_curve` | A curve: the selector, its fields, its points, in the order the profile requires, then read back |
| `der.functions` | Which functions the outstation says it supports, and which are enabled |
| `der.compare` | What the outstation serves against a Device Profile document: declared and absent, served and undeclared, class and deadband as declared |

A write takes `verify=True`, which reads the mirroring input afterwards and
reports whether it matches within one step of the point's multiplier. The
functions covered are the ones the profile defines: constant power factor,
volt-var, watt-var, constant reactive power, volt-watt, frequency droop, the
active power limit, enter service, and the voltage and frequency trip curves.

## The web console

For demonstrating the software and for working at a bench. It carries the
Project Satori identity as the project's website has it: warm paper and
charcoal ink, hairline rules and square corners, a serif for headings and a
mono for anything read off the wire, teal for what is live and coral for what
needs attention, and the dark "screen" panel the site shows a device on, used
here for a frame read layer by layer. The lockup is the one in `docs/assets/`.

### Laid out the way DNP3 tools are

People who will use this have used other DNP3 test tools, and those tools agree
with each other more than they differ. The console follows the common layout
and the standard's own words, so nobody has to learn where things are.

Surveyed: the [ASE2000](https://www.ase-systems.com/products/ase2000-v2/)
communication test set, the Triangle MicroWorks
[Protocol Test Harness](https://www.trianglemicroworks.com/products/testing-and-configuration-tools/test-harness-pages/overview),
the FreyrSCADA
[DNP3 client simulator](https://www.freyrscada.com/docs/FreyrSCADA-DNP-Client-Simulator-User-Manual.pdf),
and Wireshark's DNP3 dissector. What they have in common, and what the console
takes from each:

| Convention | Where it is found | In the console |
|---|---|---|
| A tree of masters and outstations on the left, and tabs for the selected one | The simulators | The same: a list of outstations with a status lamp, tabs for the one selected |
| Tabs named for configuration, data, traffic and log | The simulators | Overview, Points, Commands, Events, Traffic, Log |
| A point list as a table by type: index, value, quality, time, class | All of them | One table per point type, with those columns and the profile's name where one is loaded |
| Values raw and scaled side by side | The test sets | Both columns, when a profile gives a multiplier |
| Station commands kept apart from point commands | The simulators | A Commands tab for the station; a command dialog opened from a point's row |
| Scans offered by class: 0, 1, 2, 3, events, integrity | All of them | The same list, in those words |
| A point command as operation, count, on time, off time and select or direct | All of them | The same fields, defaulting to latch and direct operate |
| Poll intervals per class, timeouts and unsolicited at startup as configuration | The simulators | The outstation's settings, with the task table above |
| Traffic with a time, a direction, the octets, and Clear and Save | All of them | The Traffic tab |
| Interpreted and raw side by side, where selecting a field highlights its octets | The test sets, Wireshark | The same, with link, transport and application as a tree |
| Filtering traffic by layer | The test harness, Wireshark | Layer and direction filters |
| A list of saved requests, each sent once or repeated at an interval | The test sets | A Requests list |
| Counts of messages and errors | The test sets | The Overview tab |

Words on the screen are the standard's: integrity poll, select before operate,
direct operate, latch on, trip, close, `ONLINE`, `COMM_LOST`, and each
indication by its name and its bit.

### What it shows

| Tab | Contents |
|---|---|
| **Overview** | Addresses, connection state, time of the last response, every indication as a lamp, which classes are enabled for unsolicited reporting, whether the time has been written, the task table with its intervals, and the counts |
| **Points** | A table per type: binary inputs, binary outputs, counters, frozen counters, analog inputs, analog outputs. Index, name, value raw and scaled, flags, time, class, when it last changed, and whether a poll or an event said so. Filter by name, by flag, by changed recently |
| **Commands** | Station commands: the scans, freeze, write time, clear restart, enable and disable unsolicited, restart. The result of each, as the API returned it |
| **Events** | Events in the order received, solicited and unsolicited told apart, with class and time |
| **Traffic** | Every frame, interpreted and raw, with filters, Clear, Save, and export as a capture |
| **Requests** | Saved requests: send once, or repeat at an interval |
| **DER** | With a profile loaded: nameplate, monitoring, each function with its settings and an enable switch, a curve as a plot and a table, and the comparison with a Device Profile document |
| **Evaluate** | Deviations to switch on, checks to run, the report |
| **Log** | What the master itself did and why |

Everything an outstation has reported is visible somewhere. A value the master
received and could not decode appears in Traffic with its octets and in Log
with the reason.

### How it is built

- Static files with no build step, shipped inside the package, so a wheel is
  enough to run it and the repository needs no second toolchain.
- It speaks the JSON service over HTTP and nothing else (M7, M10).
- It loads nothing from the network. The site's fonts are named and not
  fetched, so a console on a lab network asks the outside world for nothing.
- `py1815-master console` serves it. `py1815-master console --demo` also starts
  a simulated DER in the same process and connects to it, so the demonstration
  is one command, and a container image runs that command.
- Commands are disabled unless the master was started with `--allow-control`,
  and the page says which outstation a command is about to go to (M9).
- Its tests are the service's tests, since it holds no logic, plus one browser
  test that loads the demonstration and reads a value.

## Testing the master

- **Literal octets.** Every request the master builds and every object it
  decodes is pinned to octets written out by hand or published in the standard.
- **The two halves together.** A master association against a `Session`, in
  process, on one clock. Fast and exhaustive, and by the argument at the top
  not evidence that either is right.
- **Outstations this project did not write.** The interoperability jobs gain a
  direction: the master reads and commands an opendnp3 outstation and a `dnp3`
  crate outstation. This is the test that counts.
- **Dissectors.** The capture jobs already read what the outstation sends. They
  read what the master sends as well.
- **Deviations are tested as deviations.** Each one has a test showing the
  octets it changes and that nothing changes with it off.

## Work

Each item is a pull request or a short stack, and each has a statement of what
done means.

1. **Responses and objects.** `build_request`, `parse_response`, the decoders,
   the one size table. *Done when* the probe and the harnesses can use them and
   produce the octets and readings they produce now. *Built,* in `application`
   and `decode`. *Left:* moving the probe and the harnesses onto them.
2. **The association.** One request at a time, multi-fragment responses,
   confirmations, timeouts, read retries, the store. In process only. *Done
   when* an integrity poll and a class poll of the simulated DER fill the store
   with what the outstation holds. *Built,* with unsolicited responses taken
   and confirmed as well. *Left:* retrying a read.
3. **The channel.** TCP and TLS, reconnecting. *Done when* `py1815-master poll`
   does what `py1815-der poll` does, and that command is implemented with it.
   *Built:* TCP, inside `master.api`, and making again a connection that was
   lost. *Left:* TLS, retrying a first connection that could not be made, and
   the command.
4. **Controls and the rest of the requests.** Select and operate, direct
   operate, freezes, the time, the restart indication, restart. *Done when*
   every request in *Scope* has a test against a `Session` and a pinned frame.
   *Built:* `operate` in its three modes, with the rule for when a select is
   followed and a status for each control, the time write, clearing the restart
   indication, the freezes and restart, each against a session and with its
   frame pinned. *Left:* broadcast, and the delay measurement before a time
   write.
5. **Tasks and unsolicited responses.** The table in *The association*, and
   `manual=True`. *Done when* a master left alone keeps a store current through
   a restart of the outstation, and a manual one sends nothing unasked.
   *Built,* with both of those as tests over a socket: the tasks decided in
   `master.tasks` with no I/O, done by the master on a socket and by the one
   wired to a session, set for each outstation through the service and the
   command line, and shown in the console. *Left:* changing an outstation's
   tasks after it has been added, and fetching at once the events a poll left
   waiting.
6. **The API and the service.** The Python interface settled, the JSON service,
   the command line, `--allow-control`. *Done when* the workload in *What a test
   rig asks of a master* runs as a test over the socket. *Built,* for what the
   master can do so far: every reading operation, over a line socket and over
   HTTP with a route for each, described in an OpenAPI document the tests hold
   the service to; and the operations that command, refused unless the service
   is started with `--allow-control`; and every setting in one JSON file, loaded
   with `--config` and printed by `py1815-master config`. *Left:* `wait_for`, and the synchronous
   counterparts.
7. **The trace.** Recording, subscription, the capture writer moved out of
   `interop/`. *Done when* the dissector jobs read a capture the master wrote.
   *Built:* recording, reading layer by layer, subscription, and the capture
   writer, now `py1815.master.capture` and used by the sweep (D87). A trace
   exports itself as a pcap file, each connection a TCP stream of its own;
   the service's `capture` operation returns that file and the console's
   Traffic tab saves it; `--capture FILE` on `console` and `serve`, and
   `capture` in the configuration, write every frame to a file as it crosses
   the wire (D88). The parsers job reads a capture this master wrote, with
   tshark and Suricata. A master left running for days keeps bounded
   memory, rotates the capture and an optional log file by size, and logs
   every command it sends (D89). *Left:* nothing. That job's first run is in CI:
   Suricata 7.0.3 read the master's capture locally with no objection, and
   no tshark was at hand.
8. **Interoperability.** The independent outstations in CI. *Done when* both
   are read and commanded on every pull request. *Built:* an opendnp3
   outstation and a `dnp3` crate outstation, read and commanded by
   `interop/master_check.py` in two jobs of the interoperability workflow, with
   each control and the time write checked against the outstation's own log.
   It found the master reading named points with a qualifier opendnp3 rejects
   (D82). The parsers job also has the master read `interop/outstation.py`
   (its startup sequence, event and class polls, a time write, a read of
   named points, output status) and write a capture, which Wireshark's and
   Suricata's dissectors read with the master's requests and confirmations
   counted as well as the outstation's responses (`interop/master_capture.py`).
   *Left:* freezes, which neither outstation's fixture serves; and TLS.
9. **Deviations.** The catalog. *Done when* each has its test and three of the
   certification procedures have been reproduced through it over a socket.
10. **The DER profile.** Names, units, functions, curves, `verify`. *Done when*
    each function can be configured, enabled and read back by name against the
    simulated DER. *Built,* in `master.profile`, with every operation of the
    table above, `verify`, and a `der.*` service operation for each: each
    function the simulated DER implements is configured, enabled and read back
    by name over a socket, and the rig's last rows play over the line socket
    (D90 to D93). *Left:* the functions the simulated DER does not implement
    (watt-var, frequency droop, the trip curves, enter service) are found and
    written by name, and have been driven against no outstation that carries
    them out; the schedules; checking a point's event class by the events it
    produces, where the comparison now reports the declared class; and running
    the profile's operations against an independent outstation, which needs
    one that serves the profile.
11. **The console.** The layout above, the demonstration command, the image.
    *Done when* a person can add an outstation, watch its points, operate an
    output, enable a function and read the traffic without a terminal.
    *Built:* adding an outstation, its points, scans and reads, events, and
    the traffic, with `console --demo`; the profile's points an outstation has
    not reported; operating an output, the time, the restart indication and
    the freezes, when started to command; the image; and tests that load it in
    a browser; and the DER tab, with the nameplate, monitoring, each supported
    function with its settings and an enable switch, the curve as a plot and a
    table, and the comparison with a Device Profile document. *Left:* the
    Evaluate tab, and the saved requests.
12. **Checks and the report.** `evaluate`, with the DER profile procedure as
    the first set. *Done when* it runs against the simulated DER over a socket
    and its report says what the in-process procedures say.

## Sequencing

1 to 3 give a master that reads, which replaces the probe and is already
useful. 4 and 5 make it a master. 6 is where it becomes something a test rig
can adopt, and is the point to stop and use it before building more. 7 and 8
should not trail far behind 6: a master nobody independent has checked should
not be relied on for long. 9, 10 and 11 are independent of each other once 6
exists, and the console can begin against the service as soon as the service
is stable. 12 is last because it is built from all of them.

## What changes elsewhere

- The package describes itself as an outstation: in `pyproject.toml`, the
  documentation site, and the README's first lines and layer table. They change
  when phase 3 lands and there is a master to describe, and not before.
- `[project.scripts]` gains `py1815-master`, and an extra carries what the
  console's server needs.
- The release workflow asserts what the wheel and the sdist may hold. The
  master is part of the package and passes. The console's static files are not
  Python, so the workflow gains a check that they reached both.
- [DESIGN.md](../DESIGN.md)'s layering section gains the master's layers, and
  the testing section the rule about decoders.
- The container image gains a second entry point for the demonstration.

## Risks

- **It grows into a SCADA master.** Each request for history, alarms or users
  is reasonable alone. *Purpose* is the answer, and it should be pointed at.
- **Agreement mistaken for correctness.** The loopback tests will be green long
  before the independent outstations are wired in. Phase 8 is scheduled early
  for that reason.
- **A demonstration tool on a real network.** A console that can open a breaker
  is a liability if it is easy to leave reachable. M9 is the control, and it
  needs a test of its own.
- **A second language in the repository.** The console is JavaScript in a
  Python project. No build step, no logic in the page, and tests at the service
  are what keep that cost small.

## Open

- **What serves the console.** Settled: HTTP, with server-sent events for what
  happens unasked. The standard library has no WebSocket server, and a POST and
  an event stream carry everything a WebSocket would have, with no dependency
  and no protocol implementation to own (D77). So there is no extra to install.
- **Master conformance procedures.** Whether the DNP Users Group publishes test
  procedures for a master that this project can carry out as it does the
  outstation's. If so they become a phase; if not, the deviations catalog and
  the independent outstations are the evidence.
- **Whether the console belongs in this repository.** Kept here it ships with
  the master and the demonstration is one command. Kept apart it can move at
  its own pace. Here, until it is large enough to argue otherwise.
- **Analog output variations.** Which of the four the master offers by default
  for a point with no profile to say: the outstation accepts all of them and a
  device on a bench may not.
- **Synchronous interface.** Whether the blocking counterparts of the API are
  written by hand or generated from the asynchronous ones.
