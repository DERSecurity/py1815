# Conformance run with dnp3c

[dnp3c](https://github.com/stepfunc/dnp3c) is a DNP3 conformance test harness from
[Step Function I/O](https://stepfunc.io). It acts as a master and runs the outstation
test procedures of the DNP Users Group's *DNP3 IED Certification Procedure* against a
device. Continuous integration runs it against this library's outstation, and this page
says how each procedure ends.

Every procedure that runs passes. None passes with a warning, none is excluded, and no
option is turned off to avoid a failure. The report the tool writes is kept in
[`compliance/`](https://github.com/DERSecurity/py1815/tree/main/compliance).

It is a second carrying-out of the certification procedures, by a tool this project did
not write. The first is [the unit suite's own](testing.md#the-certification-procedures-are-carried-out-section-by-section),
which is this project reading the procedures and checking its reading. Where the two
agree, the agreement means something. Where they did not, the difference was settled from
the documents, and this page says how.

This is not a certification, and it is not a statement by Step Function I/O about this
library. It is what their tool reported when this project ran it.

## What is run

| | |
|---|---|
| Tool | dnp3c, version 0.2.0, as published on Maven Central |
| Procedures | Revision 3.1 rev 1 (13 September 2022), at Subset Level 2 |
| Device | A Subset Level 2 configuration of this library's outstation, served over TCP on a loopback address of its own by `interop/conformance_outstation.py` |
| Steps a master cannot perform | Done by a plugin through the device's control channel: cycling power, changing inputs and flags, setting up the network, and checking each response against what the device holds |
| Where | The `dnp3c-conformance` job of the `interop` workflow, on every pull request. The `interop` gate waits for it, so a pull request does not merge while it fails |

The device is built from the library's defaults. A few things a device built on the
library decides for itself are decided as the procedures expect:

- It carries out a cold restart request, and can be set not to, without a restart.
- It carries out a control sent to a broadcast address (IEEE 1815-2012 4.7), and takes
  broadcasts sent as UDP datagrams beside its TCP connection (13.2.3.2).
- It asks for the time again ten seconds after a master writes it, and stops trusting its
  clock twenty seconds after the write, as a clock that drifts does (D60).

Before each procedure the counters are frozen once, as an operator would before testing,
so that a frozen counter holds a value. Flags are set abnormal through the point's source:
the test bench marks an input's or an output's source as having lost communication, and
a frozen counter carries its counter's flags from the freeze.

## How each section ends

The tables on this page are written from `interop/dnp3c/expected.json`, the record the
job compares every run with. A procedure that starts to fail, starts to pass, stops
running, or passes with a new warning fails the job until the record and this page are
brought up to date.

<!-- record: sections -->
| Section | Covers | Passed | Skipped | Failed |
|---|---|---|---|---|
| 6.1 | Reset Link and Passive Confirm support | 6.1.2 |  |  |
| 6.3 | Request Link Status | 6.3.2 |  |  |
| 6.4 | Test Retries |  | 6.4.2 |  |
| 6.5 | DIR and FCV Bits | 6.5.2 |  |  |
| 6.6 | Data Link Rejects Invalid Frames | 6.6.2a to 6.6.2c, 6.6.2e, 6.6.2f | 6.6.2d, 6.6.3a to 6.6.3d |  |
| 6.7 | Self-Address Support |  | 6.7.2 |  |
| 7 | Transport Layer | 7.2 |  |  |
| 8.1 | Binary Output Status | 8.1.2 |  |  |
| 8.2 | Binary Outputs | 8.2.1.2.1 to 8.2.1.2.15, 8.2.2.2.1 to 8.2.2.2.3, 8.2.3.2.1 to 8.2.3.2.3, 8.2.4, 8.2.5.2.1, 8.2.5.2.2, 8.2.6 |  |  |
| 8.3 | Analog Output Status | 8.3.2 |  |  |
| 8.4 | Analog Outputs | 8.4.1.2.1 to 8.4.1.2.13, 8.4.2.2.1 to 8.4.2.2.3, 8.4.3.2.1 to 8.4.3.2.3, 8.4.4 |  |  |
| 8.5 | Class Data | 8.5.1, 8.5.2.2.1 to 8.5.2.2.4, 8.5.3.2.1 to 8.5.3.2.4, 8.5.4.2.1 to 8.5.4.2.4, 8.5.5.2.1, 8.5.5.2.2, 8.5.6 |  |  |
| 8.6 | Indications | 8.6.1 to 8.6.3, 8.6.5a, 8.6.5b, 8.6.6.2.1 | 8.6.4a, 8.6.4b, 8.6.6.2.2 to 8.6.6.2.4 |  |
| 8.7 | Time | 8.7.1.1.2, 8.7.1.2.2, 8.7.2 |  |  |
| 8.8 | Cold Restart | 8.8.2 |  |  |
| 8.9 | Application Layer Fragmentation | 8.9.1, 8.9.2 |  |  |
| 8.10 | Multi-Drop Support |  | 8.10.2 |  |
| 8.11 | Unsolicited Responses | 8.11.2.5, 8.11.2a to 8.11.2e |  |  |
| 8.12 | Collision Avoidance |  | 8.12.2 |  |
| 8.13 | Binary Inputs Specific Object Requests | 8.13.2c, 8.13.2d | 8.13.2a, 8.13.2b |  |
| 8.14 | Binary Input Change Specific Requests | 8.14.2c to 8.14.2p | 8.14.2a, 8.14.2b |  |
| 8.15 | Common Time of Occurrence | 8.15.2, 8.15.3 |  |  |
| 8.16 | Binary Counters Specific Object Requests | 8.16.1.2.3, 8.16.1.2.4, 8.16.2.2.3 to 8.16.2.2.6 | 8.16.1.2.1, 8.16.1.2.2, 8.16.2.2.1, 8.16.2.2.2 |  |
| 8.17 | Binary Counters, Event | 8.17.2b | 8.17.2a, 8.17.2c to 8.17.2f |  |
| 8.18 | Analog Input | 8.18.2c | 8.18.2a, 8.18.2b |  |
| 8.19 | Analog Change Event | 8.19.2.4, 8.19.2b, 8.19.2c | 8.19.2a |  |
| 8.20 | Multiple Read Requests | 8.20.2b | 8.20.2a |  |
| 8.21 | Double-bit Inputs | 8.21.1, 8.21b | 8.21a, 8.21c, 8.21d |  |
| 8.22 | Double-bit Input Change | 8.22.1, 8.22b | 8.22a, 8.22c to 8.22p |  |
| 8.23 | Specific Point Ranges | 8.23.2.1.1 to 8.23.2.1.3, 8.23.2.2.1 to 8.23.2.2.3, 8.23.2.3.1 to 8.23.2.3.3, 8.23.2.4.1 to 8.23.2.4.3, 8.23.2.5.1 to 8.23.2.5.3, 8.23.2.6.1 to 8.23.2.6.3 |  |  |
| 8.24 | Specific variations for Static Inputs | 8.24.2a to 8.24.2g |  |  |
| 8.25 | Specific Variations for Events | 8.25.2a to 8.25.2e |  |  |
| 8.26 | Assign Class | 8.26.2 | 8.26.3 |  |
| 9.5 | Network: All Communication Methods | 9.5.1.1.2, 9.5.1.2.2, 9.5.1.5.2 | 9.5.1.3.2, 9.5.1.4.2, 9.5.1.6.2, 9.5.2.1.2, 9.5.2.2.2, 9.5.2.3.2, 9.5.2.4.2, 9.5.2.5.2, 9.5.3.1.2, 9.5.3.2.2, 9.5.3.3.2, 9.5.3.4.2, 9.5.3.5.2, 9.5.4 |  |
| 10.3 | Output Control Events: Binary |  | 10.3.2 to 10.3.4 |  |
| 10.4 | Output Control Events: Analog |  | 10.4.2 to 10.4.4 |  |
<!-- end -->

## Procedures that fail

<!-- record: failed -->
None.
<!-- end -->

## Procedures that are excluded

<!-- record: excluded -->
None.
<!-- end -->

## Procedures that pass with a warning

dnp3c warns on a pass where the device should probably change something, for instance
where it complies with IEEE 1815-2012 but not with IEEE 1815-202x.

<!-- record: warnings -->
None.
<!-- end -->

## What the run settled

Each of these ended differently in an earlier run, and was settled from the documents.

- **A read while an unsolicited response is unconfirmed** (8.11.2a). The outstation holds
  the read until the confirmation arrives or its timeout expires, as 3.1 rev 1's 8.11.1
  and IEEE 1815-2012 rule 16 have it (D71). dnp3c used to wait only the response timeout.
  It now waits the unsolicited confirm timeout too.
- **Counter reads in other variations** (8.24.2d). The outstation now answers a 16-bit or
  flagless counter read at 32 bits with flags, as 8.24.2 allows a device that keeps 32-bit
  values, where it refused the read (D100).
- **Frozen counters a device lacks** (8.23.2.4.1). An outstation whose counters do not
  freeze refuses a read of group 21 with IIN2.1, where it answered with nothing (D100).
- **A disable request with unsolicited responses off** (8.11.2). The outstation now refuses
  it with IIN2.0 (D21).
- **A broadcast sent as confirmed user data** (8.6.5). The outstation now acts on it
  (D50).
- **Events with time before the time is written** (8.14.2j to 8.14.2l), and **the error
  indication from a device without double-bit inputs** (8.21, 8.22). The outstation's
  answers were already the ones 3.1 rev 1 gives, and dnp3c now accepts them.

## Procedures that are skipped

dnp3c skips a procedure when an option says the device does not have the feature it
tests. Each option that is off, and the reason:

<!-- record: options -->
| Option turned off | Why | Procedures skipped for it |
|---|---|---|
| `network.tcp.multicast` | The outstation joins no multicast group. | 9.5.1.6.2 |
| `network.tcp.specificAddress` | The outstation accepts a connection from any master and keeps no list of masters. | 9.5.1.3.2 |
| `network.tcp.wildcard` | The outstation keeps no list of masters, so no range of them either. | 9.5.1.4.2 |
| `network.udp` | The outstation answers requests over TCP only. It takes broadcasts as UDP datagrams beside TCP, and nothing else over UDP. | 9.5.2.1.2, 9.5.2.2.2, 9.5.2.3.2, 9.5.2.4.2, 9.5.2.5.2 |
| `network.udp.unsolicited` | The outstation sends unsolicited responses over TCP only. | 9.5.3.1.2, 9.5.3.2.2, 9.5.3.3.2, 9.5.3.4.2, 9.5.3.5.2, 9.5.4 |
| `serial.enabled` | The outstation is reached over TCP. This library has no serial link. | 6.6.2d, 8.10.2, 8.12.2 |
| `supports.analogInputEventsQueuedPerPoint` | An analog input keeps one event, its newest. | 8.6.6.2.2 |
| `supports.analogOutputChangeEvents` | Analog output events are not offered. | 10.4.2, 10.4.3 |
| `supports.analogOutputCommandEvents` | Analog output events are not offered. | 10.4.2, 10.4.4 |
| `supports.assignNoClass` | Assign class is not implemented. A point's class is fixed when the outstation is built. | none |
| `supports.binaryOutputChangeEvents` | Binary output events are not offered. | 10.3.2, 10.3.3 |
| `supports.binaryOutputCommandEvents` | Binary output events are not offered. | 10.3.2, 10.3.4 |
| `supports.counterChangeEvents` | A counter reports no change events. | 8.6.6.2.3, 8.17.2c to 8.17.2f |
| `supports.counterEventsQueuedPerPoint` | A counter reports no change events, so none are queued. | none |
| `supports.dataLinkConfirmRequests` | The outstation never requests data link confirmation. | 6.4.2, 6.6.3a to 6.6.3d |
| `supports.dataLinkRetries` | The outstation never requests data link confirmation, so it has nothing to send again. | none |
| `supports.deviceAttributes` | Device attributes are not served. | none |
| `supports.disable.doubleBitInput` | The outstation has no double-bit binary inputs to disable. | none |
| `supports.doubleBitInput` | The outstation has no double-bit binary inputs. | 8.6.6.2.4, 8.21c, 8.21d, 8.22c to 8.22p |
| `supports.doubleBitInputChangeEvents` | The outstation has no double-bit binary inputs, so none report events. | none |
| `supports.frozenCounterChangeEvents` | Held to Subset Level 2, a freeze buffers no event. | none |
| `supports.globalRemoteSupervisoryControl` | Outputs have no local state, so no switch puts them all in it. | 8.6.4a |
| `supports.individualRemoteSupervisoryControl` | Outputs have no local state. | 8.6.4b |
| `supports.multipleAddresses` | The outstation answers to one link address. | 6.6.2d |
| `supports.selfAddress` | The outstation does not answer the self-address. | 6.7.2 |
<!-- end -->

It also skips a procedure written for a device without a feature, when the device has
it:

<!-- record: without -->
| Procedure | Skipped because |
|---|---|
| 8.13.2b | `supports.binaryInput != false` |
| 8.14.2b | `it needs not (supports.binaryInput == true and supports.binaryInputChangeEvents == true)` |
| 8.16.1.2.2 | `supports.counter != false` |
| 8.16.2.2.2 | `supports.frozenCounter != false` |
| 8.18.2b | `supports.analogInput != false` |
<!-- end -->

And it skips the procedures written for another subset level:

<!-- record: levels -->
| Procedure | Skipped because |
|---|---|
| 8.13.2a, 8.14.2a, 8.16.1.2.1, 8.16.2.2.1, 8.17.2a, 8.18.2a, 8.19.2a, 8.20.2a, 8.21a, 8.22a | it applies to subset level(s) 1, and the device is configured for level 2 |
| 8.26.3 | it applies to subset level(s) 3, and the device is configured for level 2 |
<!-- end -->

## Procedures dnp3c does not implement

<!-- record: not-implemented -->
None.
<!-- end -->

## Seeing a run

[`compliance/`](https://github.com/DERSecurity/py1815/tree/main/compliance) keeps the
report of the run on record: `report.html`, and each procedure's `log.html` with every
step, every frame sent and received decoded at each layer, and every check. A test holds
its outcomes to the record above.

The job also keeps a run's whole output as the `dnp3c-conformance-results` artifact of
the workflow run, whether the run passed or not, with each procedure's `dump.pcap`, its
traffic, which opens in Wireshark, and `outstation.log`, the device's own log.

To run it yourself, see
[`interop/dnp3c/README.md`](https://github.com/DERSecurity/py1815/blob/main/interop/dnp3c/README.md).
It needs Java 17 or newer, Maven, and a Python with this library installed.

## The tool's license

dnp3c is licensed under the
[GNU General Public License v3.0 only](https://github.com/stepfunc/dnp3c/blob/main/LICENSE).
The plugin that drives it is a separate program in `interop/dnp3c/` that links the
tool's library and is used only in this repository's tests. The report in `compliance/`
is the tool's output and carries its text, so it is licensed the same way. Nothing of the
tool, the plugin or the report is in the library, its wheel or its source distribution.
