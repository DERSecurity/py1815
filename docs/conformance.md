# Conformance run with dnp3c

[dnp3c](https://github.com/stepfunc/dnp3c) is a DNP3 conformance test harness from
[Step Function I/O](https://stepfunc.io). It acts as a master and runs the DNP3 IED
Level 2 outstation certification test procedures against a device. Continuous
integration runs it against this library's outstation, and this page says how each
procedure ends.

It is a second carrying-out of the certification procedures, by a tool this project did
not write. The first is [the unit suite's own](testing.md#the-certification-procedures-are-carried-out-section-by-section),
which is this project reading the procedures and checking its reading. Where the two
agree, the agreement means something. Where they do not, this page says which document
the difference turns on.

This is not a certification, and it is not a statement by Step Function I/O about this
library. It is what their tool reported when this project ran it.

## What is run

| | |
|---|---|
| Tool | dnp3c, version 0.1.0, as published on Maven Central |
| Procedures | The DNP Users Group's *DNP3 IED Certification Procedure* for Subset Level 2, as dnp3c implements it |
| Device | A Subset Level 2 configuration of this library's outstation, served over TCP on the loopback interface by `interop/conformance_outstation.py` |
| Steps a master cannot perform | Done by a plugin through the device's control channel: cycling power, changing inputs, and checking each response against what the device holds |
| Where | The `dnp3c-conformance` job of the `interop` workflow, on every pull request |

dnp3c does not say which edition of the procedure it implements. It is not version 3.1
revision 1, which the unit suite follows: its 8.6.5.3 sends a control by broadcast, a
procedure 3.1 does not have, and its 8.23 is device attributes, where 3.1 has specific
point ranges. Several of the differences below come from that. The numbers on this page
are dnp3c's, and from 8.13 on a procedure's number is often one less than in 3.1.

The device is built from the library's defaults. Three things a device built on the
library decides for itself are decided as the procedures expect: it carries out a cold
restart request, it carries out a control sent to a broadcast address
(IEEE 1815-2012 4.7), and it asks for the time again ten seconds after a master writes
it.

## How each section ends

The tables on this page are written from `interop/dnp3c/expected.json`, the record the
job compares every run with. A procedure that starts to fail, starts to pass, or stops
running fails the job until the record and this page are brought up to date.

<!-- record: sections -->
| Section | Covers | Passed | Skipped | Failed | Not implemented by dnp3c |
|---|---|---|---|---|---|
| 6.1 | Link reset and confirmation | 6.1.2 |  |  |  |
| 6.3 | Link status request | 6.3.2 |  |  |  |
| 6.4 | Link retries |  | 6.4.2 |  |  |
| 6.5 | Direction and frame count bits | 6.5.2 |  |  |  |
| 6.6 | Invalid link frames | 6.6.2.1 to 6.6.2.5 | 6.6.3.1 to 6.6.3.4 |  |  |
| 6.7 | Self-address |  | 6.7.2 |  |  |
| 7.2 | Transport segmentation | 7.2 |  |  |  |
| 8.1 | Binary output status | 8.1.2 |  |  |  |
| 8.2 | Binary output controls | 8.2.1.2.1 to 8.2.1.2.15, 8.2.2.2.1 to 8.2.2.2.3, 8.2.3.2.1 to 8.2.3.2.3, 8.2.4.2, 8.2.5.2.1, 8.2.5.2.2 |  |  |  |
| 8.3 | Analog output status | 8.3.2 |  |  |  |
| 8.4 | Analog output controls | 8.4.1.2.1 to 8.4.1.2.12, 8.4.2.2.1 to 8.4.2.2.3, 8.4.3.2.1 to 8.4.3.2.3, 8.4.4.2 |  |  |  |
| 8.5 | Class data | 8.5.1.2, 8.5.2.2.1 to 8.5.2.2.4, 8.5.3.2.1 to 8.5.3.2.4, 8.5.4.2.1 to 8.5.4.2.4, 8.5.5.2.1, 8.5.5.2.2, 8.5.6.2 |  |  |  |
| 8.6 | Internal indications | 8.6.1.2, 8.6.2.2, 8.6.3.2, 8.6.5.3, 8.6.6.2.1 | 8.6.4.2, 8.6.4.3, 8.6.6.2.2 to 8.6.6.2.4 | 8.6.5.2, 8.6.5.4 |  |
| 8.7 | Time | 8.7.1.2, 8.7.2.2 |  |  |  |
| 8.8 | Cold restart | 8.8.2 |  |  |  |
| 8.9 | Fragmentation | 8.9.1.2, 8.9.2.2 |  |  |  |
| 8.10 | Multi-drop |  |  |  | 8.10.2 |
| 8.11 | Unsolicited responses | 8.11.2.2 to 8.11.2.5 |  | 8.11.2.1, 8.11.2.6 |  |
| 8.12 | Collision avoidance |  |  |  | 8.12.2 |
| 8.13 | Binary inputs | 8.13.2.2, 8.13.2.3 | 8.13.2.1 |  |  |
| 8.14 | Binary input events | 8.14.2.2 to 8.14.2.8, 8.14.2.12 to 8.14.2.15 | 8.14.2.1 | 8.14.2.9 to 8.14.2.11 |  |
| 8.15 | Common time of occurrence | 8.15.2 |  |  |  |
| 8.16 | Counters and frozen counters | 8.16.1.2.2, 8.16.1.2.3, 8.16.2.2.2 to 8.16.2.2.5 | 8.16.1.2.1, 8.16.2.2.1 |  |  |
| 8.17 | Counter events | 8.17.2.1 | 8.17.2.2 to 8.17.2.5 |  |  |
| 8.18 | Analog inputs | 8.18.2.2 | 8.18.2.1 |  |  |
| 8.19 | Analog input events | 8.19.2.1, 8.19.2.2 |  |  |  |
| 8.20 | Several object headers in one read | 8.20.2 |  |  |  |
| 8.21 | Double-bit inputs |  | 8.21.2.1, 8.21.2.2 |  |  |
| 8.22 | Double-bit input events |  | 8.22.2.2 to 8.22.2.15 | 8.22.2.1 |  |
| 8.23 | Device attributes |  | 8.23.2.1 to 8.23.2.4 |  |  |
<!-- end -->

## Procedures that fail

Each of these fails every run, and is on record as failing. None is skipped, and no
option is turned off to avoid one.

<!-- record: failed -->
| Procedure | What happens, and which document it turns on |
|---|---|
| 8.6.5.2, 8.6.5.4 | The procedure broadcasts a write as confirmed user data and expects it carried out. The outstation carries out a broadcast sent as unconfirmed user data, which is the function IEEE 1815-2012 9.2.4.1.3.6 and TB2013-002 have a master use for one, and drops a broadcast that asks for a link confirmation (D50). The same write sent as unconfirmed user data is carried out. Version 3.1 revision 1 of the certification procedure repeats the broadcast without the link confirmation for a device that does this; dnp3c does not. |
| 8.11.2.1 | Step 24 reads class 0 while the initial null unsolicited response is unconfirmed, and waits the response timeout for the answer. The outstation holds a read until that response is confirmed or its confirmation times out, then answers it and sends the null response again, as rule 16 of TB2015-002a and Table 6-1 of IEEE 1815-2012 have it (D71). The answer comes at the unsolicited confirmation timeout, which is later than dnp3c waits. dnp3c lists this step among its known limitations. |
| 8.11.2.6 | With unsolicited responses configured off, the procedure expects a request to disable them to be refused as an unsupported function. The outstation agrees to it, since a device that sends none is already in the state the request asks for. This is a deliberate departure from the procedure (D21). |
| 8.14.2.9 to 8.14.2.11 | The procedure reads binary input events with absolute time before any time has been written, and expects them in that variation. The outstation sends an event stamped by a clock nobody has set with relative time, behind a common time of occurrence that says the clock was not synchronized (TB2017-003, D60). Version 3.1 revision 1 of the certification procedure, section 8.14.1, gives that answer for this case. |
| 8.22.2.1 | The procedure reads double-bit input events from a device that has none and expects a null response with no error indication. The outstation answers with a null response and IIN2.1, object unknown. Version 3.1 revision 1 of the certification procedure, section 8.22.1, allows IIN2.1 or IIN2.2 there. |
<!-- end -->

Of these, the departure in 8.11.2.6 is this library's own choice, recorded as D21 in
[Design decisions](DESIGN.md). In 8.11.2.1 the outstation does what a technical
bulletin requires and dnp3c says so in its own list of limitations. In the others the
outstation's answer is one that version 3.1 revision 1 of the procedure accepts, and
dnp3c expects another.

## Procedures that are skipped

dnp3c skips a procedure when an option says the device does not have the feature it
tests. Each option that is off, and the reason:

<!-- record: options -->
| Option turned off | Why | Procedures skipped for it |
|---|---|---|
| `supports.analogEventsQueuedPerPoint` | An analog input keeps one event, its newest. | 8.6.6.2.2 |
| `supports.analogOutputChangeEvents` | Analog output events are not offered. | none |
| `supports.binaryOutputChangeEvents` | Binary output events are not offered. | none |
| `supports.counterChangeEvents` | A counter reports no change events. | 8.6.6.2.3, 8.17.2.2 to 8.17.2.5 |
| `supports.counterEventsQueuedPerPoint` | A counter reports no change events, so none are queued. | none |
| `supports.dataLinkConfirmRequests` | The outstation never requests data link confirmation. | 6.4.2, 6.6.3.1 to 6.6.3.4 |
| `supports.dataLinkRetries` | The outstation never requests data link confirmation, so it has nothing to send again. | none |
| `supports.deviceAttributes` | Device attributes are not served. | 8.23.2.1 to 8.23.2.4 |
| `supports.disable.doubleBit` | The outstation has no double-bit binary inputs to disable. | none |
| `supports.doubleBit` | The outstation has no double-bit binary inputs. | 8.6.6.2.4, 8.21.2.1, 8.21.2.2, 8.22.2.2 to 8.22.2.15 |
| `supports.doubleBitChangeEvents` | The outstation has no double-bit binary inputs, so none report events. | none |
| `supports.frozenCounterChangeEvents` | Held to Subset Level 2, a freeze buffers no event. | none |
| `supports.globalRemoteSupervisoryControl` | Outputs have no local state, so no switch puts them all in it. | 8.6.4.2 |
| `supports.individualRemoteSupervisoryControl` | Outputs have no local state. | 8.6.4.3 |
| `supports.noClassAssignment` | Assign class is not implemented. A point's class is fixed when the outstation is built. | none |
| `supports.selfAddress` | The outstation does not answer the self-address. | 6.7.2 |
<!-- end -->

It also skips a procedure written for a device without a feature, when the device has
it:

<!-- record: without -->
| Procedure | For a device where this is off |
|---|---|
| 8.13.2.1 | `supports.binaryInput` |
| 8.14.2.1 | `supports.binaryInputChangeEvents` |
| 8.16.1.2.1 | `supports.counter` |
| 8.16.2.2.1 | `supports.frozenCounter` |
| 8.18.2.1 | `supports.analog` |
<!-- end -->

## Procedures dnp3c does not implement

<!-- record: not-implemented -->
8.10.2, 8.12.2
<!-- end -->

dnp3c's report shows them struck through. The unit suite
carries out multi-drop support itself, and collision avoidance does not apply to an
outstation that has no serial port.

## What dnp3c does not cover

dnp3c has no procedure for some sections the unit suite carries out from version 3.1
revision 1: a control that arrives with a status already set, 32-bit analog output
values, time set by recording the current time, specific point ranges and specific
variations, the refusal of assign class, the procedures for TCP, and the absence of
output events. `tests/test_ied_coverage.py` lists every section of that version with
the tests that carry it out, or the reason it does not apply.

## Seeing a run

The job keeps dnp3c's whole output as the `dnp3c-conformance-results` artifact of the
workflow run, whether the run passed or not:

- `report.html` is dnp3c's report, with every procedure and its result.
- Each procedure's directory holds `log.html`, with every step, every frame sent and
  received decoded at each layer, and every check; and `dump.pcap`, the procedure's
  traffic, which opens in Wireshark.
- `outstation.log` is the device's own log.

The report is not kept in the repository. It would go out of date with the next change
to the library, and the record above is what is held to each run.

To run it yourself, see
[`interop/dnp3c/README.md`](https://github.com/DERSecurity/py1815/blob/main/interop/dnp3c/README.md).
It needs Java 17 or newer, Maven, and a Python with this library installed.

## The tool's license

dnp3c is licensed under the
[GNU General Public License v3.0 only](https://github.com/stepfunc/dnp3c/blob/main/LICENSE).
The plugin that drives it is a separate program in `interop/dnp3c/` that links the
tool's library and is used only in this repository's tests. Nothing of the tool or the
plugin is in the library, its wheel or its source distribution.
