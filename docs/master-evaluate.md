# Evaluating an outstation

`py1815-master evaluate` connects to an IEEE 1815.2 DER outstation, runs a list of
checks against it, and prints a verdict for each. A check is a short procedure a
controlling station would carry out: read a function's points, write its settings and
read them back, enable and disable it, edit a curve. The same checks run against a device
on a bench and against the simulated DER.

```bash
py1815-master evaluate --outstation lab=192.0.2.10:20000
```

```text
lab at 192.0.2.10:20000, outstation 1024, 2026-10-09T16:39:39+00:00, read only
profile tables: IEEE Std 1815.2-2025

PROFILE-001  not applicable  Device Profile agrees with what is served
             no Device Profile document was given
MON-001      passed          Monitoring
             note: 24 of the meter's 24 points are served
ALARM-001    passed          Alarm reporting
             note: 22 of the 22 alarm points are served
OP-001       passed          Operating states
CONN-001     not run         Connect and disconnect
             it writes to the outstation, and the run was not allowed to
...

35 checks: 3 passed, 1 not applicable, 31 not run
```

The command needs the IEEE 1815.2 profile tables, which name the points and say how they
are paired. See [Serving a DER](der.md#where-the-tables-come-from) for how to get them.

!!! warning "A run with `--allow-control` changes the outstation"
    Without `--allow-control` the command only reads. With it, the checks write settings,
    enable and disable functions, write curves, open and close the connect switch, and
    stop and start the DER. Use it on a device on a bench, not on one in service. See
    [What a run leaves behind](#what-a-run-leaves-behind).

## Verdicts

| Verdict | Meaning |
|---|---|
| `passed` | The outstation did everything the check requires |
| `FAILED` | The outstation did something the check does not allow. The next line says what |
| `not applicable` | The outstation does not serve what the check needs |
| `not run` | The check writes and the run was read only, the check has the master break a protocol rule and the run was not allowed to, or the connection was lost earlier |

A `note` line is something the check saw that does not decide the verdict: how many of a
block's points are served, an alarm that was raised when read, a refusal with an unusual
status.

The exit status is 0 when no check failed, 1 when one did, and 2 when the run could not
be made: a setting that cannot be used, no tables, no connection, or no answer.

## The checks

`py1815-master evaluate --list` prints them, each with its set and whether it reads,
writes or deviates. `--check NAME` runs one check or one set, and may be repeated.

The `der` set carries out EPRI's *Test Procedure for Validating DNP Application Note
AN2018-001 in Distributed Energy Resources* (report 3002016144). Each check is named for
the identifier the report gives its procedure. The report was written for the application
note that IEEE 1815.2 replaced; where the two differ, the checks follow the standard.

| Check | Writes | What it requires |
|---|---|---|
| `MON-001` | no | Every served point of the system meter is ONLINE and inside the range the tables give |
| `ALARM-001` | no | Every served alarm is ONLINE |
| `OP-001` | no | Every served operating state is ONLINE; started and stopped are not both set; and no more than one of BI18 to BI22 is set, with exactly one required when the outstation serves all five |
| `CONN-001` | yes | The connect settings read back what was written, and the switch status follows a command to open and to close |
| `SERV-001` | yes | The service settings read back, each permission follows its command, and a stop and a start are carried out and reported |
| `SERV-001.2`, `SERV-001.3` | yes | A start, or a stop, is refused while its permission is withdrawn, and the DER stays as it was |
| `CURVE-001` | yes | The referenced indicator is clear for a curve no function names and set once one does |
| `CURVE-001.2` | yes | A curve beyond the last one stored cannot be selected |
| `CURVE-002` | yes | A curve named by an enabled function cannot be edited, another curve can, and disabling the function releases it |
| `CURVE-002.2` | yes | An enabled function can be pointed at another curve, which frees the one it left |
| `CURVE-003` | yes | A function cannot be pointed at a curve of a type it does not follow, and such a curve cannot change type under it |
| `CURVE-003.2` | yes | A function cannot be pointed at a curve with no type, or at one that does not exist |
| `VRT-001` to `PSIG-001` | yes | One check for each of the 21 functions, by the binary output that enables it. See below |

Each function check first reads the input that says whether the outstation supports the
function, and the report's title says which it found.

- **Supported.** The function's inputs carry values and no ONLINE flag while it is
  disabled. Its settings are written and read back. It is enabled, and its inputs become
  ONLINE. Its settings and switches are written twice more with different values and read
  back each time, and a volt-var or volt-watt function is given a curve. It is disabled
  again, and its inputs lose the ONLINE flag.
- **Not supported.** The enable output refuses a command, and the outstation serves none
  of the function's points.

The `device-profile` set has one check, `PROFILE-001`. It compares what the outstation
serves with its DNP3 Device Profile document, given with `--device-profile FILE`: a point
declared and not served, served and not declared, or in class 0 when the document says
otherwise fails it.

### The deviation set

The `deviation` set has the master break a protocol rule on purpose and requires what the
standard requires of the outstation in return. These checks write nothing to the
outstation. They are run only with `--allow-deviations`, and are reported as `not run`
without it.

```bash
py1815-master evaluate --outstation lab=192.0.2.10:20000 --check deviation --allow-deviations
```

!!! warning "A run with `--allow-deviations` sends the outstation malformed traffic"
    The checks send frames with bad checksums and wrong lengths, segments out of place,
    and withhold confirmations the outstation asked for. An outstation that conforms
    discards the frames and reports its events again. Use it on a device on a bench.

| Check | What the master does | What it requires |
|---|---|---|
| `LINK-001` | Sends a read in a frame whose header checksum is wrong | No answer |
| `LINK-002` | Sends a read in a frame whose data checksum is wrong | No answer |
| `LINK-003` | Sends a read in a frame with its last octet missing | No answer |
| `LINK-004` | Sends a read in a frame whose length octet claims more than the frame carries | No answer |
| `TRANSPORT-001` | Sends a read as a segment that is not a first segment | No answer, and the next read is answered |
| `TRANSPORT-002` | Sends a read whose final segment never comes | No answer, and the next read, which begins a new series, is answered |
| `CONFIRM-001` | Reads the events and sends no confirmation | The same events are reported again |
| `CONFIRM-002` | Reads the events and confirms the wrong sequence number | The same events are reported again |
| `CONFIRM-003` | Reads the events and sends the confirmation after its next request | The same events are reported again |

The sources:

- **A frame with a bad checksum.** IEEE 1815-2012 9.2.4.3 has the checksums checked so
  that only valid data pass up from the data link layer, and the invalid CRC procedure of
  section 6.6.2 of the DNP Users Group's IED Certification Procedure requires that such a
  frame draws no link confirmation and no response.
- **A segment out of place.** IEEE 1815-2012 8.2.4, Table 8-1, as Technical Bulletin
  TB2013-003 restates it: a segment that is not a first segment is discarded while no
  fragment is being assembled, and a first segment replaces a series under way.
- **Events and confirmations.** IEEE 1815-2012 Table 6-1: a confirmation that does not
  match is discarded and no events are removed, and a request that arrives in place of a
  confirmation means the confirmation failed. Sections 8.5.2.2.4, 8.5.3.2.4 and 8.5.4.2.4
  of the certification procedure read class data without confirming it and require the
  same events again.

Each link and transport check first sends a well-formed read, which has to be answered,
so that the silence that follows is about the damaged request. Afterwards it sends
well-formed reads until one is answered. A frame that was cut short can take the start of
the next frame with it, so after a link check up to three reads are sent, and the report
notes when the first was not the one answered. After a transport check the first read
has to be answered.

A read that has to go unanswered is waited for as long as any other: the response
timeout, times the read retries plus one. Each of these checks takes that long at least.

The three event checks work on the events the outstation has when the check begins, and
are `not applicable` when it has none. After the events are reported again, they are read
once more with a confirmation and must not be reported after that. Events that carry no
time cannot be told from later events at the same point, so for those the last step is
skipped and noted. A master set to send no confirmations cannot run these checks.

A check of this set begins with every deviation of the master off, so that one left on
does not damage the well-formed reads the check compares against. It also holds the
master until it ends: no automatic task, repeated scan or other caller sends that
outstation a request while the check runs, so none is damaged by the check's deviation
and none comes between its steps. Whatever deviations were on before the check are on
again when it ends, and the same is so for a run that is cancelled part way.

Two events can be equal in every field. An event that was reported twice has to be
reported twice again.

### What counts as supported

The run begins by reading which points the outstation serves: a class 0 read, a read of
output status, and a read by range of every other point of the profile. These reads are
made with every deviation of the master off. A point is
supported when one of those reads returned it. A check reads only served points, and is
not applicable when the points it is about are not served.

### What a refusal has to be

Where a command is to be refused, the check requires that it is not accepted and that
nothing changed. The status it is refused with is the outstation's to choose: one other
than the usual status is reported as a note.

### Waiting

A device takes time to stop, to close a switch, or to report a new setting. Where a check
waits for one of these it reads again every half second for up to the settling time, 5
seconds unless `--settle` says otherwise, and fails with the last thing it read.

### Curves

The number of curves an outstation stores is its own. The run finds it by selecting each
curve in turn until one is refused, up to 64. `--curves N` states it instead, and then
`CURVE-001.2` checks that curve N + 1 is refused.

Sample curves are written for the volt-var and volt-watt functions. A function that
follows another kind of curve has its other settings checked, and its curve setting is
left unwritten and noted.

## What a run leaves behind

A check puts back what one command restores, as it found it: the connect switch, the two
permissions, and whether the DER is started. Settings and curves stay as the check last wrote them. Every
function a check enabled is disabled when the check ends, including a function that was
enabled when the run began, which the report notes. No function names a curve afterwards.

When something cannot be put back, the report says so in a note on that check.

## The report and the traffic

`--report FILE` also writes the report as JSON:

```json
{
  "tool": "py1815-master evaluate",
  "version": "0.2.0",
  "outstation": "lab at 192.0.2.10:20000, outstation 1024",
  "started": "2026-10-09T16:39:39+00:00",
  "allow_control": true,
  "allow_deviations": false,
  "tables": "IEEE Std 1815.2-2025",
  "summary": {"passed": 34, "failed": 0, "not_applicable": 1, "not_run": 0},
  "results": [
    {
      "id": "SERV-001",
      "title": "Cease to energize and return to service",
      "verdict": "passed",
      "detail": "",
      "notes": ["the stop was seen under way", "the start was seen under way"],
      "requests": 90,
      "seconds": 1.61,
      "frames": [318, 551],
      "packets": [321, 554]
    }
  ]
}
```

`--capture FILE` writes every frame of the run to a pcap file, as it does for the
console. `packets` is the first and last packet of a check in that file, by the number
Wireshark shows for each. It is `null` when no capture is written. The printed report
gives the same range for a check that failed, so the exchange that failed it can be
found.

`frames` counts DNP3 frames from 1 in the order they crossed the wire, as the master's
trace does. A capture also holds each connection's TCP handshake, so a frame's number is
not its packet's.

## Settings

Every setting is also in the [configuration file](master-config.md), under `evaluate`,
and the outstation's address, link addresses, TLS files and timeouts come from the file
or the same flags the console takes.

```bash
py1815-master evaluate lab --config master.json --allow-control \
    --check der --report lab.json --capture lab.pcap
```

| Flag | Setting | Meaning |
|---|---|---|
| `NAME` | | The outstation to evaluate, when the configuration has more than one |
| `--list` | | Print the checks and exit. Nothing is sent |
| `--check NAME` | `evaluate.checks` | Run only this check or set. May be repeated, and replaces the list in the file. All of them when not given |
| `--settle SECONDS` | `evaluate.settle` | How long to wait for the outstation to reach a state it was commanded to. 5 when not given |
| `--curves N` | `evaluate.curves` | How many curves the outstation stores. Found by selecting each when not given |
| `--report FILE` | `evaluate.report` | Also write the report as JSON |
| `--allow-control` | `allow_control` | Run the checks that write |
| `--allow-deviations` | `evaluate.allow_deviations` | Run the checks that have the master break a protocol rule |
| `--device-profile FILE` | `defaults.device_profile` | The Device Profile document `PROFILE-001` compares with |
| `--capture FILE` | `capture` | Write the traffic to a pcap file |

## From Python

```python
import asyncio

from py1815.master import Outstation
from py1815.master.evaluate import evaluate
from py1815.profile import load


async def main() -> None:
    outstation = Outstation("lab", host="192.0.2.10")
    await outstation.connect()
    await outstation.idle()
    try:
        report = await evaluate(outstation, load.load(), commanding=True, deviating=True)
    finally:
        await outstation.close()
    for line in report.lines():
        print(line)


asyncio.run(main())
```

`report.results` holds a `Result` for each check, with its verdict, and `report.failed`
says whether any failed. `evaluate_loopback` runs the same checks against a session in
the same process, with no socket and no waiting, which is how this library's own tests
run them.

### Writing a check

A check is a function that takes a `Bench` and yields requests. `Bench` has the requests
a check is made of, each called with `yield from`: `obtain`, `online`, `offline`, `state`
and `value` read a point; `set` and `latch` write one and return the status; `eventually`
repeats a read for the settling time. A check fails by raising `Failed`, or through
`bench.require`.

```python
from py1815.master.bench import Bench, Check, NotApplicable
from py1815.master.checks import CATALOG
from py1815.master.evaluate import evaluate
from py1815.profile.model import Kind


def started_is_reported(bench: Bench):
    if not bench.supported(Kind.BI, 14):
        raise NotApplicable("the outstation does not serve BI14")
    started = yield from bench.state(bench.map.point(Kind.BI, 14))
    bench.require(started, "the DER is not started")


mine = Check("SITE-001", "The DER is started", False, started_is_reported)
report = await evaluate(outstation, point_map, checks=[*CATALOG, mine])
```

The third argument says whether the check writes. One that does is run only when
`commanding` is set.

A check that has the master break a protocol rule is made with `deviates=True`, and is
run only when `deviating` is set. `bench.deviate("corrupt_header_crc")` turns a deviation
on until the check ends, `bench.conform()` turns it off sooner, `bench.unanswered(what)`
sends a small read that has to draw no answer, and `bench.answers(after)` sends reads
until one is answered. `not_answered` and `events_kept` in `py1815.master.checks` build
the checks of the deviation set from these.
