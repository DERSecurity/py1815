# The dnp3c conformance run

[dnp3c](https://github.com/stepfunc/dnp3c) is a DNP3 conformance test harness published
by [Step Function I/O](https://stepfunc.io). It acts as a master, runs the DNP3 IED
Level 2 outstation certification test procedures against a device, and writes an HTML
report with a log of every step and frame.

This directory runs it against this library's outstation in continuous integration. The
unit suite carries out the same procedures in process (`tests/test_ied_*.py`), but that
is this project reading the procedures and then checking its own reading. dnp3c was
written by other people from their own reading, so where the two agree, the agreement
means something, and where they do not, one of them has something to explain.
[The summary of the results](../../docs/conformance.md) says which is which.

The tool, its report format and the idea of driving it from a plugin are all Step
Function I/O's. So is the `dnp3` crate that two other jobs in this repository use.

## What is here

| File | What it is |
|---|---|
| `../conformance_outstation.py` | The device under test: a Subset Level 2 outstation of this library, and a control channel that changes its inputs, cycles its power and reports what it holds |
| `src/main/scala/py1815conformance/` | The integration plugin. dnp3c calls it for each step it cannot perform over DNP3, and the plugin performs the step through the control channel |
| `device.ini` | What dnp3c is told about the outstation |
| `pom.xml` | The Maven project. Every version in it is pinned |
| `expected.json` | How each procedure ends, on record |
| `check_outcomes.py` | Compares a run with the record |

## The license, and how this directory is scoped

Everything in this directory is licensed under the GNU General Public License,
version 3 only. [LICENSE](LICENSE) here is its text. The rest of this repository is
licensed under the Apache License, Version 2.0, and this directory is the one exception.

The reason is the harness. dnp3c is licensed under the GNU General Public License v3.0
only. Read the license instead of a summary of it:

<https://github.com/stepfunc/dnp3c/blob/main/LICENSE>

The plugin in this directory is a separate program. It links the dnp3c library, which
Maven fetches from Maven Central when the job runs, and it is used only in this
repository's tests. No part of dnp3c is in this repository.

Nothing in this directory is part of the py1815 library. The library does not import
it, depend on it or need it. It is not in the wheel or in the source distribution:
`pyproject.toml` leaves the whole of `interop/` out of both, and the release workflow
fails if either carries a file from it. The device under test talks to the harness over
a TCP connection and nothing else.

To stop using dnp3c, delete this directory and `../conformance_outstation.py`, and in
`.github/workflows/interop.yml` delete the `dnp3c-conformance` job.

## What the outstation is told to be

The device is a Level 2 configuration of the library with its defaults. Three things a
device built on the library decides for itself are decided the way the procedures
expect of a device, and `../conformance_outstation.py` says why for each: it carries
out a cold restart request, it carries out a control sent to a broadcast address, and
it asks for the time again ten seconds after a master writes it.

`device.ini` states every option dnp3c has. A `supports.*` option is off only where the
outstation does not have the feature:

| Option turned off | Why |
|---|---|
| `supports.doubleBit`, `supports.disable.doubleBit`, `supports.doubleBitChangeEvents` | The outstation has no double-bit binary inputs |
| `supports.counterChangeEvents`, `supports.counterEventsQueuedPerPoint` | A counter reports no change events |
| `supports.frozenCounterChangeEvents` | Held to Level 2, a freeze buffers no event |
| `supports.analogEventsQueuedPerPoint` | An analog input keeps one event, its newest |
| `supports.binaryOutputChangeEvents`, `supports.analogOutputChangeEvents` | Output events are not offered |
| `supports.dataLinkConfirmRequests`, `supports.dataLinkRetries` | The outstation never requests data link confirmation, so it has nothing to retry |
| `supports.selfAddress` | The outstation does not answer the self-address |
| `supports.noClassAssignment` | Assign class is not implemented. A point's class is fixed when the outstation is built |
| `supports.globalRemoteSupervisoryControl`, `supports.individualRemoteSupervisoryControl` | Outputs have no local state |
| `supports.deviceAttributes` | Device attributes are not served |

`expected.json` carries the same reasons, and `tests/test_conformance_record.py` fails
when an option is off in `device.ini` without one, or without a row here.

Each binary output accepts every control code and behaves as a latch. So the points
`device.ini` names for one code or a pair of codes do accept those codes, and none of
them accepts only those.

## What the plugin checks, and against what

The plugin never answers a check from what dnp3c parsed alone. It asks the device:

- **A control operated**, or did not: the device records every write that reaches an
  output. A check that an output operated needs exactly one such write since the last
  check of that output.
- **Values**: each value in a response is compared with the value the device holds for
  that point, and a class 0 response has to carry every installed input.
- **Events**: the plugin generates events by changing inputs, and the device answers
  each change with whether it buffered an event and the time it gave it. A response has
  to hold those events, in order, with those times.
- **Time**: the event generated for the time check has to carry a time within 100 ms of
  when the plugin generated it, by the clock of the machine the run is on. The
  outstation's Device Profile states no accuracy, so that figure is this run's own. The
  same figure bounds the delay a delay measurement may report.

A step for a feature the outstation does not have throws. The plugin implements
dnp3c's plugin interface directly and not its default plugin, so no step can wait for a
person at standard input.

## Running it

It needs Java 17 or newer, Maven, and a Python with this library installed. From the
repository root:

```bash
pip install -e .
cd interop/dnp3c
export PY1815_CONFORMANCE_PYTHON="$(command -v python)"
mvn --batch-mode compile
mvn --batch-mode scala:run -Dlauncher=conformance
python check_outcomes.py
```

`PY1815_CONFORMANCE_PYTHON` is the interpreter the plugin starts the device with. It is
required, and is not guessed. The run takes several minutes, most of it waiting out
timeouts the procedures call for.

One procedure or section is run by adding its number:

```bash
mvn --batch-mode scala:run -Dlauncher=conformance "-DaddArgs=-run|8.11.2.5"
```

The results are written to `results/`, which Git ignores:

| File | What it is |
|---|---|
| `report.html` | dnp3c's report, linking to each procedure's log |
| `<procedure>/log.html` | Every step, frame and check of one procedure |
| `<procedure>/dump.pcap` | The procedure's traffic, when capture is on |
| `outstation.log` | The device's own log |
| `outcomes.json` | Each procedure's outcome, with dnp3c's words for a skip or a failure |

dnp3c stops a run at the first procedure that fails. The program here then runs each
procedure it did not reach, one at a time, so that one failure does not hide the rest.
It exits with a failure if any procedure failed.

Packet capture needs libpcap and the privilege to capture, and is off in `device.ini`.
The CI job turns it on. To capture locally, set `tcp.capture.adapter` to the loopback
adapter's address as `dnp3c -adapters` prints it, and run as a user that may capture.

## The record

`expected.json` holds how every procedure ends: passed, skipped for a named option, not
implemented by dnp3c, or failed, with the reason. `check_outcomes.py` compares a run
with it and fails when a procedure ends differently, when one on record did not run,
and when one ran that is not on record. So a procedure that starts to fail is caught,
and so is one that starts to pass.

When a run differs for a good reason, put it on record and say why:

```bash
python check_outcomes.py --write
```

That keeps the reasons already given and leaves an empty one for anything new, which
the comparison refuses until it is filled in. A new failure is a finding. Work out
which side is right from IEEE Std 1815-2012, the technical bulletins and the
certification procedure, in that order, before writing its reason down. Then update
[`docs/conformance.md`](../../docs/conformance.md), which a test holds to the record.
