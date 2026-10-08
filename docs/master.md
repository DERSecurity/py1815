# The master

`py1815.master` is a DNP3 master, the side that asks. It is here to exercise
outstations: this library's, in tests, and any other, on a bench. This page is
the master from Python; [the console](console.md) and [the API](master-api.md)
are the same master from a browser and from another process.

!!! note "A first version"
    It polls by class, reads named points, confirms what asks to be
    confirmed, takes unsolicited responses and keeps the last value of every
    point. It operates outputs, sets the clock, clears the restart indication
    and freezes counters. Left alone it looks after an outstation as a master
    does: settles it on connecting, fetches the events it says it has, and
    connects again when the connection is lost. All of it from Python, from a
    JSON service, or from a web console. It has no TLS yet. [The plan](https://github.com/DERSecurity/py1815/blob/main/docs/planning/MASTER.md)
    says what follows.

## Over a socket

```python
import asyncio

from py1815.master import ALL, Master, PointType


async def main() -> None:
    async with Master() as master:
        lab = await master.add(
            "lab", host="192.0.2.10", port=20000, outstation_address=1024, master_address=1
        )

        await lab.idle()               # what it does on connecting is done
        print(len(lab.store.points(PointType.ANALOG_INPUT)), "analog inputs read")

        poll = await lab.integrity_poll()
        print(poll.outcome, len(poll.fragments), "fragments", len(poll.objects), "objects")

        answer = await lab.read(analog_inputs=[4, 6, 8], binary_inputs=ALL)
        for decoded in answer.objects:
            print(decoded.point.value, decoded.index, decoded.value, decoded.flags)

        power = lab.store.analog_input(4)
        print(power.value, power.flags, power.from_event)


asyncio.run(main())
```

`Master` holds outstations by the name you give each. `add` connects and
returns an `Outstation`, which is where the requests are:

| Request | Asks for |
|---|---|
| `integrity_poll()` | Classes 1, 2 and 3, then class 0: every event, then every static value |
| `scan(kind)` | `"integrity"`, `"events"`, one class: `"class0"` to `"class3"`, or `"outputs"` |
| `read(...)` | Named points, by type and index, or `ALL` of a type, in one request |
| `operate(...)` | Outputs commanded, by type and index. See [Commanding outputs](#commanding-outputs) |
| `write_time(ms)` | The outstation's clock, in milliseconds since the epoch, or now |
| `clear_restart()` | The restart indication, cleared |
| `freeze(clear=, respond=)` | Every counter frozen, and cleared as it is if asked |
| `restart(kind)` | A `"cold"` or a `"warm"` restart |
| `request(function, body)` | Any function code, with the octets that follow it |

Requests made at the same time take turns, in the order they were made. An
outstation carries one request at a time.

`read(...)` sends each run of consecutive indices as one start-stop range, in
ascending order, because that is the form every outstation accepts. The points
come back in ascending order, whatever order you named them in.

An integrity poll does not return what the outputs stand at. The IEEE 1815.2
profile leaves output status out of class 0, so it is read by naming its
groups: `scan("outputs")` reads binary and analog output status, and
`read(analog_outputs=ALL)` reads one of them.

## What comes back

Every request returns an `Exchange` that says what happened. Nothing about the
outstation's answer is an exception.

| Field | Holds |
|---|---|
| `outcome` | `COMPLETE`, `TIMEOUT`, `SENT` for a request that takes no response, or `ABANDONED` when the connection ended first or the caller stopped waiting |
| `fragments` | Each response fragment, in the order received |
| `objects` | Every object of every fragment, decoded, in the order sent |
| `iin` | The indications of the last fragment, or `None` if nothing arrived |
| `undecoded` | Where an object could not be read: why, and the octets from there on |
| `request`, `sequence`, `elapsed` | The fragment that was sent, its sequence number, and how long the exchange took |

A timeout is a result, and so is a refusal:

```python
answer = await lab.read(analog_inputs=[60000])
if answer.iin.is_set(IIN2Bit.PARAM_ERROR):
    print("the outstation has no such point")
```

An exception means the interface was misused or there was no connection:
`NotConnected` for a request with no connection, `OSError` from `add` or
`connect` when the connection cannot be made, `ValueError` for a request that
names nothing.

A decoded object carries its group, variation and index, its value, its flag
octet, and its time when the outstation gave one. `flags` is `None` for a
variation that has no flags, which is not the same as none being set. An
object the library does not know ends the reading of that fragment: what came
before it is kept, and `undecoded` holds the reason and the rest of the octets.

## What it does without being asked

A master does a few things of its own accord, and this one does them unless
told not to. Each is a task:

| Task | Does | When | Default |
|---|---|---|---|
| `startup` | Stops unsolicited reporting, then reads everything with an integrity poll | On connecting, and when the outstation reports that it restarted | On |
| `clear_restart` | Clears the restart indication | When a response carries it | On |
| `write_time` | Sets the outstation's clock | When a response asks for the time | On |
| `enable_unsolicited` | Asks the outstation to report the classes named without being polled | After startup | Off: no classes |
| `events_when_indicated` | Polls for events | When a response says some are waiting | On |
| `integrity_on_overflow` | Reads everything again | When a response says the event buffer overflowed | On |

```python
from py1815.master import Tasks

lab = await master.add(
    "lab",
    host="192.0.2.10",
    tasks=Tasks(enable_unsolicited=(1, 2, 3), write_time=False),
)
await lab.idle()
```

`add` and `connect` return as soon as the connection is made. What is done on
connecting is done next, before anything you ask for and before any scan on a
schedule, and `idle()` waits for it. When several tasks are due they are done
in the order of the table, with nothing else between them.

Every request a task makes is an exchange like any other: it is in the trace,
it is counted, it is handed to `on_exchange`, and its `task` says which task
made it. An exchange you asked for has `task` set to `None`.

Three things a task never does:

- **Command an output.** No task selects or operates anything, and none sends
  a request between a select and its operate.
- **Answer itself.** A task is not made due by the response to its own
  request. An outstation that never clears an indication is asked about it at
  most once for each response that carries it, and never in a stream.
- **Repeat a scan.** Nothing is sent on a schedule unless you ask for it with
  [`repeat_scan`](#repeating-a-scan).

### A connection that is lost

A connection that was made and then lost is made again: the master tries every
five seconds until it succeeds, and then does what it does on connecting, so
the store is read afresh from an outstation that may have restarted.

```python
lab = await master.add("lab", host="192.0.2.10", reconnect=1.0)   # every second
lab = await master.add("lab", host="192.0.2.10", reconnect=None)  # never
```

A connection you closed with `close()` is not made again, and a first
connection that cannot be made still raises `OSError`.

## The store

Each outstation has a `store`: the last value of every point it has reported,
whichever request or unsolicited response brought it.

```python
lab.store.analog_input(4)          # one point, or None if never reported
lab.store.points(PointType.BINARY_INPUT)   # every binary input, by index
lab.store.events                   # the events received, oldest first
```

A stored value says whether it came from an event (`from_event`), the time the
outstation gave it (`time_ms`), and when it was received.

## Unsolicited responses

An outstation built to send them does so whenever it has something to report.
The master confirms each one, puts its values in the store, keeps it in
`lab.unsolicited`, and calls a handler if you gave one:

```python
lab = await master.add("lab", host="192.0.2.10", on_unsolicited=print)
```

The master enables them when it is told which classes to enable, after it has
settled the outstation, and again after each restart and each reconnection:

```python
lab = await master.add("lab", host="192.0.2.10", tasks=Tasks(enable_unsolicited=(1, 2)))
```

Or once, by asking:

```python
await lab.enable_unsolicited(1, 2)
```

## Commanding outputs

```python
result = await lab.operate(
    binary_outputs={17: True},        # a latch on
    analog_outputs={88: 500},         # a setpoint
    mode="select",
)
print(result.accepted)                             # True, False, or None
for status in result.statuses:
    print(status.command.point.value, status.command.index, status.status)
```

A binary output is given `True` or `False` for a latch on or off, or an
operation by name: `"pulse_on"`, `"pulse_off"`, `"trip"`, `"close"`. An analog
output is given a number. Binary outputs are sent first, and each in the order
given, all in one request.

| `mode` | Sends |
|---|---|
| `"direct"` | A direct operate. The outstation answers with a status for each control |
| `"select"` | A select, and then an operate, with nothing allowed between them |
| `"direct_no_ack"` | A direct operate the outstation does not answer |

After a select, the operate is sent only if the outstation echoed every
control back unchanged and accepted each one. One refusal stops them all.

The result says what happened and does not raise for it:

| | |
|---|---|
| `result.exchanges` | Each request made: one, or the select and the operate |
| `result.statuses` | For each control, the status the outstation answered with, and whether it echoed the control as sent |
| `result.operated` | Whether a request that operates was sent at all. False after a select that was refused |
| `result.accepted` | `True` when the outstation accepted every control, `False` when it refused one, and `None` when it never said |

`accepted` is `None` for a request that takes no acknowledgment, and for one
whose response did not arrive. That is not a refusal: the output may have been
operated. **Nothing is ever sent twice.** Whether to try again is yours to
decide, because only you know whether operating twice is harmless.

A whole number is sent as an integer, in 16 bits when it fits and 32 when it
does not, and anything else as a float. `variation=` says which outright.
The difference matters to an outstation that scales its points, as an
IEEE 1815.2 DER does: an integer is the value as transmitted, so 500 on a point
in tenths of a percent is 50 percent, and a float is the engineering value.

What cannot be carried is refused with a `ValueError` before anything is sent:
an output that is not a number, a value that does not fit the variation named,
an operation that is not one.

## Driving an outstation by hand

`manual=True` turns off every task and stops the master confirming anything.
Nothing is then sent that you did not ask for, which is what a test of an
outstation's own behavior needs: its restart indication is still set when you
look, and events left unconfirmed are still there on the next scan.

```python
lab = await master.add("lab", host="192.0.2.10", manual=True)
```

It is shorthand for `tasks=Tasks.none(), confirm=False`, and either given
beside it is kept as given: `manual=True, confirm=True` sends nothing unasked
but confirmations. Reconnecting is apart from it, since it sends nothing to
the outstation; turn it off with `reconnect=None`.

## Repeating a scan

Nothing is sent on a schedule unless you ask for it:

```python
lab.repeat_scan("integrity", 30)   # every thirty seconds
lab.repeat_scan("outputs", 30)     # output status, which the integrity poll leaves out
lab.repeat_scan("events", 2)
lab.repeat_scan("events", None)    # stop
```

A repeated scan takes its turn with every other request, stops when the
connection ends, and starts again when the connection is made again.

## The traffic

Each outstation keeps a `trace`: every frame sent and received, with its time,
its octets and a reading of them one layer at a time.

```python
for entry in lab.trace.since():
    print(entry.direction, entry.summary)
# tx DISABLE_UNSOLICITED seq 0: class 1, class 2, class 3
# rx RESPONSE seq 0 [CLASS_3_EVENTS, NEED_TIME, DEVICE_RESTART]
# tx WRITE seq 1
# rx RESPONSE seq 1 [CLASS_3_EVENTS, NEED_TIME]
# tx WRITE seq 2
# rx RESPONSE seq 2 [CLASS_3_EVENTS]
# tx READ seq 3: class 1, class 2, class 3, class 0
# rx RESPONSE seq 3 CON: g1v2 x49, g20v1 x4, g21v5 x4, g23v5 x4, g30v1 x283
# tx CONFIRM seq 3
```

That is a connection being made to an outstation that has just started: the
four requests of startup, each answered.

## Captures

A trace can be saved as a pcap file, which Wireshark, tshark and Suricata read
as it is:

```python
pathlib.Path("lab.pcap").write_bytes(lab.trace.capture())
```

Each frame is one TCP segment of an IPv4 connection, carried in Ethernet, at
the time it was sent or received. Each connection the master made is a TCP
stream of its own, between the addresses and ports it really had, opened with
a handshake and closed with FIN segments. The file is written from the trace
and not observed on the network, so it needs no capture tool and no
privileges, and it holds exactly the frames the master sent and received. It
does not show how the operating system split the stream into segments, or
retransmissions and acknowledgments of its own. An address that is not IPv4
is written as `127.0.0.1`, with its port kept. `capture(after=id)` keeps only
the frames after one, as `since` does.

To write every frame to a file as it crosses the wire, from the start of a
run, give the command a file:

```bash
py1815-master serve --outstation lab=192.0.2.10:20000 --capture lab.pcap
```

`console` takes `--capture` as well, and the configuration file takes
`"capture"`. Every outstation's frames go to the one file, each connection a
stream of its own, and each packet is on disk as soon as it is written, so a
master that is stopped or killed leaves a file Wireshark can open. The file is
emptied when the master starts. From Python, a `CaptureFile` and a `Recorder`
on a trace's `listeners` do the same:

```python
from py1815.master.capture import CaptureFile
from py1815.master.trace import Recorder

written = CaptureFile("lab.pcap")
recorder = Recorder(written, lab.trace, port=lab.port)
lab.trace.listeners.append(recorder.record)
...
recorder.close()  # ends the open connection in the file
written.close()
```

The console's Traffic tab has a Save capture button, and the service a
`capture` operation, that return what the trace holds.

## From a browser, or from another process

The same master can be driven without writing Python:

- [The console](console.md) is a web page that shows an outstation's points,
  events and traffic. `py1815-master console --demo` starts it beside a
  simulated DER.
- [The master's API](master-api.md) is every operation as JSON, over HTTP or a
  line at a time over a local socket, described in an OpenAPI document.
- [Configuring the master](master-config.md) lists every setting, as a JSON
  file and as command-line flags.

## In one process, with no socket

`Loopback` wires a master straight to a `Session`. It has the same requests,
and they return at once and are not awaited:

```python
from py1815.master import Loopback

master = Loopback(outstation.session())
poll = master.integrity_poll()
unasked = master.listen()      # what the session would send without being asked
```

A `Loopback` does nothing unasked unless it is given tasks. Given them,
`start()` stands for the connection being made and returns the exchanges it
led to, and whatever comes due later is done after the request or the
`listen()` that showed it, and kept in `master.unasked`:

```python
master = Loopback(outstation.session(), tasks=Tasks())
for exchange in master.start():
    print(exchange.task, exchange.outcome)
```

Give the session and the `Loopback` the same clock and a test moves time
itself, through as many retries as it likes.

!!! warning "What this does not prove"
    A master and an outstation from one library share their reading of the
    standard. When they agree, that is convenient and proves little. The
    decoders here are tested from octets written out by hand, and the
    independent masters and parsers described in [Testing](testing.md) are
    what judge whether the outstation's octets are right.
