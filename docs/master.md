# The master

`py1815.master` is a DNP3 master, the side that asks. It is here to exercise
outstations: this library's, in tests, and any other, on a bench. This page is
the master from Python; [the console](console.md) and [the API](master-api.md)
are the same master from a browser and from another process.

!!! note "A first version"
    It polls by class, reads named points, confirms what asks to be
    confirmed, takes unsolicited responses and keeps the last value of every
    point. It operates outputs, sets the clock by a plain write or by either
    of the standard's procedures, clears the restart indication, freezes
    counters and sends broadcasts. Left alone it looks after an outstation as
    a master does: settles it on connecting, fetches the events it says it
    has, and connects again when the connection is lost. It connects over TCP
    or TLS. All of it from Python, with or without an event loop, from a JSON
    service, or from a web console. [The plan](https://github.com/DERSecurity/py1815/blob/main/docs/planning/MASTER.md)
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
| `synchronize_time(procedure)` | The outstation's clock, by the `"lan"` or `"non_lan"` procedure. See [Setting the clock](#setting-the-clock) |
| `clear_restart()` | The restart indication, cleared |
| `freeze(clear=, respond=)` | Every counter frozen, and cleared as it is if asked |
| `restart(kind)` | A `"cold"` or a `"warm"` restart |
| `request(function, body)` | Any function code, with the octets that follow it |
| `broadcast(function, body, address=)` | Any function code, sent to a broadcast address. See [Broadcast](#broadcast) |

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

### A read that is not answered

A read that times out with nothing received can be sent again, as IEEE
1815-2012 4.3 rule 16 has it: under the same sequence number, with the same
octets, so an outstation that did answer the first is answering both.

```python
lab = await master.add("lab", host="192.0.2.10", read_retries=2)
poll = await lab.integrity_poll()
print(poll.retries)                # how many times it was sent again
```

None by default, as the DNP Users Group recommends for a master's application
layer: a retry hides that the outstation did not answer, which is what a test
of an outstation wants to see. Only a read is ever sent again. A control, a
write, a freeze, a restart, a time synchronization and a broadcast are each
sent once, whatever `read_retries` says, and a read whose answer has begun to
arrive is not sent again.

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
| `event_follow_ups` | Polls for events again, at once | When a poll's own response still says events are waiting, up to this many times in a row | 3 |

```python
from py1815.master import Tasks

lab = await master.add(
    "lab",
    host="192.0.2.10",
    tasks=Tasks(enable_unsolicited=(1, 2, 3), write_time=False),
)
await lab.idle()

lab.tasks = Tasks(events_when_indicated=False)   # changed while connected
```

`write_time` writes the master's time as it stands unless
`time_procedure` names one of the standard's procedures, `"lan"` or
`"non_lan"`: see [Setting the clock](#setting-the-clock).

Tasks can be changed at any time by setting `tasks`. What is done next
follows the new settings, and a task that was due and is now off is not
done; a startup sequence under way finishes.

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
- **Answer itself without end.** A task is not made due by the response to
  its own request, with one bounded exception: a poll whose response still
  says events are waiting is followed by another, at most `event_follow_ups`
  times in a row, and then not again until a poll finds nothing waiting. An
  outstation that never clears an indication costs a few requests, never a
  stream.
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

A connection you closed with `close()` is not made again.

A first connection that cannot be made raises `OSError` at once, unless you
ask the master to wait for the outstation:

```python
lab = await master.add("lab", host="192.0.2.10", wait=60)   # try for a minute
await lab.connect(wait=60, every=2.0)                      # every two seconds
```

It tries once a second unless told otherwise, and raises the last error when
the time is up.

### Over TLS

Give the outstation a TLS context, and the connection is made over TLS:

```python
from py1815.master.tls import TlsSettings

tls = TlsSettings(
    ca="lab-ca.pem",              # what the outstation's certificate is checked against
    certificate="master.pem",     # what the master offers
    key="master.key",
    server_name="inverter.lab",   # when the certificate does not name the host
)
lab = await master.add(
    "lab", host="192.0.2.10", port=20000, tls=tls.context(), server_name=tls.server_name
)
```

Any `ssl.SSLContext` will do. An outstation that listens with TLS usually
requires a certificate of the master, as this library's does. A key that is
encrypted is opened with the password in the `PY1815_MASTER_KEY_PASSWORD`
environment variable. A certificate that does not check out is an `OSError`
from `add` or `connect`.

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

### Waiting for something

`wait_for` returns when a condition holds, and says whether it did:

```python
held = await lab.wait_for(lambda store: store.analog_output(87).value == 5000, timeout=10)
held = await lab.wait_for(lambda _: lab.indications.is_set(IINBit.NEED_TIME), timeout=10)
```

The condition is looked at at once, and again each time a response or an
unsolicited response has been stored, and when the connection is made or ends.
Nothing is sent to make it hold. `lab.indications` is the indications of the
last response of either kind. A timeout returns `False`; it is not an
exception.

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

## Setting the clock

`write_time()` sends the master's clock as it reads when the request is
built, and the outstation is behind by however long the request took to
arrive. IEEE 1815-2012 10.3.3 gives two procedures that correct for that, and
`synchronize_time` follows either:

```python
done = await lab.synchronize_time("lan")
print(done.written, done.accepted, done.time_ms)
done = await lab.synchronize_time("non_lan")
print(done.delay_ms)
```

| Procedure | Sends |
|---|---|
| `"lan"` | A request to record the current time, then a write of the time the master sent it (group 50 variation 3). The outstation adds what has passed since it arrived. The default, since the master speaks TCP |
| `"non_lan"` | A delay measurement, then a write of the master's time plus half the round trip less the time the outstation says it held the request (group 50 variation 1) |

The write is sent only if the first request was answered without an error
indication; `written` says whether it was, and `accepted` whether the
outstation took it. Neither request is ever sent again (10.3.4). The master
takes its times when it builds each request, which is as close to the wire as
a program above the operating system's sockets gets.

The `write_time` task can use either procedure:
`Tasks(time_procedure="lan")`.

## Broadcast

A request sent to a broadcast address reaches every outstation on the link,
and none answers it:

```python
from py1815.master import requests

sent = await lab.broadcast(FunctionCode.IMMED_FREEZE_NR, requests.freeze_counters())
sent = await lab.broadcast(
    FunctionCode.WRITE, requests.write_time(now_ms), address="shall_confirm"
)
```

| `address` | Is | What the outstation does about the response that reports it |
|---|---|---|
| `"no_confirm"` | 0xFFFD | Does not ask for it to be confirmed |
| `"shall_confirm"` | 0xFFFE | Asks for it to be confirmed |
| `"optional_confirm"` | 0xFFFF | Either. The default, since every outstation takes it |

The exchange ends as soon as the request is sent, with `outcome` `SENT` and
`broadcast` naming the address. The outstation says it received one with
IIN1.0 in its next response to this master. Over TCP a broadcast reaches the
one outstation at the other end of the connection, which acts on it as a
broadcast.

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

## Without an event loop

`py1815.master.sync` is the same master for a script that has no event loop.
Every request blocks until it is done:

```python
from py1815.master.sync import Master

with Master() as master:
    lab = master.add("lab", host="192.0.2.10")
    lab.idle()
    poll = lab.integrity_poll()
    print(poll.outcome, lab.store.analog_input(4))
    lab.wait_for(lambda store: store.analog_output(87) is not None, timeout=10)
```

The master runs on an event loop of its own in a thread it starts and stops,
so the tasks, unsolicited responses and repeated scans carry on between calls.
Its blocking methods are made from the asynchronous ones, and a test fails if
an operation is added to one and not the other.

## From the command line

`py1815-master poll` reads an outstation once: one integrity poll, with
confirmations and nothing else, and a summary and the analog inputs, named
from the IEEE 1815.2 tables when this machine has them. `py1815-der poll` is
the same command.

```bash
py1815-master poll --host 192.0.2.10 --port 20000 --limit 20
py1815-master poll --host 192.0.2.10 --tls-ca lab-ca.pem \
    --tls-certificate master.pem --tls-key master.key
```

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

Retries and broadcasts work here as they do over a socket: a read with
`master.association.read_retries` set is sent again when the session did not
answer it, and a broadcast is handed to the session, which acts on it and
answers nothing.

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
