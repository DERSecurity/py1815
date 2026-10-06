# Reading an outstation

`py1815.master` is a DNP3 master, the side that asks. It is here to exercise
outstations: this library's, in tests, and any other, on a bench.

!!! note "A first version"
    It reads. It polls by class, reads named points, confirms what asks to be
    confirmed, takes unsolicited responses and keeps the last value of every
    point, from Python, from a JSON service, or from a web console. It does
    not command an output, does not reconnect by itself, and has no TLS yet. [The plan](https://github.com/DERSecurity/py1815/blob/main/docs/planning/MASTER.md)
    says what follows.

## Over a socket

```python
import asyncio

from py1815.master import ALL, Master


async def main() -> None:
    async with Master() as master:
        lab = await master.add(
            "lab", host="192.0.2.10", port=20000, outstation_address=1024, master_address=1
        )

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
| `request(function, body)` | Any function code, with the octets that follow it |

Requests made at the same time take turns, in the order they were made. An
outstation carries one request at a time.

An integrity poll does not return what the outputs stand at. The IEEE 1815.2
profile leaves output status out of class 0, so it is read by naming its
groups: `scan("outputs")` reads binary and analog output status, and
`read(analog_outputs=ALL)` reads one of them.

## What comes back

Every request returns an `Exchange` that says what happened. Nothing about the
outstation's answer is an exception.

| Field | Holds |
|---|---|
| `outcome` | `COMPLETE`, `TIMEOUT`, `SENT` for a request that takes no response, or `ABANDONED` when the connection ended first |
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

The master does not enable them for you. Send the request yourself:

```python
from py1815.application import FunctionCode, class_header

await lab.request(FunctionCode.ENABLE_UNSOLICITED, class_header(1) + class_header(2))
```

## Driving an outstation by hand

`confirm=False` stops the master confirming anything. Nothing is then sent that
you did not ask for, which is what a test of an outstation's own behavior
needs: events left unconfirmed are still there on the next scan.

```python
lab = await master.add("lab", host="192.0.2.10", confirm=False)
```

## Repeating a scan

Nothing is sent on a schedule unless you ask for it:

```python
lab.repeat_scan("integrity", 30)   # every thirty seconds
lab.repeat_scan("outputs", 30)     # output status, which the integrity poll leaves out
lab.repeat_scan("events", 2)
lab.repeat_scan("events", None)    # stop
```

A repeated scan takes its turn with every other request, stops when the
connection ends, and starts again when `connect()` makes it again.

## The traffic

Each outstation keeps a `trace`: every frame sent and received, with its time,
its octets and a reading of them one layer at a time.

```python
for entry in lab.trace.since():
    print(entry.direction, entry.summary)
# tx READ seq 0: class 1, class 2, class 3, class 0
# rx RESPONSE seq 0 CON [NEED_TIME, DEVICE_RESTART]: g1v2 x49, g30v1 x283
```

## The console

```bash
py1815-master console --demo
```

serves a web console on `http://127.0.0.1:8815/` and, with `--demo`, starts a
simulated IEEE 1815.2 DER beside it and connects to it. The demonstration
needs the profile's point tables, which `py1815-der tables fetch` obtains; see
[Serving a DER](der.md).

To watch a device of your own:

```bash
py1815-master console --outstation lab=192.0.2.10:20000 \
    --integrity-interval 30 --event-interval 2
```

| Tab | Shows |
|---|---|
| **Overview** | Addresses, connection state, counts, and every internal indication of the last response |
| **Points** | A table for each point type: index, value, flags by name, the outstation's time, the object that carried it, and whether a poll or an event reported it. With a profile, the points of the profile the outstation has not reported can be shown beside the ones it has |
| **Commands** | Scans by class, a read of named points, enabling and disabling unsolicited responses, any request by function code, and the result of each |
| **Events** | Events as they arrive, polled or unsolicited |
| **Traffic** | Each frame with its time and direction, and the selected one read layer by layer beside its octets |
| **Log** | What the console asked for, and what came of it |

For an IEEE 1815.2 DER, `--profile` gives the console the profile's whole
point map, from the same tables `--demo` uses:

```bash
py1815-master console --outstation lab=192.0.2.10:20000 --profile --integrity-interval 30
```

Points are then shown by name, and "Show points not reported" on the Points
tab lists the points of the profile the outstation has not reported, with the
ones the profile makes mandatory marked. A point is not reported either
because the outstation does not implement it or because nobody has read it:
a master cannot tell which from silence. Output status and the few inputs the
profile leaves out of class 0 are in the second group until they are read.

The console listens on this machine only. To reach it from another, give it a
token, which every request then has to carry:

```bash
py1815-master console --bind 0.0.0.0:8815 --token "$(openssl rand -hex 16)"
```

It refuses a request that comes from a page it did not serve, since a browser
will carry a request from any site to a port on your own machine. It loads
nothing from the network: no fonts, no scripts, no styles.

## The service

The console holds no logic. It speaks to a service whose operations are JSON,
and anything it does a script can do with the same messages.

```bash
py1815-master serve --bind 127.0.0.1:8816
```

A request is one JSON object on one line, and so is its answer:

```json
{"id": 1, "op": "add", "params": {"name": "lab", "host": "192.0.2.10", "port": 20000}}
{"id": 2, "op": "scan", "outstation": "lab", "params": {"kind": "integrity"}}
{"id": 3, "op": "read", "outstation": "lab", "params": {"points": {"ai": [4, 6, 8], "bi": "all"}}}
```

```json
{"id": 3, "ok": true, "result": {"function": "READ", "outcome": "complete", "fragments": 1,
  "indications": ["NEED_TIME", "DEVICE_RESTART"], "object_count": 52, "elapsed_ms": 14.2,
  "objects": [{"type": "ai", "index": 4, "value": 50000, "flags": ["ONLINE"], "...": "..."}]}}
```

| Operation | Does |
|---|---|
| `status` | Each outstation: connection, addresses, indications, counts |
| `add`, `remove` | An outstation, by name. `add` takes `host`, `port`, both link addresses, `integrity_interval`, `event_interval` and `output_interval`. Output status is read as often as the integrity poll unless `output_interval` says otherwise, or is `null` |
| `connect`, `disconnect` | Its connection |
| `scan` | A poll by `kind`: `integrity`, `events`, `class0` to `class3`, `outputs` |
| `read` | Named points by type: `bi`, `bo`, `counter`, `frozen`, `ai`, `ao`, each a list of indices or `"all"` |
| `values` | What the store holds, with no traffic |
| `profile` | Every point of the profile an outstation was started with, reported or not: index, name, whether it is mandatory, and its section |
| `events` | The events received |
| `request` | Any request: `function` by name or number, `body` in hexadecimal |
| `enable_unsolicited`, `disable_unsolicited` | By `classes` |
| `repeat` | A scan of `kind` every `interval` seconds, or `null` to stop |
| `trace` | The frames recorded, optionally `after` an id |
| `clear` | The `trace` or the `events` |
| `stop` | Ends the service |

An answer has `"ok": false` and an `error` with a `message` when the message
could not be acted on (`"kind": "request"`) or there was no connection
(`"kind": "connection"`). An outstation that did not answer is not an error:
the result's `outcome` is `timeout`.

Send `{"op": "subscribe"}` and the same connection is also sent what happens
unasked, one line each, with an `event` field: `frame`, `exchange`,
`unsolicited`, `connection`, `outstations`.

The console uses the same messages over HTTP: `POST /api` with a message as
`application/json`, and `GET /events` for the stream as server-sent events.

## In one process, with no socket

`Loopback` wires a master straight to a `Session`. It has the same requests,
and they return at once and are not awaited:

```python
from py1815.master import Loopback

master = Loopback(outstation.session())
poll = master.integrity_poll()
unasked = master.listen()      # what the session would send without being asked
```

Give the session and the `Loopback` the same clock and a test moves time
itself, through as many retries as it likes.

!!! warning "What this does not prove"
    A master and an outstation from one library share their reading of the
    standard. When they agree, that is convenient and proves little. The
    decoders here are tested from octets written out by hand, and the
    independent masters and parsers described in [Testing](testing.md) are
    what judge whether the outstation's octets are right.
