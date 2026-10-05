# Reading an outstation

`py1815.master` is a DNP3 master, the side that asks. It is here to exercise
outstations: this library's, in tests, and any other, on a bench.

!!! note "A first version"
    It reads. It polls by class, reads named points, confirms what asks to be
    confirmed, takes unsolicited responses and keeps the last value of every
    point. It does not command an output, does not reconnect by itself, and
    has no TLS yet. [The plan](https://github.com/DERSecurity/py1815/blob/main/docs/planning/MASTER.md)
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
| `scan(kind)` | `"integrity"`, `"events"`, or one class: `"class0"` to `"class3"` |
| `read(...)` | Named points, by type and index, or `ALL` of a type, in one request |
| `request(function, body)` | Any function code, with the octets that follow it |

Requests made at the same time take turns, in the order they were made. An
outstation carries one request at a time.

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
