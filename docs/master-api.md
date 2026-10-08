# The master's API

The master's operations as JSON, for a caller in another process or another
language: a test rig, a script, or the [console](console.md), which uses
nothing else.

```bash
py1815-master console      # the API over HTTP, and the console, on 127.0.0.1:8815
py1815-master serve        # the API a line of JSON at a time, on 127.0.0.1:8816
```

Both take the same outstation options as the [console](console.md#starting-it),
and both can load every setting from a JSON file with `--config`. See
[Configuring the master](master-config.md).

## Over HTTP

Each operation is a route. Its parameters are a JSON object in the body, and
its answer is a JSON object.

```bash
curl -s http://127.0.0.1:8815/api/add -H 'Content-Type: application/json' \
     -d '{"name": "lab", "host": "192.0.2.10", "port": 20000}'

curl -s http://127.0.0.1:8815/api/scan -H 'Content-Type: application/json' \
     -d '{"outstation": "lab", "kind": "integrity"}'
```

```json
{"id": null, "ok": true, "result": {
  "function": "READ", "task": null, "sequence": 2, "outcome": "complete", "fragments": 1,
  "indications": ["NEED_TIME", "DEVICE_RESTART"], "object_count": 344,
  "elapsed_ms": 15.0, "request": "c0013c02063c03063c04063c0106", "undecoded": [],
  "objects": [{"type": "bi", "group": 1, "variation": 2, "index": 0, "name": null,
               "value": false, "flags": ["ONLINE"], "time_ms": null,
               "synchronized": null, "event": false}]}}
```

The whole API is described in an OpenAPI document, which the service serves at
[`/openapi.json`](https://github.com/DERSecurity/py1815/blob/main/src/py1815/master/console/openapi.json)
and the repository keeps beside the console. It is built from one description
of the operations, and a test fails when the service and the document
disagree.

| Route | Does |
|---|---|
| `POST /api/status` | The outstations, and how each stands |
| `POST /api/add` | Adds an outstation and connects to it |
| `POST /api/remove` | Closes an outstation's connection and forgets it |
| `POST /api/connect`, `POST /api/disconnect` | Its connection |
| `POST /api/idle` | Waits until nothing the master does unasked is due or under way |
| `POST /api/profile` | Every point of the profile an outstation is meant to serve |
| `POST /api/scan` | A poll by `kind`: `integrity`, `events`, `class0` to `class3`, `outputs` |
| `POST /api/read` | Named points, in one request |
| `POST /api/values` | What has been read, with no traffic |
| `POST /api/events` | The events received |
| `POST /api/request` | Any request, by function code |
| `POST /api/operate` | Outputs commanded, by type and index |
| `POST /api/write_time`, `POST /api/clear_restart` | The clock, and the restart indication |
| `POST /api/freeze` | Counters frozen |
| `POST /api/restart` | A cold or a warm restart |
| `POST /api/enable_unsolicited`, `POST /api/disable_unsolicited` | Reporting by event class |
| `POST /api/repeat` | A scan on a schedule, or an end to one |
| `POST /api/trace` | The frames sent and received |
| `POST /api/capture` | The frames kept, as a pcap file in base64 |
| `POST /api/clear` | Forgets the frames or the events kept |
| `POST /api/stop` | Ends the service |
| `POST /api` | Any of the above as one message: see below |
| `GET /events` | What happens unasked, as server-sent events |
| `GET /openapi.json` | The description of these routes |

A request body is sent as `application/json`, always. Anything else is
refused, which is part of how the service tells its own page from someone
else's.

## What an answer means

```json
{"id": null, "ok": true, "result": {}}
{"id": null, "ok": false, "error": {"kind": "request", "message": "there is no outstation named 'lab'"}}
```

`ok` says whether the operation was carried out. It is false in three cases:

| `error.kind` | Means |
|---|---|
| `request` | The message could not be acted on: an operation that does not exist, an outstation nobody added, a parameter of the wrong kind |
| `connection` | There was no connection to ask over, or one could not be made |
| `not_allowed` | The operation commands the outstation, and the service was not started to. See [Commanding](#commanding) |

An outstation that did not answer is neither. The operation was carried out,
`ok` is true, and the result's `outcome` is `timeout`. The same goes for a
request the outstation refused: `outcome` is `complete`, and `indications`
names what it refused with.

| `outcome` | Means |
|---|---|
| `complete` | The response arrived, to its final fragment |
| `timeout` | Nothing more arrived in time. What did arrive is in the result |
| `sent` | The request takes no response, and was sent |
| `abandoned` | The request was given up on while it was outstanding: the connection ended, or the scan on a schedule that made it was set again |

## What the master does by itself

An outstation added through the service is looked after as
[the master looks after any](master.md#what-it-does-without-being-asked): it is
settled when the connection is made, its events are fetched when it says it has
some, and a connection that is lost is made again. `add` says otherwise:

```bash
curl -s http://127.0.0.1:8815/api/add -H 'Content-Type: application/json' \
     -d '{"name": "lab", "host": "192.0.2.10",
          "tasks": {"enable_unsolicited": [1, 2, 3], "events_when_indicated": false},
          "reconnect": 1.0}'
```

| Parameter | Is |
|---|---|
| `tasks` | An object of choices by task: `startup`, `clear_restart`, `write_time`, `events_when_indicated` and `integrity_on_overflow`, each true or false, and `enable_unsolicited`, a list of event classes. A task left out stands at its default |
| `manual` | True to send nothing that was not asked for: no task, and no confirmation. `tasks` and `confirm` given beside it are kept as given |
| `reconnect` | Seconds between attempts to make a lost connection again. Five when left out, and null for never |

`add` and `connect` answer as soon as the connection is made, and `idle`
answers once what is done on connecting has been done. An outstation's entry in
`status` gives its `tasks`, the `tasks_due` that are waiting, and `reconnect`.
A request the master made for a task has the task's name in `task`, in the
`exchange` event that reports it; a request that was asked for has null.

Two of the tasks write to the outstation: `clear_restart` and `write_time`. In
a service that was not [started to command](#commanding) they are off, and
asking for either by name is refused as `not_allowed`. Such a service settles
an outstation and leaves its restart indication and its clock as it found
them. Started with `--allow-control`, it does both.

## Commanding

A service reads unless it is started to command:

```bash
py1815-master console --allow-control
py1815-master serve --allow-control
```

Without that, every operation that changes an outstation is refused with
`not_allowed` and nothing is sent: `operate`, `write_time`, `clear_restart`,
`freeze`, `restart`, and a `request` by any function code other than `READ`,
`ENABLE_UNSOLICITED`, `DISABLE_UNSOLICITED` and `DELAY_MEASURE`. The two tasks
that write are off as well. `status` says which it is, in `allow_control`.

```bash
curl -s http://127.0.0.1:8815/api/operate -H 'Content-Type: application/json' \
     -d '{"outstation": "lab", "points": {"bo": {"17": true}, "ao": {"88": 500}}, "mode": "select"}'
```

```json
{"id": null, "ok": true, "result": {
  "mode": "select", "operated": true, "accepted": true,
  "statuses": [
    {"type": "bo", "index": 17, "name": null, "variation": 1, "value": 3,
     "status": "SUCCESS", "echoed": true},
    {"type": "ao", "index": 88, "name": null, "variation": 2, "value": 500,
     "status": "SUCCESS", "echoed": true}],
  "exchanges": [{"function": "SELECT", "outcome": "complete"},
                {"function": "OPERATE", "outcome": "complete"}]}}
```

| Field | Holds |
|---|---|
| `points` | The outputs: `bo` and `ao`, each an object of values by index. A binary output takes `true` or `false` for a latch, or an operation by name; an analog output takes a number |
| `mode` | `direct`, `select` for a select and then an operate, or `direct_no_ack` |
| `operated` | Whether a request that operates was sent. False after a select the outstation refused |
| `accepted` | True when every control was accepted, false when one was refused, null when the outstation never said |
| `statuses` | For each control, the status the outstation answered with, by name, and whether it echoed the control as sent |
| `exchanges` | Each request made, as any other exchange is described |

A refused control is an answer, with `ok` true: the operation was carried out
and the outstation said no. `accepted` is null when the request takes no
acknowledgment or the response did not arrive. The service never sends a
control twice.

A whole number is sent as an integer and anything else as a float, unless
`variation` says which. An outstation that scales its points takes an integer
as the transmitted value and a float as the engineering one.

## Values

An object out of a response, in `objects` and in `events`:

| Field | Holds |
|---|---|
| `type` | `bi`, `bo`, `counter`, `frozen`, `ai` or `ao`, or null for an object that is not a point's value |
| `group`, `variation`, `index` | Where the object sits in DNP3's terms |
| `name` | The point's name, when the outstation has a profile |
| `value` | A boolean, a count, or an analog value as transmitted |
| `flags` | The flag bits set, by name, or null for a variation that carries none |
| `time_ms` | The outstation's time for the value, in milliseconds since the epoch, when it gave one |
| `event` | Whether it reports a change, and not the present value |

A point of a profile, from `profile`:

| Field | Holds |
|---|---|
| `index`, `name` | The point, named as the profile's tables name it |
| `label` | The name without the values it lists, for a point that is an enumeration |
| `enumeration` | Those values, each a `value` and a `name`, or null |
| `mandatory` | Whether the profile requires every outstation to implement it |
| `section` | The heading the tables list it under |

## A capture

`capture` answers with the frames kept for an outstation as a pcap file, in
base64 so that JSON can carry it, and the number of frames in it. Decoded, it
opens in Wireshark:

```bash
curl -s http://127.0.0.1:8815/api/capture -H 'Content-Type: application/json' \
     -d '{"outstation": "lab"}' | jq -r .result.pcap | base64 -d > lab.pcap
```

`after` keeps only the frames with a greater id, as it does for `trace`. The
file's layout is described under [Captures](master.md#captures). It reads
nothing from the outstation, so a service that does not command answers it.

## What happens unasked

`GET /events` is a stream of server-sent events that stays open. Each event's
data is a JSON object:

| `event` | Sent when | Carries |
|---|---|---|
| `frame` | A frame is sent or received | `outstation`, `frame` |
| `exchange` | A request ends: asked for, repeated, or made for a task | `outstation`, `exchange` |
| `unsolicited` | An unsolicited response arrives | `outstation`, `indications`, `objects` |
| `connection` | A connection is made or ends | `outstation`, `connected` |
| `outstations` | An outstation is added or removed | |
| `lost` | This subscriber fell 10,000 updates behind, and the waiting updates were dropped | `dropped`: how many |

A subscriber that receives `lost` should read the state it shows again, for
example with `status`, `values`, `events` and `trace`. It stays subscribed.
An event stream that has not accepted a write for 60 seconds is closed; open a
new one.

Every operation that commands an outstation is written to the master's log at
INFO with the points and values asked for and the result, and one refused for
lack of `--allow-control` at WARNING.

```bash
curl -N http://127.0.0.1:8815/events
```

## One message at a time

`POST /api` takes any operation as one message: the operation by name, its
parameters, and an `id` the answer repeats.

```json
{"id": 7, "op": "scan", "outstation": "lab", "params": {"kind": "integrity"}}
```

`py1815-master serve` takes the same messages, one to a line over a local TCP
socket, and answers each with one line. A test rig starts it, adds its
outstations, and ends it with `stop`:

```python
import json
import socket

rig = socket.create_connection(("127.0.0.1", 8816)).makefile("rw")


def ask(op, outstation=None, **params):
    rig.write(json.dumps({"op": op, "outstation": outstation, "params": params}) + "\n")
    rig.flush()
    return json.loads(rig.readline())


ask("add", name="lab", host="192.0.2.10", port=20000)
poll = ask("scan", "lab", kind="integrity")["result"]
print(poll["outcome"], poll["object_count"])
```

Send `{"op": "subscribe"}` and the same connection is also sent the events
above, one to a line. The line service listens on this machine only.

## A token

Started with a token, the service requires it of every request to `/api` and
`/events`, as `Authorization: Bearer <token>`, or as a `token` query parameter
where a header cannot be set, as on the event stream. The console's own files,
and `/openapi.json`, need none. See
[Who can reach it](console.md#who-can-reach-it).
