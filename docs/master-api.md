# The master's API

The master's operations as JSON, for a caller in another process or another
language: a test rig, a script, or the [console](console.md), which uses
nothing else.

```bash
py1815-master console      # the API over HTTP, and the console, on 127.0.0.1:8815
py1815-master serve        # the API a line of JSON at a time, on 127.0.0.1:8816
```

Both take `--outstation`, `--profile` and the interval options the
[console](console.md#starting-it) takes.

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
  "function": "READ", "sequence": 0, "outcome": "complete", "fragments": 1,
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
| `POST /api/profile` | Every point of the profile an outstation is meant to serve |
| `POST /api/scan` | A poll by `kind`: `integrity`, `events`, `class0` to `class3`, `outputs` |
| `POST /api/read` | Named points, in one request |
| `POST /api/values` | What has been read, with no traffic |
| `POST /api/events` | The events received |
| `POST /api/request` | Any request, by function code |
| `POST /api/enable_unsolicited`, `POST /api/disable_unsolicited` | Reporting by event class |
| `POST /api/repeat` | A scan on a schedule, or an end to one |
| `POST /api/trace` | The frames sent and received |
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

`ok` says whether the operation was carried out. It is false in two cases:

| `error.kind` | Means |
|---|---|
| `request` | The message could not be acted on: an operation that does not exist, an outstation nobody added, a parameter of the wrong kind |
| `connection` | There was no connection to ask over, or one could not be made |

An outstation that did not answer is neither. The operation was carried out,
`ok` is true, and the result's `outcome` is `timeout`. The same goes for a
request the outstation refused: `outcome` is `complete`, and `indications`
names what it refused with.

| `outcome` | Means |
|---|---|
| `complete` | The response arrived, to its final fragment |
| `timeout` | Nothing more arrived in time. What did arrive is in the result |
| `sent` | The request takes no response, and was sent |
| `abandoned` | The connection ended while the request was outstanding |

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

## What happens unasked

`GET /events` is a stream of server-sent events that stays open. Each event's
data is a JSON object:

| `event` | Sent when | Carries |
|---|---|---|
| `frame` | A frame is sent or received | `outstation`, `frame` |
| `exchange` | A request ends, asked for or repeated | `outstation`, `exchange` |
| `unsolicited` | An unsolicited response arrives | `outstation`, `indications`, `objects` |
| `connection` | A connection is made or ends | `outstation`, `connected` |
| `outstations` | An outstation is added or removed | |

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
