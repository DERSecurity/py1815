# Connection, request and anomaly reports

The outstation and the master log what happens to their connections, and the
session logs each frame or request it drops. A log line is written for a
person to read. A host application that keeps a record of every connection
attempt, logs or forwards the requests its outstation serves, or passes
protocol anomalies to its own security monitoring, can instead take the same
facts as structured records, through three observers:

- A **connection observer** receives a `ConnectionEvent` each time a connection
  is accepted, refused, displaced or ended at the outstation, and each time the
  master connects, fails to connect, loses a connection or closes one.
- An **anomaly observer** receives a `ProtocolAnomaly` each time the session
  drops a frame or a request it cannot accept, or gives up on an unsolicited
  response.
- A **request observer** receives a `RequestRecord` for each request the
  outstation handles, with the response it sent back and the connection the
  request arrived on, and for each unsolicited response it sends.

An observer is any callable that takes one record. Each kind is optional and
off by default, and the log lines are written whether or not one is set. The
records and their enumerations are importable from `py1815` and from
`py1815.observers`, which also holds `SEVERITY`.

## At the outstation

```python
import dataclasses
import json

from py1815 import ConnectionEvent, OutstationServer, ProtocolAnomaly, RequestRecord, Session


def connection(event: ConnectionEvent) -> None:
    print(json.dumps(dataclasses.asdict(event)))


def anomaly(found: ProtocolAnomaly) -> None:
    print(json.dumps(dataclasses.asdict(found)))


def request(record: RequestRecord) -> None:
    fields = dataclasses.asdict(record)
    fields["request"] = record.request.hex()
    fields["response"] = None if record.response is None else record.response.hex()
    print(json.dumps(fields))


session = Session(provider, outstation_address=1024, master_address=1, anomaly_observer=anomaly)
server = OutstationServer(
    session, bind="0.0.0.0:20000", connection_observer=connection, request_observer=request
)
await server.start()
```

Each can also be set, changed or removed later, as an attribute:

```python
server.connection_observer = connection
server.request_observer = request
session.anomaly_observer = None
```

The listener passes its `request_observer` to the session, so
`server.request_observer` and `session.request_observer` are the same
attribute. A session driven without a listener takes a `request_observer` of
its own.

To publish the requests as a JSON body per fragment, defined by a versioned
JSON Schema, pass each record to `py1815.traffic`; see
[DNP3 traffic records](traffic.md).

A connection accepted and then closed by the master is reported as two events:

```json
{"role": "outstation", "direction": "inbound", "outcome": "accepted", "transport": "tcp",
 "remote": {"host": "192.0.2.10", "port": 49152}, "local": {"host": "198.51.100.5", "port": 20000},
 "peer_identity": null, "reason": "", "name": null, "timestamp": 1792310400.0}
{"role": "outstation", "direction": "inbound", "outcome": "ended", "transport": "tcp",
 "remote": {"host": "192.0.2.10", "port": 49152}, "local": {"host": "198.51.100.5", "port": 20000},
 "peer_identity": null, "reason": "closed by peer", "name": null, "timestamp": 1792310460.0}
```

The outstation reports these outcomes:

| Outcome | When | Reason |
|---|---|---|
| `accepted` | A connection is admitted as the master's. Over TLS, `peer_identity` is the allow-list entry the certificate matched. | empty |
| `refused` | A TLS peer is not on the allow-list, the listener stopped while the connection was being admitted, or admission failed. | `not authorized: ...` naming what the certificate offered, `listener stopped`, `admission failed` |
| `displaced` | A newer connection was admitted in place of this one. | `displaced by <address>:<port>` |
| `ended` | An admitted connection ended. | `closed by peer`, `connection reset`, `broken pipe`, `timeout` (nothing received within the idle timeout, or the peer stopped reading), `listener stopped`, `error: <exception type>` |

Each admitted connection is reported `accepted` once and then `displaced` or
`ended` once. A TLS handshake that fails, such as one from a client whose
certificate the context does not trust, ends before the listener sees the
connection, and is not reported.

## At the master

```python
from py1815.master import Master

async with Master() as master:
    lab = await master.add("lab", host="192.0.2.10", connection_observer=connection)
```

The master reports these outcomes. `name` is the name the outstation was added
under, and `remote` is the host and port connected to.

| Outcome | When | Reason |
|---|---|---|
| `connected` | The connection is made. Over TLS, `peer_identity` is the name the outstation's certificate was checked against, or its `sha256:` fingerprint when the context checks no name. | empty |
| `failed` | An attempt to connect failed. Every attempt is reported, including each automatic reconnection attempt. | `refused`, `timeout`, `TLS failure: ...`, `connection reset`, `unreachable: ...`, `closed at once` |
| `lost` | A connection that was made ended without `close()`. | `closed by peer`, `connection reset`, `timeout`, `TLS failure: ...`, `error: ...` |
| `ended` | `close()` closed the connection. | `closed by the master` |

Each `connected` is followed by one `lost` or `ended`. A reconnection attempt
whose new connection the outstation closes at once is reported as `connected`
and `lost`, and then also as `failed` with the reason `closed at once`, so that a
count of failed attempts includes it. `on_connection`, which is called with
`True` and `False`, works as before, beside the observer.

## Protocol anomalies

Each anomaly has a stable `code`, a `severity`, the `message` the session also
logs, and the link addresses involved. `peer` is the connection the octets
arrived on, or the sender of a broadcast datagram, when the session is served
by `OutstationServer`; it is None for a session driven some other way.

```json
{"code": "unexpected_master_address", "severity": "high",
 "message": "dropping frame from unexpected master address 2", "source": 2, "destination": 1024,
 "peer": {"host": "192.0.2.10", "port": 49152}, "timestamp": 1792310400.0}
```

| Code | Severity | What the session did |
|---|---|---|
| `unexpected_master_address` | high | Dropped a frame from a master address other than the one it serves |
| `invalid_source_address` | high | Dropped a frame from an address no master can have: a reserved or broadcast address, or the outstation's own |
| `invalid_frame_count_valid` | medium | Dropped a frame whose frame count valid bit does not match its function |
| `link_payload_mismatch` | medium | Dropped a user data frame with no data, or another link function carrying data |
| `malformed_broadcast_write` | medium | Dropped a broadcast write whose objects could not be read |
| `not_a_request` | medium | Dropped a fragment that cannot be a request: too short, not a whole message, or marked unsolicited |
| `malformed_request` | medium | Answered a request whose object headers could not be read with an error indication |
| `transport_error` | low | Discarded a transport segment out of sequence, too large, or otherwise refused |
| `broadcast_transport_error` | low | The same, for a broadcast |
| `unsolicited_not_confirmed` | low | Stopped retrying an unsolicited response the master did not confirm; its events stay buffered |
| `broadcast_not_acted_on` | info | Received a broadcast and did not carry it out: the function is disabled, broadcast controls are off, or the function is not one acted on by broadcast |

The severities mean:

- **high**: traffic from an address that should not be speaking on this
  association.
- **medium**: a malformed frame or request, from a defective or misconfigured
  peer or one probing the outstation.
- **low**: as easily explained by a lossy link or a slow master as by
  misbehavior.
- **info**: expected in normal operation, and reported for completeness.

`SEVERITY` maps each code to its severity. Requests the outstation refuses with
an indication, such as an unsupported function or a control it cannot carry out,
are answers the protocol defines and are not reported as anomalies.

## Requests

Each request the session handles is reported once, after the response is
built. `request` and `response` are the application fragments, from the
application control octet to the last object, without the link and transport
framing. `peer` is the master's end of the connection the request arrived on,
or the sender of a broadcast datagram, and `local` is the outstation's end,
when the session is served by `OutstationServer`. `local` is None for a
broadcast datagram, and both are None for a session driven some other way.

An integrity poll, with the octets written as hex:

```json
{"peer": {"host": "192.0.2.10", "port": 49152}, "source": 1, "destination": 1024,
 "function": 1, "request": "c1013c02063c03063c04063c0106",
 "response": "c1810000010200000301010101", "unsolicited": false, "timestamp": 1792310400.0,
 "local": {"host": "198.51.100.5", "port": 20000}}
```

| What arrived or was sent | `function` | `response` |
|---|---|---|
| A request the session answered, including a refusal with an indication | the request's | the response |
| A request repeated by a master that did not hear the answer | the request's | the response, sent again |
| A confirmation | 0 | the next fragment of a response that spans several, otherwise None |
| A function that takes no response, such as direct operate without response, whether or not it is carried out | the request's | None |
| A request sent to a broadcast address; `destination` is that address | the request's | None |
| A read held while an unsolicited response waits for its confirmation | the request's | the response, when the read is answered; None, when the read is discarded unanswered |
| An unsolicited response; `unsolicited` is true, `request` is empty, `source` is the outstation and `destination` the master | 130 | the unsolicited response, each time it is sent |

A response that spans several fragments is reported in parts: the first
fragment with the request, and each later one with the confirmation that drew
it out. A read held behind an unsolicited response is reported when it is
answered or discarded, not when it arrives, so it may follow the record of a
request that arrived after it.

A frame or fragment reported as a protocol anomaly is not reported as a
request as well. That includes a request whose object headers could not be
read, which is answered with an error indication.

## Writing an observer

An observer is called on the event loop, or for a session driven without one, on
the thread that passed it the octets. It should return quickly: hand the record
to a queue or a logger rather than writing to a remote service in the call.

An observer that raises does not affect the connection or the session. The
first exception from an observer is logged with its traceback at ERROR; later
exceptions from the same observer are logged at DEBUG.

Each record is a frozen dataclass of strings, numbers, booleans and nested
`Endpoint` records, so `dataclasses.asdict` gives a dictionary that
`json.dumps` accepts. The exception is the octets of a `RequestRecord`, which
are `bytes`: convert them first, to hex as above or to base64.
`timestamp` is seconds since the Unix epoch. A `reason` or a `message` holds no
secret: no key, password or token is ever part of one.
