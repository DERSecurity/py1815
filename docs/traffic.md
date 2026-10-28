# Traffic records for a network monitor

A passive network monitor that watches DNP3 traffic dissects each application
fragment with Wireshark's DNP3 dissector and publishes a description of it: a
JSON message body inside a message envelope. An application that embeds this
library's outstation or master already knows every fragment it sends and
receives. `py1815.traffic` turns those fragments into the same bodies and
envelopes, so the application can publish its own traffic on the monitor's
channel and the monitor's consumers handle it as captured traffic, without
conversion code of their own.

The envelope type is in `py1815.envelope`. It is a copy of the published
envelope format and needs no other package.

## From the outstation

Give the listener a request observer (see
[Connection, request and anomaly reports](observers.md)), and turn each
`RequestRecord` into envelopes:

```python
from py1815 import OutstationServer, RequestRecord
from py1815.traffic import record_messages


def publish(record: RequestRecord) -> None:
    for message in record_messages(record, forwarder_id="substation-7"):
        queue.put(message.to_json())


server = OutstationServer(session, bind="0.0.0.0:20000", request_observer=publish)
```

A record gives one envelope for the request and one for the response, or the
request alone when nothing was sent back. An unsolicited response gives one.
Every envelope is stamped with the record's time.

The record's `peer` and `local` are the master's and the outstation's ends of
the connection, and fill the body's `source_ip` and `destination_ip` and the
envelope's `source`. A record without `local`, from a broadcast datagram or a
session driven without a listener, needs the outstation's address given:
`record_messages(record, outstation=Endpoint("198.51.100.5", 20000))`.
Without one it raises `ValueError`. `record_bodies(record)` returns the bodies
alone.

## From the master

Give the outstation an `on_exchange` and an `on_unsolicited`, and build the
envelopes from each exchange and unsolicited response. `connection` holds the
two ends of the connection the master made:

```python
from py1815.master import Master
from py1815.traffic import exchange_messages, unsolicited_message

async with Master() as master:
    lab = await master.add("lab", host="198.51.100.5")

    def publish(exchange):
        connection = lab.connection
        for message in exchange_messages(
            exchange,
            master_address=lab.association.master_address,
            outstation_address=lab.association.outstation_address,
            master=connection.local,
            outstation=connection.remote,
        ):
            queue.put(message.to_json())

    lab.on_exchange = publish
```

An exchange gives one envelope for the request and one for each response
fragment. The responses are stamped with the time the exchange ended, `at`,
which is now when it is not given, and the request with the time it was first
sent. A request sent again after a timeout is described once.
`unsolicited_message` does the same for an unsolicited response, and
`exchange_bodies` and `unsolicited_body` return the bodies alone.

## The body

```json
{"source_address": 1, "destination_address": 1024, "function_code": 2, "prm": 1,
 "source_ip": "192.0.2.10", "destination_ip": "198.51.100.5",
 "points": [{"type": "binary", "index": 7, "value": 0}],
 "direction": "request", "objects": [{"group": 80, "variation": 1}]}
```

| Key | Value |
|---|---|
| `source_address`, `destination_address` | The link addresses of the sender and the receiver |
| `function_code` | The application function code |
| `prm` | The link layer's primary-message bit: 1, since every fragment travels as user data |
| `source_ip`, `destination_ip` | The addresses of the sender and the receiver, or null where they are not known |
| `points` | The values the fragment carries, described below |
| `direction` | `response` for function codes 129 and 130, otherwise `request` |
| `objects` | One `{"group", "variation"}` per object header, in the order sent |
| `apdu_rejected` | Only on a response that ends inside an object: `malformed`, with `points` and `objects` empty |

The keys are always in this order, which matters to a consumer: the envelope's
`hash` covers the payload text.

Object headers are listed for the requests whose headers the dissector reads:
read, write, select, operate, the two direct operates, the four freezes,
enable and disable unsolicited, and the file functions. Other requests, such as
a cold restart or a confirmation, list none.

### Points

Each point is `{"type", "index", "value"}`, with `"quality"` added where the
monitor reads one. The monitor reports a value only where the dissector
exposes one, so some objects give no point:

| Objects | `type` | `value` | `quality` |
|---|---|---|---|
| Packed binary: group 1, 10 and 80 variation 1 | `binary` | 0 or 1 | none |
| Counters and frozen counters, and their events: groups 20 to 23 | `counter` | an integer | none |
| Analog inputs: group 30 variations 1 to 5, and their events, group 32 variations 1 to 5 and 7 | `analog` | a number | the flag octet, for a variation that has one |
| Binary objects with flags, double-bit inputs, double-precision analog values, frozen analog inputs, analog outputs, commands, times | no point | | |

A single-precision analog value is rounded to six significant digits, as the
dissector displays it. Every group 80 point in an octet takes the octet's
lowest bit as its value, not its own bit, because that is how the dissector
reports the internal indications.

Points are listed analog first, then binary, then counter, each in the order
sent, and at most 2000 of one type. Indices are those on the wire, except where
two groups of one type share a fragment: the first group to give points of the
type keeps its indices, and each header of another group of that type is
numbered on from the highest index used so far. A class poll that returns
packed binary inputs 0 to 3 and then packed binary outputs 0 and 1 lists the
outputs as 4 and 5.

A response is read as far as the master's decoder reads it. Objects after a
group or variation it does not read are not listed, where the monitor would
list them.

## The envelope

```json
{"version": "0.3.0", "protocol": "dnp3", "direction": "upstream",
 "timestamp": "2026-10-27T12:00:00.250000+00:00", "client_id": "1024",
 "forwarder_id": "", "payload": {"content_type": "application/json",
 "data": "{\"source_address\": 1, ...}", "encoding": "utf-8"},
 "source": {"ip": "198.51.100.5", "port": 20000},
 "hash": "b2e5ecfe-3fc1-30db-bf63-f2f00479ead3", "is_valid": true,
 "protocol_data": {"extra": {"capture_origin": "live", "client_id_source": ""}}}
```

- `version` is this library's release, or `2.0` when it has none.
- `direction` is `upstream` for every DNP3 message, as the monitor writes it.
- `client_id` is the outstation's link address: the source address of a
  response and the destination address of a request.
- `source` is the outstation's address and port, whichever end sent the
  fragment.
- `forwarder_id` is the `forwarder_id` given, empty by default.
- `protocol_data.extra.capture_origin` is the `capture_origin` given, `live` by
  default.
- `hash` is a UUIDv3 over the protocol, `client_id`, `timestamp` and the
  payload text.

`ProtocolMessage.from_json` reads an envelope back, and `message.body` returns
its payload as a dictionary.
