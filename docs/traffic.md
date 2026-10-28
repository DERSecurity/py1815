# DNP3 traffic records

An application that embeds this library's outstation or master knows every
fragment it sends and receives. `py1815.traffic` describes each fragment as a
JSON body and wraps it in a message envelope, so the application can publish
its own DNP3 traffic to consumers that also take traffic captured from the
network, without conversion code of its own.

The body is defined by a versioned JSON Schema, the DNP3 traffic schema,
version 1, with the `$id` `https://dersec.com/schemas/dnp3-traffic/v1`. A copy
ships in the package, and `py1815.traffic.load_schema()` returns it as a
dictionary. Every body this library builds is valid against it. The envelope
type is in `py1815.envelope`. Neither needs another package.

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
the connection. They fill each body's IP addresses and ports and the
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

## From any fragment

`fragment_body` describes one application fragment, from the application
control octet to the last object, given which end sent it and the link
addresses:

```python
from py1815.observers import Endpoint
from py1815.traffic import fragment_body

body = fragment_body(
    bytes.fromhex("C3 05 0C 01 28 01 00 03 00 03 01 00 00 00 00 00 00 00 00 00"),
    direction="request",
    source=1,
    destination=10,
    sender=Endpoint("192.0.2.10", 50123),
    receiver=Endpoint("192.0.2.20", 20000),
)
```

`direction` is `"request"` for a fragment the master sent and `"response"`
for one the outstation sent, an unsolicited response included. A response is
read with its internal indications. `sender` and `receiver` are optional; an
end that is not given is left out of the body.

## The body

The direct operate above, a CROB that latches output 3 on:

```json
{"schema": 1, "source_address": 1, "destination_address": 10, "function_code": 5,
 "prm": 1, "direction": "request", "unsolicited": false,
 "source_ip": "192.0.2.10", "source_port": 50123,
 "destination_ip": "192.0.2.20", "destination_port": 20000,
 "objects": [{"group": 12, "variation": 1, "qualifier": 40, "count": 1}],
 "points": [{"type": "binary_output", "group": 12, "variation": 1, "index": 3,
             "command": true, "op_type": 3, "trip_close": 0, "clear": false,
             "queue": false, "count": 1, "on_time": 0, "off_time": 0, "status": 0}]}
```

| Key | Value |
|---|---|
| `schema` | `1`, the version of the body's shape |
| `source_address`, `destination_address` | The link addresses of the sender and the receiver |
| `function_code` | The application function code, as sent |
| `prm` | The link layer's primary-message bit: 1, since every fragment travels as user data |
| `direction` | `request` from the master, `response` from the outstation |
| `unsolicited` | The UNS bit of the application control octet |
| `iin` | On a response only: the names of the internal indication bits set, `[]` when none is |
| `source_ip`, `source_port`, `destination_ip`, `destination_port` | The ends of the connection. Left out when not known; an address that is not an IP address is left out and its port kept |
| `objects` | One entry per object header, in the order sent |
| `points` | Every point the fragment carries, in the order sent |
| `apdu_rejected` | Only on a fragment that cannot be read to its end; see below |

The keys are always in this order, which matters to a consumer that
deduplicates: the envelope's `hash` covers the payload text.

The internal indication names, IIN1.0 to IIN2.7, are `broadcast`,
`class_1_events`, `class_2_events`, `class_3_events`, `need_time`,
`local_control`, `device_trouble`, `device_restart`, `no_func_code_support`,
`object_unknown`, `parameter_error`, `event_buffer_overflow`,
`already_executing`, `config_corrupt`, `reserved_2` and `reserved_1`.

### Object headers

Each entry has `group`, `variation` and `qualifier`, the qualifier octet as
sent. Range specifier codes 0 to 5 add `start` and `stop`, codes 7, 8, 9 and
11 add `count`, and code 6 adds neither. Every header is listed, those that
carry no points included: a class read, a time write, a write of the internal
indications.

### Points

Every point has `type`, `group`, `variation`, `index` and `command`. `index`
is the index on the wire: the range start plus the object's position, or the
index in front of the object. Points of different types keep their own
indices, so binary input 5 and binary output 5 are different points.
`command` is true for a CROB (group 12) and an analog output block (group 41),
in a request or echoed in a response.

| `type` | Groups | `value` |
|---|---|---|
| `binary` | 1, 2 | 0 or 1 |
| `double_bit_binary` | 3, 4 | 0 intermediate, 1 off, 2 on, 3 indeterminate |
| `binary_output` | 10, 11, 12, 13 | 0 or 1; none on a CROB |
| `counter` | 20, 21, 22, 23 | An integer |
| `analog` | 30, 31, 32, 33 | A number |
| `analog_deadband` | 34 | A number |
| `analog_output` | 40, 41, 42, 43 | A number |
| `octet_string` | 110, 111 | The octets in lowercase hex |

The other fields appear where the object carries them:

- `flags`: the flag octet as sent. A binary object's state bits are part of
  it. A variation without flags has none.
- `time`: milliseconds since 1970 on the outstation's clock. A relative-time
  event is counted from the common time of occurrence before it in the same
  fragment, and has no `time` when there is none.
- `status`: the control status octet of a CROB, an analog output block, and
  their command events (groups 13 and 43). A binary output command event
  carries its commanded state in bit 7, as `value`, and its status in bits 0
  to 6.
- `op_type`, `trip_close`, `clear`, `queue`, `count`, `on_time` and
  `off_time`: a CROB's control code, split into its fields, and the rest of
  the block. A pattern control (group 12 variations 2 and 3) gives one CROB
  point, with variation 2, for each output its mask selects.
- `non_finite`: on a floating-point value that is not finite, `nan`, `inf` or
  `-inf`. `value` is then null, since JSON has no such numbers.

An integer variation gives an integer `value`, and a floating-point variation
the exact value sent: single precision `0.1` is `0.10000000149011612`.

Points come only from those groups. Objects of other groups, such as the time,
class data, files and the internal indications, appear in `objects` only.

### Rejected fragments

A fragment that cannot be read to its end is described with
`apdu_rejected` and with `objects` and `points` empty, since values read from
it cannot be trusted. Its addresses, function code and, when the response
header was complete, `iin` remain.

| `apdu_rejected` | When |
|---|---|
| `point_count` | The object data ends after a whole object, before the objects a header's range or count declares |
| `malformed` | Anything else that stops the reading: a fragment cut short inside a header or an object, a reserved qualifier, an inverted range in object data, a point sent with no index, an object this library cannot size, or more than 65536 points or 4096 object headers |

This library reads every object group and variation in the tables above, the
time and date (group 50 variations 1 to 4), the common time of occurrence
(51), the time delay (52), class data (60), the internal indications (80),
virtual terminal objects (112, 113), and any object sent with a size prefix,
which it walks past. A fragment that carries object data of any other group
or variation, such as device attributes (group 0) or the obsolete delta
counters, is reported as `malformed`.

## Validating

The schema is a JSON Schema, draft 2020-12. To check bodies with it, install a
validator such as `jsonschema`, which this library does not depend on:

```python
import jsonschema
from py1815.traffic import load_schema

schema = load_schema()
validator = jsonschema.Draft202012Validator(
    schema, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
)
validator.validate(body)
```

The IP address fields are checked only with a format checker, as here.

## The envelope

```json
{"version": "0.3.0", "protocol": "dnp3", "direction": "upstream",
 "timestamp": "2026-10-27T12:00:00.250000+00:00", "client_id": "10",
 "forwarder_id": "", "payload": {"content_type": "application/json",
 "data": "{\"schema\": 1, \"source_address\": 10, ...}", "encoding": "utf-8"},
 "source": {"ip": "192.0.2.20", "port": 20000},
 "hash": "…", "is_valid": true,
 "protocol_data": {"extra": {"capture_origin": "live", "client_id_source": ""}}}
```

- `version` is this library's release, or `2.0` when it has none.
- `direction` is `upstream` for every DNP3 message, whichever end sent it.
- `client_id` is the outstation's link address: the source address of a
  response and the destination address of a request.
- `source` is the outstation's address and port, whichever end sent the
  fragment.
- `forwarder_id` is the `forwarder_id` given, empty by default.
- `protocol_data.extra.capture_origin` is the `capture_origin` given, `live` by
  default.
- `hash` is a UUIDv3, in the DNS namespace, over
  `"<protocol>:<client_id>:<timestamp>:<payload text>"`.

`ProtocolMessage.from_json` reads an envelope back, and `message.body` returns
its payload as a dictionary.
