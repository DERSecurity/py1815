"""DNP3 traffic described in the shape a network monitor publishes it.

A network monitor that watches DNP3 traffic dissects each application fragment
with Wireshark's DNP3 dissector and publishes a description of it: a message
body, in a :class:`~py1815.envelope.ProtocolMessage` envelope. This module
builds the same bodies and envelopes from what this library already reports:
a :class:`~py1815.observers.RequestRecord` from the outstation, and an
exchange or unsolicited response from the master. An application can then
publish the traffic it serves or polls on the monitor's channel, and the
monitor's consumers treat it as captured traffic.

A body has these keys, in this order:

- ``source_address``, ``destination_address``: the link addresses.
- ``function_code``: the application function code.
- ``prm``: the link layer's primary-message bit, 1 on every frame that carries
  a fragment.
- ``source_ip``, ``destination_ip``: the addresses of the connection's two
  ends, or None where they are not known.
- ``points``: the values the fragment carries, each
  ``{"type", "index", "value"}`` and, for an analog value with a flag octet,
  ``"quality"``.
- ``direction``: ``"response"`` for function codes 129 and 130, otherwise
  ``"request"``.
- ``objects``: one ``{"group", "variation"}`` per object header.
- ``apdu_rejected``: present only on a response whose objects end early, with
  the value ``"malformed"``. Its ``points`` and ``objects`` are then empty.

The points are what the monitor reads from the dissector, which exposes a
value for some objects and not for others (D103). A point's ``type`` is
``analog``, ``binary`` or ``counter``:

- ``binary``: the packed variations, group 1, 10 and 80 variation 1. A binary
  object with a flag octet carries its state in that octet, which the
  dissector reports as flags and not as a value, so it gives no point.
- ``counter``: groups 20 to 23, every variation, with no quality.
- ``analog``: group 30 variations 1 to 5 and group 32 variations 1 to 5 and
  7. The double-precision variations, the frozen analog inputs and the analog
  outputs give no point. A single-precision value is rounded to six
  significant digits, as the dissector displays it.

Points are listed analog, then binary, then counter, each in the order sent.
Indices are the indices on the wire, with one exception that comes from the
monitor: within a fragment, the first group to give points of a type keeps
its indices, and each header of another group of that type is numbered on
from the highest index used so far.

What this module does not know it leaves out. A response is read as far as
:mod:`py1815.decode` reads it, so the objects after a group or variation that
module does not read are not listed, where the monitor would list them.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from py1815.application import QualifierCode, build_response
from py1815.decode import LAYOUTS, DecodedBlock, DecodedObject, Layout, decode_blocks
from py1815.envelope import (
    NetworkEndpoint,
    Protocol,
    ProtocolMessage,
    ProtocolMetadata,
    WireDirection,
)
from py1815.observers import Endpoint, RequestRecord

if TYPE_CHECKING:
    from py1815.application import Response
    from py1815.master.association import Exchange, Unsolicited

#: The key, in the envelope's ``protocol_data.extra``, that says where the
#: traffic was captured, and the value for traffic seen as it happened.
CAPTURE_ORIGIN_KEY = "capture_origin"
CAPTURE_ORIGIN_LIVE = "live"

#: The key, beside it, that says how ``client_id`` was learned. The monitor
#: declares nothing for DNP3 and writes it empty.
CLIENT_ID_SOURCE_KEY = "client_id_source"

ANALOG = "analog"
BINARY = "binary"
COUNTER = "counter"

#: The order point types are listed in.
_TYPE_ORDER = (ANALOG, BINARY, COUNTER)

#: The most points of one type listed for one fragment; the rest are dropped.
MAX_POINTS_PER_TYPE = 2000

#: The function codes of a response from the outstation.
_RESPONSE_FUNCTIONS = frozenset({129, 130})

#: The primary-message bit of the frames that carry fragments. A request and
#: a response both travel as user data, which a primary station sends.
_PRIMARY = 1

#: Request functions whose object headers the dissector reads: read, write,
#: select, operate, the two direct operates, the four freezes, enable and
#: disable unsolicited, and the three file functions. Wireshark 4.0 reads no
#: header in any other request (D103).
_HEADER_FUNCTIONS = frozenset({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 21, 25, 26, 27})

#: Request functions whose headers are followed by objects: write, select,
#: operate and the two direct operates.
_DATA_FUNCTIONS = frozenset({2, 3, 4, 5, 6})

#: Group 80 variation 1, the internal indications.
_INDICATIONS = (80, 1)

#: The objects read here. The table the master reads with, and the internal
#: indications, which a master writes to clear the restart bit and the
#: dissector reports as binary points.
_LAYOUTS: dict[tuple[int, int], Layout] = {
    **LAYOUTS,
    _INDICATIONS: Layout(None, flags=False, packed=True),
}

_PACKED_BINARY = frozenset({(1, 1), (10, 1), _INDICATIONS})
_COUNTER_GROUPS = frozenset({20, 21, 22, 23})
_ANALOG = frozenset({(30, v) for v in (1, 2, 3, 4, 5)} | {(32, v) for v in (1, 2, 3, 4, 5, 7)})
_SINGLE_PRECISION = frozenset({(30, 5), (32, 5), (32, 7)})

#: Octets of the range or count that follows a qualifier in a request header,
#: and octets of each index after it.
_RANGE_OCTETS: dict[int, tuple[int, int]] = {
    QualifierCode.UINT8_START_STOP: (2, 0),
    QualifierCode.UINT16_START_STOP: (4, 0),
    QualifierCode.ALL_OBJECTS: (0, 0),
    QualifierCode.UINT8_COUNT: (1, 0),
    QualifierCode.UINT16_COUNT: (2, 0),
    QualifierCode.UINT8_COUNT_UINT8_INDEX: (1, 1),
    QualifierCode.UINT16_COUNT_UINT16_INDEX: (2, 2),
}


# ------------------------------------------------------------------- bodies


def fragment_body(
    fragment: bytes,
    *,
    source: int,
    destination: int,
    source_ip: str | None = None,
    destination_ip: str | None = None,
) -> dict[str, Any]:
    """Return the message body for one application fragment, request or response.

    ``source`` and ``destination`` are the link addresses of the frames that
    carried it, and the two addresses the ends of the connection.
    """
    function = fragment[1] if len(fragment) > 1 else 0
    body: dict[str, Any] = {
        "source_address": source,
        "destination_address": destination,
        "function_code": function,
        "prm": _PRIMARY,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "points": [],
        "direction": "response" if function in _RESPONSE_FUNCTIONS else "request",
    }
    blocks: Sequence[DecodedBlock]
    if function in _RESPONSE_FUNCTIONS:
        decoded = decode_blocks(fragment[4:], _LAYOUTS)
        if decoded.truncated:
            # The dissector marks a response that ends inside an object as
            # malformed, and the monitor then trusts none of its values.
            body["objects"] = []
            body["apdu_rejected"] = "malformed"
            return body
        blocks = decoded.blocks
    elif function in _DATA_FUNCTIONS:
        blocks = decode_blocks(fragment[2:], _LAYOUTS).blocks
    elif function in _HEADER_FUNCTIONS:
        blocks = _headers(fragment[2:])
    else:
        blocks = ()
    body["objects"] = [{"group": block.group, "variation": block.variation} for block in blocks]
    body["points"] = _points(blocks)
    return body


def _headers(data: bytes) -> list[DecodedBlock]:
    """Return the object headers of a request that carries no objects, as empty blocks."""
    headers: list[DecodedBlock] = []
    offset = 0
    while offset + 3 <= len(data):
        group, variation, qualifier = data[offset : offset + 3]
        headers.append(DecodedBlock(group, variation, qualifier, ()))
        sizes = _RANGE_OCTETS.get(qualifier)
        if sizes is None:
            break
        range_octets, index_octets = sizes
        count = int.from_bytes(data[offset + 3 : offset + 3 + range_octets], "little")
        offset += 3 + range_octets + (count * index_octets if index_octets else 0)
    return headers


def _point(decoded: DecodedObject) -> dict[str, Any] | None:
    """Return the point the monitor reports for one object, or None when it reports none."""
    if decoded.index is None or decoded.value is None:
        return None
    key = (decoded.group, decoded.variation)
    if key == _INDICATIONS:
        # The dissector reports every internal indication bit in an octet as
        # that octet's lowest bit, and the monitor reads what it reports.
        return {"type": BINARY, "index": decoded.index, "value": decoded.raw[0] & 1}
    if key in _PACKED_BINARY:
        return {"type": BINARY, "index": decoded.index, "value": int(decoded.value)}
    if decoded.group in _COUNTER_GROUPS:
        return {"type": COUNTER, "index": decoded.index, "value": int(decoded.value)}
    if key not in _ANALOG:
        return None
    value = float(decoded.value)
    if key in _SINGLE_PRECISION:
        # The dissector displays a single-precision value to six significant
        # digits, and the monitor reads the display.
        value = float(f"{value:.6g}")
    point: dict[str, Any] = {"type": ANALOG, "index": decoded.index, "value": value}
    if decoded.flags is not None:
        point["quality"] = decoded.flags
    return point


def _points(blocks: Iterable[DecodedBlock]) -> list[dict[str, Any]]:
    """Return the points of a fragment, by type and then in the order sent."""
    by_type: dict[str, list[dict[str, Any]]] = {kind: [] for kind in _TYPE_ORDER}
    first_group: dict[str, int] = {}
    highest: dict[str, int] = {}
    for block in blocks:
        # Where this header is numbered from, if it is not the first group of
        # its type to give points.
        follows = {kind: highest.get(kind, -1) + 1 for kind in _TYPE_ORDER}
        for position, decoded in enumerate(block.objects):
            point = _point(decoded)
            if point is None:
                continue
            kind = point["type"]
            if first_group.setdefault(kind, block.group) != block.group:
                point["index"] = follows[kind] + position
            listed = by_type[kind]
            if len(listed) >= MAX_POINTS_PER_TYPE:
                continue
            highest[kind] = max(highest.get(kind, -1), point["index"])
            listed.append(point)
    return [point for kind in _TYPE_ORDER for point in by_type[kind]]


def _host(endpoint: Endpoint | None) -> str | None:
    return None if endpoint is None else endpoint.host


def record_bodies(
    record: RequestRecord, *, outstation: Endpoint | None = None
) -> list[dict[str, Any]]:
    """Return the message bodies of one request record: the request, then the response.

    An unsolicited response gives one body, and a request that was not
    answered gives the request alone. ``outstation`` is this outstation's
    address, for a record that does not carry one in ``local``.
    """
    master_ip = _host(record.peer)
    outstation_ip = _host(outstation or record.local)
    if record.unsolicited:
        assert record.response is not None
        return [
            fragment_body(
                record.response,
                source=record.source,
                destination=record.destination,
                source_ip=outstation_ip,
                destination_ip=master_ip,
            )
        ]
    bodies = [
        fragment_body(
            record.request,
            source=record.source,
            destination=record.destination,
            source_ip=master_ip,
            destination_ip=outstation_ip,
        )
    ]
    if record.response is not None:
        bodies.append(
            fragment_body(
                record.response,
                source=record.destination,
                destination=record.source,
                source_ip=outstation_ip,
                destination_ip=master_ip,
            )
        )
    return bodies


def _fragment(response: Response) -> bytes:
    return build_response(
        control=response.control, iin=response.iin, body=response.body, function=response.function
    )


def exchange_bodies(
    exchange: Exchange,
    *,
    master_address: int,
    outstation_address: int,
    master: Endpoint | None = None,
    outstation: Endpoint | None = None,
) -> list[dict[str, Any]]:
    """Return the message bodies of one master exchange: the request, then each response fragment.

    ``master`` and ``outstation`` are the two ends of the master's connection.
    The request is described once, however many times it was sent again.
    """
    destination = outstation_address if exchange.broadcast is None else int(exchange.broadcast)
    bodies = [
        fragment_body(
            exchange.request,
            source=master_address,
            destination=destination,
            source_ip=_host(master),
            destination_ip=_host(outstation),
        )
    ]
    bodies.extend(
        fragment_body(
            _fragment(response),
            source=outstation_address,
            destination=master_address,
            source_ip=_host(outstation),
            destination_ip=_host(master),
        )
        for response in exchange.fragments
    )
    return bodies


def unsolicited_body(
    unsolicited: Unsolicited,
    *,
    master_address: int,
    outstation_address: int,
    master: Endpoint | None = None,
    outstation: Endpoint | None = None,
) -> dict[str, Any]:
    """Return the message body of one unsolicited response the master received."""
    return fragment_body(
        _fragment(unsolicited.response),
        source=outstation_address,
        destination=master_address,
        source_ip=_host(outstation),
        destination_ip=_host(master),
    )


# ------------------------------------------------------------------ envelopes


def envelope(
    body: dict[str, Any],
    *,
    outstation: Endpoint,
    at: float,
    forwarder_id: str = "",
    capture_origin: str = CAPTURE_ORIGIN_LIVE,
) -> ProtocolMessage:
    """Return the envelope the monitor publishes one message body in.

    The envelope names the outstation: ``source`` is its address and port and
    ``client_id`` its link address. The monitor marks every DNP3 message
    ``upstream``, whichever way it travelled.

    Args:
        body: A body from :func:`fragment_body` or the functions built on it.
        outstation: The outstation's address and port.
        at: When the fragment was sent, in seconds since the Unix epoch.
        forwarder_id: Names the system publishing the message.
        capture_origin: Where the traffic was captured; ``"live"`` for
            traffic seen as it happened.
    """
    if body.get("source_ip") == outstation.host:
        link_address = body.get("source_address")
    else:
        link_address = body.get("destination_address")
    return ProtocolMessage(
        protocol=Protocol.DNP3,
        direction=WireDirection.UPSTREAM,
        client_id=str(link_address if link_address is not None else 0),
        payload=body,
        source=NetworkEndpoint(ip=outstation.host, port=outstation.port),
        forwarder_id=forwarder_id,
        protocol_data=ProtocolMetadata(
            extra={
                CAPTURE_ORIGIN_KEY: capture_origin.strip() or CAPTURE_ORIGIN_LIVE,
                CLIENT_ID_SOURCE_KEY: "",
            }
        ),
        timestamp=datetime.fromtimestamp(at, UTC).isoformat(),
    )


def _known(outstation: Endpoint | None) -> Endpoint:
    if outstation is None:
        raise ValueError(
            "the outstation's address is not known; give it as outstation= to build an envelope"
        )
    return outstation


def record_messages(
    record: RequestRecord,
    *,
    outstation: Endpoint | None = None,
    forwarder_id: str = "",
    capture_origin: str = CAPTURE_ORIGIN_LIVE,
) -> list[ProtocolMessage]:
    """Return the envelopes of one request record, stamped with the record's time.

    Raises:
        ValueError: If the record has no ``local`` address and no
            ``outstation`` is given.
    """
    endpoint = _known(outstation or record.local)
    return [
        envelope(
            body,
            outstation=endpoint,
            at=record.timestamp,
            forwarder_id=forwarder_id,
            capture_origin=capture_origin,
        )
        for body in record_bodies(record, outstation=endpoint)
    ]


def exchange_messages(
    exchange: Exchange,
    *,
    master_address: int,
    outstation_address: int,
    outstation: Endpoint,
    master: Endpoint | None = None,
    at: float | None = None,
    forwarder_id: str = "",
    capture_origin: str = CAPTURE_ORIGIN_LIVE,
) -> list[ProtocolMessage]:
    """Return the envelopes of one master exchange.

    ``at`` is when the exchange ended, now if not given. The responses are
    stamped with it, and the request with the time it was first sent.
    """
    ended = time.time() if at is None else at
    bodies = exchange_bodies(
        exchange,
        master_address=master_address,
        outstation_address=outstation_address,
        master=master,
        outstation=outstation,
    )
    return [
        envelope(
            body,
            outstation=outstation,
            at=ended - exchange.elapsed if number == 0 else ended,
            forwarder_id=forwarder_id,
            capture_origin=capture_origin,
        )
        for number, body in enumerate(bodies)
    ]


def unsolicited_message(
    unsolicited: Unsolicited,
    *,
    master_address: int,
    outstation_address: int,
    outstation: Endpoint,
    master: Endpoint | None = None,
    at: float | None = None,
    forwarder_id: str = "",
    capture_origin: str = CAPTURE_ORIGIN_LIVE,
) -> ProtocolMessage:
    """Return the envelope of one unsolicited response, stamped ``at`` or now."""
    body = unsolicited_body(
        unsolicited,
        master_address=master_address,
        outstation_address=outstation_address,
        master=master,
        outstation=outstation,
    )
    return envelope(
        body,
        outstation=outstation,
        at=time.time() if at is None else at,
        forwarder_id=forwarder_id,
        capture_origin=capture_origin,
    )


__all__ = [
    "ANALOG",
    "BINARY",
    "CAPTURE_ORIGIN_KEY",
    "CAPTURE_ORIGIN_LIVE",
    "CLIENT_ID_SOURCE_KEY",
    "COUNTER",
    "MAX_POINTS_PER_TYPE",
    "envelope",
    "exchange_bodies",
    "exchange_messages",
    "fragment_body",
    "record_bodies",
    "record_messages",
    "unsolicited_body",
    "unsolicited_message",
]
