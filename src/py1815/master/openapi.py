"""The master's HTTP API, described as an OpenAPI document.

One description of every operation: what it takes, what it returns, and an
example of asking for it. :func:`build` turns that into an OpenAPI 3.1
document with a route for each operation, and the document is committed beside
the console, which serves it at ``/openapi.json``.

The description is checked against the service and not trusted: a test fails
when an operation exists that is not described here, or is described here and
does not exist, and when the committed document is not the one this module
builds.

    python -m py1815.master.openapi            # print the document
    python -m py1815.master.openapi --write    # write it where it is served from
    python -m py1815.master.openapi --check    # fail if the committed one is stale

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections.abc import Sequence
from typing import Any

from py1815.master.controls import OPERATIONS as OPERATIONS_BY_NAME
from py1815.master.requests import SCAN_KINDS

#: Where the document is committed, and served from.
DOCUMENT = pathlib.Path(__file__).parent / "console" / "openapi.json"

API_VERSION = "1"

_POINT_TYPES = ["bi", "bo", "counter", "frozen", "ai", "ao"]
_OUTCOMES = ["complete", "timeout", "sent", "abandoned"]

Schema = dict[str, Any]


def _ref(name: str) -> Schema:
    return {"$ref": f"#/components/schemas/{name}"}


def _object(properties: dict[str, Schema], required: Sequence[str] = (), **extra: Any) -> Schema:
    schema: Schema = {"type": "object", "properties": properties}
    if required:
        schema["required"] = list(required)
    schema.update(extra)
    return schema


def _nullable(schema: Schema) -> Schema:
    return {"oneOf": [schema, {"type": "null"}]}


_STRING: Schema = {"type": "string"}
_INTEGER: Schema = {"type": "integer"}
_NUMBER: Schema = {"type": "number"}
_BOOLEAN: Schema = {"type": "boolean"}
_INDEX: Schema = {"type": "integer", "minimum": 0, "maximum": 65535}
_ADDRESS: Schema = {"type": "integer", "minimum": 0, "maximum": 65519}
_FLAGS: Schema = {
    "description": "The flag bits that are set, by name. Null for a variation that carries "
    "no flag octet, which is not the same as none being set.",
    **_nullable({"type": "array", "items": _STRING}),
}
_VALUE: Schema = {
    "description": "A state, a count or an analog value. A float with no number is sent as "
    'the string "NaN", "Infinity" or "-Infinity".',
    "oneOf": [_BOOLEAN, _NUMBER, _STRING, {"type": "null"}],
}
_PER_TYPE_COUNTS = _object(dict.fromkeys(_POINT_TYPES, _INTEGER))
_OUTSTATION_NAME: Schema = {
    "type": "string",
    "description": "The name the outstation was added under.",
}

SCHEMAS: dict[str, Schema] = {
    "PointType": {
        "type": "string",
        "enum": _POINT_TYPES,
        "description": "Binary input, binary output status, counter, frozen counter, analog "
        "input, analog output status.",
    },
    "Tasks": _object(
        {
            "startup": {
                "type": "boolean",
                "description": "On connecting, and when the outstation reports that it "
                "restarted: stop its unsolicited reporting, then read everything it holds.",
            },
            "clear_restart": {
                "type": "boolean",
                "description": "Clear the restart indication once it has been seen. A write: "
                "off in a service that was not started to command.",
            },
            "write_time": {
                "type": "boolean",
                "description": "Set the outstation's clock when it asks for the time. A "
                "write: off in a service that was not started to command.",
            },
            "enable_unsolicited": {
                "type": "array",
                "items": {"type": "integer", "enum": [1, 2, 3]},
                "description": "After startup, ask the outstation to report these event "
                "classes without being polled.",
            },
            "events_when_indicated": {
                "type": "boolean",
                "description": "Fetch events when a response says there are some waiting.",
            },
            "integrity_on_overflow": {
                "type": "boolean",
                "description": "Read everything again when the outstation says its event "
                "buffer overflowed.",
            },
        },
        description="What the master does for an outstation without being asked.",
    ),
    "Outstation": _object(
        {
            "name": _STRING,
            "host": _STRING,
            "port": _INTEGER,
            "outstation_address": _ADDRESS,
            "master_address": _ADDRESS,
            "connected": _BOOLEAN,
            "indications": {
                "type": "array",
                "items": _STRING,
                "description": "The internal indications of the last response, by name.",
            },
            "last_response_at": _nullable(
                {"type": "number", "description": "Seconds since the epoch."}
            ),
            "counts": {
                "type": "object",
                "additionalProperties": _INTEGER,
                "description": "How the exchanges so far ended, by outcome.",
            },
            "unsolicited": {
                "type": "integer",
                "description": "Unsolicited responses received.",
            },
            "points": {
                **_PER_TYPE_COUNTS,
                "description": "Points reported so far, by type.",
            },
            "events": _INTEGER,
            "frames": _INTEGER,
            "repeat": {
                "type": "object",
                "additionalProperties": _NUMBER,
                "description": "The scans being repeated, by kind, as seconds between them.",
            },
            "tasks": _ref("Tasks"),
            "tasks_due": {
                "type": "array",
                "items": _STRING,
                "description": "The tasks waiting to be done, in the order they will be.",
            },
            "reconnect": {
                "description": "Seconds between attempts to make again a connection that "
                "was lost, or null when it is not made again.",
                **_nullable(_NUMBER),
            },
            "named": _BOOLEAN,
            "profile": {
                "description": "Points in the profile the outstation is meant to serve, by "
                "type, or null when no profile was given.",
                **_nullable(_PER_TYPE_COUNTS),
            },
        },
        required=[
            "name",
            "host",
            "port",
            "outstation_address",
            "master_address",
            "connected",
            "indications",
            "counts",
            "points",
            "repeat",
            "tasks",
            "tasks_due",
            "reconnect",
        ],
    ),
    "Object": _object(
        {
            "type": _nullable(_ref("PointType")),
            "group": _INTEGER,
            "variation": _INTEGER,
            "index": _nullable(_INDEX),
            "name": _nullable(_STRING),
            "value": _VALUE,
            "flags": _FLAGS,
            "time_ms": _nullable(
                {
                    "type": "integer",
                    "description": "The time the outstation gave, in milliseconds since the epoch.",
                }
            ),
            "synchronized": _nullable(_BOOLEAN),
            "event": _BOOLEAN,
        },
        required=["group", "variation", "index", "value", "flags", "event"],
        description="One object out of a response, decoded.",
    ),
    "ControlStatus": _object(
        {
            "type": {"type": "string", "enum": ["bo", "ao"]},
            "index": _INDEX,
            "name": _nullable(_STRING),
            "variation": _INTEGER,
            "value": {
                "description": "An analog output's value as sent, or a binary output's "
                "control code.",
            },
            "status": {
                **_nullable(_STRING),
                "description": "The status the outstation answered with, by name, as in "
                "SUCCESS or NOT_SUPPORTED. Null if the response did not carry this control.",
            },
            "echoed": {
                "type": "boolean",
                "description": "Whether what came back was the control as sent, apart from "
                "its status.",
            },
        },
        required=["type", "index", "variation", "value", "status", "echoed"],
        description="What an outstation said about one control.",
    ),
    "Operated": _object(
        {
            "mode": {"type": "string", "enum": ["direct", "select", "direct_no_ack"]},
            "operated": {
                "type": "boolean",
                "description": "Whether a request that operates was sent. False for a select "
                "the outstation refused, after which no operate is sent.",
            },
            "accepted": {
                **_nullable(_BOOLEAN),
                "description": "Whether the outstation accepted every control. Null when it "
                "never said: the request takes no acknowledgment, or the response did not "
                "arrive. That is not a refusal, and the output may have been operated.",
            },
            "statuses": {"type": "array", "items": _ref("ControlStatus")},
            "exchanges": {
                "type": "array",
                "items": _ref("Exchange"),
                "description": "Each request made, in order: one, or a select and an operate.",
            },
        },
        required=["mode", "operated", "accepted", "statuses", "exchanges"],
        description="A control request, or the two of a select and operate, and what came of them.",
    ),
    "Exchange": _object(
        {
            "function": {"type": "string", "description": "The request's function code."},
            "task": {
                "description": "The task the master made the request for of its own "
                "accord, or null for a request that was asked for.",
                **_nullable(_STRING),
            },
            "sequence": {"type": "integer", "minimum": 0, "maximum": 15},
            "outcome": {
                "type": "string",
                "enum": _OUTCOMES,
                "description": "How the exchange ended. An outstation that did not answer "
                "is a timeout, and not an error.",
            },
            "fragments": {"type": "integer", "description": "Response fragments received."},
            "indications": {
                "description": "The internal indications of the last fragment, by name, or "
                "null if nothing arrived.",
                **_nullable({"type": "array", "items": _STRING}),
            },
            "objects": {"type": "array", "items": _ref("Object")},
            "object_count": {
                "type": "integer",
                "description": "Objects received. More than are described in `objects` when "
                "a response is very large.",
            },
            "undecoded": {
                "type": "array",
                "items": _object(
                    {"problem": _STRING, "unread": {"type": "string", "description": "Hex."}},
                    required=["problem", "unread"],
                ),
                "description": "Where an object could not be read: why, and the octets from "
                "there on.",
            },
            "elapsed_ms": _NUMBER,
            "request": {"type": "string", "description": "The request fragment, in hex."},
        },
        required=[
            "function",
            "sequence",
            "outcome",
            "fragments",
            "indications",
            "objects",
            "object_count",
            "undecoded",
            "elapsed_ms",
            "request",
        ],
        description="One request and everything that came back for it.",
    ),
    "PointValue": _object(
        {
            "index": _INDEX,
            "name": _nullable(_STRING),
            "value": _VALUE,
            "flags": _FLAGS,
            "time_ms": _nullable(_INTEGER),
            "from_event": _BOOLEAN,
            "group": _INTEGER,
            "variation": _INTEGER,
            "age": {"type": "number", "description": "Seconds since it was received."},
        },
        required=["index", "value", "flags", "from_event", "group", "variation", "age"],
        description="The last thing an outstation said about one point.",
    ),
    "ProfilePoint": _object(
        {
            "index": _INDEX,
            "name": {"type": "string", "description": "The name as the profile's tables have it."},
            "label": {
                "type": "string",
                "description": "The name without the values it lists, for a point that is "
                "an enumeration; otherwise the name.",
            },
            "enumeration": {
                "description": "The values the point's name lists, in the order listed, or "
                "null when it lists none. A value is a number, a range such as `11-255`, "
                "or a number and up such as `99+`.",
                **_nullable(
                    {
                        "type": "array",
                        "items": _object(
                            {"value": _STRING, "name": _STRING}, required=["value", "name"]
                        ),
                    }
                ),
            },
            "mandatory": _BOOLEAN,
            "section": _nullable(_STRING),
        },
        required=["index", "name", "label", "enumeration", "mandatory", "section"],
        description="One point of the profile an outstation is meant to serve.",
    ),
    "Frame": _object(
        {
            "id": {"type": "integer", "description": "Counts up for the life of the trace."},
            "at": {"type": "number", "description": "Seconds since the epoch."},
            "direction": {
                "type": "string",
                "enum": ["tx", "rx"],
                "description": "Sent by this master, or received.",
            },
            "octets": {"type": "string", "description": "The frame, in hex."},
            "link": {"type": "object", "description": "The data link layer's reading."},
            "transport": _nullable(
                {"type": "object", "description": "The transport header, on user data."}
            ),
            "application": _nullable(
                {
                    "type": "object",
                    "description": "The application fragment, on the frame that completed it.",
                }
            ),
            "summary": {"type": "string", "description": "One line that says what it is."},
        },
        required=["id", "at", "direction", "octets", "link", "transport", "application", "summary"],
    ),
    "Error": _object(
        {
            "kind": {
                "type": "string",
                "enum": ["request", "connection", "not_allowed"],
                "description": "`request`: the message could not be acted on. `connection`: "
                "there was no connection to ask over.",
            },
            "message": _STRING,
        },
        required=["kind", "message"],
    ),
    "Failure": _object(
        {
            "id": {"description": "The id of the message, when it had one."},
            "ok": {"const": False},
            "error": _ref("Error"),
        },
        required=["ok", "error"],
    ),
}


def _outstation(
    properties: dict[str, Schema] | None = None, required: Sequence[str] = ()
) -> Schema:
    return _object(
        {"outstation": _OUTSTATION_NAME, **(properties or {})},
        required=["outstation", *required],
    )


_SCAN_KIND: Schema = {
    "type": "string",
    "enum": list(SCAN_KINDS),
    "description": "`integrity` is classes 1, 2, 3 and then 0. `events` is classes 1, 2 and "
    "3. `outputs` reads binary and analog output status by their groups, which an "
    "integrity poll does not return.",
}
_INDICES: Schema = {
    "oneOf": [{"type": "array", "items": _INDEX}, {"const": "all"}],
    "description": 'The indices wanted, or "all".',
}
_CLASSES: Schema = {
    "type": "array",
    "items": {"type": "integer", "enum": [1, 2, 3]},
    "description": "Event classes. All three when left out.",
}
_INTERVAL: Schema = {"type": "number", "exclusiveMinimum": 0, "description": "Seconds."}

#: Every operation of the service: what it does, what it takes, what it
#: returns, and an example of its parameters.
OPERATIONS: dict[str, dict[str, Any]] = {
    "status": {
        "summary": "The outstations, and how each stands",
        "tag": "Outstations",
        "params": _object({}),
        "result": _object(
            {
                "allow_control": {
                    "type": "boolean",
                    "description": "Whether this service carries out the operations that "
                    "command an outstation. When false they are refused as `not_allowed`.",
                },
                "outstations": {"type": "array", "items": _ref("Outstation")},
            },
            required=["allow_control", "outstations"],
        ),
        "example": {},
    },
    "add": {
        "summary": "Add an outstation, and connect to it",
        "description": "An outstation that cannot be reached is still added, and the answer "
        "is a connection error: it is listed as not connected and can be connected later. "
        "Once connected, the master settles the outstation and looks after it, as `tasks` "
        "says; `idle` waits for that to be done.",
        "tag": "Outstations",
        "params": _object(
            {
                "name": {"type": "string", "description": "What to call it. Used once."},
                "host": _STRING,
                "port": {"type": "integer", "default": 20000},
                "outstation_address": {**_ADDRESS, "default": 1024},
                "master_address": {**_ADDRESS, "default": 1},
                "response_timeout": {**_INTERVAL, "default": 5},
                "connect_timeout": {**_INTERVAL, "default": 5},
                "confirm": {
                    "type": "boolean",
                    "description": "Whether fragments that ask to be confirmed are. They "
                    "are, unless `manual` is given.",
                },
                "tasks": {
                    "description": "What the master does for the outstation unasked. A task "
                    "left out stands at its default: on, except `enable_unsolicited`, and "
                    "except the two that write in a service not started to command. Asking "
                    "for one of those two there is refused as `not_allowed`.",
                    **_ref("Tasks"),
                },
                "manual": {
                    "type": "boolean",
                    "default": False,
                    "description": "Send nothing that was not asked for: no task, and no "
                    "confirmation. `tasks` and `confirm` given beside it are kept as given.",
                },
                "reconnect": {
                    "description": "Seconds between attempts to make again a connection "
                    "that was made and then lost. Null for never.",
                    "default": 5,
                    **_nullable(_INTERVAL),
                },
                "integrity_interval": {
                    "description": "Repeat an integrity poll this often.",
                    **_nullable(_INTERVAL),
                },
                "event_interval": {
                    "description": "Repeat an event poll this often.",
                    **_nullable(_INTERVAL),
                },
                "output_interval": {
                    "description": "Repeat a read of output status this often. As often as "
                    "the integrity poll when left out; null for never.",
                    **_nullable(_INTERVAL),
                },
                "connect": {"type": "boolean", "default": True},
            },
            required=["name", "host"],
        ),
        "result": _ref("Outstation"),
        "example": {
            "name": "lab",
            "host": "192.0.2.10",
            "port": 20000,
            "integrity_interval": 30,
            "event_interval": 2,
        },
    },
    "remove": {
        "summary": "Close an outstation's connection and forget it",
        "tag": "Outstations",
        "params": _outstation(),
        "result": _object({"removed": _STRING}, required=["removed"]),
        "example": {"outstation": "lab"},
    },
    "connect": {
        "summary": "Make an outstation's connection",
        "tag": "Outstations",
        "params": _outstation(),
        "result": _ref("Outstation"),
        "example": {"outstation": "lab"},
    },
    "disconnect": {
        "summary": "Close an outstation's connection, and keep what was read",
        "tag": "Outstations",
        "params": _outstation(),
        "result": _ref("Outstation"),
        "example": {"outstation": "lab"},
    },
    "idle": {
        "summary": "Wait until nothing the master does unasked is due or under way",
        "description": "What is done on connecting is done after `add` and `connect` have "
        "answered. This answers once it is finished, and at once when the connection has "
        "ended.",
        "tag": "Outstations",
        "params": _outstation(),
        "result": _ref("Outstation"),
        "example": {"outstation": "lab"},
    },
    "profile": {
        "summary": "Every point of the profile an outstation is meant to serve",
        "description": "Reported or not. `points` is null when the outstation was given no "
        "profile.",
        "tag": "Outstations",
        "params": _outstation(),
        "result": _object(
            {
                "version": _nullable(_STRING),
                "points": _nullable(
                    _object(
                        {
                            kind: {"type": "array", "items": _ref("ProfilePoint")}
                            for kind in _POINT_TYPES
                        }
                    )
                ),
            },
            required=["version", "points"],
        ),
        "example": {"outstation": "lab"},
    },
    "scan": {
        "summary": "Poll an outstation, by kind",
        "tag": "Reading",
        "params": _outstation({"kind": {**_SCAN_KIND, "default": "integrity"}}),
        "result": _ref("Exchange"),
        "example": {"outstation": "lab", "kind": "integrity"},
    },
    "read": {
        "summary": "Read named points, in one request",
        "tag": "Reading",
        "params": _outstation(
            {
                "points": _object(
                    dict.fromkeys(_POINT_TYPES, _INDICES),
                    minProperties=1,
                    additionalProperties=False,
                    description="By point type.",
                )
            },
            required=["points"],
        ),
        "result": _ref("Exchange"),
        "example": {"outstation": "lab", "points": {"ai": [4, 6, 8], "bi": "all"}},
    },
    "values": {
        "summary": "What the store holds, with no traffic",
        "tag": "Reading",
        "params": _outstation(
            {
                "types": {
                    "type": "array",
                    "items": _ref("PointType"),
                    "description": "Every type when left out.",
                }
            }
        ),
        "result": _object(
            {
                "points": _object(
                    {kind: {"type": "array", "items": _ref("PointValue")} for kind in _POINT_TYPES}
                )
            },
            required=["points"],
        ),
        "example": {"outstation": "lab", "types": ["ai"]},
    },
    "events": {
        "summary": "The events received, oldest first",
        "tag": "Reading",
        "params": _outstation({"limit": {"type": "integer", "default": 500, "minimum": 0}}),
        "result": _object(
            {"events": {"type": "array", "items": _ref("Object")}, "total": _INTEGER},
            required=["events", "total"],
        ),
        "example": {"outstation": "lab", "limit": 100},
    },
    "request": {
        "summary": "Send any request, by function code",
        "description": "READ, ENABLE_UNSOLICITED, DISABLE_UNSOLICITED and DELAY_MEASURE are "
        "always sent. Any other function code commands the outstation, and is refused as "
        "`not_allowed` unless the service was started to command.",
        "tag": "Reading",
        "params": _outstation(
            {
                "function": {
                    "oneOf": [_STRING, {"type": "integer", "minimum": 0, "maximum": 255}],
                    "description": "By name, as in DELAY_MEASURE, or by number.",
                },
                "body": {
                    "type": "string",
                    "default": "",
                    "description": "The octets after the function code, in hexadecimal.",
                },
            },
            required=["function"],
        ),
        "result": _ref("Exchange"),
        "example": {"outstation": "lab", "function": "DELAY_MEASURE"},
    },
    "operate": {
        "summary": "Command outputs, by type and index, in one request",
        "description": "Binary outputs are sent first, and each in the order given. Nothing "
        "is sent twice: a response that does not arrive is reported, with `accepted` null, "
        "and whether to try again is the caller's to decide.",
        "tag": "Commanding",
        "params": _outstation(
            {
                "points": _object(
                    {
                        "bo": {
                            "type": "object",
                            "additionalProperties": {
                                "oneOf": [
                                    _BOOLEAN,
                                    {"type": "string", "enum": list(OPERATIONS_BY_NAME)},
                                    _object(
                                        {
                                            "operation": {
                                                "type": "string",
                                                "enum": list(OPERATIONS_BY_NAME),
                                            },
                                            "count": {"type": "integer", "minimum": 0},
                                            "on_time_ms": {"type": "integer", "minimum": 0},
                                            "off_time_ms": {"type": "integer", "minimum": 0},
                                        },
                                        required=["operation"],
                                    ),
                                ]
                            },
                            "description": "By index: true or false for a latch on or off, "
                            "an operation by name, or an operation with its count and times.",
                        },
                        "ao": {
                            "type": "object",
                            "additionalProperties": {"oneOf": [_NUMBER, _STRING]},
                            "description": "By index: a number, or a numeric string.",
                        },
                    },
                    description="The outputs to command. At least one.",
                ),
                "mode": {
                    "type": "string",
                    "enum": ["direct", "select", "direct_no_ack"],
                    "default": "direct",
                    "description": "`direct` is a direct operate. `select` is a select "
                    "followed by an operate, sent only if the outstation echoed every control "
                    "unchanged and accepted each one. `direct_no_ack` is a direct operate the "
                    "outstation does not answer.",
                },
                "variation": {
                    **_nullable({"type": "integer", "enum": [1, 2, 3, 4]}),
                    "description": "The analog output variation: 1 or 2 for a 32- or 16-bit "
                    "integer, 3 or 4 for a single or double float. Left out, a whole number "
                    "is sent as an integer and anything else as a float. An outstation that "
                    "scales its points takes an integer as the transmitted value and a float "
                    "as the engineering one.",
                },
            },
            required=["points"],
        ),
        "result": _ref("Operated"),
        "example": {
            "outstation": "lab",
            "points": {"ao": {"88": 500}, "bo": {"17": True}},
            "mode": "select",
        },
    },
    "write_time": {
        "summary": "Set an outstation's clock",
        "tag": "Commanding",
        "params": _outstation(
            {
                "time_ms": {
                    **_nullable({"type": "integer", "minimum": 0}),
                    "description": "Milliseconds since the epoch, UTC. Now, when left out.",
                }
            }
        ),
        "result": _ref("Exchange"),
        "example": {"outstation": "lab"},
    },
    "clear_restart": {
        "summary": "Clear an outstation's restart indication",
        "tag": "Commanding",
        "params": _outstation(),
        "result": _ref("Exchange"),
        "example": {"outstation": "lab"},
    },
    "freeze": {
        "summary": "Freeze an outstation's counters",
        "tag": "Commanding",
        "params": _outstation(
            {
                "clear": {
                    "type": "boolean",
                    "default": False,
                    "description": "Clear each counter as it is frozen.",
                },
                "respond": {
                    "type": "boolean",
                    "default": True,
                    "description": "False for the request an outstation does not answer.",
                },
            }
        ),
        "result": _ref("Exchange"),
        "example": {"outstation": "lab", "clear": False},
    },
    "restart": {
        "summary": "Ask an outstation to restart",
        "tag": "Commanding",
        "params": _outstation(
            {"kind": {"type": "string", "enum": ["cold", "warm"], "default": "cold"}}
        ),
        "result": _ref("Exchange"),
        "example": {"outstation": "lab", "kind": "cold"},
    },
    "enable_unsolicited": {
        "summary": "Ask an outstation to report event classes without being polled",
        "tag": "Unsolicited responses",
        "params": _outstation({"classes": _CLASSES}),
        "result": _ref("Exchange"),
        "example": {"outstation": "lab", "classes": [1, 2]},
    },
    "disable_unsolicited": {
        "summary": "Ask an outstation to stop reporting event classes unasked",
        "tag": "Unsolicited responses",
        "params": _outstation({"classes": _CLASSES}),
        "result": _ref("Exchange"),
        "example": {"outstation": "lab", "classes": [1, 2, 3]},
    },
    "repeat": {
        "summary": "Repeat a scan on a schedule, or stop repeating it",
        "tag": "Reading",
        "params": _outstation(
            {
                "kind": {**_SCAN_KIND, "default": "integrity"},
                "interval": {"description": "Null to stop.", **_nullable(_INTERVAL)},
            }
        ),
        "result": _object(
            {"repeat": {"type": "object", "additionalProperties": _NUMBER}},
            required=["repeat"],
        ),
        "example": {"outstation": "lab", "kind": "events", "interval": 2},
    },
    "trace": {
        "summary": "The frames sent and received",
        "tag": "Traffic",
        "params": _outstation(
            {
                "after": {
                    "type": "integer",
                    "default": 0,
                    "description": "Only frames with a greater id.",
                },
                "limit": {"type": "integer", "default": 500},
            }
        ),
        "result": _object(
            {"frames": {"type": "array", "items": _ref("Frame")}}, required=["frames"]
        ),
        "example": {"outstation": "lab", "after": 0, "limit": 50},
    },
    "clear": {
        "summary": "Forget the frames or the events kept",
        "tag": "Traffic",
        "params": _outstation(
            {"what": {"type": "string", "enum": ["trace", "events"], "default": "trace"}}
        ),
        "result": _object({"cleared": _STRING}, required=["cleared"]),
        "example": {"outstation": "lab", "what": "trace"},
    },
    "stop": {
        "summary": "End the service",
        "tag": "Service",
        "params": _object({}),
        "result": _object({"stopping": _BOOLEAN}, required=["stopping"]),
        "example": {},
    },
}

_TAGS = [
    ("Outstations", "The outstations a master speaks to, and their connections."),
    ("Reading", "Polls, reads, and what has been read."),
    (
        "Commanding",
        "Operations that change an outstation. Refused as `not_allowed` unless the service "
        "was started with `--allow-control`.",
    ),
    ("Unsolicited responses", "Reporting an outstation does without being polled."),
    ("Traffic", "The frames that crossed the wire."),
    ("Service", "The service itself."),
]

_REFUSALS = {
    "400": "The body is not JSON, or was not sent as `application/json`.",
    "401": "A token is required, and is missing or wrong.",
    "403": "The request comes from another site, or names a host this server is not.",
}


def _success(result: Schema) -> Schema:
    return _object(
        {
            "id": {"description": "The id of the message, when it had one."},
            "ok": {"const": True},
            "result": result,
        },
        required=["ok", "result"],
    )


def _responses(result: Schema) -> dict[str, Any]:
    responses: dict[str, Any] = {
        "200": {
            "description": "The answer. `ok` says whether the operation was carried out; "
            "when it was not, `error` says why.",
            "content": {
                "application/json": {"schema": {"oneOf": [_success(result), _ref("Failure")]}}
            },
        }
    }
    for status, description in _REFUSALS.items():
        responses[status] = {
            "description": description,
            "content": {"text/plain": {"schema": _STRING}},
        }
    return responses


def build() -> dict[str, Any]:
    """The OpenAPI document, as a dictionary."""
    paths: dict[str, Any] = {}
    for name, operation in OPERATIONS.items():
        described: dict[str, Any] = {
            "operationId": name,
            "summary": operation["summary"],
            "tags": [operation["tag"]],
            "requestBody": {
                "required": bool(operation["params"].get("required")),
                "content": {
                    "application/json": {
                        "schema": operation["params"],
                        "example": operation["example"],
                    }
                },
            },
            "responses": _responses(operation["result"]),
        }
        if "description" in operation:
            described["description"] = operation["description"]
        paths[f"/api/{name}"] = {"post": described}

    paths["/api"] = {
        "post": {
            "operationId": "message",
            "summary": "Any operation, as one message",
            "description": "The form the line service uses: the operation by name, its "
            "parameters, and an id the answer repeats. Every operation above can be asked "
            "this way.",
            "tags": ["Service"],
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": _object(
                            {
                                "id": {"description": "Repeated in the answer."},
                                "op": {"type": "string", "enum": list(OPERATIONS)},
                                "outstation": _OUTSTATION_NAME,
                                "params": {"type": "object"},
                            },
                            required=["op"],
                        ),
                        "example": {
                            "id": 7,
                            "op": "scan",
                            "outstation": "lab",
                            "params": {"kind": "integrity"},
                        },
                    }
                },
            },
            "responses": _responses({"description": "The result of the operation named."}),
        }
    }
    paths["/events"] = {
        "get": {
            "operationId": "events_stream",
            "summary": "What happens unasked, as server-sent events",
            "description": "A stream that stays open. Each event's data is a JSON object "
            "with an `event` field: `frame`, `exchange`, `unsolicited`, `connection` or "
            "`outstations`, and the `outstation` it is about.",
            "tags": ["Service"],
            "responses": {
                "200": {
                    "description": "The stream.",
                    "content": {"text/event-stream": {"schema": _STRING}},
                },
                **{
                    status: {"description": description}
                    for status, description in _REFUSALS.items()
                    if status != "400"
                },
            },
        }
    }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "py1815 master",
            "version": API_VERSION,
            "summary": "A DNP3 master for exercising outstations, as a service.",
            "description": "Every operation of the master, each as a route that takes its "
            "parameters as a JSON object and answers with a JSON object.\n\n"
            "An outstation that does not answer is not an error: the exchange's `outcome` "
            "is `timeout`. An answer has `ok: false` only when the message could not be "
            "acted on, or there was no connection to ask over.\n\n"
            "The service listens on the machine it runs on unless it was given a token, "
            "which every request then carries as `Authorization: Bearer`, or as a `token` "
            "query parameter where a header cannot be set.",
            "license": {"name": "Apache-2.0", "identifier": "Apache-2.0"},
        },
        "servers": [{"url": "http://127.0.0.1:8815", "description": "The default."}],
        "tags": [{"name": name, "description": description} for name, description in _TAGS],
        "paths": paths,
        "components": {
            "schemas": SCHEMAS,
            "securitySchemes": {
                "token": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "Required only when the service was started with a token.",
                }
            },
        },
        "security": [{}, {"token": []}],
    }


def render() -> str:
    """The document as it is committed: stable, and readable in a diff."""
    return json.dumps(build(), indent=2, sort_keys=False) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="The master's API as an OpenAPI document.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write", action="store_true", help=f"write {DOCUMENT.name}")
    group.add_argument("--check", action="store_true", help="fail if the committed one is stale")
    args = parser.parse_args(argv)
    document = render()
    if args.write:
        DOCUMENT.write_text(document, encoding="utf-8", newline="\n")
        print(f"wrote {DOCUMENT}")
        return 0
    if args.check:
        current = DOCUMENT.read_text(encoding="utf-8") if DOCUMENT.is_file() else ""
        if current != document:
            print(
                f"{DOCUMENT} is not what the service describes; run "
                "`python -m py1815.master.openapi --write`",
                file=sys.stderr,
            )
            return 1
        return 0
    sys.stdout.write(document)
    return 0


if __name__ == "__main__":
    sys.exit(main())
