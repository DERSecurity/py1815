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
from py1815.master.deviations import Deviations
from py1815.master.operations import BROADCASTS
from py1815.master.requests import SCAN_KINDS
from py1815.master.service import INDICATIONS
from py1815.master.timesync import PROCEDURES

#: Every deviation's name, for the ``deviate`` operation's description.
DEVIATION_NAMES = Deviations.names()

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
            "time_procedure": {
                **_nullable({"type": "string", "enum": list(PROCEDURES)}),
                "description": "How `write_time` sets the clock. Null writes the master's "
                "time as it stands; `lan` and `non_lan` follow the procedures of IEEE "
                "1815-2012 10.3.3, which correct for the time the request takes.",
            },
            "event_follow_ups": {
                "type": "integer",
                "minimum": 0,
                "description": "Event polls made at once, one after another, while a poll's "
                "own response still says events are waiting. Zero leaves them for the next "
                "response that says so.",
            },
        },
        description="What the master does for an outstation without being asked.",
    ),
    "Tls": _object(
        {
            "ca": {
                **_nullable(_STRING),
                "description": "A PEM file of the authorities the outstation's certificate "
                "is checked against. The system's own when null.",
            },
            "certificate": {
                **_nullable(_STRING),
                "description": "The master's certificate, in PEM, with its chain.",
            },
            "key": {
                **_nullable(_STRING),
                "description": "The master's private key, in PEM, when it is not in the "
                "certificate's file. A password is read from PY1815_MASTER_KEY_PASSWORD on "
                "the machine the service runs on, and is never a parameter.",
            },
            "server_name": {
                **_nullable(_STRING),
                "description": "The name the outstation's certificate is checked against, "
                "when it is not the host.",
            },
        },
        additionalProperties=False,
        description="Files on the machine the service runs on, for a TLS connection.",
    ),
    "Outstation": _object(
        {
            "name": _STRING,
            "host": _STRING,
            "port": _INTEGER,
            "outstation_address": _ADDRESS,
            "master_address": _ADDRESS,
            "read_retries": {
                "type": "integer",
                "description": "Times a read that times out is sent again.",
            },
            "tls": {
                **_nullable(_ref("Tls")),
                "description": "The TLS settings, or null for plain TCP.",
            },
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
            "device_profile": {
                "type": "boolean",
                "description": "Whether the outstation was given a Device Profile document "
                "for `der.compare`.",
            },
        },
        required=[
            "name",
            "host",
            "port",
            "outstation_address",
            "master_address",
            "read_retries",
            "tls",
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
            "retries": {
                "type": "integer",
                "description": "Times the request was sent again after a timeout. Only a "
                "read is, under its own sequence number.",
            },
            "broadcast": {
                **_nullable({"type": "string", "enum": list(BROADCASTS)}),
                "description": "The broadcast address the request went to, or null when it "
                "went to the outstation's own.",
            },
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
            "retries",
            "broadcast",
        ],
        description="One request and everything that came back for it.",
    ),
    "Synchronized": _object(
        {
            "procedure": {"type": "string", "enum": list(PROCEDURES)},
            "written": {
                "type": "boolean",
                "description": "Whether the write was sent. It is not when the first request "
                "was refused or not answered.",
            },
            "accepted": {
                **_nullable(_BOOLEAN),
                "description": "Whether the outstation took the time. False when no write "
                "was sent or the write was refused; null when its response did not arrive.",
            },
            "delay_ms": {
                **_nullable(_NUMBER),
                "description": "The one-way delay measured by `non_lan`, in milliseconds.",
            },
            "time_ms": {
                **_nullable(_INTEGER),
                "description": "The time the write carried, in milliseconds since the epoch.",
            },
            "exchanges": {
                "type": "array",
                "items": _ref("Exchange"),
                "description": "The first request, and the write when one was sent.",
            },
        },
        required=["procedure", "written", "accepted", "delay_ms", "time_ms", "exchanges"],
        description="A time synchronization by one of the procedures of IEEE 1815-2012 10.3.3.",
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
    "DerPoint": _object(
        {
            "address": {"type": "string", "description": "Kind and index, as in `AO87`."},
            "type": _ref("PointType"),
            "index": _INDEX,
            "name": {"type": "string", "description": "The name as the profile's tables have it."},
            "label": {
                "type": "string",
                "description": "The first sentence of the name, without the values it lists.",
            },
            "units": _nullable(_STRING),
            "multiplier": {
                "description": "The transmitted number times this is the engineering value.",
                **_nullable(_NUMBER),
            },
            "minimum": {"description": "In engineering units.", **_nullable(_NUMBER)},
            "maximum": {"description": "In engineering units.", **_nullable(_NUMBER)},
            "states": {
                "description": "A binary point's two states by name: 0, then 1.",
                **_nullable({"type": "array", "items": _STRING}),
            },
            "mirror": {
                "description": "The input that reads an output back, by address.",
                **_nullable(_STRING),
            },
        },
        required=["address", "type", "index", "name", "label", "units", "mirror"],
        description="One point of the DER profile.",
    ),
    "DerReading": _object(
        {
            "address": _STRING,
            "type": _ref("PointType"),
            "index": _INDEX,
            "name": _STRING,
            "label": _STRING,
            "units": _nullable(_STRING),
            "value": {
                **_VALUE,
                "description": "In engineering units: the transmitted number through the "
                "point's multiplier, or a state. Null when the point was not reported.",
            },
            "raw": {**_VALUE, "description": "The value as it travelled."},
            "state": {
                "description": "A binary point's state, by the name the tables give it.",
                **_nullable(_STRING),
            },
            "flags": _FLAGS,
            "quality": {
                "type": "string",
                "enum": ["good", "offline", "comm_lost", "restart", "no_flags", "not_reported"],
                "description": "What the flags say: `good` is ONLINE. `offline` is a value sent "
                "without ONLINE, which is how a disabled function's inputs travel. "
                "`not_reported` is a point the outstation did not return.",
            },
            "time_ms": _nullable(_INTEGER),
        },
        required=["address", "type", "index", "name", "value", "raw", "flags", "quality"],
        description="One point of the DER profile, as the outstation reported it.",
    ),
    "DerFunction": _object(
        {
            "key": {"type": "string", "description": "Its name in lower case, as in `volt-var`."},
            "name": _STRING,
            "purpose": {"type": "string", "description": "What the tables say it is for."},
            "enable": {"type": "string", "description": "The binary output that enables it."},
            "status": {
                "description": "The binary input that reports whether it is enabled.",
                **_nullable(_STRING),
            },
            "supports": {
                "type": "string",
                "description": "The binary input that says whether it is supported.",
            },
            "supported": {
                "description": "What the outstation says. Null when it did not report it.",
                **_nullable(_BOOLEAN),
            },
            "enabled": {
                "description": "What the outstation says. Null when it did not report it.",
                **_nullable(_BOOLEAN),
            },
            "settings": {"type": "array", "items": _ref("DerPoint")},
            "inputs": {"type": "array", "items": _STRING},
            "curve_settings": {
                "type": "array",
                "items": _STRING,
                "description": "The settings that name a curve by its number.",
            },
        },
        required=["key", "name", "enable", "supports", "supported", "enabled", "settings"],
        description="One DER function, and what the outstation says of it.",
    ),
    "Curve": _object(
        {
            "number": {"description": "The curve the block shows.", **_nullable(_INTEGER)},
            "type": _nullable(_INTEGER),
            "type_name": _nullable(_STRING),
            "count": {"description": "The points in use.", **_nullable(_INTEGER)},
            "x_units": _nullable(_INTEGER),
            "x_units_name": _nullable(_STRING),
            "y_units": _nullable(_INTEGER),
            "y_units_name": _nullable(_STRING),
            "points": {
                "type": "array",
                "items": {"type": "array", "items": _VALUE, "minItems": 2, "maxItems": 2},
                "description": "X and Y of each point, as transmitted: the units the curve "
                "declares say how to scale them.",
            },
            "referenced": {
                "description": "Whether a function names this curve, where the outstation says.",
                **_nullable(_BOOLEAN),
            },
            "exchanges": {"type": "array", "items": _ref("Exchange")},
        },
        required=["number", "type", "count", "x_units", "y_units", "points", "referenced"],
        description="The curve the curve block shows, as the outstation reported it.",
    ),
    "Declared": _object(
        {
            "type": _ref("PointType"),
            "index": _INDEX,
            "name": _nullable(_STRING),
            "event_class": {
                "description": "The class its events are reported in, 0 for none, as declared.",
                **_nullable({"type": "integer", "enum": [0, 1, 2, 3]}),
            },
            "class_0": {
                "description": "Whether a class 0 read carries it, as declared.",
                **_nullable(_BOOLEAN),
            },
            "deadband": {
                "description": "In transmitted units, as declared.",
                **_nullable(_NUMBER),
            },
        },
        required=["type", "index", "name", "event_class", "class_0", "deadband"],
        description="One point as a Device Profile document declares it.",
    ),
    "DerSwitched": _object(
        {
            "function": {"type": "string", "description": "The function's key."},
            "name": _STRING,
            "enable": {"type": "boolean", "description": "True for an enable."},
            "accepted": {**_nullable(_BOOLEAN), "description": "As for `operate`."},
            "enabled": {
                "description": "Whether the outstation says the function is enabled, read "
                "afterwards. Null when it did not say.",
                **_nullable(_BOOLEAN),
            },
            "status": _nullable(_ref("DerReading")),
            "operated": _ref("Operated"),
        },
        required=["function", "name", "enable", "accepted", "enabled", "status", "operated"],
        description="A DER function enabled or disabled, and what its status input then said.",
    ),
    "ExchangeSummary": _object(
        {
            "function": _STRING,
            "outcome": {"type": "string", "enum": _OUTCOMES},
            "indications": _nullable({"type": "array", "items": _STRING}),
            "object_count": _INTEGER,
            "elapsed_ms": _NUMBER,
        },
        required=["function", "outcome", "indications", "object_count", "elapsed_ms"],
        description="One request, and how it ended, without its objects.",
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
_MODE: Schema = {
    "type": "string",
    "enum": ["direct", "select", "direct_no_ack"],
    "default": "direct",
    "description": "How each write is sent, as for `operate`.",
}
_DER_PROFILE_NEEDED = (
    " The outstation has to have been given a profile: `--profile`, or `profile` in its "
    "configuration."
)
_DER_COMMANDS = (
    " Refused as `not_allowed` unless the service was started to command. Sent once: a write "
    "whose answer did not arrive is reported as not known, and never sent again."
)

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
                "read_retries": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                    "description": "Times a read that times out with nothing received is sent "
                    "again, under the same sequence number (IEEE 1815-2012 4.3 rule 16). No "
                    "other request is ever sent again.",
                },
                "connect_timeout": {**_INTERVAL, "default": 5},
                "tls": {
                    **_nullable(_ref("Tls")),
                    "description": "Connect over TLS with these files. Plain TCP when left out.",
                },
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
        "params": _outstation(
            {
                "wait": {
                    **_nullable({"type": "number", "minimum": 0}),
                    "description": "Seconds to keep trying, once a second, when the connection "
                    "cannot be made. The first failure is the answer when left out.",
                }
            }
        ),
        "result": _ref("Outstation"),
        "example": {"outstation": "lab", "wait": 10},
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
    "set_tasks": {
        "summary": "Change what the master does for an outstation unasked",
        "description": "Merged with what the outstation has: a task left out stands as it "
        "was. A task that is due and is turned off is not done. Turning on one of the two "
        "that write is refused as `not_allowed` in a service not started to command.",
        "tag": "Outstations",
        "params": _outstation({"tasks": _ref("Tasks")}, required=["tasks"]),
        "result": _ref("Outstation"),
        "example": {"outstation": "lab", "tasks": {"events_when_indicated": False}},
    },
    "wait_for": {
        "summary": "Wait until a value, an event or an indication is as named",
        "description": "Answers when the condition holds, or at the timeout, with `held` "
        "saying which. Nothing is sent to make it hold. Exactly one of `value`, `event` and "
        "`indication` is given.",
        "tag": "Reading",
        "params": _outstation(
            {
                "timeout": {"type": "number", "minimum": 0, "description": "Seconds."},
                "value": _object(
                    {
                        "type": _ref("PointType"),
                        "index": _INDEX,
                        "equals": {"oneOf": [_NUMBER, _BOOLEAN]},
                        "tolerance": {"type": "number", "minimum": 0, "default": 0},
                        "at_least": _NUMBER,
                        "at_most": _NUMBER,
                    },
                    required=["type", "index"],
                    additionalProperties=False,
                    description="Holds once the point has been reported with the value "
                    "named; with no comparison, once it has been reported at all.",
                ),
                "event": _object(
                    {"type": _ref("PointType"), "index": _INDEX},
                    additionalProperties=False,
                    description="Holds once an event arrives after the wait began, of the "
                    "type and index named when they are.",
                ),
                "indication": _object(
                    {
                        "name": {"type": "string", "enum": list(INDICATIONS)},
                        "set": {"type": "boolean", "default": True},
                    },
                    required=["name"],
                    additionalProperties=False,
                    description="Holds once the indication is set, or clear when `set` is "
                    "false, in the last response of either kind.",
                ),
            },
            required=["timeout"],
        ),
        "result": _object(
            {
                "held": _BOOLEAN,
                "elapsed_ms": _NUMBER,
                "indications": {"type": "array", "items": _STRING},
                "point": {
                    **_nullable(_ref("PointValue")),
                    "description": "The point a `value` condition names, as it stands.",
                },
                "events": {
                    "type": "array",
                    "items": _ref("Object"),
                    "description": "The events that satisfied an `event` condition.",
                },
            },
            required=["held", "elapsed_ms", "indications", "point", "events"],
        ),
        "example": {
            "outstation": "lab",
            "timeout": 5,
            "value": {"type": "ai", "index": 4, "at_least": 0},
        },
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
    "synchronize_time": {
        "summary": "Set an outstation's clock by a procedure of IEEE 1815-2012",
        "description": "`lan` records the current time at the outstation, then writes the "
        "time the master sent that request (10.3.3.2). `non_lan` measures the delay, then "
        "writes the master's time plus the delay (10.3.3.1). The write is sent only if the "
        "first request was answered without an error indication, and neither is ever sent "
        "again.",
        "tag": "Commanding",
        "params": _outstation(
            {"procedure": {"type": "string", "enum": list(PROCEDURES), "default": "lan"}}
        ),
        "result": _ref("Synchronized"),
        "example": {"outstation": "lab", "procedure": "lan"},
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
    "broadcast": {
        "summary": "Send a request to a broadcast address",
        "description": "Every outstation on the link takes it, and none answers: the "
        "exchange's outcome is `sent`. An outstation says it received one with IIN1.0 in "
        "its next response. Over TCP it reaches the one outstation at the other end, as a "
        "broadcast. READ, ENABLE_UNSOLICITED, DISABLE_UNSOLICITED and DELAY_MEASURE are "
        "always sent; any other function code is refused as `not_allowed` unless the "
        "service was started to command.",
        "tag": "Commanding",
        "params": _outstation(
            {
                "function": {
                    "oneOf": [_STRING, {"type": "integer", "minimum": 0, "maximum": 255}],
                    "description": "By name, as in IMMED_FREEZE_NR, or by number.",
                },
                "body": {
                    "type": "string",
                    "default": "",
                    "description": "The octets after the function code, in hexadecimal.",
                },
                "address": {
                    "type": "string",
                    "enum": list(BROADCASTS),
                    "default": "optional_confirm",
                    "description": "0xFFFD, 0xFFFE or 0xFFFF: whether the outstation asks "
                    "for the response that reports the broadcast to be confirmed (IEEE "
                    "1815-2012 table 4-13).",
                },
            },
            required=["function"],
        ),
        "result": _ref("Exchange"),
        "example": {"outstation": "lab", "function": "IMMED_FREEZE_NR", "body": "140006"},
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
    "capture": {
        "summary": "The frames sent and received, as a pcap file",
        "description": "Every frame kept, each as one TCP segment of an IPv4 connection in "
        "Ethernet, with the time it was sent or received. Each connection the master made "
        "is a TCP stream of its own, opened with a handshake and closed with FIN segments. "
        "An address that is not IPv4 is written as 127.0.0.1. Wireshark, tshark and "
        "Suricata read the file as it is.",
        "tag": "Traffic",
        "params": _outstation(
            {
                "after": {
                    "type": "integer",
                    "default": 0,
                    "description": "Only frames with a greater id.",
                }
            }
        ),
        "result": _object(
            {
                "frames": {"type": "integer", "description": "The frames in the file."},
                "pcap": {
                    "type": "string",
                    "contentEncoding": "base64",
                    "contentMediaType": "application/vnd.tcpdump.pcap",
                    "description": "The file, in base64.",
                },
            },
            required=["frames", "pcap"],
        ),
        "example": {"outstation": "lab"},
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
    "deviate": {
        "summary": "Turn named deviations on or off",
        "description": "A deviation makes the master break a protocol rule on purpose, so a "
        "test can see whether the outstation rejects what the standard says it must. Each is "
        "applied to the octets the association produced, on their way to the outstation, and "
        "is off until turned on. The names are "
        + ", ".join(f"`{name}`" for name in DEVIATION_NAMES)
        + ". `set` turns them on or off; `clear` turns every one off first.",
        "tag": "Deviations",
        "params": _outstation(
            {
                "set": {
                    "type": "object",
                    "additionalProperties": _BOOLEAN,
                    "description": "Deviation names to true or false.",
                },
                "clear": {**_BOOLEAN, "description": "Turn every deviation off first."},
            }
        ),
        "result": _object(
            {
                "deviations": {"type": "object", "additionalProperties": _BOOLEAN},
                "on": {"type": "array", "items": _STRING},
            },
            required=["deviations", "on"],
        ),
        "example": {"outstation": "lab", "set": {"corrupt_header_crc": True}},
    },
    "der.read": {
        "summary": "Read points of the DER profile by name, or a named group",
        "description": "In engineering units, with each point's quality. A point is named by "
        "its address, as in `AI148`, or by its name or the name's first sentence; a name the "
        "tables give to more than one point is refused with the addresses it could mean. A "
        "group is a function, by key, name or purpose, or everything of one purpose, as in "
        "`Nameplate` or `Monitoring`. One request, unless the outstation refuses it whole for "
        "a range it does not serve: then each range is read again on its own, and a point no "
        "read returned is `not_reported`." + _DER_PROFILE_NEEDED,
        "tag": "DER profile",
        "params": _outstation(
            {
                "names": {
                    "type": "array",
                    "items": _STRING,
                    "description": "Points, by address or name.",
                },
                "group": {"type": "string", "description": "A function, or a purpose."},
            }
        ),
        "result": _object(
            {
                "points": {"type": "array", "items": _ref("DerReading")},
                "exchanges": {"type": "array", "items": _ref("Exchange")},
            },
            required=["points", "exchanges"],
        ),
        "example": {"outstation": "lab", "group": "volt-var"},
    },
    "der.write": {
        "summary": "Write outputs of the DER profile by name, in engineering units",
        "description": "One request, in the order given. An analog value is divided by the "
        "point's multiplier and sent as the nearest whole number; one outside the point's "
        "range is refused before anything is sent. With `verify`, the input that mirrors "
        "each output is read afterwards and compared with what was asked, within one step "
        "of the multiplier." + _DER_COMMANDS + _DER_PROFILE_NEEDED,
        "tag": "DER profile",
        "params": _outstation(
            {
                "points": {
                    "type": "object",
                    "additionalProperties": {"oneOf": [_NUMBER, _BOOLEAN, _STRING]},
                    "minProperties": 1,
                    "description": "Values by address or name: a number in engineering "
                    "units, or for a binary output true, false, or a state by name.",
                },
                "verify": {"type": "boolean", "default": False},
                "mode": _MODE,
                "variation": {
                    **_nullable({"type": "integer", "enum": [1, 2, 3, 4]}),
                    "description": "1 or 2 sends the transmitted number as a 32- or 16-bit "
                    "integer; 3 or 4 sends the engineering value as a float, which the profile "
                    "has an outstation take unscaled. The narrowest integer when left out.",
                },
            },
            required=["points"],
        ),
        "result": _object(
            {
                "accepted": {**_nullable(_BOOLEAN), "description": "As for `operate`."},
                "verified": {
                    "description": "True when every readback matched, false when one did "
                    "not, null when not asked or not known.",
                    **_nullable(_BOOLEAN),
                },
                "points": {
                    "type": "array",
                    "items": _object(
                        {
                            "address": _STRING,
                            "type": _ref("PointType"),
                            "index": _INDEX,
                            "name": _STRING,
                            "units": _nullable(_STRING),
                            "requested": {**_VALUE, "description": "As asked for."},
                            "sent": {**_VALUE, "description": "As it travelled."},
                            "sent_value": {
                                **_VALUE,
                                "description": "What was sent, in engineering units.",
                            },
                            "status": _nullable(_STRING),
                            "echoed": _BOOLEAN,
                            "readback": _nullable(_ref("DerReading")),
                            "matches": _nullable(_BOOLEAN),
                        },
                        required=["address", "requested", "sent", "status", "matches"],
                    ),
                },
                "operated": _ref("Operated"),
            },
            required=["accepted", "verified", "points", "operated"],
        ),
        "example": {"outstation": "lab", "points": {"AO87": 50}, "verify": True},
    },
    "der.enable": {
        "summary": "Enable a DER function, and read whether it is enabled",
        "description": "Latches the function's enable output on, then reads the input that "
        "reports whether the function is enabled." + _DER_COMMANDS + _DER_PROFILE_NEEDED,
        "tag": "DER profile",
        "params": _outstation(
            {
                "function": {
                    "type": "string",
                    "description": "By key, name, purpose, or its enable output's address.",
                },
                "mode": _MODE,
            },
            required=["function"],
        ),
        "result": _ref("DerSwitched"),
        "example": {"outstation": "lab", "function": "volt-var"},
    },
    "der.disable": {
        "summary": "Disable a DER function, and read whether it is enabled",
        "description": "Latches the function's enable output off, then reads the input that "
        "reports whether the function is enabled." + _DER_COMMANDS + _DER_PROFILE_NEEDED,
        "tag": "DER profile",
        "params": _outstation(
            {"function": {"type": "string"}, "mode": _MODE},
            required=["function"],
        ),
        "result": _ref("DerSwitched"),
        "example": {"outstation": "lab", "function": "volt-var"},
    },
    "der.functions": {
        "summary": "The DER functions, which are supported and which enabled",
        "description": "Reads every function's supports input and enabled input, in one "
        "request, and lists each function with its settings." + _DER_PROFILE_NEEDED,
        "tag": "DER profile",
        "params": _outstation(),
        "result": _object(
            {
                "functions": {"type": "array", "items": _ref("DerFunction")},
                "exchanges": {"type": "array", "items": _ref("Exchange")},
            },
            required=["functions", "exchanges"],
        ),
        "example": {"outstation": "lab"},
    },
    "der.curve": {
        "summary": "Read the curve the curve block shows",
        "description": "The block shows one curve at a time, the one its selector names. "
        "Given `number`, the selector is written first, which is a control: refused as "
        "`not_allowed` unless the service was started to command." + _DER_PROFILE_NEEDED,
        "tag": "DER profile",
        "params": _outstation(
            {
                "number": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Select this curve first.",
                },
                "mode": _MODE,
            }
        ),
        "result": _object(
            {"curve": _ref("Curve"), "selected": _nullable(_ref("Operated"))},
            required=["curve", "selected"],
        ),
        "example": {"outstation": "lab"},
    },
    "der.write_curve": {
        "summary": "Write a curve, and read it back",
        "description": "Three writes, in the order IEEE 1815.2 clause 6.1.3 lays the curve "
        "block out: the selector; the type, the number of points and the units of X and Y; "
        "then X and Y of each point. Each is made only when the one before it was accepted. "
        "The curve is then read back whatever happened. Values travel as the whole numbers "
        "given, since the units the curve declares say how they scale."
        + _DER_COMMANDS
        + _DER_PROFILE_NEEDED,
        "tag": "DER profile",
        "params": _outstation(
            {
                "number": {"type": "integer", "minimum": 1},
                "type": {"type": "integer", "description": "The curve type, as enumerated."},
                "x_units": _INTEGER,
                "y_units": _INTEGER,
                "points": {
                    "type": "array",
                    "items": {"type": "array", "items": _INTEGER, "minItems": 2, "maxItems": 2},
                    "maxItems": 100,
                    "description": "X and Y of each point.",
                },
                "mode": _MODE,
            },
            required=["number", "type", "x_units", "y_units", "points"],
        ),
        "result": _object(
            {
                "accepted": {
                    "description": "True when every write was accepted, false when one was "
                    "refused, null when one was not answered.",
                    **_nullable(_BOOLEAN),
                },
                "matches": {
                    "type": "boolean",
                    "description": "Whether the curve read back is the curve written.",
                },
                "stopped_at": {
                    "description": "The write that was not accepted, after which none was made.",
                    **_nullable({"type": "string", "enum": ["selector", "fields", "points"]}),
                },
                "steps": {"type": "array", "items": _ref("Operated")},
                "curve": _ref("Curve"),
            },
            required=["accepted", "matches", "stopped_at", "steps", "curve"],
        ),
        "example": {
            "outstation": "lab",
            "number": 1,
            "type": 2,
            "x_units": 129,
            "y_units": 2,
            "points": [[920, 300], [980, 0], [1020, 0], [1080, -300]],
        },
    },
    "der.compare": {
        "summary": "Compare what an outstation serves with its Device Profile document",
        "description": "Reads class 0, then output status, then every declared point neither "
        "returned. A declared point no read returned is absent; a point returned that is "
        "not declared is undeclared; a served point a class 0 read does or does not carry, "
        "against what is declared, is listed under `class_0`. A point's event class and "
        "deadband cannot be read from an outstation, so they are given as declared. Needs "
        "no profile.",
        "tag": "DER profile",
        "params": _outstation(
            {
                "document": {
                    "type": "string",
                    "description": "The document's XML. The one given with "
                    "`--device-profile` when left out.",
                }
            }
        ),
        "result": _object(
            {
                "declared": {"type": "integer", "description": "Points declared."},
                "served": {"type": "integer", "description": "Points declared and served."},
                "absent": {"type": "array", "items": _ref("Declared")},
                "undeclared": {
                    "type": "array",
                    "items": _object(
                        {"type": _ref("PointType"), "index": _INDEX, "name": _nullable(_STRING)},
                        required=["type", "index", "name"],
                    ),
                },
                "class_0": {
                    "type": "array",
                    "items": _object(
                        {
                            **SCHEMAS["Declared"]["properties"],
                            "carried": {
                                "type": "boolean",
                                "description": "Whether the class 0 read carried it.",
                            },
                        },
                        required=[*SCHEMAS["Declared"]["required"], "carried"],
                    ),
                },
                "points": {
                    "type": "array",
                    "items": _ref("Declared"),
                    "description": "Every point declared and served, with its class and "
                    "deadband as declared.",
                },
                "exchanges": {"type": "array", "items": _ref("ExchangeSummary")},
            },
            required=["declared", "served", "absent", "undeclared", "class_0", "points"],
        ),
        "example": {"outstation": "lab"},
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
    (
        "Deviations",
        "Protocol rules the master breaks on purpose, so a test can see whether the "
        "outstation rejects what the standard says it must. Off until turned on.",
    ),
    (
        "DER profile",
        "An IEEE 1815.2 DER's points by name and in engineering units, its functions, its "
        "curves, and its Device Profile document.",
    ),
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
            "`outstations`, and the `outstation` it is about. A subscriber that falls 10,000 "
            "updates behind has its waiting updates replaced by one `lost` event whose "
            "`dropped` field says how many were dropped; read the state again, for example "
            "with `status`, `values`, `events` and `trace`. A stream that has not accepted "
            "a write for 60 seconds is closed.",
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
