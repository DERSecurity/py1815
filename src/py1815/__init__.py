"""DNP3 (IEEE 1815) outstation.

The layers are separate modules so that each is testable without the ones above
it: framing without a data source, the session without a socket, and neither
test having to stand up the other half. This package holds the protocol below
the point map -- the data link, the transport function, the application
envelope, the static object encoders, and the session that drives them.

See ``docs/DESIGN.md`` for the decisions behind the shape.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

from py1815 import control, crc, events, objects
from py1815.application import (
    IIN,
    AppControl,
    FunctionCode,
    IIN2Bit,
    IINBit,
    QualifierCode,
    Request,
    RequestError,
    build_response,
    null_response,
    object_header,
    parse_request,
)
from py1815.link import (
    Broadcast,
    FrameReader,
    LinkFrame,
    LinkFrameError,
    PrimaryFunction,
    SecondaryFunction,
)
from py1815.server import OutstationServer, PeerRefused
from py1815.session import ReadProvider, Session, UnknownObject
from py1815.transport import Reassembler, TransportError, segment

__all__ = [
    "IIN",
    "AppControl",
    "Broadcast",
    "FrameReader",
    "FunctionCode",
    "IIN2Bit",
    "IINBit",
    "LinkFrame",
    "LinkFrameError",
    "OutstationServer",
    "PeerRefused",
    "PrimaryFunction",
    "QualifierCode",
    "ReadProvider",
    "Reassembler",
    "Request",
    "RequestError",
    "SecondaryFunction",
    "Session",
    "TransportError",
    "UnknownObject",
    "build_response",
    "control",
    "crc",
    "events",
    "null_response",
    "object_header",
    "objects",
    "parse_request",
    "segment",
]
