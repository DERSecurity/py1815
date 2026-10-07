"""A DNP3 master, for evaluating outstations.

The other end of the conversation the rest of this package serves. Its first
purpose is to exercise an outstation, this library's or any other, from a
script: read what it holds, keep what it said, and report each exchange as a
result with every fragment in it.

This first version reads. It polls by class, reads named points, confirms what
asks to be confirmed, takes unsolicited responses, and keeps the last value of
every point. It does not command, does not reconnect, and sends nothing a
caller did not ask for beyond confirmations. ``docs/planning/MASTER.md`` is the
plan for the rest.

A master built on this library's own framing shares its reading of the
standard with the outstation beside it. Agreement between the two is
convenient and proves little; the independent masters and parsers in the
interoperability suite are what judge the octets.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

from py1815.decode import Decoded, DecodedObject, PointType, decode_objects
from py1815.master.api import Master, NotConnected, Outstation
from py1815.master.association import (
    Busy,
    Exchange,
    MasterAssociation,
    Outcome,
    Unsolicited,
)
from py1815.master.loopback import Loopback
from py1815.master.operations import ALL
from py1815.master.store import PointValue, Store

__all__ = [
    "ALL",
    "Busy",
    "Decoded",
    "DecodedObject",
    "Exchange",
    "Loopback",
    "Master",
    "MasterAssociation",
    "NotConnected",
    "Outcome",
    "Outstation",
    "PointType",
    "PointValue",
    "Store",
    "Unsolicited",
    "decode_objects",
]
