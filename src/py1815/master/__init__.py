"""A DNP3 master, for evaluating outstations.

The other end of the conversation the rest of this package serves. Its first
purpose is to exercise an outstation, this library's or any other, from a
script: read what it holds, keep what it said, and report each exchange as a
result with every fragment in it.

It polls by class, reads named points, confirms what asks to be confirmed,
takes unsolicited responses, keeps the last value of every point, and commands
outputs when a caller asks. Left alone it looks after an outstation as a master
does: settles it on connecting, clears its restart indication, sets its clock
when asked, fetches the events it says it has, and connects again when the
connection is lost. Each of those is a task that can be turned off, and
``manual=True`` turns off every one. ``docs/planning/MASTER.md`` is the plan
for the rest.

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
from py1815.master.controls import Command, Mode, Operated, PointStatus
from py1815.master.loopback import Loopback
from py1815.master.operations import ALL
from py1815.master.store import PointValue, Store
from py1815.master.tasks import Tasks

__all__ = [
    "ALL",
    "Busy",
    "Command",
    "Decoded",
    "DecodedObject",
    "Exchange",
    "Loopback",
    "Master",
    "MasterAssociation",
    "Mode",
    "NotConnected",
    "Operated",
    "Outcome",
    "Outstation",
    "PointStatus",
    "PointType",
    "PointValue",
    "Store",
    "Tasks",
    "Unsolicited",
    "decode_objects",
]
