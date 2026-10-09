"""Setting an outstation's clock by the procedures of IEEE 1815-2012 10.3.3.

A plain time write (:meth:`~py1815.master.operations.Operations.write_time`)
sends the master's clock as it reads when the request is built, and the
outstation is late by however long the request took to arrive. The standard
gives two procedures that correct for that:

- **non-LAN** (10.3.3.1): a ``DELAY_MEASURE`` request, whose response carries
  how long the outstation held it (group 52). Half the round trip less that
  is the one-way delay, and the time written (group 50 variation 1) is the
  master's clock plus the delay.
- **LAN** (10.3.3.2): a ``RECORD_CURRENT_TIME`` request, at which the
  outstation notes when it arrived, then a write of the time the master sent
  it (group 50 variation 3). The outstation adds what has passed since.

Each is a :class:`TimeSync` plan of two requests, decided one at a time, as a
select and its operate are: whatever carries the requests asks what to send
next. The write is sent only if the first request was answered without an
error indication, and neither request is ever sent again (10.3.4.1).

The master's times are taken when each request is built, which is as close
to the wire as a master above the operating system's sockets gets. The
standard's note 3 in 10.3.3.2 says what that costs.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from py1815.application import FunctionCode, IIN2Bit
from py1815.master import requests
from py1815.master.association import Exchange

#: The procedures, by the names the standard's headings give them.
LAN = "lan"
NON_LAN = "non_lan"
PROCEDURES = (LAN, NON_LAN)

#: The group of the time delay objects a ``DELAY_MEASURE`` response carries.
TIME_DELAY_GROUP = 52
#: Group 52 variation 1 counts seconds, and variation 2 milliseconds.
_DELAY_UNITS_MS = {1: 1000, 2: 1}

#: Indications that say the first request was refused, after which nothing
#: is written.
_REFUSALS = (IIN2Bit.FUNC_NOT_SUPPORTED, IIN2Bit.OBJECT_UNKNOWN, IIN2Bit.PARAM_ERROR)


def _wall_clock_ms() -> int:
    return round(time.time() * 1000)


@dataclass(frozen=True)
class Synchronized:
    """The requests of one time synchronization, and what came of them."""

    procedure: str
    #: Each exchange made, in order: the first request, and the write when
    #: one was sent.
    exchanges: tuple[Exchange, ...]
    #: The one-way delay measured, in milliseconds, for the non-LAN
    #: procedure when the outstation answered. None otherwise.
    delay_ms: float | None
    #: The time the write carried, in milliseconds since the epoch, or None
    #: when no write was sent.
    time_ms: int | None

    @property
    def written(self) -> bool:
        """Whether the write was sent."""
        return self.time_ms is not None

    @property
    def accepted(self) -> bool | None:
        """Whether the outstation took the time: yes, no, or not known.

        False when no write was sent, or the write was refused. None when the
        write's response did not arrive.
        """
        if not self.written:
            return False
        write = self.exchanges[-1]
        if not write.complete:
            return None
        return write.iin is not None and not any(write.iin.is_set(bit) for bit in _REFUSALS)


def outstation_delay_ms(exchange: Exchange) -> float | None:
    """How long the outstation held a ``DELAY_MEASURE`` request, from its response."""
    for decoded in exchange.objects:
        unit = _DELAY_UNITS_MS.get(decoded.variation)
        if decoded.group == TIME_DELAY_GROUP and unit and isinstance(decoded.value, int):
            return float(decoded.value * unit)
    return None


class TimeSync:
    """The requests of one time synchronization, decided one at a time."""

    def __init__(self, procedure: str, *, clock_ms: Callable[[], int] = _wall_clock_ms) -> None:
        """
        Args:
            procedure: ``lan`` or ``non_lan``.
            clock_ms: The master's clock, in milliseconds since the epoch.
        """
        if procedure not in PROCEDURES:
            raise ValueError(f"{procedure!r} is not a time procedure; lan or non_lan")
        self.procedure = procedure
        self._clock_ms = clock_ms
        #: The master's clock when the first request was built.
        self._sent_ms: int | None = None
        self._delay_ms: float | None = None
        self._written_ms: int | None = None

    def next(self, done: Sequence[Exchange]) -> tuple[FunctionCode, bytes] | None:
        """Return the request to make after those already made, or None."""
        if not done:
            self._sent_ms = self._clock_ms()
            first = (
                FunctionCode.RECORD_CURRENT_TIME
                if self.procedure == LAN
                else FunctionCode.DELAY_MEASURE
            )
            return first, b""
        if len(done) != 1 or not self._answered(done[0]):
            return None
        if self.procedure == LAN:
            assert self._sent_ms is not None
            self._written_ms = self._sent_ms
            return FunctionCode.WRITE, requests.write_recorded_time(self._sent_ms)
        assert self._delay_ms is not None
        self._written_ms = self._clock_ms() + round(self._delay_ms)
        return FunctionCode.WRITE, requests.write_time(self._written_ms)

    def _answered(self, first: Exchange) -> bool:
        if not first.complete or first.iin is None:
            return False
        if any(first.iin.is_set(bit) for bit in _REFUSALS):
            return False
        if self.procedure == LAN:
            return True
        held = outstation_delay_ms(first)
        if held is None:
            return False
        # (D - A - outstation processing delay) / 2, as 10.3.3.1 e) has it.
        self._delay_ms = max(0.0, (first.elapsed * 1000 - held) / 2)
        return True

    def result(self, done: Sequence[Exchange]) -> Synchronized:
        """Return what the exchanges made amount to."""
        written = self._written_ms if len(done) == 2 else None
        return Synchronized(self.procedure, tuple(done), self._delay_ms, written)


__all__ = [
    "LAN",
    "NON_LAN",
    "PROCEDURES",
    "Synchronized",
    "TimeSync",
    "outstation_delay_ms",
]
