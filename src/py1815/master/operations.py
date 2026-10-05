"""The operations a master offers, whatever carries them.

One list of operations with one implementation each, so that a master wired
straight to a session and a master on a socket cannot drift apart. What
differs between them is only how an exchange is carried out, which is the one
method a subclass supplies; over a socket that method is a coroutine, and the
operations return what it returns.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Generic, Literal, TypeVar

from py1815.application import FunctionCode
from py1815.decode import PointType
from py1815.master import requests

#: What an operation returns: an :class:`~py1815.master.association.Exchange`,
#: or an awaitable of one.
ResultT = TypeVar("ResultT")

#: Every point of a type, where indices would otherwise be listed.
ALL: Literal["all"] = "all"

Indices = Sequence[int] | Literal["all"] | None


def _event_classes(classes: Sequence[int]) -> Sequence[int]:
    named = classes or (1, 2, 3)
    if any(number not in (1, 2, 3) for number in named):
        raise ValueError("unsolicited reporting is by event class: 1, 2 or 3")
    return named


class Operations(Generic[ResultT]):
    """What a master can be asked to do. This first version reads."""

    def _exchange(self, function: FunctionCode, body: bytes) -> ResultT:
        raise NotImplementedError

    def request(self, function: FunctionCode, body: bytes = b"") -> ResultT:
        """Send any request, as a function code and the octets after it.

        The escape hatch: whatever this interface does not name yet can still
        be asked, and the answer comes back decoded as far as it can be.
        """
        return self._exchange(function, body)

    def scan(self, kind: str) -> ResultT:
        """Read by class: ``integrity``, ``events``, or ``class0`` to ``class3``."""
        return self._exchange(FunctionCode.READ, requests.scan(kind))

    def integrity_poll(self) -> ResultT:
        """Read every event class and then every static value."""
        return self.scan("integrity")

    def enable_unsolicited(self, *classes: int) -> ResultT:
        """Ask the outstation to report the named event classes without being polled."""
        return self._exchange(
            FunctionCode.ENABLE_UNSOLICITED, requests.class_scan(*_event_classes(classes))
        )

    def disable_unsolicited(self, *classes: int) -> ResultT:
        """Ask the outstation to stop reporting the named event classes unasked."""
        return self._exchange(
            FunctionCode.DISABLE_UNSOLICITED, requests.class_scan(*_event_classes(classes))
        )

    def read(
        self,
        *,
        binary_inputs: Indices = None,
        binary_outputs: Indices = None,
        counters: Indices = None,
        frozen_counters: Indices = None,
        analog_inputs: Indices = None,
        analog_outputs: Indices = None,
    ) -> ResultT:
        """Read named points, in one request.

        Each argument is the indices wanted of one point type, or ``"all"``
        for every point of that type. The outstation answers in whichever
        variation it sends by default.
        """
        named = {
            PointType.BINARY_INPUT: binary_inputs,
            PointType.BINARY_OUTPUT: binary_outputs,
            PointType.COUNTER: counters,
            PointType.FROZEN_COUNTER: frozen_counters,
            PointType.ANALOG_INPUT: analog_inputs,
            PointType.ANALOG_OUTPUT: analog_outputs,
        }
        wanted: dict[PointType, Sequence[int] | None] = {}
        for point, indices in named.items():
            if indices is None:
                continue
            if isinstance(indices, str):
                if indices != ALL:
                    raise ValueError(f"{indices!r} is not a list of indices or 'all'")
                wanted[point] = None
            else:
                wanted[point] = list(indices)
        if not wanted:
            raise ValueError("a read names at least one point")
        return self._exchange(FunctionCode.READ, requests.read_points(wanted))
