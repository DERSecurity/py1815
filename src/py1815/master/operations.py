"""The operations a master offers, whatever carries them.

One list of operations with one implementation each, so that a master wired
straight to a session and a master on a socket cannot drift apart. What
differs between them is only how an exchange is carried out, which is the one
method a subclass supplies; over a socket that method is a coroutine, and the
operations return what it returns.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from typing import Any, Generic, Literal, Protocol, TypeVar

from py1815 import link
from py1815.application import FunctionCode
from py1815.decode import PointType
from py1815.master import controls, requests
from py1815.master.timesync import LAN, TimeSync

#: What an operation returns: an :class:`~py1815.master.association.Exchange`,
#: or an awaitable of one.
ResultT = TypeVar("ResultT")

#: What an operate returns: an :class:`~py1815.master.controls.Operated`, or
#: an awaitable of one.
OperatedT = TypeVar("OperatedT")

#: What a time synchronization returns: a
#: :class:`~py1815.master.timesync.Synchronized`, or an awaitable of one.
SyncedT = TypeVar("SyncedT")

#: The broadcast addresses by name: what the outstation does about confirming
#: the response that reports the broadcast (IEEE 1815-2012 table 4-13).
BROADCASTS: dict[str, link.Broadcast] = {
    address.name.lower(): address for address in link.Broadcast
}

#: The address a broadcast goes to unless another is named. The standard says
#: to use it where any outstation predates the other two, so every
#: outstation takes it.
DEFAULT_BROADCAST = link.Broadcast.OPTIONAL_CONFIRM


class Steps(Protocol):
    """Requests decided one at a time, each from the answers to those before it.

    A select and its operate, and a time synchronization, are carried out
    this way, so every carrier follows one rule for when the second request
    is sent.
    """

    def next(self, done: Sequence[Any]) -> tuple[FunctionCode, bytes] | None:
        """Return the request to make after those in ``done``, or None."""

    def result(self, done: Sequence[Any]) -> Any:
        """Return what the requests made amount to."""


def broadcast_address(address: link.Broadcast | int | str) -> link.Broadcast:
    """Return a broadcast address given by name, by number or as itself."""
    if isinstance(address, str):
        try:
            return BROADCASTS[address]
        except KeyError:
            raise ValueError(
                f"{address!r} is not a broadcast address; one of {', '.join(BROADCASTS)}"
            ) from None
    try:
        return link.Broadcast(address)
    except ValueError:
        raise ValueError(f"{address!r} is not a broadcast address: 0xFFFD to 0xFFFF") from None


#: Every point of a type, where indices would otherwise be listed.
ALL: Literal["all"] = "all"

Indices = Sequence[int] | Literal["all"] | None


def _event_classes(classes: Sequence[int]) -> Sequence[int]:
    named = classes or (1, 2, 3)
    if any(number not in (1, 2, 3) for number in named):
        raise ValueError("unsolicited reporting is by event class: 1, 2 or 3")
    return named


class Operations(Generic[ResultT, OperatedT, SyncedT]):
    """What a master can be asked to do."""

    def _exchange(
        self, function: FunctionCode, body: bytes, *, broadcast: link.Broadcast | None = None
    ) -> ResultT:
        raise NotImplementedError

    def _carry_out(self, plan: controls.Plan) -> OperatedT:
        """Make the requests a plan calls for, one after another with none between."""
        raise NotImplementedError

    def _synchronize(self, plan: TimeSync) -> SyncedT:
        """Make the requests of a time synchronization, with none between them."""
        raise NotImplementedError

    def _now_ms(self) -> int:
        """Return the master's clock, in milliseconds since the epoch."""
        return round(time.time() * 1000)

    def operate(
        self,
        *,
        binary_outputs: Mapping[Any, Any] | None = None,
        analog_outputs: Mapping[Any, Any] | None = None,
        mode: controls.Mode | str = controls.Mode.DIRECT,
        variation: int | None = None,
    ) -> OperatedT:
        """Command outputs, named by index, in one request.

        A binary output is given true or false for a latch, or an operation
        by name: ``pulse_on``, ``trip``, ``close``. An analog output is given
        a number. Binary outputs are sent first, and each in the order given.

        ``mode`` is ``direct`` for a direct operate, ``select`` for a select
        followed by an operate, and ``direct_no_ack`` for a direct operate the
        outstation does not answer. After a select the operate is sent only if
        the outstation echoed every control unchanged and accepted each one.

        The result has a status for each control, and says whether the
        outstation accepted them all, refused, or never said. Nothing is sent
        twice: a response that does not arrive is reported, and whether to try
        again is the caller's to decide.

        A whole number is sent as an integer and anything else as a float,
        unless ``variation`` says which. An outstation that scales its points
        takes an integer as the transmitted value and a float as the
        engineering one.
        """
        made = controls.commands(binary_outputs, analog_outputs, variation=variation)
        return self._carry_out(controls.Plan(made, mode))

    def write_time(self, milliseconds: int | None = None) -> ResultT:
        """Set the outstation's clock: milliseconds since the epoch, UTC, or now."""
        when = self._now_ms() if milliseconds is None else int(milliseconds)
        return self._exchange(FunctionCode.WRITE, requests.write_time(when))

    def synchronize_time(self, procedure: str = LAN) -> SyncedT:
        """Set the outstation's clock by one of the procedures of IEEE 1815-2012 10.3.3.

        ``lan`` records the current time at the outstation and then writes
        the time the master sent that request. ``non_lan`` measures the delay
        and writes the master's time plus the delay. The write is sent only
        if the first request was answered without an error indication, and
        neither request is ever sent again. See :mod:`py1815.master.timesync`.
        """
        return self._synchronize(TimeSync(procedure, clock_ms=self._now_ms))

    def broadcast(
        self,
        function: FunctionCode,
        body: bytes = b"",
        *,
        address: link.Broadcast | int | str = DEFAULT_BROADCAST,
    ) -> ResultT:
        """Send a request to a broadcast address: every outstation on the link.

        ``address`` is ``no_confirm`` (0xFFFD), ``shall_confirm`` (0xFFFE) or
        ``optional_confirm`` (0xFFFF), which say whether an outstation asks
        for its next response to be confirmed. No outstation answers a
        broadcast, so the exchange ends as sent and the indication that one
        arrived (IIN1.0) comes in the next response to a request of this
        master's own. Nothing is sent again.
        """
        return self._exchange(function, body, broadcast=broadcast_address(address))

    def clear_restart(self) -> ResultT:
        """Clear the restart indication, which a master does once it has seen it."""
        return self._exchange(FunctionCode.WRITE, requests.clear_restart())

    def freeze(self, *, clear: bool = False, respond: bool = True) -> ResultT:
        """Freeze every counter, clearing each as it is frozen if asked.

        With ``respond`` false the request is one the outstation does not
        answer.
        """
        function = {
            (False, True): FunctionCode.IMMED_FREEZE,
            (False, False): FunctionCode.IMMED_FREEZE_NR,
            (True, True): FunctionCode.FREEZE_CLEAR,
            (True, False): FunctionCode.FREEZE_CLEAR_NR,
        }[(bool(clear), bool(respond))]
        return self._exchange(function, requests.freeze_counters())

    def restart(self, kind: str = "cold") -> ResultT:
        """Ask the outstation to restart: ``cold`` or ``warm``."""
        functions = {"cold": FunctionCode.COLD_RESTART, "warm": FunctionCode.WARM_RESTART}
        if kind not in functions:
            raise ValueError(f"{kind!r} is not a restart; cold or warm")
        return self._exchange(functions[kind], b"")

    def request(self, function: FunctionCode, body: bytes = b"") -> ResultT:
        """Send any request, as a function code and the octets after it.

        The escape hatch: whatever this interface does not name yet can still
        be asked, and the answer comes back decoded as far as it can be.
        """
        return self._exchange(function, body)

    def scan(self, kind: str) -> ResultT:
        """Read by name: ``integrity``, ``events``, ``class0`` to ``class3``, or ``outputs``.

        ``outputs`` reads binary and analog output status by their groups. It
        is not part of an integrity poll: the IEEE 1815.2 profile leaves
        output status out of class 0.
        """
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
