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
from typing import Any, Generic, Literal, TypeVar

from py1815.application import FunctionCode
from py1815.decode import PointType
from py1815.master import controls, requests

#: What an operation returns: an :class:`~py1815.master.association.Exchange`,
#: or an awaitable of one.
ResultT = TypeVar("ResultT")

#: What an operate returns: an :class:`~py1815.master.controls.Operated`, or
#: an awaitable of one.
OperatedT = TypeVar("OperatedT")

#: Every point of a type, where indices would otherwise be listed.
ALL: Literal["all"] = "all"

Indices = Sequence[int] | Literal["all"] | None


def _event_classes(classes: Sequence[int]) -> Sequence[int]:
    named = classes or (1, 2, 3)
    if any(number not in (1, 2, 3) for number in named):
        raise ValueError("unsolicited reporting is by event class: 1, 2 or 3")
    return named


class Operations(Generic[ResultT, OperatedT]):
    """What a master can be asked to do."""

    def _exchange(self, function: FunctionCode, body: bytes) -> ResultT:
        raise NotImplementedError

    def _carry_out(self, plan: controls.Plan) -> OperatedT:
        """Make the requests a plan calls for, one after another with none between."""
        raise NotImplementedError

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
        when = round(time.time() * 1000) if milliseconds is None else int(milliseconds)
        return self._exchange(FunctionCode.WRITE, requests.write_time(when))

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
