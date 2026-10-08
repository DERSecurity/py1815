"""What a master does without being asked, as a list of tasks.

A conformant master does a few things of its own accord: it settles an
outstation when it connects, clears the restart indication once it has seen
it, sets the clock when it is asked to, and fetches events when it is told
there are some. Here each is a task that can be turned off, and the deciding
is kept apart from the doing: :class:`Housekeeper` is told what indications
arrived and says what to send next, and whatever owns the connection sends it.
It does no I/O and keeps no time, so it is tested without a socket.

No task is made due by its own answer, so the master never talks to itself.
The restart indication and the request for the time are acted on when they
appear and not again until they have cleared and come back, since the write
that answers each is what clears it. Events waiting and an overflow are acted
on whenever a response says so, except the response to the poll made for them,
which may go on saying so until what it carried has been confirmed. An
indication that an outstation never clears therefore costs at most one request
for each response that carries it, and never a stream of them.

No task commands an output, and none is ever added that does.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields, replace
from typing import Any, NamedTuple

from py1815.application import IIN, FunctionCode, IIN2Bit, IINBit
from py1815.master import requests

#: The tasks, in the order they are done when several are due. Unsolicited
#: reporting is stopped before anything is read, so that what is read is not
#: overtaken; the restart indication is cleared before the poll that would
#: otherwise report it again; the clock is set before events are fetched, so
#: that they are timed by it; and reporting is turned back on last.
#: The tasks that write to the outstation: its restart indication, its clock.
WRITING = ("clear_restart", "write_time")

ORDER = (
    "disable_unsolicited",
    "clear_restart",
    "write_time",
    "integrity",
    "events",
    "enable_unsolicited",
)

_EVENT_BITS = (IINBit.CLASS_1_EVENTS, IINBit.CLASS_2_EVENTS, IINBit.CLASS_3_EVENTS)


@dataclass(frozen=True)
class Tasks:
    """Which of the things a master does unasked it is to do."""

    #: On connecting, and when the outstation reports that it restarted: stop
    #: its unsolicited reporting, then read everything it holds.
    startup: bool = True
    #: Clear the restart indication once it has been seen.
    clear_restart: bool = True
    #: Set the outstation's clock when it asks for the time.
    write_time: bool = True
    #: After startup, ask the outstation to report these event classes
    #: without being polled. None, unless given.
    enable_unsolicited: tuple[int, ...] = ()
    #: Fetch events when a response says there are some waiting.
    events_when_indicated: bool = True
    #: Read everything again when the outstation says its event buffer
    #: overflowed, since events were lost.
    integrity_on_overflow: bool = True

    def __post_init__(self) -> None:
        classes = tuple(int(number) for number in self.enable_unsolicited)
        if any(number not in (1, 2, 3) for number in classes):
            raise ValueError("unsolicited reporting is by event class: 1, 2 or 3")
        object.__setattr__(self, "enable_unsolicited", classes)

    @classmethod
    def none(cls) -> Tasks:
        """Nothing unasked: for driving an outstation by hand."""
        return cls(
            startup=False,
            clear_restart=False,
            write_time=False,
            events_when_indicated=False,
            integrity_on_overflow=False,
        )

    def changed(self, given: Mapping[str, Any]) -> Tasks:
        """These tasks with the ones a mapping names set as it says."""
        known = {each.name for each in fields(self)}
        unknown = sorted(set(given) - known)
        if unknown:
            raise ValueError(f"{unknown[0]!r} is not a task; one of {', '.join(sorted(known))}")
        chosen: dict[str, Any] = {}
        for name, value in given.items():
            if name == "enable_unsolicited":
                if isinstance(value, (str, bytes)) or not hasattr(value, "__iter__"):
                    raise ValueError("enable_unsolicited is a list of event classes")
                chosen[name] = tuple(value)
            elif not isinstance(value, bool):
                raise ValueError(f"{name} is true or false")
            else:
                chosen[name] = value
        return replace(self, **chosen)

    def reading_only(self) -> Tasks:
        """These tasks without the ones that write: for a master that may only read."""
        return replace(self, clear_restart=False, write_time=False)

    def describe(self) -> dict[str, Any]:
        return {
            each.name: (
                list(self.enable_unsolicited)
                if each.name == "enable_unsolicited"
                else getattr(self, each.name)
            )
            for each in fields(self)
        }


class Step(NamedTuple):
    """One request a task calls for."""

    task: str
    function: FunctionCode
    body: bytes


def _wall_clock_ms() -> int:
    return round(time.time() * 1000)


class Housekeeper:
    """Decides what a master sends unasked, from the indications it is shown."""

    def __init__(
        self, tasks: Tasks | None = None, *, clock_ms: Callable[[], int] = _wall_clock_ms
    ) -> None:
        self.tasks = Tasks() if tasks is None else tasks
        self._clock_ms = clock_ms
        self._due: set[str] = set()
        #: Whether the startup that connecting began is still under way, so
        #: that the restart it finds is not taken for a second one.
        self._starting = False
        #: Indications that are set and have been acted on already.
        self._restart_seen = False
        self._time_asked = False

    @property
    def due(self) -> tuple[str, ...]:
        """The tasks waiting to be done, in the order they will be."""
        return tuple(name for name in ORDER if name in self._due)

    def connected(self) -> None:
        """A connection was made: nothing is known of the outstation, and startup is due."""
        self._due.clear()
        self._restart_seen = self._time_asked = False
        self._starting = False
        if self.tasks.startup:
            self._begin_startup()
        elif self.tasks.enable_unsolicited:
            self._due.add("enable_unsolicited")

    def _begin_startup(self) -> None:
        self._starting = True
        self._due |= {"disable_unsolicited", "integrity"}
        if self.tasks.enable_unsolicited:
            self._due.add("enable_unsolicited")

    def saw(
        self, indications: IIN | None, *, answering: tuple[FunctionCode, bytes] | None = None
    ) -> None:
        """Take note of the indications of a response.

        Args:
            indications: What the response carried, or None if none arrived.
            answering: The request it answered, as a function code and the
                octets after it, or None for an unsolicited response. A poll
                whose answer still indicates what it was made for is not
                followed by another.
        """
        integrity = answering == (FunctionCode.READ, requests.scan("integrity"))
        polled = integrity or answering == (FunctionCode.READ, requests.scan("events"))
        # The startup's poll has been made, answered or not: a restart seen
        # from here on is a new one.
        starting, self._starting = self._starting, self._starting and not integrity
        if indications is None:
            return
        tasks = self.tasks

        if indications.is_set(IINBit.DEVICE_RESTART):
            if not self._restart_seen:
                self._restart_seen = True
                if tasks.clear_restart:
                    self._due.add("clear_restart")
                if tasks.startup and not starting:
                    self._begin_startup()
        else:
            self._restart_seen = False

        if indications.is_set(IINBit.NEED_TIME):
            if not self._time_asked:
                self._time_asked = True
                if tasks.write_time:
                    self._due.add("write_time")
        else:
            self._time_asked = False

        # Events were lost, and only reading every value says what was missed.
        # The poll that does so may still carry the indication, which stands
        # until the events sent with it are confirmed.
        lost = indications.is_set(IIN2Bit.EVENT_BUFFER_OVERFLOW)
        if lost and tasks.integrity_on_overflow and not integrity:
            self._due.add("integrity")

        waiting = any(indications.is_set(bit) for bit in _EVENT_BITS)
        if waiting and tasks.events_when_indicated and not polled and "integrity" not in self._due:
            self._due.add("events")

    def next(self) -> Step | None:
        """The next request to make, or None when nothing is due."""
        for name in ORDER:
            if name in self._due:
                self._due.discard(name)
                return self._step(name)
        return None

    def _step(self, name: str) -> Step:
        if name == "disable_unsolicited":
            return Step(name, FunctionCode.DISABLE_UNSOLICITED, requests.class_scan(1, 2, 3))
        if name == "clear_restart":
            return Step(name, FunctionCode.WRITE, requests.clear_restart())
        if name == "write_time":
            return Step(name, FunctionCode.WRITE, requests.write_time(self._clock_ms()))
        if name == "integrity":
            # An integrity poll fetches the events as well.
            self._due.discard("events")
            return Step(name, FunctionCode.READ, requests.scan("integrity"))
        if name == "events":
            return Step(name, FunctionCode.READ, requests.scan("events"))
        return Step(
            name,
            FunctionCode.ENABLE_UNSOLICITED,
            requests.class_scan(*self.tasks.enable_unsolicited),
        )
