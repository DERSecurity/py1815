"""Automatic master tasks: the requests a master sends without being asked.

A conformant master runs a startup sequence when it connects, clears the
restart indication, writes the time when the outstation needs it, and polls
for events when a response indicates some are waiting. Each of these is a
task that can be disabled.

:class:`Housekeeper` decides which requests to send. It is given the internal
indications (IIN) of each response and returns the next request. It does no
I/O, so the connection owner sends the requests and the logic can be tested
without a socket.

Loop prevention: a task is never triggered without bound by the responses to
its own requests.

- Restart and need-time are edge-triggered. They fire when the bit appears and
  not again until it has cleared and reappeared.
- An overflow poll fires on any response that carries the bit, except the
  response to the integrity poll itself.
- An event poll fires on any response that says events are waiting. When the
  response to a poll still says so, the outstation held some back, and they
  are fetched at once by another event poll, up to
  :attr:`Tasks.event_follow_ups` in a row. The count starts again only when a
  poll's response says nothing is waiting.

An outstation that never clears a bit therefore costs a bounded number of
extra requests per response, and the follow-up polls are spent once until it
does.

No task operates an output.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields, replace
from typing import Any, NamedTuple

from py1815.application import IIN, FunctionCode, IIN2Bit, IINBit
from py1815.master import requests
from py1815.master.timesync import LAN, NON_LAN, TimeSync

#: Tasks that write to the outstation.
WRITING = ("clear_restart", "write_time")

#: How the ``write_time`` task may set the clock, besides a plain write of the
#: master's time: the procedures of IEEE 1815-2012 10.3.3.
TIME_PROCEDURES = (LAN, NON_LAN)

#: Event polls made in a row because the last poll's own response still said
#: events were waiting. Enough for an outstation that sends its events a few
#: at a time; few enough that one which never clears the bit is asked four
#: times and then left until the bit clears.
DEFAULT_EVENT_FOLLOW_UPS = 3

#: Execution order when several tasks are due:
#: 1. Disable unsolicited reporting, so it cannot interleave with the polls.
#: 2. Clear the restart bit, so the integrity poll does not report it again.
#: 3. Write the time, so later events are timestamped with it.
#: 4. Poll.
#: 5. Enable unsolicited reporting.
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
    """Which automatic tasks are enabled."""

    #: Run the startup sequence (disable unsolicited, then integrity poll) on
    #: connect and when the outstation reports a restart.
    startup: bool = True
    #: Clear the restart bit (IIN1.7) when a response sets it.
    clear_restart: bool = True
    #: Write the time when a response sets need-time (IIN1.4).
    write_time: bool = True
    #: Event classes to enable unsolicited reporting for after startup.
    #: Empty means do not enable it.
    enable_unsolicited: tuple[int, ...] = ()
    #: Poll for events when a response sets a class 1, 2 or 3 events bit.
    events_when_indicated: bool = True
    #: Run an integrity poll when a response sets event buffer overflow
    #: (IIN2.3), because events were lost.
    integrity_on_overflow: bool = True
    #: How ``write_time`` sets the clock: None writes the master's time as it
    #: stands, and ``lan`` and ``non_lan`` follow the procedures of IEEE
    #: 1815-2012 10.3.3, which correct for the time the request takes.
    time_procedure: str | None = None
    #: Event polls made in a row when a poll's own response still says
    #: events are waiting. Zero leaves them for the next response that says so.
    event_follow_ups: int = DEFAULT_EVENT_FOLLOW_UPS

    def __post_init__(self) -> None:
        classes = tuple(self.enable_unsolicited)
        for number in classes:
            # Checked by type as well as value: int() would turn 1.9, "1" and
            # True into class 1 instead of rejecting them.
            if isinstance(number, bool) or not isinstance(number, int) or number not in (1, 2, 3):
                raise ValueError("unsolicited reporting is by event class: 1, 2 or 3")
        object.__setattr__(self, "enable_unsolicited", classes)
        if self.time_procedure is not None and self.time_procedure not in TIME_PROCEDURES:
            raise ValueError("time_procedure is null, lan or non_lan")
        follow_ups = self.event_follow_ups
        if isinstance(follow_ups, bool) or not isinstance(follow_ups, int) or follow_ups < 0:
            raise ValueError("event_follow_ups is a count of polls, zero or more")

    @classmethod
    def none(cls) -> Tasks:
        """Return a configuration with every task disabled."""
        return cls(
            startup=False,
            clear_restart=False,
            write_time=False,
            events_when_indicated=False,
            integrity_on_overflow=False,
            event_follow_ups=0,
        )

    def changed(self, given: Mapping[str, Any]) -> Tasks:
        """Return a copy with the settings in ``given`` applied.

        Raises ``ValueError`` for an unknown task name or a value of the wrong
        type.
        """
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
            elif name in ("time_procedure", "event_follow_ups"):
                # Checked when the copy is made.
                chosen[name] = value
            elif not isinstance(value, bool):
                raise ValueError(f"{name} is true or false")
            else:
                chosen[name] = value
        return replace(self, **chosen)

    def reading_only(self) -> Tasks:
        """Return a copy with the tasks that write to the outstation disabled."""
        return replace(self, clear_restart=False, write_time=False)

    def describe(self) -> dict[str, Any]:
        """Return the settings as a JSON-compatible dict."""
        return {
            each.name: (
                list(self.enable_unsolicited)
                if each.name == "enable_unsolicited"
                else getattr(self, each.name)
            )
            for each in fields(self)
        }


class Step(NamedTuple):
    """One request to send, and the task it belongs to.

    A step with a ``plan`` is a time synchronization of two requests:
    ``function`` and ``body`` are its first, and the owner carries out the
    plan instead.
    """

    task: str
    function: FunctionCode
    body: bytes
    plan: TimeSync | None = None


def _wall_clock_ms() -> int:
    return round(time.time() * 1000)


class Housekeeper:
    """Decide which automatic requests to send, based on response indications.

    Call :meth:`connected` when a connection is made, :meth:`saw` with the
    indications of every response, and :meth:`next` to get each request
    that is due.
    """

    def __init__(
        self, tasks: Tasks | None = None, *, clock_ms: Callable[[], int] = _wall_clock_ms
    ) -> None:
        self._tasks = Tasks() if tasks is None else tasks
        self._clock_ms = clock_ms
        self._due: set[str] = set()
        #: True from the start of a startup sequence until its integrity poll
        #: ends. A restart bit seen during that time does not start another.
        self._starting = False
        #: Edge detection: True while the bit is set and already handled.
        self._restart_seen = False
        self._time_asked = False
        #: Event polls queued in a row because a poll's own response still
        #: said events were waiting.
        self._follow_ups = 0

    @property
    def tasks(self) -> Tasks:
        """The task settings."""
        return self._tasks

    @tasks.setter
    def tasks(self, tasks: Tasks) -> None:
        """Change the settings. A due task that is now off is not done.

        A startup sequence under way finishes, and an integrity poll already
        due is still made, whatever the new settings say: either may have been
        queued for more than one reason.
        """
        self._tasks = tasks
        off = {
            "clear_restart": not tasks.clear_restart,
            "write_time": not tasks.write_time,
            "enable_unsolicited": not tasks.enable_unsolicited,
            "events": not tasks.events_when_indicated,
        }
        self._due -= {name for name, dropped in off.items() if dropped}

    @property
    def due(self) -> tuple[str, ...]:
        """The pending tasks, in execution order."""
        return tuple(name for name in ORDER if name in self._due)

    def connected(self) -> None:
        """Reset state for a new connection and queue the startup sequence."""
        self._due.clear()
        self._restart_seen = self._time_asked = False
        self._starting = False
        self._follow_ups = 0
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
        """Queue the tasks that a response's indications call for.

        Args:
            indications: The response's IIN, or None if no response arrived.
            answering: The request that was answered, as (function code,
                request body), or None for an unsolicited response. Used to
                avoid re-triggering a poll from its own response.
        """
        integrity = answering == (FunctionCode.READ, requests.scan("integrity"))
        polled = integrity or answering == (FunctionCode.READ, requests.scan("events"))
        # Startup ends with its integrity poll, whether or not it was answered.
        # A restart bit seen after that is a new restart.
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

        # Overflow means events were lost, so re-read every value. Skip this
        # for the integrity poll's own response, which still carries the bit
        # until its events are confirmed.
        lost = indications.is_set(IIN2Bit.EVENT_BUFFER_OVERFLOW)
        if lost and tasks.integrity_on_overflow and not integrity:
            self._due.add("integrity")

        waiting = any(indications.is_set(bit) for bit in _EVENT_BITS)
        wanted = waiting and tasks.events_when_indicated and "integrity" not in self._due
        if not polled:
            if wanted:
                self._due.add("events")
        elif not waiting:
            self._follow_ups = 0
        elif wanted and self._follow_ups < tasks.event_follow_ups:
            # The poll's own response says more are waiting: the outstation
            # held some back. Fetched now, a bounded number of times in a row.
            self._follow_ups += 1
            self._due.add("events")

    def next(self) -> Step | None:
        """Return the next request to send, or None when nothing is due."""
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
            procedure = self.tasks.time_procedure
            if procedure is None:
                return Step(name, FunctionCode.WRITE, requests.write_time(self._clock_ms()))
            first = (
                FunctionCode.RECORD_CURRENT_TIME if procedure == LAN else FunctionCode.DELAY_MEASURE
            )
            return Step(name, first, b"", plan=TimeSync(procedure, clock_ms=self._clock_ms))
        if name == "integrity":
            # An integrity poll also reads events, so drop a pending event poll.
            self._due.discard("events")
            return Step(name, FunctionCode.READ, requests.scan("integrity"))
        if name == "events":
            return Step(name, FunctionCode.READ, requests.scan("events"))
        return Step(
            name,
            FunctionCode.ENABLE_UNSOLICITED,
            requests.class_scan(*self.tasks.enable_unsolicited),
        )
