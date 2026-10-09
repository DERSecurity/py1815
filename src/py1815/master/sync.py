"""The master for a script that has no event loop.

:class:`Master` and :class:`Outstation` here are those of
:mod:`py1815.master.api`, with every request a plain method that blocks until
it is done:

.. code-block:: python

    from py1815.master.sync import Master

    with Master() as master:
        lab = master.add("lab", host="192.0.2.10")
        lab.idle()
        poll = lab.integrity_poll()
        print(poll.outcome, lab.store.analog_input(4))

The master runs on an event loop of its own, in a thread it starts and stops.
Each call is handed to that loop and waited for, so the automatic tasks,
unsolicited responses and repeated scans carry on between calls, exactly as
they do for a caller in an event loop.

The blocking methods are generated from the asynchronous ones and not written
out a second time: the list of them is :data:`BLOCKING`, and a test holds it to
the asynchronous interface, so neither can gain an operation the other lacks.
Anything else on an outstation is read in the loop's thread: a method is
called there, and the store and the trace are reached through a view that
does the same, so nothing is read while the loop is changing it.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import threading
from collections.abc import Callable, Coroutine
from types import TracebackType
from typing import Any, TypeVar

from py1815.master import api
from py1815.master.operations import Operations
from py1815.master.store import Store
from py1815.master.tasks import Tasks
from py1815.master.trace import Trace

T = TypeVar("T")

#: Methods of an outstation that send something or wait for something, and so
#: block here: every operation, and the coroutines of the socket master.
BLOCKING: tuple[str, ...] = tuple(
    sorted(
        {name for name in vars(Operations) if not name.startswith("_")}
        | {
            name
            for name, value in vars(api.Outstation).items()
            if not name.startswith("_") and inspect.iscoroutinefunction(value)
        }
    )
)


class _Loop:
    """An event loop in a thread of its own, and a way to run things on it."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self.loop.run_forever, name="py1815-master", daemon=True
        )
        self._thread.start()

    def run(self, coroutine: Coroutine[Any, Any, T]) -> T:
        """Run a coroutine on the loop and return what it returns."""
        if threading.current_thread() is self._thread:
            coroutine.close()
            raise RuntimeError(
                "a blocking call made from the master's own thread would wait forever"
            )
        if self.loop.is_closed():
            coroutine.close()
            raise RuntimeError("the master has been closed")
        return asyncio.run_coroutine_threadsafe(coroutine, self.loop).result()

    def call(self, function: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Call a function on the loop's thread and return what it returns.

        Called at once from the loop's own thread, as a condition given to
        ``wait_for`` is, and once the master is closed, when nothing is left
        to change what it reads.
        """
        if threading.current_thread() is self._thread or self.loop.is_closed():
            return function(*args, **kwargs)

        async def called() -> T:
            return function(*args, **kwargs)

        return self.run(called())

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join()
        self.loop.close()


async def _call_and_wait(function: Callable[..., Any], args: Any, kwargs: Any) -> Any:
    result = function(*args, **kwargs)
    if inspect.isawaitable(result):
        result = await result
    return result


class _InLoop:
    """An object of the loop's, every attribute of which is read on the loop's thread."""

    def __init__(self, runner: _Loop, target: Any) -> None:
        self._runner = runner
        self._target = target

    def __getattr__(self, name: str) -> Any:
        value = self._runner.call(getattr, self._target, name)
        if callable(value):

            def method(*args: Any, **kwargs: Any) -> Any:
                return self._runner.call(value, *args, **kwargs)

            return method
        return value

    def __len__(self) -> int:
        return self._runner.call(len, self._target)


def _blocking(name: str) -> Callable[..., Any]:
    original = getattr(api.Outstation, name)

    @functools.wraps(original)
    def method(self: Outstation, *args: Any, **kwargs: Any) -> Any:
        # pylint: disable=protected-access
        target = getattr(self._outstation, name)
        return self._runner.run(_call_and_wait(target, args, kwargs))

    return method


class Outstation:
    """An outstation of :mod:`py1815.master.api`, whose requests block until done."""

    def __init__(self, runner: _Loop, outstation: api.Outstation) -> None:
        self._runner = runner
        self._outstation = outstation

    @property
    def store(self) -> Store:
        """The store, read on the master's thread."""
        return _InLoop(self._runner, self._outstation.store)  # type: ignore[return-value]

    @property
    def trace(self) -> Trace:
        """The trace, read on the master's thread."""
        return _InLoop(self._runner, self._outstation.trace)  # type: ignore[return-value]

    @property
    def tasks(self) -> Tasks:
        """The automatic task settings. Set it to change them."""
        return self._outstation.tasks

    @tasks.setter
    def tasks(self, tasks: Tasks) -> None:
        self._runner.call(setattr, self._outstation, "tasks", tasks)

    def __getattr__(self, name: str) -> Any:
        value = self._runner.call(getattr, self._outstation, name)
        if callable(value):

            def method(*args: Any, **kwargs: Any) -> Any:
                return self._runner.call(value, *args, **kwargs)

            return method
        return value


for _name in BLOCKING:
    if _name not in vars(Outstation):
        setattr(Outstation, _name, _blocking(_name))


class Master:
    """Outstations by name, as :class:`py1815.master.api.Master` has them, blocking."""

    def __init__(self) -> None:
        self._runner = _Loop()
        self._master = api.Master()
        self._outstations: dict[str, Outstation] = {}

    def __enter__(self) -> Master:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def outstations(self) -> dict[str, Outstation]:
        """The outstations added, by name."""
        return dict(self._outstations)

    def __getitem__(self, name: str) -> Outstation:
        return self._outstations[name]

    def add(self, name: str, **options: Any) -> Outstation:
        """Add an outstation and, unless told not to, connect to it.

        Takes what :meth:`py1815.master.api.Master.add` takes.
        """
        added = self._runner.run(self._master.add(name, **options))
        outstation = Outstation(self._runner, added)
        self._outstations[name] = outstation
        return outstation

    def remove(self, name: str) -> None:
        """Close an outstation's connection and forget it."""
        self._runner.run(self._master.remove(name))
        self._outstations.pop(name, None)

    def close(self) -> None:
        """Close every connection and stop the master's thread. Safe to call twice."""
        if self._runner.loop.is_closed():
            return
        self._runner.run(self._master.close())
        self._outstations.clear()
        self._runner.stop()


__all__ = ["BLOCKING", "Master", "Outstation"]
