"""A master wired straight to a session, in one process.

No socket, no thread and no waiting: a request is handed to the session, what
the session returns is handed to the association, and so on until neither has
anything to say. With one injected clock shared by the two, a test moves time
itself.

Automatic tasks are off unless ``tasks`` is given. With tasks,
:meth:`Loopback.start` runs the startup sequence, and pending tasks run after
each request and each :meth:`Loopback.listen`.

This is the two halves of the library talking to each other. It is the fastest
way to exercise either, and it is not evidence that either reads the standard
correctly, since they share the layers below them. See ``docs/planning/MASTER.md``.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from py1815 import link
from py1815.application import FunctionCode
from py1815.master import deviations
from py1815.master.association import Exchange, MasterAssociation, Unsolicited
from py1815.master.controls import Operated, Plan
from py1815.master.deviations import Deviations
from py1815.master.operations import Operations, Steps
from py1815.master.store import Store
from py1815.master.tasks import Housekeeper, Tasks
from py1815.master.timesync import Synchronized, TimeSync
from py1815.session import Session

#: Passes of octets between the two before something is assumed to be looping.
_MAX_PASSES = 10_000


class Loopback(Operations[Exchange, Operated, Synchronized]):
    """A master association and a session, each handed what the other sent."""

    def __init__(
        self,
        session: Session,
        *,
        association: MasterAssociation | None = None,
        store: Store | None = None,
        clock: Callable[[], float] = time.monotonic,
        tasks: Tasks | None = None,
        time_ms: Callable[[], int] | None = None,
    ) -> None:
        """
        Args:
            session: The outstation's session.
            association: The master's side. Built to match the session's
                addresses when not given.
            store: Where what is read is kept. A new one when not given.
            clock: The clock a value is stamped with when it is stored. Give
                the session, the association and this the same one.
            tasks: The automatic tasks to run. Defaults to none.
            time_ms: Clock for automatic time writes, in milliseconds since
                the epoch. Defaults to the wall clock.
        """
        if association is None:
            facts = session.facts
            association = MasterAssociation(
                outstation_address=facts.outstation_address,
                master_address=1 if facts.master_address is None else facts.master_address,
                clock=clock,
            )
        self.session = session
        self.association = association
        self.store = Store() if store is None else store
        self._clock = clock
        chosen = Tasks.none() if tasks is None else tasks
        self._time_ms = time_ms
        self.housekeeper = (
            Housekeeper(chosen) if time_ms is None else Housekeeper(chosen, clock_ms=time_ms)
        )
        #: Exchanges sent by automatic tasks, in order.
        self.unasked: list[Exchange] = []
        #: Protocol rules this master is breaking on purpose, off by default.
        self.deviations = Deviations()

    def _now_ms(self) -> int:
        return super()._now_ms() if self._time_ms is None else self._time_ms()

    def start(self) -> list[Exchange]:
        """Run the startup tasks, as on a new connection, and return their exchanges."""
        self.housekeeper.connected()
        return self._keep_house()

    def _exchange(
        self, function: FunctionCode, body: bytes, *, broadcast: link.Broadcast | None = None
    ) -> Exchange:
        exchange = self._one(function, body, broadcast=broadcast)
        self._keep_house()
        return exchange

    def _one(
        self,
        function: FunctionCode,
        body: bytes,
        *,
        task: str | None = None,
        broadcast: link.Broadcast | None = None,
    ) -> Exchange:
        self._pump(self.association.request(function, body, broadcast=broadcast))
        # Everything the session was going to say, it has said. An outstation
        # that is silent here is silent, and waiting would not change it,
        # though asking again might: a read with retries left is sent again.
        while again := self.association.retry(at_once=True):
            self._pump(again)
        self.association.give_up()
        exchange = self.association.take()
        assert exchange is not None
        if task is not None:
            exchange = replace(exchange, task=task)
        self.store.apply(exchange.objects, now=self._clock())
        self.housekeeper.saw(exchange.iin, answering=(function, body))
        self._collect()
        return exchange

    def _keep_house(self) -> list[Exchange]:
        made: list[Exchange] = []
        while (step := self.housekeeper.next()) is not None:
            if step.plan is not None:
                made += self._follow(step.plan, task=step.task).exchanges
            else:
                made.append(self._one(step.function, step.body, task=step.task))
        self.unasked += made
        return made

    def _follow(self, plan: Steps, *, task: str | None = None) -> Any:
        done: list[Exchange] = []
        while (step := plan.next(done)) is not None:
            done.append(self._one(*step, task=task))
        return plan.result(done)

    def _carry_out(self, plan: Plan) -> Operated:
        # Run pending tasks only after the whole plan, so nothing is sent
        # between a select and its operate.
        operated: Operated = self._follow(plan)
        self._keep_house()
        return operated

    def _synchronize(self, plan: TimeSync) -> Synchronized:
        synchronized: Synchronized = self._follow(plan)
        self._keep_house()
        return synchronized

    def listen(self) -> list[Unsolicited]:
        """Ask the session for what it would send unasked, and take it.

        What an owner on a socket does whenever the outstation speaks. Call
        it after the outstation has recorded events, or after moving the
        clock past a retry.
        """
        self._pump_back(self.session.initiate())
        received = self._collect()
        self._keep_house()
        return received

    def _pump(self, to_session: bytes, *, kind: str = deviations.REQUEST) -> None:
        """Carry octets back and forth until both sides are quiet.

        A deviation is applied to what the association produced on its way to
        the session, as it would be on its way to a socket: the first octets
        are a request or a confirmation as ``kind`` says, and every reply the
        association makes inside the loop is a confirmation.
        """
        to_session = self._deviate(to_session, kind=kind)
        for _ in range(_MAX_PASSES):
            if not to_session:
                return
            to_master = self.session.receive(to_session) + self.session.initiate()
            reply = self.association.receive(to_master) if to_master else b""
            to_session = self._deviate(reply, kind=deviations.CONFIRM)
        raise RuntimeError("the session and the association never stopped answering each other")

    def _deviate(self, octets: bytes, *, kind: str) -> bytes:
        """Apply any deviation to octets leaving the association. Empty stays empty."""
        if not octets:
            return octets
        return b"".join(self.deviations.outbound(octets, kind=kind))

    def _pump_back(self, to_master: bytes) -> None:
        if to_master:
            self._pump(self.association.receive(to_master), kind=deviations.CONFIRM)

    def _collect(self) -> list[Unsolicited]:
        received = self.association.take_unsolicited()
        for unsolicited in received:
            self.store.apply(unsolicited.objects, now=self._clock())
            self.housekeeper.saw(unsolicited.iin)
        return received
