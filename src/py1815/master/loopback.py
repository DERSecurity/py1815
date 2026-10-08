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

from py1815.application import FunctionCode
from py1815.master.association import Exchange, MasterAssociation, Unsolicited
from py1815.master.controls import Operated, Plan
from py1815.master.operations import Operations
from py1815.master.store import Store
from py1815.master.tasks import Housekeeper, Tasks
from py1815.session import Session

#: Passes of octets between the two before something is assumed to be looping.
_MAX_PASSES = 10_000


class Loopback(Operations[Exchange, Operated]):
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
        self.housekeeper = (
            Housekeeper(chosen) if time_ms is None else Housekeeper(chosen, clock_ms=time_ms)
        )
        #: Exchanges sent by automatic tasks, in order.
        self.unasked: list[Exchange] = []

    def start(self) -> list[Exchange]:
        """Run the startup tasks, as on a new connection, and return their exchanges."""
        self.housekeeper.connected()
        return self._keep_house()

    def _exchange(self, function: FunctionCode, body: bytes) -> Exchange:
        exchange = self._one(function, body)
        self._keep_house()
        return exchange

    def _one(self, function: FunctionCode, body: bytes, *, task: str | None = None) -> Exchange:
        self._pump(self.association.request(function, body))
        # Everything the session was going to say, it has said. An outstation
        # that is silent here is silent, and waiting would not change it.
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
            made.append(self._one(step.function, step.body, task=step.task))
        self.unasked += made
        return made

    def _carry_out(self, plan: Plan) -> Operated:
        # Run pending tasks only after the whole plan, so nothing is sent
        # between a select and its operate.
        done: list[Exchange] = []
        while (step := plan.next(done)) is not None:
            done.append(self._one(*step))
        self._keep_house()
        return plan.result(done)

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

    def _pump(self, to_session: bytes) -> None:
        """Carry octets back and forth until both sides are quiet."""
        for _ in range(_MAX_PASSES):
            if not to_session:
                return
            to_master = self.session.receive(to_session) + self.session.initiate()
            to_session = self.association.receive(to_master) if to_master else b""
        raise RuntimeError("the session and the association never stopped answering each other")

    def _pump_back(self, to_master: bytes) -> None:
        if to_master:
            self._pump(self.association.receive(to_master))

    def _collect(self) -> list[Unsolicited]:
        received = self.association.take_unsolicited()
        for unsolicited in received:
            self.store.apply(unsolicited.objects, now=self._clock())
            self.housekeeper.saw(unsolicited.iin)
        return received
