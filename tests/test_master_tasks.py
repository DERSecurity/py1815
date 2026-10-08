"""Tests for the master's automatic tasks.

Three levels: the Housekeeper's decisions with no outstation, the same tasks
against this library's outstation in one process, and over TCP. The TCP tests
cover the plan's acceptance criteria: the store stays current through an
outstation restart, and a manual master sends nothing automatic.
"""

from __future__ import annotations

import asyncio
import itertools

import pytest
from profile_fixtures import for_reference_der

from py1815.application import IIN, FunctionCode, IIN2Bit, IINBit
from py1815.master import (
    Loopback,
    Master,
    MasterAssociation,
    Outstation,
    PointType,
    Tasks,
    requests,
)
from py1815.master.tasks import ORDER, Housekeeper
from py1815.profile import der, load
from py1815.profile.model import Composition, Kind
from py1815.profile.outstation import DerOutstation
from py1815.server import OutstationServer

RESTART = IIN(first=IINBit.DEVICE_RESTART)
NEED_TIME = IIN(first=IINBit.NEED_TIME)
EVENTS = IIN(first=IINBit.CLASS_1_EVENTS)
OVERFLOW = IIN(second=IIN2Bit.EVENT_BUFFER_OVERFLOW)
QUIET = IIN()

INTEGRITY = (FunctionCode.READ, requests.scan("integrity"))
EVENT_POLL = (FunctionCode.READ, requests.scan("events"))
A_READ = (FunctionCode.READ, requests.scan("class0"))

WATTS = der.AI_METER_FIRST + 4


def _drain(housekeeper: Housekeeper) -> list[str]:
    """Return the names of all pending tasks in order, without answering any."""
    names = []
    while (step := housekeeper.next()) is not None:
        names.append(step.task)
    return names


def _answered(housekeeper: Housekeeper, *responses: IIN) -> list[str]:
    """Run pending tasks, answering each with the next IIN in ``responses``."""
    given = iter(responses)
    names = []
    while (step := housekeeper.next()) is not None:
        names.append(step.task)
        housekeeper.saw(next(given, QUIET), answering=(step.function, step.body))
    return names


@pytest.fixture
def simulation() -> der.Simulation:
    return der.build(load.resolve(for_reference_der(), Composition()))


# ---------------------------------------------------------------- decisions


class TestTaskSettings:
    def test_defaults_enable_everything_except_unsolicited(self):
        assert Tasks().describe() == {
            "startup": True,
            "clear_restart": True,
            "write_time": True,
            "enable_unsolicited": [],
            "events_when_indicated": True,
            "integrity_on_overflow": True,
        }

    def test_none_disables_every_task(self):
        described = Tasks.none().describe()
        assert not any(described.values())

    def test_reading_only_disables_only_the_writing_tasks(self):
        kept = Tasks(enable_unsolicited=(1, 2)).reading_only().describe()
        assert kept == Tasks(enable_unsolicited=(1, 2)).describe() | {
            "clear_restart": False,
            "write_time": False,
        }

    def test_changed_applies_named_settings(self):
        changed = Tasks().changed({"write_time": False, "enable_unsolicited": [3, 1]})
        assert not changed.write_time and changed.enable_unsolicited == (3, 1)
        assert changed.startup, "what was not named is left as it was"

    @pytest.mark.parametrize(
        "given, says",
        [
            ({"polling": True}, "'polling' is not a task"),
            ({"startup": "yes"}, "startup is true or false"),
            ({"startup": 1}, "startup is true or false"),
            ({"enable_unsolicited": True}, "a list of event classes"),
            ({"enable_unsolicited": "123"}, "a list of event classes"),
            ({"enable_unsolicited": [0]}, "1, 2 or 3"),
            ({"enable_unsolicited": [4]}, "1, 2 or 3"),
            ({"enable_unsolicited": [1.9]}, "1, 2 or 3"),
            ({"enable_unsolicited": ["1"]}, "1, 2 or 3"),
            ({"enable_unsolicited": [True]}, "1, 2 or 3"),
            ({"enable_unsolicited": [None]}, "1, 2 or 3"),
        ],
    )
    def test_changed_rejects_invalid_settings(self, given, says):
        with pytest.raises(ValueError, match=says):
            Tasks().changed(given)


class TestStartup:
    def test_connect_queues_disable_unsolicited_then_integrity_poll(self):
        housekeeper = Housekeeper()
        housekeeper.connected()
        assert housekeeper.due == ("disable_unsolicited", "integrity")

        first, second = housekeeper.next(), housekeeper.next()

        # Function codes 21 and 1, and the class headers each carries.
        assert (first.function, first.body.hex()) == (21, "3c02063c03063c0406")
        assert (second.function, second.body.hex()) == (1, "3c02063c03063c04063c0106")
        assert housekeeper.next() is None

    def test_startup_order_with_restart_and_need_time(self):
        housekeeper = Housekeeper(Tasks(enable_unsolicited=(1, 2, 3)), clock_ms=lambda: 1_000)
        housekeeper.connected()

        done = _answered(housekeeper, IIN(first=IINBit.DEVICE_RESTART | IINBit.NEED_TIME))

        assert done == [
            "disable_unsolicited",
            "clear_restart",
            "write_time",
            "integrity",
            "enable_unsolicited",
        ]
        assert done == [name for name in ORDER if name in done]

    def test_write_request_octets(self):
        housekeeper = Housekeeper(clock_ms=lambda: 1_700_000_000_000)
        housekeeper.saw(IIN(first=IINBit.DEVICE_RESTART | IINBit.NEED_TIME))
        steps = {step.task: step for step in iter(housekeeper.next, None)}

        # Group 80 variation 1, index 7 to 7, a zero.
        assert steps["clear_restart"].function is FunctionCode.WRITE
        assert steps["clear_restart"].body.hex() == "500100070700"
        # Group 50 variation 1, a count of one, and the time in 48 bits.
        assert steps["write_time"].function is FunctionCode.WRITE
        assert steps["write_time"].body.hex() == "320107010068e5cf8b01"

    def test_enable_unsolicited_runs_last_for_configured_classes(self):
        housekeeper = Housekeeper(Tasks(enable_unsolicited=(2, 3)))
        housekeeper.connected()
        *_, last = iter(housekeeper.next, None)
        assert (last.function, last.body.hex()) == (20, "3c03063c0406")

    def test_enable_unsolicited_runs_on_connect_without_startup(self):
        housekeeper = Housekeeper(Tasks.none().changed({"enable_unsolicited": [1]}))
        housekeeper.connected()
        assert _drain(housekeeper) == ["enable_unsolicited"]

    def test_restart_seen_during_startup_does_not_restart_startup(self):
        housekeeper = Housekeeper()
        housekeeper.connected()
        done = _answered(housekeeper, RESTART, QUIET, QUIET)
        assert done == ["disable_unsolicited", "clear_restart", "integrity"]

    def test_restart_first_seen_in_integrity_response_does_not_restart_startup(self):
        housekeeper = Housekeeper()
        housekeeper.connected()
        # The first request went unanswered, so the poll is where it is seen.
        first = housekeeper.next()
        housekeeper.saw(None, answering=(first.function, first.body))
        assert _answered(housekeeper, RESTART) == ["integrity", "clear_restart"]

    def test_restart_after_startup_runs_startup_again(self):
        housekeeper = Housekeeper(Tasks(enable_unsolicited=(1,)))
        housekeeper.connected()
        _answered(housekeeper)

        housekeeper.saw(RESTART, answering=A_READ)

        assert _answered(housekeeper) == [
            "disable_unsolicited",
            "clear_restart",
            "integrity",
            "enable_unsolicited",
        ]

    def test_unsolicited_restart_runs_startup_again(self):
        housekeeper = Housekeeper()
        housekeeper.connected()
        _answered(housekeeper)
        housekeeper.saw(RESTART)
        assert housekeeper.due == ("disable_unsolicited", "clear_restart", "integrity")

    def test_unanswered_integrity_poll_still_ends_startup(self):
        housekeeper = Housekeeper()
        housekeeper.connected()
        while (step := housekeeper.next()) is not None:
            housekeeper.saw(None, answering=(step.function, step.body))
        # So a restart seen after it is a new one, and is settled.
        housekeeper.saw(RESTART, answering=A_READ)
        assert "integrity" in housekeeper.due

    def test_reconnect_resets_pending_tasks_and_seen_bits(self):
        housekeeper = Housekeeper()
        housekeeper.saw(IIN(first=IINBit.DEVICE_RESTART | IINBit.NEED_TIME))
        housekeeper.connected()
        assert housekeeper.due == ("disable_unsolicited", "integrity")
        # Seen again on the new connection, the restart is acted on again.
        assert "clear_restart" in _answered(housekeeper, RESTART)


class TestStuckIndications:
    """A bit the outstation never clears must not cause a request loop."""

    def test_stuck_restart_bit_is_handled_once(self):
        housekeeper = Housekeeper()
        housekeeper.connected()
        done = _answered(housekeeper, *[RESTART] * 20)
        assert done == ["disable_unsolicited", "clear_restart", "integrity"]
        housekeeper.saw(RESTART, answering=A_READ)
        assert housekeeper.due == ()

    def test_restart_bit_is_handled_again_after_clearing(self):
        housekeeper = Housekeeper(Tasks.none().changed({"clear_restart": True}))
        housekeeper.saw(RESTART, answering=A_READ)
        assert _drain(housekeeper) == ["clear_restart"]
        housekeeper.saw(QUIET, answering=A_READ)
        housekeeper.saw(RESTART, answering=A_READ)
        assert _drain(housekeeper) == ["clear_restart"]

    def test_stuck_need_time_is_handled_once(self):
        housekeeper = Housekeeper()
        for _ in range(5):
            housekeeper.saw(NEED_TIME, answering=A_READ)
        assert _answered(housekeeper, *[NEED_TIME] * 5) == ["write_time"]
        housekeeper.saw(QUIET, answering=A_READ)
        housekeeper.saw(NEED_TIME, answering=A_READ)
        assert housekeeper.due == ("write_time",)

    def test_overflow_triggers_one_integrity_poll(self):
        housekeeper = Housekeeper()
        housekeeper.saw(OVERFLOW, answering=A_READ)
        assert _answered(housekeeper, *[OVERFLOW] * 5) == ["integrity"]

    def test_overflow_in_a_later_response_triggers_another_poll(self):
        """The poll's own response is ignored, so only a later one can trigger again."""
        housekeeper = Housekeeper()
        housekeeper.saw(OVERFLOW, answering=A_READ)
        _answered(housekeeper, OVERFLOW)
        housekeeper.saw(OVERFLOW, answering=EVENT_POLL)
        assert _answered(housekeeper, OVERFLOW) == ["integrity"]

    def test_poll_response_does_not_trigger_another_event_poll(self):
        housekeeper = Housekeeper()
        housekeeper.saw(EVENTS, answering=A_READ)
        assert _answered(housekeeper, *[EVENTS] * 5) == ["events"]
        housekeeper.saw(EVENTS, answering=INTEGRITY)
        housekeeper.saw(EVENTS, answering=EVENT_POLL)
        assert housekeeper.due == ()
        # The next response of any other kind that says so is what fetches them.
        housekeeper.saw(EVENTS, answering=A_READ)
        assert housekeeper.due == ("events",)


class TestEventPolls:
    @pytest.mark.parametrize(
        "bit", [IINBit.CLASS_1_EVENTS, IINBit.CLASS_2_EVENTS, IINBit.CLASS_3_EVENTS]
    )
    def test_any_class_events_bit_triggers_event_poll(self, bit):
        housekeeper = Housekeeper()
        housekeeper.saw(IIN(first=bit), answering=A_READ)
        step = housekeeper.next()
        assert (step.task, step.function, step.body.hex()) == ("events", 1, "3c02063c03063c0406")

    def test_unsolicited_response_events_bit_triggers_event_poll(self):
        housekeeper = Housekeeper()
        housekeeper.saw(EVENTS)
        assert housekeeper.due == ("events",)

    def test_pending_integrity_poll_replaces_event_poll(self):
        housekeeper = Housekeeper()
        housekeeper.saw(IIN(first=IINBit.CLASS_1_EVENTS, second=IIN2Bit.EVENT_BUFFER_OVERFLOW))
        assert _drain(housekeeper) == ["integrity"]

    def test_later_integrity_poll_replaces_pending_event_poll(self):
        housekeeper = Housekeeper()
        housekeeper.saw(EVENTS, answering=A_READ)
        assert housekeeper.due == ("events",)
        housekeeper.saw(OVERFLOW)
        assert _drain(housekeeper) == ["integrity"]

    def test_no_response_queues_nothing(self):
        housekeeper = Housekeeper()
        housekeeper.saw(None, answering=A_READ)
        assert housekeeper.due == ()


class TestDisabledTasks:
    EVERYTHING = IIN(
        first=IINBit.DEVICE_RESTART | IINBit.NEED_TIME | IINBit.CLASS_1_EVENTS,
        second=IIN2Bit.EVENT_BUFFER_OVERFLOW,
    )

    def test_none_never_queues_anything(self):
        housekeeper = Housekeeper(Tasks.none())
        housekeeper.connected()
        housekeeper.saw(self.EVERYTHING)
        housekeeper.saw(self.EVERYTHING, answering=A_READ)
        assert housekeeper.due == () and housekeeper.next() is None

    @pytest.mark.parametrize(
        "off, never",
        [
            ("startup", "disable_unsolicited"),
            ("clear_restart", "clear_restart"),
            ("write_time", "write_time"),
            ("events_when_indicated", "events"),
        ],
    )
    def test_each_task_can_be_disabled_alone(self, off, never):
        housekeeper = Housekeeper(Tasks().changed({off: False}))
        housekeeper.connected()
        _answered(housekeeper)
        housekeeper.saw(IIN(first=self.EVERYTHING.first), answering=A_READ)
        done = _answered(housekeeper)
        assert never not in done
        assert done, "and the others are still done"

    def test_overflow_poll_can_be_disabled(self):
        housekeeper = Housekeeper(Tasks().changed({"integrity_on_overflow": False}))
        housekeeper.saw(OVERFLOW, answering=A_READ)
        assert housekeeper.due == ()


class TestTasksNeverOperateOutputs:
    def test_only_reads_unsolicited_control_and_two_writes_are_sent(self):
        """Check every combination of the relevant IIN bits, with and without connect."""
        bits = [
            IIN(first=IINBit.DEVICE_RESTART),
            IIN(first=IINBit.NEED_TIME),
            IIN(first=IINBit.CLASS_1_EVENTS),
            IIN(first=IINBit.CLASS_2_EVENTS),
            IIN(first=IINBit.CLASS_3_EVENTS),
            IIN(second=IIN2Bit.EVENT_BUFFER_OVERFLOW),
        ]
        allowed = {
            FunctionCode.READ,
            FunctionCode.ENABLE_UNSOLICITED,
            FunctionCode.DISABLE_UNSOLICITED,
        }
        writes = set()
        for chosen in itertools.product((False, True), repeat=len(bits)):
            indications = IIN()
            for bit, on in zip(bits, chosen, strict=True):
                if on:
                    indications |= bit
            for connecting in (False, True):
                housekeeper = Housekeeper(Tasks(enable_unsolicited=(1, 2, 3)), clock_ms=lambda: 5)
                if connecting:
                    housekeeper.connected()
                housekeeper.saw(indications)
                for step in iter(housekeeper.next, None):
                    if step.function is FunctionCode.WRITE:
                        writes.add(step.body)
                    else:
                        assert step.function in allowed, step
        assert writes == {requests.clear_restart(), requests.write_time(5)}


# ---------------------------------------------------- against a session


def _names(exchanges) -> list[str]:
    return [exchange.task for exchange in exchanges]


class TestLoopback:
    def test_start_runs_startup_and_fills_the_store(self, simulation):
        simulation.advance(1.0)
        master = Loopback(simulation.outstation.session(), tasks=Tasks())

        done = master.start()

        assert _names(done) == ["disable_unsolicited", "clear_restart", "write_time", "integrity"]
        assert all(exchange.complete for exchange in done)
        assert done[-1].iin == IIN(), "not restarted, not asking for the time, nothing waiting"
        assert len(master.store.points(PointType.ANALOG_INPUT)) == len(
            simulation.outstation.served(Kind.AI)
        )
        assert master.store.analog_input(WATTS).value == round(simulation.der.watts)
        assert master.unasked == done

    def test_time_write_sets_the_outstation_clock(self, simulation):
        master = Loopback(
            simulation.outstation.session(), tasks=Tasks(), time_ms=lambda: 1_700_000_000_000
        )
        master.start()
        assert abs(simulation.outstation.now_ms() - 1_700_000_000_000) < 5_000

    def test_without_tasks_nothing_automatic_is_sent(self, simulation):
        master = Loopback(simulation.outstation.session())
        assert master.start() == []
        poll = master.integrity_poll()
        assert poll.iin.is_set(IINBit.DEVICE_RESTART) and poll.iin.is_set(IINBit.NEED_TIME)
        assert master.unasked == [] and poll.sequence == 0 and poll.task is None

    def test_outstation_restart_reruns_startup(self, simulation):
        session = simulation.outstation.session()
        master = Loopback(session, tasks=Tasks())
        master.start()
        before = master.store.analog_input(WATTS).value
        del master.unasked[:]

        session.restart()
        simulation.advance(3600.0)
        asked = master.read(binary_inputs=[0])

        assert asked.task is None and asked.iin.is_set(IINBit.DEVICE_RESTART)
        assert _names(master.unasked) == [
            "disable_unsolicited",
            "clear_restart",
            "write_time",
            "integrity",
        ]
        assert not session.restart_indication
        now = master.store.analog_input(WATTS).value
        assert now == round(simulation.der.watts) and now != before

    def test_events_bit_triggers_event_poll(self, simulation):
        master = Loopback(simulation.outstation.session(), tasks=Tasks())
        master.start()
        events = len(master.store.events)
        del master.unasked[:]

        simulation.advance(5.0)
        asked = master.read(binary_inputs=[0])

        assert any(asked.iin.is_set(bit) for bit in (IINBit.CLASS_1_EVENTS, IINBit.CLASS_2_EVENTS))
        assert _names(master.unasked) == ["events"]
        assert master.unasked[0].objects and len(master.store.events) > events
        assert master.read(binary_inputs=[0]).iin.first == 0, "confirmed, so none are left"

    def test_overflow_triggers_integrity_poll(self):
        point_map = load.resolve(for_reference_der(), Composition())
        device = der.ReferenceDer()
        outstation = DerOutstation(point_map, device.bind(point_map), event_capacity=1)
        simulation = der.Simulation(device, outstation)
        master = Loopback(outstation.session(), tasks=Tasks())
        master.start()
        del master.unasked[:]

        simulation.advance(5.0)
        simulation.advance(5.0)
        asked = master.read(binary_inputs=[0])

        assert asked.iin.is_set(IIN2Bit.EVENT_BUFFER_OVERFLOW)
        assert _names(master.unasked) == ["integrity"]
        assert master.store.analog_input(WATTS).value == round(simulation.der.watts)

    def test_no_task_runs_between_select_and_operate(self, simulation):
        master = Loopback(simulation.outstation.session(), tasks=Tasks())
        master.start()
        del master.unasked[:]
        simulation.advance(5.0)
        sent = []
        request = master.association.request

        def recording(function, body=b""):
            sent.append(function)
            return request(function, body)

        master.association.request = recording

        result = master.operate(analog_outputs={der.AO_POWER_LIMIT_GENERATION: 300}, mode="select")

        assert result.accepted
        # The select's answer said events were waiting. They wait for the operate.
        assert result.exchanges[0].iin.first & 0x0E
        assert sent == [FunctionCode.SELECT, FunctionCode.OPERATE, FunctionCode.READ]
        assert _names(master.unasked) == ["events"]

    def test_unsolicited_enabled_after_startup_delivers_events(self, simulation):
        session = simulation.outstation.session(unsolicited=True)
        master = Loopback(session, tasks=Tasks(enable_unsolicited=(1, 2, 3)))

        done = master.start()

        assert _names(done)[-1] == "enable_unsolicited" and done[-1].iin.second == 0
        del master.unasked[:]
        events = len(master.store.events)
        simulation.advance(5.0)
        (report,) = master.listen()
        assert report.objects and len(master.store.events) > events
        assert master.unasked == [], "what arrived unasked needed no poll"

    def test_unsolicited_restart_reruns_startup(self, simulation):
        session = simulation.outstation.session(unsolicited=True)
        master = Loopback(session, tasks=Tasks(enable_unsolicited=(1, 2, 3)))
        master.start()
        master.listen()
        del master.unasked[:]

        session.restart()
        (announcement,) = master.listen()

        assert announcement.null and announcement.iin.is_set(IINBit.DEVICE_RESTART)
        assert _names(master.unasked) == [
            "disable_unsolicited",
            "clear_restart",
            "write_time",
            "integrity",
            "enable_unsolicited",
        ]
        assert not session.restart_indication

    def test_unconfirmed_events_do_not_cause_a_poll_loop(self, simulation):
        """Unconfirmed events stay buffered. That must cause one poll, not a loop."""
        session = simulation.outstation.session()
        master = Loopback(
            session,
            association=MasterAssociation(confirm=False),
            tasks=Tasks().reading_only(),
        )
        master.start()
        del master.unasked[:]
        simulation.advance(5.0)
        for _ in range(5):
            master.read(binary_inputs=[0])
        assert len(master.unasked) <= 5 and set(_names(master.unasked)) <= {"events"}


# ---------------------------------------------------------- over a socket


async def _until(condition, *, timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.01)


class TestOverTcp:
    @pytest.mark.asyncio
    async def test_startup_runs_before_caller_requests(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        seen = []
        await server.start()
        try:
            async with Master() as master:
                lab = await master.add(
                    "lab", host="127.0.0.1", port=server.port, on_exchange=seen.append
                )
                # Asked the moment the connection is made, and still after startup.
                asked = await lab.scan("class0")
                await lab.idle()
        finally:
            await server.stop()

        assert _names(seen) == [
            "disable_unsolicited",
            "clear_restart",
            "write_time",
            "integrity",
            None,
        ]
        assert asked.sequence == 4 and asked.iin == IIN()
        assert lab.tasks == Tasks() and lab.tasks_due == ()

    @pytest.mark.asyncio
    async def test_startup_runs_before_repeated_scans(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        seen = []
        await server.start()
        try:
            lab = Master()
            async with lab as master:
                outstation = await master.add(
                    "lab", host="127.0.0.1", port=server.port, connect=False
                )
                outstation.on_exchange = seen.append
                outstation.repeat_scan("class0", 30.0)
                await outstation.connect()
                await _until(lambda: len(seen) >= 5)
        finally:
            await server.stop()
        assert _names(seen[:5])[-1] is None and None not in _names(seen[:4])

    @pytest.mark.asyncio
    async def test_store_stays_current_through_outstation_restart(self):
        """The outstation stops and comes back as a restarted device."""
        point_map = load.resolve(for_reference_der(), Composition())
        device = der.ReferenceDer()
        running = der.Simulation(device, DerOutstation(point_map, device.bind(point_map)))
        first = OutstationServer(running.outstation.session(), bind="127.0.0.1:0")
        connections = []
        await first.start()
        port = first.port
        try:
            async with Master() as master:
                lab = await master.add(
                    "lab",
                    host="127.0.0.1",
                    port=port,
                    reconnect=0.05,
                    on_connection=connections.append,
                )
                await lab.idle()
                before = lab.store.analog_input(WATTS).value
                assert before == round(device.watts)

                await first.stop()
                await _until(lambda: not lab.connected)
                device.step(3600.0)
                restarted = der.Simulation(device, DerOutstation(point_map, device.bind(point_map)))
                second = OutstationServer(restarted.outstation.session(), bind=f"127.0.0.1:{port}")
                await second.start()
                try:
                    # Nothing is asked of it from here on.
                    await _until(lambda: lab.connected)
                    await lab.idle()
                    after = lab.store.analog_input(WATTS).value
                    indications = lab.last_response.iin
                finally:
                    await second.stop()
        finally:
            await first.stop()

        assert after == round(device.watts) and after != before
        assert not indications.is_set(IINBit.DEVICE_RESTART)
        assert not indications.is_set(IINBit.NEED_TIME)
        assert connections[:3] == [True, False, True]

    @pytest.mark.asyncio
    async def test_manual_sends_nothing_automatic(self, simulation):
        # An outstation that announces its restart unasked, and asks for the
        # announcement to be confirmed.
        session = simulation.outstation.session(unsolicited=True)
        server = OutstationServer(session, bind="127.0.0.1:0", unsolicited_interval=0.02)
        await server.start()
        try:
            async with Master() as master:
                lab = await master.add("lab", host="127.0.0.1", port=server.port, manual=True)
                await _until(lambda: lab.unsolicited)
                await lab.idle()
                await asyncio.sleep(0.1)
                sent = [entry for entry in lab.trace.since(0) if entry.direction == "tx"]
                assert sent == [] and lab.counts == {}
                assert lab.tasks == Tasks.none() and session.restart_indication

                # And is still a master when asked to be.
                poll = await lab.integrity_poll()
                assert poll.complete and poll.iin.is_set(IINBit.DEVICE_RESTART)
                assert lab.counts == {"complete": 1}
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_explicit_tasks_and_confirm_override_manual(self, simulation):
        lab_tasks = Tasks.none().changed({"startup": True})
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        try:
            async with Master() as master:
                lab = await master.add(
                    "lab",
                    host="127.0.0.1",
                    port=server.port,
                    manual=True,
                    tasks=lab_tasks,
                    confirm=True,
                )
                await lab.idle()
        finally:
            await server.stop()
        assert lab.tasks == lab_tasks and lab.counts == {"complete": 2}

    @pytest.mark.asyncio
    async def test_reconnect_none_stays_disconnected(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        port = server.port
        async with Master() as master:
            lab = await master.add("lab", host="127.0.0.1", port=port, reconnect=None)
            await lab.idle()
            await server.stop()
            await _until(lambda: not lab.connected)
            again = OutstationServer(simulation.outstation.session(), bind=f"127.0.0.1:{port}")
            await again.start()
            try:
                await asyncio.sleep(0.2)
                assert not lab.connected
            finally:
                await again.stop()

    @pytest.mark.asyncio
    async def test_close_does_not_reconnect(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        try:
            async with Master() as master:
                lab = await master.add("lab", host="127.0.0.1", port=server.port, reconnect=0.02)
                await lab.idle()
                await lab.close()
                await asyncio.sleep(0.2)
                assert not lab.connected
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_close_stops_reconnection_attempts(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        port = server.port
        async with Master() as master:
            lab = await master.add("lab", host="127.0.0.1", port=port, reconnect=0.02)
            await lab.idle()
            await server.stop()
            await _until(lambda: not lab.connected)
            await lab.close()
            again = OutstationServer(simulation.outstation.session(), bind=f"127.0.0.1:{port}")
            await again.start()
            try:
                await asyncio.sleep(0.2)
                assert not lab.connected
            finally:
                await again.stop()

    @pytest.mark.asyncio
    async def test_unsolicited_restart_reruns_startup_over_tcp(self, simulation):
        session = simulation.outstation.session(unsolicited=True)
        server = OutstationServer(session, bind="127.0.0.1:0", unsolicited_interval=0.02)
        seen = []
        await server.start()
        try:
            async with Master() as master:
                lab = await master.add(
                    "lab",
                    host="127.0.0.1",
                    port=server.port,
                    tasks=Tasks(enable_unsolicited=(1, 2, 3)),
                )
                await lab.idle()
                assert not session.restart_indication
                lab.on_exchange = seen.append

                # Nothing is asked of it: the announcement is all the master has.
                session.restart()
                server.notify()
                await _until(lambda: _names(seen)[-1:] == ["enable_unsolicited"])
        finally:
            await server.stop()

        assert _names(seen) == [
            "disable_unsolicited",
            "clear_restart",
            "write_time",
            "integrity",
            "enable_unsolicited",
        ]
        assert not session.restart_indication

    @pytest.mark.asyncio
    async def test_idle_returns_when_worker_is_cancelled_before_running(self):
        """A worker cancelled before its first run never reaches its own cleanup."""
        lab = Outstation("lab", host="127.0.0.1")
        lab._settled.clear()
        lab._housekeeping = asyncio.create_task(lab._keep_house())
        lab._stop_housekeeping()
        await asyncio.wait_for(lab.idle(), 1.0)

    @pytest.mark.asyncio
    async def test_failed_connect_during_retries_does_not_stop_them(self, simulation):
        """A manual connect() that fails must leave automatic reconnection running."""
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        port = server.port
        async with Master() as master:
            lab = await master.add(
                "lab", host="127.0.0.1", port=port, reconnect=0.05, connect_timeout=0.5
            )
            await lab.idle()
            await server.stop()
            await _until(lambda: not lab.connected)
            with pytest.raises(OSError):
                await lab.connect()

            again = OutstationServer(simulation.outstation.session(), bind=f"127.0.0.1:{port}")
            await again.start()
            try:
                # Nothing more is asked of it: the retries must still be running.
                await _until(lambda: lab.connected)
            finally:
                await again.stop()

    @pytest.mark.asyncio
    async def test_first_connect_that_fails_does_not_start_retries(self):
        lab = Outstation("lab", host="127.0.0.1", port=1, reconnect=0.02, connect_timeout=0.5)
        with pytest.raises(OSError):
            await lab.connect()
        assert lab._reconnecting is None

    @pytest.mark.asyncio
    async def test_retries_continue_when_the_peer_closes_at_once(self, simulation):
        """A peer that accepts and immediately closes must not end reconnection."""
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        port = server.port
        accepted = []

        async def slam(_reader, writer):
            accepted.append(1)
            writer.close()

        async with Master() as master:
            lab = await master.add("lab", host="127.0.0.1", port=port, reconnect=0.02)
            await lab.idle()
            await server.stop()
            await _until(lambda: not lab.connected)

            closing = await asyncio.start_server(slam, "127.0.0.1", port)
            try:
                await _until(lambda: len(accepted) >= 4)
            finally:
                closing.close()
                await closing.wait_closed()

            again = OutstationServer(simulation.outstation.session(), bind=f"127.0.0.1:{port}")
            await again.start()
            try:
                await _until(lambda: lab.connected)
                assert (await lab.scan("class0")).complete
            finally:
                await again.stop()

    @pytest.mark.asyncio
    async def test_reconnect_retries_until_outstation_returns(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        port = server.port
        async with Master() as master:
            lab = await master.add(
                "lab", host="127.0.0.1", port=port, reconnect=0.02, connect_timeout=0.5
            )
            await lab.idle()
            await server.stop()
            await _until(lambda: not lab.connected)
            # Long enough for several attempts to have found nobody there.
            await asyncio.sleep(0.2)
            assert not lab.connected
            again = OutstationServer(simulation.outstation.session(), bind=f"127.0.0.1:{port}")
            await again.start()
            try:
                await _until(lambda: lab.connected)
                assert (await lab.scan("class0")).complete
            finally:
                await again.stop()

    @pytest.mark.asyncio
    async def test_idle_returns_when_connection_closes(self, simulation):
        """idle() must not hang on a startup the outstation never answers."""
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        try:
            async with Master() as master:
                # Nobody answers to address 77, so startup is still waiting.
                lab = await master.add(
                    "lab",
                    host="127.0.0.1",
                    port=server.port,
                    outstation_address=77,
                    response_timeout=30.0,
                    reconnect=None,
                )
                waiting = asyncio.create_task(lab.idle())
                await asyncio.sleep(0.05)
                assert not waiting.done()
                await lab.close()
                await asyncio.wait_for(waiting, 2.0)
        finally:
            await server.stop()

    @pytest.mark.parametrize("wait", [0, -1.0, float("inf"), float("nan")])
    def test_invalid_reconnect_interval_is_rejected(self, wait):
        with pytest.raises(ValueError, match="a wait between attempts"):
            Outstation("lab", host="127.0.0.1", reconnect=wait)
