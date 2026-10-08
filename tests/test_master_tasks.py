"""What the master does without being asked.

In three parts. The decisions, with no outstation at all: what is due, in what
order, and that an indication which stays set is not acted on twice. Then the
same against this library's own outstation in one process, and over a socket,
where the plan's own statement of done is tested: a master left alone keeps
its store current through a restart of the outstation, and a manual one sends
nothing it was not asked for.
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
    """Every task due, in the order done, with no response to any of them."""
    names = []
    while (step := housekeeper.next()) is not None:
        names.append(step.task)
    return names


def _answered(housekeeper: Housekeeper, *responses: IIN) -> list[str]:
    """The tasks done when each is answered with the next of ``responses``."""
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


class TestTheChoices:
    def test_everything_is_on_but_unsolicited_reporting(self):
        assert Tasks().describe() == {
            "startup": True,
            "clear_restart": True,
            "write_time": True,
            "enable_unsolicited": [],
            "events_when_indicated": True,
            "integrity_on_overflow": True,
        }

    def test_none_is_every_one_off(self):
        described = Tasks.none().describe()
        assert not any(described.values())

    def test_reading_only_drops_the_two_that_write_and_nothing_else(self):
        kept = Tasks(enable_unsolicited=(1, 2)).reading_only().describe()
        assert kept == Tasks(enable_unsolicited=(1, 2)).describe() | {
            "clear_restart": False,
            "write_time": False,
        }

    def test_tasks_are_changed_by_name(self):
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
        ],
    )
    def test_a_choice_that_is_not_one_is_refused(self, given, says):
        with pytest.raises(ValueError, match=says):
            Tasks().changed(given)


class TestStartup:
    def test_connecting_stops_unsolicited_reporting_and_then_reads_everything(self):
        housekeeper = Housekeeper()
        housekeeper.connected()
        assert housekeeper.due == ("disable_unsolicited", "integrity")

        first, second = housekeeper.next(), housekeeper.next()

        # Function codes 21 and 1, and the class headers each carries.
        assert (first.function, first.body.hex()) == (21, "3c02063c03063c0406")
        assert (second.function, second.body.hex()) == (1, "3c02063c03063c04063c0106")
        assert housekeeper.next() is None

    def test_a_restarted_outstation_that_wants_the_time_gets_all_of_it_in_order(self):
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

    def test_the_writes_are_these_octets(self):
        housekeeper = Housekeeper(clock_ms=lambda: 1_700_000_000_000)
        housekeeper.saw(IIN(first=IINBit.DEVICE_RESTART | IINBit.NEED_TIME))
        steps = {step.task: step for step in iter(housekeeper.next, None)}

        # Group 80 variation 1, index 7 to 7, a zero.
        assert steps["clear_restart"].function is FunctionCode.WRITE
        assert steps["clear_restart"].body.hex() == "500100070700"
        # Group 50 variation 1, a count of one, and the time in 48 bits.
        assert steps["write_time"].function is FunctionCode.WRITE
        assert steps["write_time"].body.hex() == "320107010068e5cf8b01"

    def test_unsolicited_reporting_is_enabled_for_the_classes_named_and_last(self):
        housekeeper = Housekeeper(Tasks(enable_unsolicited=(2, 3)))
        housekeeper.connected()
        *_, last = iter(housekeeper.next, None)
        assert (last.function, last.body.hex()) == (20, "3c03063c0406")

    def test_and_is_enabled_on_connecting_even_with_no_startup(self):
        housekeeper = Housekeeper(Tasks.none().changed({"enable_unsolicited": [1]}))
        housekeeper.connected()
        assert _drain(housekeeper) == ["enable_unsolicited"]

    def test_the_restart_that_startup_finds_is_not_a_second_one(self):
        housekeeper = Housekeeper()
        housekeeper.connected()
        done = _answered(housekeeper, RESTART, QUIET, QUIET)
        assert done == ["disable_unsolicited", "clear_restart", "integrity"]

    def test_nor_is_one_first_seen_in_the_answer_to_its_poll(self):
        housekeeper = Housekeeper()
        housekeeper.connected()
        # The first request went unanswered, so the poll is where it is seen.
        first = housekeeper.next()
        housekeeper.saw(None, answering=(first.function, first.body))
        assert _answered(housekeeper, RESTART) == ["integrity", "clear_restart"]

    def test_a_restart_reported_later_is_settled_again(self):
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

    def test_so_is_one_announced_unasked(self):
        housekeeper = Housekeeper()
        housekeeper.connected()
        _answered(housekeeper)
        housekeeper.saw(RESTART)
        assert housekeeper.due == ("disable_unsolicited", "clear_restart", "integrity")

    def test_a_poll_that_was_never_answered_still_ends_startup(self):
        housekeeper = Housekeeper()
        housekeeper.connected()
        while (step := housekeeper.next()) is not None:
            housekeeper.saw(None, answering=(step.function, step.body))
        # So a restart seen after it is a new one, and is settled.
        housekeeper.saw(RESTART, answering=A_READ)
        assert "integrity" in housekeeper.due

    def test_connecting_again_forgets_what_was_due_and_what_was_seen(self):
        housekeeper = Housekeeper()
        housekeeper.saw(IIN(first=IINBit.DEVICE_RESTART | IINBit.NEED_TIME))
        housekeeper.connected()
        assert housekeeper.due == ("disable_unsolicited", "integrity")
        # Seen again on the new connection, the restart is acted on again.
        assert "clear_restart" in _answered(housekeeper, RESTART)


class TestAnIndicationThatStaysSet:
    """No task is made due by its own answer, so none is done in a stream."""

    def test_a_restart_indication_nobody_clears_is_acted_on_once(self):
        housekeeper = Housekeeper()
        housekeeper.connected()
        done = _answered(housekeeper, *[RESTART] * 20)
        assert done == ["disable_unsolicited", "clear_restart", "integrity"]
        housekeeper.saw(RESTART, answering=A_READ)
        assert housekeeper.due == ()

    def test_and_acted_on_again_once_it_has_cleared_and_come_back(self):
        housekeeper = Housekeeper(Tasks.none().changed({"clear_restart": True}))
        housekeeper.saw(RESTART, answering=A_READ)
        assert _drain(housekeeper) == ["clear_restart"]
        housekeeper.saw(QUIET, answering=A_READ)
        housekeeper.saw(RESTART, answering=A_READ)
        assert _drain(housekeeper) == ["clear_restart"]

    def test_the_time_is_written_once_for_one_asking(self):
        housekeeper = Housekeeper()
        for _ in range(5):
            housekeeper.saw(NEED_TIME, answering=A_READ)
        assert _answered(housekeeper, *[NEED_TIME] * 5) == ["write_time"]
        housekeeper.saw(QUIET, answering=A_READ)
        housekeeper.saw(NEED_TIME, answering=A_READ)
        assert housekeeper.due == ("write_time",)

    def test_an_overflow_is_one_integrity_poll(self):
        housekeeper = Housekeeper()
        housekeeper.saw(OVERFLOW, answering=A_READ)
        assert _answered(housekeeper, *[OVERFLOW] * 5) == ["integrity"]

    def test_and_another_when_a_later_response_reports_one(self):
        """The poll's own answer carries it until its events are confirmed, so it cannot say."""
        housekeeper = Housekeeper()
        housekeeper.saw(OVERFLOW, answering=A_READ)
        _answered(housekeeper, OVERFLOW)
        housekeeper.saw(OVERFLOW, answering=EVENT_POLL)
        assert _answered(housekeeper, OVERFLOW) == ["integrity"]

    def test_a_poll_that_leaves_events_indicated_is_not_followed_by_another(self):
        housekeeper = Housekeeper()
        housekeeper.saw(EVENTS, answering=A_READ)
        assert _answered(housekeeper, *[EVENTS] * 5) == ["events"]
        housekeeper.saw(EVENTS, answering=INTEGRITY)
        housekeeper.saw(EVENTS, answering=EVENT_POLL)
        assert housekeeper.due == ()
        # The next response of any other kind that says so is what fetches them.
        housekeeper.saw(EVENTS, answering=A_READ)
        assert housekeeper.due == ("events",)


class TestEvents:
    @pytest.mark.parametrize(
        "bit", [IINBit.CLASS_1_EVENTS, IINBit.CLASS_2_EVENTS, IINBit.CLASS_3_EVENTS]
    )
    def test_events_of_any_class_are_fetched_when_indicated(self, bit):
        housekeeper = Housekeeper()
        housekeeper.saw(IIN(first=bit), answering=A_READ)
        step = housekeeper.next()
        assert (step.task, step.function, step.body.hex()) == ("events", 1, "3c02063c03063c0406")

    def test_and_when_an_unsolicited_response_says_there_are_more(self):
        housekeeper = Housekeeper()
        housekeeper.saw(EVENTS)
        assert housekeeper.due == ("events",)

    def test_an_integrity_poll_that_is_due_fetches_them_instead(self):
        housekeeper = Housekeeper()
        housekeeper.saw(IIN(first=IINBit.CLASS_1_EVENTS, second=IIN2Bit.EVENT_BUFFER_OVERFLOW))
        assert _drain(housekeeper) == ["integrity"]

    def test_and_one_that_comes_due_later_takes_the_place_of_the_event_poll(self):
        housekeeper = Housekeeper()
        housekeeper.saw(EVENTS, answering=A_READ)
        assert housekeeper.due == ("events",)
        housekeeper.saw(OVERFLOW)
        assert _drain(housekeeper) == ["integrity"]

    def test_no_response_is_nothing_to_act_on(self):
        housekeeper = Housekeeper()
        housekeeper.saw(None, answering=A_READ)
        assert housekeeper.due == ()


class TestWhatIsTurnedOff:
    EVERYTHING = IIN(
        first=IINBit.DEVICE_RESTART | IINBit.NEED_TIME | IINBit.CLASS_1_EVENTS,
        second=IIN2Bit.EVENT_BUFFER_OVERFLOW,
    )

    def test_with_none_nothing_is_ever_due(self):
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
    def test_each_task_is_turned_off_alone(self, off, never):
        housekeeper = Housekeeper(Tasks().changed({off: False}))
        housekeeper.connected()
        _answered(housekeeper)
        housekeeper.saw(IIN(first=self.EVERYTHING.first), answering=A_READ)
        done = _answered(housekeeper)
        assert never not in done
        assert done, "and the others are still done"

    def test_an_overflow_is_left_alone_when_told_to(self):
        housekeeper = Housekeeper(Tasks().changed({"integrity_on_overflow": False}))
        housekeeper.saw(OVERFLOW, answering=A_READ)
        assert housekeeper.due == ()


class TestNoTaskCommands:
    def test_whatever_is_indicated_nothing_is_sent_but_reads_and_these_two_writes(self):
        """Every combination of the indications a task answers, connecting or not."""
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


class TestAgainstTheOutstation:
    def test_starting_settles_it_and_fills_the_store(self, simulation):
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

    def test_the_time_written_is_the_time_the_outstation_then_keeps(self, simulation):
        master = Loopback(
            simulation.outstation.session(), tasks=Tasks(), time_ms=lambda: 1_700_000_000_000
        )
        master.start()
        assert abs(simulation.outstation.now_ms() - 1_700_000_000_000) < 5_000

    def test_given_no_tasks_it_sends_nothing_unasked(self, simulation):
        master = Loopback(simulation.outstation.session())
        assert master.start() == []
        poll = master.integrity_poll()
        assert poll.iin.is_set(IINBit.DEVICE_RESTART) and poll.iin.is_set(IINBit.NEED_TIME)
        assert master.unasked == [] and poll.sequence == 0 and poll.task is None

    def test_an_outstation_that_restarts_is_settled_again_and_read_again(self, simulation):
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

    def test_events_are_fetched_when_a_response_says_there_are_some(self, simulation):
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

    def test_an_overflow_is_answered_with_an_integrity_poll(self):
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

    def test_nothing_is_done_between_a_select_and_its_operate(self, simulation):
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

    def test_unsolicited_reporting_is_turned_on_after_startup_and_events_arrive(self, simulation):
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

    def test_a_restart_announced_unasked_is_settled(self, simulation):
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

    def test_a_master_that_does_not_confirm_is_not_made_to_poll_for_ever(self, simulation):
        """Events nobody confirms stay buffered. One poll is made for them, not a stream."""
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


class TestOverASocket:
    @pytest.mark.asyncio
    async def test_connecting_settles_the_outstation_before_anything_asked(self, simulation):
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
    async def test_a_scan_on_a_schedule_waits_for_startup_too(self, simulation):
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
    async def test_left_alone_it_keeps_its_store_current_through_a_restart(self):
        """The outstation goes away and comes back as a device that restarted."""
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
    async def test_a_manual_master_sends_nothing_it_was_not_asked_for(self, simulation):
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
    async def test_manual_leaves_alone_what_is_given_beside_it(self, simulation):
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
    async def test_a_lost_connection_is_not_made_again_when_told_not_to(self, simulation):
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
    async def test_a_connection_the_caller_closed_is_not_made_again(self, simulation):
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
    async def test_closing_while_it_is_trying_ends_the_trying(self, simulation):
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
    async def test_a_restart_announced_unasked_is_settled_over_a_socket(self, simulation):
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
    async def test_tasks_ended_before_they_began_leave_nobody_waiting(self):
        """A task cancelled before it first runs never reaches its own cleanup."""
        lab = Outstation("lab", host="127.0.0.1")
        lab._settled.clear()
        lab._housekeeping = asyncio.create_task(lab._keep_house())
        lab._stop_housekeeping()
        await asyncio.wait_for(lab.idle(), 1.0)

    @pytest.mark.asyncio
    async def test_it_keeps_trying_until_the_outstation_is_back(self, simulation):
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
    async def test_waiting_for_the_tasks_ends_with_the_connection(self, simulation):
        """Nobody is left waiting for a startup that an outstation never answers."""
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

    @pytest.mark.parametrize("wait", [0, -1.0])
    def test_a_wait_between_attempts_that_is_not_one_is_refused(self, wait):
        with pytest.raises(ValueError, match="a wait between attempts"):
            Outstation("lab", host="127.0.0.1", reconnect=wait)
