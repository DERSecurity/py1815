"""Setting an outstation's clock by the procedures of IEEE 1815-2012 10.3.3."""

from __future__ import annotations

import pytest
from profile_fixtures import for_reference_der
from test_master_association import _built, _from_outstation
from test_master_service import _added, _ask

from py1815.application import IIN, FunctionCode, IINBit
from py1815.master import Loopback, Outcome, Tasks
from py1815.master.service import Service
from py1815.master.tasks import Housekeeper
from py1815.master.timesync import TimeSync, outstation_delay_ms
from py1815.profile import der, load
from py1815.profile.model import Composition
from py1815.server import OutstationServer

NOW_MS = 1_700_000_000_000
NEED_TIME = IIN(first=IINBit.NEED_TIME)


@pytest.fixture
def simulation() -> der.Simulation:
    return der.build(load.resolve(for_reference_der(), Composition()))


def _answered(function: FunctionCode, response: str, *, seconds: float = 0.0):
    """An exchange of one request, answered after ``seconds`` with ``response``."""
    association, clock = _built()
    association.request(function, b"")
    clock.now += seconds
    association.receive(_from_outstation(response))
    return association.take()


def _unanswered(function: FunctionCode):
    association, clock = _built()
    association.request(function, b"")
    clock.now += 10.0
    association.expire()
    return association.take()


def _begun(function: FunctionCode):
    """An exchange whose first fragment arrived and whose last never did."""
    association, clock = _built()
    association.request(function, b"")
    association.receive(_from_outstation("80 81 00 00"))
    clock.now += 10.0
    association.expire()
    return association.take()


class TestThePlan:
    def test_lan_records_the_time_and_then_writes_when_it_asked(self):
        clock = iter([NOW_MS, NOW_MS + 50])
        plan = TimeSync("lan", clock_ms=lambda: next(clock))

        assert plan.next([]) == (FunctionCode.RECORD_CURRENT_TIME, b"")
        recorded = _answered(FunctionCode.RECORD_CURRENT_TIME, "C0 81 00 00")
        function, body = plan.next([recorded])

        # Group 50 variation 3, a count of one, the time the first request
        # was made: not the time the write was.
        assert function is FunctionCode.WRITE
        assert body.hex() == "320307010068e5cf8b01"
        assert plan.next([recorded, recorded]) is None

    def test_non_lan_writes_the_time_plus_half_the_round_trip_less_the_outstation_hold(self):
        clock = iter([NOW_MS, NOW_MS + 1_000])
        plan = TimeSync("non_lan", clock_ms=lambda: next(clock))

        assert plan.next([]) == (FunctionCode.DELAY_MEASURE, b"")
        # Answered after 100 ms with group 52 variation 2: held for 20 ms.
        measured = _answered(
            FunctionCode.DELAY_MEASURE, "C0 81 00 00 34 02 07 01 14 00", seconds=0.1
        )
        assert outstation_delay_ms(measured) == 20.0
        function, body = plan.next([measured])

        assert function is FunctionCode.WRITE
        written = int.from_bytes(body[4:], "little")
        assert body[:4].hex() == "32010701" and written == NOW_MS + 1_000 + 40
        result = plan.result([measured, measured])
        assert result.delay_ms == pytest.approx(40.0) and result.time_ms == written

    def test_a_delay_in_seconds_is_read_as_seconds(self):
        measured = _answered(FunctionCode.DELAY_MEASURE, "C0 81 00 00 34 01 07 01 02 00")
        assert outstation_delay_ms(measured) == 2000.0

    def test_a_hold_longer_than_the_round_trip_is_no_delay(self):
        plan = TimeSync("non_lan", clock_ms=lambda: NOW_MS)
        plan.next([])
        measured = _answered(
            FunctionCode.DELAY_MEASURE, "C0 81 00 00 34 02 07 01 E8 03", seconds=0.1
        )
        _, body = plan.next([measured])
        assert int.from_bytes(body[4:], "little") == NOW_MS

    @pytest.mark.parametrize(
        ("procedure", "first"),
        [
            # Refused by function code, then by parameter.
            ("lan", _answered(FunctionCode.RECORD_CURRENT_TIME, "C0 81 00 01")),
            ("lan", _answered(FunctionCode.RECORD_CURRENT_TIME, "C0 81 00 04")),
            ("non_lan", _answered(FunctionCode.DELAY_MEASURE, "C0 81 00 01")),
            # Answered with no delay in it.
            ("non_lan", _answered(FunctionCode.DELAY_MEASURE, "C0 81 00 00")),
            # Not answered at all.
            ("lan", _unanswered(FunctionCode.RECORD_CURRENT_TIME)),
            ("non_lan", _unanswered(FunctionCode.DELAY_MEASURE)),
            # Begun, and never finished.
            ("lan", _begun(FunctionCode.RECORD_CURRENT_TIME)),
        ],
    )
    def test_nothing_is_written_unless_the_first_request_was_answered(self, procedure, first):
        plan = TimeSync(procedure, clock_ms=lambda: NOW_MS)
        plan.next([])
        assert plan.next([first]) is None
        result = plan.result([first])
        assert not result.written and result.accepted is False and result.time_ms is None

    def test_a_procedure_that_is_not_one_is_refused(self):
        with pytest.raises(ValueError, match="lan or non_lan"):
            TimeSync("gps")


class TestAgainstASession:
    @pytest.mark.parametrize("procedure", ["lan", "non_lan"])
    def test_the_clock_is_set_and_the_outstation_stops_asking(self, simulation, procedure):
        master = Loopback(simulation.outstation.session(), time_ms=lambda: NOW_MS)
        assert master.integrity_poll().iin.is_set(IINBit.NEED_TIME)

        result = master.synchronize_time(procedure)

        assert [exchange.function for exchange in result.exchanges] == [
            FunctionCode.RECORD_CURRENT_TIME if procedure == "lan" else FunctionCode.DELAY_MEASURE,
            FunctionCode.WRITE,
        ]
        assert result.written and result.accepted
        assert not result.exchanges[-1].iin.is_set(IINBit.NEED_TIME)
        assert abs(simulation.outstation.now_ms() - NOW_MS) < 5_000

    def test_an_outstation_that_does_not_take_the_procedure_is_not_written_to(self, simulation):
        session = simulation.outstation.session(
            disabled_functions=frozenset({FunctionCode.RECORD_CURRENT_TIME})
        )
        master = Loopback(session)
        result = master.synchronize_time("lan")
        assert len(result.exchanges) == 1 and not result.written

    def test_neither_request_is_sent_again(self, simulation):
        master = Loopback(simulation.outstation.session(), time_ms=lambda: NOW_MS)
        master.association.read_retries = 5
        result = master.synchronize_time("non_lan")
        assert [exchange.retries for exchange in result.exchanges] == [0, 0]


class TestTheTask:
    @pytest.mark.parametrize(
        ("procedure", "first"),
        [("lan", FunctionCode.RECORD_CURRENT_TIME), ("non_lan", FunctionCode.DELAY_MEASURE)],
    )
    def test_the_time_task_follows_the_procedure_it_is_given(self, procedure, first):
        housekeeper = Housekeeper(Tasks(time_procedure=procedure))
        housekeeper.saw(NEED_TIME)
        (step,) = list(iter(housekeeper.next, None))
        assert (step.task, step.function, step.body) == ("write_time", first, b"")
        assert step.plan is not None and step.plan.procedure == procedure

    def test_a_plain_write_is_the_default(self):
        housekeeper = Housekeeper(clock_ms=lambda: NOW_MS)
        housekeeper.saw(NEED_TIME)
        (step,) = list(iter(housekeeper.next, None))
        assert step.plan is None and step.body.hex() == "320107010068e5cf8b01"

    def test_both_requests_of_the_procedure_are_made_for_the_task(self, simulation):
        master = Loopback(
            simulation.outstation.session(),
            tasks=Tasks(time_procedure="lan"),
            time_ms=lambda: NOW_MS,
        )
        done = master.start()
        timed = [exchange for exchange in done if exchange.task == "write_time"]
        assert [exchange.function for exchange in timed] == [
            FunctionCode.RECORD_CURRENT_TIME,
            FunctionCode.WRITE,
        ]
        assert all(exchange.outcome is Outcome.COMPLETE for exchange in timed)
        assert abs(simulation.outstation.now_ms() - NOW_MS) < 5_000


class TestTheService:
    @pytest.mark.asyncio
    async def test_it_sets_the_clock_only_when_started_to_command(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        reading, commanding = Service(), Service(allow_control=True)
        try:
            await _added(reading, server, manual=True)
            wrong = await _ask(reading, "synchronize_time", "lab", procedure="gps")
            assert wrong["error"]["kind"] == "request", "what is wrong is said first"
            refused = await _ask(reading, "synchronize_time", "lab")
            assert refused["error"]["kind"] == "not_allowed"
            await _ask(reading, "remove", "lab")

            await _added(commanding, server, manual=True, confirm=True)
            answer = (await _ask(commanding, "synchronize_time", "lab", procedure="non_lan"))[
                "result"
            ]
        finally:
            await reading.close()
            await commanding.close()
            await server.stop()

        assert answer["procedure"] == "non_lan" and answer["written"] and answer["accepted"]
        assert answer["delay_ms"] is not None and answer["time_ms"] is not None
        assert [each["function"] for each in answer["exchanges"]] == ["DELAY_MEASURE", "WRITE"]
