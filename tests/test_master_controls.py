"""Commands from the master: what is sent, in what order, and what is made of the answer.

The frames are pinned against octets written out by hand, so a mistake in the
encoder is not hidden by the outstation here reading it the same way. The
rules for a select and an operate are tested against exchanges built by hand
as well, since the outstation in this library never gives the answers that
matter most: an echo that differs, and no answer at all.
"""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from profile_fixtures import for_reference_der

from py1815.application import FunctionCode, IIN2Bit, IINBit, parse_response
from py1815.control import AnalogOutput, CommandStatus, ControlRelayOutputBlock, OperationType
from py1815.decode import decode_objects
from py1815.master import (
    Exchange,
    Loopback,
    Master,
    Mode,
    Outcome,
    PointType,
    controls,
    requests,
)
from py1815.master.controls import Plan
from py1815.profile import der, load
from py1815.profile.model import Composition, Kind
from py1815.server import OutstationServer


@pytest.fixture
def simulation() -> der.Simulation:
    return der.build(load.resolve(for_reference_der(), Composition()))


@pytest.fixture
def master(simulation) -> Loopback:
    return Loopback(simulation.outstation.session())


def _settle(simulation: der.Simulation, seconds: float = 30.0) -> None:
    for _ in range(round(seconds)):
        simulation.advance(1.0)


def _answer(
    plan: Plan,
    function: FunctionCode,
    body: bytes,
    outcome=Outcome.COMPLETE,
    *,
    arrived: bool | None = None,
) -> Exchange:
    """An exchange whose response carried ``body``, as an outstation might have sent it.

    ``arrived`` says whether the fragment got here. A response of several
    fragments can time out with the first of them in hand.
    """
    arrived = outcome is Outcome.COMPLETE if arrived is None else arrived
    fragment = bytes([0xC0, FunctionCode.RESPONSE, 0x00, 0x00]) + body
    response = parse_response(fragment)
    return Exchange(
        function=function,
        sequence=0,
        request=bytes([0xC0, function]) + plan.body,
        outcome=outcome,
        fragments=(response,) if arrived else (),
        objects=decode_objects(body).objects if arrived else (),
    )


class TestWhatTravels:
    def test_a_latch_and_a_setpoint_are_these_octets(self):
        body = controls.encode(controls.commands({17: True}, {87: 20}))
        assert body == bytes.fromhex(
            # Group 12 variation 1, one-octet count and index, one object at 17:
            # latch on, count 1, no on or off time, status 0.
            "0c 01 17 01 11 03 01 00000000 00000000 00"
            # Group 41 variation 2, one object at 87: 20 in sixteen bits, status 0.
            "29 02 17 01 57 1400 00"
        )

    def test_an_index_past_255_takes_two_octets_for_the_count_and_each_index(self):
        body = controls.encode(controls.commands(None, {87: 1, 508: 2}))
        assert body == bytes.fromhex("29 02 28 0200 5700 0100 00 fc01 0200 00")

    def test_controls_of_one_kind_share_a_header_and_keep_their_order(self):
        body = controls.encode(controls.commands({5: True, 3: False}, None))
        assert body[:4] == bytes([12, 1, 0x17, 2])
        assert body[4] == 5 and body[4 + 12] == 3

    @pytest.mark.parametrize(
        ("value", "variation"),
        [(20, 2), (-32768, 2), (32768, 1), (50_000, 1), (2**31, 3), (20.5, 3), ("5000", 2)],
    )
    def test_a_number_travels_in_the_narrowest_variation_that_carries_it(self, value, variation):
        assert controls.analog(1, value).variation == variation

    def test_a_variation_can_be_named(self):
        assert controls.analog(1, 20, 3).variation == 3
        assert controls.analog(1, 20, 4).encoded == bytes.fromhex("0000000000003440 00")

    @pytest.mark.parametrize(
        ("value", "operation"),
        [
            (True, OperationType.LATCH_ON),
            (False, OperationType.LATCH_OFF),
            ("pulse_on", OperationType.PULSE_ON),
            ("LATCH_OFF", OperationType.LATCH_OFF),
            ({"operation": "pulse_on", "count": 3, "on_time_ms": 250}, OperationType.PULSE_ON),
        ],
    )
    def test_a_binary_output_is_told_by_state_or_by_name(self, value, operation):
        block = controls.binary(4, value).control
        assert isinstance(block, ControlRelayOutputBlock)
        assert block.control_code & 0x0F == operation

    def test_a_trip_and_a_close_carry_their_code(self):
        assert controls.binary(4, "trip").control.control_code == 0x81
        assert controls.binary(4, "close").control.control_code == 0x41

    def test_a_command_made_elsewhere_is_sent_as_it_is(self):
        made = AnalogOutput(7.0, 3)
        assert controls.analog(9, made).control is made

    @pytest.mark.parametrize(
        ("binary", "analog", "options", "message"),
        [
            (None, None, {}, "at least one output"),
            (None, {87: "seven"}, {}, "takes a number"),
            (None, {87: True}, {}, "takes a number"),
            (None, {87: float("nan")}, {}, "analog output 87"),
            (None, {87: 70000}, {"variation": 2}, "does not fit"),
            (None, {87: 1}, {"variation": 9}, "variation 9"),
            (None, {70000: 1}, {}, "0 to 65535"),
            (None, {"x": 1}, {}, "not a point index"),
            ({1: "sideways"}, None, {}, "binary output can be told"),
            ({1: 1}, None, {}, "binary output can be told"),
            ({1: {"operation": "trip", "twice": 1}}, None, {}, "no 'twice'"),
        ],
    )
    def test_what_cannot_be_carried_is_refused_before_anything_is_sent(
        self, master, binary, analog, options, message
    ):
        before = master.association.busy, master.session.facts
        with pytest.raises(ValueError, match=message):
            master.operate(binary_outputs=binary, analog_outputs=analog, **options)
        assert (master.association.busy, master.session.facts) == before

    def test_a_mode_that_is_not_one_is_refused(self, master):
        with pytest.raises(ValueError, match="not a way to operate"):
            master.operate(analog_outputs={87: 1}, mode="twice")


class TestDirectOperate:
    def test_it_operates_and_reports_each_status(self, simulation, master):
        result = master.operate(
            binary_outputs={der.BO_ENABLE_POWER_LIMIT: True},
            analog_outputs={der.AO_POWER_LIMIT_GENERATION: 20},
        )
        assert [exchange.function for exchange in result.exchanges] == [FunctionCode.DIRECT_OPERATE]
        assert result.operated and result.accepted is True
        assert [status.status for status in result.statuses] == [CommandStatus.SUCCESS] * 2
        assert result.status("ao", der.AO_POWER_LIMIT_GENERATION) is CommandStatus.SUCCESS
        _settle(simulation)
        assert simulation.der.watts == pytest.approx(0.2 * simulation.der.ratings.watts, rel=0.01)

    def test_a_refusal_is_a_result_and_names_the_control(self, master):
        master.operate(binary_outputs={der.BO_LOCKOUT: True})
        result = master.operate(
            binary_outputs={der.BO_ENABLE_POWER_LIMIT: True},
            analog_outputs={der.AO_POWER_LIMIT_GENERATION: 20},
        )
        assert result.operated and result.accepted is False
        assert result.status(PointType.ANALOG_OUTPUT, der.AO_POWER_LIMIT_GENERATION) is (
            CommandStatus.BLOCKED
        )

    def test_an_output_the_outstation_does_not_have(self, master):
        result = master.operate(analog_outputs={60000: 1})
        assert result.accepted is False
        assert result.statuses[0].status is CommandStatus.NOT_SUPPORTED
        assert result.status("ao", 1) is None


class TestSelectThenOperate:
    def test_a_select_the_outstation_accepts_is_followed_by_the_operate(self, simulation, master):
        result = master.operate(analog_outputs={der.AO_POWER_LIMIT_GENERATION: 30}, mode="select")
        select, operate = result.exchanges
        assert (select.function, operate.function) == (FunctionCode.SELECT, FunctionCode.OPERATE)
        # The operate carries the objects of the select, and the next sequence number.
        assert operate.request[2:] == select.request[2:]
        assert operate.sequence == (select.sequence + 1) % 16
        assert result.accepted is True
        assert simulation.outstation.value(Kind.AO, der.AO_POWER_LIMIT_GENERATION) == 30

    def test_a_select_the_outstation_refuses_is_not_followed_by_anything(self, simulation, master):
        master.operate(binary_outputs={der.BO_LOCKOUT: True})
        before = simulation.outstation.value(Kind.AO, der.AO_POWER_LIMIT_GENERATION)
        result = master.operate(
            analog_outputs={der.AO_POWER_LIMIT_GENERATION: 30}, mode=Mode.SELECT
        )
        assert [exchange.function for exchange in result.exchanges] == [FunctionCode.SELECT]
        assert not result.operated and result.accepted is False
        assert result.statuses[0].status is CommandStatus.BLOCKED
        assert simulation.outstation.value(Kind.AO, der.AO_POWER_LIMIT_GENERATION) == before

    def test_one_refusal_among_several_stops_them_all(self, simulation, master):
        result = master.operate(analog_outputs={87: 30, 60000: 1}, mode="select")
        assert not result.operated
        assert [status.status for status in result.statuses] == [
            CommandStatus.SUCCESS,
            CommandStatus.NOT_SUPPORTED,
        ]
        assert simulation.outstation.value(Kind.AO, 87) != 30

    def test_an_echo_that_differs_is_not_a_select(self):
        """The outstation said SUCCESS, but to a value that is not the one sent."""
        plan = Plan(controls.commands(None, {87: 30}), "select")
        assert plan.next([]) == (FunctionCode.SELECT, plan.body)
        altered = bytes.fromhex("29 02 17 01 57 1f00 00")
        select = _answer(plan, FunctionCode.SELECT, altered)
        assert plan.next([select]) is None
        result = plan.result([select])
        assert not result.operated and result.accepted is False
        assert result.statuses[0].status is CommandStatus.SUCCESS and not result.statuses[0].echoed

    def test_an_echo_that_is_missing_is_not_a_select(self):
        plan = Plan(controls.commands(None, {87: 30}), "select")
        select = _answer(plan, FunctionCode.SELECT, b"")
        assert plan.next([select]) is None
        assert plan.result([select]).statuses[0].status is None

    def test_a_select_that_was_not_answered_is_not_followed_by_an_operate(self):
        plan = Plan(controls.commands(None, {87: 30}), "select")
        select = _answer(plan, FunctionCode.SELECT, plan.body, Outcome.TIMEOUT)
        assert plan.next([select]) is None
        result = plan.result([select])
        assert not result.operated and result.accepted is False

    def test_nor_is_one_whose_response_did_not_finish(self):
        """The echo arrived and said yes, but the response it was part of never ended."""
        plan = Plan(controls.commands(None, {87: 30}), "select")
        select = _answer(plan, FunctionCode.SELECT, plan.body, Outcome.TIMEOUT, arrived=True)
        assert plan.result([select]).statuses[0].accepted
        assert plan.next([select]) is None

    def test_an_operate_that_was_not_answered_is_not_known_and_not_sent_again(self):
        plan = Plan(controls.commands(None, {87: 30}), "select")
        select = _answer(plan, FunctionCode.SELECT, plan.body)
        assert plan.next([select]) == (FunctionCode.OPERATE, plan.body)
        operate = _answer(plan, FunctionCode.OPERATE, plan.body, Outcome.TIMEOUT)
        assert plan.next([select, operate]) is None
        result = plan.result([select, operate])
        assert result.operated and result.accepted is None

    def test_the_same_output_twice_in_one_request_has_two_answers(self):
        first, second = controls.analog(87, 10), controls.analog(87, 20)
        plan = Plan((first, second))
        echo = bytes.fromhex("29 02 17 02 57 0a00 00 57 1400 04")
        result = plan.result([_answer(plan, FunctionCode.DIRECT_OPERATE, echo)])
        assert [status.status for status in result.statuses] == [
            CommandStatus.SUCCESS,
            CommandStatus.NOT_SUPPORTED,
        ]
        assert all(status.echoed for status in result.statuses)


class TestWithNoAcknowledgment:
    def test_it_is_sent_once_and_nothing_is_known_of_it(self, simulation, master):
        limit = der.AO_POWER_LIMIT_GENERATION
        result = master.operate(analog_outputs={limit: 40}, mode="direct_no_ack")
        (exchange,) = result.exchanges
        assert exchange.function is FunctionCode.DIRECT_OPERATE_NR
        assert exchange.outcome is Outcome.SENT and not exchange.fragments
        assert result.operated and result.accepted is None
        assert result.statuses[0].status is None
        # The outstation acted on it all the same.
        assert simulation.outstation.value(Kind.AO, der.AO_POWER_LIMIT_GENERATION) == 40


class TestTheOtherWrites:
    def test_the_time_is_written_as_these_octets_and_the_outstation_stops_asking(self, master):
        assert master.integrity_poll().iin.is_set(IINBit.NEED_TIME)
        written = master.write_time(1_700_000_000_000)
        # Group 50 variation 1, a count of one, and the time in 48 bits.
        assert written.request[1:] == bytes.fromhex("02 32 01 07 01 0068e5cf8b01")
        assert written.complete and not written.iin.is_set(IINBit.NEED_TIME)

    def test_a_time_left_out_is_now(self, master, monkeypatch):
        monkeypatch.setattr("py1815.master.operations.time.time", lambda: 1_700_000_000.0)
        assert master.write_time().request[-6:] == (1_700_000_000_000).to_bytes(6, "little")

    def test_a_time_that_does_not_fit_is_refused(self):
        with pytest.raises(ValueError, match="48 bits"):
            requests.write_time(1 << 48)

    def test_the_restart_indication_is_cleared_with_these_octets(self, master):
        assert master.integrity_poll().iin.is_set(IINBit.DEVICE_RESTART)
        cleared = master.clear_restart()
        # Group 80 variation 1, indices 7 to 7, and the bit written as 0.
        assert cleared.request[1:] == bytes.fromhex("02 50 01 00 07 07 00")
        assert not cleared.iin.is_set(IINBit.DEVICE_RESTART)

    def test_a_freeze_gives_the_frozen_counters_what_the_counters_held(self, simulation, master):
        _settle(simulation, 120)
        frozen = master.freeze()
        assert frozen.function is FunctionCode.IMMED_FREEZE
        assert frozen.request[1:] == bytes.fromhex("07 14 00 06") and frozen.complete
        master.read(counters="all", frozen_counters="all")
        assert master.store.frozen_counter(0).value == master.store.counter(0).value > 0

    @pytest.mark.parametrize(
        ("options", "function", "outcome"),
        [
            ({"clear": True}, FunctionCode.FREEZE_CLEAR, Outcome.COMPLETE),
            ({"respond": False}, FunctionCode.IMMED_FREEZE_NR, Outcome.SENT),
            ({"clear": True, "respond": False}, FunctionCode.FREEZE_CLEAR_NR, Outcome.SENT),
        ],
    )
    def test_each_freeze_is_its_own_function(self, master, options, function, outcome):
        frozen = master.freeze(**options)
        assert (frozen.function, frozen.outcome) == (function, outcome)

    def test_a_restart_the_outstation_does_not_do_is_a_result(self, master):
        restart = master.restart("cold")
        assert restart.request[1:] == bytes([FunctionCode.COLD_RESTART])
        assert restart.complete and restart.iin.is_set(IIN2Bit.FUNC_NOT_SUPPORTED)
        assert master.restart("warm").function is FunctionCode.WARM_RESTART
        with pytest.raises(ValueError, match="cold or warm"):
            master.restart("lukewarm")


@pytest_asyncio.fixture
async def lab():
    """A master on a socket, connected to a simulated DER."""
    simulation = der.build(load.resolve(for_reference_der(), Composition()))
    server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
    await server.start()
    try:
        async with Master() as master:
            outstation = await master.add("lab", host="127.0.0.1", port=server.port)
            yield simulation, outstation
    finally:
        await server.stop()


class TestOverASocket:
    @pytest.mark.asyncio
    async def test_it_operates_by_select_and_operate(self, lab):
        simulation, outstation = lab
        result = await outstation.operate(analog_outputs={87: 30}, mode="select")
        assert [exchange.function for exchange in result.exchanges] == [
            FunctionCode.SELECT,
            FunctionCode.OPERATE,
        ]
        assert result.accepted is True
        assert simulation.outstation.value(Kind.AO, 87) == 30

    @pytest.mark.asyncio
    async def test_nothing_comes_between_a_select_and_its_operate(self, lab):
        """A scan asked for while a select is out waits for the operate as well."""
        _, outstation = lab
        sent: list[FunctionCode] = []
        outstation.on_exchange = lambda exchange: sent.append(exchange.function)
        await asyncio.gather(
            outstation.operate(analog_outputs={87: 30}, mode="select"),
            outstation.scan("class0"),
            outstation.scan("class0"),
        )
        assert sent[:2] == [FunctionCode.SELECT, FunctionCode.OPERATE]
        assert sent[2:] == [FunctionCode.READ, FunctionCode.READ]

    @pytest.mark.asyncio
    async def test_the_writes_and_the_freeze(self, lab):
        _, outstation = lab
        assert (await outstation.write_time()).complete
        assert not (await outstation.clear_restart()).iin.is_set(IINBit.DEVICE_RESTART)
        assert (await outstation.freeze(respond=False)).outcome is Outcome.SENT
