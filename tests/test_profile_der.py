"""The simulated DER, and the outstation it stands behind, run together.

Against synthetic tables built from the DER's own binding, so this runs in CI
where the IEEE tables are not available, and once more against the real ones
where a checkout has regenerated them.
"""

from __future__ import annotations

import asyncio
import struct

import pytest
from profile_fixtures import REAL_TABLES, for_reference_der

from py1815.application import FunctionCode, QualifierCode
from py1815.control import CommandStatus, ControlRelayOutputBlock, OperationType, encode_crob
from py1815.events import EventClass
from py1815.profile import der, load, probe
from py1815.profile.model import Composition, Kind
from py1815.profile.outstation import DerOutstation
from py1815.server import OutstationServer

ALL = QualifierCode.ALL_OBJECTS


@pytest.fixture
def simulation() -> der.Simulation:
    return der.build(load.resolve(for_reference_der(), Composition()))


def _settle(simulation: der.Simulation, seconds: int = 30) -> None:
    for _ in range(seconds):
        simulation.advance(1.0)


def _latch(session, index: int, state: bool, sequence: int = 0) -> CommandStatus:
    operation = OperationType.LATCH_ON if state else OperationType.LATCH_OFF
    body = bytes([12, 1, 0x17, 1, index]) + encode_crob(ControlRelayOutputBlock.build(operation))
    response = session._handle_fragment(
        bytes([0xC0 | sequence, FunctionCode.DIRECT_OPERATE]) + body
    )
    return CommandStatus(response[-1])


def _setpoint(session, index: int, raw: int, sequence: int = 0) -> CommandStatus:
    width = 0x28 if index > 255 else 0x17
    prefix = struct.pack("<HH", 1, index) if index > 255 else bytes([1, index])
    body = bytes([41, 1, width]) + prefix + struct.pack("<i", raw) + b"\x00"
    response = session._handle_fragment(
        bytes([0xC0 | sequence, FunctionCode.DIRECT_OPERATE]) + body
    )
    return CommandStatus(response[-1])


class TestTheDeviceOnItsOwn:
    def test_it_generates_toward_what_its_source_has_available(self, simulation):
        _settle(simulation)
        device = simulation.der
        assert device.watts == pytest.approx(device.available_watts(), rel=0.02)
        assert device.vars == pytest.approx(0.0, abs=1.0)

    def test_energy_accumulates_as_it_runs(self, simulation):
        _settle(simulation, 120)
        delivered, received, *_ = simulation.der.energy
        assert delivered > 0 and received == 0

    def test_the_same_seed_gives_the_same_run(self):
        point_map = load.resolve(for_reference_der(), Composition())
        first, second = der.build(point_map, seed=7), der.build(point_map, seed=7)
        _settle(first)
        _settle(second)
        assert first.der.phase_volts == second.der.phase_volts

    def test_a_step_of_no_time_changes_nothing(self, simulation):
        simulation.der.step(0.0)
        assert simulation.der.elapsed == 0.0


class TestFunctionsTakeEffect:
    def test_the_active_power_limit_caps_output(self, simulation):
        session = simulation.outstation.session()
        assert _setpoint(session, der.AO_POWER_LIMIT_MAXIMUM, 20) is CommandStatus.SUCCESS
        assert _latch(session, der.BO_ENABLE_POWER_LIMIT, True, 1) is CommandStatus.SUCCESS
        _settle(simulation)
        assert simulation.der.watts == pytest.approx(0.2 * simulation.der.ratings.watts, rel=0.01)

    def test_and_does_nothing_until_enabled(self, simulation):
        """The control: the setting alone does not limit anything."""
        _setpoint(simulation.outstation.session(), der.AO_POWER_LIMIT_MAXIMUM, 20)
        _settle(simulation)
        assert simulation.der.watts > 0.5 * simulation.der.ratings.watts

    def test_charging_draws_power_and_raises_the_state_of_charge(self, simulation):
        session = simulation.outstation.session()
        before = simulation.der.state_of_charge
        _setpoint(session, der.AO_CHARGE_DISCHARGE_TARGET, -50)
        _latch(session, der.BO_ENABLE_CHARGE_DISCHARGE, True, 1)
        _settle(simulation, 120)
        assert simulation.der.watts == pytest.approx(-0.5 * simulation.der.ratings.watts, rel=0.01)
        assert simulation.der.state_of_charge > before
        assert simulation.der.energy[1] > 0

    def test_constant_vars_sets_reactive_power(self, simulation):
        session = simulation.outstation.session()
        _setpoint(session, der.AO_CONSTANT_VARS_TARGET, 40)
        _latch(session, der.BO_ENABLE_CONSTANT_VARS, True, 1)
        _settle(simulation)
        assert simulation.der.vars == pytest.approx(0.4 * simulation.der.ratings.vars, rel=0.01)

    def test_constant_power_factor_follows_active_power(self, simulation):
        session = simulation.outstation.session()
        # The synthetic tables carry no scaling, so a factor travels as itself.
        simulation.der.settings[(Kind.AO, der.AO_CONSTANT_PF_GENERATING)] = 0.9
        _latch(session, der.BO_ENABLE_CONSTANT_PF, True)
        _settle(simulation)
        assert simulation.der.power_factor == pytest.approx(0.9, abs=0.005)
        assert simulation.der.vars > 0, "injecting, until told to absorb"

    def test_reactive_power_gives_way_at_the_apparent_rating(self, simulation):
        """Full active power and full vars together exceed the rating; vars yield."""
        session = simulation.outstation.session()
        ratings = simulation.der.ratings
        _setpoint(session, der.AO_CHARGE_DISCHARGE_TARGET, 100)
        _latch(session, der.BO_ENABLE_CHARGE_DISCHARGE, True, 1)
        _setpoint(session, der.AO_CONSTANT_VARS_TARGET, 100, 2)
        _latch(session, der.BO_ENABLE_CONSTANT_VARS, True, 3)
        _settle(simulation, 60)
        assert simulation.der.watts == pytest.approx(ratings.watts, rel=0.01)
        assert simulation.der.vars < ratings.vars * 0.9, "asked for all of it, got the headroom"
        assert simulation.der.volt_amperes <= ratings.volt_amperes * 1.001


class TestStateCommands:
    def test_stopping_brings_output_to_zero(self, simulation):
        _settle(simulation)
        assert _latch(simulation.outstation.session(), der.BO_STOP, True) is CommandStatus.SUCCESS
        _settle(simulation)
        assert simulation.der.watts == pytest.approx(0.0, abs=1.0)
        assert not simulation.der.started

    def test_starting_needs_permission(self, simulation):
        session = simulation.outstation.session()
        _latch(session, der.BO_STOP, True)
        _settle(simulation, 2)
        _latch(session, der.BO_PERMIT_START, False, 1)
        assert _latch(session, der.BO_START, True, 2) is CommandStatus.BLOCKED
        _latch(session, der.BO_PERMIT_START, True, 3)
        assert _latch(session, der.BO_START, True, 4) is CommandStatus.SUCCESS
        assert simulation.der.starting and not simulation.der.started
        _settle(simulation, 2)
        assert simulation.der.started and not simulation.der.starting

    def test_opening_the_switch_disconnects(self, simulation):
        _latch(simulation.outstation.session(), der.BO_CONNECT, False)
        _settle(simulation)
        assert simulation.der.watts == pytest.approx(0.0, abs=1.0)

    def test_a_lockout_blocks_every_command_but_its_own_release(self, simulation):
        session = simulation.outstation.session()
        assert _latch(session, der.BO_LOCKOUT, True) is CommandStatus.SUCCESS
        assert _latch(session, der.BO_STOP, True, 1) is CommandStatus.BLOCKED
        assert _setpoint(session, der.AO_POWER_LIMIT_MAXIMUM, 10, 2) is CommandStatus.BLOCKED
        assert simulation.der.started, "the blocked stop did not happen"
        assert _latch(session, der.BO_LOCKOUT, False, 3) is CommandStatus.SUCCESS
        assert _latch(session, der.BO_STOP, True, 4) is CommandStatus.SUCCESS


class TestTheCurveWindow:
    def _read(self, session, group: int, index: int, sequence: int) -> float:
        header = struct.pack("<BBBHH", group, 0, 0x01, index, index)
        response = session._handle_fragment(bytes([0xC0 | sequence, FunctionCode.READ]) + header)
        static, _ = probe.parse_objects(response[4:])
        return static[0].value

    def test_writes_land_in_the_selected_curve_and_read_back_from_it(self, simulation):
        session = simulation.outstation.session()
        first_x = der.AO_CURVE_SELECTOR + 1 + der.CURVE_FIELDS
        _setpoint(session, first_x, 950, 0)
        _setpoint(session, der.AO_CURVE_SELECTOR, 2, 1)
        assert self._read(session, 30, der.AI_CURVE_SELECTOR + 1 + der.CURVE_FIELDS, 2) == 0
        _setpoint(session, first_x, 1050, 3)
        _setpoint(session, der.AO_CURVE_SELECTOR, 1, 4)
        assert self._read(session, 30, der.AI_CURVE_SELECTOR + 1 + der.CURVE_FIELDS, 5) == 950
        assert self._read(session, 40, first_x, 6) == 950, "the output's status follows the window"
        assert self._read(session, 30, der.AI_CURVE_SELECTOR, 7) == 1

    def test_a_curve_that_does_not_exist_cannot_be_selected(self, simulation):
        session = simulation.outstation.session()
        status = _setpoint(session, der.AO_CURVE_SELECTOR, der.CURVE_COUNT + 1)
        assert status is CommandStatus.OUT_OF_RANGE
        assert simulation.der.selected_curve == 1


class TestCountersFreezeOnTheirInterval:
    def test_they_freeze_at_startup(self, simulation):
        assert simulation.outstation.events.count(EventClass.CLASS_3) == 4

    def test_and_again_each_time_the_interval_passes(self, simulation):
        before = simulation.outstation.events.count(EventClass.CLASS_3)
        _settle(simulation, 299)
        assert simulation.outstation.events.count(EventClass.CLASS_3) == before
        _settle(simulation, 2)
        assert simulation.outstation.events.count(EventClass.CLASS_3) == before + 4

    def test_a_master_can_change_the_interval(self, simulation):
        session = simulation.outstation.session()
        assert _setpoint(session, der.AO_FREEZE_INTERVAL, 10) is CommandStatus.SUCCESS
        assert _setpoint(session, der.AO_FREEZE_INTERVAL_UNITS, 2, 1) is CommandStatus.SUCCESS
        assert simulation.der.freeze_interval_seconds() == 10.0

    def test_an_interval_of_zero_stops_the_repeat(self, simulation):
        _setpoint(simulation.outstation.session(), der.AO_FREEZE_INTERVAL, 0)
        assert simulation.der.freeze_interval_seconds() is None

    def test_a_calendar_unit_is_refused(self, simulation):
        session = simulation.outstation.session()
        status = _setpoint(session, der.AO_FREEZE_INTERVAL_UNITS, 7)
        assert status is CommandStatus.NOT_SUPPORTED
        assert simulation.der.freeze_interval_seconds() == 300.0


class TestOverTcp:
    @pytest.mark.asyncio
    async def test_an_integrity_poll_reads_the_whole_map(self):
        # Small blocks and a small response, so the map takes several fragments
        # and the poll has to confirm its way through them.
        point_map = load.resolve(for_reference_der(), Composition())
        device = der.ReferenceDer()
        outstation = DerOutstation(point_map, device.bind(point_map), block_octets=200)
        simulation = der.Simulation(device, outstation)
        server = OutstationServer(outstation.session(max_response=292), bind="127.0.0.1:0")
        await server.start()
        try:
            simulation.advance(1.0)
            result = await probe.integrity_poll("127.0.0.1", server.port)
        finally:
            await server.stop()

        assert result.fragments > 1, "the map is larger than one fragment"
        assert len(result.group(1)) == len(outstation.served(Kind.BI))
        assert len(result.group(20)) == len(outstation.served(Kind.CTR))
        assert len(result.group(21)) == 4
        assert len(result.group(30)) == len(outstation.served(Kind.AI))
        watts = result.find(30, der.AI_METER_FIRST + 4)
        assert watts is not None and watts.value == round(simulation.der.watts)

    @pytest.mark.asyncio
    async def test_a_confirmed_poll_leaves_no_events_behind(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        try:
            _settle(simulation, 5)
            first = await probe.integrity_poll("127.0.0.1", server.port)
            # The confirmation is on its way; give the listener a turn to take it.
            await asyncio.sleep(0.05)
            second = await probe.integrity_poll("127.0.0.1", server.port)
        finally:
            await server.stop()
        assert first.events
        assert not second.events

    @pytest.mark.asyncio
    async def test_nothing_listening_is_reported_not_raised_raw(self):
        with pytest.raises(probe.ProbeError, match="cannot connect"):
            await probe.integrity_poll("127.0.0.1", 1, timeout=2.0)

    @pytest.mark.asyncio
    async def test_the_wrong_link_address_gets_no_answer(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        try:
            with pytest.raises(probe.ProbeError, match=r"no answer|closed"):
                await probe.integrity_poll("127.0.0.1", server.port, outstation=9, timeout=0.5)
        finally:
            await server.stop()


@pytest.mark.skipif(not REAL_TABLES.is_file(), reason="the IEEE tables are generated locally")
class TestAgainstTheProfile:
    """The reference DER on the profile's own tables, where a checkout has them."""

    def test_it_serves_every_point_the_profile_makes_mandatory(self):
        """Strict by default: building at all is the assertion."""
        simulation = der.build(load.load(REAL_TABLES))
        served = {point.address for kind in Kind for point in simulation.outstation.served(kind)}
        mandatory = {
            p.address for p in simulation.outstation.point_map.points.values() if p.mandatory
        }
        assert mandatory and mandatory <= served

    def test_only_the_functions_it_implements_are_reported_supported(self):
        simulation = der.build(load.load(REAL_TABLES))
        outstation = simulation.outstation
        blocks = outstation.read_blocks(_headers(bytes([1, 0, ALL])))
        static, _ = probe.parse_objects(b"".join(blocks))
        states = {value.index: bool(value.value) for value in static}
        supports = [p for p in outstation.served(Kind.BI) if p.enabled_by is not None]
        supported = {p.enabled_by[1] for p in supports if states[p.index]}
        assert supported == {
            der.BO_ENABLE_POWER_LIMIT,
            der.BO_ENABLE_CHARGE_DISCHARGE,
            der.BO_ENABLE_CONSTANT_VARS,
            der.BO_ENABLE_CONSTANT_PF,
            der.BO_ENABLE_VOLT_WATT,
            der.BO_ENABLE_VOLT_VAR,
        }

    def test_measurements_travel_in_the_units_the_tables_give(self):
        simulation = der.build(load.load(REAL_TABLES))
        _settle(simulation)
        outstation = simulation.outstation
        blocks = outstation.read_blocks(_headers(bytes([30, 0, ALL])))
        static, _ = probe.parse_objects(b"".join(blocks))
        raw = {value.index: value.value for value in static}
        hertz = outstation.point_map.point(Kind.AI, der.AI_METER_FIRST + 3)
        assert hertz.from_wire(raw[hertz.index]) == pytest.approx(60.0, abs=0.1)
        version = outstation.point_map.point(Kind.AI, 0)
        assert version.from_wire(raw[0]) == pytest.approx(
            float(outstation.point_map.profile_version)
        )

    def test_equipment_blocks_resolve_alongside_it(self):
        composition = Composition(meters=1, inverters=2, batteries=1, der_units=1)
        simulation = der.build(load.load(REAL_TABLES, composition))
        blocks = simulation.outstation.read_blocks(_headers(bytes([30, 0, 0x00, 25, 28])))
        static, _ = probe.parse_objects(b"".join(blocks))
        assert [value.value for value in static] == [1, 2, 1, 1]


def _headers(body: bytes):
    from py1815.application import parse_request

    return parse_request(bytes([0xC0, FunctionCode.READ]) + body).headers
