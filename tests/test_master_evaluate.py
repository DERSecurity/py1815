"""``py1815-master evaluate``: checks of an outstation, and the report.

The measure of done for the checks is that run over a socket against the
simulated DER, the report says what the in-process procedures of
``test_epri_der_procedures.py`` say: every procedure passes, and the same
functions are supported. The rest is that each check can fail: a simulated
DER made to misbehave in one way is reported as failing the check for it.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import threading
from collections.abc import Callable
from typing import Any

import pytest
import pytest_asyncio
from epri_harness import TABLES, point_map
from profile_fixtures import SUPPORTS, paired_reference_der
from test_epri_coverage import ALL, NOT_APPLICABLE
from test_epri_der_procedures import IMPLEMENTED
from test_epri_der_procedures import MODES as EPRI_MODES

from py1815.control import CommandStatus
from py1815.master import Outstation, cli
from py1815.master import bench as benches
from py1815.master.bench import Bench, Check, Failed, NoAnswer, NotApplicable, Result, Verdict
from py1815.master.checks import CATALOG, MODES, SAMPLE_CURVES, select, valid_values
from py1815.master.evaluate import Report, catalog_lines, evaluate, evaluate_loopback
from py1815.master.loopback import Loopback
from py1815.master.profile import DerProfile, Plan
from py1815.master.tasks import Tasks
from py1815.profile import binding as bindings
from py1815.profile import curves, der, device_profile, load
from py1815.profile.binding import Binding
from py1815.profile.model import Composition, Kind, Point, PointMap
from py1815.profile.outstation import DerOutstation
from py1815.server import OutstationServer

PASSED, FAILED = Verdict.PASSED, Verdict.FAILED
NOT_RUN, NOT_APPLICABLE_ = Verdict.NOT_RUN, Verdict.NOT_APPLICABLE


def _synthetic() -> PointMap:
    return load.resolve(paired_reference_der(), Composition())


def _in_process(simulation: der.Simulation, points: PointMap, **options: Any) -> Report:
    """Evaluate a simulated DER in this process, moving it forward at each wait."""
    loopback = Loopback(simulation.outstation.session(need_time=False))
    options.setdefault("commanding", True)
    return evaluate_loopback(loopback, points, advance=simulation.advance, **options)


def _by_id(report: Report) -> dict[str, Result]:
    return {result.id: result for result in report.results}


def _faulty(
    points: PointMap, change: Callable[[Binding, der.ReferenceDer], None]
) -> der.Simulation:
    """Build a simulated DER whose binding ``change`` has altered."""
    reference = der.ReferenceDer()
    binding = reference.bind(points)
    change(binding, reference)
    return der.Simulation(reference, DerOutstation(points, binding))


def _one(simulation: der.Simulation, points: PointMap, check: str, **options: Any) -> Result:
    return _in_process(simulation, points, checks=select([check]), **options).results[0]


# ------------------------------------------------- against the simulated DER


@pytest.fixture(params=TABLES)
def points(request: pytest.FixtureRequest) -> PointMap:
    return point_map(request.param)


class TestAgainstTheSimulatedDer:
    def test_every_check_passes_in_process(self, points):
        report = _in_process(der.build(points), points)
        ended = {result.id: (result.verdict, result.detail) for result in report.results}
        assert ended.pop("PROFILE-001")[0] is NOT_APPLICABLE_, "no document was given"
        assert set(ended.values()) == {(PASSED, "")}, ended
        assert not report.failed

    def test_supported_functions_match_the_in_process_procedures(self, points):
        results = _by_id(_in_process(der.build(points), points))
        supported = {
            identifier for identifier in MODES if results[identifier].title.endswith(": supported")
        }
        assert supported == IMPLEMENTED
        for identifier in set(MODES) - IMPLEMENTED:
            assert results[identifier].title.endswith(": not supported")

    def test_catalog_has_a_check_for_every_procedure_the_suite_carries_out(self):
        assert MODES == EPRI_MODES
        carried_out = set(ALL) - set(NOT_APPLICABLE)
        assert carried_out <= {check.id for check in CATALOG}

    def test_der_is_left_started_connected_and_with_no_function_enabled(self, points):
        simulation = der.build(points)
        _in_process(simulation, points)
        reference = simulation.der
        assert reference.started and reference.connected
        assert reference.settings[(Kind.BO, der.BO_PERMIT_START)]
        assert reference.settings[(Kind.BO, der.BO_PERMIT_STOP)]
        assert not any(reference.settings[(Kind.BO, f.enable)] for f in der.FUNCTIONS)
        assert not any(reference.curves.referenced(number) for number in reference.curves.curves)

    def test_der_found_stopped_is_left_stopped(self, points):
        simulation = der.build(points)
        simulation.der.started = False
        report = _in_process(
            simulation,
            points,
            checks=select(["SERV-001", "SERV-001.2", "SERV-001.3"]),
        )
        assert [result.verdict for result in report.results] == [PASSED] * 3
        assert not simulation.der.started


@pytest_asyncio.fixture
async def served(points):
    """A simulated DER on a socket, and a connected master."""
    simulation = der.build(points)
    server = OutstationServer(simulation.outstation.session(need_time=False), bind="127.0.0.1:0")
    await server.start()
    outstation = Outstation(
        "lab", host="127.0.0.1", port=server.port, tasks=Tasks.none(), reconnect=None
    )
    await outstation.connect()
    try:
        yield simulation, outstation, server
    finally:
        await outstation.close()
        await server.stop()


@pytest.mark.asyncio
class TestOverASocket:
    async def test_report_over_a_socket_says_what_the_in_process_run_says(self, served, points):
        simulation, outstation, _server = served

        async def advance(seconds: float) -> None:
            simulation.advance(seconds)

        over_socket = await evaluate(outstation, points, commanding=True, pause=advance)
        in_process = _in_process(der.build(points), points)

        def said(report: Report) -> list[tuple[str, str, Verdict, str, tuple[str, ...], int]]:
            return [
                (r.id, r.title, r.verdict, r.detail, r.notes, r.requests) for r in report.results
            ]

        assert said(over_socket) == said(in_process)
        assert over_socket.outstation == "lab"

    async def test_each_check_names_its_frames_in_the_trace(self, served, points):
        _simulation, outstation, _server = served
        report = await evaluate(outstation, points, checks=select(["MON-001", "OP-001"]))
        first, second = (result.frames for result in report.results)
        assert first is not None and second is not None
        assert first[0] <= first[1] < second[0] <= second[1] == outstation.trace.last_id
        # A request and a response for each: two frames a request.
        assert first[1] - first[0] + 1 == 2 * report.results[0].requests

    async def test_lost_connection_fails_the_check_under_way_and_stops_the_run(
        self, served, points
    ):
        _simulation, outstation, _server = served

        def reads(bench: Bench) -> Plan[None]:
            yield from bench.obtain(bench.map.point(Kind.BI, 14))

        def drops(bench: Bench) -> Plan[None]:
            yield lambda target: target.close()
            yield from reads(bench)

        checks = [
            Check("A", "reads", False, reads),
            Check("B", "drops", False, drops),
            Check("C", "reads", False, reads),
        ]
        report = await evaluate(outstation, points, checks=checks)
        a, b, c = report.results
        assert a.verdict is PASSED
        assert b.verdict is FAILED and b.detail.startswith("the connection was lost")
        assert c.verdict is NOT_RUN and "connection was lost" in c.detail

    async def test_outstation_that_answers_nothing_is_an_error_and_not_a_report(self, served):
        _simulation, _outstation, server = served
        silent = Outstation(
            "silent",
            host="127.0.0.1",
            port=server.port,
            outstation_address=9,
            response_timeout=0.2,
            tasks=Tasks.none(),
            reconnect=None,
        )
        await silent.connect()
        try:
            with pytest.raises(NoAnswer, match="did not answer a class 0 read"):
                await evaluate(silent, _synthetic())
            sent = [entry for entry in silent.trace.since() if entry.direction == "tx"]
            assert len(sent) == 1, "nothing more is asked of an outstation that is silent"
        finally:
            await silent.close()


# ------------------------------------------------------------------ read only


class TestReadOnly:
    def test_checks_that_write_are_not_run_and_no_control_is_sent(self, monkeypatch):
        points = _synthetic()

        def refuse(_self: Loopback, _plan: Any) -> None:
            raise AssertionError("a control was sent by a run that was not allowed to command")

        monkeypatch.setattr(Loopback, "_carry_out", refuse)
        report = _in_process(der.build(points), points, commanding=False)
        for check, result in zip(CATALOG, report.results, strict=True):
            if check.commands:
                assert result.verdict is NOT_RUN and "writes to the outstation" in result.detail
                assert result.requests == 0
        reading = [
            result
            for check, result in zip(CATALOG, report.results, strict=True)
            if not check.commands
        ]
        assert [result.id for result in reading] == [
            "PROFILE-001",
            "MON-001",
            "ALARM-001",
            "OP-001",
        ]
        assert [result.verdict for result in reading[1:]] == [PASSED] * 3
        assert report.count(NOT_RUN) == len(CATALOG) - 4

    def test_every_check_but_the_four_that_read_is_marked_as_writing(self):
        assert {check.id for check in CATALOG if not check.commands} == {
            "PROFILE-001",
            "MON-001",
            "ALARM-001",
            "OP-001",
        }


# --------------------------------------------------- a DER that misbehaves


def _comm_lost(kind: Kind, index: int) -> Callable[[Binding, der.ReferenceDer], None]:
    def change(binding: Binding, _reference: der.ReferenceDer) -> None:
        reader = binding.readers[(kind, index)]

        def lost() -> bindings.Reading:
            value = reader()
            if isinstance(value, bindings.Reading):
                value = value.value
            return bindings.Reading(value, bindings.Quality.COMM_LOST)

        binding.readers[(kind, index)] = lost

    return change


def _stuck(
    kind: Kind, index: int, value: float | bool
) -> Callable[[Binding, der.ReferenceDer], None]:
    def change(binding: Binding, _reference: der.ReferenceDer) -> None:
        if kind.is_output:
            binding.outputs[(kind, index)] = dataclasses.replace(
                binding.outputs[(kind, index)], status=lambda: value
            )
        else:
            binding.readers[(kind, index)] = lambda: value

    return change


class TestEachCheckCanFail:
    """One fault at a time, each reported by the check that looks for it."""

    def test_meter_point_that_is_not_online_fails_monitoring(self):
        points = _synthetic()
        result = _one(_faulty(points, _comm_lost(Kind.AI, 540)), points, "MON-001")
        assert result.verdict is FAILED
        assert result.detail.startswith("AI540 (Synthetic AI540) is reported with flags 0x")

    def test_meter_point_outside_its_range_fails_monitoring(self):
        tables = _synthetic()
        meter = (Kind.AI, 540)
        limited = dataclasses.replace(tables.points[meter], minimum=0, maximum=10)
        points = dataclasses.replace(tables, points={**tables.points, meter: limited})
        # The device does not know the limit, so it reports the value as good.
        result = _one(_faulty(tables, _stuck(Kind.AI, 540, 11.0)), points, "MON-001")
        assert result.verdict is FAILED
        assert result.detail == (
            "AI540 (Synthetic AI540) reads 11, outside the range the tables give"
        )

    def test_inputs_reported_online_while_their_function_is_disabled_fail_it(self):
        points = _synthetic()
        simulation = der.build(points, disabled_offline=False)
        result = _one(simulation, points, "APL-001", settle=1.0)
        assert result.verdict is FAILED
        assert result.detail.endswith("is reported with flags 0x01, and not as offline")

    def test_alarm_that_is_not_online_fails_alarm_reporting(self):
        points = _synthetic()
        result = _one(_faulty(points, _comm_lost(Kind.BI, 3)), points, "ALARM-001")
        assert result.verdict is FAILED and result.detail.startswith("BI3 ")

    def test_raised_alarm_is_noted_and_does_not_fail(self):
        points = _synthetic()
        result = _one(_faulty(points, _stuck(Kind.BI, 3, True)), points, "ALARM-001")
        assert result.verdict is PASSED
        assert "raised when read: BI3" in result.notes

    def test_started_and_stopped_at_once_fails_operating_states(self):
        points = _synthetic()
        result = _one(_faulty(points, _stuck(Kind.BI, 15, True)), points, "OP-001")
        assert result.verdict is FAILED
        assert result.detail == "BI14 and BI15 report started and stopped at once"

    def test_two_exclusive_states_at_once_fails_operating_states(self):
        points = _synthetic()
        result = _one(_faulty(points, _stuck(Kind.BI, 22, True)), points, "OP-001")
        assert result.verdict is FAILED
        assert result.detail.startswith("one of BI18 to BI22 is to be set, and BI")

    def test_switch_status_that_does_not_follow_fails_connect(self):
        points = _synthetic()
        result = _one(
            _faulty(points, _stuck(Kind.BO, der.BO_CONNECT, True)), points, "CONN-001", settle=1.0
        )
        assert result.verdict is FAILED
        assert "the connect switch did not follow its command" in result.detail

    def test_stop_that_never_completes_fails_after_the_settling_time(self, monkeypatch):
        monkeypatch.setattr(der, "_TRANSITION_SECONDS", 1e9)
        points = _synthetic()
        simulation = der.build(points)
        waited: list[float] = []

        def advance(seconds: float) -> None:
            waited.append(seconds)
            simulation.advance(seconds)

        loopback = Loopback(simulation.outstation.session(need_time=False))
        report = evaluate_loopback(
            loopback,
            points,
            checks=select(["SERV-001"]),
            commanding=True,
            settle=2.0,
            advance=advance,
        )
        (result,) = report.results
        assert result.verdict is FAILED
        assert result.detail.startswith("the stop did not complete: BI15 ")
        assert "the stop was seen under way" in result.notes
        # Read every half second for the settling time, then once more while
        # putting the DER back as it was found.
        assert waited[:4] == [0.5] * 4 and sum(waited[:4]) == 2.0

    def test_start_accepted_without_permission_fails(self, monkeypatch):
        def start(self: der.ReferenceDer, value: float) -> None:
            if value and (not self.started or self.stopping):
                self._transition = (True, der._TRANSITION_SECONDS)

        monkeypatch.setattr(der.ReferenceDer, "_start", start)
        points = _synthetic()
        result = _one(der.build(points), points, "SERV-001.2")
        assert result.verdict is FAILED
        assert result.detail == "a start without permission was accepted"

    def test_stop_accepted_without_permission_fails(self, monkeypatch):
        def stop(self: der.ReferenceDer, value: float) -> None:
            if value and (self.started or self.starting):
                self._transition = (False, der._TRANSITION_SECONDS)

        monkeypatch.setattr(der.ReferenceDer, "_stop", stop)
        points = _synthetic()
        simulation = der.build(points)
        result = _one(simulation, points, "SERV-001.3")
        assert result.verdict is FAILED
        assert result.detail == "a stop without permission was accepted"
        assert simulation.der.started, "the DER is started again when the check ends"
        assert simulation.der.settings[(Kind.BO, der.BO_PERMIT_STOP)]

    def test_refusal_with_another_status_is_noted_and_does_not_fail(self, monkeypatch):
        def start(self: der.ReferenceDer, value: float) -> CommandStatus | None:
            return CommandStatus.LOCAL if value else None

        monkeypatch.setattr(der.ReferenceDer, "_start", start)
        points = _synthetic()
        simulation = der.build(points)
        simulation.der.started = False
        result = _one(simulation, points, "SERV-001.2")
        assert result.verdict is PASSED
        assert (
            "a start without permission was refused with LOCAL, where BLOCKED is usual"
            in result.notes
        )

    def test_indicator_that_never_sets_fails_curve_reference(self, monkeypatch):
        monkeypatch.setattr(curves.CurveStore, "referenced", lambda self, number: False)
        points = _synthetic()
        result = _one(der.build(points), points, "CURVE-001")
        assert result.verdict is FAILED
        assert result.detail == (
            f"curve 1 is not reported as referenced, and AO{der.AO_VOLT_WATT_CURVE} names it"
        )

    def test_curve_beyond_the_stated_count_that_is_accepted_fails(self):
        points = _synthetic()
        result = _one(der.build(points), points, "CURVE-001.2", curves=der.CURVE_COUNT - 4)
        assert result.verdict is FAILED
        assert result.detail == f"the selection of curve {der.CURVE_COUNT - 3} was accepted"

    def test_count_of_curves_is_found_when_not_stated(self):
        points = _synthetic()
        result = _one(der.build(points), points, "CURVE-001.2")
        assert result.verdict is PASSED
        assert result.notes == (
            f"the outstation stores {der.CURVE_COUNT} curves, found by selecting each",
        )

    @pytest.mark.parametrize(
        "check, says",
        [
            ("CURVE-002", "a write to a point of the locked curve 1 was accepted"),
            (
                "CURVE-002.2",
                "a write to a point of curve 2, which the function now names was accepted",
            ),
        ],
    )
    def test_curve_that_is_not_locked_fails(self, monkeypatch, check, says):
        monkeypatch.setattr(curves.CurveStore, "locked", lambda self, number: False)
        points = _synthetic()
        simulation = der.build(points)
        result = _one(simulation, points, check)
        assert result.verdict is FAILED and result.detail == says
        assert not simulation.der.settings[(Kind.BO, der.BO_ENABLE_VOLT_WATT)]

    def _following_any(self, monkeypatch, *types: int) -> PointMap:
        """Have every curve function follow the given curve types as well as its own."""
        monkeypatch.setattr(
            der,
            "FUNCTIONS",
            tuple(
                f
                if f.curve is None
                else dataclasses.replace(f, curve_types=(*f.curve_types, *types))
                for f in der.FUNCTIONS
            ),
        )
        return _synthetic()

    def test_function_pointed_at_a_curve_of_another_type_fails(self, monkeypatch):
        points = self._following_any(monkeypatch, der.CURVE_VOLT_VAR, der.CURVE_VOLT_WATT)
        result = _one(der.build(points), points, "CURVE-003")
        assert result.verdict is FAILED
        assert result.detail == (
            f"pointing AO{der.AO_VOLT_VAR_CURVE} at a curve of another type was accepted"
        )

    def test_function_pointed_at_a_curve_with_no_type_fails(self, monkeypatch):
        points = self._following_any(monkeypatch, 0)
        result = _one(der.build(points), points, "CURVE-003.2")
        assert result.verdict is FAILED
        assert result.detail == (
            f"pointing AO{der.AO_VOLT_WATT_CURVE} at curve {der.CURVE_COUNT}, "
            "which has no type was accepted"
        )

    def test_setting_that_does_not_read_back_fails_its_function(self):
        points = _synthetic()
        simulation = _faulty(points, _stuck(Kind.AO, der.AO_POWER_LIMIT_CHARGING, 3.0))
        result = _one(simulation, points, "APL-001", settle=1.0)
        assert result.verdict is FAILED
        assert result.title == "active power limit: supported"
        assert f"and AO{der.AO_POWER_LIMIT_CHARGING} was set to" in result.detail
        assert not simulation.der.settings[(Kind.BO, der.BO_ENABLE_POWER_LIMIT)]

    def test_setting_wrong_only_while_enabled_fails_and_the_function_is_disabled_again(self):
        points = _synthetic()
        setting = (Kind.AO, der.AO_POWER_LIMIT_CHARGING)
        enable = (Kind.BO, der.BO_ENABLE_POWER_LIMIT)

        def change(binding: Binding, reference: der.ReferenceDer) -> None:
            binding.outputs[setting] = dataclasses.replace(
                binding.outputs[setting],
                status=lambda: 3.0 if reference.settings[enable] else reference.settings[setting],
            )

        simulation = _faulty(points, change)
        result = _one(simulation, points, "APL-001", settle=1.0)
        assert result.verdict is FAILED
        assert f"and AO{der.AO_POWER_LIMIT_CHARGING} was set to" in result.detail
        assert not simulation.der.settings[enable], "the check disabled what it enabled"

    def test_write_refused_by_a_der_that_is_locked_out_fails(self):
        points = _synthetic()
        simulation = der.build(points)
        simulation.der.settings[(Kind.BO, der.BO_LOCKOUT)] = True
        result = _one(simulation, points, "CONN-001")
        assert result.verdict is FAILED
        assert result.detail.endswith("was refused with status BLOCKED")
        assert result.detail.startswith("a write of ")

    def test_output_with_no_served_readback_is_noted_and_not_read(self):
        tables = _synthetic()
        setting = der.AO_POWER_LIMIT_CHARGING
        mirror = tables.points[(Kind.AO, setting)].associated
        # The device serves the setting and not the input that reads it back.
        unpaired = dataclasses.replace(tables.points[(Kind.AO, setting)], associated=None)
        device = dataclasses.replace(
            tables,
            points={
                address: unpaired if address == (Kind.AO, setting) else point
                for address, point in tables.points.items()
                if address != mirror
            },
        )
        result = _one(der.build(device), tables, "APL-001")
        assert result.verdict is PASSED, result.detail
        assert f"no input reads AO{setting} back, so its value was not verified" in result.notes

    def test_function_said_to_be_unsupported_that_can_be_enabled_fails_and_is_disabled(self):
        points = _synthetic()
        supports = SUPPORTS + der.BO_ENABLE_POWER_LIMIT
        simulation = _faulty(points, _stuck(Kind.BI, supports, False))
        result = _one(simulation, points, "APL-001")
        assert result.verdict is FAILED
        assert result.title == "active power limit: not supported"
        assert result.detail == "the enabling of active power limit was accepted"
        assert not simulation.der.settings[(Kind.BO, der.BO_ENABLE_POWER_LIMIT)]

    def test_function_said_to_be_unsupported_that_serves_a_point_fails(self):
        points = _synthetic()

        def change(binding: Binding, _reference: der.ReferenceDer) -> None:
            binding.read(Kind.AI, SUPPORTS + 12, lambda: 1.0)

        result = _one(_faulty(points, change), points, "VRT-001")
        assert result.verdict is FAILED
        assert result.detail == (
            "unimplemented 12 is reported as not supported, and the outstation serves "
            f"AI{SUPPORTS + 12}"
        )

    def test_function_the_tables_do_not_have_is_not_applicable(self):
        tables = paired_reference_der()
        for kind in ("BI", "BO"):
            tables["points"][kind] = [
                row for row in tables["points"][kind] if "unimplemented 12" not in row["name"]
            ]
        points = load.resolve(tables, Composition())
        result = _one(der.build(points), points, "VRT-001")
        assert result.verdict is NOT_APPLICABLE_
        assert result.detail == "the tables have no function enabled by BO12"

    def test_outstation_with_no_curve_function_makes_the_curve_checks_not_applicable(
        self, monkeypatch
    ):
        monkeypatch.setattr("py1815.master.checks.SAMPLE_CURVES", {})
        tables = _synthetic()
        # The tables name a setting that holds a curve's number as one.
        setting = (Kind.AO, der.AO_VOLT_VAR_CURVE)
        renamed = dataclasses.replace(tables.points[setting], name="Volt-Var Curve Index")
        points = dataclasses.replace(tables, points={**tables.points, setting: renamed})
        report = _in_process(der.build(points), points, checks=select(["CURVE-001", "VV-001"]))
        curve, volt_var = report.results
        assert curve.verdict is NOT_APPLICABLE_
        assert curve.detail == (
            "the outstation serves no setting that names a curve of a type with a sample"
        )
        assert volt_var.verdict is PASSED
        assert volt_var.notes == (
            f"AO{der.AO_VOLT_VAR_CURVE} names a curve of a type with no sample; not written",
        )


# ---------------------------------------------------------- the device profile


class TestTheDeviceProfile:
    def _document(self, simulation: der.Simulation) -> str:
        outstation = simulation.outstation
        return device_profile.render(device_profile.build(outstation, outstation.session()))

    def test_the_ders_own_document_passes(self):
        points = _synthetic()
        simulation = der.build(points)
        result = _one(simulation, points, "PROFILE-001", device_profile=self._document(simulation))
        assert result.verdict is PASSED
        assert len(result.notes) == 1 and result.notes[0].endswith("declared points are served")

    def _with_another_input(self, points: PointMap) -> der.Simulation:
        return _faulty(
            points, lambda binding, _der: binding.read(Kind.AI, SUPPORTS + 12, lambda: 1.0)
        )

    def test_a_point_served_and_not_declared_fails(self):
        points = _synthetic()
        document = self._document(der.build(points))
        result = _one(
            self._with_another_input(points), points, "PROFILE-001", device_profile=document
        )
        assert result.verdict is FAILED
        assert result.detail == f"served and not declared: AI{SUPPORTS + 12}"

    def test_a_point_declared_and_not_served_fails(self):
        points = _synthetic()
        document = self._document(self._with_another_input(points))
        result = _one(der.build(points), points, "PROFILE-001", device_profile=document)
        assert result.verdict is FAILED
        assert result.detail == f"declared and not served: AI{SUPPORTS + 12}"

    def test_a_point_in_class_0_that_is_declared_out_of_it_fails(self):
        tables = _synthetic()
        meter = (Kind.AI, 540)
        left_out = dataclasses.replace(tables.points[meter], event_class=None)
        declared = dataclasses.replace(tables, points={**tables.points, meter: left_out})
        document = self._document(der.build(declared))
        result = _one(der.build(tables), tables, "PROFILE-001", device_profile=document)
        assert result.verdict is FAILED
        assert result.detail == "class 0 is not as declared: AI540 (in class 0)"


# -------------------------------------------------------------------- the run


def _bench_run(checks: list[Check], **options: Any) -> tuple[Report, der.Simulation]:
    points = _synthetic()
    simulation = der.build(points)
    return _in_process(simulation, points, checks=checks, **options), simulation


class TestTheRun:
    def test_what_a_check_leaves_to_be_put_back_is_done_last_first_even_when_it_fails(self):
        done: list[str] = []

        def record(word: str) -> Callable[[], Plan[None]]:
            def plan() -> Plan[None]:
                done.append(word)
                yield from ()

            return plan

        def fails(bench: Bench) -> Plan[None]:
            bench.afterwards("first", record("first"))
            bench.afterwards("second", record("second"))
            raise Failed("it went wrong")
            yield  # pragma: no cover

        report, _ = _bench_run([Check("X", "fails", False, fails)])
        assert report.results[0].verdict is FAILED and report.results[0].detail == "it went wrong"
        assert done == ["second", "first"]

    def test_what_cannot_be_put_back_is_noted(self):
        def spoiled() -> Plan[None]:
            raise Failed("the outstation refused")
            yield  # pragma: no cover

        def check(bench: Bench) -> Plan[None]:
            bench.afterwards("the switch", spoiled)
            yield from ()

        report, _ = _bench_run([Check("X", "passes", False, check)])
        (result,) = report.results
        assert result.verdict is PASSED
        assert result.notes == ("the switch could not be put back: the outstation refused",)

    def test_what_one_check_notes_and_counts_is_not_carried_to_the_next(self):
        def first(bench: Bench) -> Plan[None]:
            bench.note("seen")
            bench.title = "renamed"
            yield from bench.obtain(bench.map.point(Kind.BI, 14))

        def second(bench: Bench) -> Plan[None]:
            yield from ()

        report, _ = _bench_run(
            [Check("A", "first", False, first), Check("B", "second", False, second)]
        )
        a, b = report.results
        assert (a.title, a.notes, a.requests) == ("renamed", ("seen",), 1)
        assert (b.title, b.notes, b.requests, b.frames) == ("second", (), 0, None)

    def test_a_check_that_does_not_apply_says_why(self):
        def check(bench: Bench) -> Plan[None]:
            raise NotApplicable("there is no such point")
            yield  # pragma: no cover

        report, _ = _bench_run([Check("X", "skips", False, check)])
        assert report.results[0].verdict is NOT_APPLICABLE_
        assert report.results[0].detail == "there is no such point"

    def test_a_point_the_outstation_does_not_report_fails_the_read_of_it(self):
        def check(bench: Bench) -> Plan[None]:
            yield from bench.obtain(Point(Kind.AI, 60_000, "Nobody's"))

        report, _ = _bench_run([Check("X", "reads", False, check)])
        assert report.results[0].detail == "AI60000 (Nobody's) could not be read"

    def test_waiting_reads_again_until_the_settling_time_and_keeps_the_last_failure(self):
        attempts = 0

        def check(bench: Bench) -> Plan[None]:
            def attempt() -> Plan[None]:
                nonlocal attempts
                attempts += 1
                raise Failed(f"not yet, on attempt {attempts}")
                yield  # pragma: no cover

            yield from bench.eventually(attempt)

        report, _ = _bench_run([Check("X", "waits", False, check)], settle=1.2)
        # At 0, 0.5, 1.0 and 1.2 seconds.
        assert attempts == 4
        assert report.results[0].detail == "not yet, on attempt 4"

    def test_a_request_that_is_not_answered_is_not_made_again(self):
        attempts = 0

        def check(bench: Bench) -> Plan[None]:
            def attempt() -> Plan[None]:
                nonlocal attempts
                attempts += 1
                raise benches.Unanswered("the outstation did not answer")
                yield  # pragma: no cover

            yield from bench.eventually(attempt)

        report, _ = _bench_run([Check("X", "waits", False, check)])
        assert attempts == 1 and report.results[0].verdict is FAILED

    def test_points_the_outstation_serves_are_found_before_the_first_check(self):
        seen: list[frozenset[tuple[Kind, int]]] = []

        def check(bench: Bench) -> Plan[None]:
            seen.append(bench.served)
            yield from ()

        _, simulation = _bench_run([Check("X", "looks", False, check)])
        outstation = simulation.outstation
        served = {p.address for kind in Kind for p in outstation.served(kind)}
        assert seen[0] == served
        assert (Kind.AO, der.AO_POWER_LIMIT_CHARGING) in served, "outputs are not in class 0"

    def test_valid_values_stay_inside_the_range_and_differ(self):
        for low, high in ((0, 100), (-50, 50), (0, 1), (None, None), (None, -5), (7, 7)):
            point = Point(Kind.AO, 1, "setting", minimum=low, maximum=high)
            first, second = valid_values(point)
            assert point.in_range(first) and point.in_range(second)
            assert (first != second) or low == high

    def test_sample_curves_come_in_pairs_that_differ_and_fit_the_block(self):
        for first, second in SAMPLE_CURVES.values():
            assert first.type == second.type and first.points != second.points
            assert max(len(first.points), len(second.points)) <= curves.MAX_POINTS


class TestSelecting:
    def test_none_and_nothing_are_the_whole_catalog(self):
        assert select(None) == CATALOG and select([]) == CATALOG

    def test_a_check_is_named_by_its_identifier_in_any_case_or_by_its_set(self):
        assert [check.id for check in select(["op-001", "MON-001"])] == ["MON-001", "OP-001"]
        assert [check.id for check in select(["device-profile"])] == ["PROFILE-001"]
        assert len(select(["der"])) == len(CATALOG) - 1

    def test_an_unknown_name_is_refused(self):
        with pytest.raises(ValueError, match="'mon-1' is not a check"):
            select(["MON-1"])

    def test_identifiers_are_not_repeated(self):
        identifiers = [check.id for check in CATALOG]
        assert len(identifiers) == len(set(identifiers))


# ----------------------------------------------------------------- the report


class TestTheReport:
    REPORT = Report(
        "lab at 192.0.2.10:20000, outstation 1024",
        0.0,
        False,
        "synthetic",
        (
            Result(
                "MON-001", "Monitoring", PASSED, notes=("24 points",), requests=24, frames=(1, 39)
            ),
            Result("SERV-001", "Service", FAILED, "BI15 did not stop", requests=9, frames=(40, 57)),
            Result("VV-001", "Volt-var", NOT_RUN, "it writes"),
        ),
    )

    def test_lines_give_a_verdict_for_each_check_and_the_totals(self):
        assert self.REPORT.lines() == [
            "lab at 192.0.2.10:20000, outstation 1024, 1970-01-01T00:00:00+00:00, read only",
            "profile tables: synthetic",
            "",
            "MON-001   passed          Monitoring",
            "          note: 24 points",
            "SERV-001  FAILED          Service",
            "          BI15 did not stop",
            "          frames 40 to 57",
            "VV-001    not run         Volt-var",
            "          it writes",
            "",
            "3 checks: 1 passed, 1 failed, 1 not run",
        ]

    def test_json_carries_the_same_results(self):
        described = json.loads(self.REPORT.render())
        assert described["summary"] == {
            "passed": 1,
            "failed": 1,
            "not_applicable": 0,
            "not_run": 1,
        }
        assert described["allow_control"] is False and described["tables"] == "synthetic"
        assert described["started"] == "1970-01-01T00:00:00+00:00"
        assert described["results"][1] == {
            "id": "SERV-001",
            "title": "Service",
            "verdict": "failed",
            "detail": "BI15 did not stop",
            "notes": [],
            "requests": 9,
            "seconds": 0.0,
            "frames": [40, 57],
        }

    def test_a_report_has_failed_when_one_check_has(self):
        assert self.REPORT.failed
        assert not dataclasses.replace(self.REPORT, results=self.REPORT.results[:1]).failed


# ---------------------------------------------------------------- the command


class _Served:
    """A simulated DER on a thread of its own, moving in real time, for a command to evaluate."""

    def __init__(self) -> None:
        self.simulation = der.build(_synthetic())
        self._loop = asyncio.new_event_loop()
        self._server = OutstationServer(
            self.simulation.outstation.session(need_time=False), bind="127.0.0.1:0"
        )
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._ticking: asyncio.Future[None] | None = None

    async def _tick(self) -> None:
        while True:
            await asyncio.sleep(0.1)
            self.simulation.advance(0.1)

    def __enter__(self) -> int:
        self._thread.start()
        asyncio.run_coroutine_threadsafe(self._server.start(), self._loop).result(5)
        self._ticking = asyncio.run_coroutine_threadsafe(self._tick(), self._loop)  # type: ignore[assignment]
        return self._server.port

    def __exit__(self, *_exc: object) -> None:
        if self._ticking is not None:
            self._ticking.cancel()
        asyncio.run_coroutine_threadsafe(self._server.stop(), self._loop).result(5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)
        self._loop.close()


@pytest.fixture
def tables(tmp_path, monkeypatch):
    """The paired synthetic tables on disk, named by the environment as a user's would be."""
    path = tmp_path / load.TABLES_NAME
    path.write_text(json.dumps(paired_reference_der()), encoding="utf-8")
    monkeypatch.setenv(load.TABLES_VARIABLE, str(path))
    return path


def _evaluate(port: int, *arguments: str) -> int:
    return cli.main(["evaluate", "--outstation", f"lab=127.0.0.1:{port}", *arguments])


@pytest.mark.usefixtures("tables")
class TestTheCommand:
    def test_list_prints_the_catalog_and_connects_to_nothing(self, capsys):
        assert cli.main(["evaluate", "--list"]) == 0
        printed = capsys.readouterr().out.splitlines()
        assert printed == catalog_lines() and len(printed) == len(CATALOG)
        assert printed[1].split() == ["MON-001", "der", "reads", "Monitoring"]
        assert printed[4].split()[:3] == ["CONN-001", "der", "writes"]

    def test_without_allow_control_it_reads_and_exits_zero(self, capsys):
        with _Served() as port:
            assert _evaluate(port) == 0
        printed = capsys.readouterr().out.splitlines()
        assert printed[0].startswith(f"lab at 127.0.0.1:{port}, outstation 1024, ")
        assert printed[0].endswith(", read only")
        assert printed[-1] == f"{len(CATALOG)} checks: 3 passed, 1 not applicable, 31 not run"

    def test_only_a_run_allowed_to_write_clears_the_restart_indication(self, capsys):
        def restart_indicated(port: int) -> bool:
            assert cli.main(["poll", "--port", str(port), "--limit", "0"]) == 0
            printed = capsys.readouterr().out.splitlines()
            (line,) = (each for each in printed if "indications " in each)
            return bool(int(line.split("indications ")[1].split()[0], 16) & 0x80)

        with _Served() as port:
            assert _evaluate(port, "--check", "OP-001") == 0
            assert restart_indicated(port), "a read-only run writes nothing, its tasks included"
            assert _evaluate(port, "--check", "OP-001", "--allow-control") == 0
            assert not restart_indicated(port)

    def test_with_allow_control_a_check_that_writes_is_run(self, capsys):
        with _Served() as port:
            assert (
                _evaluate(port, "--allow-control", "--check", "APL-001", "--check", "SERV-001") == 0
            )
        printed = capsys.readouterr().out.splitlines()
        assert printed[0].endswith(", allowed to write")
        assert printed[3].split()[:2] == ["SERV-001", "passed"]
        assert printed[-1] == "2 checks: 2 passed"

    def test_a_failed_check_exits_one(self, capsys):
        with _Served() as port:
            status = _evaluate(port, "--allow-control", "--check", "CURVE-001.2", "--curves", "5")
        assert status == 1
        printed = capsys.readouterr().out
        assert "CURVE-001.2  FAILED" in printed
        assert "the selection of curve 6 was accepted" in printed
        assert "1 checks: 1 failed" in printed

    def test_the_report_and_the_capture_are_written(self, tmp_path, capsys):
        report, capture = tmp_path / "report.json", tmp_path / "run.pcap"
        with _Served() as port:
            status = _evaluate(
                port, "--check", "MON-001", "--report", str(report), "--capture", str(capture)
            )
        assert status == 0
        assert f"wrote {report}" in capsys.readouterr().out
        described = json.loads(report.read_text(encoding="utf-8"))
        assert described["outstation"] == f"lab at 127.0.0.1:{port}, outstation 1024"
        (result,) = described["results"]
        assert result["id"] == "MON-001" and result["verdict"] == "passed"
        packets = capture.read_bytes()
        assert packets[:4] == bytes.fromhex("d4c3b2a1"), "a pcap file"
        # The handshake, then a packet for each frame up to the check's last.
        assert len(packets) > 24 + 16 * result["frames"][1]

    def test_the_device_profile_given_is_compared(self, tmp_path, capsys):
        with _Served() as port:
            served = _Served()
            outstation = served.simulation.outstation
            document = tmp_path / "profile.xml"
            document.write_text(
                device_profile.render(device_profile.build(outstation, outstation.session())),
                encoding="utf-8",
            )
            status = _evaluate(port, "--check", "device-profile", "--device-profile", str(document))
        assert status == 0
        assert "PROFILE-001  passed" in capsys.readouterr().out

    def test_settings_come_from_the_configuration_file(self, tmp_path, capsys):
        with _Served() as port:
            config = tmp_path / "master.json"
            config.write_text(
                json.dumps(
                    {
                        "allow_control": True,
                        "evaluate": {"checks": ["CURVE-001.2"], "curves": 5},
                        "outstations": [
                            {"name": "spare", "host": "127.0.0.1", "port": 1},
                            {"name": "lab", "host": "127.0.0.1", "port": port},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            assert cli.main(["evaluate", "lab", "--config", str(config)]) == 1
            assert "the selection of curve 6 was accepted" in capsys.readouterr().out
            # A flag overrides the file.
            assert cli.main(["evaluate", "lab", "--config", str(config), "--curves", "10"]) == 0
            capsys.readouterr()
            assert cli.main(["evaluate", "--config", str(config)]) == 2
            assert "name the outstation to evaluate: spare, lab" in capsys.readouterr().err
            assert cli.main(["evaluate", "bench", "--config", str(config)]) == 2
            assert "no outstation is named 'bench'" in capsys.readouterr().err

    @pytest.mark.parametrize(
        "arguments, says",
        [
            ([], "no outstation to evaluate"),
            (["--outstation", "lab=127.0.0.1:1"], "cannot evaluate lab at 127.0.0.1:1"),
            (["--outstation", "lab=127.0.0.1:1", "--check", "MON-1"], "'mon-1' is not a check"),
            (
                ["--outstation", "lab=127.0.0.1:1", "--device-profile", "absent.xml"],
                "absent.xml",
            ),
        ],
    )
    def test_a_run_that_cannot_be_made_exits_two_and_says_why(self, arguments, says, capsys):
        assert cli.main(["evaluate", *arguments]) == 2
        assert says in capsys.readouterr().err

    def test_an_outstation_that_does_not_answer_exits_two(self, tmp_path, capsys):
        config = tmp_path / "master.json"
        with _Served() as port:
            config.write_text(
                json.dumps(
                    {
                        "defaults": {"manual": True, "response_timeout": 0.3},
                        "outstations": [
                            {
                                "name": "lab",
                                "host": "127.0.0.1",
                                "port": port,
                                "outstation_address": 9,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            status = cli.main(["evaluate", "--config", str(config)])
        assert status == 2
        assert capsys.readouterr().err.strip() == (
            f"lab at 127.0.0.1:{port}: the outstation did not answer a class 0 read"
        )


def test_without_the_tables_the_command_says_so_and_exits_two(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(load.TABLES_VARIABLE, str(tmp_path / "absent.json"))
    assert cli.main(["evaluate", "--outstation", "lab=127.0.0.1:1"]) == 2
    assert "py1815-der tables fetch" in capsys.readouterr().err


def test_a_profile_made_from_the_map_may_be_given_in_its_place():
    points = _synthetic()
    simulation = der.build(points)
    report = _in_process(simulation, DerProfile(points), checks=select(["OP-001"]))
    assert report.results[0].verdict is PASSED and report.edition == points.edition
