"""The DER profile's operations through the service, over sockets.

The master on a TCP connection to the simulated DER, asked through the JSON
service as a test rig or the console asks it. The plan's measure of done for
the profile is here: each function the simulated DER implements configured,
enabled and read back by name, and the last rows of a test rig's workload
played over the line socket.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
from typing import Any

import pytest
import pytest_asyncio
from profile_fixtures import MIRROR, paired_reference_der

from py1815.master import cli
from py1815.master.service import LineServer, Service
from py1815.profile import der, device_profile, load
from py1815.profile.model import Composition, Kind, PointMap
from py1815.server import OutstationServer


@pytest.fixture
def point_map() -> PointMap:
    """The paired tables, with the power limit's settings scaled as the profile scales them."""
    tables = load.resolve(paired_reference_der(), Composition())
    points = dict(tables.points)
    for index in (der.AO_POWER_LIMIT_CHARGING, der.AO_POWER_LIMIT_GENERATION):
        for kind, at, extra in (
            (Kind.AO, index, {"minimum": 0, "maximum": 1000}),
            (Kind.AI, MIRROR + index, {}),
        ):
            points[(kind, at)] = dataclasses.replace(points[(kind, at)], multiplier=0.1, **extra)
    return dataclasses.replace(tables, points=points)


@pytest_asyncio.fixture
async def outstation(point_map):
    """A simulated DER listening on this machine."""
    simulation = der.build(point_map)
    server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
    await server.start()
    try:
        yield simulation, server
    finally:
        await server.stop()


async def _service(allow_control: bool, point_map: PointMap, server: OutstationServer) -> Service:
    service = Service(allow_control=allow_control)
    service.set_profile("lab", point_map)
    added = await service.handle(
        {"op": "add", "params": {"name": "lab", "host": "127.0.0.1", "port": server.port}}
    )
    assert added["ok"], added
    assert (await service.handle({"op": "idle", "outstation": "lab"}))["ok"]
    return service


@pytest_asyncio.fixture
async def commanding(outstation, point_map):
    """A service started to command, with the DER added."""
    service = await _service(True, point_map, outstation[1])
    try:
        yield service
    finally:
        await service.close()


@pytest_asyncio.fixture
async def reading(outstation, point_map):
    """A service that only reads, with the DER added."""
    service = await _service(False, point_map, outstation[1])
    try:
        yield service
    finally:
        await service.close()


async def _ask(service: Service, op: str, **params: Any) -> dict[str, Any]:
    return await service.handle({"id": 1, "op": op, "outstation": "lab", "params": params})


async def _result(service: Service, op: str, **params: Any) -> dict[str, Any]:
    answer = await _ask(service, op, **params)
    assert answer["ok"], answer
    result: dict[str, Any] = answer["result"]
    return result


def _sent(service: Service) -> list[str]:
    """The summaries of the frames the master sent that carried a request."""
    lab = service.master["lab"]
    return [entry.summary for entry in lab.trace.since() if entry.direction == "tx"]


def _value_for(setting: dict[str, Any], position: int) -> float:
    """A value inside a setting's range, different for each setting."""
    low = setting["minimum"] if setting["minimum"] is not None else 0
    high = setting["maximum"] if setting["maximum"] is not None else 100
    return min(high, low + 10 + position)


class TestEachFunctionByName:
    """IEEE 1815.2 functions configured, enabled and read back by name, over a socket."""

    @pytest.mark.asyncio
    async def test_each_function_the_der_implements_is_configured_enabled_and_read_back(
        self, commanding, outstation
    ):
        simulation, _ = outstation
        listed = await _result(commanding, "der.functions")
        functions = {function["name"]: function for function in listed["functions"]}
        curve_number = 0
        for implemented in der.FUNCTIONS:
            function = functions[implemented.name]
            assert function["supported"] is True and function["enabled"] is False

            values: dict[str, Any] = {}
            for position, setting in enumerate(function["settings"]):
                if setting["index"] == implemented.curve:
                    continue
                values[setting["name"]] = _value_for(setting, position)
            written = await _result(commanding, "der.write", points=values, verify=True)
            assert written["accepted"] is True and written["verified"] is True, written

            if implemented.curve is not None:
                curve_number += 1
                curve = await _result(
                    commanding,
                    "der.write_curve",
                    number=curve_number,
                    type=implemented.curve_types[0],
                    x_units=der.X_PERCENT_VOLTAGE,
                    y_units=der.Y_PERCENT_MAX_WATTS
                    if implemented.curve_types[0] == der.CURVE_VOLT_WATT
                    else der.Y_PERCENT_MAX_VARS,
                    points=[[900, 1000], [1100, 0]],
                )
                assert curve["accepted"] is True and curve["matches"] is True, curve
                named = await _result(
                    commanding,
                    "der.write",
                    points={f"AO{implemented.curve}": curve_number},
                    verify=True,
                )
                assert named["verified"] is True, named
                values[f"Synthetic AO{implemented.curve}"] = curve_number

            enabled = await _result(commanding, "der.enable", function=implemented.name)
            assert enabled["accepted"] is True and enabled["enabled"] is True

            back = await _result(commanding, "der.read", group=implemented.name)
            readings = {reading["address"]: reading for reading in back["points"]}
            for setting in function["settings"]:
                mirror = readings[setting["mirror"]]
                asked = values[setting["name"]]
                assert mirror["value"] == pytest.approx(asked, abs=setting["multiplier"] or 1)
                # Enabled, its inputs are in effect and travel ONLINE (clause 6.1.1).
                assert mirror["quality"] == "good", mirror
            assert readings[function["status"]]["value"] is True

        listed = await _result(commanding, "der.functions")
        enabled = {f["name"] for f in listed["functions"] if f["enabled"]}
        assert enabled == {function.name for function in der.FUNCTIONS}
        assert simulation.der.settings[(Kind.BO, der.BO_ENABLE_VOLT_VAR)] is True

    @pytest.mark.asyncio
    async def test_a_setting_scaled_by_its_multiplier_reaches_the_der_in_engineering_units(
        self, commanding, outstation
    ):
        simulation, _ = outstation
        written = await _result(
            commanding, "der.write", points={"Synthetic AO87": 62.5}, verify=True
        )
        (point,) = written["points"]
        assert (point["requested"], point["sent"], point["sent_value"]) == (62.5, 625, 62.5)
        assert point["readback"]["raw"] == 625 and point["readback"]["value"] == 62.5
        assert simulation.outstation.value(Kind.AO, 87) == 62.5


class TestTheWorkloadOfATestRig:
    """The last rows of the test rig's workload, over the line socket, in their order."""

    @pytest.mark.asyncio
    async def test_settings_time_curve_points_enable_then_read_back_over_the_line_socket(
        self, outstation, point_map
    ):
        simulation, server = outstation
        service = Service(allow_control=True)
        service.set_profile("lab", point_map)
        lines = LineServer(service)
        await lines.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", lines.port)
        asked = 0

        async def ask(op: str, **params: Any) -> dict[str, Any]:
            nonlocal asked
            asked += 1
            message = {"id": asked, "op": op, "outstation": "lab", "params": params}
            writer.write(json.dumps(message).encode() + b"\n")
            await writer.drain()
            answer = json.loads(await reader.readline())
            assert answer["id"] == asked and answer["ok"], answer
            result: dict[str, Any] = answer["result"]
            return result

        try:
            await ask("add", name="lab", host="127.0.0.1", port=server.port)
            await ask("idle")
            settings = await ask(
                "der.write", points={"AO212": 1, "AO213": 0, "AO214": 5}, verify=True
            )
            timing = await ask("der.write", points={"AO215": 60}, verify=True)
            curve = await ask(
                "der.write_curve",
                number=4,
                type=der.CURVE_VOLT_VAR,
                x_units=der.X_PERCENT_VOLTAGE,
                y_units=der.Y_PERCENT_MAX_VARS,
                points=[[920, 300], [980, 0], [1020, 0], [1080, -300]],
            )
            named = await ask("der.write", points={"AO217": 4}, verify=True)
            enabled = await ask("der.enable", function="volt-var")
            back = await ask("der.read", names=[f"AI{MIRROR + index}" for index in range(212, 218)])
        finally:
            writer.close()
            await lines.stop()
            await service.close()

        assert settings["verified"] and timing["verified"] and named["verified"]
        assert [step["exchanges"][0]["function"] for step in curve["steps"]] == [
            "DIRECT_OPERATE"
        ] * 3
        assert curve["accepted"] and curve["matches"] and curve["stopped_at"] is None
        assert curve["curve"]["points"] == [[920, 300], [980, 0], [1020, 0], [1080, -300]]
        assert enabled["enabled"] is True
        assert [reading["value"] for reading in back["points"]] == [1, 0, 5, 60, 0, 4]
        assert all(reading["quality"] == "good" for reading in back["points"])
        assert simulation.der.volt_var_target() is not None


class TestOneOperationAtATime:
    @pytest.mark.asyncio
    async def test_two_curves_written_at_once_are_each_written_whole(self, commanding, outstation):
        """The second waits for the first, so neither selector moves under the other's points."""
        simulation, _ = outstation

        def curve(number: int, y: int) -> dict[str, Any]:
            return {
                "number": number,
                "type": der.CURVE_VOLT_VAR,
                "x_units": der.X_PERCENT_VOLTAGE,
                "y_units": der.Y_PERCENT_MAX_VARS,
                "points": [[950, y], [1050, -y]],
            }

        first, second = await asyncio.gather(
            _result(commanding, "der.write_curve", **curve(5, 100)),
            _result(commanding, "der.write_curve", **curve(6, 200)),
        )
        assert first["matches"] and second["matches"]
        assert simulation.der.curves.curves[5].points == [(950.0, 100.0), (1050.0, -100.0)]
        assert simulation.der.curves.curves[6].points == [(950.0, 200.0), (1050.0, -200.0)]


class TestCommandingIsOffUntilTurnedOn:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("op", "params"),
        [
            ("der.write", {"points": {"AO87": 50}}),
            ("der.enable", {"function": "volt-var"}),
            ("der.disable", {"function": "volt-var"}),
            ("der.curve", {"number": 2}),
            (
                "der.write_curve",
                {"number": 1, "type": 2, "x_units": 129, "y_units": 2, "points": []},
            ),
        ],
    )
    async def test_an_operation_that_writes_is_refused_and_nothing_is_sent(
        self, reading, outstation, op, params
    ):
        simulation, _ = outstation
        before = _sent(reading)
        answer = await _ask(reading, op, **params)
        assert answer["error"]["kind"] == "not_allowed", answer
        assert "--allow-control" in answer["error"]["message"]
        assert _sent(reading) == before
        assert simulation.outstation.value(Kind.AO, 87) == 100.0
        assert simulation.der.curves.selected == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("op", "params"),
        [
            ("der.read", {"group": "volt-var"}),
            ("der.functions", {}),
            ("der.curve", {}),
        ],
    )
    async def test_an_operation_that_only_reads_is_carried_out(self, reading, op, params):
        assert (await _ask(reading, op, **params))["ok"]
        assert not any("OPERATE" in summary for summary in _sent(reading))

    @pytest.mark.asyncio
    async def test_what_is_wrong_with_a_write_is_said_before_that_it_is_not_allowed(self, reading):
        answer = await _ask(reading, "der.write", points={"AO87": 500})
        assert answer["error"]["kind"] == "request"
        assert "outside 0 to 100" in answer["error"]["message"]


class TestWhatGoesWrongIsAnAnswer:
    @pytest.mark.asyncio
    async def test_an_outstation_with_no_profile_is_refused_and_told_how(self, outstation):
        service = Service(allow_control=True)
        try:
            await service.handle(
                {
                    "op": "add",
                    "params": {"name": "lab", "host": "127.0.0.1", "port": outstation[1].port},
                }
            )
            answer = await _ask(service, "der.read", names=["AO87"])
            assert answer["error"]["kind"] == "request"
            assert "--profile" in answer["error"]["message"]
        finally:
            await service.close()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("op", "params", "says"),
        [
            ("der.read", {}, "names points, or a group"),
            ("der.read", {"names": "AO87"}, "a list"),
            ("der.read", {"names": ["AO99999"]}, "no AO99999"),
            ("der.write", {}, "names outputs"),
            ("der.write", {"points": {"AO87": 1}, "mode": "twice"}, "not a way to operate"),
            ("der.enable", {}, "names a function"),
            ("der.enable", {"function": "flight"}, "no function"),
            ("der.write_curve", {"number": 1}, "with type"),
            (
                "der.write_curve",
                {"number": 1, "type": 2, "x_units": 1, "y_units": 1, "points": "x"},
                "a list",
            ),
            ("der.compare", {}, "no Device Profile document"),
            ("der.compare", {"document": "<x/>"}, "no dataPointsList"),
        ],
    )
    async def test_a_message_that_cannot_be_acted_on(self, commanding, op, params, says):
        answer = await _ask(commanding, op, **params)
        assert answer["error"]["kind"] == "request", answer
        assert says in answer["error"]["message"]

    @pytest.mark.asyncio
    async def test_a_write_that_is_not_answered_is_sent_once_and_reported_as_not_known(
        self, outstation, point_map
    ):
        service = Service(allow_control=True)
        service.set_profile("deaf", point_map)
        try:
            await service.handle(
                {
                    "op": "add",
                    "params": {
                        "name": "deaf",
                        "host": "127.0.0.1",
                        "port": outstation[1].port,
                        "outstation_address": 77,
                        "response_timeout": 0.2,
                        "manual": True,
                    },
                }
            )
            answer = await service.handle(
                {
                    "op": "der.write",
                    "outstation": "deaf",
                    "params": {"points": {"AO87": 50}, "verify": True},
                }
            )
            result = answer["result"]
            assert result["accepted"] is None and result["verified"] is None
            sent = [entry.summary for entry in service.master["deaf"].trace.since()]
            assert sum("DIRECT_OPERATE" in summary for summary in sent) == 1
            assert result["points"][0]["readback"]["quality"] == "not_reported"
        finally:
            await service.close()


class TestComparison:
    @pytest.mark.asyncio
    async def test_a_device_profile_given_to_the_service_is_compared_with_what_is_served(
        self, reading, outstation
    ):
        simulation, _ = outstation
        session = simulation.outstation.session()
        document = device_profile.render(device_profile.build(simulation.outstation, session))
        reading.set_device_profile("lab", document)
        status = await reading.handle({"op": "status"})
        assert status["result"]["outstations"][0]["device_profile"] is True

        compared = await _result(reading, "der.compare")

        assert compared["declared"] == compared["served"] > 0
        assert compared["absent"] == [] and compared["undeclared"] == []
        assert compared["class_0"] == []
        assert [exchange["outcome"] for exchange in compared["exchanges"]] == ["complete"] * 2

    @pytest.mark.asyncio
    async def test_a_document_sent_with_the_request_is_compared_and_needs_no_profile(
        self, outstation
    ):
        simulation, server = outstation
        service = Service()
        try:
            await service.handle(
                {"op": "add", "params": {"name": "lab", "host": "127.0.0.1", "port": server.port}}
            )
            outstation_ = simulation.outstation
            document = device_profile.render(
                device_profile.build(outstation_, outstation_.session())
            ).replace("<index>0</index>", "<index>4321</index>", 1)
            compared = await _result(service, "der.compare", document=document)
            assert [(each["type"], each["index"]) for each in compared["absent"]] == [("bi", 4321)]
            assert compared["undeclared"] == [{"type": "bi", "index": 0, "name": None}]
        finally:
            await service.close()

    def test_a_document_that_cannot_be_read_is_not_kept(self):
        service = Service()
        with pytest.raises(ValueError, match="not XML"):
            service.set_device_profile("lab", "<broken")


class TestTheCommandLine:
    def test_the_device_profile_flag_sets_the_default_for_every_outstation(self):
        args = cli._parser().parse_args(["serve", "--device-profile", "device.xml"])
        assert cli.configuration(args).defaults.device_profile == "device.xml"

    @pytest.mark.asyncio
    async def test_the_document_named_is_read_when_the_outstation_is_added(
        self, outstation, tmp_path
    ):
        simulation, server = outstation
        session = simulation.outstation.session()
        path = tmp_path / "device.xml"
        path.write_text(
            device_profile.render(device_profile.build(simulation.outstation, session)),
            encoding="utf-8",
        )
        service = Service()
        try:
            args = cli._parser().parse_args(
                [
                    "serve",
                    "--outstation",
                    f"lab=127.0.0.1:{server.port}",
                    "--device-profile",
                    str(path),
                ]
            )
            assert await cli._add_outstations(service, cli.configuration(args))
            compared = await _result(service, "der.compare")
            assert compared["absent"] == []
        finally:
            await service.close()

    @pytest.mark.asyncio
    async def test_a_document_that_cannot_be_read_stops_the_start(self, tmp_path, capsys):
        service = Service()
        try:
            args = cli._parser().parse_args(
                [
                    "serve",
                    "--outstation",
                    "lab=127.0.0.1:1",
                    "--device-profile",
                    str(tmp_path / "none.xml"),
                ]
            )
            assert not await cli._add_outstations(service, cli.configuration(args))
            assert "none.xml" in capsys.readouterr().err
        finally:
            await service.close()

    @pytest.mark.asyncio
    async def test_the_demonstration_compares_the_der_with_the_document_it_publishes(
        self, point_map
    ):
        service = Service()
        demo = cli.Demo(service, point_map, tick=60.0)
        await demo.start()
        try:
            await service.handle({"op": "idle", "outstation": cli.DEMO_NAME})
            answer = await service.handle({"op": "der.compare", "outstation": cli.DEMO_NAME})
            assert answer["ok"] and answer["result"]["absent"] == []
        finally:
            await demo.stop()
            await service.close()
