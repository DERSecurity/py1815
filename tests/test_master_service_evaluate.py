"""The service's ``checks`` and ``evaluate`` operations."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest
import pytest_asyncio
from profile_fixtures import paired_reference_der

from py1815.master.checks import CATALOG
from py1815.master.service import Service
from py1815.profile import der, load
from py1815.profile.model import Composition
from py1815.server import OutstationServer


async def _ask(service: Service, op: str, **params: Any) -> dict[str, Any]:
    message: dict[str, Any] = {"op": op, "params": params}
    return await service.handle(message)


@pytest_asyncio.fixture
async def served():
    """A simulated DER on a socket, with the point map it serves."""
    points = load.resolve(paired_reference_der(), Composition())
    simulation = der.build(points)
    server = OutstationServer(simulation.outstation.session(need_time=False), bind="127.0.0.1:0")
    await server.start()
    try:
        yield points, server, simulation
    finally:
        await server.stop()


async def _service(served: Any, *, allow_control: bool = False) -> Service:
    """Return a service with the simulated DER added as ``lab`` and its profile loaded."""
    points, server, _ = served
    service = Service(allow_control=allow_control)
    added = await _ask(
        service,
        "add",
        name="lab",
        host="127.0.0.1",
        port=server.port,
        response_timeout=0.3,
        manual=True,
        confirm=True,
    )
    assert added["ok"], added
    service.set_profile("lab", points)
    return service


def _verdicts(answer: dict[str, Any]) -> dict[str, str]:
    assert answer["ok"], answer
    return {result["id"]: result["verdict"] for result in answer["result"]["results"]}


@pytest.mark.asyncio
class TestTheCatalog:
    async def test_checks_lists_every_check_with_what_it_does(self):
        service = Service()
        answer = await _ask(service, "checks")
        listed = answer["result"]["checks"]
        assert [check["id"] for check in listed] == [check.id for check in CATALOG]
        by_id = {check["id"]: check for check in listed}
        assert by_id["MON-001"] == {
            "id": "MON-001",
            "title": "Monitoring",
            "set": "der",
            "writes": False,
            "deviates": False,
        }
        assert by_id["CONN-001"]["writes"] and not by_id["CONN-001"]["deviates"]
        assert by_id["LINK-001"]["deviates"] and by_id["LINK-001"]["set"] == "deviation"


@pytest.mark.asyncio
class TestEvaluating:
    async def test_a_check_is_run_and_reported(self, served):
        service = await _service(served)
        try:
            answer = await _ask(service, "evaluate", outstation="lab", checks=["MON-001"])
            assert _verdicts(answer) == {"MON-001": "passed"}
            report = answer["result"]
            assert report["outstation"] == "lab" and report["tool"] == "py1815-master evaluate"
            assert report["allow_control"] is False and report["allow_deviations"] is False
            assert report["summary"]["passed"] == 1
            assert report["results"][0]["requests"] > 0
        finally:
            await service.close()

    async def test_each_result_is_published_as_its_check_ends(self, served):
        service = await _service(served)
        try:
            queue = service.subscribe()
            answer = await _ask(service, "evaluate", outstation="lab", checks=["MON-001", "OP-001"])
            published = []
            while not queue.empty():
                event = queue.get_nowait()
                if event["event"] == "check":
                    published.append(event)
            assert [event["outstation"] for event in published] == ["lab", "lab"]
            assert [event["result"] for event in published] == answer["result"]["results"]
        finally:
            await service.close()

    async def test_a_check_that_writes_is_not_run_by_a_service_not_started_to_command(self, served):
        service = await _service(served)
        try:
            answer = await _ask(service, "evaluate", outstation="lab", checks=["CONN-001"])
            (result,) = answer["result"]["results"]
            assert result["verdict"] == "not_run" and result["requests"] == 0
            assert "writes to the outstation" in result["detail"]
        finally:
            await service.close()

    async def test_a_service_started_to_command_runs_it_and_logs_the_command(self, served, caplog):
        service = await _service(served, allow_control=True)
        try:
            with caplog.at_level(logging.INFO, logger="py1815.master.service"):
                answer = await _ask(
                    service, "evaluate", outstation="lab", checks=["CONN-001"], settle=1
                )
            assert _verdicts(answer) == {"CONN-001": "passed"}
            assert answer["result"]["allow_control"] is True
            logged = [record.getMessage() for record in caplog.records]
            assert any("command evaluate to lab" in line for line in logged), logged
        finally:
            await service.close()

    async def test_a_reading_evaluation_is_not_in_the_command_log(self, served, caplog):
        service = await _service(served, allow_control=True)
        try:
            with caplog.at_level(logging.INFO, logger="py1815.master.service"):
                await _ask(service, "evaluate", outstation="lab", checks=["MON-001"])
            logged = [record.getMessage() for record in caplog.records]
            assert not any("command evaluate" in line for line in logged)
        finally:
            await service.close()

    async def test_a_check_that_deviates_is_run_only_when_asked_to(self, served):
        service = await _service(served)
        try:
            held = await _ask(service, "evaluate", outstation="lab", checks=["LINK-001"])
            (result,) = held["result"]["results"]
            assert result["verdict"] == "not_run" and "breaks a protocol rule" in result["detail"]

            run = await _ask(
                service, "evaluate", outstation="lab", checks=["LINK-001"], allow_deviations=True
            )
            assert _verdicts(run) == {"LINK-001": "passed"}
            assert run["result"]["allow_deviations"] is True
            state = await _ask(service, "deviate", outstation="lab")
            assert state["result"]["on"] == [], "the master is left conformant"
        finally:
            await service.close()

    @pytest.mark.parametrize(
        ("params", "says"),
        [
            ({"checks": "MON-001"}, "checks is a list of check names"),
            ({"checks": ["MON-1"]}, "'mon-1' is not a check"),
            ({"allow_deviations": "yes"}, "allow_deviations is true or false"),
            ({"settle": 0}, "settle is a number of seconds greater than 0"),
            ({"settle": float("inf")}, "settle is a number of seconds greater than 0"),
            ({"settle": float("nan")}, "settle is a number of seconds greater than 0"),
            ({"curves": 0}, "curves is a whole number of at least 1"),
        ],
    )
    async def test_a_mistake_in_the_request_is_said_and_nothing_is_run(self, params, says, served):
        service = await _service(served)
        try:
            before = service.master["lab"].trace.last_id
            answer = await _ask(service, "evaluate", outstation="lab", **params)
            assert not answer["ok"] and answer["error"]["kind"] == "request"
            assert says in answer["error"]["message"]
            assert service.master["lab"].trace.last_id == before
        finally:
            await service.close()

    async def test_an_outstation_with_no_profile_cannot_be_evaluated(self, served):
        _, server, _ = served
        service = Service()
        try:
            await _ask(service, "add", name="lab", host="127.0.0.1", port=server.port)
            answer = await _ask(service, "evaluate", outstation="lab")
            assert not answer["ok"] and "lab was given no profile" in answer["error"]["message"]
        finally:
            await service.close()

    async def test_one_evaluation_runs_against_an_outstation_at_a_time(self, served):
        service = await _service(served)
        try:
            first, second = await asyncio.gather(
                _ask(service, "evaluate", outstation="lab", checks=["MON-001"]),
                _ask(service, "evaluate", outstation="lab", checks=["OP-001"]),
            )
            assert first["ok"] and not second["ok"]
            assert second["error"]["message"] == "an evaluation of lab is already running"
            # The first has ended, so another may be run.
            again = await _ask(service, "evaluate", outstation="lab", checks=["OP-001"])
            assert _verdicts(again) == {"OP-001": "passed"}
        finally:
            await service.close()

    async def test_an_outstation_that_does_not_answer_is_a_connection_error(self, served):
        _, server, _ = served
        service = await _service(served)
        try:
            await server.stop()
            answer = await _ask(service, "evaluate", outstation="lab", checks=["MON-001"])
            assert not answer["ok"] and answer["error"]["kind"] == "connection"
        finally:
            await service.close()
