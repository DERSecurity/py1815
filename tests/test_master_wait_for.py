"""Waiting for a condition on what an outstation reported, from Python and from the service."""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from profile_fixtures import for_reference_der
from test_master_service import _added, _ask

from py1815.application import IINBit
from py1815.master import Master, Tasks
from py1815.master.service import Service
from py1815.profile import der, load
from py1815.profile.model import Composition
from py1815.server import OutstationServer

WATTS = der.AI_METER_FIRST + 4


@pytest.fixture
def simulation() -> der.Simulation:
    return der.build(load.resolve(for_reference_der(), Composition()))


@pytest_asyncio.fixture
async def served(simulation):
    server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
    await server.start()
    try:
        yield simulation, server
    finally:
        await server.stop()


class TestInPython:
    @pytest.mark.asyncio
    async def test_it_returns_when_a_response_makes_the_condition_true(self, served):
        _, server = served
        async with Master() as master:
            lab = await master.add("lab", host="127.0.0.1", port=server.port, tasks=Tasks.none())
            waiting = asyncio.create_task(
                lab.wait_for(lambda store: store.analog_input(WATTS) is not None, 5.0)
            )
            await asyncio.sleep(0.05)
            assert not waiting.done(), "nothing has been read yet"
            await lab.scan("class0")
            assert await waiting is True

    @pytest.mark.asyncio
    async def test_a_condition_that_never_holds_is_false_at_the_timeout(self, served):
        _, server = served
        async with Master() as master:
            lab = await master.add("lab", host="127.0.0.1", port=server.port, tasks=Tasks.none())
            started = asyncio.get_running_loop().time()
            assert await lab.wait_for(lambda store: False, 0.2) is False
            assert asyncio.get_running_loop().time() - started >= 0.2

    @pytest.mark.asyncio
    async def test_a_condition_already_true_returns_at_once_and_zero_looks_once(self, served):
        _, server = served
        async with Master() as master:
            lab = await master.add("lab", host="127.0.0.1", port=server.port, tasks=Tasks.none())
            await lab.scan("class0")
            assert await lab.wait_for(lambda store: len(store) > 0, 0) is True
            assert await lab.wait_for(lambda store: False, 0) is False

    @pytest.mark.asyncio
    async def test_an_indication_is_waited_for_through_the_outstation(self, served):
        _, server = served
        async with Master() as master:
            # The startup sequence reads the outstation, which says it restarted.
            lab = await master.add("lab", host="127.0.0.1", port=server.port)
            restarted = await lab.wait_for(
                lambda _: (
                    lab.indications is not None and lab.indications.is_set(IINBit.DEVICE_RESTART)
                ),
                5.0,
            )
            assert restarted

    @pytest.mark.asyncio
    async def test_an_unsolicited_response_wakes_it(self, simulation):
        server = OutstationServer(
            simulation.outstation.session(unsolicited=True), bind="127.0.0.1:0"
        )
        await server.start()
        try:
            async with Master() as master:
                lab = await master.add(
                    "lab", host="127.0.0.1", port=server.port, tasks=Tasks.none(), confirm=True
                )
                assert await lab.wait_for(lambda _: bool(lab.unsolicited), 5.0)
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_what_the_condition_raises_is_raised(self, served):
        _, server = served
        async with Master() as master:
            lab = await master.add("lab", host="127.0.0.1", port=server.port, tasks=Tasks.none())
            with pytest.raises(ZeroDivisionError):
                await lab.wait_for(lambda store: 1 / 0 > 0, 1.0)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("timeout", [-1.0, float("nan"), float("inf")])
    async def test_a_timeout_that_is_not_one_is_refused(self, served, timeout):
        _, server = served
        async with Master() as master:
            lab = await master.add("lab", host="127.0.0.1", port=server.port, tasks=Tasks.none())
            with pytest.raises(ValueError, match="timeout is"):
                await lab.wait_for(lambda store: True, timeout)


class TestTheService:
    @pytest.mark.asyncio
    async def test_a_value_is_waited_for_and_returned(self, served):
        simulation, server = served
        service = Service()
        try:
            await _added(service, server)
            answer = await _ask(
                service,
                "wait_for",
                "lab",
                timeout=1,
                value={"type": "ai", "index": WATTS, "equals": round(simulation.der.watts)},
            )
            result = answer["result"]
            assert result["held"] and result["point"]["index"] == WATTS
            missed = await _ask(
                service,
                "wait_for",
                "lab",
                timeout=0.1,
                value={"type": "ai", "index": WATTS, "at_least": 1e12},
            )
            assert missed["result"]["held"] is False
        finally:
            await service.close()

    @pytest.mark.asyncio
    async def test_a_tolerance_and_bounds_compare_numbers(self, served):
        simulation, server = served
        service = Service()
        watts = round(simulation.der.watts)
        try:
            await _added(service, server)
            for condition, held in (
                ({"equals": watts + 3, "tolerance": 5}, True),
                ({"equals": watts + 3}, False),
                ({"at_least": watts - 1, "at_most": watts + 1}, True),
                ({"at_most": watts - 1}, False),
                ({}, True),
            ):
                answer = await _ask(
                    service,
                    "wait_for",
                    "lab",
                    timeout=0,
                    value={"type": "ai", "index": WATTS, **condition},
                )
                assert answer["result"]["held"] is held, condition
        finally:
            await service.close()

    @pytest.mark.asyncio
    async def test_an_event_that_arrives_after_the_wait_began_holds_it(self, served):
        simulation, server = served
        service = Service()
        try:
            await _added(service, server)
            waiting = asyncio.create_task(
                _ask(service, "wait_for", "lab", timeout=5, event={"type": "ai"})
            )
            await asyncio.sleep(0.05)
            assert not waiting.done(), "events read before the wait do not count"
            simulation.advance(5.0)
            await _ask(service, "scan", "lab", kind="events")
            result = (await waiting)["result"]
            assert result["held"] and result["events"]
            assert {event["type"] for event in result["events"]} == {"ai"}
        finally:
            await service.close()

    @pytest.mark.asyncio
    async def test_an_indication_is_named_and_may_be_waited_clear(self, served):
        _, server = served
        service = Service()
        try:
            await _added(service, server)
            set_now = await _ask(
                service, "wait_for", "lab", timeout=0, indication={"name": "DEVICE_RESTART"}
            )
            assert (
                set_now["result"]["held"] and "DEVICE_RESTART" in set_now["result"]["indications"]
            )
            clear = await _ask(
                service,
                "wait_for",
                "lab",
                timeout=0,
                indication={"name": "DEVICE_RESTART", "set": False},
            )
            assert clear["result"]["held"] is False
        finally:
            await service.close()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("params", "says"),
        [
            ({"value": {"type": "ai", "index": 1}}, "timeout is seconds"),
            ({"timeout": True, "value": {"type": "ai", "index": 1}}, "timeout is seconds"),
            ({"timeout": 1}, "one condition"),
            ({"timeout": 1, "value": {}, "event": {}}, "one condition"),
            ({"timeout": 1, "value": {"type": "xx", "index": 1}}, "value.type is one of"),
            ({"timeout": 1, "value": {"type": "ai"}}, "value.index is 0 to 65535"),
            ({"timeout": 1, "value": {"type": "ai", "index": 1, "near": 2}}, "value.near"),
            ({"timeout": 1, "value": {"type": "ai", "index": 1, "equals": "5"}}, "a number"),
            ({"timeout": 1, "event": {"index": 4}}, "event.type is one of"),
            ({"timeout": 1, "indication": {"name": "SOON"}}, "indication.name is one of"),
            ({"timeout": 1, "indication": {"name": "NEED_TIME", "set": 1}}, "true or false"),
            ({"timeout": 1, "value": [1]}, "value is an object"),
        ],
    )
    async def test_a_condition_that_is_not_one_is_refused(self, served, params, says):
        _, server = served
        service = Service()
        try:
            await _added(service, server, manual=True)
            answer = await _ask(service, "wait_for", "lab", **params)
            assert answer["error"]["kind"] == "request" and says in answer["error"]["message"]
        finally:
            await service.close()
