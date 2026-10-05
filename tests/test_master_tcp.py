"""The master over a real socket, against this library's listener."""

from __future__ import annotations

import asyncio

import pytest
from profile_fixtures import for_reference_der

from py1815.application import IINBit
from py1815.master import ALL, Master, NotConnected, Outcome, Outstation, PointType
from py1815.profile import der, load
from py1815.profile.model import Composition, Kind
from py1815.profile.outstation import DerOutstation
from py1815.server import OutstationServer


@pytest.fixture
def simulation() -> der.Simulation:
    return der.build(load.resolve(for_reference_der(), Composition()))


async def _until(condition, *, timeout: float = 5.0) -> None:
    """Wait for something another task does, without sleeping a fixed time."""
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.01)


class TestReading:
    @pytest.mark.asyncio
    async def test_an_integrity_poll_of_many_fragments_fills_the_store(self):
        # Small blocks and a small response, so the map takes several fragments
        # and the master has to confirm its way through them.
        point_map = load.resolve(for_reference_der(), Composition())
        device = der.ReferenceDer()
        outstation = DerOutstation(point_map, device.bind(point_map), block_octets=200)
        simulation = der.Simulation(device, outstation)
        server = OutstationServer(outstation.session(max_response=292), bind="127.0.0.1:0")
        await server.start()
        try:
            simulation.advance(1.0)
            async with Master() as master:
                lab = await master.add("lab", host="127.0.0.1", port=server.port)
                poll = await lab.integrity_poll()
        finally:
            await server.stop()

        assert poll.complete and len(poll.fragments) > 1
        assert poll.iin.is_set(IINBit.DEVICE_RESTART)
        assert len(lab.store.points(PointType.BINARY_INPUT)) == len(outstation.served(Kind.BI))
        assert len(lab.store.points(PointType.ANALOG_INPUT)) == len(outstation.served(Kind.AI))
        watts = lab.store.analog_input(der.AI_METER_FIRST + 4)
        assert watts.value == round(simulation.der.watts)

    @pytest.mark.asyncio
    async def test_a_confirmed_event_scan_leaves_none_behind(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        try:
            async with Master() as master:
                lab = await master.add("lab", host="127.0.0.1", port=server.port)
                await lab.scan("events")
                simulation.advance(5.0)
                scan = await lab.scan("events")
                again = await lab.scan("events")
        finally:
            await server.stop()

        assert scan.complete and scan.objects
        assert again.complete and again.objects == ()
        assert simulation.outstation.events.total == 0

    @pytest.mark.asyncio
    async def test_requests_made_together_take_turns(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        try:
            async with Master() as master:
                lab = await master.add("lab", host="127.0.0.1", port=server.port)
                results = await asyncio.gather(
                    lab.scan("class0"),
                    lab.read(analog_outputs=ALL),
                    lab.read(binary_inputs=[0, 1]),
                )
        finally:
            await server.stop()

        assert all(result.complete for result in results)
        assert [result.sequence for result in results] == [0, 1, 2]
        assert len(results[2].objects) == 2


class TestSilenceAndConnections:
    @pytest.mark.asyncio
    async def test_an_outstation_that_does_not_answer_is_a_timeout(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        try:
            async with Master() as master:
                # The outstation's address is 1024, and this asks for 77.
                lab = await master.add(
                    "lab",
                    host="127.0.0.1",
                    port=server.port,
                    outstation_address=77,
                    response_timeout=0.2,
                )
                poll = await lab.integrity_poll()
        finally:
            await server.stop()

        assert poll.outcome is Outcome.TIMEOUT
        assert poll.fragments == () and poll.elapsed >= 0.2
        assert len(lab.store) == 0

    @pytest.mark.asyncio
    async def test_nothing_listening_is_an_error_at_connecting(self):
        closed = await asyncio.start_server(lambda reader, writer: None, "127.0.0.1", 0)
        port = closed.sockets[0].getsockname()[1]
        closed.close()
        await closed.wait_closed()

        async with Master() as master:
            with pytest.raises(OSError):
                await master.add("lab", host="127.0.0.1", port=port, connect_timeout=2.0)
            assert master.outstations == {}

    @pytest.mark.asyncio
    async def test_a_request_with_no_connection_is_misuse(self):
        lab = Outstation("lab", host="127.0.0.1", port=1)
        with pytest.raises(NotConnected, match="lab is not connected"):
            await lab.integrity_poll()

    @pytest.mark.asyncio
    async def test_a_connection_the_outstation_closes_is_noticed(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        async with Master() as master:
            lab = await master.add("lab", host="127.0.0.1", port=server.port)
            assert (await lab.scan("class0")).complete
            await server.stop()
            await _until(lambda: not lab.connected)
            with pytest.raises(NotConnected):
                await lab.scan("class0")
            assert len(lab.store) > 0, "what was read stays read"

    @pytest.mark.asyncio
    async def test_a_connection_can_be_closed_and_made_again(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        try:
            async with Master() as master:
                lab = await master.add("lab", host="127.0.0.1", port=server.port)
                first = await lab.scan("class0")
                await lab.close()
                assert not lab.connected
                await lab.connect()
                second = await lab.scan("class0")
        finally:
            await server.stop()

        assert first.complete and second.complete
        assert second.sequence == first.sequence + 1, "the association outlives the socket"


class TestUnsolicitedResponses:
    @pytest.mark.asyncio
    async def test_the_restart_announcement_arrives_unasked_and_is_confirmed(self, simulation):
        session = simulation.outstation.session(unsolicited=True)
        server = OutstationServer(session, bind="127.0.0.1:0")
        heard = []
        await server.start()
        try:
            async with Master() as master:
                lab = await master.add(
                    "lab", host="127.0.0.1", port=server.port, on_unsolicited=heard.append
                )
                await _until(lambda: lab.unsolicited)
                # Asked after the announcement was confirmed, so answered at
                # once: an unconfirmed one would have held the read back.
                poll = await lab.scan("class0")
        finally:
            await server.stop()

        (announcement,) = lab.unsolicited
        assert announcement.null and heard == [announcement]
        assert poll.complete


class TestTheMaster:
    @pytest.mark.asyncio
    async def test_outstations_are_kept_by_name_and_a_name_is_used_once(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        try:
            async with Master() as master:
                lab = await master.add("lab", host="127.0.0.1", port=server.port)
                assert master["lab"] is lab and list(master.outstations) == ["lab"]
                with pytest.raises(ValueError, match="already been added"):
                    await master.add("lab", host="127.0.0.1", port=server.port)

                await master.remove("lab")
                assert master.outstations == {} and not lab.connected
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_leaving_the_master_closes_its_connections(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        try:
            async with Master() as master:
                lab = await master.add("lab", host="127.0.0.1", port=server.port)
                assert lab.connected
            assert not lab.connected
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_an_outstation_can_be_added_without_connecting(self):
        async with Master() as master:
            lab = await master.add("lab", host="127.0.0.1", port=1, connect=False)
            assert not lab.connected
