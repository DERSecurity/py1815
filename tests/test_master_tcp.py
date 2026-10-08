"""The master over a real socket, against this library's listener.

The same two halves of the library as ``test_master_loopback.py``, with a
socket between them. What these tests show is what the socket adds: that the
master connects, takes its turn, times out, notices a connection ending, and
is told of what arrives unasked. Like the loopback tests they show that the
two ends agree, and not that either reads the standard correctly, since both
stand on the same layers. The interoperability jobs and the tests written from
octets are what speak to that.
"""

from __future__ import annotations

import asyncio

import pytest
from profile_fixtures import for_reference_der

from py1815.application import IINBit
from py1815.master import ALL, Master, NotConnected, Outcome, Outstation, PointType, Tasks
from py1815.profile import der, load
from py1815.profile.model import Composition, Kind
from py1815.profile.outstation import DerOutstation
from py1815.server import OutstationServer

#: For a test that counts what was sent: only what it asks for is.
ASKED = Tasks.none()


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
                lab = await master.add("lab", host="127.0.0.1", port=server.port, tasks=ASKED)
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
                lab = await master.add("lab", host="127.0.0.1", port=server.port, tasks=ASKED)
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
                lab = await master.add("lab", host="127.0.0.1", port=server.port, tasks=ASKED)
                first = await lab.scan("class0")
                await lab.close()
                assert not lab.connected
                await lab.connect()
                second = await lab.scan("class0")
        finally:
            await server.stop()

        assert first.complete and second.complete
        assert second.sequence == first.sequence + 1, "the association outlives the socket"


class TestARequestNobodyWaitsFor:
    """A request that is cancelled was still sent. It must not block the ones after it."""

    @pytest.mark.asyncio
    async def test_a_caller_that_stops_waiting_leaves_the_outstation_usable(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        seen = []
        await server.start()
        try:
            async with Master() as master:
                # Nobody answers to address 77, so the request stays out.
                lab = await master.add(
                    "lab",
                    host="127.0.0.1",
                    port=server.port,
                    outstation_address=77,
                    response_timeout=30.0,
                    tasks=ASKED,
                    on_exchange=seen.append,
                )
                for _ in range(2):
                    with pytest.raises(TimeoutError):
                        await asyncio.wait_for(lab.scan("class0"), 0.05)
                assert not lab.association.busy
        finally:
            await server.stop()

        assert lab.counts == {"abandoned": 2}
        assert [exchange.outcome for exchange in seen] == [Outcome.ABANDONED] * 2
        assert [exchange.sequence for exchange in seen] == [0, 1]

    @pytest.mark.asyncio
    async def test_a_repeated_scan_set_again_while_one_is_out_goes_on_scanning(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        try:
            async with Master() as master:
                lab = await master.add("lab", host="127.0.0.1", port=server.port, tasks=ASKED)
                lab.repeat_scan("events", 0.02)
                # Until a scan is out and unanswered, and then set it again.
                async with asyncio.timeout(5):
                    while not lab.association.busy:
                        await asyncio.sleep(0)
                lab.repeat_scan("events", 0.02)
                lab.repeat_scan("outputs", 0.02)

                answered = lab.counts.get("complete", 0)
                await _until(lambda: lab.counts.get("complete", 0) >= answered + 6)
                assert lab.store.points(PointType.ANALOG_OUTPUT), "the outputs scan ran"
                assert lab.counts.get("abandoned") == 1
        finally:
            await server.stop()


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


async def _free_port() -> int:
    """A port nothing listens on, for an outstation that starts later."""
    closed = await asyncio.start_server(lambda reader, writer: None, "127.0.0.1", 0)
    port = closed.sockets[0].getsockname()[1]
    closed.close()
    await closed.wait_closed()
    return port


class TestAFirstConnection:
    """A connection that could not be made at first is tried again only when asked."""

    @staticmethod
    def _refusing(lab: Outstation) -> list[int]:
        """Make every attempt of ``lab`` fail, each with its own number, and count them."""
        attempts: list[int] = []

        async def refused() -> None:
            attempts.append(len(attempts) + 1)
            raise ConnectionRefusedError(f"attempt {len(attempts)} refused")

        lab._open = refused  # type: ignore[method-assign]
        return attempts

    @pytest.mark.asyncio
    async def test_by_default_one_that_cannot_be_made_is_tried_once(self):
        lab = Outstation("lab", host="127.0.0.1", port=1)
        attempts = self._refusing(lab)
        with pytest.raises(OSError, match="attempt 1 refused"):
            await lab.connect()
        assert attempts == [1]

    @pytest.mark.asyncio
    async def test_waiting_keeps_trying_until_the_outstation_is_there(self, simulation):
        port = await _free_port()
        lab = Outstation("lab", host="127.0.0.1", port=port, tasks=ASKED)
        trying = asyncio.create_task(lab.connect(wait=10.0, every=0.05))
        await asyncio.sleep(0.2)
        assert not trying.done(), "still trying"
        server = OutstationServer(simulation.outstation.session(), bind=f"127.0.0.1:{port}")
        await server.start()
        try:
            async with asyncio.timeout(5):
                await trying
            assert lab.connected and (await lab.scan("class0")).complete
        finally:
            await lab.close()
            await server.stop()

    @pytest.mark.asyncio
    async def test_waiting_ends_with_the_last_error_when_the_time_is_up(self):
        lab = Outstation("lab", host="127.0.0.1", port=1)
        attempts = self._refusing(lab)
        with pytest.raises(OSError) as raised:
            await lab.connect(wait=0.3, every=0.1)
        # At 0, 0.1, 0.2 and perhaps 0.3 seconds, and no attempt after the time.
        assert len(attempts) in (3, 4)
        assert str(raised.value) == f"attempt {len(attempts)} refused"
        assert not lab.connected

    @pytest.mark.asyncio
    async def test_the_master_adds_one_once_it_is_reached(self, simulation, monkeypatch):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        opened = Outstation._open
        attempts: list[int] = []

        async def refused_once(outstation: Outstation) -> None:
            # The first attempt fails as if the outstation were not there yet.
            attempts.append(1)
            if len(attempts) == 1:
                raise ConnectionRefusedError("not there yet")
            await opened(outstation)

        monkeypatch.setattr(Outstation, "_open", refused_once)
        try:
            async with Master() as master:
                lab = await master.add(
                    "lab", host="127.0.0.1", port=server.port, tasks=ASKED, wait=5.0
                )
                assert lab.connected and master["lab"] is lab and len(attempts) == 2
        finally:
            await server.stop()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("options", "says"),
        [
            ({"wait": -1.0}, "wait is -1.0"),
            ({"wait": float("inf")}, "wait is inf"),
            ({"every": 0.0}, "every is 0.0"),
        ],
    )
    async def test_a_wait_that_is_not_one_is_refused(self, options, says):
        with pytest.raises(ValueError, match=says):
            await Outstation("lab", host="127.0.0.1", port=1).connect(**options)
