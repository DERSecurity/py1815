"""Requests sent to a broadcast address: acted on, never answered (IEEE 1815-2012 4.5.1)."""

from __future__ import annotations

import pytest
from profile_fixtures import for_reference_der
from test_master_association import _built, _sent
from test_master_service import _added, _ask

from py1815 import link
from py1815.application import FunctionCode, IINBit
from py1815.master import Loopback, Master, Outcome, PointType, Tasks
from py1815.master import requests as rq
from py1815.master.operations import BROADCASTS, DEFAULT_BROADCAST, broadcast_address
from py1815.master.service import Service
from py1815.profile import der, load
from py1815.profile.model import Composition
from py1815.server import OutstationServer

#: An immediate freeze of every counter, with no response: group 20 variation
#: 0, every object.
FREEZE = bytes.fromhex("14 00 06")


@pytest.fixture
def simulation() -> der.Simulation:
    return der.build(load.resolve(for_reference_der(), Composition()))


class TestTheAddress:
    @pytest.mark.parametrize(
        ("given", "address"),
        [
            ("no_confirm", 0xFFFD),
            ("shall_confirm", 0xFFFE),
            ("optional_confirm", 0xFFFF),
            (0xFFFE, 0xFFFE),
            (link.Broadcast.NO_CONFIRM, 0xFFFD),
        ],
    )
    def test_an_address_is_named_or_numbered(self, given, address):
        assert broadcast_address(given) == address

    @pytest.mark.parametrize("given", ["everyone", 0xFFFC, 1024])
    def test_anything_else_is_refused(self, given):
        with pytest.raises(ValueError, match="not a broadcast address"):
            broadcast_address(given)

    def test_the_default_is_the_one_every_outstation_takes(self):
        assert DEFAULT_BROADCAST == 0xFFFF
        assert list(BROADCASTS) == ["no_confirm", "shall_confirm", "optional_confirm"]


class TestTheAssociation:
    def test_a_broadcast_goes_to_the_address_and_waits_for_nothing(self):
        association, _ = _built()
        octets = association.request(
            FunctionCode.IMMED_FREEZE_NR, FREEZE, broadcast=link.Broadcast.SHALL_CONFIRM
        )

        # Length 11, DIR and PRM and unconfirmed user data, destination 0xFFFE,
        # source 1.
        assert octets[:8] == bytes.fromhex("05 64 0B C4 FE FF 01 00")
        ((frame, fragment),) = _sent(octets)
        assert frame.is_broadcast
        assert fragment == bytes.fromhex("C0 08 14 00 06")
        exchange = association.take()
        assert exchange.outcome is Outcome.SENT and not association.busy
        assert exchange.broadcast is link.Broadcast.SHALL_CONFIRM

    def test_a_request_that_expects_an_answer_is_still_finished_when_sent(self):
        association, _ = _built()
        association.request(FunctionCode.READ, rq.scan("class0"), broadcast=0xFFFD)
        exchange = association.take()
        assert exchange.outcome is Outcome.SENT and exchange.broadcast == 0xFFFD

    def test_a_request_to_the_outstation_names_no_broadcast(self):
        association, _ = _built()
        association.request(FunctionCode.IMMED_FREEZE_NR, FREEZE)
        assert association.take().broadcast is None


class TestAgainstASession:
    def test_a_broadcast_freeze_is_carried_out_and_not_answered(self, simulation):
        master = Loopback(simulation.outstation.session())
        master.integrity_poll()
        simulation.advance(3600.0)
        counted = master.read(counters="all")

        sent = master.broadcast(FunctionCode.IMMED_FREEZE_NR, FREEZE)
        frozen = master.read(frozen_counters="all")

        assert sent.outcome is Outcome.SENT and sent.fragments == ()
        counters = {each.index: each.value for each in counted.objects}
        assert counters and {each.index: each.value for each in frozen.objects} == counters

    @pytest.mark.parametrize(
        ("address", "confirmed"),
        [("no_confirm", False), ("shall_confirm", True), ("optional_confirm", True)],
    )
    def test_the_next_response_reports_it(self, simulation, address, confirmed):
        master = Loopback(simulation.outstation.session())
        master.broadcast(FunctionCode.IMMED_FREEZE_NR, FREEZE, address=address)
        reported = master.read(binary_inputs=[0])
        after = master.read(binary_inputs=[0])

        assert reported.iin.is_set(IINBit.BROADCAST)
        # Under the addresses that ask for it, the response asks to be
        # confirmed, and the master's confirmation is what clears the bit.
        assert reported.fragments[-1].control.con is confirmed
        assert not after.iin.is_set(IINBit.BROADCAST)

    def test_a_broadcast_time_write_sets_the_clock(self, simulation):
        master = Loopback(simulation.outstation.session())
        master.broadcast(FunctionCode.WRITE, rq.write_time(1_700_000_000_000))
        assert abs(simulation.outstation.now_ms() - 1_700_000_000_000) < 5_000

    def test_tasks_see_the_report_like_any_other_response(self, simulation):
        master = Loopback(simulation.outstation.session(), tasks=Tasks())
        master.start()
        del master.unasked[:]
        master.broadcast(FunctionCode.IMMED_FREEZE_NR, FREEZE)
        assert master.unasked == [], "a broadcast is answered by nothing, so nothing is due"


class TestOverTcp:
    @pytest.mark.asyncio
    async def test_a_broadcast_on_the_connection_reaches_the_outstation(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        try:
            async with Master() as master:
                lab = await master.add(
                    "lab", host="127.0.0.1", port=server.port, tasks=Tasks.none()
                )
                sent = await lab.broadcast(FunctionCode.IMMED_FREEZE_NR, FREEZE)
                answer = await lab.read(binary_inputs=[0])
                frames = [entry.link["destination"] for entry in lab.trace.since()]
        finally:
            await server.stop()

        assert sent.outcome is Outcome.SENT and sent.broadcast is link.Broadcast.OPTIONAL_CONFIRM
        assert answer.iin.is_set(IINBit.BROADCAST)
        assert frames[0] == 0xFFFF and lab.store.get(PointType.BINARY_INPUT, 0) is not None


class TestTheService:
    @pytest.mark.asyncio
    async def test_a_broadcast_that_changes_the_outstation_needs_commanding(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        reading, commanding = Service(), Service(allow_control=True)
        try:
            await _added(reading, server, manual=True)
            refused = await _ask(
                reading, "broadcast", "lab", function="IMMED_FREEZE_NR", body="140006"
            )
            assert refused["error"]["kind"] == "not_allowed"
            allowed = await _ask(
                reading, "broadcast", "lab", function="DISABLE_UNSOLICITED", body="3c0206"
            )
            assert allowed["ok"] and allowed["result"]["outcome"] == "sent"
            await _ask(reading, "remove", "lab")

            await _added(commanding, server, manual=True)
            sent = await _ask(
                commanding,
                "broadcast",
                "lab",
                function="IMMED_FREEZE_NR",
                body="140006",
                address="no_confirm",
            )
            assert sent["result"]["broadcast"] == "no_confirm"
            assert sent["result"]["request"] == "c008140006"
            wrong = await _ask(
                commanding, "broadcast", "lab", function="IMMED_FREEZE_NR", address="all"
            )
            assert wrong["error"]["kind"] == "request"
        finally:
            await reading.close()
            await commanding.close()
            await server.stop()
