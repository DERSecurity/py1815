"""A read that times out is sent again; nothing else ever is.

IEEE 1815-2012 4.3 rule 16: a retry carries the same sequence number and the
same octets as the request it repeats, and a direct operate, a delay
measurement, a record of the current time and a time write are never retried.
This master retries reads only, because any other request sent twice may be
acted on twice (D80).
"""

from __future__ import annotations

import asyncio

import pytest
from profile_fixtures import for_reference_der
from test_master_association import _built, _from_outstation, _sent
from test_master_service import _added, _ask

from py1815 import link
from py1815.application import FunctionCode
from py1815.master import Loopback, Master, MasterAssociation, Outcome, Tasks
from py1815.master import requests as rq
from py1815.master.association import DEFAULT_READ_RETRIES, RETRIED_FUNCTIONS
from py1815.master.service import Service
from py1815.master.trace import SENT
from py1815.profile import der, load
from py1815.profile.model import Composition
from py1815.server import OutstationServer

CLASS0 = bytes.fromhex("C0 01 3C 01 06")


@pytest.fixture
def simulation() -> der.Simulation:
    return der.build(load.resolve(for_reference_der(), Composition()))


class Lossy:
    """A session whose first requests are lost on the way to it."""

    def __init__(self, session, lost: int = 1) -> None:
        self.session = session
        self.lost = lost
        self.arrived = 0

    @property
    def facts(self):
        return self.session.facts

    def receive(self, data: bytes) -> bytes:
        self.arrived += 1
        if self.lost:
            self.lost -= 1
            return b""
        return self.session.receive(data)

    def initiate(self) -> bytes:
        return self.session.initiate()


class TestTheAssociation:
    def test_a_read_that_times_out_is_sent_again_with_its_own_sequence_number(self):
        association, clock = _built(read_retries=1)
        first = association.request(FunctionCode.READ, rq.scan("class0"))
        clock.now += 5.0
        again = association.retry()

        # The same frame header, the next transport sequence number, and the
        # same application fragment: sequence 0, a read of class 0.
        assert first[:8] == again[:8] == bytes.fromhex("05 64 0B C4 00 04 01 00")
        ((frame, fragment),) = _sent(again)
        assert frame.payload == bytes.fromhex("C1 C0 01 3C 01 06")
        assert fragment == CLASS0
        assert association.busy, "the retry waits for its answer"

    def test_the_answer_to_the_retry_completes_the_read_and_counts_it(self):
        association, clock = _built(read_retries=2)
        association.request(FunctionCode.READ, rq.scan("class0"))
        clock.now += 5.0
        association.retry()
        clock.now += 1.0
        association.receive(_from_outstation("C0 81 00 00"))
        exchange = association.take()
        assert exchange.complete and exchange.retries == 1 and exchange.sequence == 0
        assert exchange.elapsed == pytest.approx(6.0)

    def test_a_retry_waits_a_whole_response_timeout_again(self):
        association, clock = _built(read_retries=1, response_timeout=2.0)
        association.request(FunctionCode.READ, rq.scan("class0"))
        clock.now += 2.0
        association.retry()
        assert association.expires_after() == pytest.approx(2.0)
        clock.now += 1.9
        assert not association.expire()

    def test_nothing_is_sent_again_before_the_time_has_passed(self):
        association, clock = _built(read_retries=1)
        association.request(FunctionCode.READ, rq.scan("class0"))
        clock.now += 4.9
        assert association.retry() == b""
        assert association.retry(at_once=True) != b""

    def test_retries_stop_at_the_count_and_the_read_times_out(self):
        association, clock = _built(read_retries=2)
        association.request(FunctionCode.READ, rq.scan("class0"))
        sent = 0
        for _ in range(5):
            clock.now += 5.0
            if association.retry():
                sent += 1
            else:
                assert association.expire()
                break
        exchange = association.take()
        assert sent == 2 and exchange.retries == 2 and exchange.outcome is Outcome.TIMEOUT

    def test_a_read_whose_answer_has_begun_is_not_sent_again(self):
        association, clock = _built(read_retries=3)
        association.request(FunctionCode.READ, rq.scan("class0"))
        # The first of two fragments, and then nothing.
        association.receive(_from_outstation("80 81 00 00"))
        clock.now += 5.0
        assert association.retry() == b""
        assert association.expire()
        assert association.take().retries == 0

    def test_no_read_is_retried_by_default(self):
        assert DEFAULT_READ_RETRIES == 0
        association, clock = _built()
        association.request(FunctionCode.READ, rq.scan("class0"))
        clock.now += 5.0
        assert association.retry() == b""

    @pytest.mark.parametrize(
        "function",
        [
            FunctionCode.WRITE,
            FunctionCode.SELECT,
            FunctionCode.OPERATE,
            FunctionCode.DIRECT_OPERATE,
            FunctionCode.IMMED_FREEZE,
            FunctionCode.COLD_RESTART,
            FunctionCode.ENABLE_UNSOLICITED,
            FunctionCode.DELAY_MEASURE,
            FunctionCode.RECORD_CURRENT_TIME,
        ],
    )
    def test_nothing_but_a_read_is_ever_sent_again(self, function):
        association, clock = _built(read_retries=5)
        association.request(function, b"")
        clock.now += 5.0
        assert association.retry() == b""
        assert association.expire()
        assert association.take().retries == 0

    def test_only_a_read_is_named_as_retried(self):
        assert frozenset({FunctionCode.READ}) == RETRIED_FUNCTIONS

    @pytest.mark.parametrize("retries", [-1, 1.5, True, "2"])
    def test_a_count_that_is_not_one_is_refused(self, retries):
        with pytest.raises(ValueError, match="read_retries"):
            MasterAssociation(read_retries=retries)


class TestInOneProcess:
    def test_a_read_lost_on_the_way_is_answered_when_sent_again(self, simulation):
        lossy = Lossy(simulation.outstation.session())
        master = Loopback(lossy)
        master.association.read_retries = 1

        answer = master.read(binary_inputs=[0, 1])

        assert answer.complete and answer.retries == 1 and answer.sequence == 0
        assert len(answer.objects) == 2 and lossy.arrived >= 2

    def test_without_retries_the_lost_read_is_a_timeout(self, simulation):
        master = Loopback(Lossy(simulation.outstation.session()))
        answer = master.read(binary_inputs=[0])
        assert answer.outcome is Outcome.TIMEOUT and answer.retries == 0

    def test_an_operate_that_is_lost_is_not_sent_again(self, simulation):
        lossy = Lossy(simulation.outstation.session())
        master = Loopback(lossy)
        master.association.read_retries = 5

        result = master.operate(analog_outputs={der.AO_POWER_LIMIT_GENERATION: 300})

        assert result.accepted is None, "never answered, so not known"
        assert [exchange.retries for exchange in result.exchanges] == [0]
        assert lossy.arrived == 1


async def _forgetful(session, lost: int = 1) -> asyncio.Server:
    """A listener that drops the first reads of a connection and hands the rest on."""
    left = {"lost": lost}

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while data := await reader.read(4096):
            if left["lost"]:
                left["lost"] -= 1
                continue
            reply = session.receive(data)
            if reply:
                writer.write(reply)
                await writer.drain()
        writer.close()

    return await asyncio.start_server(handle, "127.0.0.1", 0)


class TestOverTcp:
    @pytest.mark.asyncio
    async def test_the_read_is_sent_twice_and_answered_once(self, simulation):
        server = await _forgetful(simulation.outstation.session())
        port = server.sockets[0].getsockname()[1]
        try:
            async with Master() as master:
                lab = await master.add(
                    "lab",
                    host="127.0.0.1",
                    port=port,
                    tasks=Tasks.none(),
                    response_timeout=0.2,
                    read_retries=1,
                )
                answer = await lab.scan("class0")
                sent = [
                    entry.application["sequence"]
                    for entry in lab.trace.since()
                    if entry.direction == SENT and entry.application
                ]
        finally:
            server.close()
            await server.wait_closed()

        assert answer.complete and answer.retries == 1 and answer.objects
        assert sent == [0, 0], "two sends of one request, under one sequence number"

    @pytest.mark.asyncio
    async def test_the_service_takes_the_count_when_adding(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        service = Service()
        try:
            await _added(service, server, read_retries=2)
            (lab,) = (await _ask(service, "status"))["result"]["outstations"]
            assert lab["read_retries"] == 2
            scan = (await _ask(service, "scan", "lab", kind="class0"))["result"]
            assert scan["retries"] == 0 and scan["broadcast"] is None
            refused = await _ask(service, "add", name="other", host="127.0.0.1", read_retries=-1)
            assert refused["error"] == {
                "kind": "request",
                "message": "read_retries is a count of retries, zero or more",
            }
        finally:
            await service.close()
            await server.stop()


def test_a_broadcast_read_is_never_sent_again():
    association, clock = _built(read_retries=3)
    association.request(FunctionCode.READ, rq.scan("class0"), broadcast=link.Broadcast.NO_CONFIRM)
    clock.now += 5.0
    assert association.retry() == b"" and association.take().outcome is Outcome.SENT
