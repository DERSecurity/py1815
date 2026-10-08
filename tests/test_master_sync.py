"""The master for a script with no event loop: each call blocks until it is done."""

from __future__ import annotations

import asyncio
import inspect
import threading

import pytest
from profile_fixtures import for_reference_der

from py1815.application import FunctionCode
from py1815.master import Outcome, PointType, Tasks, api, sync
from py1815.master.operations import Operations
from py1815.profile import der, load
from py1815.profile.model import Composition
from py1815.server import OutstationServer

WATTS = der.AI_METER_FIRST + 4


class _Served:
    """An outstation listening on a thread of its own, as a device on a bench would be."""

    def __init__(self) -> None:
        self.simulation = der.build(load.resolve(for_reference_der(), Composition()))
        self._loop = asyncio.new_event_loop()
        self._server = OutstationServer(self.simulation.outstation.session(), bind="127.0.0.1:0")
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)

    def __enter__(self) -> _Served:
        self._thread.start()
        asyncio.run_coroutine_threadsafe(self._server.start(), self._loop).result(5)
        return self

    @property
    def port(self) -> int:
        return self._server.port

    def __exit__(self, *_exc) -> None:
        asyncio.run_coroutine_threadsafe(self._server.stop(), self._loop).result(5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)
        self._loop.close()


@pytest.fixture
def served():
    with _Served() as server:
        yield server


class TestTheInterface:
    def test_every_operation_and_every_coroutine_has_a_blocking_counterpart(self):
        operations = {name for name in vars(Operations) if not name.startswith("_")}
        coroutines = {
            name
            for name, value in vars(api.Outstation).items()
            if not name.startswith("_") and inspect.iscoroutinefunction(value)
        }
        assert operations | coroutines == set(sync.BLOCKING)
        for name in sync.BLOCKING:
            method = getattr(sync.Outstation, name)
            assert not inspect.iscoroutinefunction(method), name
            assert method.__doc__ == getattr(api.Outstation, name).__doc__, name

    def test_the_ones_that_matter_are_among_them(self):
        assert {"integrity_poll", "read", "operate", "connect", "wait_for", "broadcast"} <= set(
            sync.BLOCKING
        )


class TestAgainstAnOutstation:
    def test_a_script_reads_and_waits_with_no_event_loop(self, served):
        with sync.Master() as master:
            lab = master.add("lab", host="127.0.0.1", port=served.port)
            lab.idle()
            assert lab.connected and master["lab"] is lab

            poll = lab.integrity_poll()
            answer = lab.read(analog_inputs=[WATTS])
            held = lab.wait_for(lambda store: store.analog_input(WATTS) is not None, 1.0)

        assert poll.outcome is Outcome.COMPLETE and answer.complete and held
        assert answer.objects[0].index == WATTS
        assert not lab.connected, "leaving the master closed the connection"

    def test_the_store_and_the_trace_are_read_on_the_masters_thread(self, served):
        with sync.Master() as master:
            lab = master.add("lab", host="127.0.0.1", port=served.port, tasks=Tasks.none())
            lab.scan("class0")
            watts = lab.store.analog_input(WATTS)
            analog = lab.store.points(PointType.ANALOG_INPUT)
            frames = lab.trace.since()
            assert len(lab.trace) == len(frames) > 0

        assert watts is not None and WATTS in analog

    def test_tasks_are_changed_and_scans_repeated_on_the_masters_thread(self, served):
        with sync.Master() as master:
            lab = master.add("lab", host="127.0.0.1", port=served.port)
            lab.idle()
            lab.tasks = Tasks.none()
            assert lab.tasks == Tasks.none()
            lab.repeat_scan("class0", 0.01)
            assert lab.wait_for(lambda _: lab.counts.get("complete", 0) > 6, 5.0)
            lab.repeat_scan("class0", None)

    def test_a_command_and_a_broadcast_block_until_sent(self, served):
        with sync.Master() as master:
            lab = master.add("lab", host="127.0.0.1", port=served.port, tasks=Tasks.none())
            operated = lab.operate(analog_outputs={der.AO_POWER_LIMIT_GENERATION: 300})
            frozen = lab.broadcast(FunctionCode.IMMED_FREEZE_NR, bytes.fromhex("140006"))
        assert operated.accepted and frozen.outcome is Outcome.SENT

    def test_what_the_master_raises_is_raised_to_the_caller(self, served):
        with sync.Master() as master:
            with pytest.raises(OSError):
                master.add("gone", host="127.0.0.1", port=1, connect_timeout=1.0)
            lab = master.add("lab", host="127.0.0.1", port=served.port, tasks=Tasks.none())
            with pytest.raises(ValueError, match="names at least one point"):
                lab.read()
            master.remove("lab")
            assert master.outstations == {}

    def test_closing_twice_is_harmless(self):
        master = sync.Master()
        master.close()
        master.close()
