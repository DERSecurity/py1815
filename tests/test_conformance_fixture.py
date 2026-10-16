"""The conformance fixture's control channel, tested without the harness that drives it.

`interop/conformance_outstation.py` serves a Level 2 outstation and a control
channel that stands for a test bench: it changes inputs, cycles power and
reports what the device holds. A conformance harness trusts what that channel
says, so these tests check it against the outstation itself: a master on a
real connection reads what the channel changed, and the channel reports what
that master commanded.

The requests the master sends are written out as octets. Nothing here needs
Java or the harness.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import json
import pathlib
import subprocess
import sys
from typing import Any

import pytest
from ied_harness import (
    COLD_RESTART,
    DIRECT_OPERATE,
    DIRECT_OPERATE_NR,
    IIN1_BROADCAST,
    IIN1_CLASS_1,
    IIN1_NEED_TIME,
    IIN1_RESTART,
    IIN2_BAD_FUNCTION,
    IIN2_OBJECT_UNKNOWN,
    READ,
    SELECT,
    WRITE,
    Fragment,
)

from py1815 import link
from py1815.transport import Reassembler, segment

_FIXTURE = pathlib.Path(__file__).resolve().parents[1] / "interop" / "conformance_outstation.py"

HOST = "127.0.0.1"
OUTSTATION = 1024
MASTER = 1

# Object headers, as octets.
CLASS_0 = bytes.fromhex("3C 01 06")
CLASS_1 = bytes.fromhex("3C 02 06")
CLASS_2 = bytes.fromhex("3C 03 06")
CLASS_3 = bytes.fromhex("3C 04 06")
BINARY_INPUTS = bytes.fromhex("01 00 06")
BINARY_OUTPUTS = bytes.fromhex("0A 00 06")
COUNTERS = bytes.fromhex("14 00 06")
FROZEN_COUNTERS = bytes.fromhex("15 00 06")

#: Group 50 variation 1, one object: a time to write.
TIME_WRITE = bytes.fromhex("32 01 07 01") + (1_800_000_000_000).to_bytes(6, "little")

#: Group 12 variation 1, one object behind an 8-bit index: index 2, latch on,
#: count 1, on for 100 ms, off for 100 ms, status 0.
LATCH_ON_2 = bytes.fromhex("0C 01 17 01 02 03 01 64 00 00 00 64 00 00 00 00")

#: Group 41 variation 2, one object behind an 8-bit index: index 3, value 1234, status 0.
SETPOINT_3 = bytes.fromhex("29 02 17 01 03 D2 04 00")


def _load() -> Any:
    """Load the fixture, which is a script and not a package."""
    spec = importlib.util.spec_from_file_location("conformance_outstation", _FIXTURE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


fixture = _load()


class Clock:
    """A wall clock the tests move by hand, in milliseconds."""

    def __init__(self) -> None:
        self.ms = 1_700_000_000_000

    def __call__(self) -> int:
        return self.ms


class Master:
    """A master's side of one TCP connection to the outstation."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, source: int):
        self.reader = reader
        self.writer = writer
        self.source = source
        self.frames = link.FrameReader()
        self.sequence = 0

    @classmethod
    async def connect(cls, port: int, *, source: int = MASTER) -> Master:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(HOST, port), 5.0)
        return cls(reader, writer, source)

    def _send(self, fragment: bytes, destination: int = OUTSTATION) -> None:
        # 0xC4: from the master, primary, unconfirmed user data.
        for part in segment(fragment):
            self.writer.write(link.build(0xC4, destination, self.source, part))

    async def send(self, function: int, body: bytes = b"", *, destination: int) -> None:
        """Send one request to another address, and wait for nothing."""
        self._send(bytes([0xC0 | self.sequence, function]) + body, destination)
        self.sequence = (self.sequence + 1) % 16
        await self.writer.drain()

    async def request(self, function: int, body: bytes = b"") -> Fragment:
        """Send one request and return the fragment that answers it."""
        self._send(bytes([0xC0 | self.sequence, function]) + body)
        self.sequence = (self.sequence + 1) % 16
        await self.writer.drain()
        return await self.fragment()

    async def fragment(self, timeout: float = 5.0) -> Fragment:
        """Return the next fragment the outstation sends."""
        reassembler = Reassembler()
        while True:
            data = await asyncio.wait_for(self.reader.read(4096), timeout)
            assert data, "the outstation closed the connection"
            for frame in self.frames.feed(data):
                whole = reassembler.add(frame.payload)
                if whole is not None:
                    return Fragment(whole)

    async def confirm(self, fragment: Fragment) -> None:
        self._send(bytes([0xC0 | fragment.sequence | (0x10 if fragment.uns else 0), 0]))
        await self.writer.drain()

    async def closed_by_peer(self) -> bool:
        """Whether the outstation closes this connection within a few seconds."""
        try:
            while await asyncio.wait_for(self.reader.read(4096), 5.0):
                pass
        except (ConnectionResetError, BrokenPipeError):
            return True
        except TimeoutError:
            return False
        return True

    async def close(self) -> None:
        self.writer.close()
        with contextlib.suppress(ConnectionResetError, BrokenPipeError):
            await self.writer.wait_closed()


class Bench:
    """The device, its control channel, and a connection to that channel."""

    def __init__(self, **settings: Any) -> None:
        self.clock = Clock()
        self.device = fixture.Device(
            port=0, settings=fixture.Settings(**settings), wall_ms=self.clock
        )
        self.channel = fixture.ControlChannel(self.device)
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def __aenter__(self) -> Bench:
        await self.device.start()
        await self.channel.start()
        self._reader, self._writer = await asyncio.open_connection(HOST, self.channel.port)
        return self

    async def __aexit__(self, *exc: object) -> None:
        assert self._writer is not None
        self._writer.close()
        await self.channel.stop()
        await self.device.stop()

    async def send(self, line: bytes) -> dict[str, Any]:
        """Send one line to the control channel as it is, and return the answer."""
        assert self._reader is not None and self._writer is not None
        self._writer.write(line + b"\n")
        await self._writer.drain()
        answer: dict[str, Any] = json.loads(await asyncio.wait_for(self._reader.readline(), 10.0))
        return answer

    async def ask(self, op: str, **fields: Any) -> dict[str, Any]:
        """Carry out one operation, which has to succeed."""
        answer = await self.send(json.dumps({"op": op, **fields}).encode("utf-8"))
        assert answer["ok"], answer
        return answer

    async def master(self, **options: Any) -> Master:
        return await Master.connect(self.device.port, **options)


@pytest.mark.asyncio
class TestTheOutstationItServes:
    async def test_it_starts_with_the_restart_and_need_time_indications_set(self):
        async with Bench() as bench:
            master = await bench.master()
            fragment = await master.request(READ, CLASS_1)
            assert fragment.iin1 & IIN1_RESTART
            assert fragment.iin1 & IIN1_NEED_TIME
            state = await bench.ask("state")
            assert state["restart_indication"] is True
            assert state["need_time"] is True
            await master.close()

    async def test_a_class_0_response_is_longer_than_one_link_frame(self):
        # The transport procedure is about a response that has to be segmented.
        async with Bench() as bench:
            master = await bench.master()
            fragment = await master.request(READ, CLASS_0)
            assert len(fragment.octets) > 249
            await master.close()

    async def test_a_class_0_response_holds_every_installed_input(self):
        async with Bench() as bench:
            master = await bench.master()
            fragment = await master.request(READ, CLASS_0)
            state = await bench.ask("state")
            assert [o.index for o in fragment.of(1)] == state["installed"]["BI"]
            assert [o.index for o in fragment.of(20)] == state["installed"]["CTR"]
            assert [o.index for o in fragment.of(30)] == state["installed"]["AI"]
            await master.close()

    async def test_the_control_channel_is_bound_to_the_loopback_interface(self):
        async with Bench() as bench:
            assert bench.channel.host == HOST


@pytest.mark.asyncio
class TestInputs:
    async def test_a_binary_input_change_is_an_event_in_its_class_with_the_time_reported(self):
        async with Bench(need_time=False) as bench:
            bench.clock.ms += 250
            answer = await bench.ask("set", changes=[["BI", 0, True]])
            (change,) = answer["changes"]
            assert change == {
                "kind": "BI",
                "index": 0,
                "value": True,
                "time_ms": bench.clock.ms,
                "events": 1,
            }
            master = await bench.master()
            fragment = await master.request(READ, CLASS_1)
            (event,) = fragment.of(2)
            assert (event.index, event.state, event.time) == (0, True, change["time_ms"])
            await master.close()

    async def test_a_binary_input_in_class_2_is_not_read_as_class_1(self):
        async with Bench(need_time=False) as bench:
            await bench.ask("set", changes=[["BI", 8, True]])
            master = await bench.master()
            assert not (await master.request(READ, CLASS_1)).body
            (event,) = (await master.request(READ, CLASS_2)).of(2)
            assert event.index == 8
            await master.close()

    async def test_a_point_changed_twice_reports_two_events_in_order(self):
        async with Bench(need_time=False) as bench:
            answer = await bench.ask("set", changes=[["BI", 1, True], ["BI", 1, False]])
            assert [c["events"] for c in answer["changes"]] == [1, 1]
            master = await bench.master()
            events = (await master.request(READ, CLASS_1)).of(2)
            assert [(e.index, e.state) for e in events] == [(1, True), (1, False)]
            await master.close()

    async def test_an_analog_change_inside_the_deadband_is_no_event(self):
        async with Bench(need_time=False) as bench:
            inside, outside = fixture.DEADBAND, fixture.DEADBAND + 1
            answer = await bench.ask("set", changes=[["AI", 5, inside], ["AI", 5, outside]])
            assert [c["events"] for c in answer["changes"]] == [0, 1]
            master = await bench.master()
            (event,) = (await master.request(READ, CLASS_3)).of(32)
            assert (event.index, event.value) == (5, outside)
            await master.close()

    async def test_a_counter_change_is_no_event_and_is_read_back(self):
        async with Bench(need_time=False) as bench:
            answer = await bench.ask("set", changes=[["CTR", 2, 41]])
            assert answer["changes"][0]["events"] == 0
            master = await bench.master()
            counters = (await master.request(READ, COUNTERS)).of(20)
            assert [(c.index, c.value) for c in counters] == [(0, 0), (1, 0), (2, 41), (3, 0)]
            assert (await bench.ask("state"))["counters"]["2"] == 41
            await master.close()

    async def test_a_change_asks_for_its_events_to_be_reported_at_once(self):
        """Without this an enabled class waits for the listener's next look, half a second away."""
        async with Bench() as bench:
            asked = []
            notify = bench.device.notify

            def counted() -> None:
                asked.append(True)
                notify()

            bench.device.notify = counted
            await bench.ask("set", changes=[["BI", 3, True], ["BI", 3, False]])
            assert asked == [True], "once for the request, after its last change"

    async def test_the_time_reported_follows_a_time_the_master_wrote(self):
        async with Bench() as bench:
            master = await bench.master()
            written = 1_800_000_000_000
            # Group 50 variation 1, one object by count: the time, 48 bits.
            body = bytes.fromhex("32 01 07 01") + written.to_bytes(6, "little")
            assert (await master.request(WRITE, body)).is_null
            bench.clock.ms += 400
            (change,) = (await bench.ask("set", changes=[["BI", 0, True]]))["changes"]
            assert change["time_ms"] == written + 400
            (event,) = (await master.request(READ, CLASS_1)).of(2)
            assert event.time == written + 400
            await master.close()

    @pytest.mark.parametrize(
        ("change", "message"),
        [
            (["BO", 0, True], "an input is one of"),
            (["BI", 99, True], "the device has no BI99"),
            (["BI", 0, 1], "a binary input is true or false"),
            (["AI", 0, True], "it takes a number"),
            (["CTR", 0, -1], "a counter is a whole number"),
            (["CTR", 0, 1.5], "a counter is a whole number"),
            (["AI", "0", 1], "an index is a whole number"),
            (["AI", 0], "it is [kind, index, value]"),
        ],
    )
    async def test_a_change_that_cannot_be_made_is_refused_and_says_why(self, change, message):
        async with Bench() as bench:
            before = await bench.ask("state")
            answer = await bench.send(json.dumps({"op": "set", "changes": [change]}).encode())
            assert answer["ok"] is False
            assert message in answer["error"]
            after = await bench.ask("state")
            assert (after["binary"], after["analog"], after["counters"]) == (
                before["binary"],
                before["analog"],
                before["counters"],
            )


@pytest.mark.asyncio
class TestOutputs:
    async def test_an_operated_binary_output_is_reported_with_its_index_and_value(self):
        async with Bench() as bench:
            master = await bench.master()
            fragment = await master.request(DIRECT_OPERATE, LATCH_ON_2)
            assert fragment.body == LATCH_ON_2, "echoed with status 0"
            state = await bench.ask("state")
            assert state["operated"] == [
                {"number": 1, "kind": "BO", "index": 2, "value": True, "power_cycle": 0}
            ]
            assert state["binary_outputs"]["2"] is True
            assert state["binary_outputs"]["3"] is False
            await master.close()

    async def test_an_operated_analog_output_is_reported_with_its_value(self):
        async with Bench() as bench:
            master = await bench.master()
            assert (await master.request(DIRECT_OPERATE, SETPOINT_3)).body == SETPOINT_3
            state = await bench.ask("state")
            assert [(o["kind"], o["index"], o["value"]) for o in state["operated"]] == [
                ("AO", 3, 1234.0)
            ]
            assert state["analog_outputs"]["3"] == 1234.0
            await master.close()

    async def test_a_select_alone_operates_nothing(self):
        async with Bench() as bench:
            master = await bench.master()
            assert (await master.request(SELECT, LATCH_ON_2)).body == LATCH_ON_2
            state = await bench.ask("state")
            assert state["operated"] == []
            assert state["operations"] == 0
            assert state["binary_outputs"]["2"] is False
            await master.close()


@pytest.mark.asyncio
class TestWhatTheDeviceDecidesForItself:
    async def test_a_control_sent_to_a_broadcast_address_is_operated_and_not_answered(self):
        async with Bench() as bench:
            master = await bench.master()
            await master.send(DIRECT_OPERATE_NR, LATCH_ON_2, destination=0xFFFF)
            with pytest.raises(TimeoutError):
                await master.fragment(timeout=0.3)
            state = await bench.ask("state")
            assert [(o["kind"], o["index"], o["value"]) for o in state["operated"]] == [
                ("BO", 2, True)
            ]
            assert (await master.request(READ, CLASS_1)).iin1 & IIN1_BROADCAST
            await master.close()

    async def test_with_broadcast_controls_off_a_broadcast_control_operates_nothing(self):
        async with Bench(broadcast_controls=False) as bench:
            master = await bench.master()
            await master.send(DIRECT_OPERATE_NR, LATCH_ON_2, destination=0xFFFF)
            # The broadcast is still heard, and the next response says so.
            assert (await master.request(READ, CLASS_1)).iin1 & IIN1_BROADCAST
            assert (await bench.ask("state"))["operated"] == []
            await master.close()

    async def test_the_time_is_asked_for_again_an_interval_after_it_is_written(self):
        async with Bench(time_sync_interval=0.05) as bench:
            master = await bench.master()
            body = bytes.fromhex("32 01 07 01") + (1_800_000_000_000).to_bytes(6, "little")
            written = await master.request(WRITE, body)
            assert written.is_null and not written.iin1 & IIN1_NEED_TIME
            for _ in range(250):
                if (await bench.ask("state"))["need_time"]:
                    break
                await asyncio.sleep(0.02)
            assert (await master.request(READ, CLASS_1)).iin1 & IIN1_NEED_TIME
            await master.close()

    async def test_with_no_interval_the_time_is_not_asked_for_again(self):
        async with Bench(time_sync_interval=None) as bench:
            master = await bench.master()
            body = bytes.fromhex("32 01 07 01") + (1_800_000_000_000).to_bytes(6, "little")
            await master.request(WRITE, body)
            await asyncio.sleep(0.2)
            assert not (await master.request(READ, CLASS_1)).iin1 & IIN1_NEED_TIME
            await master.close()

    async def test_it_says_that_an_analog_input_keeps_one_event(self):
        async with Bench(need_time=False) as bench:
            assert (await bench.ask("state"))["analog_events_latest_only"] is True
            await bench.ask("set", changes=[["AI", 0, 100], ["AI", 0, 200]])
            master = await bench.master()
            assert [(e.index, e.value) for e in (await master.request(READ, CLASS_3)).of(32)] == [
                (0, 200)
            ]
            await master.close()


@pytest.mark.asyncio
class TestPowerCycle:
    async def test_it_drops_the_connection_and_listens_again_on_the_same_port(self):
        async with Bench() as bench:
            master = await bench.master()
            await master.request(READ, CLASS_1)
            port = bench.device.port
            state = await bench.ask("power_cycle")
            assert state["power_cycles"] == 1
            assert state["port"] == port
            assert await master.closed_by_peer()
            again = await bench.master()
            assert (await again.request(READ, CLASS_1)).iin1 & IIN1_RESTART
            await again.close()

    async def test_it_loses_events_and_output_states_and_keeps_the_inputs(self):
        async with Bench(need_time=False) as bench:
            master = await bench.master()
            await master.request(DIRECT_OPERATE, LATCH_ON_2)
            await bench.ask("set", changes=[["BI", 0, True], ["AI", 1, 500], ["CTR", 0, 9]])
            assert (await master.request(READ, CLASS_3)).iin1 & IIN1_CLASS_1
            await master.close()

            state = await bench.ask("power_cycle")
            assert state["events_held"] == {"1": 0, "2": 0, "3": 0}
            assert state["binary_outputs"]["2"] is False
            assert (state["binary"]["0"], state["analog"]["1"], state["counters"]["0"]) == (
                True,
                500,
                9,
            )
            # What was operated before stays on record, marked with the power cycle it was in.
            assert [o["power_cycle"] for o in state["operated"]] == [0]

            again = await bench.master()
            fragment = await again.request(READ, CLASS_1 + CLASS_2 + CLASS_3)
            assert not fragment.body
            assert not fragment.iin1 & IIN1_CLASS_1
            await again.close()

    async def test_it_applies_the_settings_given(self):
        async with Bench() as bench:
            state = await bench.ask(
                "power_cycle",
                settings={
                    "unsolicited": True,
                    "unsolicited_confirm_timeout": 2,
                    "unsolicited_retries": 3,
                    "max_response": 1100,
                    "need_time": False,
                },
            )
            assert state["settings"]["unsolicited"] is True
            assert state["settings"]["unsolicited_confirm_timeout"] == 2
            assert state["settings"]["unsolicited_retries"] == 3
            facts = bench.device.session.facts
            assert facts.unsolicited is True
            assert facts.unsolicited_confirm_timeout == 2
            assert facts.unsolicited_retries == 3
            assert facts.max_response == 1100
            assert facts.asks_for_time is False

    async def test_unsolicited_reporting_sends_an_enabled_class_without_a_poll(self):
        async with Bench(need_time=False, unsolicited=True) as bench:
            master = await bench.master()
            announcement = await master.fragment()
            assert announcement.uns and not announcement.body
            await master.confirm(announcement)
            # Function 20, enable unsolicited responses, for class 1.
            assert (await master.request(20, CLASS_1)).is_null
            assert (await bench.ask("state"))["unsolicited_classes"] == [1]
            await bench.ask("set", changes=[["BI", 3, True]])
            report = await master.fragment()
            assert report.uns
            assert [(e.index, e.state) for e in report.of(2)] == [(3, True)]
            await master.confirm(report)
            await master.close()

    async def test_uninstalled_binary_inputs_are_not_served(self):
        async with Bench() as bench:
            state = await bench.ask("power_cycle", settings={"binary_inputs": False})
            assert state["installed"]["BI"] == []
            master = await bench.master()
            fragment = await master.request(READ, BINARY_INPUTS)
            assert fragment.iin2 & IIN2_OBJECT_UNKNOWN and not fragment.body
            assert not (await master.request(READ, CLASS_0)).of(1)
            await master.close()

    async def test_a_changed_master_address_is_the_one_answered(self):
        async with Bench() as bench:
            await bench.ask("power_cycle", settings={"master_address": 2})
            old = await bench.master(source=MASTER)
            old._send(bytes([0xC0, READ]) + CLASS_1)  # pylint: disable=protected-access
            await old.writer.drain()
            with pytest.raises(TimeoutError):
                await old.fragment(timeout=0.5)
            await old.close()
            new = await bench.master(source=2)
            assert (await new.request(READ, CLASS_1)).function == 0x81
            await new.close()

    @pytest.mark.parametrize(
        ("settings", "message"),
        [
            ({"no_such_setting": 1}, "settings has no 'no_such_setting'"),
            ({"unsolicited": "yes"}, "settings.unsolicited is 'yes'"),
            ({"max_response": 1100.5}, "settings.max_response is 1100.5"),
            ({"unsolicited_retries": True}, "settings.unsolicited_retries is True"),
            ({"time_sync_interval": 0}, "settings.time_sync_interval is 0"),
        ],
    )
    async def test_a_wrong_setting_is_refused_and_power_is_not_cycled(self, settings, message):
        async with Bench() as bench:
            answer = await bench.send(
                json.dumps({"op": "power_cycle", "settings": settings}).encode()
            )
            assert answer["ok"] is False
            assert message in answer["error"]
            assert (await bench.ask("state"))["power_cycles"] == 0

    async def test_a_cold_restart_request_cycles_power_after_it_is_answered(self):
        async with Bench() as bench:
            master = await bench.master()
            fragment = await master.request(COLD_RESTART)
            (delay,) = fragment.objects
            assert (delay.group, delay.variation) == (52, 2)
            assert delay.value == fixture.RESTART_DELAY_MS
            assert await master.closed_by_peer()
            for _ in range(100):
                if bench.device.power_cycles == 1:
                    break
                await asyncio.sleep(0.05)
            state = await bench.ask("state")
            assert state["power_cycles"] == 1
            assert state["restart_indication"] is True


@pytest.mark.asyncio
class TestTheTestBench:
    async def test_quality_sets_the_flags_an_input_reports(self):
        async with Bench() as bench:
            await bench.ask("quality", kind="BI", index=0, quality="comm-lost")
            master = await bench.master()
            inputs = (await master.request(READ, BINARY_INPUTS)).of(1)
            assert inputs[0].flags & 0x7F == 0x04
            assert all(o.flags & 0x7F == 0x01 for o in inputs[1:])
            await bench.ask("quality", kind="BI", index=0, quality="good")
            assert (await master.request(READ, BINARY_INPUTS)).of(1)[0].flags & 0x7F == 0x01
            await master.close()

    async def test_quality_sets_the_flags_an_output_status_reports(self):
        async with Bench() as bench:
            await bench.ask("quality", kind="BO", index=1, quality="comm-lost")
            master = await bench.master()
            outputs = (await master.request(READ, BINARY_OUTPUTS)).of(10)
            assert outputs[1].flags & 0x7F == 0x04
            assert outputs[0].flags & 0x7F == 0x01
            await master.close()

    async def test_cold_restart_turned_off_is_refused_without_a_power_cycle(self):
        async with Bench() as bench:
            master = await bench.master()
            await bench.ask("cold_restart", enabled=False)
            refused = await master.request(COLD_RESTART)
            assert refused.iin2 & IIN2_BAD_FUNCTION and not refused.objects
            await bench.ask("cold_restart", enabled=True)
            (delay,) = (await master.request(COLD_RESTART)).objects
            assert delay.value == fixture.RESTART_DELAY_MS
            await master.close()

    async def test_freeze_gives_every_counter_a_frozen_value(self):
        async with Bench() as bench:
            await bench.ask("set", changes=[["CTR", 0, 7], ["CTR", 1, 9]])
            assert (await bench.ask("state"))["frozen"] == {}
            assert (await bench.ask("freeze"))["frozen"] == len(fixture.COUNTERS)
            state = await bench.ask("state")
            assert state["frozen"] == state["counters"]
            master = await bench.master()
            frozen = (await master.request(READ, FROZEN_COUNTERS)).of(21)
            assert [(o.index, o.value) for o in frozen][:2] == [(0, 7), (1, 9)]
            await master.close()

    async def test_the_clock_is_unsynchronized_some_time_after_the_time_is_written(self):
        async with Bench(time_sync_interval=None, time_valid_for=0.05) as bench:
            master = await bench.master()
            await master.request(WRITE, TIME_WRITE)
            await bench.ask("set", changes=[["BI", 0, True]])
            assert [o.variation for o in (await master.request(READ, CLASS_1)).of(51)] == []
            await asyncio.sleep(0.2)
            await bench.ask("set", changes=[["BI", 0, False]])
            ctos = (await master.request(READ, CLASS_1)).of(51)
            assert [o.variation for o in ctos] == [2], "an unsynchronized common time"
            await master.close()

    async def test_network_moves_the_outstation_to_another_port_and_back(self):
        async with Bench() as bench:
            first = bench.device.port
            moved = await bench.ask("network", port=0, udp_broadcast=False)
            assert moved["port"] != first
            assert moved["settings"]["udp_broadcast"] is False
            master = await Master.connect(moved["port"])
            assert (await master.request(READ, CLASS_1)).iin1 & IIN1_RESTART
            await master.close()
            restored = await bench.ask("network")
            assert restored["settings"]["udp_broadcast"] is True


@pytest.mark.asyncio
class TestTheChannelItself:
    @pytest.mark.parametrize(
        ("line", "message"),
        [
            (b"not json", "the request is not JSON"),
            (b"[1, 2]", "a request is a JSON object with an 'op'"),
            (b'{"op": 7}', "a request is a JSON object with an 'op'"),
            (b'{"op": "launch"}', "unknown operation 'launch'"),
            (b'{"op": "set"}', "'changes' is a list"),
            (b'{"op": "set", "changes": [], "pause_ms": -1}', "'pause_ms' is a number"),
            (b'{"op": "power_cycle", "settings": []}', "'settings' is an object"),
        ],
    )
    async def test_a_bad_request_is_answered_with_an_error_and_the_channel_stays_open(
        self, line, message
    ):
        async with Bench() as bench:
            answer = await bench.send(line)
            assert answer["ok"] is False
            assert message in answer["error"]
            assert (await bench.ask("state"))["power_cycles"] == 0

    async def test_stop_ends_the_wait_the_script_sits_in(self):
        async with Bench() as bench:
            assert not bench.channel.stopped.is_set()
            await bench.ask("stop")
            assert bench.channel.stopped.is_set()


def test_the_script_prints_its_control_port_and_exits_when_told():
    """Run the fixture as the harness's plugin does: as a process, found by one line of output."""
    process = subprocess.Popen(
        [sys.executable, "-u", str(_FIXTURE), "--port", "0"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
    )
    try:
        assert process.stdout is not None
        line = process.stdout.readline().strip()
        prefix = f"control channel listening on {HOST}:"
        assert line.startswith(prefix), line
        port = int(line.removeprefix(prefix))

        async def stop() -> dict[str, Any]:
            reader, writer = await asyncio.open_connection(HOST, port)
            writer.write(b'{"op": "state"}\n{"op": "stop"}\n')
            await writer.drain()
            state: dict[str, Any] = json.loads(await asyncio.wait_for(reader.readline(), 10.0))
            assert json.loads(await asyncio.wait_for(reader.readline(), 10.0)) == {"ok": True}
            writer.close()
            return state

        state = asyncio.run(stop())
        assert state["ok"] and state["port"] > 0
        assert process.wait(timeout=20) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
