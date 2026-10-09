"""Tests for a master that runs for days: bounded memory, rotated files, an audit log."""

from __future__ import annotations

import asyncio
import json
import logging
import struct

import pytest
import pytest_asyncio
from profile_fixtures import for_reference_der

from py1815 import link
from py1815.application import FunctionCode
from py1815.master import Master, MasterAssociation, cli, service
from py1815.master import requests as rq
from py1815.master.api import RetryReport
from py1815.master.capture import Capture, CaptureFile, global_header, rotated
from py1815.master.config import MasterConfig
from py1815.master.service import HttpServer, Service
from py1815.master.trace import DEFAULT_CAPACITY, RECEIVED, SENT, Recorder, Trace
from py1815.profile import der, load
from py1815.profile.model import Composition
from py1815.server import OutstationServer

SYN = 0x02


def _records(pcap: bytes) -> list[bytes]:
    """Split a pcap file into its packets, checking the header and every length."""
    assert pcap[:24] == global_header()
    packets, offset = [], 24
    while offset < len(pcap):
        _seconds, _fraction, captured, length = struct.unpack_from("<IIII", pcap, offset)
        assert captured == length
        packets.append(pcap[offset + 16 : offset + 16 + captured])
        offset += 16 + captured
    assert offset == len(pcap)
    return packets


def _flags(packet: bytes) -> int:
    return packet[47]


def _request() -> bytes:
    return MasterAssociation().request(FunctionCode.READ, rq.scan("class1"))


def _response() -> bytes:
    control = link.control_byte(
        from_master=False, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
    )
    return link.build(control, 1, 1024, bytes.fromhex("C0 C0 81 00 00"))


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        self.now += 0.5
        return self.now


@pytest.fixture
def simulation() -> der.Simulation:
    return der.build(load.resolve(for_reference_der(), Composition()))


# ------------------------------------------------------------- capture rotation


class TestCaptureRotation:
    def _fill(self, capture: CaptureFile, connections: int) -> None:
        """Write connections of 714 octets each, marking a boundary before each one."""
        for number in range(connections):
            capture.boundary()
            stream = capture.stream(client=("127.0.0.1", 41000 + number))
            stream.open()
            stream.sent(b"x" * 200)
            stream.close()

    def test_a_full_file_is_renamed_and_a_new_one_started(self, tmp_path):
        path = tmp_path / "master.pcap"
        capture = CaptureFile(path, max_bytes=700, keep=3)
        self._fill(capture, 3)
        capture.close()

        assert capture.generation == 2
        assert sorted(each.name for each in tmp_path.iterdir()) == [
            "master.1.pcap",
            "master.2.pcap",
            "master.pcap",
        ]
        for each in tmp_path.iterdir():
            assert len(_records(each.read_bytes())) == 7, each.name

    def test_only_keep_older_files_are_kept(self, tmp_path):
        path = tmp_path / "master.pcap"
        capture = CaptureFile(path, max_bytes=700, keep=2)
        self._fill(capture, 6)
        capture.close()
        assert sorted(each.name for each in tmp_path.iterdir()) == [
            "master.1.pcap",
            "master.2.pcap",
            "master.pcap",
        ]

    def test_newest_older_file_is_number_one(self, tmp_path):
        path = tmp_path / "master.pcap"
        capture = CaptureFile(path, max_bytes=700, keep=5)
        for number in range(3):
            capture.boundary()
            stream = capture.stream(client=("127.0.0.1", 42000 + number))
            stream.open()
            stream.sent(b"y" * 600)
        capture.close()
        newest_old = _records(rotated(path, 1).read_bytes())
        oldest = _records(rotated(path, 2).read_bytes())
        port = lambda packet: struct.unpack_from("!H", packet, 34)[0]  # noqa: E731
        assert port(newest_old[0]) == 42001 and port(oldest[0]) == 42000

    def test_older_files_beyond_keep_from_an_earlier_run_are_removed(self, tmp_path):
        path = tmp_path / "master.pcap"
        for number in (3, 4):
            rotated(path, number).write_bytes(global_header())
        capture = CaptureFile(path, max_bytes=700, keep=2)
        self._fill(capture, 2)
        capture.close()
        assert sorted(each.name for each in tmp_path.iterdir()) == [
            "master.1.pcap",
            "master.pcap",
        ]

    def test_an_empty_file_is_not_rotated_even_above_the_limit(self, tmp_path):
        capture = CaptureFile(tmp_path / "master.pcap", max_bytes=10)
        capture.boundary()
        assert capture.generation == 0, "the global header alone is over the limit"
        capture.close()

    def test_keep_zero_keeps_only_the_current_file(self, tmp_path):
        capture = CaptureFile(tmp_path / "master.pcap", max_bytes=700, keep=0)
        self._fill(capture, 4)
        capture.close()
        assert [each.name for each in tmp_path.iterdir()] == ["master.pcap"]

    def test_no_limit_never_rotates(self, tmp_path):
        capture = CaptureFile(tmp_path / "master.pcap")
        self._fill(capture, 20)
        capture.close()
        assert capture.generation == 0
        assert [each.name for each in tmp_path.iterdir()] == ["master.pcap"]

    def test_a_file_is_not_rotated_before_the_boundary(self, tmp_path):
        capture = CaptureFile(tmp_path / "master.pcap", max_bytes=100)
        stream = capture.stream()
        stream.open()
        stream.sent(b"z" * 500)
        assert capture.generation == 0, "the size is checked only at a boundary"
        capture.boundary()
        assert capture.generation == 1
        capture.boundary()
        assert capture.generation == 1, "an empty file is not rotated"
        capture.close()

    @pytest.mark.parametrize("options", [{"max_bytes": 0}, {"keep": -1}])
    def test_invalid_limits_are_rejected(self, tmp_path, options):
        with pytest.raises(ValueError):
            CaptureFile(tmp_path / "master.pcap", **options)

    def test_a_capture_in_memory_never_rotates(self):
        capture = Capture()
        capture.boundary()
        assert capture.generation == 0

    def test_closing_a_connection_from_a_rotated_file_writes_nothing_to_the_new_one(self, tmp_path):
        path = tmp_path / "master.pcap"
        capture = CaptureFile(path, max_bytes=200, keep=1)
        first, second = Trace(clock=Clock()), Trace(clock=Clock())
        quiet = Recorder(capture, first)
        busy = Recorder(capture, second)
        first.listeners.append(quiet.record)
        second.listeners.append(busy.record)
        first.reset(local=("192.0.2.1", 50001), peer=("192.0.2.2", 20000))
        second.reset(local=("192.0.2.1", 50002), peer=("192.0.2.3", 20000))
        first.record(SENT, _request())
        second.record(SENT, _request())  # the file is full, so this one starts a new file
        assert capture.generation == 1
        quiet.close()
        busy.close()
        capture.close()
        ports = [struct.unpack_from("!H", packet, 34)[0] for packet in _records(path.read_bytes())]
        assert 50001 not in ports and 50001 not in [
            struct.unpack_from("!H", packet, 36)[0] for packet in _records(path.read_bytes())
        ]

    def test_a_recorded_connection_starts_again_in_the_new_file(self, tmp_path):
        path = tmp_path / "master.pcap"
        trace = Trace(clock=Clock())
        capture = CaptureFile(path, max_bytes=200, keep=1)
        recorder = Recorder(capture, trace)
        trace.listeners.append(recorder.record)
        trace.reset(local=("192.0.2.1", 50001), peer=("192.0.2.2", 20000))

        trace.record(SENT, _request())
        trace.record(RECEIVED, _response())
        recorder.close()
        capture.close()

        assert capture.generation == 1
        old, new = _records(rotated(path, 1).read_bytes()), _records(path.read_bytes())
        assert _flags(old[0]) == SYN
        assert _flags(new[0]) == SYN, "the new file opens the connection again"
        assert len(new) == 3 + 1 + 3, "handshake, the response, and the FIN exchange"


# --------------------------------------------------------- slow subscribers


class TestSlowSubscribers:
    def test_a_subscriber_that_falls_behind_is_told_and_stays_subscribed(self):
        events = Service()
        queue = events.subscribe()
        for number in range(service.SUBSCRIBER_QUEUE + 5):
            events.publish({"event": "frame", "number": number})

        assert queue.qsize() <= service.SUBSCRIBER_QUEUE
        assert queue in events._subscribers
        lost = queue.get_nowait()
        assert lost == {"event": "lost", "dropped": service.SUBSCRIBER_QUEUE + 1}
        later = [queue.get_nowait()["number"] for _ in range(queue.qsize())]
        assert later == list(range(service.SUBSCRIBER_QUEUE + 1, service.SUBSCRIBER_QUEUE + 5))

    def test_the_lost_count_adds_up_over_several_overflows(self):
        events = Service()
        queue = events.subscribe()
        total = service.SUBSCRIBER_QUEUE * 3 + 7
        for number in range(total):
            events.publish({"event": "frame", "number": number})
        waiting = [queue.get_nowait() for _ in range(queue.qsize())]
        lost = waiting[0]
        assert lost["event"] == "lost"
        assert lost["dropped"] + len(waiting) - 1 == total, "every update is delivered or counted"

    def test_memory_stays_bounded_however_far_a_subscriber_lags(self):
        events = Service()
        queue = events.subscribe()
        for number in range(service.SUBSCRIBER_QUEUE * 3):
            events.publish({"event": "frame", "number": number})
        assert queue.qsize() <= service.SUBSCRIBER_QUEUE

    @pytest.mark.asyncio
    async def test_an_event_stream_that_stops_reading_is_closed(self, monkeypatch):
        monkeypatch.setattr(service, "STREAM_WRITE_TIMEOUT", 0.3)
        events = Service()
        http = HttpServer(events, bind="127.0.0.1:0")
        await http.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", http.port)
        try:
            writer.write(f"GET /events HTTP/1.1\r\nHost: 127.0.0.1:{http.port}\r\n\r\n".encode())
            await writer.drain()
            await reader.readuntil(b": connected\n\n")
            assert len(events._subscribers) == 1
            # Large updates fill the socket buffers while this client never reads.
            big = "x" * 250_000
            async with asyncio.timeout(15):
                while events._subscribers:
                    events.publish({"event": "frame", "data": big})
                    await asyncio.sleep(0.01)
        finally:
            writer.close()
            await http.stop()


# ---------------------------------------------------------- bounded buffers


class TestBoundedBuffers:
    @pytest.mark.asyncio
    async def test_the_trace_keeps_a_fixed_number_of_frames_over_a_long_run(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        try:
            async with Master() as master:
                lab = await master.add("lab", host="127.0.0.1", port=server.port)
                await lab.idle()
                while lab.trace.since()[-1].id <= DEFAULT_CAPACITY + 200:
                    await lab.scan("class1")
                kept = lab.trace.since()
        finally:
            await server.stop()
        assert len(kept) == DEFAULT_CAPACITY
        assert kept[-1].id - kept[0].id == DEFAULT_CAPACITY - 1

    def test_every_buffer_has_a_limit(self):
        """A buffer added without a limit would grow for as long as the master runs."""
        from py1815.master import api, store

        assert Trace().since.__self__._entries.maxlen == DEFAULT_CAPACITY
        assert store.Store()._events.maxlen == store.DEFAULT_EVENT_CAPACITY
        assert api.Outstation("x", host="127.0.0.1")._unsolicited.maxlen is not None
        assert Service().subscribe().maxsize == service.SUBSCRIBER_QUEUE


# ----------------------------------------------------------------- the log


class TestRetryReport:
    def test_the_first_failure_is_info_and_the_rest_debug_until_an_interval_passes(self):
        now = [0.0]
        report = RetryReport("lab", interval=3600, clock=lambda: now[0])
        levels = []
        for _ in range(720):  # an hour of attempts five seconds apart
            levels.append(report.failed(OSError("refused")))
            now[0] += 5
        levels.append(report.failed(OSError("refused")))

        assert levels[0] == logging.INFO
        assert set(levels[1:720]) == {logging.DEBUG}
        assert levels[720] == logging.INFO
        assert report.attempts == 721


class TestCommandAudit:
    @pytest_asyncio.fixture
    async def lab(self, simulation):
        server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await server.start()
        try:
            yield server
        finally:
            await server.stop()

    async def _add(self, events: Service, server: OutstationServer) -> None:
        answer = await events.handle(
            {"op": "add", "params": {"name": "lab", "host": "127.0.0.1", "port": server.port}}
        )
        assert answer["ok"], answer

    @pytest.mark.asyncio
    async def test_a_command_is_logged_with_its_points_and_result(self, lab, caplog):
        events = Service(allow_control=True)
        try:
            await self._add(events, lab)
            caplog.set_level(logging.INFO, logger="py1815.master.service")
            answer = await events.handle(
                {"op": "operate", "outstation": "lab", "params": {"points": {"ao": {"87": 30}}}}
            )
            assert answer["ok"]
        finally:
            await events.close()
        (line,) = [r.getMessage() for r in caplog.records if "command operate" in r.getMessage()]
        assert "to lab" in line and '"87":30' in line and line.endswith(": accepted")

    @pytest.mark.asyncio
    async def test_every_point_of_a_large_command_is_logged(self, lab, caplog):
        events = Service(allow_control=True)
        try:
            await self._add(events, lab)
            caplog.set_level(logging.INFO, logger="py1815.master.service")
            points = {str(index): False for index in range(100)}
            await events.handle(
                {"op": "operate", "outstation": "lab", "params": {"points": {"bo": points}}}
            )
        finally:
            await events.close()
        (line,) = [r.getMessage() for r in caplog.records if "command operate" in r.getMessage()]
        assert all(f'"{index}":false' in line for index in range(100))

    @pytest.mark.asyncio
    async def test_automatic_writes_are_logged(self, lab, caplog):
        caplog.set_level(logging.INFO, logger="py1815.master.api")
        events = Service(allow_control=True)
        try:
            await self._add(events, lab)
            await events.handle({"op": "idle", "outstation": "lab"})
        finally:
            await events.close()
        lines = [r.getMessage() for r in caplog.records]
        assert "dnp3 master: automatic clear_restart to lab: complete" in lines
        assert "dnp3 master: automatic write_time to lab: complete" in lines

    @pytest.mark.asyncio
    async def test_a_refused_command_is_logged_as_a_warning(self, lab, caplog):
        events = Service()
        try:
            await self._add(events, lab)
            caplog.set_level(logging.INFO, logger="py1815.master.service")
            answer = await events.handle({"op": "write_time", "outstation": "lab", "params": {}})
            assert answer["error"]["kind"] == "not_allowed"
        finally:
            await events.close()
        refused = [r for r in caplog.records if "refused write_time for lab" in r.getMessage()]
        assert refused and refused[0].levelno == logging.WARNING

    @pytest.mark.asyncio
    async def test_a_read_is_not_logged_as_a_command(self, lab, caplog):
        events = Service(allow_control=True)
        try:
            await self._add(events, lab)
            caplog.set_level(logging.INFO, logger="py1815.master.service")
            await events.handle({"op": "scan", "outstation": "lab", "params": {}})
            await events.handle(
                {"op": "request", "outstation": "lab", "params": {"function": "READ"}}
            )
        finally:
            await events.close()
        assert not [r for r in caplog.records if "command " in r.getMessage()]


class TestLogFile:
    @pytest.fixture(autouse=True)
    def _restore_logging(self):
        root = logging.getLogger()
        handlers, level = list(root.handlers), root.level
        yield
        for handler in list(root.handlers):
            root.removeHandler(handler)
            handler.close()
        for handler in handlers:
            root.addHandler(handler)
        root.setLevel(level)

    def test_the_log_file_rotates_at_its_size_and_keeps_its_count(self, tmp_path):
        config = MasterConfig.from_mapping(
            {"log_file": str(tmp_path / "master.log"), "log_max_mb": 0.002, "log_keep": 2}
        )
        handler = cli.configure_logging(config, verbose=False)
        assert handler is not None
        for number in range(200):
            logging.getLogger("py1815.master.test").info("line %d %s", number, "x" * 40)
        handler.flush()
        names = sorted(each.name for each in tmp_path.iterdir())
        assert names == ["master.log", "master.log.1", "master.log.2"]
        assert all(each.stat().st_size <= 2_100 for each in tmp_path.iterdir())

    def test_the_file_takes_its_level_and_the_terminal_stays_at_warning(self, tmp_path):
        path = tmp_path / "master.log"
        config = MasterConfig.from_mapping({"log_file": str(path), "log_level": "info"})
        handler = cli.configure_logging(config, verbose=False)
        assert handler is not None
        terminal = [h for h in logging.getLogger().handlers if h is not handler]
        assert [h.level for h in terminal] == [logging.WARNING]
        logging.getLogger("py1815.master.test").debug("not written")
        logging.getLogger("py1815.master.test").info("written")
        handler.flush()
        text = path.read_text(encoding="utf-8")
        assert "written" in text and "not written" not in text

    def test_no_log_file_is_terminal_only(self):
        assert cli.configure_logging(MasterConfig.from_mapping({}), verbose=True) is None
        (terminal,) = logging.getLogger().handlers
        assert terminal.level == logging.INFO

    def test_the_settings_come_from_flags_and_the_file(self, tmp_path):
        path = tmp_path / "master.json"
        path.write_text(json.dumps({"log_file": "a.log", "log_keep": 9}), encoding="utf-8")
        args = cli._parser().parse_args(
            [
                "serve",
                "--config",
                str(path),
                "--log-file",
                "b.log",
                "--log-max-mb",
                "3",
                "--log-level",
                "debug",
                "--capture-max-mb",
                "50",
                "--capture-keep",
                "4",
            ]
        )
        config = cli.configuration(args)
        assert (config.log_file, config.log_keep, config.log_max_mb, config.log_level) == (
            "b.log",
            9,
            3.0,
            "debug",
        )
        assert (config.capture_max_mb, config.capture_keep) == (50.0, 4)

    @pytest.mark.asyncio
    async def test_the_capture_file_is_opened_with_the_configured_rotation(self, tmp_path):
        config = MasterConfig.from_mapping(
            {"capture": str(tmp_path / "master.pcap"), "capture_max_mb": 2.5, "capture_keep": 3}
        )
        made = cli._service(config)
        assert made is not None and made.capture_file is not None
        try:
            assert (made.capture_file.max_bytes, made.capture_file.keep) == (2_500_000, 3)
        finally:
            await made.close()

    @pytest.mark.parametrize(
        "document, says",
        [
            ({"log_level": "verbose"}, "log_level must be one of debug, info, warning"),
            ({"log_max_mb": 0}, "log_max_mb must be greater than 0"),
            ({"capture_max_mb": "big"}, "capture_max_mb must be a number of megabytes"),
            ({"capture_keep": -1}, "capture_keep must be a whole number from 0 to 1000"),
            ({"log_keep": 0}, "log_keep must be a whole number from 1 to 1000"),
            ({"log_file": ""}, "log_file must be a non-empty string"),
        ],
    )
    def test_invalid_settings_are_rejected(self, document, says):
        with pytest.raises(ValueError, match=says):
            MasterConfig.from_mapping(document)
