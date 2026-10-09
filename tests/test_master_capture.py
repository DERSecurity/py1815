"""The capture writer, the trace's export to it, and the ways a caller gets a capture.

The file format is pinned to octets worked out by hand from the libpcap file
format, RFC 791 and RFC 793, checksums included. A test that wrote a file
with this module and read it back with this module would agree with itself
through a swapped field or a checksum computed over the wrong octets.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import itertools
import struct

import pytest
import pytest_asyncio
from profile_fixtures import for_reference_der

from py1815 import link
from py1815.application import FunctionCode
from py1815.master import MasterAssociation, cli
from py1815.master import requests as rq
from py1815.master.capture import (
    MAX_PAYLOAD,
    Capture,
    CaptureFile,
    checksum,
    global_header,
    ipv4,
    record,
)
from py1815.master.config import ConfigError, MasterConfig
from py1815.master.service import Service
from py1815.master.trace import RECEIVED, SENT, Recorder, Trace
from py1815.profile import der, load
from py1815.profile.model import Composition
from py1815.server import OutstationServer

#: The global header: magic a1b2c3d4 little-endian, version 2.4, no time zone
#: offset, no accuracy, a snapshot length of 65535, link type 1 (Ethernet).
GLOBAL_HEADER = bytes.fromhex("d4c3b2a1 0200 0400 00000000 00000000 ffff0000 01000000")

#: The SYN from 192.0.2.1:41000 to 192.0.2.2:20000 at 1000.001 s, as a record.
SYN_RECORD = bytes.fromhex(
    # record header: 1000 s, 1000 us, 54 octets captured, 54 on the wire
    "e8030000 e8030000 36000000 36000000"
    # Ethernet: to the server's MAC, from the client's, IPv4
    "020000000002 020000000001 0800"
    # IPv4: version 4, 20-octet header, total length 40, don't fragment, TTL 64,
    # TCP, header checksum 0xb6cc, source and destination
    "4500 0028 0000 4000 4006 b6cc c0000201 c0000202"
    # TCP: ports 41000 and 20000, sequence 1, no acknowledgment, 20-octet
    # header, SYN, window 65535, checksum 0x3d95, no urgent pointer
    "a028 4e20 00000001 00000000 5002 ffff 3d95 0000"
)

#: The first two octets of a DNP3 frame, sent by the client after the handshake.
DATA_RECORD = bytes.fromhex(
    "e8030000 a00f0000 38000000 38000000"
    "020000000002 020000000001 0800"
    "4500 002a 0000 4000 4006 b6ca c0000201 c0000202"
    # sequence 2 after the SYN, acknowledging the server's 2, PSH and ACK
    "a028 4e20 00000002 00000002 5018 ffff 3816 0000"
    "0564"
)


def _records(pcap: bytes) -> list[tuple[int, bytes]]:
    """Split a pcap file into (microseconds, packet), read with ``struct`` alone."""
    assert pcap[:24] == GLOBAL_HEADER
    found, offset = [], 24
    while offset < len(pcap):
        seconds, fraction, captured, length = struct.unpack_from("<IIII", pcap, offset)
        assert captured == length
        found.append((seconds * 1_000_000 + fraction, pcap[offset + 16 : offset + 16 + captured]))
        offset += 16 + captured
    assert offset == len(pcap)
    return found


def _segment(packet: bytes) -> dict:
    """Read the addresses, ports, flags, numbers and payload of a packet."""
    source, destination = packet[26:30], packet[30:34]
    sport, dport, sequence, acknowledged, _offset, flags = struct.unpack_from("!HHIIBB", packet, 34)
    return {
        "client": f"{'.'.join(map(str, source))}:{sport}",
        "server": f"{'.'.join(map(str, destination))}:{dport}",
        "flags": flags,
        "sequence": sequence,
        "acknowledged": acknowledged,
        "payload": packet[54:],
    }


def _verifies(packet: bytes) -> bool:
    """Whether both checksums of a packet verify, summed here independently."""

    def ones(data: bytes) -> int:
        data += b"\x00" * (len(data) % 2)
        total = sum(int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2))
        while total > 0xFFFF:
            total = (total & 0xFFFF) + (total >> 16)
        return total

    ip, tcp = packet[14:34], packet[34:]
    pseudo = ip[12:20] + bytes([0, 6]) + len(tcp).to_bytes(2, "big")
    return ones(ip) == 0xFFFF and ones(pseudo + tcp) == 0xFFFF


class TestTheFileFormat:
    def test_the_file_starts_with_the_libpcap_global_header(self):
        assert global_header() == GLOBAL_HEADER
        assert Capture().pcap() == GLOBAL_HEADER

    def test_a_handshake_opens_with_a_syn_pinned_to_its_octets(self):
        capture = Capture(start=1000.0)
        stream = capture.stream(client=("192.0.2.1", 41000), server=("192.0.2.2", 20000))
        stream.open()
        assert capture.pcap()[24 : 24 + len(SYN_RECORD)] == SYN_RECORD

    def test_a_segment_carries_its_octets_after_the_handshake(self):
        capture = Capture(start=1000.0)
        stream = capture.stream(client=("192.0.2.1", 41000), server=("192.0.2.2", 20000))
        stream.open()
        stream.sent(b"\x05\x64")
        assert capture.pcap()[-len(DATA_RECORD) :] == DATA_RECORD
        assert capture.packets == 4

    def test_a_time_is_split_into_seconds_and_microseconds_without_overflow(self):
        # 1.9999996 s rounds up to 2 s and 0 us, never to 1 s and 1000000 us.
        assert record(1_999_999 + 1, b"")[:8] == bytes.fromhex("02000000 00000000")
        capture = Capture()
        capture.add(b"\x00", at=1.9999996)
        assert capture.pcap()[24:32] == bytes.fromhex("02000000 00000000")

    def test_the_captures_own_clock_steps_one_millisecond_exactly(self):
        capture = Capture(start=1_758_600_000.0)
        for _ in range(5000):
            capture.add(b"\x00")
        times = [at for at, _ in _records(capture.pcap())]
        assert times[0] == 1_758_600_000_001_000
        assert times[-1] == 1_758_600_005_000_000
        assert {later - earlier for earlier, later in itertools.pairwise(times)} == {1000}

    def test_the_checksum_is_the_ones_complement_sum(self):
        # RFC 1071, section 3: the words 0001 f203 f4f5 f6f7 sum to ddf2.
        assert checksum(bytes.fromhex("0001f203f4f5f6f7")) == 0xFFFF - 0xDDF2
        assert checksum(b"\x01") == 0xFEFF, "an odd octet is padded with a zero"


class TestAConnection:
    def test_each_packet_continues_the_numbering_of_the_one_before(self):
        capture = Capture()
        stream = capture.stream()
        stream.open()
        stream.sent(b"abc")
        stream.received(b"defgh")
        stream.sent(b"")  # adds nothing
        stream.close()
        segments = [_segment(packet) for _, packet in _records(capture.pcap())]
        assert [(s["flags"], s["sequence"], s["acknowledged"]) for s in segments] == [
            (0x02, 1, 0),  # SYN
            (0x12, 1, 2),  # SYN, ACK
            (0x10, 2, 2),  # ACK
            (0x18, 2, 2),  # PSH, ACK: 3 octets
            (0x18, 2, 5),  # PSH, ACK: 5 octets
            (0x11, 5, 7),  # FIN, ACK from the client
            (0x11, 7, 6),  # FIN, ACK from the server
            (0x10, 6, 8),  # ACK
        ]
        assert all(_verifies(packet) for _, packet in _records(capture.pcap()))

    def test_a_received_segment_goes_from_the_server_to_the_client(self):
        capture = Capture()
        capture.stream(client=("10.0.0.1", 50000), server=("10.0.0.2", 20001)).received(b"x")
        (packet,) = [packet for _, packet in _records(capture.pcap())]
        assert packet[:12] == bytes.fromhex("020000000001 020000000002")
        segment = _segment(packet)
        assert (segment["client"], segment["server"]) == ("10.0.0.2:20001", "10.0.0.1:50000")

    def test_a_payload_that_would_exceed_the_snapshot_length_is_refused(self):
        capture = Capture()
        stream = capture.stream()
        stream.sent(b"\x00" * MAX_PAYLOAD)
        ((_, packet),) = _records(capture.pcap())
        assert len(packet) == 65535, "the longest packet fills the snapshot length exactly"
        with pytest.raises(ValueError, match="do not fit"):
            stream.sent(b"\x00" * (MAX_PAYLOAD + 1))

    @pytest.mark.parametrize(
        ("client", "says"),
        [(("::1", 1), "not an IPv4 address"), (("127.0.0.1", 70000), "not a TCP port")],
    )
    def test_an_address_that_cannot_be_written_is_refused(self, client, says):
        with pytest.raises(ValueError, match=says):
            Capture().stream(client=client)

    @pytest.mark.parametrize(
        ("given", "read"),
        [
            ("192.0.2.7", "192.0.2.7"),
            ("::ffff:192.0.2.7", "192.0.2.7"),
            ("::1", None),
            ("fe80::1%3", None),
            ("localhost", None),
            (None, None),
        ],
    )
    def test_an_address_is_read_as_ipv4_where_it_is_one(self, given, read):
        assert ipv4(given) == read


class TestAFile:
    def test_each_packet_is_on_disk_as_soon_as_it_is_added(self, tmp_path):
        path = tmp_path / "live.pcap"
        written = CaptureFile(path, start=1000.0)
        try:
            assert path.read_bytes() == GLOBAL_HEADER
            stream = written.stream(client=("192.0.2.1", 41000), server=("192.0.2.2", 20000))
            stream.open()
            assert path.read_bytes()[24 : 24 + len(SYN_RECORD)] == SYN_RECORD
            assert written.packets == 3
        finally:
            written.close()

    def test_it_holds_what_the_same_capture_in_memory_holds(self, tmp_path):
        kept, written = Capture(), CaptureFile(tmp_path / "a.pcap")
        for capture in (kept, written):
            stream = capture.stream()
            stream.open()
            stream.sent(b"\x05\x64\x05")
            stream.close()
        written.close()
        assert (tmp_path / "a.pcap").read_bytes() == kept.pcap() == written.pcap()
        assert kept.write(tmp_path / "b.pcap") == 7
        assert (tmp_path / "b.pcap").read_bytes() == kept.pcap()

    def test_a_closed_file_takes_no_more_packets(self, tmp_path):
        written = CaptureFile(tmp_path / "a.pcap")
        written.close()
        written.close()
        with pytest.raises(ValueError, match="closed"):
            written.add(b"\x00")

    def test_an_empty_capture_is_still_a_capture(self):
        """A capture with no packets is not false, so ``if capture`` cannot skip one."""
        assert Capture()
        assert Capture().packets == 0


# ---------------------------------------------------------------- the trace


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


class TestTheTraceAsACapture:
    def test_each_frame_is_one_segment_at_the_time_it_was_recorded(self):
        trace = Trace(clock=Clock())
        trace.reset(local=("192.0.2.1", 50123), peer=("192.0.2.2", 20000))
        trace.record(SENT, _request())
        trace.record(RECEIVED, _response())

        packets = _records(trace.capture())

        assert len(packets) == 3 + 2 + 3
        times = [at for at, _ in packets]
        assert times == [100_500_000] * 4 + [101_000_000] * 4
        segments = [_segment(packet) for _, packet in packets]
        assert segments[3]["payload"] == _request()
        assert segments[4]["payload"] == _response()
        assert segments[3]["client"] == "192.0.2.1:50123"
        assert segments[3]["server"] == "192.0.2.2:20000"
        assert [s["flags"] for s in segments[5:]] == [0x11, 0x11, 0x10]

    def test_each_connection_is_a_stream_of_its_own(self):
        trace = Trace(clock=Clock())
        trace.reset(local=("192.0.2.1", 50001), peer=("192.0.2.2", 20000))
        trace.record(SENT, _request())
        trace.reset(local=("192.0.2.1", 50002), peer=("192.0.2.2", 20000))
        trace.record(SENT, _request())

        segments = [_segment(packet) for _, packet in _records(trace.capture())]

        assert [s["flags"] for s in segments] == [0x02, 0x12, 0x10, 0x18, 0x11, 0x11, 0x10] * 2
        assert {s["client"] for s in segments[:7]} | {s["server"] for s in segments[:7]} == {
            "192.0.2.1:50001",
            "192.0.2.2:20000",
        }
        assert segments[10]["client"] == "192.0.2.1:50002"
        assert segments[10]["sequence"] == 2, "a new connection numbers its octets afresh"

    def test_a_frame_recorded_before_any_connection_is_given_placeholder_addresses(self):
        trace = Trace()
        trace.record(SENT, _request())
        segment = _segment(_records(trace.capture(port=20005))[3][1])
        assert (segment["client"], segment["server"]) == ("127.0.0.1:41000", "127.0.0.1:20005")

    def test_an_ipv6_connection_keeps_its_ports_and_is_written_as_ipv4(self):
        trace = Trace()
        trace.reset(local=("::1", 50999), peer=("::1", 20000))
        trace.record(SENT, _request())
        segment = _segment(_records(trace.capture())[3][1])
        assert (segment["client"], segment["server"]) == ("127.0.0.1:50999", "127.0.0.1:20000")

    def test_only_frames_after_an_id_are_exported_when_asked(self):
        trace = Trace()
        trace.reset(local=("192.0.2.1", 50001), peer=("192.0.2.2", 20000))
        (first,) = trace.record(SENT, _request())
        trace.record(RECEIVED, _response())
        segments = [_segment(packet) for _, packet in _records(trace.capture(after=first.id))]
        assert [s["payload"] for s in segments if s["payload"]] == [_response()]

    def test_an_empty_trace_is_a_file_with_no_packets(self):
        assert Trace().capture() == GLOBAL_HEADER

    def test_every_checksum_in_an_export_verifies(self):
        trace = Trace()
        trace.reset(local=("192.0.2.1", 50001), peer=("192.0.2.2", 20000))
        for _ in range(3):
            trace.record(SENT, _request())
            trace.record(RECEIVED, _response())
        assert all(_verifies(packet) for _, packet in _records(trace.capture()))

    def test_the_addresses_of_connections_no_frame_crossed_are_forgotten(self):
        trace = Trace()
        for port in range(50000, 50010):
            trace.reset(local=("192.0.2.1", port), peer=("192.0.2.2", 20000))
        trace.record(SENT, _request())
        trace.reset(local=("192.0.2.1", 50010), peer=("192.0.2.2", 20000))
        assert trace.endpoints(1) == (None, None)
        assert trace.endpoints(10) == (("192.0.2.1", 50009), ("192.0.2.2", 20000))
        trace.clear()
        trace.reset()
        assert trace.endpoints(10) == (None, None)


class TestLongRuns:
    def test_sequence_numbers_wrap_at_32_bits(self):
        capture = Capture()
        stream = capture.stream()
        stream.open()
        stream._client.sequence = 0xFFFFFFF0
        stream.sent(b"x" * 32)
        stream.sent(b"y")
        packets = [packet for _, packet in _records(capture.pcap())]
        assert _segment(packets[-2])["sequence"] == 0xFFFFFFF0
        assert _segment(packets[-1])["sequence"] == 0x10
        assert all(_verifies(packet) for packet in packets)

    def test_connections_with_no_frames_are_not_kept(self):
        trace = Trace(clock=Clock())
        trace.reset(local=("192.0.2.1", 50000), peer=("192.0.2.2", 20000))
        trace.record(SENT, _request())
        for port in range(50001, 50501):
            trace.reset(local=("192.0.2.1", port), peer=("192.0.2.2", 20000))
        assert len(trace._endpoints) == 2, "the connection a frame crossed, and the current one"
        assert trace.endpoints(1) == (("192.0.2.1", 50000), ("192.0.2.2", 20000))


class TestARecorder:
    def test_a_listener_writes_each_frame_as_it_is_recorded(self, tmp_path):
        trace = Trace(clock=Clock())
        written = CaptureFile(tmp_path / "live.pcap")
        recorder = Recorder(written, trace)
        trace.listeners.append(recorder.record)
        trace.reset(local=("192.0.2.1", 50001), peer=("192.0.2.2", 20000))

        trace.record(SENT, _request())
        assert written.packets == 4, "the handshake and the frame, before the response"
        trace.record(RECEIVED, _response())
        recorder.close()
        written.close()

        assert (tmp_path / "live.pcap").read_bytes() == trace.capture()

    def test_the_old_connection_is_closed_when_a_new_one_starts(self):
        trace = Trace(clock=Clock())
        capture = Capture()
        recorder = Recorder(capture, trace)
        trace.listeners.append(recorder.record)
        trace.reset(local=("192.0.2.1", 50001), peer=("192.0.2.2", 20000))
        trace.record(SENT, _request())
        trace.reset(local=("192.0.2.1", 50002), peer=("192.0.2.2", 20000))
        trace.record(SENT, _request())

        flags = [_segment(packet)["flags"] for _, packet in _records(capture.pcap())]
        assert flags == [0x02, 0x12, 0x10, 0x18, 0x11, 0x11, 0x10, 0x02, 0x12, 0x10, 0x18]
        times = [at for at, _ in _records(capture.pcap())]
        assert times[4:7] == [times[3]] * 3, "closed at the time of its last frame"


# ----------------------------------------------------- the service and CLI


@pytest_asyncio.fixture
async def outstation():
    """A simulated DER listening on this machine."""
    simulation = der.build(load.resolve(for_reference_der(), Composition()))
    server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


async def _add(service: Service, server: OutstationServer) -> None:
    answer = await service.handle(
        {
            "op": "add",
            "params": {"name": "lab", "host": "127.0.0.1", "port": server.port, "manual": True},
        }
    )
    assert answer["ok"], answer


class TestTheService:
    @pytest.mark.asyncio
    async def test_the_capture_operation_returns_the_trace_as_a_pcap_file(self, outstation):
        service = Service()
        try:
            await _add(service, outstation)
            await service.handle({"op": "scan", "outstation": "lab", "params": {"kind": "class1"}})
            answer = await service.handle({"op": "capture", "outstation": "lab"})
            trace = service.master["lab"].trace
        finally:
            await service.close()

        assert answer["ok"], answer
        assert answer["result"]["frames"] == len(trace) == 2
        pcap = base64.b64decode(answer["result"]["pcap"])
        assert pcap == trace.capture(port=outstation.port)
        segments = [_segment(packet) for _, packet in _records(pcap)]
        assert segments[3]["server"] == f"127.0.0.1:{outstation.port}"
        assert [s["payload"] for s in segments if s["payload"]] == [
            entry.octets for entry in trace.since()
        ]

    @pytest.mark.asyncio
    async def test_a_connection_is_written_between_the_ports_the_socket_used(self, outstation):
        service = Service()
        try:
            await _add(service, outstation)
            await service.handle({"op": "scan", "outstation": "lab", "params": {"kind": "class1"}})
            trace = service.master["lab"].trace
            local, peer = trace.endpoints(1)
            answer = await service.handle({"op": "capture", "outstation": "lab"})
        finally:
            await service.close()
        assert peer == ("127.0.0.1", outstation.port)
        assert local is not None and local[0] == "127.0.0.1"
        segment = _segment(_records(base64.b64decode(answer["result"]["pcap"]))[3][1])
        assert segment["client"] == f"127.0.0.1:{local[1]}"

    @pytest.mark.asyncio
    async def test_a_service_that_only_reads_still_exports_a_capture(self, outstation):
        service = Service(allow_control=False)
        try:
            await _add(service, outstation)
            answer = await service.handle({"op": "capture", "outstation": "lab"})
        finally:
            await service.close()
        assert answer["ok"] and answer["result"]["frames"] == 0

    @pytest.mark.asyncio
    async def test_a_capture_file_receives_every_frame_and_is_closed_with_the_service(
        self, outstation, tmp_path
    ):
        path = tmp_path / "master.pcap"
        service = Service(capture=CaptureFile(path))
        try:
            await _add(service, outstation)
            await service.handle({"op": "scan", "outstation": "lab", "params": {"kind": "class1"}})
            assert len(_records(path.read_bytes())) == 5, "written as the frames crossed"
            trace = service.master["lab"].trace
        finally:
            await service.close()

        assert path.read_bytes() == trace.capture(port=outstation.port)
        assert [_segment(p)["flags"] for _, p in _records(path.read_bytes())][-3:] == [
            0x11,
            0x11,
            0x10,
        ]

    @pytest.mark.asyncio
    async def test_a_removed_outstations_connection_is_closed_in_the_file(
        self, outstation, tmp_path
    ):
        path = tmp_path / "master.pcap"
        service = Service(capture=CaptureFile(path))
        try:
            await _add(service, outstation)
            await service.handle({"op": "scan", "outstation": "lab", "params": {"kind": "class1"}})
            await service.handle({"op": "remove", "outstation": "lab"})
            flags = [_segment(packet)["flags"] for _, packet in _records(path.read_bytes())]
        finally:
            await service.close()
        assert flags[-3:] == [0x11, 0x11, 0x10]

    @pytest.mark.asyncio
    async def test_a_capture_file_that_fails_stops_the_capture_and_not_the_connection(
        self, outstation, tmp_path
    ):
        written = CaptureFile(tmp_path / "master.pcap")
        service = Service(capture=written)
        try:
            await _add(service, outstation)
            written.close()  # every later write fails
            answer = await service.handle(
                {"op": "scan", "outstation": "lab", "params": {"kind": "class1"}}
            )
            assert answer["ok"] and answer["result"]["outcome"] == "complete"
            again = await service.handle(
                {"op": "scan", "outstation": "lab", "params": {"kind": "class1"}}
            )
            assert again["ok"] and again["result"]["outcome"] == "complete"
        finally:
            await service.close()

    @pytest.mark.asyncio
    async def test_a_failed_capture_stops_for_every_outstation_and_removal_still_works(
        self, outstation, tmp_path
    ):
        written = CaptureFile(tmp_path / "master.pcap")
        service = Service(capture=written)
        # A second outstation of its own: one session serves one connection.
        simulation = der.build(load.resolve(for_reference_der(), Composition()))
        second = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        await second.start()
        try:
            await _add(service, outstation)
            answer = await service.handle(
                {
                    "op": "add",
                    "params": {
                        "name": "bench",
                        "host": "127.0.0.1",
                        "port": second.port,
                        "manual": True,
                    },
                }
            )
            assert answer["ok"], answer
            await service.handle({"op": "scan", "outstation": "lab", "params": {"kind": "class1"}})
            written._file.close()  # the disk fails under an open file
            await service.handle({"op": "scan", "outstation": "lab", "params": {"kind": "class1"}})

            listeners = [len(service.master[name].trace.listeners) for name in ("lab", "bench")]
            assert listeners == [1, 1], "only the console's listener is left on each trace"
            removed = await service.handle({"op": "remove", "outstation": "lab"})
            assert removed["ok"], removed
        finally:
            await service.close()
            await second.stop()


class TestTheCommandLine:
    def test_the_capture_file_is_a_setting_and_a_flag(self, tmp_path):
        parser = cli._parser()
        for command in ("console", "serve", "config"):
            assert cli.configuration(parser.parse_args([command])).capture is None
            given = parser.parse_args([command, "--capture", "a.pcap"])
            assert cli.configuration(given).capture == "a.pcap"
        assert MasterConfig.from_mapping({"capture": "b.pcap"}).capture == "b.pcap"
        assert MasterConfig.from_mapping({"capture": None}).capture is None
        with pytest.raises(ConfigError, match="capture"):
            MasterConfig.from_mapping({"capture": 5})

    def test_the_flag_overrides_the_file(self, tmp_path):
        path = tmp_path / "master.json"
        path.write_text('{"capture": "from-file.pcap"}', encoding="utf-8")
        args = cli._parser().parse_args(["serve", "--config", str(path)])
        assert cli.configuration(args).capture == "from-file.pcap"
        args = cli._parser().parse_args(
            ["serve", "--config", str(path), "--capture", "from-flag.pcap"]
        )
        assert cli.configuration(args).capture == "from-flag.pcap"

    @pytest.mark.asyncio
    async def test_serve_writes_every_frame_to_the_file_it_was_given(
        self, outstation, tmp_path, capsys
    ):
        path = tmp_path / "serve.pcap"
        args = cli._parser().parse_args(
            [
                "serve",
                "--bind",
                "127.0.0.1:0",
                "--capture",
                str(path),
                "--outstation",
                f"lab=127.0.0.1:{outstation.port}",
            ]
        )
        running = asyncio.create_task(cli.run_service(args))
        try:
            async with asyncio.timeout(10):
                while "listening on" not in (printed := capsys.readouterr().out):
                    await asyncio.sleep(0.05)
            assert f"writing every frame to {path}" in printed
            async with asyncio.timeout(10):
                while len(_records(path.read_bytes())) < 3:
                    await asyncio.sleep(0.05)
        finally:
            running.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await running
        segments = [_segment(packet) for _, packet in _records(path.read_bytes())]
        assert [s["flags"] for s in segments[:3]] == [0x02, 0x12, 0x10]
        assert [s["flags"] for s in segments[-3:]] == [0x11, 0x11, 0x10], "closed on the way out"

    @pytest.mark.asyncio
    async def test_a_capture_file_that_cannot_be_made_stops_the_command(self, tmp_path, capsys):
        missing = tmp_path / "no such folder" / "a.pcap"
        for command in ("serve", "console"):
            args = cli._parser().parse_args(
                [command, "--bind", "127.0.0.1:0", "--capture", str(missing)]
            )
            run = cli.run_service if command == "serve" else cli.run_console
            assert await run(args) == 2
            assert "cannot write the capture file" in capsys.readouterr().err
