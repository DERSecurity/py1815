"""Write the exchange to a capture file, without a packet capture tool.

The parser jobs need a pcap. The obvious way to get one is ``tcpdump`` on the
loopback interface, which needs root, and needs the capture to be running
before the first octet and still running after the last -- a race whose failure
mode is an empty file and a job that passes because there was nothing to
disagree with.

Writing it here instead removes both problems. The sweep already holds every
octet it sent and received, in order, so the capture is a record of the
exchange rather than an observation of it, and it is byte-identical from one
run to the next.

What that trades away is TCP-level fidelity: the segment boundaries here are
one segment per DNP3 exchange rather than whatever the kernel chose on the day.
The parsers under test reassemble the stream before looking at DNP3 either way,
so what they are being asked about is unaffected, but a bug that lived purely
in how the outstation's writes land in segments would not show up in this file.

Checksums are computed properly because Suricata verifies them and drops
packets that fail, which would otherwise look like a parser that had no
objection to the traffic.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

#: Ethernet, which every tool reads without being told the link type.
LINKTYPE_ETHERNET = 1

_ETHERTYPE_IPV4 = 0x0800
_PROTO_TCP = 6

_FIN = 0x01
_SYN = 0x02
_ACK = 0x10
_PSH = 0x18  # PSH|ACK, which is what a write with data looks like


def _checksum(data: bytes) -> int:
    """The one's-complement sum IP and TCP both use."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


@dataclass
class _Endpoint:
    ip: str
    port: int
    mac: bytes
    sequence: int = 1


@dataclass
class Capture:
    """The exchange, accumulated as packets and written out at the end."""

    client_ip: str = "127.0.0.1"
    server_ip: str = "127.0.0.1"
    client_port: int = 41000
    server_port: int = 20000
    _packets: list[tuple[float, bytes]] = field(default_factory=list)
    _clock: float = 1_758_600_000.0

    def __post_init__(self) -> None:
        self._client = _Endpoint(self.client_ip, self.client_port, b"\x02\x00\x00\x00\x00\x01")
        self._server = _Endpoint(self.server_ip, self.server_port, b"\x02\x00\x00\x00\x00\x02")

    # -- the three things a caller does ------------------------------------
    def open(self) -> None:
        """The handshake, so the stream engines have a session to track."""
        self._emit(self._client, self._server, _SYN, b"")
        self._client.sequence += 1
        self._emit(self._server, self._client, _SYN | _ACK, b"")
        self._server.sequence += 1
        self._emit(self._client, self._server, _ACK, b"")

    def sent(self, payload: bytes) -> None:
        """Octets the master put on the wire."""
        if payload:
            self._emit(self._client, self._server, _PSH, payload)
            self._client.sequence += len(payload)

    def received(self, payload: bytes) -> None:
        """Octets the outstation put on the wire."""
        if payload:
            self._emit(self._server, self._client, _PSH, payload)
            self._server.sequence += len(payload)

    def close(self) -> None:
        self._emit(self._client, self._server, _FIN | _ACK, b"")
        self._client.sequence += 1
        self._emit(self._server, self._client, _FIN | _ACK, b"")
        self._server.sequence += 1
        self._emit(self._client, self._server, _ACK, b"")

    def write(self, path: str) -> int:
        """Write the capture; returns the number of packets in it."""
        with open(path, "wb") as handle:
            handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, LINKTYPE_ETHERNET))
            for timestamp, packet in self._packets:
                seconds = int(timestamp)
                microseconds = round((timestamp - seconds) * 1_000_000)
                handle.write(struct.pack("<IIII", seconds, microseconds, len(packet), len(packet)))
                handle.write(packet)
        return len(self._packets)

    # -- packet construction -----------------------------------------------
    def _emit(self, source: _Endpoint, destination: _Endpoint, flags: int, payload: bytes) -> None:
        tcp = self._tcp(source, destination, flags, payload)
        ip = self._ipv4(source, destination, tcp)
        ethernet = destination.mac + source.mac + struct.pack("!H", _ETHERTYPE_IPV4)
        self._clock += 0.001
        self._packets.append((self._clock, ethernet + ip + tcp))

    def _tcp(self, source: _Endpoint, destination: _Endpoint, flags: int, payload: bytes) -> bytes:
        header = struct.pack(
            "!HHIIBBHHH",
            source.port,
            destination.port,
            source.sequence,
            destination.sequence if flags & _ACK else 0,
            5 << 4,  # data offset: five 32-bit words, no options
            flags,
            65535,
            0,  # checksum, filled in below
            0,
        )
        pseudo = (
            ipaddress.IPv4Address(source.ip).packed
            + ipaddress.IPv4Address(destination.ip).packed
            + struct.pack("!BBH", 0, _PROTO_TCP, len(header) + len(payload))
        )
        checksum = _checksum(pseudo + header + payload)
        return header[:16] + struct.pack("!H", checksum) + header[18:] + payload

    def _ipv4(self, source: _Endpoint, destination: _Endpoint, tcp: bytes) -> bytes:
        header = struct.pack(
            "!BBHHHBBH4s4s",
            (4 << 4) | 5,
            0,
            20 + len(tcp),
            0,
            0x4000,  # don't fragment
            64,
            _PROTO_TCP,
            0,  # checksum, filled in below
            ipaddress.IPv4Address(source.ip).packed,
            ipaddress.IPv4Address(destination.ip).packed,
        )
        return header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
