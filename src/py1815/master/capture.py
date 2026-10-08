"""Write DNP3 traffic to a pcap file, without a packet capture tool.

A capture is built from octets the caller already holds, in order: the master's
trace, or a script's record of what it sent and received. Each piece of
traffic becomes one TCP segment of an IPv4 connection carried in Ethernet,
which every dissector reads without being told the link type. A connection
opens with a three-way handshake and closes with an exchange of FIN segments,
so a stream engine has a session to track.

Writing it here instead of running ``tcpdump`` needs no root and has no race
between starting a capture and starting the traffic, whose failure mode is an
empty file. The cost is TCP fidelity: the segment boundaries are where the
caller put them, not where a kernel did, and no segment is lost, repeated or
acknowledged on its own. A dissector reassembles the stream before it reads
DNP3, so what it says about the DNP3 is unaffected.

IP and TCP checksums are computed, because Suricata verifies them and drops a
packet that fails, which would otherwise look like a parser with no objection
to the traffic.

The file format is the classic libpcap one: a 24-octet global header, then for
each packet a 16-octet record header and the packet. Every field is
little-endian, and times are in microseconds.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import ipaddress
import pathlib
import struct
from typing import BinaryIO

#: The magic number of a libpcap file with microsecond times.
MAGIC = 0xA1B2C3D4

#: Ethernet, which every tool reads without being told the link type.
LINKTYPE_ETHERNET = 1

#: The longest packet the file says it holds.
SNAPLEN = 0xFFFF

#: The registered DNP3 port, used where a capture does not know the real one.
DNP3_PORT = 20000

#: Where a capture starts its own clock when the caller gives no times:
#: a fixed instant, so a capture written twice is the same octets.
DEFAULT_START = 1_758_600_000.0

#: The longest payload one segment can carry, so that the whole packet, with
#: its Ethernet (14), IPv4 (20) and TCP (20) headers, fits in ``SNAPLEN``.
MAX_PAYLOAD = SNAPLEN - 54

Address = tuple[str, int]

_HEADER = struct.Struct("<IHHiIII")
_RECORD = struct.Struct("<IIII")

_ETHERTYPE_IPV4 = 0x0800
_PROTO_TCP = 6

_FIN = 0x01
_SYN = 0x02
_PSH = 0x08
_ACK = 0x10

#: Locally administered MAC addresses, one for each end.
_CLIENT_MAC = bytes.fromhex("020000000001")
_SERVER_MAC = bytes.fromhex("020000000002")


def checksum(data: bytes) -> int:
    """Return the one's-complement sum that IPv4 and TCP headers carry."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def global_header() -> bytes:
    """Return the 24 octets a pcap file starts with."""
    return _HEADER.pack(MAGIC, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET)


def microseconds(at: float) -> int:
    """Return a time in seconds since the epoch as whole microseconds."""
    return round(at * 1_000_000)


def record(at: int, packet: bytes) -> bytes:
    """Return a packet with the 16-octet record header that precedes it in a file.

    ``at`` is in microseconds since the epoch.
    """
    seconds, fraction = divmod(at, 1_000_000)
    return _RECORD.pack(seconds, fraction, len(packet), len(packet)) + packet


def ipv4(address: str | None) -> str | None:
    """Return ``address`` as dotted IPv4, or None when it is not an IPv4 address.

    An IPv4 address mapped into IPv6, as a dual-stack socket reports one, is
    returned as the IPv4 address it maps.
    """
    if address is None:
        return None
    try:
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv6Address):
        mapped = parsed.ipv4_mapped
        return None if mapped is None else str(mapped)
    return str(parsed)


class _End:
    """One end of a TCP connection: its address, port, MAC and next sequence number."""

    def __init__(self, address: Address, mac: bytes) -> None:
        ip, port = address
        if ipv4(ip) is None:
            raise ValueError(f"{ip!r} is not an IPv4 address")
        if not 0 <= port <= 0xFFFF:
            raise ValueError(f"{port} is not a TCP port")
        self.ip = ipaddress.IPv4Address(ipv4(ip)).packed
        self.port = port
        self.mac = mac
        self.sequence = 1


class Stream:
    """One TCP connection in a capture, from a client (the master) to a server.

    Make one with :meth:`Capture.stream`. Each method adds packets to the
    capture. ``at`` is the time of the packet in seconds since the epoch; when
    it is left out, the capture's own clock gives the time.
    """

    def __init__(self, capture: Capture, client: Address, server: Address) -> None:
        self._capture = capture
        self._client = _End(client, _CLIENT_MAC)
        self._server = _End(server, _SERVER_MAC)

    def open(self, at: float | None = None) -> None:
        """Add the three-way handshake."""
        self._emit(self._client, self._server, _SYN, b"", at)
        self._client.sequence += 1
        self._emit(self._server, self._client, _SYN | _ACK, b"", at)
        self._server.sequence += 1
        self._emit(self._client, self._server, _ACK, b"", at)

    def sent(self, payload: bytes, at: float | None = None) -> None:
        """Add octets the client sent, as one segment. Empty octets add nothing."""
        if payload:
            self._emit(self._client, self._server, _PSH | _ACK, payload, at)
            self._client.sequence += len(payload)

    def received(self, payload: bytes, at: float | None = None) -> None:
        """Add octets the server sent, as one segment. Empty octets add nothing."""
        if payload:
            self._emit(self._server, self._client, _PSH | _ACK, payload, at)
            self._server.sequence += len(payload)

    def close(self, at: float | None = None) -> None:
        """Add the client's FIN, the server's FIN and the client's last acknowledgment."""
        self._emit(self._client, self._server, _FIN | _ACK, b"", at)
        self._client.sequence += 1
        self._emit(self._server, self._client, _FIN | _ACK, b"", at)
        self._server.sequence += 1
        self._emit(self._client, self._server, _ACK, b"", at)

    def _emit(
        self, source: _End, destination: _End, flags: int, payload: bytes, at: float | None
    ) -> None:
        if len(payload) > MAX_PAYLOAD:
            raise ValueError(f"{len(payload)} octets do not fit in one segment")
        tcp = _tcp(source, destination, flags, payload)
        ip = _ipv4(source, destination, tcp)
        ethernet = destination.mac + source.mac + struct.pack("!H", _ETHERTYPE_IPV4)
        self._capture.add(ethernet + ip + tcp, at)


def _tcp(source: _End, destination: _End, flags: int, payload: bytes) -> bytes:
    header = struct.pack(
        "!HHIIBBHHH",
        source.port,
        destination.port,
        source.sequence,
        destination.sequence if flags & _ACK else 0,
        5 << 4,  # data offset: five 32-bit words, no options
        flags,
        65535,  # window
        0,  # checksum, filled in below
        0,  # urgent pointer
    )
    pseudo = (
        source.ip + destination.ip + struct.pack("!BBH", 0, _PROTO_TCP, len(header) + len(payload))
    )
    value = checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", value) + header[18:] + payload


def _ipv4(source: _End, destination: _End, tcp: bytes) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5,  # version 4, five 32-bit words, no options
        0,
        20 + len(tcp),
        0,  # identification
        0x4000,  # don't fragment
        64,  # time to live
        _PROTO_TCP,
        0,  # checksum, filled in below
        source.ip,
        destination.ip,
    )
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:]


class Capture:
    """Packets for a pcap file, kept in memory until :meth:`pcap` or :meth:`write`."""

    def __init__(self, *, start: float = DEFAULT_START) -> None:
        """
        Args:
            start: Where the capture's own clock starts. A packet added
                without a time is one millisecond after the packet before it.
        """
        self._packets: list[tuple[int, bytes]] = []
        # Whole microseconds, so a clock advanced a step at a time does not drift.
        self._clock = microseconds(start)

    def stream(
        self,
        *,
        client: Address = ("127.0.0.1", 41000),
        server: Address = ("127.0.0.1", DNP3_PORT),
    ) -> Stream:
        """Return a new TCP connection in this capture. Raises ``ValueError`` for an
        address that is not IPv4 or a port out of range."""
        return Stream(self, client, server)

    def add(self, packet: bytes, at: float | None = None) -> None:
        """Add one Ethernet frame, at ``at`` or at the capture's own next time."""
        if at is None:
            self._clock += 1000
        else:
            self._clock = microseconds(at)
        self._keep(self._clock, packet)

    def _keep(self, at: int, packet: bytes) -> None:
        self._packets.append((at, packet))

    @property
    def packets(self) -> int:
        """The number of packets added."""
        return len(self._packets)

    def pcap(self) -> bytes:
        """Return the whole file."""
        return global_header() + b"".join(record(at, packet) for at, packet in self._packets)

    def write(self, path: str | pathlib.Path) -> int:
        """Write the file to ``path`` and return the number of packets in it."""
        pathlib.Path(path).write_bytes(self.pcap())
        return len(self._packets)


class CaptureFile(Capture):
    """A capture written to a file as each packet is added.

    Each packet is flushed as it is written, so a process that is killed
    leaves a file that holds everything up to that point. Nothing is kept in
    memory.
    """

    def __init__(self, path: str | pathlib.Path, *, start: float = DEFAULT_START) -> None:
        """Create or truncate ``path`` and write the global header. Raises ``OSError``."""
        super().__init__(start=start)
        self.path = pathlib.Path(path)
        self._file: BinaryIO | None = self.path.open("wb")
        self._count = 0
        self._file.write(global_header())
        self._file.flush()

    def _keep(self, at: int, packet: bytes) -> None:
        if self._file is None:
            raise ValueError(f"the capture file {self.path} is closed")
        self._file.write(record(at, packet))
        self._file.flush()
        self._count += 1

    @property
    def packets(self) -> int:
        """The number of packets written."""
        return self._count

    def pcap(self) -> bytes:
        """Return the file as written so far."""
        if self._file is not None:
            self._file.flush()
        return self.path.read_bytes()

    def write(self, path: str | pathlib.Path) -> int:
        """Copy the file as written so far to ``path``."""
        pathlib.Path(path).write_bytes(self.pcap())
        return self._count

    def close(self) -> None:
        """Close the file. Adding a packet afterwards raises ``ValueError``."""
        if self._file is not None:
            self._file.close()
            self._file = None


__all__ = [
    "DNP3_PORT",
    "LINKTYPE_ETHERNET",
    "MAGIC",
    "Address",
    "Capture",
    "CaptureFile",
    "Stream",
    "checksum",
    "global_header",
    "ipv4",
    "microseconds",
    "record",
]
