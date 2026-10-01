"""IED certification procedures, section 9: network communication.

The tests for TCP as the main communication method, carried out against a real
listener on the loopback interface. The device does not use UDP as a main
method, so of the UDP procedures only the one a TCP device is subject to
applies: a broadcast arriving as a datagram.
"""

from __future__ import annotations

import asyncio
import socket

import pytest
from ied_harness import (
    FREEZE,
    IIN1_BROADCAST,
    READ,
    Dut,
    Fragment,
    classes,
    header,
)

from py1815 import link
from py1815.server import DEFAULT_PORT, OutstationServer
from py1815.transport import Reassembler

HOST = "127.0.0.1"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((HOST, 0))
        return int(probe.getsockname()[1])


class Connection:
    """A master's side of one TCP connection."""

    def __init__(self, dut: Dut, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.dut = dut
        self.reader = reader
        self.writer = writer
        self.frames = link.FrameReader()
        self.sequence = 0

    @classmethod
    async def open(cls, dut: Dut, port: int, *, source_port: int | None = None) -> Connection:
        local = (HOST, source_port) if source_port is not None else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(HOST, port, local_addr=local), 5.0
        )
        return cls(dut, reader, writer)

    async def link_status(self) -> list[int]:
        self.writer.write(self.dut.master.frame(0xC9))
        await self.writer.drain()
        data = await asyncio.wait_for(self.reader.read(4096), 5.0)
        return [frame.control for frame in self.frames.feed(data)]

    async def request(self, function: int, body: bytes) -> Fragment:
        fragment = bytes([0xC0 | self.sequence, function]) + body
        self.sequence = (self.sequence + 1) % 16
        self.writer.write(self.dut.master.frames(fragment))
        await self.writer.drain()
        reassembler = Reassembler()
        while True:
            data = await asyncio.wait_for(self.reader.read(4096), 5.0)
            assert data, "the outstation closed the connection"
            for frame in self.frames.feed(data):
                whole = reassembler.add(frame.payload)
                if whole is not None:
                    return Fragment(whole)

    async def close(self) -> None:
        self.writer.close()
        await self.writer.wait_closed()


async def _closed(server: OutstationServer) -> None:
    for _ in range(200):
        if not server.connected:
            return
        await asyncio.sleep(0.01)
    raise AssertionError("the outstation did not notice the connection close")


class TestTcp:
    def test_9_5_1_1_the_default_listen_port_is_20000(self):
        assert DEFAULT_PORT == 20000

    @pytest.mark.asyncio
    async def test_9_5_1_1_connections_are_accepted_from_any_source_port(self):
        dut = Dut()
        server = OutstationServer(dut.session, bind=f"{HOST}:0")
        await server.start()
        try:
            for source_port in (_free_port(), _free_port()):
                connection = await Connection.open(dut, server.port, source_port=source_port)
                assert await connection.link_status() in ([0x0B], [0x1B])
                await connection.close()
                await _closed(server)
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_9_5_1_2_a_configured_port_is_the_only_one_listened_on(self):
        dut = Dut()
        configured, other = _free_port(), _free_port()
        server = OutstationServer(dut.session, bind=f"{HOST}:{configured}")
        await server.start()
        try:
            with pytest.raises(OSError):
                await Connection.open(dut, other)
            connection = await Connection.open(dut, configured)
            assert await connection.link_status() in ([0x0B], [0x1B])
            await connection.close()
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_9_5_1_a_class_poll_is_answered_over_tcp(self):
        dut = Dut()
        server = OutstationServer(dut.session, bind=f"{HOST}:0")
        await server.start()
        try:
            connection = await Connection.open(dut, server.port)
            fragment = await connection.request(READ, classes(1, 2, 3, 0))
            assert fragment.of(30) and not fragment.is_error
            await connection.close()
        finally:
            await server.stop()


class TestBroadcastDatagram:
    async def _send(self, port: int, datagram: bytes) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=(HOST, port)
        )
        try:
            transport.sendto(datagram)
            # A datagram is not acknowledged; give the listener a moment to take it.
            await asyncio.sleep(0.2)
        finally:
            transport.close()

    @pytest.mark.asyncio
    async def test_9_5_1_5_a_broadcast_sent_as_a_datagram_while_using_tcp(self):
        dut = Dut()
        server = OutstationServer(dut.session, bind=f"{HOST}:0", broadcast_datagrams=True)
        await server.start()
        try:
            connection = await Connection.open(dut, server.port)
            before = await connection.request(READ, classes(1, 2, 3, 0))
            assert not before.iin1 & IIN1_BROADCAST
            freeze = bytes([0xC5, FREEZE]) + header(20, 0)
            await self._send(server.port, dut.master.frames(freeze, destination=0xFFFF))
            after = await connection.request(READ, classes(1, 2, 3, 0))
            assert after.iin1 & IIN1_BROADCAST
            assert not after.is_error
            assert [o.value for o in after.of(21)] == [5, 5, 5], "and the freeze was carried out"
            await connection.close()
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_9_5_1_5_a_datagram_that_is_not_a_broadcast_is_ignored(self):
        """Only a broadcast is taken from a datagram: nothing else could be answered there."""
        dut = Dut()
        server = OutstationServer(dut.session, bind=f"{HOST}:0", broadcast_datagrams=True)
        await server.start()
        try:
            freeze = bytes([0xC5, FREEZE]) + header(20, 0)
            await self._send(server.port, dut.master.frames(freeze))
            connection = await Connection.open(dut, server.port)
            after = await connection.request(READ, classes(1, 2, 3, 0))
            assert not after.iin1 & IIN1_BROADCAST
            assert not after.of(21), "nothing was frozen"
            await connection.close()
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_9_5_1_5_datagrams_are_not_listened_for_unless_asked(self):
        dut = Dut()
        server = OutstationServer(dut.session, bind=f"{HOST}:0")
        await server.start()
        try:
            freeze = bytes([0xC5, FREEZE]) + header(20, 0)
            await self._send(server.port, dut.master.frames(freeze, destination=0xFFFF))
            connection = await Connection.open(dut, server.port)
            after = await connection.request(READ, classes(1, 2, 3, 0))
            assert not after.iin1 & IIN1_BROADCAST
            await connection.close()
        finally:
            await server.stop()
