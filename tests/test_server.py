"""The listener: who may connect, who wins when two do, and when one is closed.

Authorization is tested against stub TLS objects rather than a live handshake.
The policy is what matters and it is pure -- which names and fingerprints a
certificate offers, and which of them the allow-list accepts -- so pinning it
needs no certificate authority and no sockets. The socket behavior is tested
over plaintext, where it is the same code path.
"""

from __future__ import annotations

import asyncio
import hashlib
import ssl

import pytest

from py1815 import link
from py1815.application import FunctionCode, QualifierCode
from py1815.server import (
    FINGERPRINT_PREFIX,
    OutstationServer,
    PeerRefused,
    authorize,
    peer_identities,
)
from py1815.session import Session

OUTSTATION = 1024
MASTER = 1

CLASS_0_READ = bytes([0xC0, FunctionCode.READ, 60, 1, QualifierCode.ALL_OBJECTS])
OBJECTS = bytes([30, 1, QualifierCode.UINT8_START_STOP, 0, 0, 0x01, 0x2A, 0x00, 0x00, 0x00])

DER = b"a certificate, as far as these tests are concerned"
FINGERPRINT = FINGERPRINT_PREFIX + hashlib.sha256(DER).hexdigest()


class StubTls:
    """The two methods the authorization path uses on an ``SSLObject``."""

    def __init__(self, common_name=None, dns=(), der=DER):
        self._cert = {}
        if common_name:
            self._cert["subject"] = ((("commonName", common_name),),)
        if dns:
            self._cert["subjectAltName"] = tuple(("DNS", name) for name in dns)
        self._der = der

    def getpeercert(self, binary_form=False):
        return self._der if binary_form else self._cert


class Provider:
    def read(self, headers):
        return OBJECTS


def _session() -> Session:
    return Session(Provider(), outstation_address=OUTSTATION, master_address=MASTER)


def _request() -> bytes:
    control = link.control_byte(
        from_master=True, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
    )
    return link.build(
        control, destination=OUTSTATION, source=MASTER, payload=b"\xc0" + CLASS_0_READ
    )


class TestPeerIdentities:
    def test_a_common_name_is_offered(self):
        assert "master.example" in peer_identities(StubTls(common_name="master.example"))

    def test_subject_alternative_names_are_offered(self):
        identities = peer_identities(StubTls(dns=("a.example", "b.example")))

        assert {"a.example", "b.example"} <= identities

    def test_the_fingerprint_is_offered(self):
        assert FINGERPRINT in peer_identities(StubTls(common_name="x"))

    def test_a_certificate_with_nothing_usable_offers_only_its_fingerprint(self):
        assert peer_identities(StubTls()) == {FINGERPRINT}


class TestAuthorize:
    def test_a_matching_common_name_is_admitted(self):
        assert authorize(StubTls(common_name="master.example"), frozenset({"master.example"}))

    def test_a_matching_fingerprint_is_admitted(self):
        assert authorize(StubTls(), frozenset({FINGERPRINT})) == FINGERPRINT

    def test_names_match_without_regard_to_case(self):
        """DNS is case-insensitive, so an allow-list that cared would refuse
        certificates that are the same certificate."""
        assert authorize(StubTls(common_name="Master.Example"), frozenset({"master.example"}))

    def test_a_fingerprint_is_matched_exactly(self):
        """Hex digest case is not a naming convention; a mismatch here is a
        different certificate or a typo, and both should be refused."""
        with pytest.raises(PeerRefused):
            authorize(StubTls(), frozenset({FINGERPRINT.upper()}))

    def test_an_unlisted_peer_is_refused(self):
        with pytest.raises(PeerRefused, match="none of which is allowed"):
            authorize(StubTls(common_name="other.example"), frozenset({"master.example"}))

    def test_a_wildcard_entry_does_not_match(self):
        """An allow-list whose entries match things nobody enumerated is not an
        allow-list."""
        with pytest.raises(PeerRefused):
            authorize(StubTls(common_name="master.example"), frozenset({"*.example"}))

    def test_an_empty_allow_list_refuses_everything(self):
        with pytest.raises(PeerRefused):
            authorize(StubTls(common_name="master.example"), frozenset())


class TestTlsConfiguration:
    def test_tls_without_an_allow_list_is_refused_at_construction(self):
        """Trusting the CA alone admits every certificate it ever issued."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.verify_mode = ssl.CERT_REQUIRED

        with pytest.raises(ValueError, match="requires authorized_peers"):
            OutstationServer(_session(), ssl_context=context)

    def test_tls_without_a_required_client_certificate_is_refused(self):
        """There would be no identity to check the allow-list against."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.verify_mode = ssl.CERT_NONE

        with pytest.raises(ValueError, match="CERT_REQUIRED"):
            OutstationServer(_session(), ssl_context=context, authorized_peers=frozenset({"a"}))

    def test_plaintext_needs_no_allow_list(self):
        assert OutstationServer(_session(), bind="127.0.0.1:0") is not None


@pytest.mark.asyncio
class TestServing:
    async def _started(self, session=None, **kwargs):
        server = OutstationServer(session or _session(), bind="127.0.0.1:0", **kwargs)
        await server.start()
        return server

    async def test_a_request_is_answered(self):
        server = await self._started()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            writer.write(_request())
            await writer.drain()
            reply = await asyncio.wait_for(reader.read(4096), timeout=5)
            writer.close()
        finally:
            await server.stop()

        frames = link.FrameReader().feed(reply)
        assert frames and frames[0].payload[1:][1] == FunctionCode.RESPONSE

    async def test_the_bound_port_is_reported(self):
        server = await self._started()
        try:
            assert server.port != 0
            assert server.running
        finally:
            await server.stop()

    async def test_a_second_connection_displaces_the_first(self):
        """Event and confirmation state belong to the association, and the usual
        cause of a second connection is a master whose socket died silently."""
        server = await self._started()
        try:
            first_reader, first = await asyncio.open_connection("127.0.0.1", server.port)
            await asyncio.sleep(0.05)
            second_reader, second = await asyncio.open_connection("127.0.0.1", server.port)

            # End of stream on the first connection is the observable fact that
            # the server let it go; the client's own transport may not have
            # noticed yet, so asserting on this side would test the event loop.
            assert await asyncio.wait_for(first_reader.read(4096), timeout=5) == b""

            second.write(_request())
            await second.drain()
            assert await asyncio.wait_for(second_reader.read(4096), timeout=5)
            first.close()
            second.close()
        finally:
            await server.stop()

    async def test_a_reconnection_keeps_association_state(self):
        """The restart indication a master has not cleared survives a socket
        that went away."""
        session = _session()
        server = await self._started(session)
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", server.port)
            await asyncio.sleep(0.05)
            writer.close()
            await asyncio.sleep(0.05)

            assert session.restart_indication
            reader2, writer2 = await asyncio.open_connection("127.0.0.1", server.port)
            writer2.write(_request())
            await writer2.drain()
            reply = await asyncio.wait_for(reader2.read(4096), timeout=5)
            writer2.close()
        finally:
            await server.stop()

        fragment = link.FrameReader().feed(reply)[0].payload[1:]
        assert fragment[2] & 0x80

    async def test_half_a_frame_from_a_dead_connection_is_not_completed(self):
        """Framing state is per socket. Completing it across connections would
        splice two conversations into one request."""
        session = _session()
        server = await self._started(session)
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", server.port)
            writer.write(_request()[:6])
            await writer.drain()
            await asyncio.sleep(0.05)
            writer.close()
            await asyncio.sleep(0.05)

            reader2, writer2 = await asyncio.open_connection("127.0.0.1", server.port)
            writer2.write(_request()[6:])
            await writer2.drain()
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(reader2.read(4096), timeout=0.3)
            writer2.close()
        finally:
            await server.stop()

    async def test_an_idle_connection_is_closed(self):
        server = await self._started(idle_timeout=0.2)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            assert await asyncio.wait_for(reader.read(4096), timeout=5) == b""
            writer.close()
        finally:
            await server.stop()

    async def test_stop_ends_a_connection_in_progress(self):
        """Closing the listener alone stops new connections and leaves an
        established one being served."""
        server = await self._started()
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        await asyncio.sleep(0.05)

        await server.stop()

        assert await asyncio.wait_for(reader.read(4096), timeout=5) == b""
        assert not server.running
        assert not server.connected
        writer.close()

    async def test_a_malformed_stream_does_not_kill_the_listener(self):
        server = await self._started()
        try:
            _, noise = await asyncio.open_connection("127.0.0.1", server.port)
            noise.write(b"\xff" * 512)
            await noise.drain()
            await asyncio.sleep(0.05)
            noise.close()

            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            writer.write(_request())
            await writer.drain()
            assert await asyncio.wait_for(reader.read(4096), timeout=5)
            writer.close()
        finally:
            await server.stop()
