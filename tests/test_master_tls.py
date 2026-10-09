"""The master over TLS, against this library's own TLS listener.

The listener requires a client certificate and checks it against an
allow-list (D8), so each test makes an authority, a certificate for the
outstation and one for the master, in a temporary directory.
"""

from __future__ import annotations

import asyncio
import json
import ssl
import threading

import pytest
import pytest_asyncio
from profile_fixtures import for_reference_der
from test_master_service import _ask

from py1815.master import Master, NotConnected, Outcome, Outstation, Tasks, cli
from py1815.master.config import ConfigError, MasterConfig
from py1815.master.service import Service
from py1815.master.tls import PASSWORD_VARIABLE, TlsSettings
from py1815.profile import der, load
from py1815.profile.model import Composition
from py1815.server import OutstationServer

# The certificates are made with cryptography, which is in the dev extra. A
# job that installs only pytest skips these tests.
pytest.importorskip("cryptography", reason="the TLS tests make their certificates with it")
from tls_fixtures import Authority, server_context

ASKED = Tasks.none()


class Pki:
    """An authority, the outstation's certificate, the master's, and a stranger's authority."""

    def __init__(self, directory) -> None:
        self.authority = Authority(directory)
        self.outstation = self.authority.issue("outstation.test", dns=("outstation.test",))
        self.master = self.authority.issue("master.test")
        self.stranger = Authority(directory, "another authority")

    def settings(self, **changes) -> TlsSettings:
        given = {
            "ca": str(self.authority.file),
            "certificate": str(self.master.certificate),
            "key": str(self.master.key),
            "server_name": "outstation.test",
        }
        return TlsSettings(**(given | changes))


@pytest.fixture
def pki(tmp_path) -> Pki:
    return Pki(tmp_path)


def _session():
    return der.build(load.resolve(for_reference_der(), Composition())).outstation.session()


@pytest_asyncio.fixture
async def listening(pki):
    server = OutstationServer(
        _session(),
        bind="127.0.0.1:0",
        ssl_context=server_context(pki.authority, pki.outstation),
        authorized_peers=frozenset({"master.test"}),
    )
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


class TestTheSettings:
    def test_a_key_needs_its_certificate(self):
        with pytest.raises(ValueError, match="give the certificate"):
            TlsSettings(key="master.key")

    def test_a_setting_that_does_not_exist_is_refused(self):
        with pytest.raises(ValueError, match=r"tls\.password is not a setting"):
            TlsSettings.from_mapping({"password": "secret"})

    @pytest.mark.parametrize("value", ["", 5])
    def test_a_path_is_text(self, value):
        with pytest.raises(ValueError, match=r"tls\.ca is a path"):
            TlsSettings(ca=value)

    def test_a_server_name_needs_tls(self):
        with pytest.raises(ValueError, match="give tls"):
            Outstation("lab", host="127.0.0.1", server_name="outstation.test")

    def test_an_encrypted_key_is_opened_with_the_password_from_the_environment(
        self, pki, monkeypatch
    ):
        locked = pki.authority.issue("locked.test", password=b"open sesame")
        settings = TlsSettings(certificate=str(locked.certificate), key=str(locked.key))
        monkeypatch.setenv(PASSWORD_VARIABLE, "open sesame")
        assert settings.context() is not None
        monkeypatch.setenv(PASSWORD_VARIABLE, "wrong")
        with pytest.raises(ssl.SSLError):
            settings.context()


class TestConnecting:
    @pytest.mark.asyncio
    async def test_an_integrity_poll_is_read_over_tls(self, pki, listening):
        settings = pki.settings()
        async with Master() as master:
            lab = await master.add(
                "lab",
                host="127.0.0.1",
                port=listening.port,
                tasks=ASKED,
                tls=settings.context(),
                server_name=settings.server_name,
            )
            poll = await lab.integrity_poll()
        assert poll.complete and len(lab.store) > 100

    @pytest.mark.asyncio
    async def test_the_outstation_is_checked_against_the_name_given(self, pki, listening):
        settings = pki.settings(server_name="somebody-else.test")
        async with Master() as master:
            with pytest.raises(OSError, match=r"(?i)certificate|hostname"):
                await master.add(
                    "lab",
                    host="127.0.0.1",
                    port=listening.port,
                    tls=settings.context(),
                    server_name=settings.server_name,
                )
            assert master.outstations == {}

    @pytest.mark.asyncio
    async def test_an_outstation_another_authority_signed_is_refused(self, pki, listening):
        settings = pki.settings(ca=str(pki.stranger.file))
        async with Master() as master:
            with pytest.raises(OSError, match=r"(?i)certificate"):
                await master.add(
                    "lab",
                    host="127.0.0.1",
                    port=listening.port,
                    tls=settings.context(),
                    server_name=settings.server_name,
                )

    @pytest.mark.asyncio
    async def test_a_master_with_no_certificate_is_refused_by_the_outstation(self, pki, listening):
        settings = pki.settings(certificate=None, key=None)
        async with Master() as master:
            try:
                lab = await master.add(
                    "lab",
                    host="127.0.0.1",
                    port=listening.port,
                    tasks=ASKED,
                    response_timeout=0.5,
                    reconnect=None,
                    tls=settings.context(),
                    server_name=settings.server_name,
                )
            except OSError:
                return  # Refused during the handshake.
            # With TLS 1.3 the listener refuses after the handshake has ended.
            try:
                poll = await lab.integrity_poll()
            except NotConnected:
                return
            assert poll.outcome is not Outcome.COMPLETE


class TestTheService:
    @pytest.mark.asyncio
    async def test_an_outstation_is_added_over_tls_and_says_so(self, pki, listening):
        service = Service()
        try:
            answer = await _ask(
                service,
                "add",
                name="lab",
                host="127.0.0.1",
                port=listening.port,
                manual=True,
                tls=pki.settings().describe(),
            )
            assert answer["ok"], answer
            assert answer["result"]["tls"] == pki.settings().describe()
            scan = await _ask(service, "scan", "lab", kind="class0")
            assert scan["result"]["outcome"] == "complete"
        finally:
            await service.close()

    @pytest.mark.asyncio
    async def test_a_file_that_cannot_be_read_is_a_mistake_in_the_request(self, pki, tmp_path):
        service = Service()
        try:
            answer = await _ask(
                service,
                "add",
                name="lab",
                host="127.0.0.1",
                tls={"ca": str(tmp_path / "absent.pem")},
            )
            assert answer["error"]["kind"] == "request"
            assert answer["error"]["message"].startswith("tls: ")
            answer = await _ask(service, "add", name="lab", host="127.0.0.1", tls="yes")
            assert answer["error"]["kind"] == "request"
            assert (await _ask(service, "status"))["result"]["outstations"] == []
        finally:
            await service.close()


class TestTheConfiguration:
    def test_an_outstation_entry_is_merged_with_the_default_and_null_is_plain(self):
        config = MasterConfig.from_mapping(
            {
                "defaults": {"tls": {"ca": "ca.pem", "certificate": "m.pem", "key": "m.key"}},
                "outstations": [
                    {"name": "a", "host": "h", "tls": {"server_name": "a.lab"}},
                    {"name": "b", "host": "h", "tls": None},
                ],
            }
        )
        first, second = config.outstations
        assert first.tls == TlsSettings("ca.pem", "m.pem", "m.key", "a.lab")
        assert second.tls is None
        params = first.add_params(allow_control=False)
        assert params["tls"]["server_name"] == "a.lab"
        described = config.describe()["outstations"]
        assert described[0]["tls"] == {"server_name": "a.lab"}
        assert described[1]["tls"] is None

    @pytest.mark.parametrize(
        ("given", "says"),
        [
            ("yes", "defaults.tls must be an object"),
            ({"pasword": "x"}, r"defaults.tls: tls.pasword is not a setting"),
            ({"key": "m.key"}, "give the certificate"),
        ],
    )
    def test_a_mistake_is_named_where_it_is(self, given, says):
        with pytest.raises(ConfigError, match=says):
            MasterConfig.from_mapping({"defaults": {"tls": given}})

    def test_the_flags_set_the_defaults_and_nothing_secret_is_printed(self, monkeypatch, capsys):
        monkeypatch.setenv(PASSWORD_VARIABLE, "never-printed")
        assert (
            cli.main(
                [
                    "config",
                    "--tls-ca",
                    "ca.pem",
                    "--tls-certificate",
                    "m.pem",
                    "--tls-key",
                    "m.key",
                    "--tls-server-name",
                    "lab.test",
                    "--read-retries",
                    "2",
                ]
            )
            == 0
        )
        printed = capsys.readouterr().out
        defaults = json.loads(printed)["defaults"]
        assert defaults["tls"] == {
            "ca": "ca.pem",
            "certificate": "m.pem",
            "key": "m.key",
            "server_name": "lab.test",
        }
        assert defaults["read_retries"] == 2
        assert "never-printed" not in printed


class _Served:
    """A TLS listener on a thread of its own, for a command to poll."""

    def __init__(self, pki: Pki) -> None:
        self._loop = asyncio.new_event_loop()
        self._server = OutstationServer(
            _session(),
            bind="127.0.0.1:0",
            ssl_context=server_context(pki.authority, pki.outstation),
            authorized_peers=frozenset({"master.test"}),
        )
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)

    def __enter__(self) -> int:
        self._thread.start()
        asyncio.run_coroutine_threadsafe(self._server.start(), self._loop).result(5)
        return self._server.port

    def __exit__(self, *_exc) -> None:
        asyncio.run_coroutine_threadsafe(self._server.stop(), self._loop).result(5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)
        self._loop.close()


def test_the_poll_command_reads_over_tls(pki, capsys):
    with _Served(pki) as port:
        status = cli.main(
            [
                "poll",
                "--port",
                str(port),
                "--tls-ca",
                str(pki.authority.file),
                "--tls-certificate",
                str(pki.master.certificate),
                "--tls-key",
                str(pki.master.key),
                "--tls-server-name",
                "outstation.test",
            ]
        )
    assert status == 0, capsys.readouterr().err
    assert "answered in" in capsys.readouterr().out
