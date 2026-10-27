"""Connection events and protocol anomalies, as a host application receives them.

The anomaly tests feed the session crafted frames and check the record each one
produces. The connection tests use real sockets on the loopback interface: the
outstation's listener against a client, and the master against a listener.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import ssl

import pytest
from ied_harness import (
    COLD_RESTART,
    CONFIRM,
    DIRECT_OPERATE,
    DIRECT_OPERATE_NR,
    OPERATE,
    READ,
    SELECT,
    UNSOLICITED_RESPONSE,
    Dut,
    analog_output,
    classes,
    crob,
)
from test_master_tcp import _free_port
from test_session_unsolicited_responses import TIMEOUT, _analog, _enabled, _said

from py1815 import link
from py1815.master import Outstation, Tasks
from py1815.observers import (
    SEVERITY,
    AnomalyCode,
    AnomalySeverity,
    ConnectionDirection,
    ConnectionEvent,
    ConnectionOutcome,
    ConnectionRole,
    ConnectionTransport,
    Endpoint,
    ProtocolAnomaly,
    RequestRecord,
)
from py1815.server import OutstationServer
from py1815.session import Session

OUTSTATION, MASTER = 1024, 1

#: Group 30 variation 1, one 32-bit analog input at index 0 with value 42.
OBJECTS = bytes([30, 1, 0x00, 0, 0, 0x01, 0x2A, 0x00, 0x00, 0x00])

#: A class 0 read: application control FIR FIN sequence 0, READ, group 60
#: variation 1, qualifier 0x06 (all objects).
CLASS_0_READ = bytes.fromhex("C0 01 3C 01 06")

#: Control octets, from the master: DIR and PRM set, then the function.
#: 0xC4 is unconfirmed user data (function 4) with FCV clear.
UNCONFIRMED_USER_DATA = 0xC4
#: 0xD4 is the same with the frame count valid bit set, which function 4 never has.
UNCONFIRMED_USER_DATA_WITH_FCV = 0xD4
#: 0xC9 is request link status (function 9), which carries no data.
REQUEST_LINK_STATUS = 0xC9

#: A transport header with FIN (0x80) and FIR (0x40) set, sequence 0: a whole
#: fragment.
WHOLE = b"\xc0"
#: A transport header with FIN set and FIR clear: the end of a series never
#: started.
CONTINUATION = b"\x80"

#: The broadcast address that asks for no confirmation.
BROADCAST = 0xFFFD


class Provider:
    def read(self, headers):
        return OBJECTS


def _session(**options) -> Session:
    options.setdefault("master_address", MASTER)
    return Session(Provider(), outstation_address=OUTSTATION, **options)


def _frame(
    control: int,
    payload: bytes,
    *,
    source: int = MASTER,
    destination: int = OUTSTATION,
) -> bytes:
    return link.build(control, destination=destination, source=source, payload=payload)


def _request(fragment: bytes = CLASS_0_READ, **addresses: int) -> bytes:
    return _frame(UNCONFIRMED_USER_DATA, WHOLE + fragment, **addresses)


def _observed(session: Session) -> list[ProtocolAnomaly]:
    seen: list[ProtocolAnomaly] = []
    session.anomaly_observer = seen.append
    return seen


async def _until(condition, *, timeout: float = 5.0) -> None:
    async def poll() -> None:
        while not condition():
            await asyncio.sleep(0.01)

    await asyncio.wait_for(poll(), timeout=timeout)


# ------------------------------------------------------------------ anomalies


class TestAnomalyCodes:
    def test_a_frame_from_another_master_address_is_reported_as_high(self):
        session = _session()
        seen = _observed(session)

        assert session.receive(_request(source=2)) == b""

        (anomaly,) = seen
        assert anomaly.code is AnomalyCode.UNEXPECTED_MASTER_ADDRESS
        assert anomaly.severity is AnomalySeverity.HIGH
        assert (anomaly.source, anomaly.destination) == (2, OUTSTATION)
        assert anomaly.message == "dropping frame from unexpected master address 2"

    def test_a_frame_from_the_outstations_own_address_is_reported_as_high(self):
        session = _session(master_address=None)
        seen = _observed(session)

        assert session.receive(_request(source=OUTSTATION)) == b""

        (anomaly,) = seen
        assert anomaly.code is AnomalyCode.INVALID_SOURCE_ADDRESS
        assert anomaly.severity is AnomalySeverity.HIGH
        assert anomaly.source == OUTSTATION

    def test_a_frame_count_valid_bit_on_unconfirmed_data_is_reported(self):
        session = _session()
        seen = _observed(session)

        assert session.receive(_frame(UNCONFIRMED_USER_DATA_WITH_FCV, WHOLE + CLASS_0_READ)) == b""

        (anomaly,) = seen
        assert anomaly.code is AnomalyCode.INVALID_FRAME_COUNT_VALID
        assert anomaly.severity is AnomalySeverity.MEDIUM
        assert anomaly.message == "dropping link function 4: frame count valid bit is True"

    def test_a_link_status_request_carrying_data_is_reported(self):
        session = _session()
        seen = _observed(session)

        assert session.receive(_frame(REQUEST_LINK_STATUS, b"\x00")) == b""

        (anomaly,) = seen
        assert anomaly.code is AnomalyCode.LINK_PAYLOAD_MISMATCH
        assert anomaly.severity is AnomalySeverity.MEDIUM
        assert anomaly.message == "dropping link function 9 carrying 1 octet(s)"

    def test_a_segment_continuing_no_series_is_a_transport_error(self):
        session = _session()
        seen = _observed(session)

        session.receive(_frame(UNCONFIRMED_USER_DATA, CONTINUATION + CLASS_0_READ))

        (anomaly,) = seen
        assert anomaly.code is AnomalyCode.TRANSPORT_ERROR
        assert anomaly.severity is AnomalySeverity.LOW
        assert (anomaly.source, anomaly.destination) == (MASTER, OUTSTATION)
        assert anomaly.message.startswith("transport error from 1: ")

    def test_a_broadcast_segment_continuing_no_series_is_a_broadcast_transport_error(self):
        session = _session()
        seen = _observed(session)

        session.receive(
            _frame(UNCONFIRMED_USER_DATA, CONTINUATION + CLASS_0_READ, destination=BROADCAST)
        )

        (anomaly,) = seen
        assert anomaly.code is AnomalyCode.BROADCAST_TRANSPORT_ERROR
        assert anomaly.severity is AnomalySeverity.LOW
        assert anomaly.destination == BROADCAST

    def test_a_broadcast_write_with_a_truncated_header_is_reported(self):
        session = _session()
        seen = _observed(session)

        # WRITE (0x02) followed by one octet of an object header.
        session.receive(_request(bytes.fromhex("C0 02 50"), destination=BROADCAST))

        (anomaly,) = seen
        assert anomaly.code is AnomalyCode.MALFORMED_BROADCAST_WRITE
        assert anomaly.severity is AnomalySeverity.MEDIUM
        assert anomaly.message.startswith("unreadable broadcast write dropped: ")

    def test_a_broadcast_read_is_reported_as_not_acted_on(self):
        session = _session()
        seen = _observed(session)

        session.receive(_request(destination=BROADCAST))

        (anomaly,) = seen
        assert anomaly.code is AnomalyCode.BROADCAST_NOT_ACTED_ON
        assert anomaly.severity is AnomalySeverity.INFO
        assert anomaly.message == "broadcast function 0x01 noted and not acted on"

    def test_a_broadcast_control_with_broadcast_controls_off_is_reported_as_not_acted_on(self):
        session = _session()
        seen = _observed(session)

        # DIRECT_OPERATE (0x05) of one CROB, group 12 variation 1, qualifier
        # 0x17, count 1, index 0: latch on, count 1, on and off times 0.
        crob = bytes.fromhex("C0 05 0C 01 17 01 00 03 01 00000000 00000000 00")
        session.receive(_request(crob, destination=BROADCAST))

        (anomaly,) = seen
        assert anomaly.code is AnomalyCode.BROADCAST_NOT_ACTED_ON
        assert anomaly.message == "broadcast control not operated: broadcast controls are off"

    def test_a_disabled_function_sent_as_a_broadcast_is_reported_as_not_acted_on(self):
        # Function 0x07 is IMMEDIATE_FREEZE.
        session = _session(disabled_functions=[0x07])
        seen = _observed(session)

        session.receive(_request(bytes.fromhex("C0 07 14 00 06"), destination=BROADCAST))

        (anomaly,) = seen
        assert anomaly.code is AnomalyCode.BROADCAST_NOT_ACTED_ON
        assert anomaly.message == "broadcast function 0x07 not acted on: disabled"

    def test_a_fragment_too_short_for_a_request_is_reported(self):
        session = _session()
        seen = _observed(session)

        assert session.receive(_request(b"\xc0")) == b""

        (anomaly,) = seen
        assert anomaly.code is AnomalyCode.NOT_A_REQUEST
        assert anomaly.severity is AnomalySeverity.MEDIUM
        assert (anomaly.source, anomaly.destination) == (MASTER, OUTSTATION)
        assert anomaly.message == "dropping a fragment that is not a request: c0"

    def test_a_read_with_a_truncated_object_header_is_reported(self):
        session = _session()
        seen = _observed(session)

        # READ of group 60 with the variation and qualifier missing. The
        # session still answers it, with a null response.
        assert session.receive(_request(bytes.fromhex("C0 01 3C"))) != b""

        (anomaly,) = seen
        assert anomaly.code is AnomalyCode.MALFORMED_REQUEST
        assert anomaly.severity is AnomalySeverity.MEDIUM
        assert anomaly.message.startswith("malformed request: ")

    def test_an_unsolicited_response_not_confirmed_after_its_retries_is_reported(self):
        session, buffers, clock = _enabled(
            outstation_address=OUTSTATION,
            master_address=MASTER,
            unsolicited_retries=1,
            unsolicited_resume=None,
        )
        seen = _observed(session)
        _analog(buffers, 0)
        _said(session)
        for _ in range(3):
            clock.now += TIMEOUT
            _said(session)

        (anomaly,) = seen
        assert anomaly.code is AnomalyCode.UNSOLICITED_NOT_CONFIRMED
        assert anomaly.severity is AnomalySeverity.LOW
        assert (anomaly.source, anomaly.destination) == (OUTSTATION, MASTER)
        assert anomaly.message.endswith("not confirmed after 1 retries; its events stay buffered")

    def test_every_code_has_a_severity(self):
        assert set(SEVERITY) == set(AnomalyCode)


class TestAnomalyDelivery:
    def test_a_well_formed_request_reports_nothing(self):
        session = _session()
        seen = _observed(session)

        assert session.receive(_request()) != b""

        assert seen == []

    def test_the_log_line_is_written_as_before(self, caplog):
        session = _session(anomaly_observer=lambda anomaly: None)

        with caplog.at_level(logging.WARNING, logger="py1815.session"):
            session.receive(_request(source=2))

        assert [record.getMessage() for record in caplog.records] == [
            "dnp3: dropping frame from unexpected master address 2"
        ]

    def test_an_observer_given_at_construction_is_called(self):
        seen: list[ProtocolAnomaly] = []
        session = _session(anomaly_observer=seen.append)

        session.receive(_request(source=2))

        assert [anomaly.code for anomaly in seen] == [AnomalyCode.UNEXPECTED_MASTER_ADDRESS]

    def test_the_connection_peer_is_reported(self):
        session = _session()
        seen = _observed(session)
        session.connection_peer = Endpoint("192.0.2.10", 49152)

        session.receive(_request(source=2))

        assert seen[0].peer == Endpoint("192.0.2.10", 49152)

    def test_a_broadcast_datagram_reports_its_sender_and_not_the_connection(self):
        session = _session()
        seen = _observed(session)
        session.connection_peer = Endpoint("192.0.2.10", 49152)

        session.receive_broadcast(
            _request(destination=BROADCAST), sender=Endpoint("198.51.100.7", 20000)
        )
        session.receive(_request(source=2))

        assert [anomaly.peer for anomaly in seen] == [
            Endpoint("198.51.100.7", 20000),
            Endpoint("192.0.2.10", 49152),
        ]

    def test_an_observer_that_raises_does_not_stop_the_session(self, caplog):
        def failing(anomaly: ProtocolAnomaly) -> None:
            raise RuntimeError("observer failed")

        session = _session(anomaly_observer=failing)

        with caplog.at_level(logging.DEBUG, logger="py1815.observers"):
            session.receive(_request(source=2))
            session.receive(_request(source=3))
            answer = session.receive(_request())

        assert answer != b"", "the next request is answered"
        errors = [record for record in caplog.records if record.levelno >= logging.ERROR]
        assert len(errors) == 1, "the first failure is logged and the second is not"

    def test_a_record_converts_to_plain_values(self):
        anomaly = ProtocolAnomaly(
            code=AnomalyCode.TRANSPORT_ERROR,
            severity=SEVERITY[AnomalyCode.TRANSPORT_ERROR],
            message="transport error from 1: segment is empty",
            source=1,
            destination=OUTSTATION,
            peer=Endpoint("192.0.2.10", 49152),
            timestamp=1.5,
        )

        assert dataclasses.asdict(anomaly) == {
            "code": "transport_error",
            "severity": "low",
            "message": "transport error from 1: segment is empty",
            "source": 1,
            "destination": OUTSTATION,
            "peer": {"host": "192.0.2.10", "port": 49152},
            "timestamp": 1.5,
        }


class TestEndpoint:
    def test_a_socket_name_gives_its_address_and_port(self):
        assert Endpoint.of(("192.0.2.1", 20000)) == Endpoint("192.0.2.1", 20000)

    def test_an_ipv6_socket_name_keeps_its_address(self):
        assert Endpoint.of(("2001:db8::1", 20000, 0, 0)) == Endpoint("2001:db8::1", 20000)

    def test_a_name_that_is_not_an_address_and_port_gives_none(self):
        assert Endpoint.of(None) is None
        assert Endpoint.of("/run/socket") is None

    def test_an_ipv6_endpoint_is_written_in_brackets(self):
        assert str(Endpoint("2001:db8::1", 20000)) == "[2001:db8::1]:20000"
        assert str(Endpoint("192.0.2.1", 20000)) == "192.0.2.1:20000"


# ------------------------------------------------------------------- requests

#: The connection the harness's requests are said to arrive on.
PEER = Endpoint("192.0.2.10", 49152)


def _dut(**options) -> Dut:
    """Return the harness outstation with binary inputs and outputs, past its restart."""
    dut = Dut(analog_inputs=False, counters=False, **options)
    dut.clear_restart()
    dut.session.connection_peer = PEER
    return dut


def _unsolicited_dut() -> Dut:
    """Return the harness outstation with unsolicited responses on, at its startup."""
    dut = Dut(analog_inputs=False, counters=False, unsolicited=True)
    dut.session.connection_peer = PEER
    return dut


def _records(session: Session) -> list[RequestRecord]:
    seen: list[RequestRecord] = []
    session.request_observer = seen.append
    return seen


class TestRequestRecords:
    def test_an_integrity_read_is_reported_with_its_response(self):
        dut = _dut()
        seen = _records(dut.session)

        dut.master.read(classes(1, 2, 3, 0))

        (record,) = seen
        assert (record.peer, record.source, record.destination) == (PEER, MASTER, OUTSTATION)
        assert record.function == READ
        # FIR FIN sequence 1, READ; group 60 variations 2, 3, 4 and 1, qualifier 0x06.
        assert record.request == bytes.fromhex("C1 01 3C 02 06 3C 03 06 3C 04 06 3C 01 06")
        # FIR FIN sequence 1, RESPONSE, no indications; group 1 variation 2,
        # qualifier 0x00, start 0, stop 3; four inputs, each flagged online.
        assert record.response == bytes.fromhex("C1 81 00 00 01 02 00 00 03 01 01 01 01")
        assert not record.unsolicited

    def test_a_direct_operate_of_an_analog_output_is_reported_with_its_echo(self):
        dut = _dut()
        seen = _records(dut.session)

        dut.master.request(DIRECT_OPERATE, analog_output(1, 250))

        (record,) = seen
        assert (record.peer, record.source, record.destination) == (PEER, MASTER, OUTSTATION)
        assert record.function == DIRECT_OPERATE
        # Group 41 variation 2, qualifier 0x17, one object: index 1, value 250, status 0.
        assert record.request == bytes.fromhex("C1 05 29 02 17 01 01 FA 00 00")
        assert record.response == bytes.fromhex("C1 81 00 00 29 02 17 01 01 FA 00 00")
        assert dut.operated == [("AO", 1, 250.0)]

    def test_a_select_and_its_operate_of_a_binary_output_are_reported_in_turn(self):
        dut = _dut()
        seen = _records(dut.session)

        dut.master.request(SELECT, crob(2))
        dut.master.request(OPERATE, crob(2))

        select, operate = seen
        # Group 12 variation 1, qualifier 0x17, one object: index 2, latch on,
        # count 1, on time 100 ms, off time 200 ms, status 0.
        block = "0C 01 17 01 02 03 01 64 00 00 00 C8 00 00 00 00"
        assert (select.function, operate.function) == (SELECT, OPERATE)
        assert select.request == bytes.fromhex(f"C1 03 {block}")
        assert select.response == bytes.fromhex(f"C1 81 00 00 {block}")
        assert operate.request == bytes.fromhex(f"C2 04 {block}")
        assert operate.response == bytes.fromhex(f"C2 81 00 00 {block}")
        assert {(record.peer, record.source, record.destination) for record in seen} == {
            (PEER, MASTER, OUTSTATION)
        }
        assert dut.operated == [("BO", 2, True)]

    def test_a_cold_restart_is_reported_with_its_time_delay(self):
        dut = _dut(restart_handler=lambda: 1500)
        seen = _records(dut.session)

        dut.master.request(COLD_RESTART)

        (record,) = seen
        assert (record.peer, record.source, record.destination) == (PEER, MASTER, OUTSTATION)
        assert record.function == COLD_RESTART
        assert record.request == bytes.fromhex("C1 0D")
        # Group 52 variation 2, qualifier 0x07, count 1: 1500 ms.
        assert record.response == bytes.fromhex("C1 81 00 00 34 02 07 01 DC 05")

    def test_a_confirmation_is_reported_with_no_response(self):
        dut = _dut()
        dut.toggle(0)
        seen = _records(dut.session)

        read = dut.master.read(classes(1)).fragment
        dut.master.confirm(read)

        assert [(record.function, record.request[:2]) for record in seen] == [
            (READ, bytes([0xC0 | read.sequence, READ])),
            (CONFIRM, bytes([0xC0 | read.sequence, CONFIRM])),
        ]
        assert seen[0].response == read.octets
        assert seen[1].response is None

    def test_a_function_that_takes_no_response_is_reported_with_none(self):
        dut = _dut()
        seen = _records(dut.session)

        assert dut.master.request(DIRECT_OPERATE_NR, crob(1)).silent

        (record,) = seen
        assert record.function == DIRECT_OPERATE_NR
        # Group 12 variation 1, qualifier 0x17, one object: index 1, latch on.
        assert record.request == bytes.fromhex("C1 06 0C 01 17 01 01 03 01 64000000 C8000000 00")
        assert record.response is None
        assert dut.operated == [("BO", 1, True)]

    def test_a_broadcast_is_reported_with_its_address_and_no_response(self):
        dut = _dut()
        seen = _records(dut.session)
        # FIR FIN sequence 3, WRITE; group 80 variation 1, qualifier 0x00,
        # index 7 to 7, value 0: clear the restart indication.
        fragment = bytes.fromhex("C3 02 50 01 00 07 07 00")

        assert dut.master.raw(dut.master.frames(fragment, destination=BROADCAST)).silent

        (record,) = seen
        assert (record.source, record.destination) == (MASTER, BROADCAST)
        assert (record.request, record.response) == (fragment, None)

    def test_a_request_dropped_as_an_anomaly_is_not_reported(self):
        dut = _dut()
        seen = _records(dut.session)
        anomalies = _observed(dut.session)

        # A read whose object header stops after the group.
        dut.master.raw(dut.master.frames(bytes.fromhex("C1 01 3C")))

        assert [anomaly.code for anomaly in anomalies] == [AnomalyCode.MALFORMED_REQUEST]
        assert seen == []

    def test_an_unsolicited_response_is_reported_with_no_request(self):
        dut = _unsolicited_dut()
        seen = _records(dut.session)

        dut.master.listen()

        (record,) = seen
        assert record.unsolicited
        assert (record.peer, record.source, record.destination) == (PEER, OUTSTATION, MASTER)
        assert record.function == UNSOLICITED_RESPONSE
        assert record.request == b""
        # FIR FIN CON UNS sequence 0, UNSOLICITED_RESPONSE, IIN1.7 device restart.
        assert record.response == bytes.fromhex("F0 82 80 00")

    def test_a_read_held_behind_an_unsolicited_response_is_reported_once_answered(self):
        dut = _unsolicited_dut()
        seen = _records(dut.session)
        dut.master.listen()

        assert dut.master.read(classes(0)).silent
        assert [record.unsolicited for record in seen] == [True], "the held read is not reported"

        answer = dut.master.confirm_unsolicited(0).fragment

        confirmation, read = seen[1:]
        assert (read.peer, read.source, read.destination) == (PEER, MASTER, OUTSTATION)
        assert (confirmation.request, confirmation.response) == (bytes.fromhex("D0 00"), None)
        assert read.request == bytes.fromhex("C0 01 3C 01 06")
        assert read.response == answer.octets

    def test_a_read_held_and_then_discarded_is_reported_with_no_response(self):
        dut = _unsolicited_dut()
        seen = _records(dut.session)
        dut.master.listen()
        dut.master.read(classes(0))

        dut.session.connection_reset()

        _, read = seen
        assert (read.peer, read.source, read.destination) == (PEER, MASTER, OUTSTATION)
        assert read.request == bytes.fromhex("C0 01 3C 01 06")
        assert read.response is None

    def test_an_observer_that_raises_does_not_stop_the_session(self, caplog):
        def failing(record: RequestRecord) -> None:
            raise RuntimeError("observer failed")

        dut = _dut()
        dut.session.request_observer = failing

        with caplog.at_level(logging.DEBUG, logger="py1815.observers"):
            first = dut.master.read(classes(0))
            dut.master.request(DIRECT_OPERATE, analog_output(1, 250))
            second = dut.master.read(classes(0))

        assert first.fragment.objects and second.fragment.objects, "each read is answered"
        assert dut.operated == [("AO", 1, 250.0)]
        errors = [record for record in caplog.records if record.levelno >= logging.ERROR]
        assert len(errors) == 1, "the first failure is logged and later ones are not"

    def test_a_record_converts_to_plain_values(self):
        record = RequestRecord(
            peer=PEER,
            source=MASTER,
            destination=OUTSTATION,
            function=READ,
            request=CLASS_0_READ,
            response=None,
            timestamp=1.5,
        )

        assert dataclasses.asdict(record) == {
            "peer": {"host": "192.0.2.10", "port": 49152},
            "source": MASTER,
            "destination": OUTSTATION,
            "function": READ,
            "request": CLASS_0_READ,
            "response": None,
            "unsolicited": False,
            "timestamp": 1.5,
        }


# ------------------------------------------------------- the outstation's side


class _Listener:
    """An outstation listening on the loopback interface, with its events kept."""

    def __init__(self, **options) -> None:
        self.events: list[ConnectionEvent] = []
        self.session = options.pop("session", None) or _session()
        self.server = OutstationServer(
            self.session, bind="127.0.0.1:0", connection_observer=self.events.append, **options
        )

    async def __aenter__(self) -> _Listener:
        await self.server.start()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.server.stop()

    def outcomes(self) -> list[tuple[ConnectionOutcome, str]]:
        return [(event.outcome, event.reason) for event in self.events]


def _pki(directory):
    """Return an authority with certificates for the outstation and the master."""
    pytest.importorskip("cryptography", reason="the TLS tests make their certificates with it")
    from test_master_tls import Pki

    return Pki(directory)


def _tls_listener(pki) -> _Listener:
    """Return a listener that admits only the certificate named master.test."""
    from tls_fixtures import server_context

    return _Listener(
        ssl_context=server_context(pki.authority, pki.outstation),
        authorized_peers=frozenset({"master.test"}),
    )


@pytest.mark.asyncio
class TestOutstationConnections:
    async def test_a_connection_is_reported_accepted_and_then_ended_by_the_peer(self):
        async with _Listener() as listening:
            port = listening.server.port
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            client = Endpoint.of(writer.get_extra_info("sockname"))
            await _until(lambda: listening.events)
            writer.close()
            await _until(lambda: len(listening.events) == 2)

        accepted, ended = listening.events
        assert listening.outcomes() == [
            (ConnectionOutcome.ACCEPTED, ""),
            (ConnectionOutcome.ENDED, "closed by peer"),
        ]
        assert accepted.role is ConnectionRole.OUTSTATION
        assert accepted.direction is ConnectionDirection.INBOUND
        assert accepted.transport is ConnectionTransport.TCP
        assert accepted.remote == client
        assert accepted.local == Endpoint("127.0.0.1", port)
        assert accepted.peer_identity is None
        assert ended.remote == client

    async def test_a_second_connection_reports_the_first_displaced(self):
        async with _Listener() as listening:
            _, first = await asyncio.open_connection("127.0.0.1", listening.server.port)
            await _until(lambda: listening.events)
            _, second = await asyncio.open_connection("127.0.0.1", listening.server.port)
            newcomer = Endpoint.of(second.get_extra_info("sockname"))
            await _until(lambda: len(listening.events) == 3)
            first.close()
            await asyncio.sleep(0.1)
            second.close()

        assert listening.outcomes()[:3] == [
            (ConnectionOutcome.ACCEPTED, ""),
            (ConnectionOutcome.DISPLACED, f"displaced by {newcomer}"),
            (ConnectionOutcome.ACCEPTED, ""),
        ]
        displaced = listening.events[1]
        assert displaced.remote == listening.events[0].remote
        assert [event.outcome for event in listening.events].count(ConnectionOutcome.ENDED) == 1, (
            "the displaced connection's end is reported once"
        )

    async def test_stopping_the_listener_reports_the_connection_ended(self):
        async with _Listener() as listening:
            _, writer = await asyncio.open_connection("127.0.0.1", listening.server.port)
            await _until(lambda: listening.events)
            await listening.server.stop()
            writer.close()

        assert listening.outcomes() == [
            (ConnectionOutcome.ACCEPTED, ""),
            (ConnectionOutcome.ENDED, "listener stopped"),
        ]

    async def test_an_idle_connection_is_reported_ended_by_timeout(self):
        async with _Listener(idle_timeout=0.2) as listening:
            _, writer = await asyncio.open_connection("127.0.0.1", listening.server.port)
            await _until(lambda: len(listening.events) == 2)
            writer.close()

        assert listening.outcomes()[1] == (ConnectionOutcome.ENDED, "timeout")

    async def test_a_tls_peer_on_the_allow_list_is_reported_with_its_identity(self, tmp_path):
        pki = _pki(tmp_path)
        async with _tls_listener(pki) as listening:
            settings = pki.settings()
            _, writer = await asyncio.open_connection(
                "127.0.0.1",
                listening.server.port,
                ssl=settings.context(),
                server_hostname=settings.server_name,
            )
            await _until(lambda: listening.events)
            writer.close()

        accepted = listening.events[0]
        assert accepted.outcome is ConnectionOutcome.ACCEPTED
        assert accepted.transport is ConnectionTransport.TLS
        assert accepted.peer_identity == "master.test"

    async def test_a_tls_peer_off_the_allow_list_is_reported_refused(self, tmp_path):
        pki = _pki(tmp_path)
        stranger = pki.authority.issue("stranger.test")
        async with _tls_listener(pki) as listening:
            settings = pki.settings(certificate=str(stranger.certificate), key=str(stranger.key))
            _, writer = await asyncio.open_connection(
                "127.0.0.1",
                listening.server.port,
                ssl=settings.context(),
                server_hostname=settings.server_name,
            )
            await _until(lambda: listening.events)
            writer.close()

        (refused,) = listening.events
        assert refused.outcome is ConnectionOutcome.REFUSED
        assert refused.transport is ConnectionTransport.TLS
        assert refused.peer_identity is None
        assert refused.reason.startswith("not authorized: peer offers names ['stranger.test']")
        assert not listening.server.connected

    async def test_a_broadcast_datagram_anomaly_names_its_sender(self):
        seen: list[ProtocolAnomaly] = []
        session = _session(anomaly_observer=seen.append)
        async with _Listener(session=session, broadcast_datagrams=True) as listening:
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                asyncio.DatagramProtocol, remote_addr=("127.0.0.1", listening.server.port)
            )
            sender = Endpoint.of(transport.get_extra_info("sockname"))
            transport.sendto(_request(destination=BROADCAST))
            await _until(lambda: seen)
            transport.close()

        assert seen[0].code is AnomalyCode.BROADCAST_NOT_ACTED_ON
        assert seen[0].peer == sender

    async def test_an_anomaly_names_the_connection_it_arrived_on(self):
        seen: list[ProtocolAnomaly] = []
        async with _Listener(session=_session(anomaly_observer=seen.append)) as listening:
            _, writer = await asyncio.open_connection("127.0.0.1", listening.server.port)
            client = Endpoint.of(writer.get_extra_info("sockname"))
            writer.write(_request(source=2))
            await writer.drain()
            await _until(lambda: seen)
            writer.close()
            await _until(lambda: len(listening.events) == 2)

            assert listening.session.connection_peer is None, "cleared when the connection ends"

        assert seen[0].peer == client

    async def test_an_observer_that_raises_does_not_break_the_connection(self, caplog):
        def failing(event: ConnectionEvent) -> None:
            raise RuntimeError("observer failed")

        async with _Listener() as listening:
            listening.server.connection_observer = failing
            with caplog.at_level(logging.DEBUG, logger="py1815.observers"):
                for _ in range(2):
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1", listening.server.port
                    )
                    writer.write(_request())
                    await writer.drain()
                    answer = await asyncio.wait_for(reader.read(4096), timeout=5)
                    assert answer, "the request is answered"
                    writer.close()

        errors = [record for record in caplog.records if record.levelno >= logging.ERROR]
        assert len(errors) == 1, "the first failure is logged and later ones are not"


class TestOutstationRequests:
    def test_the_listener_sets_the_sessions_request_observer(self):
        seen: list[RequestRecord] = []
        session = _session()

        server = OutstationServer(session, bind="127.0.0.1:0", request_observer=seen.append)

        assert session.request_observer == seen.append
        server.request_observer = None
        assert session.request_observer is None

    def test_a_listener_given_no_request_observer_keeps_the_sessions(self):
        seen: list[RequestRecord] = []
        session = _session(request_observer=seen.append)

        server = OutstationServer(session, bind="127.0.0.1:0")

        assert server.request_observer == seen.append

    @pytest.mark.asyncio
    async def test_a_request_is_reported_with_the_connection_it_arrived_on(self):
        dut = _dut()
        seen: list[RequestRecord] = []
        async with _Listener(session=dut.session, request_observer=seen.append) as listening:
            reader, writer = await asyncio.open_connection("127.0.0.1", listening.server.port)
            client = Endpoint.of(writer.get_extra_info("sockname"))
            # FIR FIN sequence 2, DIRECT_OPERATE; group 41 variation 2,
            # qualifier 0x17, one object: index 3, value -5, status 0.
            request = bytes.fromhex("C2 05 29 02 17 01 03 FB FF 00")
            writer.write(dut.master.frames(request))
            await writer.drain()
            await _until(lambda: seen)
            answer = await asyncio.wait_for(reader.read(4096), timeout=5)
            writer.close()

        (record,) = seen
        assert (record.peer, record.source, record.destination) == (client, MASTER, OUTSTATION)
        assert record.function == DIRECT_OPERATE
        assert record.request == request
        assert record.response == bytes.fromhex("C2 81 00 00 29 02 17 01 03 FB FF 00")
        assert record.response in answer, "the response reported is the one sent"
        assert dut.operated == [("AO", 3, -5.0)]

    @pytest.mark.asyncio
    async def test_a_request_observer_that_raises_does_not_break_the_connection(self, caplog):
        def failing(record: RequestRecord) -> None:
            raise RuntimeError("observer failed")

        async with _Listener(request_observer=failing) as listening:
            reader, writer = await asyncio.open_connection("127.0.0.1", listening.server.port)
            with caplog.at_level(logging.DEBUG, logger="py1815.observers"):
                for _ in range(2):
                    writer.write(_request())
                    await writer.drain()
                    answer = await asyncio.wait_for(reader.read(4096), timeout=5)
                    assert answer, "the request is answered"
            writer.close()

        errors = [record for record in caplog.records if record.levelno >= logging.ERROR]
        assert len(errors) == 1, "the first failure is logged and later ones are not"


# ------------------------------------------------------------ the master's side


def _master(port: int, events: list[ConnectionEvent], **options) -> Outstation:
    options.setdefault("tasks", Tasks.none())
    options.setdefault("reconnect", None)
    return Outstation(
        "lab", host="127.0.0.1", port=port, connection_observer=events.append, **options
    )


@pytest.mark.asyncio
class TestMasterConnections:
    async def test_a_connection_made_and_lost_is_reported_with_its_endpoints(self):
        events: list[ConnectionEvent] = []
        async with _Listener() as listening:
            port = listening.server.port
            lab = _master(port, events)
            await lab.connect()
            await listening.server.stop()
            await _until(lambda: len(events) == 2)

        connected, lost = events
        assert connected.outcome is ConnectionOutcome.CONNECTED
        assert connected.role is ConnectionRole.MASTER
        assert connected.direction is ConnectionDirection.OUTBOUND
        assert connected.transport is ConnectionTransport.TCP
        assert connected.name == "lab"
        assert connected.remote == Endpoint("127.0.0.1", port)
        assert connected.local is not None and connected.local.host == "127.0.0.1"
        assert (lost.outcome, lost.reason) == (ConnectionOutcome.LOST, "closed by peer")
        assert (lost.local, lost.remote) == (connected.local, connected.remote)

    async def test_a_connection_closed_by_the_master_is_reported_ended(self):
        events: list[ConnectionEvent] = []
        async with _Listener() as listening:
            lab = _master(listening.server.port, events)
            await lab.connect()
            await lab.close()

        assert [(event.outcome, event.reason) for event in events] == [
            (ConnectionOutcome.CONNECTED, ""),
            (ConnectionOutcome.ENDED, "closed by the master"),
        ]

    async def test_a_refused_connection_is_reported_failed(self):
        events: list[ConnectionEvent] = []
        port = await _free_port()
        lab = _master(port, events)

        with pytest.raises(OSError):
            await lab.connect()

        (failed,) = events
        assert (failed.outcome, failed.reason) == (ConnectionOutcome.FAILED, "refused")
        assert failed.remote == Endpoint("127.0.0.1", port)
        assert failed.local is None

    async def test_a_connection_not_made_in_time_is_reported_failed_by_timeout(self, monkeypatch):
        async def never(*args, **kwargs):
            await asyncio.sleep(10)

        monkeypatch.setattr(asyncio, "open_connection", never)
        events: list[ConnectionEvent] = []
        lab = _master(20000, events, connect_timeout=0.05)

        with pytest.raises(TimeoutError):
            await lab.connect()

        assert [(event.outcome, event.reason) for event in events] == [
            (ConnectionOutcome.FAILED, "timeout")
        ]

    async def test_a_tls_connection_reports_the_name_the_outstation_proved(self, tmp_path):
        pki = _pki(tmp_path)
        events: list[ConnectionEvent] = []
        async with _tls_listener(pki) as listening:
            settings = pki.settings()
            lab = _master(
                listening.server.port,
                events,
                tls=settings.context(),
                server_name=settings.server_name,
            )
            await lab.connect()
            await lab.close()

        connected = events[0]
        assert connected.outcome is ConnectionOutcome.CONNECTED
        assert connected.transport is ConnectionTransport.TLS
        assert connected.peer_identity == "outstation.test"

    async def test_a_failed_tls_handshake_is_reported_failed(self, tmp_path):
        pki = _pki(tmp_path)
        events: list[ConnectionEvent] = []
        async with _tls_listener(pki) as listening:
            settings = pki.settings(server_name="somebody-else.test")
            lab = _master(
                listening.server.port,
                events,
                tls=settings.context(),
                server_name=settings.server_name,
            )
            with pytest.raises(ssl.SSLError):
                await lab.connect()

        (failed,) = events
        assert failed.outcome is ConnectionOutcome.FAILED
        assert failed.transport is ConnectionTransport.TLS
        assert failed.reason.startswith("TLS failure: ")

    async def test_on_connection_is_still_called_beside_the_observer(self):
        events: list[ConnectionEvent] = []
        states: list[bool] = []
        async with _Listener() as listening:
            lab = _master(listening.server.port, events, on_connection=states.append)
            await lab.connect()
            await listening.server.stop()
            await _until(lambda: len(states) == 2)

        assert states == [True, False]
        assert [event.outcome for event in events] == [
            ConnectionOutcome.CONNECTED,
            ConnectionOutcome.LOST,
        ]

    async def test_an_observer_that_raises_does_not_break_the_connection(self, caplog):
        def failing(event: ConnectionEvent) -> None:
            raise RuntimeError("observer failed")

        states: list[bool] = []
        async with _Listener() as listening:
            lab = Outstation(
                "lab",
                host="127.0.0.1",
                port=listening.server.port,
                tasks=Tasks.none(),
                reconnect=None,
                on_connection=states.append,
            )
            lab.connection_observer = failing
            with caplog.at_level(logging.DEBUG, logger="py1815.observers"):
                await lab.connect()
                poll = await lab.integrity_poll()
                await lab.close()

        assert poll.complete, "the connection carried a request"
        assert states == [True]
        errors = [record for record in caplog.records if record.levelno >= logging.ERROR]
        assert len(errors) == 1, "the first failure is logged and the second is not"

    async def test_a_retry_the_outstation_closes_at_once_is_reported_failed(self):
        """The retry worker checks the new connection after it is made. The
        listener here closes every connection after the first as soon as it
        arrives, and the master waits long enough for the close to arrive."""
        connections: list[asyncio.StreamWriter] = []

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            connections.append(writer)
            if len(connections) > 1:
                writer.close()

        listener = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = listener.sockets[0].getsockname()[1]
        events: list[ConnectionEvent] = []

        class SlowToCheck(Outstation):
            async def _open(self) -> None:
                await super()._open()
                if len(connections) > 1:
                    await _until(lambda: not self.connected)

        lab = SlowToCheck(
            "lab",
            host="127.0.0.1",
            port=port,
            tasks=Tasks.none(),
            reconnect=0.05,
            connection_observer=events.append,
        )
        try:
            await lab.connect()
            await _until(lambda: connections)
            connections[0].close()
            await _until(
                lambda: (
                    (ConnectionOutcome.FAILED, "closed at once")
                    in [(event.outcome, event.reason) for event in events]
                )
            )
        finally:
            await lab.close()
            listener.close()
            await listener.wait_closed()

        assert [event.outcome for event in events[:2]] == [
            ConnectionOutcome.CONNECTED,
            ConnectionOutcome.LOST,
        ]
