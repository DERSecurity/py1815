"""Traffic records in the shape a network monitor publishes them.

The contract is a recording, ``traffic_records.json``: fragments passed
through Wireshark's DNP3 dissector and the monitor's parser, with the body the
monitor published for each, and a few of those bodies in the envelope it
published them in. The tests here hold this library's bodies and envelopes to
that recording, key order included, since the order is part of the payload
text that the envelope's hash covers.

The rest builds records from real traffic: the outstation's request records,
and a master's exchanges over the loopback interface.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import re
from datetime import UTC, datetime

import pytest
from ied_harness import DIRECT_OPERATE, Dut, analog_output, classes
from test_observers import _Listener, _until

from py1815.envelope import (
    WIRE_FORMAT_VERSION,
    NetworkEndpoint,
    Protocol,
    ProtocolMessage,
    WireDirection,
    wire_version,
)
from py1815.master import Master, Tasks
from py1815.observers import Endpoint, RequestRecord
from py1815.traffic import (
    MAX_POINTS_PER_TYPE,
    envelope,
    exchange_bodies,
    exchange_messages,
    fragment_body,
    record_bodies,
    record_messages,
)

RECORDING = json.loads(
    (pathlib.Path(__file__).parent / "traffic_records.json").read_text(encoding="utf-8")
)
MASTER = RECORDING["master"]
OUTSTATION = RECORDING["outstation"]
MASTER_END = Endpoint(MASTER["ip"], MASTER["port"])
OUTSTATION_END = Endpoint(OUTSTATION["ip"], OUTSTATION["port"])

#: Recorded fragments this library describes differently, and why. Each one
#: holds an object that :mod:`py1815.decode` does not read, so its header and
#: any point are missing here. Every fragment not listed must match.
DEPARTURES = {
    "g3v2 double bit": "double-bit binary inputs are not read",
    "g4v1 double bit event": "double-bit binary input events are not read",
    "g31v1": "frozen analog inputs are not read",
    "g34v1 deadband": "analog deadbands are not read",
    "write g34v1": "analog deadbands are not read",
    "write g50v3": "the last recorded time is not read",
}


def _body(case: dict) -> dict:
    sender, receiver = (MASTER, OUTSTATION) if case["from"] == "master" else (OUTSTATION, MASTER)
    return fragment_body(
        bytes.fromhex(case["fragment"]),
        source=sender["address"],
        destination=receiver["address"],
        source_ip=sender["ip"],
        destination_ip=receiver["ip"],
    )


def _cases(departures: bool) -> list:
    return [
        pytest.param(case, id=case["label"])
        for case in RECORDING["fragments"]
        if (case["label"] in DEPARTURES) == departures
    ]


class TestRecordedBodies:
    @pytest.mark.parametrize("case", _cases(departures=False))
    def test_the_body_is_the_one_recorded(self, case):
        # Compared as JSON text, so the key order counts.
        assert json.dumps(_body(case)) == json.dumps(case["body"])

    @pytest.mark.parametrize("case", _cases(departures=True))
    def test_a_listed_departure_still_differs(self, case):
        # A departure that starts to match is no longer one: take it off the list.
        assert json.dumps(_body(case)) != json.dumps(case["body"])

    def test_every_departure_is_in_the_recording(self):
        labels = {case["label"] for case in RECORDING["fragments"]}
        assert set(DEPARTURES) <= labels


class TestBodies:
    def test_a_response_that_ends_inside_an_object_is_rejected(self):
        # Group 30 variation 1, qualifier 0x00, start 0, stop 1: two objects
        # declared and one and a half sent.
        fragment = bytes.fromhex("C0 81 00 00 1E 01 00 00 01 01 64 00 00 00 01 64")

        body = fragment_body(fragment, source=1024, destination=1)

        assert body["apdu_rejected"] == "malformed"
        assert (body["objects"], body["points"]) == ([], [])
        assert list(body) == [
            "source_address",
            "destination_address",
            "function_code",
            "prm",
            "source_ip",
            "destination_ip",
            "points",
            "direction",
            "objects",
            "apdu_rejected",
        ]

    def test_a_request_that_ends_inside_an_object_is_not_rejected(self):
        # WRITE, group 80 variation 1, qualifier 0x00, start 7, stop 7, and no octet.
        body = fragment_body(bytes.fromhex("C0 02 50 01 00 07 07"), source=1, destination=1024)

        assert "apdu_rejected" not in body
        assert body["objects"] == []

    def test_points_of_one_type_stop_at_the_limit(self):
        # Group 20 variation 6, qualifier 0x01, start 0, stop 2000: 2001
        # counters of two octets each.
        count = MAX_POINTS_PER_TYPE + 1
        fragment = (
            bytes.fromhex("C0 81 00 00 14 06 01")
            + (0).to_bytes(2, "little")
            + (count - 1).to_bytes(2, "little")
            + bytes(2 * count)
        )

        body = fragment_body(fragment, source=1024, destination=1)

        assert len(body["points"]) == MAX_POINTS_PER_TYPE
        assert body["points"][-1]["index"] == MAX_POINTS_PER_TYPE - 1


class TestRecordedEnvelopes:
    @pytest.mark.parametrize(
        "case", [pytest.param(case, id=case["timestamp"]) for case in RECORDING["envelopes"]]
    )
    def test_the_envelope_is_the_one_recorded(self, case):
        body = RECORDING["fragments"][case["body"]]["body"]
        at = datetime.fromisoformat(case["timestamp"]).timestamp()

        message = envelope(body, outstation=OUTSTATION_END, at=at).to_dict()

        assert re.fullmatch(r"\d+\.\d+\.\d+|2\.0", message.pop("version"))
        assert json.dumps(message) == json.dumps(case["envelope"])

    def test_a_serialized_envelope_reads_back_unchanged(self):
        case = RECORDING["envelopes"][0]
        recorded = dict(case["envelope"], version="2.0")

        message = ProtocolMessage.from_dict(recorded)

        assert message.hash == recorded["hash"]
        assert message.body == RECORDING["fragments"][case["body"]]["body"]
        written = message.to_dict()
        written.pop("version")
        assert json.dumps(written) == json.dumps(case["envelope"])


class TestEnvelope:
    def test_the_version_is_a_release_or_the_wire_format_version(self):
        assert re.fullmatch(r"\d+\.\d+\.\d+", wire_version()) or (
            wire_version() == WIRE_FORMAT_VERSION
        )

    def test_a_timestamp_ending_in_z_is_written_with_an_offset(self):
        message = ProtocolMessage(
            protocol=Protocol.DNP3,
            direction=WireDirection.UPSTREAM,
            client_id="1024",
            payload={},
            source=NetworkEndpoint("198.51.100.5", 20000),
            timestamp="2026-10-27T12:00:00Z",
        )

        assert message.timestamp == "2026-10-27T12:00:00+00:00"

    def test_an_empty_client_id_is_refused(self):
        with pytest.raises(ValueError, match="client_id"):
            ProtocolMessage(
                protocol="dnp3",
                direction="upstream",
                client_id=" ",
                payload={},
                source=NetworkEndpoint("198.51.100.5", 20000),
            )

    def test_a_response_names_the_outstation_by_its_source_address(self):
        body = fragment_body(
            bytes.fromhex("C0 81 00 00"),
            source=7,
            destination=1,
            source_ip=OUTSTATION["ip"],
            destination_ip=MASTER["ip"],
        )

        assert envelope(body, outstation=OUTSTATION_END, at=0.0).client_id == "7"


# ---------------------------------------------------------------- the outstation


def _dut(**options) -> tuple[Dut, list[RequestRecord]]:
    dut = Dut(analog_inputs=False, counters=False, **options)
    dut.clear_restart()
    dut.session.connection_peer = MASTER_END
    dut.session.connection_local = OUTSTATION_END
    seen: list[RequestRecord] = []
    dut.session.request_observer = seen.append
    return dut, seen


class TestRequestRecords:
    def test_a_direct_operate_gives_its_request_and_its_echo(self):
        dut, seen = _dut()
        dut.master.request(DIRECT_OPERATE, analog_output(1, 250))
        (record,) = seen

        request, response = record_bodies(record)

        assert request == fragment_body(
            bytes.fromhex("C1 05 29 02 17 01 01 FA 00 00"),
            source=MASTER["address"],
            destination=OUTSTATION["address"],
            source_ip=MASTER["ip"],
            destination_ip=OUTSTATION["ip"],
        )
        assert (response["source_address"], response["destination_address"]) == (1024, 1)
        assert (response["source_ip"], response["destination_ip"]) == (
            OUTSTATION["ip"],
            MASTER["ip"],
        )
        assert response["direction"] == "response"
        assert response["objects"] == [{"group": 41, "variation": 2}]

    def test_the_envelopes_carry_the_record_time_and_the_outstation(self):
        dut, seen = _dut()
        dut.master.read(classes(1, 2, 3, 0))
        (record,) = seen

        messages = record_messages(record, forwarder_id="lab-1")

        stamp = datetime.fromtimestamp(record.timestamp, UTC).isoformat()
        assert [message.timestamp for message in messages] == [stamp, stamp]
        assert {message.client_id for message in messages} == {"1024"}
        assert {message.forwarder_id for message in messages} == {"lab-1"}
        assert messages[0].source == NetworkEndpoint(OUTSTATION["ip"], OUTSTATION["port"])
        assert [message.body for message in messages] == record_bodies(record)

    def test_an_unsolicited_response_gives_one_body_from_the_outstation(self):
        dut = Dut(analog_inputs=False, counters=False, unsolicited=True)
        dut.session.connection_peer = MASTER_END
        dut.session.connection_local = OUTSTATION_END
        seen: list[RequestRecord] = []
        dut.session.request_observer = seen.append
        dut.master.listen()

        (body,) = record_bodies(seen[0])

        assert body["function_code"] == 130
        assert (body["source_address"], body["source_ip"]) == (1024, OUTSTATION["ip"])
        assert (body["destination_address"], body["destination_ip"]) == (1, MASTER["ip"])

    def test_a_record_without_the_outstation_address_needs_one_given(self):
        dut, seen = _dut()
        dut.session.connection_local = None
        dut.master.read(classes(0))
        (record,) = seen

        with pytest.raises(ValueError, match="outstation"):
            record_messages(record)
        (request, _) = record_messages(record, outstation=OUTSTATION_END)
        assert request.source.ip == OUTSTATION["ip"]
        assert request.body is not None and request.body["destination_ip"] == OUTSTATION["ip"]

    @pytest.mark.asyncio
    async def test_a_listener_reports_both_ends_of_the_connection(self):
        dut = Dut(analog_inputs=False, counters=False)
        seen: list[RequestRecord] = []
        async with _Listener(session=dut.session, request_observer=seen.append) as listening:
            port = listening.server.port
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            client = Endpoint.of(writer.get_extra_info("sockname"))
            writer.write(dut.master.frames(bytes.fromhex("C0 01 3C 01 06")))
            await writer.drain()
            await _until(lambda: seen)
            writer.close()

        (record,) = seen
        assert record.peer == client
        assert record.local == Endpoint("127.0.0.1", port)
        request, response = record_bodies(record)
        assert (request["source_ip"], request["destination_ip"]) == ("127.0.0.1", "127.0.0.1")
        assert (response["source_address"], response["destination_address"]) == (1024, 1)
        (message, _) = record_messages(record)
        assert message.source == NetworkEndpoint("127.0.0.1", port)


# -------------------------------------------------------------------- the master


class TestExchanges:
    @pytest.mark.asyncio
    async def test_an_exchange_gives_its_request_and_each_response_fragment(self):
        dut = Dut(analog_inputs=False, counters=False)
        async with _Listener(session=dut.session) as listening, Master() as master:
            lab = await master.add(
                "lab", host="127.0.0.1", port=listening.server.port, tasks=Tasks.none()
            )
            exchange = await lab.scan("class0")
            connection = lab.connection
            addresses = (lab.association.master_address, lab.association.outstation_address)
            port = listening.server.port

        assert connection is not None and connection.local is not None
        assert connection.remote is not None
        bodies = exchange_bodies(
            exchange,
            master_address=addresses[0],
            outstation_address=addresses[1],
            master=connection.local,
            outstation=connection.remote,
        )
        assert len(bodies) == 1 + len(exchange.fragments)
        assert bodies[0] == fragment_body(
            exchange.request,
            source=addresses[0],
            destination=addresses[1],
            source_ip="127.0.0.1",
            destination_ip="127.0.0.1",
        )
        # Binary inputs with flags, which give the monitor no points.
        assert bodies[1]["objects"] == [{"group": 1, "variation": 2}]
        assert (bodies[1]["direction"], bodies[1]["points"]) == ("response", [])

        messages = exchange_messages(
            exchange,
            master_address=addresses[0],
            outstation_address=addresses[1],
            master=connection.local,
            outstation=connection.remote,
            at=1_792_310_400.5,
        )
        request_at = datetime.fromisoformat(messages[0].timestamp).timestamp()
        assert request_at == pytest.approx(1_792_310_400.5 - exchange.elapsed)
        assert messages[1].timestamp == datetime.fromtimestamp(1_792_310_400.5, UTC).isoformat()
        assert {message.source.port for message in messages} == {port}
