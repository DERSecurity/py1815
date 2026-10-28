"""DNP3 traffic records: the bodies follow the DNP3 traffic schema, version 1.

``traffic_vectors.json`` pairs application fragments, in hex, with the body
the schema's authors wrote for each from the IEEE 1815 object layouts. Each
fragment is read here by this library and its body must match the vector
exactly, key order included, since the order is part of the payload text that
the envelope's hash covers.

The schema checks need ``jsonschema``, which is in the dev extra. Without it
this file fails to import, with a message that says to reinstall the extra,
rather than skipping the checks. Every body this library produces in these
tests is validated against the copy of the schema in the package: the
vectors, a body for every object variation it reads, and the traffic of a
session and a master over the loopback interface.
The rest pins how each kind of object is read, with literal octets.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import pathlib
import re
import struct
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from ied_harness import (
    COLD_RESTART,
    DELAY_MEASURE,
    DIRECT_OPERATE,
    ENABLE_UNSOLICITED,
    FREEZE,
    OPERATE,
    Q_ALL,
    Q_RANGE_8,
    RECORD_CURRENT_TIME,
    SELECT,
    Dut,
    analog_output,
    classes,
    crob,
    header,
)
from test_observers import _Listener, _until

from py1815.decode import LAYOUTS, _Time
from py1815.envelope import (
    WIRE_FORMAT_VERSION,
    NetworkEndpoint,
    Protocol,
    ProtocolMessage,
    ProtocolMetadata,
    WireDirection,
    wire_version,
)
from py1815.master import Master, Tasks
from py1815.observers import Endpoint, RequestRecord
from py1815.traffic import (
    _LAYOUTS,
    IIN_BITS,
    MAX_DATA_OCTETS,
    MAX_OBJECTS,
    MAX_POINTS,
    SCHEMA_ID,
    SCHEMA_VERSION,
    Direction,
    _Field,
    envelope,
    exchange_bodies,
    exchange_messages,
    fragment_body,
    load_schema,
    record_bodies,
    record_messages,
)

try:
    import jsonschema
except ImportError as missing:
    # jsonschema is a declared dev dependency, so its absence means a stale
    # environment. Fail here instead of skipping the schema checks.
    raise ImportError(
        "the traffic schema checks need jsonschema, from the dev extra: "
        'reinstall it with pip install -e ".[dev]"'
    ) from missing

VECTORS: dict[str, dict[str, Any]] = json.loads(
    (pathlib.Path(__file__).parent / "traffic_vectors.json").read_text(encoding="utf-8")
)

MASTER_END = Endpoint("192.0.2.10", 50123)
OUTSTATION_END = Endpoint("192.0.2.20", 20000)


def _vector_body(case: dict[str, Any]) -> dict[str, Any]:
    """Read a vector's fragment, with the connection facts its body states."""
    body = case["body"]
    return fragment_body(
        bytes.fromhex(case["apdu"]),
        direction=body["direction"],
        source=body["source_address"],
        destination=body["destination_address"],
        sender=Endpoint(body["source_ip"], body["source_port"]),
        receiver=Endpoint(body["destination_ip"], body["destination_port"]),
    )


def _request(hex_octets: str) -> dict[str, Any]:
    """Return the body of a request from the master, address 1, to outstation 10."""
    return fragment_body(
        bytes.fromhex(hex_octets), direction=Direction.REQUEST, source=1, destination=10
    )


def _response(hex_octets: str) -> dict[str, Any]:
    """Return the body of a response from outstation 10 to the master, address 1."""
    return fragment_body(
        bytes.fromhex(hex_octets), direction=Direction.RESPONSE, source=10, destination=1
    )


def _validator() -> Any:
    schema = load_schema()
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema, format_checker=cls.FORMAT_CHECKER)


def _assert_valid(bodies: list[dict[str, Any]]) -> None:
    validator = _validator()
    for body in bodies:
        errors = [error.message for error in validator.iter_errors(body)]
        assert not errors, f"{json.dumps(body)}: {errors}"


# ----------------------------------------------------------------- vectors


class TestVectors:
    @pytest.mark.parametrize("name", list(VECTORS))
    def test_the_body_is_the_vector_body(self, name):
        # Compared as JSON text, so the key order counts.
        assert json.dumps(_vector_body(VECTORS[name])) == json.dumps(VECTORS[name]["body"])

    def test_the_vectors_cover_requests_responses_and_rejections(self):
        bodies = [case["body"] for case in VECTORS.values()]
        assert {body["direction"] for body in bodies} == {"request", "response"}
        assert {body.get("apdu_rejected") for body in bodies} == {
            None,
            "malformed",
            "point_count",
        }


# ------------------------------------------------------------------ schema


#: Every point variation the module reads. A response carries two objects of
#: each, at indices 3 and 4, with every object octet 0x41, which is a finite
#: value in every number format.
SWEEP = [
    (1, 1),
    (1, 2),
    (2, 1),
    (2, 2),
    (2, 3),
    (3, 1),
    (3, 2),
    (4, 1),
    (4, 2),
    (4, 3),
    (10, 1),
    (10, 2),
    (11, 1),
    (11, 2),
    (12, 1),
    (13, 1),
    (13, 2),
    *[(20, v) for v in (1, 2, 5, 6)],
    *[(21, v) for v in (1, 2, 5, 6, 9, 10)],
    *[(22, v) for v in (1, 2, 5, 6)],
    *[(23, v) for v in (1, 2, 5, 6)],
    *[(30, v) for v in range(1, 7)],
    *[(31, v) for v in range(1, 9)],
    *[(32, v) for v in range(1, 9)],
    *[(33, v) for v in range(1, 9)],
    (34, 1),
    (34, 2),
    (34, 3),
    *[(40, v) for v in range(1, 5)],
    *[(41, v) for v in range(1, 5)],
    *[(42, v) for v in range(1, 9)],
    *[(43, v) for v in range(1, 9)],
    (110, 3),
    (111, 3),
]

#: Octets of one object, for the variations in SWEEP that are not packed.
OBJECT_SIZES = {
    (1, 2): 1,
    (2, 1): 1,
    (2, 2): 7,
    (2, 3): 3,
    (3, 2): 1,
    (4, 1): 1,
    (4, 2): 7,
    (4, 3): 3,
    (10, 2): 1,
    (11, 1): 1,
    (11, 2): 7,
    (12, 1): 11,
    (13, 1): 1,
    (13, 2): 7,
    (20, 1): 5,
    (20, 2): 3,
    (20, 5): 4,
    (20, 6): 2,
    (21, 1): 5,
    (21, 2): 3,
    (21, 5): 11,
    (21, 6): 9,
    (21, 9): 4,
    (21, 10): 2,
    (22, 1): 5,
    (22, 2): 3,
    (22, 5): 11,
    (22, 6): 9,
    (23, 1): 5,
    (23, 2): 3,
    (23, 5): 11,
    (23, 6): 9,
    (30, 1): 5,
    (30, 2): 3,
    (30, 3): 4,
    (30, 4): 2,
    (30, 5): 5,
    (30, 6): 9,
    (31, 1): 5,
    (31, 2): 3,
    (31, 3): 11,
    (31, 4): 9,
    (31, 5): 4,
    (31, 6): 2,
    (31, 7): 5,
    (31, 8): 9,
    **{(group, 1): 5 for group in (32, 33, 42)},
    **{(group, 2): 3 for group in (32, 33, 42)},
    **{(group, 3): 11 for group in (32, 33, 42)},
    **{(group, 4): 9 for group in (32, 33, 42)},
    **{(group, 5): 5 for group in (32, 33, 42)},
    **{(group, 6): 9 for group in (32, 33, 42)},
    **{(group, 7): 11 for group in (32, 33, 42)},
    **{(group, 8): 15 for group in (32, 33, 42)},
    (34, 1): 2,
    (34, 2): 4,
    (34, 3): 4,
    (40, 1): 5,
    (40, 2): 3,
    (40, 3): 5,
    (40, 4): 9,
    (41, 1): 5,
    (41, 2): 3,
    (41, 3): 5,
    (41, 4): 9,
    (43, 1): 5,
    (43, 2): 3,
    (43, 3): 11,
    (43, 4): 9,
    (43, 5): 5,
    (43, 6): 9,
    (43, 7): 11,
    (43, 8): 15,
    (110, 3): 3,
    (111, 3): 3,
}

#: Packed variations: octets for two objects.
PACKED = {(1, 1): 1, (3, 1): 1, (10, 1): 1}


def _sweep_fragment(group: int, variation: int) -> bytes:
    """Return a response carrying two objects of one variation, at indices 3 and 4."""
    if (group, variation) in PACKED:
        objects = bytes([group, variation, 0x00, 3, 4]) + b"\x41" * PACKED[group, variation]
    else:
        size = OBJECT_SIZES[group, variation]
        objects = bytes([group, variation, 0x17, 2])
        objects += b"".join(bytes([index]) + b"\x41" * size for index in (3, 4))
    return bytes.fromhex("C0 81 00 00") + objects


def _session_bodies() -> list[dict[str, Any]]:
    """Return the bodies of a session's traffic: polls, events, controls and the rest."""
    dut = Dut(unsolicited=True)
    dut.session.connection_peer = MASTER_END
    dut.session.connection_local = OUTSTATION_END
    records: list[RequestRecord] = []
    dut.session.request_observer = records.append
    dut.master.listen()
    dut.master.confirm_unsolicited(0)
    dut.clear_restart()
    dut.master.read(classes(1, 2, 3, 0))
    dut.toggle(1)
    dut.step(0)
    dut.count()
    dut.master.poll(classes(1, 2, 3))
    dut.master.request(SELECT, crob(2, 0x41))
    dut.master.request(OPERATE, crob(2, 0x41))
    dut.master.request(DIRECT_OPERATE, analog_output(1, -250))
    dut.master.request(FREEZE, header(20, 0, Q_ALL))
    dut.master.read(header(21, 0, Q_ALL), header(1, 0, Q_RANGE_8, 0, 3))
    dut.master.request(DELAY_MEASURE)
    dut.master.request(RECORD_CURRENT_TIME)
    dut.master.request(ENABLE_UNSOLICITED, classes(1, 2, 3))
    dut.master.request(COLD_RESTART)
    return [body for record in records for body in record_bodies(record)]


class TestSchema:
    def test_the_schema_copy_is_the_version_the_module_names(self):
        # The copy, the $id the module names and the version it writes change
        # together. Updating one of them without the others fails here.
        schema = load_schema()
        assert schema["$id"] == SCHEMA_ID
        assert SCHEMA_ID.endswith(f"/v{SCHEMA_VERSION}")
        assert schema["properties"]["schema"]["const"] == SCHEMA_VERSION
        assert "schema" in schema["required"]

    def test_every_body_names_the_schema_version(self):
        bodies = [_vector_body(case) for case in VECTORS.values()] + _session_bodies()
        assert {body["schema"] for body in bodies} == {SCHEMA_VERSION}

    def test_the_schema_copy_is_a_valid_json_schema(self):
        _validator()

    @pytest.mark.parametrize("name", list(VECTORS))
    def test_each_vector_body_read_here_is_valid(self, name):
        _assert_valid([_vector_body(VECTORS[name])])

    @pytest.mark.parametrize(
        "group, variation", [pytest.param(*key, id=f"g{key[0]}v{key[1]}") for key in SWEEP]
    )
    def test_a_response_of_each_variation_read_is_valid(self, group, variation):
        body = _response(_sweep_fragment(group, variation).hex())

        assert "apdu_rejected" not in body
        assert [(p["group"], p["variation"], p["index"]) for p in body["points"]] == [
            (group, variation, 3),
            (group, variation, 4),
        ]
        _assert_valid([body])

    def test_every_body_of_a_session_is_valid(self):
        _assert_valid(_session_bodies())

    def test_the_validator_refuses_a_body_that_breaks_a_rule(self):
        # A request with internal indications, and a CROB with a value.
        request = _request("C0 01 3C 01 06")
        request["iin"] = []
        crob_body = dict(VECTORS["direct operate/g12 request"]["body"])
        crob_body["points"] = [{**crob_body["points"][0], "value": 1}]
        validator = _validator()
        assert not validator.is_valid(request)
        assert not validator.is_valid(crob_body)
        assert not validator.is_valid({**_request("C0 01"), "source_ip": "not an address"})


class TestSessionTraffic:
    def test_no_body_of_a_session_is_rejected(self):
        bodies = _session_bodies()

        assert [body for body in bodies if "apdu_rejected" in body] == []
        kinds = {(p["type"], p["group"]) for body in bodies for p in body["points"]}
        assert {("binary_output", 12), ("analog_output", 41), ("counter", 21)} <= kinds


# --------------------------------------------------------------- reading


def _flags(layout: Any) -> bool:
    return bool(layout.fields) and layout.fields[0] in (_Field.FLAGS, _Field.FLAGS_STATE)


def _time(layout: Any) -> _Time:
    if _Field.TIME in layout.fields:
        return _Time.ABSOLUTE
    if _Field.RELATIVE_TIME in layout.fields:
        return _Time.RELATIVE
    return _Time.NONE


class TestLayouts:
    # A body and the master's decoder read the octets of an object both know
    # in one way. A correction to one that does not reach the other fails here.
    @pytest.mark.parametrize(
        "group, variation", [pytest.param(*key, id=f"g{key[0]}v{key[1]}") for key in LAYOUTS]
    )
    def test_an_object_the_master_decodes_is_read_with_the_same_layout(self, group, variation):
        decoded = LAYOUTS[(group, variation)]
        ours = _LAYOUTS[(group, variation)]

        assert bool(ours.packed_bits) == decoded.packed
        if decoded.packed:
            assert ours.packed_bits == 1
            return
        assert ours.size(variation) == decoded.size
        if decoded.opaque:
            # The master walks past a command object; a body reads its fields.
            return
        assert _flags(ours) == decoded.flags
        assert ours.number == decoded.number
        assert _time(ours) is decoded.time


class TestFragment:
    def test_a_response_names_each_internal_indication_set(self):
        # IIN1 0x80 device restart; IIN2 0x06 object unknown and parameter error.
        body = _response("C0 81 80 06")
        assert body["iin"] == ["device_restart", "object_unknown", "parameter_error"]

    def test_every_internal_indication_bit_has_its_name(self):
        assert _response("C0 81 FF FF")["iin"] == list(IIN_BITS)
        assert len(IIN_BITS) == 16

    def test_a_request_carries_no_internal_indications(self):
        assert "iin" not in _request("C0 01 3C 01 06")

    def test_a_response_function_code_from_the_master_is_described_as_a_request(self):
        # The direction is the sender's, so a master sending 0x81 is still a
        # request, read without internal indications.
        body = _request("C0 81 00 00")

        assert (body["direction"], body["function_code"]) == ("request", 0x81)
        assert "iin" not in body
        assert body["apdu_rejected"] == "malformed"

    def test_the_unsolicited_bit_is_read_from_the_control_octet(self):
        assert _request("D3 00")["unsolicited"] is True
        assert _request("C3 00")["unsolicited"] is False

    def test_a_fragment_shorter_than_a_function_code_is_refused(self):
        with pytest.raises(ValueError, match="function"):
            fragment_body(b"\xc0", direction="request", source=1, destination=10)

    def test_an_unknown_direction_is_refused(self):
        with pytest.raises(ValueError):
            fragment_body(b"\xc0\x01", direction="sideways", source=1, destination=10)

    def test_the_connection_gives_both_addresses_and_ports(self):
        body = fragment_body(
            bytes.fromhex("C0 01"),
            direction="request",
            source=1,
            destination=10,
            sender=Endpoint("fe80::1%eth0", 50000),
            receiver=Endpoint("outstation.example", 20000),
        )

        # The zone names an interface on this host and is not part of the
        # address; a name that is not an address is left out, with its port.
        assert (body["source_ip"], body["source_port"]) == ("fe80::1", 50000)
        assert "destination_ip" not in body
        assert body["destination_port"] == 20000

    def test_an_unknown_end_is_left_out(self):
        body = _request("C0 01")
        assert not {"source_ip", "source_port", "destination_ip", "destination_port"} & set(body)


class TestPoints:
    def test_indices_are_the_wire_indices_of_each_point_type(self):
        # Group 1 variation 1, qualifier 0x00, 0 to 3: 0b0101. Then group 10
        # variation 1, 0 to 1: 0b10.
        body = _response("C0 81 00 00  01 01 00 00 03 05  0A 01 00 00 01 02")

        assert [(p["type"], p["index"], p["value"]) for p in body["points"]] == [
            ("binary", 0, 1),
            ("binary", 1, 0),
            ("binary", 2, 1),
            ("binary", 3, 0),
            ("binary_output", 0, 0),
            ("binary_output", 1, 1),
        ]

    def test_points_keep_wire_order_across_types(self):
        # Group 30 variation 2 at index 7, then group 1 variation 2 at index 2.
        body = _response("C0 81 00 00  1E 02 17 01 07 01 2C 01  01 02 17 01 02 81")

        assert [(p["type"], p["index"]) for p in body["points"]] == [("analog", 7), ("binary", 2)]

    def test_a_binary_with_flags_reads_its_state_from_bit_7_and_keeps_the_octet(self):
        # Group 1 variation 2, qualifier 0x00, 5 to 6: 0x81 (on, online), 0x02 (off, restart).
        body = _response("C0 81 00 00  01 02 00 05 06 81 02")

        assert [(p["index"], p["value"], p["flags"]) for p in body["points"]] == [
            (5, 1, 0x81),
            (6, 0, 0x02),
        ]

    def test_packed_double_bit_inputs_are_two_bits_each(self):
        # Group 3 variation 1, qualifier 0x00, 0 to 3: 0xE4 = 11 10 01 00.
        body = _response("C0 81 00 00  03 01 00 00 03 E4")

        assert [(p["type"], p["index"], p["value"]) for p in body["points"]] == [
            ("double_bit_binary", 0, 0),
            ("double_bit_binary", 1, 1),
            ("double_bit_binary", 2, 2),
            ("double_bit_binary", 3, 3),
        ]
        assert all("flags" not in p for p in body["points"])

    def test_a_double_bit_input_with_flags_reads_bits_6_and_7(self):
        # Group 4 variation 1, qualifier 0x17, one object: index 9, 0x41
        # (state 01, online).
        (point,) = _response("C0 81 00 00  04 01 17 01 09 41")["points"]
        assert (point["value"], point["flags"]) == (1, 0x41)

    def test_a_binary_output_command_event_splits_its_octet(self):
        # Group 13 variation 2, qualifier 0x17, one object: index 4, 0x84
        # (commanded on, status 4), then the time 1000 ms.
        (point,) = _response("C0 81 00 00  0D 02 17 01 04 84 E8 03 00 00 00 00")["points"]

        assert point == {
            "type": "binary_output",
            "group": 13,
            "variation": 2,
            "index": 4,
            "command": False,
            "value": 1,
            "time": 1000,
            "status": 4,
        }

    def test_an_analog_output_command_event_carries_its_status_first(self):
        # Group 43 variation 2, qualifier 0x17, one object: index 1, status 0,
        # value -5.
        (point,) = _response("C0 81 00 00  2B 02 17 01 01 00 FB FF")["points"]
        assert (point["value"], point["status"], point["command"]) == (-5, 0, False)
        assert "flags" not in point

    def test_a_crob_carries_its_control_code_as_fields(self):
        # Group 12 variation 1, qualifier 0x17, one object: index 2, code 0xB1
        # (trip, clear, queue, pulse on), count 3, on 100, off 200, status 0.
        (point,) = _request("C0 05  0C 01 17 01 02 B1 03 64 00 00 00 C8 00 00 00 00")["points"]

        assert point == {
            "type": "binary_output",
            "group": 12,
            "variation": 1,
            "index": 2,
            "command": True,
            "op_type": 1,
            "trip_close": 2,
            "clear": True,
            "queue": True,
            "count": 3,
            "on_time": 100,
            "off_time": 200,
            "status": 0,
        }

    def test_a_pattern_control_is_one_crob_per_output_its_mask_selects(self):
        # Group 12 variation 2, qualifier 0x07, count 1: code 0x03, count 1,
        # on 0, off 0, status 0. Then group 12 variation 3, qualifier 0x00,
        # 5 to 8: mask 0b0101, outputs 5 and 7.
        body = _request("C0 05  0C 02 07 01 03 01 00 00 00 00 00 00 00 00 00  0C 03 00 05 08 05")

        assert [(o["group"], o["variation"]) for o in body["objects"]] == [(12, 2), (12, 3)]
        assert [(p["group"], p["variation"], p["index"]) for p in body["points"]] == [
            (12, 2, 5),
            (12, 2, 7),
        ]
        assert {p["op_type"] for p in body["points"]} == {3}

    def test_a_pattern_mask_without_its_control_block_gives_no_points(self):
        body = _request("C0 05  0C 03 00 05 08 05")
        assert (len(body["objects"]), body["points"]) == (1, [])

    def test_a_relative_time_counts_from_the_common_time_of_occurrence(self):
        # Group 51 variation 1, qualifier 0x07, count 1: 1000000 ms. Then
        # group 2 variation 3, qualifier 0x17, one object: index 0, 0x81, 250 ms.
        body = _response("C0 81 00 00  33 01 07 01 40 42 0F 00 00 00  02 03 17 01 00 81 FA 00")

        (point,) = body["points"]
        assert point["time"] == 1_000_250
        assert [o["group"] for o in body["objects"]] == [51, 2]

    def test_a_relative_time_without_a_common_time_is_left_out(self):
        (point,) = _response("C0 81 00 00  02 03 17 01 00 81 FA 00")["points"]
        assert "time" not in point

    def test_integer_variations_give_integers_and_floats_keep_their_exact_value(self):
        # Group 30 variation 1 at index 0: 100. Group 30 variation 5 at index
        # 1: single precision 0.1, which is 0x3DCCCCCD.
        body = _response(
            "C0 81 00 00  1E 01 17 01 00 01 64 00 00 00  1E 05 17 01 01 01 CD CC CC 3D"
        )

        integer, single = (p["value"] for p in body["points"])
        assert (type(integer), integer) == (int, 100)
        assert single == struct.unpack("<f", bytes.fromhex("CDCCCC3D"))[0] != 0.1

    @pytest.mark.parametrize(
        "octets, name",
        [("000080FF", "-inf"), ("0000807F", "inf"), ("0000C07F", "nan")],
    )
    def test_a_non_finite_analog_value_is_null_with_its_name(self, octets, name):
        # Group 41 variation 3, qualifier 0x17, one object: index 0, the
        # value, status 0.
        (point,) = _request(f"C0 05  29 03 17 01 00 {octets} 00")["points"]
        assert (point["value"], point["non_finite"]) == (None, name)

    def test_a_double_precision_infinity_is_named(self):
        # Group 30 variation 6, qualifier 0x00, 0 to 0: flags 0x01, +infinity.
        (point,) = _response("C0 81 00 00  1E 06 00 00 00 01 00 00 00 00 00 00 F0 7F")["points"]
        assert (point["value"], point["non_finite"], point["flags"]) == (None, "inf", 1)

    def test_an_octet_string_is_its_octets_in_lowercase_hex(self):
        # Group 111 variation 2, qualifier 0x17, one object: index 3, 0xAB 0xCD.
        (point,) = _response("C0 81 00 00  6F 02 17 01 03 AB CD")["points"]
        assert (point["type"], point["value"]) == ("octet_string", "abcd")

    def test_a_virtual_address_range_numbers_from_its_start(self):
        # Group 110 variation 1, qualifier 0x03, virtual addresses 4 to 5.
        body = _response("C0 81 00 00  6E 01 03 04 05 41 42")

        assert body["objects"] == [
            {"group": 110, "variation": 1, "qualifier": 3, "start": 4, "stop": 5}
        ]
        assert [p["index"] for p in body["points"]] == [4, 5]


class TestObjects:
    def test_a_read_by_index_lists_its_headers_and_no_points(self):
        # Group 30 variation 0, qualifier 0x17, indices 3 and 5. Then group 60
        # variation 1, qualifier 0x06.
        body = _request("C0 01  1E 00 17 02 03 05  3C 01 06")

        assert body["objects"] == [
            {"group": 30, "variation": 0, "qualifier": 0x17, "count": 2},
            {"group": 60, "variation": 1, "qualifier": 0x06},
        ]
        assert body["points"] == []

    def test_a_read_with_an_inverted_range_is_malformed(self):
        # Group 30 variation 0, qualifier 0x00, start 5, stop 2: a range that
        # runs backwards, in a request that carries no objects.
        body = _request("C0 01  1E 00 00 05 02")
        assert (body["apdu_rejected"], body["objects"]) == ("malformed", [])

    def test_a_freeze_at_time_reads_its_time_object_and_then_its_headers(self):
        # Group 50 variation 2, qualifier 0x07, count 1: time and interval.
        # Then group 20 variation 0, qualifier 0x06.
        body = _request("C0 0B  32 02 07 01 00 00 00 00 00 00 10 27 00 00  14 00 06")

        assert body["objects"] == [
            {
                "group": 50,
                "variation": 2,
                "qualifier": 7,
                "count": 1,
                "data": "000000000000" + "10270000",
            },
            {"group": 20, "variation": 0, "qualifier": 6},
        ]
        assert body["points"] == []

    def test_a_write_of_the_internal_indications_gives_a_point_per_bit(self):
        # Group 80 variation 1, qualifier 0x00, 4 to 7: 0b0101, bits 4 and 6 set.
        body = _request("C0 02  50 01 00 04 07 05")

        assert body["objects"] == [
            {"group": 80, "variation": 1, "qualifier": 0, "start": 4, "stop": 7}
        ]
        assert [(p["type"], p["index"], p["value"]) for p in body["points"]] == [
            ("internal_indication", 4, 1),
            ("internal_indication", 5, 0),
            ("internal_indication", 6, 1),
            ("internal_indication", 7, 0),
        ]
        assert all(
            set(p) == {"type", "group", "variation", "index", "command", "value"}
            for p in body["points"]
        )

    def test_a_common_time_header_carries_its_octets_as_data(self):
        body = _response("C0 81 00 00  33 01 07 01 40 42 0F 00 00 00  02 03 17 01 00 81 FA 00")
        assert body["objects"][0]["data"] == "40420f000000"
        assert "data" not in body["objects"][1]

    def test_a_header_with_no_octets_after_it_has_no_data(self):
        body = _request("C0 01  3C 01 06  32 01 07 01")
        assert all("data" not in header for header in body["objects"])

    def test_an_object_with_a_size_prefix_is_walked_past(self):
        # Group 70 variation 3, qualifier 0x5B, count 1, size 3, three octets.
        # Then group 60 variation 1, qualifier 0x06.
        body = _request("C0 19  46 03 5B 01 03 00 AA BB CC  3C 01 06")

        assert body["objects"] == [
            {"group": 70, "variation": 3, "qualifier": 0x5B, "count": 1, "data": "0300aabbcc"},
            {"group": 60, "variation": 1, "qualifier": 6},
        ]
        assert "apdu_rejected" not in body


class TestRejected:
    @pytest.mark.parametrize(
        "fragment",
        [
            # The response header cut short: no internal indications.
            pytest.param("C0 81 00", id="header"),
            # Group 30 variation 1, 0 to 1, and one object and a half.
            pytest.param("C0 81 00 00  1E 01 00 00 01 01 64 00 00 00 01 64", id="object"),
            # An object header cut short.
            pytest.param("C0 81 00 00  1E 01", id="object header"),
            # Group 200, which this module does not read, with data.
            pytest.param("C0 81 00 00  C8 01 00 00 00 41", id="unknown group"),
            # Reserved range specifier code 0x0A.
            pytest.param("C0 81 00 00  1E 01 0A", id="reserved range"),
            # Group 30 variation 1 under a count with no index to name it.
            pytest.param("C0 81 00 00  1E 01 07 01 01 64 00 00 00", id="no index"),
            # An inverted range in a response, which leaves no object count.
            pytest.param("C0 81 00 00  1E 01 00 05 02", id="inverted range"),
            # Group 110 variation 0, an octet string of no length, with data.
            pytest.param("C0 81 00 00  6E 00 00 00 00", id="octet string of no length"),
        ],
    )
    def test_a_fragment_that_cannot_be_read_to_its_end_is_malformed(self, fragment):
        body = _response(fragment)

        assert body["apdu_rejected"] == "malformed"
        assert (body["objects"], body["points"]) == ([], [])
        _assert_valid([body])

    @pytest.mark.parametrize(
        "direction, fragment",
        [
            # Group 1 variation 2, qualifier 0x80: start-stop 0 to 0 with bit 7
            # set, which Table 4-6 does not permit, then one binary input.
            pytest.param("response", "C0 81 00 00  01 02 80 00 00 81", id="0x80"),
            # A read of class 1 data, qualifier 0x86: all objects with bit 7 set.
            pytest.param("request", "C0 01  3C 02 86", id="0x86"),
            # Group 50 variation 1, qualifier 0x0B: range code B with no size prefix.
            pytest.param("response", "C0 81 00 00  32 01 0B 01 01 02 03 04 05 06", id="0x0B"),
            # Group 30 variation 1, qualifier 0x10: an index prefix with a start and stop.
            pytest.param("response", "C0 81 00 00  1E 01 10 00 00 00 01 64 00 00 00", id="0x10"),
            # Group 50 variation 1, qualifier 0x47: a size prefix with range code 7.
            pytest.param("request", "C0 02  32 01 47 01 06 01 02 03 04 05 06", id="0x47"),
            # Group 30 variation 1, qualifier 0x70: reserved prefix code 7.
            pytest.param("response", "C0 81 00 00  1E 01 70 00 00", id="0x70"),
        ],
    )
    def test_a_qualifier_table_4_6_does_not_permit_is_malformed(self, direction, fragment):
        body = fragment_body(bytes.fromhex(fragment), direction=direction, source=1, destination=10)

        assert body["apdu_rejected"] == "malformed"
        assert (body["objects"], body["points"]) == ([], [])
        _assert_valid([body])

    @pytest.mark.parametrize(
        "fragment",
        [
            # Group 50 variation 1, qualifier 0x5B, count 1: a size of 1 for a
            # six-octet time.
            pytest.param("C0 02  32 01 5B 01 01 00 01 02 03 04 05 06", id="smaller"),
            # The same with a size of 7, followed by a seventh octet.
            pytest.param("C0 02  32 01 5B 01 07 00 01 02 03 04 05 06 07", id="larger"),
            # Two times under qualifier 0x4B: the first size is right and the
            # second, 3, is not. A walk that skipped by the layout's size would
            # read the octets after it as the next header.
            pytest.param(
                "C0 02  32 01 4B 02 06 01 02 03 04 05 06 03 01 02 03 04 05 06",
                id="second of two",
            ),
        ],
    )
    def test_a_size_prefix_that_disagrees_with_a_known_object_is_malformed(self, fragment):
        body = _request(fragment)

        assert body["apdu_rejected"] == "malformed"
        assert (body["objects"], body["points"]) == ([], [])
        _assert_valid([body])

    def test_a_size_prefix_that_matches_a_known_object_is_read(self):
        # Group 50 variation 1, qualifier 0x5B, count 1, size 6, then the time.
        body = _request("C0 02  32 01 5B 01 06 00 01 02 03 04 05 06")

        assert "apdu_rejected" not in body
        assert body["objects"] == [
            {"group": 50, "variation": 1, "qualifier": 0x5B, "count": 1, "data": "0600010203040506"}
        ]

    def test_a_rejected_response_keeps_its_internal_indications(self):
        body = _response("C0 81 80 00  1E 01")
        assert (body["iin"], body["apdu_rejected"]) == (["device_restart"], "malformed")

    def test_objects_that_end_before_the_range_does_disagree_with_its_count(self):
        # Group 20 variation 6, qualifier 0x00, 0 to 3: two of four counters.
        body = _response("C0 81 00 00  14 06 00 00 03 01 00 02 00")
        assert body["apdu_rejected"] == "point_count"

    def test_points_up_to_the_limit_are_listed(self):
        body = _response(_packed_binaries(MAX_POINTS).hex())
        assert len(body["points"]) == MAX_POINTS

    def test_more_points_than_the_limit_are_too_large(self):
        body = _response(_packed_binaries(MAX_POINTS + 1).hex())
        assert (body["apdu_rejected"], body["points"]) == ("too_large", [])
        _assert_valid([body])

    def test_data_up_to_a_whole_fragment_is_kept_and_longer_is_too_large(self):
        # Group 70 variation 3, qualifier 0x5B, count 1, then a two-octet size.
        def file_write(size: int) -> str:
            return ("C0 19  46 03 5B 01" + struct.pack("<H", size).hex() + "00" * size).replace(
                " ", ""
            )

        (header,) = _request(file_write(MAX_DATA_OCTETS - 2))["objects"]
        assert len(header["data"]) == 2 * MAX_DATA_OCTETS
        assert _request(file_write(MAX_DATA_OCTETS - 1))["apdu_rejected"] == "too_large"

    def test_object_headers_up_to_the_limit_are_listed_and_more_are_rejected(self):
        # Group 60 variation 1, qualifier 0x06, repeated.
        at_limit = bytes.fromhex("C0 01") + bytes.fromhex("3C 01 06") * MAX_OBJECTS
        over = at_limit + bytes.fromhex("3C 01 06")

        assert len(_request(at_limit.hex())["objects"]) == MAX_OBJECTS
        assert _request(over.hex())["apdu_rejected"] == "too_large"


def _packed_binaries(count: int) -> bytes:
    """Return a response with ``count`` packed binary inputs from index 0, all off."""
    # Group 1 variation 1, qualifier 0x02 (4-octet start and stop).
    head = bytes.fromhex("01 01 02") + struct.pack("<II", 0, count - 1)
    return bytes.fromhex("C0 81 00 00") + head + bytes((count + 7) // 8)


# --------------------------------------------------------------- envelopes


class TestEnvelope:
    def test_a_response_names_the_outstation_by_its_source_address(self):
        body = _response("C0 81 00 00")
        message = envelope(body, outstation=OUTSTATION_END, at=0.0)

        assert message.client_id == "10"
        assert message.source == NetworkEndpoint(OUTSTATION_END.host, OUTSTATION_END.port)

    def test_a_request_names_the_outstation_by_its_destination_address(self):
        assert envelope(_request("C0 01"), outstation=OUTSTATION_END, at=0.0).client_id == "10"

    def test_the_envelope_carries_the_body_and_a_hash_over_it(self):
        body = _vector_body(VECTORS["write/null response"])
        at = datetime(2026, 10, 27, 12, 0, 0, 250000, tzinfo=UTC).timestamp()

        message = envelope(body, outstation=OUTSTATION_END, at=at, forwarder_id="lab-1").to_dict()

        assert re.fullmatch(r"\d+\.\d+\.\d+|2\.0", message.pop("version"))
        data = json.dumps(body)
        timestamp = "2026-10-27T12:00:00.250000+00:00"
        assert message == {
            "protocol": "dnp3",
            "direction": "upstream",
            "timestamp": timestamp,
            "client_id": "10",
            "forwarder_id": "lab-1",
            "payload": {"content_type": "application/json", "data": data, "encoding": "utf-8"},
            "source": {"ip": "192.0.2.20", "port": 20000},
            "hash": str(uuid.uuid3(uuid.NAMESPACE_DNS, f"dnp3:10:{timestamp}:{data}")),
            "is_valid": True,
            "protocol_data": {"extra": {"capture_origin": "live", "client_id_source": ""}},
        }

    def test_the_serialized_fields_are_the_ones_the_contract_lists(self):
        # The fields py1815.envelope documents: always present, and present
        # only when set. A field added to the class and not to the contract,
        # or the reverse, fails here.
        always = {
            "version",
            "protocol",
            "direction",
            "timestamp",
            "client_id",
            "forwarder_id",
            "payload",
            "source",
            "hash",
            "is_valid",
        }
        when_set = {"destination", "protocol_data", "validation_error"}
        bare = ProtocolMessage(
            protocol=Protocol.DNP3,
            direction=WireDirection.UPSTREAM,
            client_id="10",
            payload={},
            source=NetworkEndpoint("192.0.2.20", 20000),
        )
        full = ProtocolMessage(
            protocol=Protocol.DNP3,
            direction=WireDirection.UPSTREAM,
            client_id="10",
            payload={},
            source=NetworkEndpoint("192.0.2.20", 20000),
            destination=NetworkEndpoint("192.0.2.10", 50123),
            protocol_data=ProtocolMetadata(extra={"capture_origin": "live"}),
            validation_error="example",
        )

        assert set(bare.to_dict()) == always
        assert set(full.to_dict()) == always | when_set
        assert {each.name for each in dataclasses.fields(ProtocolMessage)} == (
            always | when_set
        ) - {"version"}

    def test_a_serialized_envelope_reads_back_unchanged(self):
        body = _vector_body(VECTORS["unsolicited/event response"])
        written = envelope(body, outstation=OUTSTATION_END, at=1_792_310_400.0).to_dict()

        message = ProtocolMessage.from_dict(written)

        assert message.body == body
        assert message.to_dict() == written

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

    @pytest.mark.parametrize(
        "timestamp, problem",
        [
            pytest.param("2026-10-27T12:00:00", "no UTC offset", id="no offset"),
            pytest.param("2026-10-27 12:00:00.250", "no UTC offset", id="no offset, space"),
            pytest.param("2026-10-27", "no time", id="date only"),
            pytest.param("20261027", "no time", id="basic date only"),
            pytest.param("27 October 2026", "ISO 8601", id="not ISO 8601"),
        ],
    )
    def test_a_timestamp_that_names_no_instant_is_refused(self, timestamp, problem):
        with pytest.raises(ValueError, match=problem):
            ProtocolMessage(
                protocol=Protocol.DNP3,
                direction=WireDirection.UPSTREAM,
                client_id="1024",
                payload={},
                source=NetworkEndpoint("198.51.100.5", 20000),
                timestamp=timestamp,
            )

    def test_a_serialized_envelope_without_an_offset_is_refused(self):
        written = envelope(_request("C0 01"), outstation=OUTSTATION_END, at=0.0).to_dict()
        written["timestamp"] = "1970-01-01T00:00:00"

        with pytest.raises(ValueError, match="no UTC offset"):
            ProtocolMessage.from_dict(written)

    def test_a_timestamp_with_an_offset_other_than_utc_is_kept(self):
        message = ProtocolMessage(
            protocol=Protocol.DNP3,
            direction=WireDirection.UPSTREAM,
            client_id="1024",
            payload={},
            source=NetworkEndpoint("198.51.100.5", 20000),
            timestamp="2026-10-27T05:00:00-07:00",
        )

        assert message.to_dict()["timestamp"] == "2026-10-27T05:00:00-07:00"

    def test_an_empty_client_id_is_refused(self):
        with pytest.raises(ValueError, match="client_id"):
            ProtocolMessage(
                protocol="dnp3",
                direction="upstream",
                client_id=" ",
                payload={},
                source=NetworkEndpoint("198.51.100.5", 20000),
            )


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
            direction="request",
            source=1,
            destination=1024,
            sender=MASTER_END,
            receiver=OUTSTATION_END,
        )
        assert (response["source_address"], response["destination_address"]) == (1024, 1)
        assert (response["source_ip"], response["source_port"]) == ("192.0.2.20", 20000)
        assert (response["destination_ip"], response["destination_port"]) == ("192.0.2.10", 50123)
        assert response["direction"] == "response"
        assert response["objects"] == [{"group": 41, "variation": 2, "qualifier": 0x17, "count": 1}]
        assert response["points"] == [
            {
                "type": "analog_output",
                "group": 41,
                "variation": 2,
                "index": 1,
                "command": True,
                "value": 250,
                "status": 0,
            }
        ]

    def test_the_envelopes_carry_the_record_time_and_the_outstation(self):
        dut, seen = _dut()
        dut.master.read(classes(1, 2, 3, 0))
        (record,) = seen

        messages = record_messages(record, forwarder_id="lab-1")

        stamp = datetime.fromtimestamp(record.timestamp, UTC).isoformat()
        assert [message.timestamp for message in messages] == [stamp, stamp]
        assert {message.client_id for message in messages} == {"1024"}
        assert {message.forwarder_id for message in messages} == {"lab-1"}
        assert messages[0].source == NetworkEndpoint(OUTSTATION_END.host, OUTSTATION_END.port)
        assert [message.body for message in messages] == record_bodies(record)

    def test_an_unsolicited_response_gives_one_body_from_the_outstation(self):
        dut = Dut(analog_inputs=False, counters=False, unsolicited=True)
        dut.session.connection_peer = MASTER_END
        dut.session.connection_local = OUTSTATION_END
        seen: list[RequestRecord] = []
        dut.session.request_observer = seen.append
        dut.master.listen()

        (body,) = record_bodies(seen[0])

        assert (body["function_code"], body["unsolicited"]) == (130, True)
        assert "device_restart" in body["iin"]
        assert (body["source_address"], body["source_ip"]) == (1024, OUTSTATION_END.host)
        assert (body["destination_address"], body["destination_ip"]) == (1, MASTER_END.host)

    def test_a_record_without_the_outstation_address_needs_one_given(self):
        dut, seen = _dut()
        dut.session.connection_local = None
        dut.master.read(classes(0))
        (record,) = seen

        with pytest.raises(ValueError, match="outstation"):
            record_messages(record)
        (request, _) = record_messages(record, outstation=OUTSTATION_END)
        assert request.source.ip == OUTSTATION_END.host
        assert request.body is not None
        assert request.body["destination_ip"] == OUTSTATION_END.host

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
        assert client is not None and record.peer == client
        request, response = record_bodies(record)
        assert (request["source_ip"], request["source_port"]) == ("127.0.0.1", client.port)
        assert (request["destination_ip"], request["destination_port"]) == ("127.0.0.1", port)
        assert (response["source_address"], response["destination_address"]) == (1024, 1)
        (message, _) = record_messages(record)
        assert message.source == NetworkEndpoint("127.0.0.1", port)
        _assert_valid([request, response])


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
            direction="request",
            source=addresses[0],
            destination=addresses[1],
            sender=connection.local,
            receiver=connection.remote,
        )
        # Binary inputs with flags: each is a point, with its state and flag octet.
        assert [(o["group"], o["variation"]) for o in bodies[1]["objects"]] == [(1, 2)]
        assert bodies[1]["direction"] == "response"
        assert [(p["type"], p["index"]) for p in bodies[1]["points"]] == [
            ("binary", index) for index in range(4)
        ]
        assert all("flags" in p for p in bodies[1]["points"])
        _assert_valid(bodies)

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
