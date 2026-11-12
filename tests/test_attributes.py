"""Device attributes, object group 0, at Subset Level 4.

Every expectation is octets written out by hand from IEEE 1815-2012 5.5 and
Annex A.1, with the data type codes of TB2017-007a. The device under test is
the one of ``ied_harness``: four binary inputs, four analog inputs, three
counters that freeze, four binary outputs and four analog outputs.
"""

from __future__ import annotations

import pytest
from ied_harness import (
    ASSIGN_CLASS,
    IIN2_OBJECT_UNKNOWN,
    IIN2_PARAMETER,
    Q_RANGE_8,
    Q_RANGE_16,
    READ,
    WRITE,
    Dut,
    crobs,
    header,
)
from test_double_bit import Device as DoubleBitDevice

from py1815.application import ObjectHeader, QualifierCode
from py1815.attributes import (
    Attribute,
    BadParameter,
    DataType,
    DeviceAttributes,
    DeviceInformation,
    UnknownVariation,
    Variation,
    attribute_block,
    parse_attribute,
    parse_writes,
    read_blocks,
)
from py1815.decode import decode_objects
from py1815.profile import device_profile
from py1815.profile.model import Kind
from py1815.session import Session

INFORMATION = DeviceInformation(
    manufacturer="Acme",
    product="Widget 9",
    software_version="1.2.3",
    hardware_version="Rev D",
    serial_number="SN-1",
    location_name="Plant 4",
    device_id="ID-7",
    device_name="Unit A",
    timing_accuracy_us=2000,
)

#: What the device under test reports for each variation, as the data type
#: code, the length octet and the value, in the order of the standard's
#: Annex A.1. Each is read below under qualifier 0x00 with index 0.
EXPECTED = {
    209: "02 01 00",
    210: "02 01 00",
    211: "01 00",
    212: "02 01 00",
    213: "02 01 00",
    214: "02 01 00",
    215: "02 01 00",
    # Both fragment sizes are 2048 octets. A request of 156 control relay
    # output blocks, each with a two-octet index, fills the 2048-octet response.
    216: "02 01 9C",
    217: "02 02 D0 07",
    218: "02 01 00",
    219: "03 01 01",
    220: "02 01 03",
    221: "02 01 04",
    222: "03 01 01",
    223: "02 01 03",
    224: "02 01 04",
    225: "03 01 01",
    226: "03 01 01",
    227: "03 01 01",
    228: "02 01 02",
    229: "02 01 03",
    230: "03 01 00",
    231: "03 01 01",
    232: "02 01 03",
    233: "02 01 04",
    234: "03 01 00",
    235: "02 01 00",
    236: "02 01 00",
    237: "03 01 01",
    238: "02 01 03",
    239: "02 01 04",
    240: "02 02 00 08",
    241: "02 02 00 08",
    # "1.2.3", "Rev D", "Plant 4", "ID-7", "Unit A", "SN-1", "4:", "Widget 9", "Acme".
    242: "01 05 31 2E 32 2E 33",
    243: "01 05 52 65 76 20 44",
    245: "01 07 50 6C 61 6E 74 20 34",
    246: "01 04 49 44 2D 37",
    247: "01 06 55 6E 69 74 20 41",
    248: "01 04 53 4E 2D 31",
    249: "01 02 34 3A",
    250: "01 08 57 69 64 67 65 74 20 39",
    252: "01 04 41 63 6D 65",
}

#: The list of variations: each variation, then 01 where a master may write it.
LIST = bytes.fromhex(
    "D1 00 D2 00 D3 00 D4 00 D5 00 D6 00 D7 00 D8 00 D9 00 DA 00 DB 00 DC 00 DD 00 DE 00 DF 00"
    " E0 00 E1 00 E2 00 E3 00 E4 00 E5 00 E6 00 E7 00 E8 00 E9 00 EA 00 EB 00 EC 00 ED 00 EE 00"
    " EF 00 F0 01 F1 00 F2 00 F3 00 F5 01 F6 01 F7 01 F8 00 F9 00 FA 00 FC 00"
)


@pytest.fixture
def dut() -> Dut:
    return Dut(level=4, information=INFORMATION)


def _read(dut: Dut, variation: int, qualifier: int = Q_RANGE_8, *where: int):
    where = where or (0, 0)
    return dut.master.read(header(0, variation, qualifier, *where)).fragment


def _object(octets: str) -> bytes:
    return bytes.fromhex(octets)


def _write(dut: Dut, *objects: tuple[int, str], qualifier: int = Q_RANGE_8, index: int = 0):
    """Write attributes, each as a header with its range at ``index`` and its octets."""
    body = b""
    for variation, octets in objects:
        body += header(0, variation, qualifier, index, index) + _object(octets)
    return dut.master.request(WRITE, body).fragment


def _text(value: str) -> str:
    """The octets of a VSTR attribute: data type 1, the length, the characters."""
    return f"01 {len(value):02X} " + value.encode("ascii").hex(" ")


class TestRead:
    @pytest.mark.parametrize("variation", sorted(EXPECTED))
    def test_each_required_variation_is_read_alone_with_its_type_length_and_value(
        self, dut, variation
    ):
        response = _read(dut, variation)
        assert response.iin2 == 0
        assert response.body == bytes([0, variation, 0x00, 0, 0]) + _object(EXPECTED[variation])

    @pytest.mark.parametrize("variation", [209, 240, 249, 252])
    def test_a_sixteen_bit_range_is_answered_the_same_way(self, dut, variation):
        response = _read(dut, variation, Q_RANGE_16, 0, 0)
        assert response.iin2 == 0
        assert response.body == bytes([0, variation, 0x00, 0, 0]) + _object(EXPECTED[variation])

    def test_the_all_attributes_request_returns_every_attribute_in_order_and_no_list(self, dut):
        response = dut.master.read(header(0, 254)).fragment
        expected = b"".join(
            bytes([0, variation, 0x00, 0, 0]) + _object(octets)
            for variation, octets in sorted(EXPECTED.items())
        )
        assert response.body == expected
        assert response.iin2 == 0 and response.fir and response.fin

    def test_the_all_attributes_request_with_a_range_names_the_set(self, dut):
        everything = dut.master.read(header(0, 254)).fragment.body
        assert _read(dut, 254).body == everything

    def test_the_list_of_variations_marks_only_the_writable_ones(self, dut):
        response = dut.master.read(header(0, 255)).fragment
        # Qualifier 0x17, a count of one, set 0, data type 254, then the list.
        assert response.body == bytes([0, 255, 0x17, 1, 0, 254, len(LIST)]) + LIST
        assert response.iin2 == 0

    def test_the_list_read_by_range_is_the_same_list(self, dut):
        assert _read(dut, 255).body == dut.master.read(header(0, 255)).fragment.body

    def test_a_response_the_master_decoder_reads_in_full(self, dut):
        decoded = decode_objects(dut.master.read(header(0, 254)).fragment.body)
        assert decoded.complete
        assert [obj.variation for obj in decoded.objects] == sorted(EXPECTED)
        by_variation = {obj.variation: obj.attribute for obj in decoded.objects}
        assert by_variation[252].value == "Acme"
        assert by_variation[237].value == 1

    def test_a_read_of_two_variations_answers_in_the_order_asked(self, dut):
        response = dut.master.read(
            header(0, 252, Q_RANGE_8, 0, 0), header(0, 209, Q_RANGE_8, 0, 0)
        ).fragment
        assert response.body == (
            bytes([0, 252, 0, 0, 0]) + _object(EXPECTED[252]) + bytes([0, 209, 0, 0, 0, 2, 1, 0])
        )

    def test_attributes_and_points_in_one_read_keep_the_order_asked(self, dut):
        response = dut.master.read(
            header(1, 2, Q_RANGE_8, 0, 0),
            header(0, 209, Q_RANGE_8, 0, 0),
            header(1, 2, Q_RANGE_8, 1, 1),
        ).fragment
        assert response.body == bytes.fromhex(
            "01 02 00 00 00 01  00 D1 00 00 00 02 01 00  01 02 00 01 01 01"
        )

    def test_an_unoffered_optional_variation_is_an_unknown_object(self, dut):
        for variation in (196, 204, 208, 244, 251, 253):
            response = _read(dut, variation)
            assert response.iin2 & IIN2_OBJECT_UNKNOWN, variation
            assert response.body == b""

    def test_a_set_other_than_zero_is_a_parameter_error(self, dut):
        for variation in (209, 254, 255):
            response = _read(dut, variation, Q_RANGE_8, 1, 1)
            assert response.iin2 == IIN2_PARAMETER, variation
            assert response.body == b""

    def test_a_range_that_includes_a_missing_set_is_a_parameter_error(self, dut):
        assert _read(dut, 209, Q_RANGE_8, 0, 1).iin2 == IIN2_PARAMETER

    def test_qualifier_0x06_selects_no_single_attribute(self, dut):
        response = dut.master.read(header(0, 209)).fragment
        assert response.iin2 == IIN2_PARAMETER and response.body == b""

    def test_the_default_conformance_claim_is_the_level_and_no_test_year(self, dut):
        assert _read(dut, 249).body.endswith(bytes.fromhex("01 02 34 3A"))


class TestLevel:
    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_below_level_4_group_0_is_an_unknown_object_as_before(self, level):
        dut = Dut(level=level)
        assert dut.outstation.attributes is None
        for request in (header(0, 254), header(0, 209, Q_RANGE_8, 0, 0), header(0, 255)):
            response = dut.master.read(request).fragment
            assert response.iin2 == IIN2_OBJECT_UNKNOWN
            assert response.body == b""
        assert dut.session.facts.attributes is False

    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_below_level_4_a_write_of_an_attribute_is_an_unknown_object(self, level):
        response = _write(Dut(level=level), (245, _text("x")))
        assert response.iin2 == IIN2_OBJECT_UNKNOWN

    def test_level_4_claims_the_level_in_the_subset_attribute(self):
        dut = Dut(level=4)
        assert dut.outstation.attributes is not None
        assert dut.session.facts.attributes is True

    def test_a_session_given_no_attributes_does_not_answer_group_0(self):
        dut = Dut(level=4)
        plain = Session(dut.outstation, max_response=2048)
        assert plain.facts.attributes is False


class TestWhereValuesComeFrom:
    def test_counts_and_highest_indices_follow_the_points_served(self):
        dut = Dut(level=4, counters=False, binary_outputs=False, analog_inputs=False)
        values = {
            obj.variation: obj.value
            for obj in decode_objects(dut.master.read(header(0, 254)).fragment.body).objects
        }
        assert (values[228], values[229]) == (0, 0)
        assert (values[223], values[224]) == (0, 0)
        assert (values[232], values[233]) == (0, 0)
        assert (values[238], values[239]) == (3, 4)
        assert (values[220], values[221]) == (3, 4)

    def test_frozen_counters_are_reported_only_when_the_counters_freeze(self):
        # Counters that do not freeze have no class here, so they raise no
        # counter events either (D124).
        dut = Dut(level=4, frozen_counters=False)
        assert _read(dut, 226).body.endswith(bytes.fromhex("03 01 00"))
        assert _read(dut, 225).body.endswith(bytes.fromhex("03 01 00"))
        assert _read(dut, 227).body.endswith(bytes.fromhex("03 01 00"))
        assert _read(dut, 229).body.endswith(bytes.fromhex("02 01 03"))

    def test_event_support_is_false_for_a_kind_with_no_points(self):
        dut = Dut(level=4, binary_inputs=False, analog_inputs=False, binary_outputs=False)
        for variation in (237, 231, 222):
            assert _read(dut, variation).body.endswith(bytes.fromhex("03 01 00"))
        assert _read(dut, 219).body.endswith(bytes.fromhex("03 01 01"))

    def test_inputs_whose_events_start_off_still_support_events(self):
        # The tables give the binary inputs a class, so an ASSIGN_CLASS may turn
        # their events back on (D110).
        dut = Dut(level=4, event_policy={"defaults": {"BI": {"events": False}}})
        assert dut.outstation.event_class(Kind.BI, 0) == 0
        assert _read(dut, 237).body.endswith(bytes.fromhex("03 01 01"))

    def test_an_assign_class_to_class_0_leaves_event_support_as_it_was(self, dut):
        # Groups 1, 20, 30, 10 and 40, all points, to class 0. The points can
        # still be given a class again, so the device still supports their events.
        body = bytes.fromhex("3C 01 06  01 00 06  14 00 06  1E 00 06  0A 00 06  28 00 06")
        assert dut.master.request(ASSIGN_CLASS, body).fragment.iin2 == 0
        for variation in (219, 222, 225, 227, 231, 237):
            assert _read(dut, variation).body.endswith(bytes.fromhex("03 01 01"))

    def test_double_bit_inputs_are_counted_and_report_events(self):
        # Six double-bit inputs, indices 0 to 5, five of them in a class.
        device = DoubleBitDevice()
        body = device.body(*(header(0, v, Q_RANGE_8, 0, 0) for v in (234, 235, 236)))
        assert body == bytes.fromhex(
            "00 EA 00 00 00 03 01 01  00 EB 00 00 00 02 01 05  00 EC 00 00 00 02 01 06"
        )

    def test_subset_level_is_the_level_claimed(self):
        # The attributes exist only at Level 4, so the claim is always "4:".
        assert Dut(level=4).outstation.attributes.snapshot()[249] == Attribute.text("4:")

    def test_the_binary_output_limit_is_zero_without_controls(self):
        dut = Dut(level=4, binary_outputs=False, analog_outputs=False)
        assert _read(dut, 216).body.endswith(bytes.fromhex("02 01 00"))

    def test_the_default_identity_is_reported(self):
        dut = Dut(level=4)
        assert _read(dut, 252).body.endswith(_object(_text("Not stated")))
        assert _read(dut, 250).body.endswith(_object(_text("py1815 DER outstation")))
        assert _read(dut, 245).body.endswith(bytes.fromhex("01 00"))

    def test_the_binary_output_limit_is_what_a_control_request_may_carry(self, dut):
        # 156 control relay output blocks fit the request and its echo; 157 do not.
        fits = dut.master.request(5, crobs(list(range(156)))).fragment
        assert fits.body != b""
        refused = dut.master.request(5, crobs(list(range(157)))).fragment
        assert refused.body == b"" and refused.iin2 == IIN2_PARAMETER


class TestWriteText:
    @pytest.mark.parametrize("variation", [245, 246, 247])
    def test_a_written_text_is_answered_with_a_null_response_and_read_back(self, dut, variation):
        response = _write(dut, (variation, _text("Main Street")))
        assert response.is_null
        assert _read(dut, variation).body == (
            bytes([0, variation, 0, 0, 0]) + _object(_text("Main Street"))
        )

    def test_a_write_of_the_three_names_in_one_request_stores_all_three(self, dut):
        response = _write(dut, (245, _text("A")), (246, _text("B")), (247, _text("C")))
        assert response.is_null
        for variation, text in ((245, "A"), (246, "B"), (247, "C")):
            assert _read(dut, variation).body.endswith(_object(_text(text)))

    def test_a_write_by_sixteen_bit_range_is_taken(self, dut):
        body = bytes.fromhex("00 F6 01 00 00 00 00") + _object(_text("Z"))
        assert dut.master.request(WRITE, body).fragment.is_null
        assert _read(dut, 246).body.endswith(_object(_text("Z")))

    def test_an_empty_text_clears_the_attribute(self, dut):
        assert _write(dut, (245, "01 00")).is_null
        assert _read(dut, 245).body == bytes.fromhex("00 F5 00 00 00 01 00")

    def test_a_text_of_the_longest_length_is_taken_and_one_longer_is_refused(self, dut):
        longest = "x" * 128
        assert _write(dut, (245, _text(longest))).is_null
        response = _write(dut, (245, _text("y" * 129)))
        assert response.iin2 == IIN2_PARAMETER
        assert _read(dut, 245).body.endswith(_object(_text(longest)))

    @pytest.mark.parametrize(
        "octets",
        [
            pytest.param("02 01 07", id="an integer"),
            pytest.param("08 02 41 42", id="unicode text"),
            pytest.param("01 02 41 00", id="a null"),
            pytest.param("01 02 41 C3", id="a character past ASCII"),
            pytest.param("01 02 41 7F", id="a delete"),
            pytest.param("01 05 41 42", id="a length past the octets"),
            pytest.param("01", id="no length"),
        ],
    )
    def test_an_unacceptable_value_changes_nothing_and_sets_the_parameter_error(self, dut, octets):
        before = _read(dut, 245).body
        assert _write(dut, (245, octets)).iin2 == IIN2_PARAMETER
        assert _read(dut, 245).body == before

    def test_one_bad_value_in_a_request_stores_none_of_the_others(self, dut):
        response = _write(dut, (245, _text("New")), (246, "02 01 07"))
        assert response.iin2 == IIN2_PARAMETER
        assert _read(dut, 245).body.endswith(_object(EXPECTED[245]))

    @pytest.mark.parametrize("variation", [209, 242, 248, 249, 250, 252, 254, 255, 196])
    def test_an_attribute_a_master_may_not_write_is_an_unknown_object(self, dut, variation):
        before = dut.master.read(header(0, 254)).fragment.body
        assert _write(dut, (variation, _text("x"))).iin2 == IIN2_OBJECT_UNKNOWN
        assert dut.master.read(header(0, 254)).fragment.body == before

    def test_a_write_to_another_set_is_a_parameter_error(self, dut):
        assert _write(dut, (245, _text("x")), index=1).iin2 == IIN2_PARAMETER

    def test_a_write_under_a_count_qualifier_is_a_parameter_error(self, dut):
        body = bytes.fromhex("00 F5 07 01") + _object(_text("x"))
        assert dut.master.request(WRITE, body).fragment.iin2 == IIN2_PARAMETER

    def test_a_written_value_is_kept_across_a_new_connection(self, dut):
        _write(dut, (245, _text("Kept")))
        dut.session.connection_reset()
        assert _read(dut, 245).body.endswith(_object(_text("Kept")))

    def test_a_restart_returns_written_values_to_the_configured_ones(self, dut):
        _write(dut, (245, _text("Gone")))
        _write(dut, (240, "02 02 00 05"))
        dut.session.restart()
        assert _read(dut, 245).body.endswith(_object(EXPECTED[245]))
        assert _read(dut, 240).body.endswith(_object(EXPECTED[240]))


class TestWriteFragmentSize:
    def test_a_written_size_is_read_back_and_answered_with_a_null_response(self, dut):
        assert _write(dut, (240, "02 02 B0 04")).is_null
        assert _read(dut, 240).body == bytes.fromhex("00 F0 00 00 00 02 02 B0 04")

    def test_a_size_in_one_octet_or_four_is_read_as_the_same_number(self):
        small = Dut(level=4, block_octets=32)
        assert _write(small, (240, "02 01 80")).is_null
        assert _read(small, 240).body.endswith(bytes.fromhex("02 01 80"))
        assert _write(small, (240, "02 04 00 08 00 00")).is_null
        assert _read(small, 240).body.endswith(bytes.fromhex("02 02 00 08"))

    def test_responses_are_fragmented_to_the_size_written(self):
        many = Dut(level=4, extra_analogs=800, capacity=50)
        # The analog inputs take several blocks of the largest size.
        request = header(30, 1, Q_RANGE_16, 0, 803)
        before = many.master.poll(request)
        assert max(len(f.octets) for f in before) > 1200
        assert _write(many, (240, "02 02 B0 04")).is_null  # 1200 octets
        after = many.master.poll(request)
        assert len(after) > len(before)
        assert max(len(f.octets) for f in after) <= 1200

    def test_a_response_is_never_larger_than_the_size_written_for_the_attributes_either(self):
        many = Dut(level=4)
        assert _write(many, (240, "02 02 04 04")).is_null  # 1028, the least this device can use
        sizes = [len(f.octets) for f in many.master.poll(header(0, 254))]
        assert all(size <= 1028 for size in sizes)

    @pytest.mark.parametrize(
        "octets",
        [
            pytest.param("02 02 03 04", id="below the largest block"),
            pytest.param("02 02 01 08", id="above the size configured"),
            pytest.param("02 01 00", id="zero"),
            pytest.param("03 02 B0 04", id="a signed integer"),
            pytest.param("02 00", id="no octets"),
            pytest.param("01 02 31 32", id="text"),
        ],
    )
    def test_a_size_outside_the_limits_changes_nothing_and_sets_the_parameter_error(
        self, dut, octets
    ):
        assert _write(dut, (240, octets)).iin2 == IIN2_PARAMETER
        assert _read(dut, 240).body.endswith(_object(EXPECTED[240]))

    def test_the_size_can_be_raised_back_up_to_the_one_configured(self, dut):
        assert _write(dut, (240, "02 02 B0 04")).is_null
        assert _write(dut, (240, "02 02 00 08")).is_null
        assert _read(dut, 240).body.endswith(_object(EXPECTED[240]))

    def test_the_binary_output_limit_follows_the_size_written(self, dut):
        assert _write(dut, (240, "02 02 B0 04")).is_null
        # (1200 - 4 - 5) // 13 control relay output blocks.
        assert _read(dut, 216).body.endswith(bytes.fromhex("02 01 5B"))

    def test_a_size_and_a_name_in_one_request_are_both_stored(self, dut):
        assert _write(dut, (240, "02 02 B0 04"), (247, _text("Both"))).is_null
        assert _read(dut, 240).body.endswith(bytes.fromhex("02 02 B0 04"))
        assert _read(dut, 247).body.endswith(_object(_text("Both")))

    def test_the_size_is_the_largest_the_session_is_asked_for_and_not_the_one_it_receives(
        self, dut
    ):
        assert _write(dut, (240, "02 02 B0 04")).is_null
        assert _read(dut, 241).body.endswith(_object(EXPECTED[241]))


class TestAttributeModule:
    def test_unsigned_integers_take_the_fewest_octets_of_1_2_4_or_8(self):
        assert Attribute.unsigned(0).encode() == bytes.fromhex("02 01 00")
        assert Attribute.unsigned(255).encode() == bytes.fromhex("02 01 FF")
        assert Attribute.unsigned(256).encode() == bytes.fromhex("02 02 00 01")
        assert Attribute.unsigned(65536).encode() == bytes.fromhex("02 04 00 00 01 00")
        assert Attribute.unsigned(2**32).encode() == bytes.fromhex("02 08 00 00 00 00 01 00 00 00")
        with pytest.raises(ValueError):
            Attribute.unsigned(-1)

    def test_a_flag_is_an_integer_of_one_octet(self):
        assert Attribute.flag(True).encode() == bytes.fromhex("03 01 01")
        assert Attribute.flag(False).encode() == bytes.fromhex("03 01 00")

    def test_text_is_visible_ascii_of_at_most_128_characters(self):
        assert Attribute.text("a b~").encode() == bytes.fromhex("01 04 61 20 62 7E")
        for bad in ("é", "a\tb", "x" * 129, "\x7f"):
            with pytest.raises(ValueError, match="visible ASCII"):
                Attribute.text(bad)

    def test_a_list_longer_than_255_octets_takes_the_extended_data_type(self):
        listing = Attribute.variation_list({variation: False for variation in range(1, 129)})
        assert listing.code == DataType.U8BS8EXLIST
        assert listing.encode()[:2] == bytes([255, 0])
        assert len(listing.data) == 256
        parsed, end = parse_attribute(listing.encode())
        assert parsed == listing and end == 258

    def test_an_extended_list_outside_256_to_511_octets_is_refused(self):
        with pytest.raises(ValueError):
            Attribute(DataType.U8BS8EXLIST, b"\x00" * 255)
        with pytest.raises(ValueError):
            Attribute(DataType.VSTR, b"x" * 256)

    @pytest.mark.parametrize(
        "octets, value",
        [
            ("01 03 41 42 43", "ABC"),
            ("02 02 DC 05", 1500),
            ("03 02 FF FF", -1),
            ("04 04 00 00 C8 42", 100.0),
            ("04 08 00 00 00 00 00 00 59 40", 100.0),
            ("05 02 01 02", b"\x01\x02"),
            ("06 02 05 01", 0x0105),
            ("07 06 00 E4 0B 54 02 00", 10_000_000_000),
            ("08 02 C3 A9", "é"),
            ("FE 04 F0 01 F1 00", ((0xF0, True), (0xF1, False))),
            ("FE 00", ()),
        ],
    )
    def test_each_data_type_decodes_to_its_value(self, octets, value):
        attribute, end = parse_attribute(_object(octets))
        assert end == len(_object(octets))
        assert attribute.value == value

    def test_a_float_of_another_size_has_no_value(self):
        assert parse_attribute(bytes.fromhex("04 03 00 00 00"))[0].value is None

    def test_an_attribute_cut_short_is_refused(self):
        for octets in ("", "01", "01 03 41 42"):
            with pytest.raises(ValueError, match="cut short"):
                parse_attribute(_object(octets))

    def test_the_block_of_a_list_is_under_qualifier_0x17_and_any_other_under_a_range(self):
        listing = Attribute.variation_list({240: True})
        assert attribute_block(255, listing) == bytes.fromhex("00 FF 17 01 00 FE 02 F0 01")
        assert attribute_block(250, Attribute.text("A"), index=0) == bytes.fromhex(
            "00 FA 00 00 00 01 01 41"
        )

    def test_a_read_names_the_set_and_the_variation_it_asks_for(self):
        view = {209: Attribute.unsigned(0)}
        read = ObjectHeader(0, 209, QualifierCode.UINT8_START_STOP, 0, 0)
        assert read_blocks([read], view, ()) == [bytes.fromhex("00 D1 00 00 00 02 01 00")]
        with pytest.raises(UnknownVariation):
            read_blocks([ObjectHeader(0, 250, QualifierCode.UINT8_START_STOP, 0, 0)], view, ())
        with pytest.raises(BadParameter):
            read_blocks([ObjectHeader(0, 209, QualifierCode.UINT8_COUNT, count=1)], view, ())

    def test_a_write_walks_each_header_and_the_object_after_it(self):
        first = ObjectHeader(0, 245, QualifierCode.UINT8_START_STOP, 0, 0)
        body = _object("01 01 41  00 F6 00 00 00 01 02 42 43")
        assert parse_writes(first, body) == [
            (245, Attribute.text("A")),
            (246, Attribute.text("BC")),
        ]

    def test_a_write_of_another_group_is_an_unknown_variation(self):
        first = ObjectHeader(0, 245, QualifierCode.UINT8_START_STOP, 0, 0)
        body = _object("01 01 41  01 02 00 00 00")
        with pytest.raises(UnknownVariation):
            parse_writes(first, body)

    def test_the_store_checks_before_it_stores(self):
        store = DeviceAttributes(
            {245: Attribute.text("a"), 246: Attribute.text("b")}, writable=(245, 246)
        )
        with pytest.raises(BadParameter):
            store.write([(245, Attribute.text("x")), (246, Attribute.unsigned(1))])
        assert store.snapshot()[245] == Attribute.text("a")

    def test_a_store_refuses_what_is_not_its_to_hold(self):
        with pytest.raises(ValueError, match="not the store's"):
            DeviceAttributes({240: Attribute.unsigned(1)})
        with pytest.raises(ValueError, match="not the store's"):
            DeviceAttributes({255: Attribute.unsigned(1)})
        with pytest.raises(ValueError, match="does not hold text"):
            DeviceAttributes({245: Attribute.unsigned(1)}, writable=(245,))
        with pytest.raises(ValueError, match="not supplied"):
            DeviceAttributes({}, writable=(245,))


class TestDeviceInformation:
    def test_each_text_names_its_field_when_it_is_refused(self):
        with pytest.raises(ValueError, match=r"^serial_number: "):
            DeviceInformation(serial_number="café")
        with pytest.raises(ValueError, match=r"^product: "):
            DeviceInformation(product="x" * 129)

    @pytest.mark.parametrize("accuracy", [-1, 2**32, True])
    def test_the_timing_accuracy_is_an_unsigned_32_bit_number(self, accuracy):
        with pytest.raises(ValueError, match="timing_accuracy_us"):
            DeviceInformation(timing_accuracy_us=accuracy)

    def test_no_software_version_means_this_librarys_version(self):
        assert DeviceInformation().software().startswith("py1815")
        assert DeviceInformation(software_version="9").software() == "9"

    def test_the_information_given_is_what_the_attributes_report(self):
        dut = Dut(level=4, information=INFORMATION)
        view = dut.outstation.attributes.snapshot()
        assert view[Variation.MANUFACTURER_NAME] == Attribute.text("Acme")
        assert view[Variation.LOCAL_TIMING_ACCURACY] == Attribute.unsigned(2000)


class TestRequestsAreRead:
    def test_a_read_request_for_the_standards_own_example_is_answered_as_it_shows(self):
        # IEEE 1815-2012 5.5.5: reading the maximum receive fragment size.
        dut = Dut(level=4, max_response=1500, max_fragment=1500)
        assert dut.master.request(READ, bytes.fromhex("00 F1 00 00 00")).fragment.body == (
            bytes.fromhex("00 F1 00 00 00 02 02 DC 05")
        )


class TestDeviceProfile:
    def _rows(self, dut: Dut):
        table = device_profile.implementation(dut.outstation, dut.session.facts)
        return [row for row in table.rows if row.group == 0]

    def test_below_level_4_no_attribute_is_listed(self):
        for level in (None, 2, 3):
            assert self._rows(Dut(level=level)) == []

    def test_the_table_lists_each_attribute_the_session_serves_and_the_two_lists(self, dut):
        listed = {row.variation for row in self._rows(dut)}
        assert listed == set(EXPECTED) | {254, 255}

    def test_the_writable_variations_are_the_ones_listed_for_write(self, dut):
        written = {r.variation for r in self._rows(dut) if r.request[0] == device_profile.WRITE}
        assert written == {240, 245, 246, 247}

    def test_every_request_the_table_lists_is_answered_with_a_qualifier_it_lists(self, dut):
        for row in self._rows(dut):
            function, qualifiers = row.request
            for qualifier in qualifiers:
                if function == device_profile.READ:
                    span = {0x00: (0, 0), 0x01: (0, 0)}.get(qualifier, ())
                    response = dut.master.read(header(0, row.variation, qualifier, *span)).fragment
                    assert response.iin2 == 0, (row, qualifier)
                    if row.response is not None:
                        assert response.body[2] in row.response[1], (row, qualifier)
                else:
                    octets = "02 02 00 08" if row.variation == 240 else _text("x")
                    response = _write(dut, (row.variation, octets), qualifier=qualifier)
                    assert response.is_null, (row, qualifier)

    def test_no_row_is_listed_twice(self, dut):
        table = device_profile.implementation(dut.outstation, dut.session.facts)
        assert len(table.rows) == len(set(table.rows))
