"""The application envelope from a master's side: requests built, responses parsed."""

from __future__ import annotations

import pytest

from py1815.application import (
    FunctionCode,
    IIN2Bit,
    IINBit,
    ResponseError,
    all_objects_header,
    build_confirm,
    build_request,
    class_header,
    index_list_header,
    parse_response,
)


class TestBuildingARequest:
    def test_a_read_is_one_fragment_that_asks_for_no_confirmation(self):
        body = bytes.fromhex("3C 02 06 3C 03 06 3C 04 06 3C 01 06")
        assert build_request(FunctionCode.READ, sequence=3, body=body) == bytes.fromhex(
            "C3 01 3C 02 06 3C 03 06 3C 04 06 3C 01 06"
        )

    def test_the_sequence_number_wraps_into_four_bits(self):
        assert build_request(FunctionCode.READ, sequence=15)[0] == 0xCF
        assert build_request(FunctionCode.READ, sequence=16)[0] == 0xC0

    def test_a_request_with_nothing_after_the_function_code(self):
        assert build_request(FunctionCode.DELAY_MEASURE, sequence=0) == bytes.fromhex("C0 17")


class TestConfirming:
    def test_a_solicited_fragment(self):
        assert build_confirm(sequence=5) == bytes.fromhex("C5 00")

    def test_an_unsolicited_one_carries_the_unsolicited_bit(self):
        assert build_confirm(sequence=5, unsolicited=True) == bytes.fromhex("D5 00")


class TestHeaders:
    def test_each_class_has_its_variation_of_group_60(self):
        assert class_header(0) == bytes.fromhex("3C 01 06")
        assert class_header(1) == bytes.fromhex("3C 02 06")
        assert class_header(2) == bytes.fromhex("3C 03 06")
        assert class_header(3) == bytes.fromhex("3C 04 06")

    def test_there_is_no_class_4(self):
        with pytest.raises(ValueError, match="no class 4"):
            class_header(4)

    def test_every_object_of_a_group(self):
        assert all_objects_header(30, 0) == bytes.fromhex("1E 00 06")

    def test_named_points_fit_one_octet_each_when_they_can(self):
        assert index_list_header(30, 0, [4, 6, 8]) == bytes.fromhex("1E 00 17 03 04 06 08")

    def test_and_take_two_when_one_of_them_cannot(self):
        assert index_list_header(30, 0, [4, 300]) == bytes.fromhex("1E 00 28 02 00 04 00 2C 01")

    def test_the_order_given_is_the_order_asked_and_a_point_may_repeat(self):
        assert index_list_header(1, 0, [9, 2, 9]) == bytes.fromhex("01 00 17 03 09 02 09")

    @pytest.mark.parametrize("indices", [[], [-1], [65536]])
    def test_an_index_list_that_cannot_be_sent_is_refused(self, indices):
        with pytest.raises(ValueError):
            index_list_header(30, 0, indices)


class TestParsingAResponse:
    def test_a_response_is_its_envelope_and_the_objects_unread(self):
        response = parse_response(bytes.fromhex("C3 81 90 04 1E 02 00 00 00 01 2C 01"))
        assert response.function is FunctionCode.RESPONSE
        assert (response.control.fir, response.control.fin, response.control.con) == (
            True,
            True,
            False,
        )
        assert response.control.sequence == 3
        assert response.iin.is_set(IINBit.DEVICE_RESTART)
        assert response.iin.is_set(IINBit.NEED_TIME)
        assert response.iin.is_set(IIN2Bit.PARAM_ERROR)
        assert response.body == bytes.fromhex("1E 02 00 00 00 01 2C 01")
        assert not response.unsolicited

    def test_a_null_response(self):
        response = parse_response(bytes.fromhex("C0 81 00 00"))
        assert response.body == b""

    def test_an_unsolicited_response(self):
        response = parse_response(bytes.fromhex("F2 82 80 00"))
        assert response.unsolicited
        assert response.control.con and response.control.uns
        assert response.control.sequence == 2

    def test_a_fragment_shorter_than_a_response_header_is_not_one(self):
        with pytest.raises(ResponseError, match="shorter"):
            parse_response(bytes.fromhex("C0 81 00"))

    def test_a_request_is_not_a_response(self):
        with pytest.raises(ResponseError, match="READ is a request"):
            parse_response(bytes.fromhex("C0 01 3C 01 06"))

    def test_nor_is_a_function_code_nobody_assigned(self):
        with pytest.raises(ResponseError, match="0x7F"):
            parse_response(bytes.fromhex("C0 7F 00 00"))

    def test_a_function_and_an_unsolicited_bit_that_disagree_are_refused(self):
        """Read either way, it would be confirmed in the wrong sequence series."""
        with pytest.raises(ResponseError, match="unsolicited bit set"):
            parse_response(bytes.fromhex("D0 81 00 00"))
        with pytest.raises(ResponseError, match="unsolicited bit clear"):
            parse_response(bytes.fromhex("C0 82 00 00"))
