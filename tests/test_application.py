"""The DNP3 application envelope: what a request says, and what a response says back.

Object semantics are not tested here because they are not implemented here. What
is pinned is the envelope and its edges: the control octet, the qualifiers this
outstation accepts, the ranges it refuses, and which indication bit a malformed
request earns.
"""

from __future__ import annotations

import struct

import pytest

from py1815.application import (
    IIN,
    SEQ_MASK,
    AppControl,
    FunctionCode,
    IIN2Bit,
    IINBit,
    QualifierCode,
    RequestError,
    build_response,
    null_response,
    object_header,
    parse_request,
)


def _request(function: int, *objects: bytes, sequence: int = 0) -> bytes:
    control = AppControl(sequence=sequence).to_byte()
    return bytes([control, function]) + b"".join(objects)


def _class_header(variation: int) -> bytes:
    return bytes([60, variation, QualifierCode.ALL_OBJECTS])


class TestAppControl:
    def test_every_bit_round_trips(self):
        control = AppControl(fir=True, fin=False, con=True, uns=True, sequence=9)

        assert AppControl.from_byte(control.to_byte()) == control

    @pytest.mark.parametrize(
        ("control", "octet"),
        [
            (AppControl(fir=True, fin=False, sequence=5), 0x85),
            (AppControl(fir=False, fin=True, sequence=5), 0x45),
            (AppControl(fir=False, fin=False, con=True, sequence=0), 0x20),
            (AppControl(fir=False, fin=False, uns=True, sequence=0), 0x10),
            (AppControl(fir=True, fin=True, con=True, uns=True, sequence=15), 0xFF),
        ],
    )
    def test_each_field_encodes_to_the_octet_the_standard_specifies(self, control, octet):
        """Literal octets rather than the module's own masks.

        FIR is 0x80 and FIN is 0x40 here, the reverse of the transport function,
        and a test written against the constants would pass just as happily with
        the two swapped -- which is the mistake it exists to catch."""
        assert control.to_byte() == octet
        assert AppControl.from_byte(octet) == control

    def test_the_sequence_wraps_at_sixteen(self):
        """Four bits here, six in the transport function."""
        assert AppControl(sequence=16).to_byte() & SEQ_MASK == 0
        assert AppControl(sequence=17).to_byte() & SEQ_MASK == 1


class TestIin:
    def test_bits_merge(self):
        merged = IIN(first=IINBit.DEVICE_RESTART) | IIN(second=IIN2Bit.FUNC_NOT_SUPPORTED)

        assert merged.is_set(IINBit.DEVICE_RESTART)
        assert merged.is_set(IIN2Bit.FUNC_NOT_SUPPORTED)
        assert merged.to_bytes() == bytes([0x80, 0x01])

    def test_a_bit_of_one_octet_is_not_read_from_the_other(self):
        """BROADCAST and FUNC_NOT_SUPPORTED are both 0x01, in different octets."""
        iin = IIN(first=IINBit.BROADCAST)

        assert iin.is_set(IINBit.BROADCAST)
        assert not iin.is_set(IIN2Bit.FUNC_NOT_SUPPORTED)

    def test_an_empty_field_is_two_zero_octets(self):
        assert IIN().to_bytes() == b"\x00\x00"


class TestParsingReads:
    def test_an_integrity_poll_names_class_zero_through_three(self):
        request = parse_request(
            _request(FunctionCode.READ, *(_class_header(v) for v in (1, 2, 3, 4)))
        )

        assert request.known_function is FunctionCode.READ
        assert [h.event_class for h in request.headers] == [0, 1, 2, 3]
        assert all(h.qualifier is QualifierCode.ALL_OBJECTS for h in request.headers)

    def test_a_class_one_poll_names_one_class(self):
        request = parse_request(_request(FunctionCode.READ, _class_header(2)))

        assert [h.event_class for h in request.headers] == [1]

    def test_a_one_octet_range_read_is_parsed(self):
        request = parse_request(
            _request(FunctionCode.READ, bytes([30, 1, QualifierCode.UINT8_START_STOP, 4, 9]))
        )
        header = request.headers[0]

        assert (header.group, header.variation) == (30, 1)
        assert (header.start, header.stop) == (4, 9)

    def test_a_two_octet_range_read_is_parsed(self):
        """The fleet map runs past index 255, so the wide range field is the
        common case rather than the exotic one."""
        body = struct.pack("<BBBHH", 30, 5, QualifierCode.UINT16_START_STOP, 1000, 2000)
        header = parse_request(_request(FunctionCode.READ, body)).headers[0]

        assert (header.start, header.stop) == (1000, 2000)

    def test_a_group_that_names_no_class_reports_none(self):
        header = parse_request(
            _request(FunctionCode.READ, bytes([30, 1, QualifierCode.ALL_OBJECTS]))
        ).headers[0]

        assert not header.is_class_request
        assert header.event_class is None

    def test_a_read_with_no_headers_is_legal(self):
        assert parse_request(_request(FunctionCode.READ)).headers == ()


class TestParsingOtherFunctions:
    def test_a_confirmation_is_parsed(self):
        request = parse_request(_request(FunctionCode.CONFIRM, sequence=4))

        assert request.known_function is FunctionCode.CONFIRM
        assert request.control.sequence == 4

    def test_a_confirmation_carrying_objects_is_refused(self):
        with pytest.raises(RequestError, match="carries no objects"):
            parse_request(_request(FunctionCode.CONFIRM, _class_header(1)))

    def test_a_write_is_parsed_as_far_as_its_first_header(self):
        """Walking past it needs the width of every group, which is the point
        map's knowledge. The objects come back untouched instead."""
        request = parse_request(
            _request(
                FunctionCode.WRITE,
                bytes([80, 1, QualifierCode.UINT8_START_STOP, 7, 7]),
                b"\x00",
            )
        )

        assert (request.headers[0].group, request.headers[0].variation) == (80, 1)
        assert request.body == b"\x00"

    def test_an_indexed_read_consumes_its_index_list(self):
        """Qualifier 0x17 is followed by its indices, and a parser that stopped
        at the count would read the first index as the next object header."""
        request = parse_request(
            _request(
                FunctionCode.READ,
                bytes([30, 1, QualifierCode.UINT8_COUNT_UINT8_INDEX, 3, 4, 9, 11]),
            )
        )

        assert len(request.headers) == 1
        assert request.headers[0].indices == (4, 9, 11)
        assert request.body == b""

    def test_a_wide_indexed_read_consumes_two_octets_per_index(self):
        request = parse_request(
            _request(
                FunctionCode.READ,
                bytes([30, 1, QualifierCode.UINT16_COUNT_UINT16_INDEX])
                + struct.pack("<HHH", 2, 1009, 2018),
            )
        )

        assert request.headers[0].indices == (1009, 2018)

    def test_an_indexed_read_is_followed_by_the_next_header(self):
        """The proof that the index list was consumed rather than skipped."""
        request = parse_request(
            _request(
                FunctionCode.READ,
                bytes([30, 1, QualifierCode.UINT8_COUNT_UINT8_INDEX, 2, 4, 9]),
                bytes([60, 2, QualifierCode.ALL_OBJECTS]),
            )
        )

        assert [(h.group, h.variation) for h in request.headers] == [(30, 1), (60, 2)]

    def test_a_truncated_index_list_is_refused(self):
        with pytest.raises(RequestError, match="index list is truncated"):
            parse_request(
                _request(
                    FunctionCode.READ,
                    bytes([30, 1, QualifierCode.UINT8_COUNT_UINT8_INDEX, 3, 4]),
                )
            )

    def test_a_data_carrying_request_leaves_its_indices_in_the_body(self):
        """There the indices prefix their own objects and the two interleave, so
        a contiguous list would be the wrong reading."""
        request = parse_request(
            _request(
                FunctionCode.WRITE,
                bytes([41, 1, QualifierCode.UINT8_COUNT_UINT8_INDEX, 1]),
                b"payload",
            )
        )

        assert request.headers[0].count == 1
        assert request.headers[0].indices is None
        assert request.body == b"payload"

    def test_a_count_qualifier_reports_its_count(self):
        request = parse_request(
            _request(FunctionCode.WRITE, bytes([50, 1, QualifierCode.UINT8_COUNT, 1]), b"x" * 6)
        )

        assert request.headers[0].count == 1
        assert request.body == b"x" * 6

    def test_an_unknown_function_carrying_a_payload_still_parses(self):
        """Nothing here knows an unknown function's body layout, so reading its
        first octets as an object header would invent a structure and then
        refuse the request for failing to have it -- leaving the session unable
        to answer FUNC_NOT_SUPPORTED, which is the answer a master is owed."""
        request = parse_request(_request(0x7F, b""))

        assert request.known_function is None
        assert request.headers == ()
        assert request.body == b""

    @pytest.mark.parametrize(
        "function",
        [FunctionCode.OPEN_FILE, FunctionCode.AUTH_REQUEST, FunctionCode.DELAY_MEASURE],
    )
    def test_a_recognized_function_this_module_does_not_parse_still_parses(self, function):
        """Its qualifiers are ones this module does not accept, and raising on
        them answers "parameter error" to a request whose real answer is
        "function not supported". The caller needs the request to say that."""
        request = parse_request(_request(function, bytes([70, 3, 0x5B, 0x00])))

        assert request.known_function is function
        assert request.headers == ()
        assert request.body == bytes([70, 3, 0x5B, 0x00])

    def test_an_unknown_function_code_still_parses(self):
        """Answering "function not supported" requires having read the request,
        so an unrecognized code is a parse result rather than a parse failure."""
        request = parse_request(_request(0x7F))

        assert request.known_function is None
        assert request.function == 0x7F


class TestMalformedRequests:
    def test_a_fragment_too_short_for_a_header_is_refused(self):
        with pytest.raises(RequestError, match="shorter than an application header"):
            parse_request(b"\xc0")

    def test_a_truncated_object_header_is_refused(self):
        with pytest.raises(RequestError, match="header is truncated"):
            parse_request(_request(FunctionCode.READ, bytes([60, 1])))

    def test_a_truncated_range_field_is_refused(self):
        with pytest.raises(RequestError, match="range field is truncated"):
            parse_request(
                _request(FunctionCode.READ, bytes([30, 1, QualifierCode.UINT8_START_STOP, 4]))
            )

    def test_a_truncated_count_field_is_refused(self):
        with pytest.raises(RequestError, match="count field is truncated"):
            parse_request(_request(FunctionCode.WRITE, bytes([50, 1, QualifierCode.UINT16_COUNT])))

    def test_a_backwards_range_is_refused(self):
        with pytest.raises(RequestError, match="ends before it begins"):
            parse_request(
                _request(FunctionCode.READ, bytes([30, 1, QualifierCode.UINT8_START_STOP, 9, 4]))
            )

    def test_an_unsupported_qualifier_is_a_parameter_error(self):
        with pytest.raises(RequestError, match="not one this outstation accepts") as raised:
            parse_request(_request(FunctionCode.READ, bytes([30, 1, 0x5B])))

        assert raised.value.bit is IIN2Bit.PARAM_ERROR

    def test_a_malformed_request_carries_the_bit_that_answers_it(self):
        """The session answers from the bit rather than re-deriving why."""
        with pytest.raises(RequestError) as raised:
            parse_request(_request(FunctionCode.READ, bytes([60, 1])))

        assert raised.value.bit is IIN2Bit.PARAM_ERROR


class TestBuildingResponses:
    def test_a_response_carries_its_control_function_and_indications(self):
        response = build_response(
            control=AppControl(sequence=3),
            iin=IIN(first=IINBit.DEVICE_RESTART),
            body=b"objects",
        )

        assert response[0] & SEQ_MASK == 3
        assert response[1] == FunctionCode.RESPONSE
        assert response[2:4] == bytes([0x80, 0x00])
        assert response[4:] == b"objects"

    def test_a_null_response_is_four_octets(self):
        response = null_response(sequence=5, iin=IIN(second=IIN2Bit.FUNC_NOT_SUPPORTED))

        assert len(response) == 4
        assert response[3] == IIN2Bit.FUNC_NOT_SUPPORTED

    def test_an_unsolicited_response_says_so_in_its_function_code(self):
        response = build_response(
            control=AppControl(uns=True, con=True, sequence=1),
            iin=IIN(),
            function=FunctionCode.UNSOLICITED_RESPONSE,
        )

        assert response[1] == FunctionCode.UNSOLICITED_RESPONSE
        assert response[0] == 0xF1


class TestObjectHeaders:
    def test_a_narrow_range_uses_the_one_octet_qualifier(self):
        assert object_header(30, 1, start=0, stop=6) == bytes(
            [30, 1, QualifierCode.UINT8_START_STOP, 0, 6]
        )

    def test_a_range_past_255_uses_the_two_octet_qualifier(self):
        """The fleet map runs past 255, so this is the ordinary case."""
        header = object_header(30, 5, start=1009, stop=1015)

        assert header[2] == QualifierCode.UINT16_START_STOP
        assert struct.unpack("<HH", header[3:]) == (1009, 1015)

    def test_a_header_this_module_writes_is_one_it_can_read(self):
        request = parse_request(_request(FunctionCode.READ, object_header(30, 5, start=0, stop=6)))

        assert (request.headers[0].start, request.headers[0].stop) == (0, 6)

    def test_a_backwards_range_is_refused(self):
        with pytest.raises(ValueError, match="ends before it begins"):
            object_header(30, 1, start=9, stop=4)

    @pytest.mark.parametrize(("start", "stop"), [(0, 0x10000), (-1, 5)])
    def test_an_index_outside_the_16_bit_space_is_refused(self, start, stop):
        """A legible error is what says the device ceiling is wrong rather than
        the encoder, and the map advertisement lives at the top of the space."""
        with pytest.raises(ValueError, match="16-bit index"):
            object_header(30, 1, start=start, stop=stop)
