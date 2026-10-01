"""IED certification procedures, sections 6 and 7: the data link and transport layers.

Each test is named for the section of the DNP Users Group's IED Certification
Procedure it carries out, and follows that procedure's steps against a real
session: link control octets are the ones the procedure states, and the
frames are built and parsed by the harness, not by the code under test.
"""

from __future__ import annotations

import pytest
from ied_harness import (
    CONFIRM,
    READ,
    Dut,
    classes,
    corrupt_body_crc,
    corrupt_header_crc,
    with_start,
)

#: A read of class 0, the request these procedures use throughout.
CLASS_0 = classes(0)

ACK, NOT_SUPPORTED = 0x00, 0x0F


def _reset(dut: Dut) -> None:
    assert dut.master.link(0xC0).link_controls == [ACK]


class TestResetLinkAndPassiveConfirm:
    def test_6_1_2_unconfirmed_data_needs_no_reset(self):
        dut = Dut()
        reply = dut.master.read(CLASS_0, control=0xC4)
        assert reply.fragment.of(30), "a valid response, with no link reset before it"

    @pytest.mark.parametrize("control", [0xF3, 0xD3])
    def test_6_1_2_confirmed_data_before_a_reset_is_not_answered(self, control):
        dut = Dut()
        assert dut.master.read(CLASS_0, control=control).silent

    def test_6_1_2_a_reset_is_confirmed_and_confirmed_data_then_answered(self):
        dut = Dut()
        _reset(dut)
        reply = dut.master.read(CLASS_0, control=0xF3)
        assert reply.link_controls[0] == ACK
        assert reply.fragment.of(30)

    def test_6_1_2_alternating_frame_counts_are_each_answered(self):
        dut = Dut()
        _reset(dut)
        for control in (0xF3, 0xD3, 0xF3, 0xD3, 0xF3, 0xD3):
            reply = dut.master.read(CLASS_0, control=control)
            assert reply.link_controls[0] == ACK, hex(control)
            assert reply.fragment.of(30), hex(control)

    def test_6_1_2_the_wrong_frame_count_is_confirmed_and_not_acted_on(self):
        dut = Dut()
        _reset(dut)
        # A reset expects the count bit set, so a frame with it clear is a repeat.
        wrong = dut.master.read(CLASS_0, control=0xD3)
        assert wrong.link_controls == [ACK] and not wrong.fragments
        right = dut.master.read(CLASS_0, control=0xF3)
        assert right.link_controls[0] == ACK and right.fragment.of(30)
        repeat = dut.master.read(CLASS_0, control=0xF3)
        assert repeat.link_controls == [ACK] and not repeat.fragments

    def test_6_1_2_a_second_reset_starts_the_count_again(self):
        dut = Dut()
        _reset(dut)
        dut.master.read(CLASS_0, control=0xF3)
        _reset(dut)
        assert dut.master.read(CLASS_0, control=0xF3).fragments


class TestRequestLinkStatus:
    @pytest.mark.parametrize("control", [0xC9, 0xE9])
    def test_6_3_2_link_status_is_answered_whatever_the_frame_count_bit(self, control):
        dut = Dut()
        reply = dut.master.link(control)
        assert reply.link_controls in ([0x0B], [0x1B])
        assert not reply.fragments


class TestDirAndFcvBits:
    def test_6_5_2_a_response_is_unconfirmed_user_data_from_the_outstation(self):
        dut = Dut()
        reply = dut.master.read(CLASS_0, control=0xC4)
        # 0x44: primary, unconfirmed user data, direction and frame count valid clear.
        assert reply.link_controls == [0x44]

    def test_6_5_2_every_frame_of_a_long_response_has_the_bits_clear(self):
        dut = Dut(extra_analogs=120)
        reply = dut.master.read(CLASS_0)
        assert len(reply.frames) > 1
        assert set(reply.link_controls) == {0x44}


class TestDataLinkRejectsInvalidFrames:
    """Section 6.6.2: frames a device must not answer at either layer."""

    def _frame(self, dut: Dut, control: int = 0xD3) -> bytes:
        return dut.master.frames(bytes([0xC0, READ]) + CLASS_0, control=control)

    def _ready(self) -> Dut:
        """The preamble: reset the link and see confirmed data answered."""
        dut = Dut()
        _reset(dut)
        reply = dut.master.read(CLASS_0, control=0xF3)
        assert reply.link_controls[0] == ACK and reply.fragments
        return dut

    @pytest.mark.parametrize("start", [(0x09, 0x64), (0x05, 0xFF), (0x64, 0x05), (0x00, 0x00)])
    def test_6_6_2_1_invalid_start_octets(self, start):
        dut = self._ready()
        assert dut.master.raw(with_start(self._frame(dut), *start)).silent

    @pytest.mark.parametrize("control", [0xD5, 0xD6, 0xC7, 0xCA])
    def test_6_6_2_2_invalid_primary_function_code(self, control):
        dut = self._ready()
        reply = dut.master.raw(self._frame(dut, control))
        assert reply.silent or reply.link_controls == [NOT_SUPPORTED]
        assert not reply.fragments

    @pytest.mark.parametrize("address", [1025, 7, 0])
    def test_6_6_2_3_invalid_destination_address(self, address):
        dut = self._ready()
        assert dut.master.read(CLASS_0, control=0xD3, destination=address).silent
        assert dut.master.read(CLASS_0, control=0xC4, destination=address).silent

    def test_6_6_2_4_no_gap_between_a_frame_for_another_station_and_a_request(self):
        dut = Dut()
        elsewhere = dut.master.frames(bytes([0xC0, CONFIRM]), destination=1025)
        request = dut.master.frames(bytes([0xC1, READ]) + CLASS_0)
        together = dut.master.raw(elsewhere + request)
        alone = Dut().master.raw(request)
        assert together.raw == alone.raw
        assert together.fragment.of(30)

    def test_6_6_2_5_invalid_crc_in_the_header(self):
        dut = self._ready()
        assert dut.master.raw(corrupt_header_crc(self._frame(dut))).silent

    def test_6_6_2_5_invalid_crc_in_the_data(self):
        dut = self._ready()
        assert dut.master.raw(corrupt_body_crc(self._frame(dut))).silent

    def test_6_6_2_5_other_crc_values_are_rejected_too(self):
        dut = self._ready()
        frame = self._frame(dut)
        for position in (8, 9, len(frame) - 2):
            damaged = frame[:position] + bytes([frame[position] ^ 0x5A]) + frame[position + 1 :]
            assert dut.master.raw(damaged).silent, position

    def test_6_6_2_5_a_good_frame_after_a_damaged_one_is_still_answered(self):
        """The control: the silence above is about the frame, not a stuck receiver."""
        dut = self._ready()
        dut.master.raw(corrupt_header_crc(self._frame(dut)))
        assert dut.master.read(CLASS_0, control=0xD3).fragments

    @pytest.mark.parametrize(
        "control",
        [
            pytest.param(0xC3, id="confirmed data without the count valid"),
            pytest.param(0xD4, id="unconfirmed data with the count valid"),
            pytest.param(0xC2, id="test link without the count valid"),
            pytest.param(0xD0, id="reset link with the count valid"),
            pytest.param(0xD9, id="link status request with the count valid"),
        ],
    )
    def test_6_6_2_6_invalid_fcv(self, control):
        dut = self._ready()
        reply = dut.master.raw(self._frame(dut, control))
        assert reply.silent or reply.link_controls == [NOT_SUPPORTED]
        assert not reply.fragments


class TestSelfAddress:
    def test_6_7_2_self_address_is_not_answered_when_the_feature_is_absent(self):
        """Self-address is not offered, which is the state the procedure ends in."""
        dut = Dut()
        assert dut.master.read(CLASS_0, destination=0xFFFC).silent


class TestTransportLayer:
    def test_7_2_a_short_response_is_one_segment_marked_first_and_final(self):
        dut = Dut()
        reply = dut.master.read(CLASS_0)
        ((fin, fir, _, payload),) = reply.segments
        assert fir and fin
        assert len(payload) < 249

    def test_7_2_a_long_response_is_segmented_in_order(self):
        dut = Dut(extra_analogs=200)
        reply = dut.master.read(CLASS_0)
        segments = reply.segments
        assert len(segments) > 2, "long enough to have a middle"
        assert (segments[0][1], segments[0][0]) == (True, False), "first: FIR set, FIN clear"
        for fin, fir, _, _ in segments[1:-1]:
            assert (fir, fin) == (False, False)
        assert (segments[-1][1], segments[-1][0]) == (False, True), "last: FIN set, FIR clear"
        numbers = [sequence for _, _, sequence, _ in segments]
        assert numbers == [(numbers[0] + step) % 64 for step in range(len(numbers))]
        assert all(len(payload) == 249 for _, _, _, payload in segments[:-1])
        assert reply.fragment.of(30), "and the pieces reassemble into the response"
