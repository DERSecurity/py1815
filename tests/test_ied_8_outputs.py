"""IED certification procedures, sections 8.1 to 8.4: binary and analog outputs.

Named for the sections they carry out. "Operates" is checked at the device
behind the outstation: each test looks at what reached the bound output, which
is the observation the procedure leaves to the tester.
"""

from __future__ import annotations

import pytest
from ied_harness import (
    DIRECT_OPERATE,
    DIRECT_OPERATE_NR,
    ERROR_IIN,
    FLAG_ONLINE,
    IIN2_BAD_FUNCTION,
    IIN2_OBJECT_UNKNOWN,
    IIN2_PARAMETER,
    OPERATE,
    Q_INDEX_8,
    Q_INDEX_16,
    Q_RANGE_8,
    Q_RANGE_16,
    SELECT,
    WIDE_OUTPUT,
    Dut,
    analog_output,
    analog_outputs,
    crob,
    crobs,
    header,
)

#: An index no output is installed at.
UNINSTALLED = 9

SUCCESS, TIMEOUT, NO_SELECT, NOT_SUPPORTED = 0, 1, 2, 4

LATCH_ON, LATCH_OFF, PULSE_ON, CLOSE, TRIP = 0x03, 0x04, 0x01, 0x41, 0x81


def _select_operate(dut: Dut, body: bytes) -> tuple:
    select = dut.master.request(SELECT, body)
    operate = dut.master.request(OPERATE, body)
    return select.fragment, operate.fragment


class TestBinaryOutputStatus:
    def test_8_1_2_status_is_read_with_flags_over_a_range(self):
        dut = Dut()
        fragment = dut.master.read(header(10, 0)).fragment
        objects = fragment.of(10)
        assert [o.index for o in objects] == [0, 1, 2, 3]
        assert {o.variation for o in objects} == {2}
        assert {o.qualifier for o in objects} <= {Q_RANGE_8, Q_RANGE_16}
        assert all(o.flags == FLAG_ONLINE for o in objects), "online, and nothing else"
        assert not fragment.is_error

    def test_8_1_2_a_device_with_no_binary_outputs_says_so(self):
        dut = Dut(binary_outputs=False)
        fragment = dut.master.read(header(10, 0)).fragment
        assert not fragment.body
        assert fragment.iin2 & (IIN2_OBJECT_UNKNOWN | IIN2_PARAMETER)


class TestBinaryOutputSelectBeforeOperate:
    def test_8_2_1_2_1_sixteen_bit_indexing(self):
        dut = Dut()
        body = crob(0, qualifier=Q_INDEX_16)
        select, operate = _select_operate(dut, body)
        assert select.body == body, "the select echoed exactly"
        assert operate.body == body
        assert dut.operated == [("BO", 0, True)]

    def test_8_2_1_2_2_eight_bit_indexing_to_a_different_point(self):
        dut = Dut()
        body = crob(1, qualifier=Q_INDEX_8)
        select, operate = _select_operate(dut, body)
        assert select.body == body and operate.body == body
        assert dut.operated == [("BO", 1, True)]

    def test_8_2_1_2_3_select_to_an_uninstalled_point(self):
        dut = Dut()
        fragment = dut.master.request(SELECT, crob(UNINSTALLED, qualifier=Q_INDEX_16)).fragment
        assert fragment.iin2 & IIN2_PARAMETER
        assert [o.status for o in fragment.objects] == [NOT_SUPPORTED]
        assert dut.operated == []

    def test_8_2_1_2_4_execute_after_the_select_has_timed_out(self):
        dut = Dut(select_timeout=5.0)
        body = crob(0)
        assert dut.master.request(SELECT, body).fragment.body == body
        dut.clock.advance(6.0)
        fragment = dut.master.request(OPERATE, body).fragment
        assert [o.status for o in fragment.objects] == [TIMEOUT]
        assert dut.operated == []

    @pytest.mark.parametrize(
        ("section", "operate"),
        [
            pytest.param("8.2.1.2.5", crob(1), id="8_2_1_2_5_a_different_point"),
            pytest.param("8.2.1.2.6", crob(0, on=101), id="8_2_1_2_6_a_different_on_time"),
            pytest.param("8.2.1.2.7", crob(0, off=201), id="8_2_1_2_7_a_different_off_time"),
            pytest.param("8.2.1.2.8", crob(0, LATCH_OFF), id="8_2_1_2_8_a_different_control_code"),
        ],
    )
    def test_8_2_1_2_5_to_8_an_execute_that_does_not_match_its_select(self, section, operate):
        dut = Dut()
        select = crob(0)
        assert dut.master.request(SELECT, select).fragment.body == select
        fragment = dut.master.request(OPERATE, operate).fragment
        assert [o.status for o in fragment.objects] == [NO_SELECT], section
        assert dut.operated == [], section

    def test_8_2_1_2_9_select_with_one_index_size_execute_with_the_other(self):
        dut = Dut()
        select = crob(0, qualifier=Q_INDEX_16)
        assert dut.master.request(SELECT, select).fragment.body == select
        fragment = dut.master.request(OPERATE, crob(0, qualifier=Q_INDEX_8)).fragment
        assert [o.status for o in fragment.objects] == [NO_SELECT]
        assert dut.operated == []

    def test_8_2_1_2_10_no_binary_outputs_installed(self):
        dut = Dut(binary_outputs=False)
        fragment = dut.master.request(SELECT, crob(0, qualifier=Q_INDEX_16)).fragment
        assert fragment.iin2 & (IIN2_OBJECT_UNKNOWN | IIN2_PARAMETER)
        assert dut.operated == []

    def test_8_2_1_1_a_device_with_no_outputs_at_all_answers_object_unknown(self):
        """The desired behavior for a device that supports no controls: IIN2.1, and not IIN2.2."""
        dut = Dut(binary_outputs=False, analog_outputs=False)
        fragment = dut.master.request(SELECT, crob(0, qualifier=Q_INDEX_16)).fragment
        assert fragment.iin2 & IIN2_OBJECT_UNKNOWN
        assert not fragment.iin2 & IIN2_PARAMETER

    def test_8_2_1_2_11_a_select_retried_under_the_same_sequence_number(self):
        dut = Dut()
        body = crob(0)
        first = dut.master.request(SELECT, body, sequence=3).fragment
        again = dut.master.request(SELECT, body, sequence=3).fragment
        assert first.body == body and again.body == body
        operate = dut.master.request(OPERATE, body, sequence=4).fragment
        assert operate.body == body
        assert dut.operated == [("BO", 0, True)]

    def test_8_2_1_1_a_same_sequence_select_retry_does_not_restart_the_timer(self):
        dut = Dut(select_timeout=5.0)
        body = crob(0)
        dut.master.request(SELECT, body, sequence=3)
        dut.clock.advance(4.0)
        dut.master.request(SELECT, body, sequence=3)
        dut.clock.advance(2.0)
        fragment = dut.master.request(OPERATE, body, sequence=4).fragment
        assert [o.status for o in fragment.objects] == [TIMEOUT], (
            "six seconds after the first select"
        )
        assert dut.operated == []

    def test_8_2_1_2_12_a_select_retried_under_the_next_sequence_number(self):
        dut = Dut()
        body = crob(0)
        dut.master.request(SELECT, body, sequence=3)
        again = dut.master.request(SELECT, body, sequence=4).fragment
        assert again.body == body
        operate = dut.master.request(OPERATE, body, sequence=5).fragment
        assert operate.body == body
        assert dut.operated == [("BO", 0, True)]

    def test_8_2_1_1_a_new_sequence_select_retry_restarts_the_timer(self):
        dut = Dut(select_timeout=5.0)
        body = crob(0)
        dut.master.request(SELECT, body, sequence=3)
        dut.clock.advance(4.0)
        dut.master.request(SELECT, body, sequence=4)
        dut.clock.advance(2.0)
        fragment = dut.master.request(OPERATE, body, sequence=5).fragment
        assert [o.status for o in fragment.objects] == [SUCCESS], "two seconds after the second"

    def test_8_2_1_2_13_an_operate_retried_under_the_same_sequence_number(self):
        dut = Dut()
        body = crob(0)
        dut.master.request(SELECT, body, sequence=3)
        first = dut.master.request(OPERATE, body, sequence=4).fragment
        again = dut.master.request(OPERATE, body, sequence=4).fragment
        assert first.body == body and again.body == body, "echoed both times"
        assert dut.operated == [("BO", 0, True)], "and operated once"

    def test_8_2_1_2_14_an_operate_retried_under_the_next_sequence_number(self):
        dut = Dut()
        body = crob(0)
        dut.master.request(SELECT, body, sequence=3)
        dut.master.request(OPERATE, body, sequence=4)
        again = dut.master.request(OPERATE, body, sequence=5).fragment
        assert [o.status for o in again.objects] == [NO_SELECT]
        assert dut.operated == [("BO", 0, True)]

    def test_8_2_1_2_15_an_operate_whose_sequence_number_does_not_follow_the_select(self):
        dut = Dut()
        body = crob(0)
        dut.master.request(SELECT, body, sequence=3)
        skipped = dut.master.request(OPERATE, body, sequence=6).fragment
        assert [o.status for o in skipped.objects] == [NO_SELECT]
        # The mismatched operate cleared the select, so the right one fails too.
        late = dut.master.request(OPERATE, body, sequence=4).fragment
        assert [o.status for o in late.objects] == [NO_SELECT]
        assert dut.operated == []


class TestBinaryOutputDirectOperate:
    def test_8_2_2_2_1_direct_operate(self):
        dut = Dut()
        body = crob(2)
        fragment = dut.master.request(DIRECT_OPERATE, body).fragment
        assert fragment.body == body, "echoed exactly, status zero"
        assert dut.operated == [("BO", 2, True)]

    def test_8_2_2_2_1_a_device_with_no_outputs_at_all(self):
        dut = Dut(binary_outputs=False, analog_outputs=False)
        fragment = dut.master.request(DIRECT_OPERATE, crob(0)).fragment
        assert fragment.iin2 & IIN2_OBJECT_UNKNOWN and not fragment.iin2 & IIN2_PARAMETER

    def test_8_2_2_2_2_direct_operate_to_an_uninstalled_point(self):
        dut = Dut()
        body = crob(UNINSTALLED, qualifier=Q_INDEX_16)
        fragment = dut.master.request(DIRECT_OPERATE, body).fragment
        assert fragment.iin2 & IIN2_PARAMETER
        assert [o.status for o in fragment.objects] == [NOT_SUPPORTED]
        assert dut.operated == []

    def test_8_2_2_2_3_no_binary_outputs_installed(self):
        dut = Dut(binary_outputs=False)
        fragment = dut.master.request(DIRECT_OPERATE, crob(0, qualifier=Q_INDEX_16)).fragment
        assert fragment.iin2 & (IIN2_OBJECT_UNKNOWN | IIN2_PARAMETER)
        assert dut.operated == []


class TestBinaryOutputDirectOperateNoAcknowledge:
    def test_8_2_3_2_1_operates_and_does_not_respond(self):
        dut = Dut()
        assert dut.master.request(DIRECT_OPERATE_NR, crob(1)).silent
        assert dut.operated == [("BO", 1, True)]

    def test_8_2_3_2_2_to_an_uninstalled_point(self):
        dut = Dut()
        reply = dut.master.request(DIRECT_OPERATE_NR, crob(UNINSTALLED, qualifier=Q_INDEX_16))
        assert reply.silent
        assert dut.operated == []

    @pytest.mark.parametrize("analog_outputs", [True, False])
    def test_8_2_3_2_3_no_binary_outputs_installed(self, analog_outputs):
        dut = Dut(binary_outputs=False, analog_outputs=analog_outputs)
        assert dut.master.request(DIRECT_OPERATE_NR, crob(0, qualifier=Q_INDEX_16)).silent
        assert dut.operated == []


class TestBinaryOutputMultipleObjects:
    def test_8_2_4_2_every_installed_point_in_one_request(self):
        dut = Dut()
        body = crobs([0, 1, 2, 3])
        select, operate = _select_operate(dut, body)
        for fragment in (select, operate):
            assert not fragment.iin2 & ERROR_IIN
            assert [o.status for o in fragment.objects] == [SUCCESS] * 4
        assert dut.operated == [("BO", index, True) for index in range(4)]

    def test_8_2_4_2_an_installed_point_and_an_uninstalled_one(self):
        dut = Dut()
        fragment = dut.master.request(SELECT, crobs([0, UNINSTALLED])).fragment
        assert fragment.iin2 & IIN2_PARAMETER
        assert [o.status for o in fragment.objects] == [SUCCESS, NOT_SUPPORTED]


class TestControlCodeSupport:
    @pytest.mark.parametrize(
        ("on", "off"),
        [
            pytest.param(LATCH_ON, LATCH_OFF, id="the latch pair"),
            pytest.param(CLOSE, TRIP, id="the close and trip pair"),
            pytest.param(LATCH_ON, TRIP, id="latch on then trip"),
            pytest.param(CLOSE, LATCH_OFF, id="close then latch off"),
        ],
    )
    def test_8_2_5_2_1_complementary_codes_perform_complementary_functions(self, on, off):
        dut = Dut()
        for code in (on, off):
            body = crob(0, code)
            assert dut.master.request(DIRECT_OPERATE, body).fragment.body == body
        assert dut.operated == [("BO", 0, True), ("BO", 0, False)]

    @pytest.mark.parametrize(
        ("code", "state"),
        [(PULSE_ON, True), (LATCH_ON, True), (LATCH_OFF, False), (CLOSE, True), (TRIP, False)],
    )
    def test_8_2_5_2_2_each_accepted_code_completes(self, code, state):
        dut = Dut()
        body = crob(3, code)
        select, operate = _select_operate(dut, body)
        assert select.body == body and operate.body == body
        assert dut.operated == [("BO", 3, state)]

    def test_8_2_6_2_a_control_arriving_with_a_status_already_set(self):
        dut = Dut()
        fragment = dut.master.request(SELECT, crob(0, status=126)).fragment
        (echo,) = fragment.objects
        assert echo.status != SUCCESS, "this edition passes zero with a note; the next will not"
        assert echo.raw[:-1] == crob(0)[5:-1], "otherwise an echo of what was sent"
        operate = dut.master.request(OPERATE, crob(0, status=126)).fragment
        assert operate.objects[0].status != SUCCESS
        assert dut.operated == []


class TestAnalogOutputStatus:
    def test_8_3_2_status_reads_back_the_value_written(self):
        dut = Dut()
        dut.master.request(DIRECT_OPERATE, analog_output(1, 1234, qualifier=Q_INDEX_16))
        fragment = dut.master.read(header(40, 0)).fragment
        objects = fragment.of(40)
        assert {o.variation for o in objects} == {2}, "sixteen bits, for subset levels 1 and 2"
        assert {o.qualifier for o in objects} <= {Q_RANGE_8, Q_RANGE_16}
        assert {o.index: o.value for o in objects}[1] == 1234
        assert all(o.flags == FLAG_ONLINE for o in objects)

    def test_8_3_2_a_device_with_no_analog_outputs(self):
        dut = Dut(analog_outputs=False)
        fragment = dut.master.read(header(40, 0)).fragment
        assert not fragment.body
        assert fragment.iin2 & (IIN2_OBJECT_UNKNOWN | IIN2_PARAMETER)


class TestAnalogOutputSelectBeforeOperate:
    def test_8_4_1_2_1_sixteen_bit_indexing(self):
        dut = Dut()
        body = analog_output(0, 500, qualifier=Q_INDEX_16)
        select, operate = _select_operate(dut, body)
        assert select.body == body and operate.body == body
        assert dut.operated == [("AO", 0, 500)]

    def test_8_4_1_2_2_eight_bit_indexing_to_a_different_point(self):
        dut = Dut()
        body = analog_output(1, -750)
        select, operate = _select_operate(dut, body)
        assert select.body == body and operate.body == body
        assert dut.operated == [("AO", 1, -750)]

    def test_8_4_1_2_3_select_to_an_uninstalled_point(self):
        dut = Dut()
        body = analog_output(UNINSTALLED, 1, qualifier=Q_INDEX_16)
        fragment = dut.master.request(SELECT, body).fragment
        assert fragment.iin2 & IIN2_PARAMETER
        assert [o.status for o in fragment.objects] == [NOT_SUPPORTED]
        assert dut.operated == []

    def test_8_4_1_2_4_execute_after_the_select_has_timed_out(self):
        dut = Dut(select_timeout=5.0)
        body = analog_output(0, 500)
        dut.master.request(SELECT, body)
        dut.clock.advance(6.0)
        fragment = dut.master.request(OPERATE, body).fragment
        assert [o.status for o in fragment.objects] == [TIMEOUT]
        assert dut.operated == []

    def test_8_4_1_2_5_execute_with_a_different_value(self):
        dut = Dut()
        dut.master.request(SELECT, analog_output(0, 500))
        fragment = dut.master.request(OPERATE, analog_output(0, 501)).fragment
        assert [o.status for o in fragment.objects] == [NO_SELECT]
        assert dut.operated == []

    def test_8_4_1_2_6_select_with_one_index_size_execute_with_the_other(self):
        dut = Dut()
        dut.master.request(SELECT, analog_output(0, 500, qualifier=Q_INDEX_16))
        fragment = dut.master.request(OPERATE, analog_output(0, 500, qualifier=Q_INDEX_8)).fragment
        assert [o.status for o in fragment.objects] == [NO_SELECT]
        assert dut.operated == []

    def test_8_4_1_2_7_no_analog_outputs_installed(self):
        dut = Dut(analog_outputs=False)
        body = analog_output(0, 1, qualifier=Q_INDEX_16)
        fragment = dut.master.request(SELECT, body).fragment
        assert fragment.iin2 & (IIN2_OBJECT_UNKNOWN | IIN2_PARAMETER)
        assert dut.operated == []

    def test_8_4_1_2_8_a_select_retried_under_the_same_sequence_number(self):
        dut = Dut()
        body = analog_output(0, 500)
        dut.master.request(SELECT, body, sequence=3)
        assert dut.master.request(SELECT, body, sequence=3).fragment.body == body
        assert dut.master.request(OPERATE, body, sequence=4).fragment.body == body
        assert dut.operated == [("AO", 0, 500)]

    def test_8_4_1_2_9_a_select_retried_under_the_next_sequence_number(self):
        dut = Dut()
        body = analog_output(0, 500)
        dut.master.request(SELECT, body, sequence=3)
        assert dut.master.request(SELECT, body, sequence=4).fragment.body == body
        assert dut.master.request(OPERATE, body, sequence=5).fragment.body == body
        assert dut.operated == [("AO", 0, 500)]

    def test_8_4_1_2_10_an_operate_retried_under_the_same_sequence_number(self):
        dut = Dut()
        body = analog_output(0, 500)
        dut.master.request(SELECT, body, sequence=3)
        first = dut.master.request(OPERATE, body, sequence=4).fragment
        again = dut.master.request(OPERATE, body, sequence=4).fragment
        assert first.body == body and again.body == body
        assert dut.operated == [("AO", 0, 500)]

    def test_8_4_1_2_11_an_operate_retried_under_the_next_sequence_number(self):
        dut = Dut()
        body = analog_output(0, 500)
        dut.master.request(SELECT, body, sequence=3)
        dut.master.request(OPERATE, body, sequence=4)
        again = dut.master.request(OPERATE, body, sequence=5).fragment
        assert [o.status for o in again.objects] == [NO_SELECT]
        assert dut.operated == [("AO", 0, 500)]

    def test_8_4_1_2_12_an_operate_whose_sequence_number_does_not_follow_the_select(self):
        dut = Dut()
        body = analog_output(0, 500)
        dut.master.request(SELECT, body, sequence=3)
        skipped = dut.master.request(OPERATE, body, sequence=6).fragment
        assert [o.status for o in skipped.objects] == [NO_SELECT]
        late = dut.master.request(OPERATE, body, sequence=4).fragment
        assert [o.status for o in late.objects] == [NO_SELECT]
        assert dut.operated == []

    def test_8_4_1_2_13_a_thirty_two_bit_value(self):
        dut = Dut()
        body = analog_output(WIDE_OUTPUT, 70000, variation=1, qualifier=Q_INDEX_16)
        select, operate = _select_operate(dut, body)
        assert select.body == body and operate.body == body
        assert dut.operated == [("AO", WIDE_OUTPUT, 70000)]

    def test_8_4_1_2_13_a_thirty_two_bit_value_to_a_sixteen_bit_point(self):
        dut = Dut()
        body = analog_output(0, 70000, variation=1, qualifier=Q_INDEX_16)
        fragment = dut.master.request(SELECT, body).fragment
        assert [o.status for o in fragment.objects] == [12], "out of range"
        assert dut.operated == []


class TestAnalogOutputDirectOperate:
    def test_8_4_2_2_1_direct_operate(self):
        dut = Dut()
        body = analog_output(2, 321)
        assert dut.master.request(DIRECT_OPERATE, body).fragment.body == body
        assert dut.operated == [("AO", 2, 321)]

    def test_8_4_2_2_1_a_device_with_no_outputs_at_all(self):
        dut = Dut(binary_outputs=False, analog_outputs=False)
        fragment = dut.master.request(DIRECT_OPERATE, analog_output(0, 1)).fragment
        assert fragment.iin2 & IIN2_OBJECT_UNKNOWN
        assert not fragment.iin2 & (IIN2_PARAMETER | IIN2_BAD_FUNCTION)

    def test_8_4_2_2_2_direct_operate_to_an_uninstalled_point(self):
        dut = Dut()
        body = analog_output(UNINSTALLED, 1, qualifier=Q_INDEX_16)
        fragment = dut.master.request(DIRECT_OPERATE, body).fragment
        assert fragment.iin2 & IIN2_PARAMETER
        assert [o.status for o in fragment.objects] == [NOT_SUPPORTED]
        assert dut.operated == []

    def test_8_4_2_2_3_no_analog_outputs_installed(self):
        dut = Dut(analog_outputs=False)
        body = analog_output(0, 1, qualifier=Q_INDEX_16)
        fragment = dut.master.request(DIRECT_OPERATE, body).fragment
        assert fragment.iin2 & (IIN2_OBJECT_UNKNOWN | IIN2_PARAMETER)
        assert dut.operated == []


class TestAnalogOutputDirectOperateNoAcknowledge:
    def test_8_4_3_2_1_operates_and_does_not_respond(self):
        dut = Dut()
        assert dut.master.request(DIRECT_OPERATE_NR, analog_output(1, 77)).silent
        assert dut.operated == [("AO", 1, 77)]

    def test_8_4_3_2_2_to_an_uninstalled_point(self):
        dut = Dut()
        body = analog_output(UNINSTALLED, 1, qualifier=Q_INDEX_16)
        assert dut.master.request(DIRECT_OPERATE_NR, body).silent
        assert dut.operated == []

    @pytest.mark.parametrize("binary_outputs", [True, False])
    def test_8_4_3_2_3_no_analog_outputs_installed(self, binary_outputs):
        dut = Dut(analog_outputs=False, binary_outputs=binary_outputs)
        body = analog_output(0, 1, qualifier=Q_INDEX_16)
        assert dut.master.request(DIRECT_OPERATE_NR, body).silent
        assert dut.operated == []


class TestAnalogOutputMultipleObjects:
    def test_8_4_4_2_every_installed_point_in_one_request(self):
        dut = Dut()
        body = analog_outputs([(0, 10), (1, 20), (2, 30), (3, 40)])
        select, operate = _select_operate(dut, body)
        for fragment in (select, operate):
            assert not fragment.iin2 & ERROR_IIN
            assert [o.status for o in fragment.objects] == [SUCCESS] * 4
        assert dut.operated == [("AO", 0, 10), ("AO", 1, 20), ("AO", 2, 30), ("AO", 3, 40)]

    def test_8_4_4_2_an_installed_point_and_an_uninstalled_one(self):
        dut = Dut()
        fragment = dut.master.request(SELECT, analog_outputs([(0, 10), (UNINSTALLED, 20)])).fragment
        assert fragment.iin2 & IIN2_PARAMETER
        assert [o.status for o in fragment.objects] == [SUCCESS, NOT_SUPPORTED]
