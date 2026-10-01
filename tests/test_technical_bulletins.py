"""What the DNP Users Group's technical bulletins and application notes ask of an outstation.

The base standard has been corrected and clarified since it was published, in
technical bulletins (TB) and application notes (AN). Each test here checks one
thing one of those documents asks for, and is named for the document:
``test_tb2013_003_...`` is from TB2013-003. ``test_bulletin_coverage.py``
lists every document and says which were acted on and which do not apply.

The documents are the Users Group's and are not reproduced; what each asks
for is described here in our own words.
"""

from __future__ import annotations

import struct

import pytest
from ied_harness import (
    CONFIRM,
    DELAY_MEASURE,
    DIRECT_OPERATE,
    DIRECT_OPERATE_NR,
    FREEZE,
    FREEZE_NR,
    IIN1_BROADCAST,
    IIN2_BAD_FUNCTION,
    IIN2_OBJECT_UNKNOWN,
    IIN2_PARAMETER,
    MASTER,
    OPERATE,
    OUTSTATION,
    Q_ALL,
    Q_COUNT_8,
    Q_INDEX_8,
    Q_RANGE_8,
    READ,
    RECORD_CURRENT_TIME,
    SELECT,
    WRITE,
    Dut,
    classes,
    crob,
    header,
)

from py1815 import crc
from py1815.control import CommandStatus
from py1815.objects import encode_time
from py1815.profile import device_profile
from py1815.session import Session
from py1815.transport import Reassembler, TransportError

FIR, FIN = 0x40, 0x80


def _segment(*, first: bool, final: bool, sequence: int, data: bytes = b"") -> bytes:
    return bytes([(FIR if first else 0) | (FIN if final else 0) | sequence]) + data


def _raw_frame(control: int, destination: int, source: int, payload: bytes = b"") -> bytes:
    """A link frame built by hand, so that its fields can contradict each other."""
    head = bytes([0x05, 0x64, 5 + len(payload), control]) + struct.pack("<HH", destination, source)
    out = crc.encode(head)
    for start in range(0, len(payload), 16):
        out += crc.encode(payload[start : start + 16])
    return out


class Provider:
    def read(self, headers):
        return b""


# ------------------------------------------------------------- TB2013-002


class TestSpecialUseAddresses:
    @pytest.mark.parametrize(
        "address", [0xFFF0, 0xFFFB, 0xFFFC, 0xFFFD, 0xFFFE, 0xFFFF, 0x10000, -1]
    )
    def test_tb2013_002_a_device_is_not_given_a_reserved_address(self, address):
        with pytest.raises(ValueError):
            Session(Provider(), outstation_address=address)
        with pytest.raises(ValueError):
            Session(Provider(), master_address=address)

    def test_tb2013_002_the_highest_ordinary_address_is_accepted(self):
        Session(Provider(), outstation_address=0xFFEF, master_address=0)

    def test_tb2013_002_the_two_ends_have_different_addresses(self):
        with pytest.raises(ValueError):
            Session(Provider(), outstation_address=7, master_address=7)

    @pytest.mark.parametrize("source", [0xFFF0, 0xFFFC, 0xFFFD, 0xFFFF])
    def test_tb2013_002_a_frame_from_a_special_address_is_ignored(self, source):
        dut = Dut()
        assert dut.master.raw(_raw_frame(0xC9, OUTSTATION, source)).silent

    @pytest.mark.parametrize("destination", [0xFFF0, 0xFFFB])
    def test_tb2013_002_a_frame_to_a_reserved_address_is_ignored(self, destination):
        dut = Dut()
        assert dut.master.raw(_raw_frame(0xC9, destination, MASTER)).silent

    def test_tb2013_002_the_self_address_is_off(self):
        """Support for it is optional, and where supported it is disabled by default."""
        dut = Dut()
        assert dut.master.raw(_raw_frame(0xC9, 0xFFFC, MASTER)).silent
        assert dut.master.read(classes(0), destination=0xFFFC).silent

    @pytest.mark.parametrize("control", [0xC0, 0xC9, 0xF2, 0xF3])
    def test_tb2013_002_a_broadcast_is_unconfirmed_user_data_and_nothing_else(self, control):
        """Reset, link status, test and confirmed data sent to everyone are not acted on."""
        dut = Dut()
        dut.master.link(0xC0)
        freeze = bytes([0xC0, 0xC0, FREEZE]) + header(20, 0)
        payload = freeze if control == 0xF3 else b""
        assert dut.master.raw(_raw_frame(control, 0xFFFF, MASTER, payload)).silent
        after = dut.master.read(classes(0)).fragment
        assert not after.iin1 & IIN1_BROADCAST
        assert not after.of(21), "the freeze sent as confirmed data was not carried out"

    def test_tb2013_002_a_confirmation_sent_to_everyone_confirms_nothing(self):
        dut = Dut()
        dut.toggle(0)
        fragment = dut.master.read(classes(1, 2, 3)).fragment
        assert fragment.con and fragment.of(2)
        confirm = bytes([0xC0 | fragment.sequence, CONFIRM])
        assert dut.master.raw(dut.master.frames(confirm, destination=0xFFFF)).silent
        assert dut.master.read(classes(1, 2, 3)).fragment.of(2), "the event is still held"


# ------------------------------------------------------------- TB2013-003


class TestTransportReception:
    """The reception state table, row by row. The fragment buffer holds eight octets."""

    def _idle(self) -> Reassembler:
        return Reassembler(max_fragment=8)

    def _assembling(self) -> Reassembler:
        reassembler = self._idle()
        assert reassembler.add(_segment(first=True, final=False, sequence=5, data=b"ab")) is None
        assert reassembler.in_progress
        return reassembler

    def test_tb2013_003_row_1_idle_and_not_a_first_segment(self):
        reassembler = self._idle()
        with pytest.raises(TransportError):
            reassembler.add(_segment(first=False, final=True, sequence=3, data=b"zz"))
        assert not reassembler.in_progress

    @pytest.mark.parametrize("state", ["_idle", "_assembling"])
    def test_tb2013_003_rows_2_and_21_a_whole_fragment_with_nothing_in_it(self, state):
        reassembler = getattr(self, state)()
        assert reassembler.add(_segment(first=True, final=True, sequence=0)) is None
        assert not reassembler.in_progress

    @pytest.mark.parametrize("state", ["_idle", "_assembling"])
    def test_tb2013_003_rows_3_and_22_a_whole_fragment_that_fits(self, state):
        reassembler = getattr(self, state)()
        assert reassembler.add(_segment(first=True, final=True, sequence=0, data=b"12345678")) == (
            b"12345678"
        )
        assert not reassembler.in_progress

    @pytest.mark.parametrize("state", ["_idle", "_assembling"])
    def test_tb2013_003_rows_4_and_23_a_whole_fragment_too_large(self, state):
        reassembler = getattr(self, state)()
        with pytest.raises(TransportError):
            reassembler.add(_segment(first=True, final=True, sequence=0, data=b"123456789"))
        assert not reassembler.in_progress

    @pytest.mark.parametrize("state", ["_idle", "_assembling"])
    def test_tb2013_003_rows_5_6_18_19_a_first_segment_starts_a_series(self, state):
        for data in (b"", b"xy"):
            reassembler = getattr(self, state)()
            assert reassembler.add(_segment(first=True, final=False, sequence=9, data=data)) is None
            assert reassembler.in_progress
            assert reassembler.add(_segment(first=False, final=True, sequence=10, data=b"!")) == (
                data + b"!"
            ), "nothing of an earlier series is left in front of it"

    @pytest.mark.parametrize("state", ["_idle", "_assembling"])
    def test_tb2013_003_rows_7_and_20_a_first_segment_too_large(self, state):
        reassembler = getattr(self, state)()
        with pytest.raises(TransportError):
            reassembler.add(_segment(first=True, final=False, sequence=0, data=b"123456789"))
        assert not reassembler.in_progress

    def test_tb2013_003_row_8_a_segment_repeated_octet_for_octet(self):
        """A link-layer repeat of a continuing segment is dropped and the series goes on."""
        reassembler = self._assembling()
        middle = _segment(first=False, final=False, sequence=6, data=b"cd")
        assert reassembler.add(middle) is None
        assert reassembler.add(middle) is None
        assert reassembler.in_progress
        assert reassembler.add(_segment(first=False, final=True, sequence=7, data=b"ef")) == (
            b"abcdef"
        )

    def test_tb2013_003_row_9_the_same_sequence_with_different_contents(self):
        reassembler = self._assembling()
        reassembler.add(_segment(first=False, final=False, sequence=6, data=b"cd"))
        with pytest.raises(TransportError):
            reassembler.add(_segment(first=False, final=False, sequence=6, data=b"XX"))
        assert not reassembler.in_progress

    def test_tb2013_003_rows_10_and_11_the_expected_segment_with_more_to_come(self):
        reassembler = self._assembling()
        assert reassembler.add(_segment(first=False, final=False, sequence=6)) is None
        assert reassembler.add(_segment(first=False, final=False, sequence=7, data=b"cd")) is None
        assert reassembler.add(_segment(first=False, final=True, sequence=8, data=b"e")) == b"abcde"

    def test_tb2013_003_row_12_a_series_that_outgrows_the_buffer(self):
        reassembler = self._assembling()
        with pytest.raises(TransportError):
            reassembler.add(_segment(first=False, final=False, sequence=6, data=b"1234567"))
        assert not reassembler.in_progress

    def test_tb2013_003_row_13_a_series_that_ends_with_nothing_in_it(self):
        reassembler = self._idle()
        reassembler.add(_segment(first=True, final=False, sequence=0))
        assert reassembler.add(_segment(first=False, final=True, sequence=1)) is None
        assert not reassembler.in_progress

    def test_tb2013_003_rows_14_and_15_the_final_segment(self):
        reassembler = self._assembling()
        assert reassembler.add(_segment(first=False, final=True, sequence=6)) == b"ab"
        reassembler = self._assembling()
        assert reassembler.add(_segment(first=False, final=True, sequence=6, data=b"cdefgh")) == (
            b"abcdefgh"
        )

    def test_tb2013_003_row_16_a_final_segment_that_outgrows_the_buffer(self):
        reassembler = self._assembling()
        with pytest.raises(TransportError):
            reassembler.add(_segment(first=False, final=True, sequence=6, data=b"1234567"))
        assert not reassembler.in_progress

    @pytest.mark.parametrize("sequence", [7, 4, 20])
    def test_tb2013_003_row_17_a_segment_out_of_order(self, sequence):
        reassembler = self._assembling()
        with pytest.raises(TransportError):
            reassembler.add(_segment(first=False, final=True, sequence=sequence, data=b"cd"))
        assert not reassembler.in_progress

    def test_tb2013_003_the_sequence_wraps_at_sixty_four(self):
        reassembler = self._idle()
        reassembler.add(_segment(first=True, final=False, sequence=63, data=b"a"))
        assert reassembler.add(_segment(first=False, final=True, sequence=0, data=b"b")) == b"ab"

    def test_tb2013_003_a_repeat_is_only_of_the_segment_just_before(self):
        """After a series ends, its last segment arriving again starts nothing."""
        reassembler = self._assembling()
        last = _segment(first=False, final=True, sequence=6, data=b"cd")
        assert reassembler.add(last) == b"abcd"
        with pytest.raises(TransportError):
            reassembler.add(last)

    def test_tb2013_003_an_empty_request_fragment_reaches_nothing(self):
        """Through the session: a fragment of no octets is not answered."""
        dut = Dut()
        assert dut.master.raw(dut.master.frame(0xC4, bytes([0xC0]))).silent


# ------------------------------------------------------------- TB2014-002


class TestControlStatusCodes:
    def test_tb2014_002_the_table_of_codes(self):
        assert [int(status) for status in CommandStatus if int(status) <= 18] == list(range(19))
        assert CommandStatus.UNDEFINED == 127
        assert CommandStatus.DOWNSTREAM_LOCAL == 13
        assert CommandStatus.DOWNSTREAM_FAIL == 18

    @pytest.mark.parametrize("status", [1, 4, 126, 127])
    def test_tb2014_002_a_request_carrying_a_status_is_not_operated(self, status):
        dut = Dut()
        fragment = dut.master.request(DIRECT_OPERATE, crob(0, status=status)).fragment
        (echo,) = fragment.objects
        assert echo.status != CommandStatus.SUCCESS
        assert dut.operated == []

    def test_tb2014_002_the_reserved_bit_of_the_status_octet(self):
        """It is always zero. A request with it set is not a request to act on."""
        dut = Dut()
        fragment = dut.master.request(DIRECT_OPERATE, crob(0, status=0x80)).fragment
        (echo,) = fragment.objects
        assert echo.status != CommandStatus.SUCCESS
        assert dut.operated == []

    def test_tb2014_002_the_withdrawn_code_is_never_answered(self):
        """Code 126 was removed. Nothing here produces it, and the profile does not list it."""
        dut = Dut()
        for body in (crob(0), crob(9), crob(0, status=126)):
            for function in (SELECT, OPERATE, DIRECT_OPERATE):
                for echo in dut.master.request(function, body).fragment.objects:
                    assert echo.status != 126
        root = device_profile.build(dut.outstation, dut.session)
        assert not list(root.iter(f"{{{device_profile.NAMESPACE}}}code126"))

    def test_tb2014_002_the_device_profile_lists_the_codes_it_answers_with(self):
        dut = Dut()
        root = device_profile.build(dut.outstation, dut.session)
        (supported,) = root.iter(f"{{{device_profile.NAMESPACE}}}controlStatusCodesSupported")
        listed = {child.tag.rsplit("}", 1)[1] for group in supported for child in group}
        assert {"code1", "code2", "code3", "code4"} <= listed


# ------------------------------------------------------------- TB2016-001


class TestErrorIndications:
    def test_tb2016_001_a_function_not_supported_is_a_null_response_with_iin2_0(self):
        dut = Dut()
        fragment = dut.master.request(0x1F).fragment
        assert fragment.iin2 & IIN2_BAD_FUNCTION and not fragment.body

    def test_tb2016_001_an_object_not_supported_for_the_function_is_iin2_1(self):
        dut = Dut()
        assert dut.master.read(header(110, 1)).fragment.iin2 & IIN2_OBJECT_UNKNOWN
        assert dut.master.request(WRITE, header(30, 1)).fragment.iin2 & IIN2_OBJECT_UNKNOWN

    def test_tb2016_001_a_supported_object_with_no_points_is_iin2_1_or_iin2_2(self):
        dut = Dut(counters=False)
        fragment = dut.master.read(header(20, 0)).fragment
        assert fragment.iin2 & (IIN2_OBJECT_UNKNOWN | IIN2_PARAMETER) and not fragment.body

    @pytest.mark.parametrize("qualifier", [0x02, 0x09, 0x0A, 0x0B, 0x5B])
    def test_tb2016_001_a_qualifier_not_supported_is_iin2_2(self, qualifier):
        dut = Dut()
        fragment = dut.master.read(bytes([30, 0, qualifier, 0, 0, 0, 0, 0, 0, 0, 0])).fragment
        assert fragment.iin2 & IIN2_PARAMETER and not fragment.body

    def test_tb2016_001_an_index_not_installed_is_iin2_2(self):
        dut = Dut()
        assert dut.master.read(header(30, 0, Q_RANGE_8, 2, 9)).fragment.iin2 & IIN2_PARAMETER
        fragment = dut.master.request(DIRECT_OPERATE, crob(9)).fragment
        assert fragment.iin2 & IIN2_PARAMETER

    def test_tb2016_001_no_error_response_to_a_function_that_takes_none(self):
        dut = Dut()
        assert dut.master.request(DIRECT_OPERATE_NR, header(110, 1)).silent
        assert dut.master.request(DIRECT_OPERATE_NR, crob(9)).silent

    def test_tb2016_001_no_error_response_to_a_broadcast(self):
        dut = Dut()
        assert dut.master.request(0x1F, destination=0xFFFF).silent
        assert dut.master.read(header(110, 1), destination=0xFFFF).silent


# ------------------------------------------------- TB2018-001 and TB2018-003


class TestTime:
    def test_tb2018_001_an_outstation_that_asks_for_the_time_can_take_it(self):
        with pytest.raises(ValueError):
            Session(Provider(), need_time=True)
        dut = Dut(need_time=True)
        assert not dut.master.request(DELAY_MEASURE).fragment.is_error
        moment = header(50, 1, Q_COUNT_8, 1) + (1_800_000_000_000).to_bytes(6, "little")
        assert not dut.master.request(WRITE, moment).fragment.is_error

    def test_tb2018_001_an_outstation_with_no_clock_to_set(self):
        """It never asks, and says the time objects are unknown to it."""
        session = Session(Provider())
        assert session.need_time is False
        dut = Dut()
        dut.session = None  # the harness's own session is not the one under test
        master = type(dut.master)(session)
        written = master.request(
            WRITE, header(50, 1, Q_COUNT_8, 1) + (1_800_000_000_000).to_bytes(6, "little")
        ).fragment
        assert written.iin2 & IIN2_OBJECT_UNKNOWN
        assert master.request(RECORD_CURRENT_TIME).fragment.iin2 & IIN2_BAD_FUNCTION

    def test_tb2018_001_events_are_sent_in_the_order_seen_not_the_order_stamped(self):
        """A clock set backwards between two events does not reorder them."""
        dut = Dut(need_time=True)
        dut.master.empty_events()
        late = header(50, 1, Q_COUNT_8, 1) + (1_800_000_000_000).to_bytes(6, "little")
        early = header(50, 1, Q_COUNT_8, 1) + (1_700_000_000_000).to_bytes(6, "little")
        dut.master.request(WRITE, late)
        dut.toggle(0)
        dut.master.request(WRITE, early)
        dut.toggle(1)
        events = dut.master.read(header(2, 2)).fragment.of(2)
        assert [event.index for event in events] == [0, 1]
        assert events[0].time > events[1].time

    def test_tb2018_003_the_time_of_the_standards_own_example(self):
        """Midnight at the start of 2008, UTC, with no leap seconds counted."""
        assert encode_time(1_199_145_600_000) == bytes([0x00, 0xC4, 0xA5, 0x32, 0x17, 0x01])
        assert 1_199_145_600_000 - 883_612_800_000 == 315_532_800_000


# ------------------------------------------------------------- TB2018-004


class TestAnalogInputRules:
    def test_tb2018_004_rule_6_what_class_0_reports_a_read_of_its_group_reports(self):
        dut = Dut()
        poll = {o.index for o in dut.master.read(classes(0)).fragment.of(30)}
        named = {o.index for o in dut.master.read(header(30, 0)).fragment.of(30)}
        assert poll and poll == named

    def test_tb2018_004_rule_7_what_a_class_poll_reports_a_read_of_its_group_reports(self):
        dut = Dut()
        dut.master.empty_events()
        dut.step(1)
        by_class = dut.master.read(classes(1, 2, 3)).fragment.of(32)
        by_group = dut.master.read(header(32, 0)).fragment.of(32)
        assert [o.index for o in by_class] == [o.index for o in by_group] == [1]

    @pytest.mark.parametrize("group", [31, 33])
    def test_tb2018_004_rule_10_frozen_analogs_read_as_any_object_with_none(self, group):
        """There are none, and the answer is the one given for any object that is not there."""
        dut = Dut()
        frozen = dut.master.read(header(group, 0)).fragment
        other = dut.master.read(header(110, 0)).fragment
        assert (frozen.iin2, frozen.body) == (other.iin2, other.body)
        assert frozen.iin2 & IIN2_OBJECT_UNKNOWN

    def test_tb2018_004_rule_12_a_point_that_reports_events_reads_as_static_data(self):
        dut = Dut()
        dut.master.empty_events()
        dut.step(2)
        (event,) = dut.master.read(header(32, 0)).fragment.of(32)
        (static,) = dut.master.read(header(30, 0, Q_RANGE_8, event.index, event.index)).fragment.of(
            30
        )
        assert static.value == event.value


# ------------------------------------------------------------ AN2013-004b


class TestValidationOfIncomingData:
    @pytest.mark.parametrize("control", [0xC0, 0xC9, 0xF2])
    def test_an2013_004b_a_link_function_with_data_behind_it(self, control):
        """Only user data has a payload; a reset or status request that has one is discarded."""
        dut = Dut()
        dut.master.link(0xC0)
        assert dut.master.raw(_raw_frame(control, OUTSTATION, MASTER, b"\x00\x00")).silent
        assert not dut.master.link(0xC9).silent, "and the link still answers a proper one"

    @pytest.mark.parametrize("control", [0xC4, 0xF3])
    def test_an2013_004b_user_data_with_no_data(self, control):
        dut = Dut()
        dut.master.link(0xC0)
        assert dut.master.raw(_raw_frame(control, OUTSTATION, MASTER)).silent

    def test_an2013_004b_a_fragment_shorter_than_its_header_is_discarded(self):
        dut = Dut()
        assert dut.master.raw(dut.master.frames(bytes([0xC0]))).silent

    @pytest.mark.parametrize("control", [0x40, 0x80, 0x00], ids=["no FIR", "no FIN", "neither"])
    def test_an2013_004b_a_request_is_one_whole_fragment(self, control):
        dut = Dut()
        assert dut.master.raw(dut.master.frames(bytes([control | 1, READ]) + classes(0))).silent
        assert not dut.master.read(classes(0)).fragment.is_error

    def test_an2013_004b_the_unsolicited_bit_on_a_request(self):
        dut = Dut()
        assert dut.master.raw(dut.master.frames(bytes([0xD0, READ]) + classes(0))).silent

    def test_an2013_004b_a_malformed_fragment_still_ends_a_select(self):
        dut = Dut()
        assert dut.master.request(SELECT, crob(0)).fragment.objects[0].status == 0
        dut.master.raw(dut.master.frames(bytes([0x41, READ]) + classes(0)))
        (echo,) = dut.master.request(OPERATE, crob(0)).fragment.objects
        assert echo.status == CommandStatus.NO_SELECT
        assert dut.operated == []

    @pytest.mark.parametrize("function", [READ, WRITE, SELECT, OPERATE, DIRECT_OPERATE, FREEZE])
    def test_an2013_004b_a_function_that_needs_objects_and_has_none(self, function):
        dut = Dut()
        fragment = dut.master.request(function).fragment
        assert fragment.iin2 & IIN2_PARAMETER and not fragment.body

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param(bytes([30, 0]), id="header cut short"),
            pytest.param(bytes([30, 0, Q_RANGE_8, 1]), id="range cut short"),
            pytest.param(header(30, 0, Q_RANGE_8, 3, 1), id="range ends before it begins"),
            pytest.param(classes(0) + bytes([30]), id="a second header cut short"),
        ],
    )
    def test_an2013_004b_a_request_that_cannot_be_parsed_is_iin2_2(self, body):
        dut = Dut()
        fragment = dut.master.read(body).fragment
        assert fragment.iin2 & IIN2_PARAMETER and not fragment.body

    def test_an2013_004b_a_control_cut_short_operates_nothing(self):
        dut = Dut()
        whole = crob(0, qualifier=Q_INDEX_8)
        fragment = dut.master.request(DIRECT_OPERATE, whole[:-3]).fragment
        assert fragment.is_error
        assert dut.operated == []

    def test_an2013_004b_a_count_larger_than_the_data_behind_it(self):
        dut = Dut()
        body = bytes([12, 1, Q_INDEX_8, 200]) + crob(0)[4:]
        fragment = dut.master.request(DIRECT_OPERATE, body).fragment
        assert fragment.is_error
        assert dut.operated == []

    def test_an2013_004b_nothing_is_answered_to_a_malformed_request_that_takes_no_response(self):
        dut = Dut()
        assert dut.master.request(DIRECT_OPERATE_NR, bytes([12, 1])).silent
        assert dut.master.read(bytes([30, 0]), destination=0xFFFF).silent


# ------------------------------------------------------------- AN2014-001


class TestDisablingFunctionCodes:
    def test_an2014_001_a_disabled_function_is_refused_as_one_never_implemented(self):
        dut = Dut(disabled_functions=[DIRECT_OPERATE, DELAY_MEASURE])
        operate = dut.master.request(DIRECT_OPERATE, crob(0)).fragment
        assert operate.iin2 & IIN2_BAD_FUNCTION and not operate.body
        assert dut.operated == []
        assert dut.master.request(DELAY_MEASURE).fragment.iin2 & IIN2_BAD_FUNCTION

    def test_an2014_001_the_functions_left_on_still_work(self):
        dut = Dut(disabled_functions=[DIRECT_OPERATE])
        assert dut.master.request(SELECT, crob(0)).fragment.objects[0].status == 0
        assert dut.master.request(OPERATE, crob(0)).fragment.objects[0].status == 0
        assert len(dut.operated) == 1

    @pytest.mark.parametrize("function", [DIRECT_OPERATE_NR, FREEZE_NR])
    def test_an2014_001_a_disabled_function_that_takes_no_response_draws_none(self, function):
        dut = Dut(disabled_functions=[function])
        body = crob(0) if function == DIRECT_OPERATE_NR else header(20, 0)
        assert dut.master.request(function, body).silent
        assert dut.operated == []
        assert not dut.master.read(classes(0)).fragment.of(21), "nothing was frozen"

    def test_an2014_001_a_disabled_function_sent_to_everyone(self):
        """Not acted on, not answered, and the broadcast is still reported."""
        dut = Dut(disabled_functions=[FREEZE])
        assert dut.master.request(FREEZE, header(20, 0), destination=0xFFFD).silent
        after = dut.master.read(classes(0)).fragment
        assert after.iin1 & IIN1_BROADCAST
        assert not after.of(21)

    def test_an2014_001_disabling_the_time_write(self):
        """For an outstation whose clock is set some other way."""
        dut = Dut(disabled_functions=[RECORD_CURRENT_TIME, DELAY_MEASURE])
        assert dut.master.request(RECORD_CURRENT_TIME).fragment.iin2 & IIN2_BAD_FUNCTION
        assert dut.master.request(DELAY_MEASURE).fragment.iin2 & IIN2_BAD_FUNCTION

    def test_an2014_001_confirm_cannot_be_disabled(self):
        with pytest.raises(ValueError):
            Session(Provider(), disabled_functions=[CONFIRM])

    def test_an2014_001_the_device_profile_leaves_out_what_is_disabled(self):
        dut = Dut(disabled_functions=[DIRECT_OPERATE, DIRECT_OPERATE_NR, RECORD_CURRENT_TIME])
        table = device_profile.implementation(dut.outstation, dut.session.facts)
        functions = {row.request[0] for row in table.rows if row.request}
        assert not functions & {DIRECT_OPERATE, DIRECT_OPERATE_NR}
        assert {SELECT, OPERATE, READ} <= functions
        assert RECORD_CURRENT_TIME not in table.function_codes
        assert DELAY_MEASURE in table.function_codes

    def test_an2014_001_nothing_is_disabled_unless_asked(self):
        dut = Dut()
        assert dut.session.facts.disabled_functions == frozenset()


# ------------------------------------------------------------- AN2015-001


class TestRecommendedDefaults:
    def test_an2015_001_fragment_sizes(self):
        facts = Session(Provider()).facts
        assert facts.max_response == 2048
        assert facts.max_request >= 249

    def test_an2015_001_a_direct_operate_sent_to_everyone_is_off_by_default(self):
        dut = Dut()
        assert dut.session.facts.broadcast_controls is False
        dut.master.request(DIRECT_OPERATE, crob(0), destination=0xFFFF)
        assert dut.operated == []

    def test_an2015_001_the_restart_indication_can_be_cleared_by_broadcast(self):
        dut = Dut()
        dut.restart()
        clear = header(80, 1, Q_RANGE_8, 7, 7) + b"\x00"
        assert dut.master.request(WRITE, clear, destination=0xFFFD).silent
        assert not dut.master.read(classes(0)).fragment.iin1 & 0x80

    def test_an2015_001_the_time_is_asked_for_from_startup_by_a_device_with_a_clock(self):
        dut = Dut(need_time=True)
        assert dut.master.read(classes(0)).fragment.iin1 & 0x10

    def test_an2015_001_event_data_asks_for_confirmation_and_static_data_does_not(self):
        dut = Dut()
        dut.toggle(0)
        assert dut.master.read(classes(1, 2, 3)).fragment.con
        assert not dut.master.read(classes(0)).fragment.con

    def test_an2015_001_a_read_naming_every_object_is_answered(self):
        dut = Dut()
        assert dut.master.read(header(1, 0, Q_ALL)).fragment.of(1)
