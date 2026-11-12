"""What Subset Level 3 reads that Level 2 does not: the time, the indications and more.

TB2016-003b Tables 12-3 to 12-53 and the IED Certification Procedure 3.1 rev 1 (8.16.2) are
the sources. Each request is sent to the device under test of the IED harness and the response
body is compared octet for octet. The device has four binary inputs, four binary outputs, four
analog inputs and outputs, and three counters that freeze, each counting 5. Its clock reads
1,000,000 ms, which is the octets 40 42 0F 00 00 00.
"""

from __future__ import annotations

import pytest
from ied_harness import (
    FREEZE,
    IIN1_CLASS_1,
    IIN2_OBJECT_UNKNOWN,
    IIN2_PARAMETER,
    WRITE,
    Dut,
    classes,
    header,
)

from py1815.profile import device_profile

ABOVE_LEVEL_2 = pytest.mark.parametrize("level", [3, 4])
BELOW_LEVEL_3 = pytest.mark.parametrize("level", [2, None], ids=["level_2", "default"])
CLOCK = "40 42 0F 00 00 00"
#: The three frozen counter events a freeze of every counter records, in variation 1.
THREE_FROZEN_EVENTS = "17 01 17 03 00 01 05 00 00 00 01 01 05 00 00 00 02 01 05 00 00 00"


def _hex(octets: bytes) -> str:
    return octets.hex(" ").upper()


def _body(dut: Dut, request: str) -> str:
    """Send a read and return its response body."""
    return _hex(dut.master.read(bytes.fromhex(request)).fragment.body)


def _refusal(dut: Dut, request: str) -> int:
    """Send a read, check that no object came back, and return the second indication octet."""
    fragment = dut.master.read(bytes.fromhex(request)).fragment
    assert not fragment.body
    return fragment.iin2


def _frozen(level: int | None) -> Dut:
    dut = Dut(level=level)
    dut.master.request(FREEZE, header(20, 0))
    return dut


class TestBinaryInputInPackedVariation:
    # Table 12-3 lists group 1 variation 1 from Level 3. Footnote a lets the answer carry
    # flags (variation 2), so a packed read is answered in variation 2 and never packed.
    @ABOVE_LEVEL_2
    @pytest.mark.parametrize(
        ("request_octets", "response"),
        [
            ("01 01 06", "01 02 00 00 03 01 01 01 01"),
            ("01 01 00 01 02", "01 02 00 01 02 01 01"),
            ("01 01 01 03 00 03 00", "01 02 00 03 03 01"),
        ],
        ids=["all", "range_8_bit", "range_16_bit"],
    )
    def test_is_answered_with_flags(self, level, request_octets, response):
        assert _body(Dut(level=level), request_octets) == response

    @ABOVE_LEVEL_2
    def test_answers_the_state_of_each_input(self, level):
        dut = Dut(level=level)
        dut.toggle(1)
        assert _body(dut, "01 01 00 00 01") == "01 02 00 00 01 01 81"

    @BELOW_LEVEL_3
    @pytest.mark.parametrize("request_octets", ["01 01 06", "01 01 00 00 01"])
    def test_is_refused_below_level_3(self, level, request_octets):
        assert _refusal(Dut(level=level), request_octets) == IIN2_OBJECT_UNKNOWN


class TestStaticReadsByVariationAndRange:
    # Tables 12-3, 12-11, 12-19, 12-21, 12-27 and 12-37: every static group is read in each
    # variation it lists and by both range qualifiers.
    @ABOVE_LEVEL_2
    @pytest.mark.parametrize(
        ("request_octets", "response"),
        [
            # Group 1 variation 0, with each range qualifier.
            ("01 00 00 00 01", "01 02 00 00 01 01 01"),
            ("01 00 01 02 00 03 00", "01 02 00 02 03 01 01"),
            # Group 10 variations 0 and 2.
            ("0A 00 00 00 01", "0A 02 00 00 01 01 01"),
            ("0A 02 01 02 00 03 00", "0A 02 00 02 03 01 01"),
            # Group 20 variations 0, 1, 2, 5 and 6. A 32-bit counter with flags answers each.
            ("14 00 00 00 01", "14 01 00 00 01 01 05 00 00 00 01 05 00 00 00"),
            ("14 01 00 02 02", "14 01 00 02 02 01 05 00 00 00"),
            ("14 02 00 00 00", "14 01 00 00 00 01 05 00 00 00"),
            ("14 05 00 01 01", "14 01 00 01 01 01 05 00 00 00"),
            ("14 06 01 00 00 00 00", "14 01 00 00 00 01 05 00 00 00"),
            # Group 30 variations 0 to 4.
            ("1E 00 00 00 00", "1E 01 00 00 00 01 64 00 00 00"),
            ("1E 01 00 01 01", "1E 01 00 01 01 01 64 00 00 00"),
            ("1E 02 00 02 03", "1E 02 00 02 03 01 64 00 01 64 00"),
            ("1E 03 00 00 00", "1E 03 00 00 00 64 00 00 00"),
            ("1E 04 01 00 00 00 00", "1E 04 00 00 00 64 00"),
            # Group 40 variations 0, 1 and 2.
            ("28 00 00 00 00", "28 01 00 00 00 01 00 00 00 00"),
            ("28 01 00 00 01", "28 01 00 00 01 01 00 00 00 00 01 00 00 00 00"),
            ("28 02 01 02 00 02 00", "28 02 00 02 02 01 00 00"),
        ],
    )
    def test_is_answered(self, level, request_octets, response):
        assert _body(Dut(level=level), request_octets) == response

    @ABOVE_LEVEL_2
    @pytest.mark.parametrize(
        ("request_octets", "response"),
        [
            ("15 01 00 02 02", "15 01 00 02 02 01 05 00 00 00"),
            ("15 02 00 00 00", "15 01 00 00 00 01 05 00 00 00"),
            ("15 09 01 01 00 01 00", "15 09 00 01 01 05 00 00 00"),
            ("15 0A 00 00 00", "15 09 00 00 00 05 00 00 00"),
        ],
    )
    def test_frozen_counters_are_answered_after_a_freeze(self, level, request_octets, response):
        assert _body(_frozen(level), request_octets) == response

    def test_level_3_reports_frozen_counters_without_time_unless_asked(self):
        # Table 12-21 lists variation 5, with time, from Level 4 on.
        by_level = {level: _body(_frozen(level), "15 00 00 00 00") for level in (2, 3, 4, None)}
        assert by_level[2] == by_level[3] == "15 01 00 00 00 01 05 00 00 00"
        assert by_level[4] == by_level[None] == f"15 05 00 00 00 01 05 00 00 00 {CLOCK}"
        assert _body(_frozen(3), "15 05 00 00 00") == f"15 05 00 00 00 01 05 00 00 00 {CLOCK}"

    @BELOW_LEVEL_3
    def test_a_range_of_variation_0_is_answered_below_level_3_as_well(self, level):
        # Not required of Level 2 and answered all along; the answer does not change.
        dut = Dut(level=level)
        assert _body(dut, "01 00 00 00 01") == "01 02 00 00 01 01 01"
        assert _body(dut, "1E 00 01 00 00 01 00") == "1E 01 00 00 01 01 64 00 00 00 01 64 00 00 00"


class TestEventReadsByVariation:
    # Tables 12-23, 12-25 and 12-31: events named by variation, with qualifiers 06, 07 and 08.
    @ABOVE_LEVEL_2
    @pytest.mark.parametrize("qualifier", ["06", "07 01", "08 01 00"])
    def test_binary_input_events(self, level, qualifier):
        dut = Dut(level=level)
        dut.toggle(0)
        assert _body(dut, f"02 01 {qualifier}") == "02 01 17 01 00 81"
        assert _body(dut, f"02 02 {qualifier}") == "02 02 17 01 00 81 4A 42 0F 00 00 00"

    @ABOVE_LEVEL_2
    @pytest.mark.parametrize("qualifier", ["06", "07 01", "08 01 00"])
    def test_analog_input_events(self, level, qualifier):
        dut = Dut(level=level)
        dut.step(0)
        assert _body(dut, f"20 01 {qualifier}") == "20 01 17 01 00 01 96 00 00 00"
        assert _body(dut, f"20 02 {qualifier}") == "20 02 17 01 00 01 96 00"

    @ABOVE_LEVEL_2
    @pytest.mark.parametrize("variation", [0, 1, 2])
    @pytest.mark.parametrize("qualifier", ["06", "07 01", "08 01 00"])
    def test_counter_change_events_are_read_and_none_are_held(self, level, variation, qualifier):
        dut = Dut(level=level)
        dut.count()
        dut.outstation.poll()
        assert dut.master.read(bytes.fromhex(f"16 {variation:02X} {qualifier}")).fragment.is_null

    @ABOVE_LEVEL_2
    @pytest.mark.parametrize(
        ("request_octets", "response"),
        [
            ("17 01 06", THREE_FROZEN_EVENTS),
            ("17 02 06", THREE_FROZEN_EVENTS),
            ("17 01 07 02", "17 01 17 02 00 01 05 00 00 00 01 01 05 00 00 00"),
            ("17 02 08 01 00", "17 01 17 01 00 01 05 00 00 00"),
        ],
    )
    def test_frozen_counter_events_are_answered_in_variation_1(
        self, level, request_octets, response
    ):
        # A 16-bit read is answered in the 32-bit variation, as a 16-bit counter read is.
        assert _body(_frozen(level), request_octets) == response

    @BELOW_LEVEL_3
    @pytest.mark.parametrize("qualifier", ["06", "07 01", "08 01 00"])
    def test_16_bit_frozen_counter_events_are_refused_below_level_3(self, level, qualifier):
        assert _refusal(_frozen(level), f"17 02 {qualifier}") == IIN2_OBJECT_UNKNOWN


class TestFrozenCounterEventsInClassPolls:
    # Table 12-49 and IED procedure 8.16.2: a Level 3 device reports frozen counter events in
    # a class poll, in variation 1 or 2. Level 2 reports none.
    def test_level_3_reports_them_in_class_3_without_time(self):
        fragment = _frozen(3).master.read(classes(3)).fragment
        assert _hex(fragment.body) == THREE_FROZEN_EVENTS
        assert fragment.con

    def test_level_4_and_the_default_report_them_with_time(self):
        for level in (4, None):
            body = _hex(_frozen(level).master.read(classes(3)).fragment.body)
            assert body == (
                f"17 05 17 03 00 01 05 00 00 00 {CLOCK} 01 01 05 00 00 00 {CLOCK}"
                f" 02 01 05 00 00 00 {CLOCK}"
            )

    def test_level_2_reports_none(self):
        assert _frozen(2).master.read(classes(3)).fragment.is_null

    def test_level_3_events_and_frozen_counters_read_together_agree(self):
        # 8.16.2.2.3 step 3: the events lead, and the frozen values follow in variation 1.
        body = _frozen(3).master.read(header(23, 0), header(21, 0)).fragment.body
        assert _hex(body) == (
            f"{THREE_FROZEN_EVENTS} 15 01 00 00 02 01 05 00 00 00 01 05 00 00 00 01 05 00 00 00"
        )

    def test_level_3_unsolicited_responses_carry_the_same_variation(self):
        dut = Dut(level=3, unsolicited=True)
        facts = dut.session.facts
        assert facts.frozen_counter_event_variation == 1
        assert Dut(level=4, unsolicited=True).session.facts.frozen_counter_event_variation == 5


class TestCurrentTimeRead:
    # Table 12-45: Level 3 reads the time with qualifier 07 and a count of 1.
    @ABOVE_LEVEL_2
    def test_answers_the_outstation_clock(self, level):
        dut = Dut(level=level)
        assert _body(dut, "32 01 07 01") == f"32 01 07 01 {CLOCK}"
        dut.clock.advance(2.0)
        assert _body(dut, "32 01 07 01") == "32 01 07 01 10 4A 0F 00 00 00"

    @ABOVE_LEVEL_2
    def test_answers_the_time_a_master_wrote(self, level):
        dut = Dut(level=level)
        # 1,700,000,000,000 ms.
        dut.master.request(WRITE, bytes.fromhex("32 01 07 01 00 68 E5 CF 8B 01"))
        assert _body(dut, "32 01 07 01") == "32 01 07 01 00 68 E5 CF 8B 01"

    @ABOVE_LEVEL_2
    def test_a_clock_past_the_48_bit_range_reads_as_the_largest_time(self, level):
        dut = Dut(level=level)
        # The largest time six octets hold, then one millisecond past it.
        dut.master.request(WRITE, bytes.fromhex("32 01 07 01 FF FF FF FF FF FF"))
        dut.clock.advance(0.001)
        assert _body(dut, "32 01 07 01") == "32 01 07 01 FF FF FF FF FF FF"

    @ABOVE_LEVEL_2
    @pytest.mark.parametrize(
        ("request_octets", "refusal"),
        [
            ("32 01 07 02", IIN2_PARAMETER),
            ("32 01 07 00", IIN2_PARAMETER),
            ("32 01 06", IIN2_OBJECT_UNKNOWN),
            ("32 01 00 00 00", IIN2_OBJECT_UNKNOWN),
            ("32 02 07 01", IIN2_OBJECT_UNKNOWN),
        ],
    )
    def test_refuses_what_is_not_one_time_object(self, level, request_octets, refusal):
        assert _refusal(Dut(level=level), request_octets) == refusal

    @BELOW_LEVEL_3
    def test_is_refused_below_level_3(self, level):
        assert _refusal(Dut(level=level), "32 01 07 01") == IIN2_OBJECT_UNKNOWN

    @ABOVE_LEVEL_2
    def test_is_answered_beside_other_objects_in_request_order(self, level):
        dut = Dut(level=level)
        body = _body(dut, "01 02 00 00 00 32 01 07 01 14 01 00 00 00")
        assert body == f"01 02 00 00 00 01 32 01 07 01 {CLOCK} 14 01 00 00 00 01 05 00 00 00"


class TestInternalIndicationsRead:
    # Table 12-52: Level 3 reads group 80 variation 1 with qualifier 00 or 01. Index n is
    # internal indication bit n, IIN1.0 first (A.28.1), and the first index is bit 0 of the
    # first octet.
    @ABOVE_LEVEL_2
    def test_reports_the_restart_bit_until_a_master_clears_it(self, level):
        dut = Dut(level=level)
        assert _body(dut, "50 01 00 00 0F") == "50 01 00 00 0F 80 00"
        assert _body(dut, "50 01 00 07 07") == "50 01 00 07 07 01"
        dut.clear_restart()
        assert _body(dut, "50 01 00 00 0F") == "50 01 00 00 0F 00 00"
        assert _body(dut, "50 01 00 07 07") == "50 01 00 07 07 00"

    @ABOVE_LEVEL_2
    def test_answers_a_16_bit_range_with_an_8_bit_one(self, level):
        # Indexes 4 to 8, so the restart bit (index 7) is the fourth of five.
        assert _body(Dut(level=level), "50 01 01 04 00 08 00") == "50 01 00 04 08 08"

    @ABOVE_LEVEL_2
    def test_packs_the_first_index_into_bit_0(self, level):
        # Indexes 6 to 8 are IIN1.6, IIN1.7 and IIN2.0: the restart bit is the middle one.
        assert _body(Dut(level=level), "50 01 00 06 08") == "50 01 00 06 08 02"

    @ABOVE_LEVEL_2
    def test_reports_the_classes_that_hold_events(self, level):
        dut = Dut(level=level)
        dut.clear_restart()
        dut.master.empty_events()
        dut.toggle(0)
        fragment = dut.master.read(bytes.fromhex("50 01 00 00 0F")).fragment
        assert _hex(fragment.body) == "50 01 00 00 0F 02 00"
        assert fragment.iin1 & IIN1_CLASS_1

    @ABOVE_LEVEL_2
    def test_reports_the_need_for_time(self, level):
        dut = Dut(level=level, need_time=True)
        dut.clear_restart()
        assert _body(dut, "50 01 00 04 04") == "50 01 00 04 04 01"

    @ABOVE_LEVEL_2
    @pytest.mark.parametrize("request_octets", ["50 01 00 00 10", "50 01 00 10 10"])
    def test_refuses_an_index_beyond_the_sixteen_standard_ones(self, level, request_octets):
        assert _refusal(Dut(level=level), request_octets) == IIN2_PARAMETER

    @ABOVE_LEVEL_2
    @pytest.mark.parametrize("request_octets", ["50 01 06", "50 01 07 01"])
    def test_refuses_a_qualifier_that_names_no_index(self, level, request_octets):
        assert _refusal(Dut(level=level), request_octets) == IIN2_OBJECT_UNKNOWN

    @BELOW_LEVEL_3
    @pytest.mark.parametrize("request_octets", ["50 01 00 00 0F", "50 01 00 07 07"])
    def test_is_refused_below_level_3(self, level, request_octets):
        assert _refusal(Dut(level=level), request_octets) == IIN2_OBJECT_UNKNOWN


class TestTheDeviceProfileListsWhatLevel3Reads:
    @staticmethod
    def _reads(level, group, variation):
        dut = Dut(level=level)
        rows = device_profile.implementation(dut.outstation, dut.session.facts).rows
        return [
            row
            for row in rows
            if (row.group, row.variation) == (group, variation)
            and row.request
            and row.request[0] == device_profile.READ
        ]

    @pytest.mark.parametrize(("group", "variation"), [(1, 1), (23, 2), (50, 1), (80, 1)])
    def test_level_3_and_4_list_each_read_and_level_2_does_not(self, group, variation):
        assert self._reads(3, group, variation)
        assert self._reads(4, group, variation)
        assert not self._reads(2, group, variation)
        assert not self._reads(None, group, variation)

    def test_the_time_and_indications_rows_name_the_qualifiers_the_session_answers(self):
        (time,) = self._reads(3, 50, 1)
        (indications,) = self._reads(3, 80, 1)
        assert time.request[1] == (0x07,) and time.response == (device_profile.RESPONSE, (0x07,))
        assert indications.request[1] == (0x00, 0x01)
        assert indications.response == (device_profile.RESPONSE, (0x00,))

    @pytest.mark.parametrize(("group", "variation"), [(1, 1), (23, 2), (50, 1), (80, 1)])
    def test_every_qualifier_a_row_lists_is_answered_without_an_error(self, group, variation):
        (row,) = self._reads(3, group, variation)
        for qualifier in row.request[1]:
            tail = {
                0x00: "00 00",
                0x01: "00 00 00 00",
                0x06: "",
                0x07: "01",
                0x08: "01 00",
                0x17: "01 00",
                0x28: "01 00 00 00",
            }[qualifier]
            request = f"{group:02X} {variation:02X} {qualifier:02X} {tail}"
            fragment = Dut(level=3).master.read(bytes.fromhex(request)).fragment
            assert not fragment.is_error, request
