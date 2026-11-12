"""Subset Level 4 output events: groups 11, 13, 42 and 43.

An output reports an event when its value or flags change, from Level 4 up.
Every expectation is the octets of the response, written out by hand from the
object layouts of IEEE 1815-2012 Annex A and the requirements of the subset
tables (TB2016-003b, Tables 12-13, 12-17, 12-41, 12-43 and 12-49).

The device under test stamps events with 1 000 000 ms, which is the octets
``40 42 0F 00 00 00`` of a DNP3 time.
"""

from __future__ import annotations

import pytest
from ied_harness import (
    ASSIGN_CLASS,
    DIRECT_OPERATE,
    IIN1_CLASS_1,
    IIN1_CLASS_2,
    IIN1_CLASS_3,
    IIN2_OBJECT_UNKNOWN,
    IIN2_OVERFLOW,
    IIN2_PARAMETER,
    OPERATE,
    Q_COUNT_8,
    SELECT,
    Dut,
    TestMaster,
    analog_output,
    classes,
    crob,
    header,
)
from profile_fixtures import analog, document, row

from py1815.profile import load
from py1815.profile.binding import Binding, Quality, Reading
from py1815.profile.model import Composition, Kind
from py1815.profile.outstation import DerOutstation
from py1815.session import Session

LATCH_OFF = 0x04
#: The time the device under test stamps its events with, as a DNP3 time.
STAMP = "40 42 0F 00 00 00"


def _bytes(octets: str) -> bytes:
    return bytes.fromhex(octets)


def _switch(dut: Dut, index: int, on: bool = True) -> None:
    """Operate a binary output the way a master does, and ignore the response."""
    dut.master.request(DIRECT_OPERATE, crob(index, 0x03 if on else LATCH_OFF))


def _setpoint(dut: Dut, index: int, value: int) -> None:
    dut.master.request(DIRECT_OPERATE, analog_output(index, value))


def _events(dut: Dut) -> bytes:
    """The body of a read of every event class."""
    return dut.master.read(classes(1, 2, 3)).fragment.body


class TestBinaryOutputEvents:
    def test_an_operate_that_changes_an_output_raises_an_event_a_class_poll_returns(self):
        dut = Dut(level=4)
        _switch(dut, 1)
        fragment = dut.master.read(classes(3)).fragment
        # Group 11 variation 2, count 1, index 1: state on and online, then the time.
        assert fragment.body == _bytes(f"0B 02 17 01 01 81 {STAMP}")
        assert fragment.con, "events are confirmed before they leave the buffer"

    def test_the_indication_bit_is_set_as_soon_as_the_operate_is_answered(self):
        dut = Dut(level=4)
        reply = dut.master.request(DIRECT_OPERATE, crob(1))
        assert reply.fragment.iin1 & IIN1_CLASS_3

    def test_turning_an_output_off_is_an_event_too(self):
        dut = Dut(level=4)
        _switch(dut, 1)
        dut.master.poll(classes(3))
        _switch(dut, 1, on=False)
        assert _events(dut) == _bytes(f"0B 02 17 01 01 01 {STAMP}")

    def test_an_operate_that_leaves_the_output_as_it_was_raises_none(self):
        dut = Dut(level=4)
        _switch(dut, 1)
        dut.master.poll(classes(3))
        _switch(dut, 1)
        fragment = dut.master.read(classes(3)).fragment
        assert fragment.is_null
        assert not fragment.iin1 & IIN1_CLASS_3

    def test_a_select_raises_none(self):
        dut = Dut(level=4)
        dut.master.request(SELECT, crob(2))
        assert dut.master.read(classes(3)).fragment.is_null

    def test_the_operate_after_a_select_raises_one(self):
        dut = Dut(level=4)
        body = crob(2)
        dut.master.request(SELECT, body)
        dut.master.request(OPERATE, body)
        assert _events(dut) == _bytes(f"0B 02 17 01 02 81 {STAMP}")

    def test_a_refused_control_raises_none(self):
        dut = Dut(level=4)
        _setpoint(dut, 0, 31000)  # beyond the 30000 the point allows
        assert dut.master.read(classes(3)).fragment.is_null

    def test_a_confirmed_event_leaves_the_buffer(self):
        dut = Dut(level=4)
        _switch(dut, 1)
        dut.master.poll(classes(3))
        assert dut.master.read(classes(3)).fragment.is_null

    def test_events_arrive_in_the_order_they_happened_across_both_kinds(self):
        dut = Dut(level=4)
        _setpoint(dut, 2, 1234)
        _switch(dut, 0)
        assert _events(dut) == _bytes(
            f"2A 03 17 01 02 01 D2 04 00 00 {STAMP}  0B 02 17 01 00 81 {STAMP}"
        )

    def test_a_full_buffer_drops_the_oldest_and_reports_overflow(self):
        dut = Dut(level=4, capacity=3)
        for on in (True, False, True, False, True):
            _switch(dut, 1, on)
        fragment = dut.master.read(classes(3)).fragment
        # The last three of five: on, off, on.
        assert fragment.body == _bytes(f"0B 02 17 03  01 81 {STAMP}  01 01 {STAMP}  01 81 {STAMP}")
        assert fragment.iin2 & IIN2_OVERFLOW


class TestAnalogOutputEvents:
    def test_an_operate_that_changes_an_output_raises_an_event_a_class_poll_returns(self):
        dut = Dut(level=4)
        _setpoint(dut, 2, 1234)
        fragment = dut.master.read(classes(3)).fragment
        # Group 42 variation 3, count 1, index 2: online, 1234 in 32 bits, then the time.
        assert fragment.body == _bytes(f"2A 03 17 01 02 01 D2 04 00 00 {STAMP}")

    def test_every_change_of_value_is_an_event(self):
        dut = Dut(level=4)
        _setpoint(dut, 2, 1)
        _setpoint(dut, 2, 2)
        assert _events(dut) == _bytes(
            f"2A 03 17 02  02 01 01 00 00 00 {STAMP}  02 01 02 00 00 00 {STAMP}"
        )

    def test_the_same_value_again_raises_none(self):
        dut = Dut(level=4)
        _setpoint(dut, 2, 7)
        dut.master.poll(classes(3))
        _setpoint(dut, 2, 7)
        assert dut.master.read(classes(3)).fragment.is_null

    def test_a_negative_value_travels_as_a_signed_number(self):
        dut = Dut(level=4)
        _setpoint(dut, 1, -2)
        assert _events(dut) == _bytes(f"2A 03 17 01 01 01 FE FF FF FF {STAMP}")


class TestReadingOutputEventsByGroup:
    @pytest.fixture
    def dut(self) -> Dut:
        dut = Dut(level=4)
        _switch(dut, 1)
        _setpoint(dut, 2, 1234)
        return dut

    def _read(self, dut: Dut, *headers: bytes) -> bytes:
        fragment = dut.master.read(*headers).fragment
        assert not fragment.is_error
        return fragment.body

    @pytest.mark.parametrize(
        ("variation", "expected"),
        [
            (0, f"0B 02 17 01 01 81 {STAMP}"),
            (1, "0B 01 17 01 01 81"),
            (2, f"0B 02 17 01 01 81 {STAMP}"),
        ],
    )
    def test_group_11_in_each_variation_over_all_objects(self, dut, variation, expected):
        assert self._read(dut, header(11, variation)) == _bytes(expected)

    @pytest.mark.parametrize(
        ("variation", "expected"),
        [
            (0, f"2A 03 17 01 02 01 D2 04 00 00 {STAMP}"),
            (1, "2A 01 17 01 02 01 D2 04 00 00"),
            (2, "2A 02 17 01 02 01 D2 04"),
            (3, f"2A 03 17 01 02 01 D2 04 00 00 {STAMP}"),
            (4, f"2A 04 17 01 02 01 D2 04 {STAMP}"),
            # 1234.0 as a single-precision float is 0x449A4000.
            (5, "2A 05 17 01 02 01 00 40 9A 44"),
            (7, f"2A 07 17 01 02 01 00 40 9A 44 {STAMP}"),
        ],
    )
    def test_group_42_in_each_variation_over_all_objects(self, dut, variation, expected):
        assert self._read(dut, header(42, variation)) == _bytes(expected)

    def test_a_limited_quantity_returns_that_many_oldest_first(self, dut):
        _switch(dut, 0)
        assert self._read(dut, header(11, 1, Q_COUNT_8, 1)) == _bytes("0B 01 17 01 01 81")

    def test_a_group_with_no_events_is_a_null_response(self):
        dut = Dut(level=4)
        for group, variation in ((11, 0), (11, 1), (11, 2), (42, 0), (42, 5), (42, 7)):
            fragment = dut.master.read(header(group, variation)).fragment
            assert fragment.is_null, f"g{group}v{variation}"

    def test_a_variation_the_tables_do_not_ask_for_is_an_unknown_object(self, dut):
        for group, variation in ((11, 3), (42, 6), (42, 8)):
            fragment = dut.master.read(header(group, variation)).fragment
            assert fragment.iin2 & IIN2_OBJECT_UNKNOWN, f"g{group}v{variation}"

    def test_a_range_names_nothing_on_an_event_group(self, dut):
        fragment = dut.master.read(header(11, 2, 0x00, 0, 3)).fragment
        assert fragment.iin2 & IIN2_PARAMETER, "a start and stop select no events"


class TestCommandEvents:
    """Command events are not generated, so every read of them is a null response."""

    @pytest.mark.parametrize(
        ("group", "variations"), [(13, (0, 1, 2)), (43, (0, 1, 2, 3, 4, 5, 7))]
    )
    def test_each_variation_the_tables_list_is_answered_with_nothing(self, group, variations):
        dut = Dut(level=4)
        # Controls that succeed, and that fail, leave no command event.
        _switch(dut, 1)
        _setpoint(dut, 2, 5)
        _setpoint(dut, 0, 31000)
        for variation in variations:
            fragment = dut.master.read(header(group, variation)).fragment
            assert fragment.is_null, f"g{group}v{variation}"
            fragment = dut.master.read(header(group, variation, Q_COUNT_8, 2)).fragment
            assert fragment.is_null, f"g{group}v{variation} with a count"

    @pytest.mark.parametrize(("group", "variation"), [(13, 3), (43, 6), (43, 8)])
    def test_a_variation_that_is_not_offered_is_an_unknown_object(self, group, variation):
        fragment = Dut(level=4).master.read(header(group, variation)).fragment
        assert fragment.iin2 & IIN2_OBJECT_UNKNOWN

    def test_a_control_adds_nothing_to_the_class_buffers_but_its_output_event(self):
        dut = Dut(level=4)
        _switch(dut, 1)
        assert dut.outstation.events.total == 1


class TestClass0AtLevel4:
    def test_class_0_carries_the_output_status_beside_the_inputs(self):
        dut = Dut(level=4)
        fragment = dut.master.read(classes(0)).fragment
        assert fragment.body == _bytes(
            "01 02 00 00 03  01 01 01 01"  # g1v2, four binary inputs
            "0A 02 00 00 03  01 01 01 01"  # g10v2, four binary outputs, all off
            "14 01 00 00 02  01 05 00 00 00  01 05 00 00 00  01 05 00 00 00"  # g20v1, counters
            "1E 01 00 00 03  01 64 00 00 00  01 64 00 00 00  01 64 00 00 00  01 64 00 00 00"
            "28 01 00 00 03  01 00 00 00 00  01 00 00 00 00  01 00 00 00 00  01 00 00 00 00"
        )

    def test_the_output_status_in_class_0_is_what_a_later_event_changes(self):
        dut = Dut(level=4)
        _switch(dut, 1)
        body = dut.master.read(classes(0)).fragment.body
        assert _bytes("0A 02 00 00 03  01 81 01 01") in body

    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_below_level_4_class_0_carries_no_output_status(self, level):
        dut = Dut(level=level)
        fragment = dut.master.read(classes(0)).fragment
        assert {obj.group for obj in fragment.objects} == {1, 20, 30}

    def test_levels_2_and_3_answer_class_0_alike(self):
        bodies = {
            level: Dut(level=level).master.read(classes(0)).fragment.body for level in (None, 2, 3)
        }
        assert bodies[2] == bodies[3] == bodies[None]


class TestBelowLevel4:
    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_controls_raise_no_output_event(self, level):
        dut = Dut(level=level)
        _switch(dut, 1)
        _setpoint(dut, 2, 1234)
        fragment = dut.master.read(classes(1, 2, 3)).fragment
        assert fragment.is_null
        assert dut.outstation.events.total == 0

    @pytest.mark.parametrize("level", [None, 2, 3])
    @pytest.mark.parametrize("group", [11, 13, 42, 43])
    def test_the_groups_are_unknown_objects(self, level, group):
        fragment = Dut(level=level).master.read(header(group, 0)).fragment
        assert fragment.iin2 & IIN2_OBJECT_UNKNOWN


def _tables(*, binary_pair_class: int | None, analog_pair_class: int | None):
    """Two outputs, each paired with an input that reports in the given class."""
    binary_inputs = [row("Relay seen", 0, event_class=binary_pair_class, associated="BO0")]
    analog_inputs = [analog("Level seen", 0, event_class=analog_pair_class, associated="AO0")]
    return document(
        {
            "BI": binary_inputs if binary_pair_class is not None else [],
            "BO": [row("Relay", 0, associated="BI0" if binary_pair_class is not None else None)],
            "AI": analog_inputs if analog_pair_class is not None else [],
            "AO": [
                analog(
                    "Level",
                    0,
                    minimum=-100,
                    maximum=100,
                    associated="AI0" if analog_pair_class is not None else None,
                )
            ],
        }
    )


class Plant:
    """What the status readers report, for changes the device makes itself."""

    def __init__(self) -> None:
        self.relay = Reading(False)
        self.level = Reading(0.0)


def _outstation(tables, plant: Plant, *, level: int = 4) -> tuple[DerOutstation, TestMaster]:
    binding = Binding()
    binding.output(Kind.BO, 0, lambda value: None, initial=False, status=lambda: plant.relay)
    binding.output(Kind.AO, 0, lambda value: None, initial=0.0, status=lambda: plant.level)
    outstation = DerOutstation(
        load.resolve(tables, Composition()),
        binding,
        strict=False,
        clock_ms=lambda: 1_000_000,
        level=level,
    )
    session = outstation.session(need_time=False, clock=lambda: 1000.0)
    outstation.poll()
    return outstation, TestMaster(session)


class TestTheClassAnOutputReportsIn:
    def test_an_output_reports_in_the_class_of_the_input_paired_with_it(self):
        outstation, _ = _outstation(_tables(binary_pair_class=2, analog_pair_class=1), Plant())
        assert outstation.event_class(Kind.BO, 0) == 2
        assert outstation.event_class(Kind.AO, 0) == 1

    def test_the_event_is_returned_by_a_poll_of_that_class_and_no_other(self):
        plant = Plant()
        outstation, master = _outstation(_tables(binary_pair_class=2, analog_pair_class=1), plant)
        plant.relay = Reading(True)
        plant.level = Reading(5.0)
        outstation.poll()
        indications = master.read(classes(0)).fragment.iin1
        assert indications & IIN1_CLASS_2 and indications & IIN1_CLASS_1
        # The paired input reports the same change in the same class, ahead of
        # the output's own event, which is the last object of the response.
        class_2 = master.read(classes(2)).fragment
        assert class_2.body.endswith(_bytes(f"0B 02 17 01 00 81 {STAMP}"))
        class_1 = master.read(classes(1)).fragment
        assert class_1.body.endswith(_bytes(f"2A 03 17 01 00 01 05 00 00 00 {STAMP}"))
        assert master.read(classes(3)).fragment.is_null

    def test_an_output_whose_paired_input_reports_no_events_reports_none(self):
        plant = Plant()
        outstation, master = _outstation(_tables(binary_pair_class=0, analog_pair_class=0), plant)
        assert outstation.event_class(Kind.BO, 0) == 0
        plant.relay = Reading(True)
        outstation.poll()
        # The paired inputs report nothing either, and the output is left out
        # of class 0, since there is no event for it to explain.
        assert master.read(classes(1, 2, 3)).fragment.is_null
        groups = {obj.group for obj in master.read(classes(0)).fragment.objects}
        assert groups == {1, 30}

    def test_an_output_with_no_paired_input_reports_in_class_3(self):
        outstation, _ = _outstation(
            _tables(binary_pair_class=None, analog_pair_class=None), Plant()
        )
        assert outstation.event_class(Kind.BO, 0) == 3
        assert outstation.event_class(Kind.AO, 0) == 3

    def test_below_level_4_no_output_reports(self):
        outstation, _ = _outstation(
            _tables(binary_pair_class=2, analog_pair_class=1), Plant(), level=3
        )
        assert outstation.event_class(Kind.BO, 0) == 0
        assert outstation.event_class(Kind.AO, 0) == 0


def _assigned(master: TestMaster, body: str) -> None:
    """Send an ASSIGN_CLASS request written as hexadecimal octets; expect a null response."""
    fragment = master.request(ASSIGN_CLASS, _bytes(body)).fragment
    assert fragment.is_null and not fragment.iin2, f"IIN2 0x{fragment.iin2:02X}"


class TestAssigningAnOutputsClass:
    """The output's class is the one ASSIGN_CLASS uses (D110, D115, IEEE 1815-2012 Table 4-12)."""

    def test_assigning_group_10_moves_the_binary_output_events(self):
        dut = Dut(level=4)
        # Class 1 (g60v2), then g10v0 with a start-stop range of index 1.
        _assigned(dut.master, "3C 02 06  0A 00 00 01 01")
        _switch(dut, 1)
        assert dut.master.read(classes(3)).fragment.is_null
        assert dut.master.read(classes(1)).fragment.body == _bytes(f"0B 02 17 01 01 81 {STAMP}")

    def test_assigning_group_40_moves_the_analog_output_events(self):
        dut = Dut(level=4)
        # Class 2 (g60v3), then g40v0 with a start-stop range of index 2.
        _assigned(dut.master, "3C 03 06  28 00 00 02 02")
        _setpoint(dut, 2, 1234)
        assert dut.master.read(classes(3)).fragment.is_null
        assert dut.master.read(classes(2)).fragment.body == _bytes(
            f"2A 03 17 01 02 01 D2 04 00 00 {STAMP}"
        )

    @pytest.mark.parametrize("group", [0x0C, 0x29])
    def test_a_command_group_assignment_leaves_the_output_events_where_they_are(self, group):
        # Group 12 and group 41 assign the command events (groups 13 and 43),
        # which are not generated.
        dut = Dut(level=4)
        _assigned(dut.master, f"3C 02 06  {group:02X} 00 06")
        assert dut.outstation.event_class(Kind.BO, 1) == 3
        assert dut.outstation.event_class(Kind.AO, 2) == 3
        _switch(dut, 1)
        assert dut.master.read(classes(1)).fragment.is_null
        assert dut.master.read(classes(3)).fragment.body == _bytes(f"0B 02 17 01 01 81 {STAMP}")

    def test_a_command_group_naming_a_missing_output_is_a_parameter_error(self):
        dut = Dut(level=4)
        fragment = dut.master.request(ASSIGN_CLASS, _bytes("3C 02 06  0C 00 00 09 09")).fragment
        assert fragment.iin2 & IIN2_PARAMETER

    def test_an_output_assigned_to_class_0_raises_no_events_and_leaves_class_0(self):
        dut = Dut(level=4)
        # Events off (g60v1) for binary output 1 and analog output 2.
        _assigned(dut.master, "3C 01 06  0A 00 00 01 01  28 00 00 02 02")
        _switch(dut, 1)
        _setpoint(dut, 2, 1234)
        assert dut.master.read(classes(1, 2, 3)).fragment.is_null
        body = dut.master.read(classes(0)).fragment.body
        # g10v2 for outputs 0 and then 2 to 3, all off, without output 1.
        assert _bytes("0A 02 00 00 00  01  0A 02 00 02 03  01 01") in body
        # g40v1 for outputs 0 and 1, then 3, all 0, without output 2.
        assert body.endswith(
            _bytes("28 01 00 00 01  01 00 00 00 00  01 00 00 00 00  28 01 00 03 03  01 00 00 00 00")
        )

    def test_an_output_given_a_class_again_reports_only_later_changes(self):
        dut = Dut(level=4)
        _assigned(dut.master, "3C 01 06  0A 00 00 01 01  28 00 00 02 02")
        _switch(dut, 1)
        _setpoint(dut, 2, 5)
        _assigned(dut.master, "3C 04 06  0A 00 00 01 01  28 00 00 02 02")
        assert dut.master.read(classes(1, 2, 3)).fragment.is_null
        _switch(dut, 1, on=False)
        _setpoint(dut, 2, 6)
        assert _events(dut) == _bytes(
            f"0B 02 17 01 01 01 {STAMP}  2A 03 17 01 02 01 06 00 00 00 {STAMP}"
        )

    def test_assigning_the_paired_input_leaves_the_output_in_its_own_class(self):
        plant = Plant()
        outstation, master = _outstation(_tables(binary_pair_class=2, analog_pair_class=2), plant)
        # Class 1 for binary input 0 and analog input 0, the outputs' pairs.
        _assigned(master, "3C 02 06  01 00 00 00 00  1E 00 00 00 00")
        assert outstation.event_class(Kind.BI, 0) == outstation.event_class(Kind.AI, 0) == 1
        assert outstation.event_class(Kind.BO, 0) == outstation.event_class(Kind.AO, 0) == 2
        plant.relay = Reading(True)
        outstation.poll()
        assert master.read(classes(2)).fragment.body == _bytes(f"0B 02 17 01 00 81 {STAMP}")

    def test_a_restart_returns_an_output_to_its_starting_class(self):
        dut = Dut(level=4)
        _assigned(dut.master, "3C 02 06  0A 00 00 01 01")
        dut.outstation.reset_classes()
        assert dut.outstation.event_class(Kind.BO, 1) == 3


class TestChangesTheDeviceMakesItself:
    def test_a_change_the_status_reader_reports_is_an_event_at_the_next_poll(self):
        plant = Plant()
        outstation, master = _outstation(
            _tables(binary_pair_class=None, analog_pair_class=None), plant
        )
        plant.relay = Reading(True)
        assert outstation.poll() == 1
        assert master.read(classes(3)).fragment.body == _bytes(f"0B 02 17 01 00 81 {STAMP}")

    def test_a_change_of_quality_alone_is_an_event(self):
        plant = Plant()
        outstation, master = _outstation(
            _tables(binary_pair_class=None, analog_pair_class=None), plant
        )
        plant.relay = Reading(False, Quality.COMM_LOST)
        outstation.poll()
        # Comm lost is flag bit 2, and the state stays off.
        assert master.read(classes(3)).fragment.body == _bytes(f"0B 02 17 01 00 04 {STAMP}")

    def test_the_first_poll_reports_nothing(self):
        plant = Plant()
        plant.relay = Reading(True)
        outstation, master = _outstation(
            _tables(binary_pair_class=None, analog_pair_class=None), plant
        )
        assert outstation.events.total == 0
        assert master.read(classes(3)).fragment.is_null


class TestWhichGroupsAreAnswered:
    def test_an_outstation_without_analog_outputs_does_not_have_group_42(self):
        dut = Dut(level=4, analog_outputs=False)
        assert dut.master.read(header(42, 0)).fragment.iin2 & IIN2_OBJECT_UNKNOWN
        assert dut.master.read(header(43, 0)).fragment.iin2 & IIN2_OBJECT_UNKNOWN
        assert dut.master.read(header(11, 0)).fragment.is_null

    def test_a_session_refuses_a_group_that_is_not_an_output_event_group(self):
        dut = Dut(level=4)
        with pytest.raises(ValueError, match="output_events names group 2"):
            Session(dut.outstation, events=dut.outstation.events, output_events=[2])

    def test_a_session_built_without_the_option_has_none_of_the_groups(self):
        dut = Dut(level=4)
        session = Session(dut.outstation, events=dut.outstation.events)
        master = TestMaster(session)
        assert master.read(header(11, 0)).fragment.iin2 & IIN2_OBJECT_UNKNOWN
