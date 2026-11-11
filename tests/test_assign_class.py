"""ASSIGN_CLASS (function code 22), required from Subset Level 3.

IEEE 1815-2012 4.4.14 defines the request, and TB2016-003b Table 12-49 and the
group tables say which levels take it. The IED Certification Procedure 3.1
rev 1, section 8.26.2, carries it out; ``test_8_26_2_procedure_as_written``
follows its steps in order. Requests are written as literal octets. Each class
header is group 60 with qualifier 0x06, and variation 1 to 4 means class 0 to 3
(``3C 01 06`` turns events off, ``3C 02 06`` is class 1). The headers after it
name the points, as a read does.

The device has binary inputs 0 and 1 in class 1, 2 in class 2 and 3 in class 3;
analog inputs 0 to 3 in classes 1, 2, 3 and 2; and counters whose freezes report
in class 3.
"""

from __future__ import annotations

import pytest
from ied_harness import (
    ASSIGN_CLASS,
    DEADBAND,
    FREEZE,
    IIN1_CLASS_1,
    IIN1_CLASS_2,
    IIN1_CLASS_3,
    IIN2_BAD_FUNCTION,
    IIN2_OBJECT_UNKNOWN,
    IIN2_PARAMETER,
    RESPONSE,
    Dut,
    classes,
)

from py1815.profile import device_profile
from py1815.profile.model import Kind

CLASS_BITS = IIN1_CLASS_1 | IIN1_CLASS_2 | IIN1_CLASS_3


def assign(dut: Dut, body: str):
    """Send an ASSIGN_CLASS request written as hexadecimal octets, and return the response."""
    return dut.master.request(ASSIGN_CLASS, bytes.fromhex(body)).fragment


def assigned(dut: Dut, body: str) -> None:
    """Send an ASSIGN_CLASS request that must be answered with a null response."""
    fragment = assign(dut, body)
    assert fragment.function == RESPONSE
    assert not fragment.body
    assert not fragment.iin2, f"IIN2 0x{fragment.iin2:02X}"


def waiting(fragment) -> int:
    """The class bits of a response's IIN1."""
    return fragment.iin1 & CLASS_BITS


def indices(fragment, group: int) -> list[int]:
    return [obj.index for obj in fragment.of(group)]


class TestRefusedBelowLevel3:
    @pytest.mark.parametrize("level", [2, None])
    def test_level_2_and_default_refuse_function_code_22(self, level):
        dut = Dut(level=level)
        # Class 1 (3C 02 06), then g1v0 with qualifier 0x06.
        fragment = assign(dut, "3C 02 06 01 00 06")
        assert not fragment.body
        assert fragment.iin2 == IIN2_BAD_FUNCTION

    @pytest.mark.parametrize("level", [2, None])
    def test_a_refused_request_leaves_the_classes_as_built(self, level):
        dut = Dut(level=level)
        assign(dut, "3C 03 06 01 00 06")
        dut.master.empty_events()
        dut.toggle(0)
        assert indices(dut.master.read(classes(1)).fragment, 2) == [0]


class TestLevel3:
    def test_8_26_2_procedure_as_written(self):
        """IED Certification Procedure 3.1 rev 1, 8.26.2, steps 1 to 58."""
        dut = Dut(level=3)
        # Steps 1 to 5: a poll of every class.
        dut.master.empty_events()
        # Steps 6 to 17: one event in class 1 and one in class 2.
        dut.toggle(0)
        dut.toggle(2)
        three = dut.master.read(classes(3)).fragment
        assert not three.body
        assert waiting(three) == IIN1_CLASS_1 | IIN1_CLASS_2
        one = dut.master.read(classes(1)).fragment
        assert indices(one, 2) == [0] and one.con
        assert waiting(one) == IIN1_CLASS_2
        dut.master.confirm(one)
        two = dut.master.read(classes(2)).fragment
        assert indices(two, 2) == [2] and two.con
        assert waiting(two) == 0
        dut.master.confirm(two)
        # Step 18: the class 2 point (binary input 2) to class 3, the class 1
        # points (binary inputs 0 and 1) to class 2.
        assigned(dut, "3C 04 06 01 00 00 02 02  3C 03 06 01 00 00 00 01")
        # Steps 20 and 21.
        everything = dut.master.read(classes(1, 2, 3)).fragment
        assert not everything.body and waiting(everything) == 0
        # Steps 22 to 25: an event for a point now in class 2.
        dut.toggle(0)
        one = dut.master.read(classes(1)).fragment
        assert not one.body
        assert waiting(one) == IIN1_CLASS_2
        # Steps 26 to 30: an event for a point now in class 3.
        dut.toggle(2)
        two = dut.master.read(classes(2)).fragment
        assert indices(two, 2) == [0] and two.con
        assert waiting(two) == IIN1_CLASS_3
        dut.master.confirm(two)
        # Steps 31 to 34: the class 2 points to class 0.
        assigned(dut, "3C 01 06 01 00 00 00 01")
        one = dut.master.read(classes(1)).fragment
        assert not one.body
        assert waiting(one) == IIN1_CLASS_3
        # Steps 35 to 39: another class 3 point, and a change to a point in class 0.
        dut.toggle(3)
        dut.toggle(0)
        one = dut.master.read(classes(1)).fragment
        assert not one.body
        assert waiting(one) == IIN1_CLASS_3
        # Steps 40 to 43: the two class 3 events and nothing else.
        three = dut.master.read(classes(1, 2, 3)).fragment
        assert indices(three, 2) == [2, 3] and three.con
        assert waiting(three) == 0
        dut.master.confirm(three)
        # Steps 44 and 45.
        again = dut.master.read(classes(1, 2, 3)).fragment
        assert not again.body and waiting(again) == 0
        # Steps 46 to 48: back to the startup assignment. The change made
        # while binary input 0 was in class 0 is not reported now.
        assigned(
            dut,
            "3C 02 06 01 00 00 00 01  3C 03 06 01 00 00 02 02  3C 04 06 01 00 00 03 03",
        )
        again = dut.master.read(classes(1, 2, 3)).fragment
        assert not again.body and waiting(again) == 0
        # Steps 49 to 52.
        dut.toggle(0)
        dut.toggle(2)
        three = dut.master.read(classes(3)).fragment
        assert not three.body
        assert waiting(three) == IIN1_CLASS_1 | IIN1_CLASS_2
        # Steps 53 to 58.
        both = dut.master.read(classes(1, 2, 3)).fragment
        assert indices(both, 2) == [0, 2] and both.con
        assert waiting(both) == 0
        dut.master.confirm(both)
        last = dut.master.read(classes(1, 2, 3)).fragment
        assert not last.body and waiting(last) == 0

    def test_a_point_assigned_to_class_0_raises_no_events(self):
        dut = Dut(level=3)
        dut.master.empty_events()
        assigned(dut, "3C 01 06 01 00 00 00 00")
        assert dut.outstation.event_class(Kind.BI, 0) == 0
        dut.toggle(0)
        dut.toggle(0)
        fragment = dut.master.read(classes(1, 2, 3)).fragment
        assert not fragment.body
        assert waiting(fragment) == 0

    def test_a_point_assigned_to_class_0_is_still_in_a_class_0_read(self):
        dut = Dut(level=3)
        assigned(dut, "3C 01 06 01 00 00 00 00")
        fragment = dut.master.read(classes(0)).fragment
        assert 0 in indices(fragment, 1)

    def test_the_response_is_a_null_response(self):
        dut = Dut(level=3)
        fragment = assign(dut, "3C 03 06 01 00 06")
        assert fragment.octets[1] == RESPONSE
        assert fragment.body == b""
        assert fragment.iin2 == 0

    def test_events_already_buffered_stay_in_the_class_they_were_recorded_in(self):
        dut = Dut(level=3)
        dut.master.empty_events()
        dut.toggle(0)  # a class 1 event
        assigned(dut, "3C 03 06 01 00 00 00 01")
        one = dut.master.read(classes(1)).fragment
        assert indices(one, 2) == [0]
        assert waiting(one) == 0

    def test_a_change_not_yet_scanned_is_recorded_under_the_old_class(self):
        dut = Dut(level=3)
        dut.master.empty_events()
        dut.binary[0] = True  # changed, and the outstation has not looked yet
        assigned(dut, "3C 03 06 01 00 00 00 01")
        assert indices(dut.master.read(classes(1)).fragment, 2) == [0]
        assert not dut.master.read(classes(2)).fragment.body

    def test_a_point_assigned_to_class_0_keeps_its_buffered_events(self):
        dut = Dut(level=3)
        dut.master.empty_events()
        dut.toggle(0)
        assigned(dut, "3C 01 06 01 00 00 00 01")
        assert indices(dut.master.read(classes(1)).fragment, 2) == [0]

    def test_a_later_set_in_one_request_wins(self):
        dut = Dut(level=3)
        assigned(dut, "3C 03 06 01 00 06  3C 04 06 01 00 00 01 01")
        assert dut.outstation.event_class(Kind.BI, 0) == 2
        assert dut.outstation.event_class(Kind.BI, 1) == 3

    def test_a_request_that_fails_changes_nothing(self):
        dut = Dut(level=3)
        # The first set is fine; the second names binary input 9.
        fragment = assign(dut, "3C 04 06 01 00 00 00 00  3C 03 06 01 00 00 09 09")
        assert fragment.iin2 == IIN2_PARAMETER
        assert dut.outstation.event_class(Kind.BI, 0) == 1

    def test_a_restart_returns_every_point_to_its_startup_class(self):
        dut = Dut(level=3)
        assigned(dut, "3C 04 06 01 00 06  3C 01 06 1E 00 06")
        assert dut.outstation.event_class(Kind.BI, 0) == 3
        assert dut.outstation.event_class(Kind.AI, 0) == 0
        dut.restart()
        assert dut.outstation.event_class(Kind.BI, 0) == 1
        assert dut.outstation.event_class(Kind.AI, 0) == 1

    def test_a_point_that_resumes_reporting_uses_its_deadband(self):
        dut = Dut(level=3)
        dut.master.empty_events()
        assigned(dut, "3C 01 06 1E 00 00 00 00")
        dut.step(0, 3 * DEADBAND)  # not reported while in class 0
        assigned(dut, "3C 03 06 1E 00 00 00 00")
        assert not dut.master.read(classes(2)).fragment.of(32)
        dut.step(0, 1)  # inside the deadband
        assert not dut.master.read(classes(2)).fragment.of(32)
        dut.step(0, 3 * DEADBAND)
        assert indices(dut.master.read(classes(2)).fragment, 32) == [0]

    @pytest.mark.parametrize(
        "points",
        [
            "01 00 00 00 00",  # g1v0, 8-bit range 0 to 0
            "01 00 01 00 00 00 00",  # g1v0, 16-bit range 0 to 0
            "01 00 17 01 00",  # g1v0, index list holding 0 (8-bit)
            "01 00 28 01 00 00 00",  # g1v0, index list holding 0 (16-bit)
        ],
    )
    def test_binary_inputs_are_named_by_range_or_index_list(self, points):
        dut = Dut(level=3)
        dut.master.empty_events()
        assigned(dut, "3C 04 06 " + points)
        dut.toggle(0)
        assert not dut.master.read(classes(1)).fragment.body
        assert indices(dut.master.read(classes(3)).fragment, 2) == [0]

    def test_analog_inputs_are_assigned_by_g30(self):
        dut = Dut(level=3)
        dut.master.empty_events()
        assigned(dut, "3C 04 06 1E 00 01 00 00 00 00")
        dut.step(0)
        assert not dut.master.read(classes(1)).fragment.body
        assert indices(dut.master.read(classes(3)).fragment, 32) == [0]

    def test_an_all_objects_header_moves_every_analog_input(self):
        dut = Dut(level=3)
        assigned(dut, "3C 04 06 1E 00 06")
        assert [dut.outstation.event_class(Kind.AI, i) for i in range(4)] == [3, 3, 3, 3]

    def test_frozen_counter_events_are_assigned_by_g20_and_g21(self):
        dut = Dut(level=3)
        dut.master.empty_events()
        assigned(dut, "3C 03 06 14 00 06")
        dut.master.request(FREEZE, bytes.fromhex("14 00 06"))
        assert not dut.master.read(classes(3)).fragment.body
        fragment = dut.master.read(classes(2)).fragment
        assert indices(fragment, 23) == [0, 1, 2]
        dut.master.confirm(fragment)
        assigned(dut, "3C 02 06 15 00 00 01 01")
        dut.master.request(FREEZE, bytes.fromhex("14 00 06"))
        one = dut.master.read(classes(1)).fragment
        assert indices(one, 23) == [1]

    @pytest.mark.parametrize("group", [0x0A, 0x0C, 0x28, 0x29])
    def test_output_groups_are_not_assignable_at_level_3(self, group):
        dut = Dut(level=3)
        fragment = assign(dut, f"3C 03 06 {group:02X} 00 06")
        assert fragment.iin2 == IIN2_OBJECT_UNKNOWN

    @pytest.mark.parametrize("group", [0x32, 0x50])
    def test_other_groups_are_refused_as_unknown_objects(self, group):
        dut = Dut(level=3)
        fragment = assign(dut, f"3C 03 06 {group:02X} 01 06")
        assert fragment.iin2 == IIN2_OBJECT_UNKNOWN

    @pytest.mark.parametrize("points", ["01 00 00 09 09", "01 00 17 01 09", "1E 00 00 00 20"])
    def test_a_point_that_is_not_there_is_a_parameter_error(self, points):
        dut = Dut(level=3)
        assert assign(dut, "3C 03 06 " + points).iin2 == IIN2_PARAMETER

    @pytest.mark.parametrize(
        "body",
        [
            "01 00 06",  # a point header before any class header would mean no class
            "3C 03 00 00 00",  # a class header whose qualifier is not 0x06
            "3C 05 06 01 00 06",  # group 60 variation 5 names no class
        ],
    )
    def test_a_malformed_assignment_is_a_parameter_error(self, body):
        dut = Dut(level=3)
        assert assign(dut, body).iin2 == IIN2_PARAMETER

    def test_a_request_naming_nothing_is_a_parameter_error(self):
        dut = Dut(level=3)
        assert assign(dut, "").iin2 == IIN2_PARAMETER

    def test_a_class_header_with_no_points_assigns_nothing(self):
        dut = Dut(level=3)
        assigned(dut, "3C 03 06")
        assert dut.outstation.event_class(Kind.BI, 0) == 1


class TestLevel4:
    @pytest.mark.parametrize("group", [0x01, 0x14, 0x15, 0x1E, 0x0A, 0x0C, 0x28, 0x29])
    def test_each_required_group_is_accepted(self, group):
        dut = Dut(level=4)
        assigned(dut, f"3C 03 06 {group:02X} 00 06")

    def test_output_groups_name_outputs_by_range(self):
        dut = Dut(level=4)
        assigned(dut, "3C 02 06 0A 00 00 00 03  3C 03 06 28 00 01 00 00 03 00")
        assert dut.outstation.event_class(Kind.BO, 3) == 1
        assert dut.outstation.event_class(Kind.AO, 3) == 2

    def test_an_output_that_is_not_there_is_a_parameter_error(self):
        dut = Dut(level=4)
        assert assign(dut, "3C 03 06 0A 00 00 09 09").iin2 == IIN2_PARAMETER

    def test_input_groups_still_move_events(self):
        dut = Dut(level=4)
        dut.master.empty_events()
        assigned(dut, "3C 04 06 01 00 00 00 00")
        dut.toggle(0)
        assert indices(dut.master.read(classes(3)).fragment, 2) == [0]


class TestDeviceProfile:
    @staticmethod
    def assignable(level) -> set[tuple[int, int]]:
        dut = Dut(level=level)
        table = device_profile.implementation(dut.outstation, dut.session.facts)
        return {
            (row.group, row.variation)
            for row in table.rows
            if row.request is not None and row.request[0] == ASSIGN_CLASS
        }

    @pytest.mark.parametrize("level", [2, None])
    def test_below_level_3_no_row_lists_function_code_22(self, level):
        assert not self.assignable(level)

    def test_level_3_lists_the_class_headers_and_the_input_groups(self):
        assert self.assignable(3) == {(60, 1), (60, 2), (60, 3), (60, 4)} | {
            (group, 0) for group in (1, 20, 21, 30)
        }

    def test_level_4_adds_the_output_groups(self):
        assert self.assignable(4) == self.assignable(3) | {(group, 0) for group in (10, 12, 40, 41)}
