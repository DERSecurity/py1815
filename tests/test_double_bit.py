"""Double-bit binary inputs, groups 3 and 4, served at Subset Level 4.

Every expectation is a response body written out as octets from the object
layouts of IEEE 1815-2012, Annex A.4 and A.5, and from the Subset Level 4
tables of TB2016-003b (Tables 12-7 to 12-10). The state of a double-bit point
is 0 INTERMEDIATE, 1 DETERMINED_OFF, 2 DETERMINED_ON or 3 INDETERMINATE
(Table 11-14). With flags it travels in bits 6 and 7 of the flag octet; packed
it takes two bits, the first point in bits 0 and 1 of the first octet.
"""

from __future__ import annotations

import datetime
import pathlib
from typing import Any
from xml.etree import ElementTree

import pytest
from ied_harness import (
    IIN1_CLASS_1,
    IIN1_CLASS_2,
    IIN2_OBJECT_UNKNOWN,
    IIN2_PARAMETER,
    Q_COUNT_8,
    Q_INDEX_8,
    Q_RANGE_8,
    Clock,
    TestMaster,
    classes,
    header,
)
from profile_fixtures import document, row
from test_profile_device_profile_view import column, table

from py1815.decode import PointType
from py1815.master.profile import read_device_profile
from py1815.profile import device_profile, device_profile_view, load
from py1815.profile.binding import Binding, Quality, Reading
from py1815.profile.device_profile import NAMESPACE
from py1815.profile.model import Composition, Kind
from py1815.profile.outstation import DerOutstation

NS = {"d": NAMESPACE}

#: The event class of each double-bit point of the device. Point 4 has none,
#: which leaves it out of the event buffers and in class 0.
CLASSES = {0: 1, 1: 1, 2: 2, 3: 3, 4: 0, 5: 1}


class Device:
    """A Level 4 outstation with one binary input and six double-bit inputs."""

    def __init__(self, *, level: int | None = 4, need_time: bool = False) -> None:
        self.clock = Clock()
        self.states: dict[int, Any] = dict.fromkeys(CLASSES, 0)
        self.quality: dict[int, Quality] = {}
        binding = Binding()
        binding.read(Kind.BI, 0, lambda: False)
        for index in CLASSES:
            binding.read(Kind.DBI, index, self._reader(index))
        tables = document(
            {
                "BI": [row("Alarm", 0, event_class=1)],
                "DBI": [row(f"Valve {i}", i, event_class=cls) for i, cls in CLASSES.items()],
            }
        )
        self.outstation = DerOutstation(
            load.resolve(tables, Composition()),
            binding,
            strict=False,
            clock_ms=self.clock.ms,
            level=level,
        )
        self.session = self.outstation.session(need_time=need_time, clock=self.clock)
        self.master = TestMaster(self.session)
        self.outstation.poll()

    def _reader(self, index: int) -> Any:
        return lambda: Reading(self.states[index], self.quality.get(index, Quality.GOOD))

    def move(self, index: int, state: Any, quality: Quality | None = None) -> None:
        """Change one point one second after the last change and let the outstation notice."""
        self.clock.advance(1.0)
        self.states[index] = state
        if quality is not None:
            self.quality[index] = quality
        self.outstation.poll()

    def body(self, *headers: bytes) -> bytes:
        """The body of the one fragment a read is answered with."""
        return self.master.read(*headers).fragment.body

    def set_states(self, *states: int) -> None:
        for index, state in enumerate(states):
            self.states[index] = state


def _hex(octets: str) -> bytes:
    return bytes.fromhex(octets)


class TestStaticWithFlags:
    def test_g3v2_carries_each_state_in_bits_6_and_7_beside_the_online_flag(self):
        device = Device()
        device.set_states(0, 1, 2, 3, 2, 1)
        # Flag octet 0x01 is ONLINE. State 0 adds 0x00, 1 adds 0x40, 2 adds 0x80, 3 adds 0xC0.
        assert device.body(header(3, 2, Q_RANGE_8, 0, 5)) == _hex(
            "03 02 00 00 05  01 41 81 C1 81 41"
        )

    def test_variation_zero_is_answered_with_flags(self):
        device = Device()
        device.set_states(0, 1, 2, 3, 2, 1)
        assert device.body(header(3, 0)) == _hex("03 02 00 00 05  01 41 81 C1 81 41")

    def test_a_range_names_the_points_it_covers(self):
        device = Device()
        device.set_states(0, 1, 2, 3, 2, 1)
        assert device.body(header(3, 2, Q_RANGE_8, 2, 3)) == _hex("03 02 00 02 03  81 C1")

    def test_a_read_by_index_is_answered_by_index(self):
        device = Device()
        device.set_states(0, 1, 2, 3, 3, 1)
        request = _hex("03 02 17 02 01 04")
        # Count 2, then index 1 with state 1 and index 4 with state 3.
        assert device.body(request) == _hex("03 02 17 02  01 41  04 C1")

    def test_a_range_past_the_last_point_is_a_parameter_error(self):
        fragment = Device().master.read(header(3, 2, Q_RANGE_8, 0, 9)).fragment
        assert not fragment.body and fragment.iin2 & IIN2_PARAMETER


class TestStaticPacked:
    def test_g3v1_packs_two_bits_a_point_with_the_first_in_the_low_bits(self):
        device = Device()
        device.set_states(0, 1, 2, 3, 0, 0)
        # Points 0 to 3 are 00, 01, 10, 11 from bit 0 up: 0b11_10_01_00.
        assert device.body(header(3, 1, Q_RANGE_8, 0, 3)) == _hex("03 01 00 00 03  E4")

    def test_a_run_longer_than_four_points_takes_a_second_octet_padded_with_zeros(self):
        device = Device()
        device.set_states(3, 2, 1, 0, 2, 3)
        # 3, 2, 1, 0 is 0b00_01_10_11 = 0x1B. Then 2 and 3, and two unused pairs: 0b00_00_11_10.
        assert device.body(header(3, 1, Q_RANGE_8, 0, 5)) == _hex("03 01 00 00 05  1B 0E")

    def test_the_first_point_of_a_range_is_aligned_on_bit_0_whatever_its_index(self):
        device = Device()
        device.set_states(0, 0, 1, 2, 3, 0)
        # Points 2, 3 and 4 are 01, 10 and 11: 0b00_11_10_01.
        assert device.body(header(3, 1, Q_RANGE_8, 2, 4)) == _hex("03 01 00 02 04  39")

    def test_a_point_in_an_exception_condition_is_reported_with_flags_in_the_run(self):
        device = Device()
        device.set_states(1, 2, 2, 2, 3, 0)
        device.quality[2] = Quality.COMM_LOST
        # Points 0 and 1 are 01 and 10 (0x09). Point 2 is COMM_LOST (0x04) with state 2 (0x80).
        # Points 3 to 5 are 10, 11, 00 (0x0E).
        assert device.body(header(3, 1, Q_RANGE_8, 0, 5)) == _hex(
            "03 01 00 00 01  09  03 02 00 02 02  84  03 01 00 03 05  0E"
        )

    @pytest.mark.parametrize(
        "quality, flags",
        [
            (Quality.COMM_LOST, "04"),
            (Quality.NEVER_READ, "02"),
            (Quality.OFFLINE, "00"),
        ],
    )
    def test_every_quality_other_than_good_leaves_the_packed_variation(self, quality, flags):
        device = Device()
        device.set_states(2, 0, 0, 0, 0, 0)
        device.quality[0] = quality
        # State 2 adds 0x80 to the flag octet.
        expected = f"03 02 00 00 00  {int(flags, 16) | 0x80:02X}"
        assert device.body(header(3, 1, Q_RANGE_8, 0, 0)) == _hex(expected)

    def test_the_packed_variation_has_no_form_with_an_index(self):
        fragment = Device().master.read(_hex("03 01 17 01 02")).fragment
        assert not fragment.body and fragment.iin2 & IIN2_OBJECT_UNKNOWN


class TestStatesAndQualityFromTheBinding:
    @pytest.mark.parametrize("value", [-1, 4, 1.5, True, float("nan")])
    def test_a_value_that_is_not_a_state_is_indeterminate_and_not_reachable(self, value):
        device = Device()
        device.states[0] = value
        # State 3 adds 0xC0 to the COMM_LOST flag 0x04.
        assert device.body(header(3, 2, Q_RANGE_8, 0, 0)) == _hex("03 02 00 00 00  C4")

    def test_a_state_given_as_a_whole_float_is_taken(self):
        device = Device()
        device.states[0] = 2.0
        assert device.body(header(3, 2, Q_RANGE_8, 0, 0)) == _hex("03 02 00 00 00  81")


class TestClassZero:
    def test_class_0_carries_double_bit_inputs_after_the_binary_inputs(self):
        device = Device()
        device.set_states(0, 1, 2, 3, 2, 1)
        assert device.body(classes(0)) == _hex(
            "01 02 00 00 00  01  03 02 00 00 05  01 41 81 C1 81 41"
        )

    def test_an_integrity_poll_with_every_class_carries_them_too(self):
        device = Device()
        device.set_states(0, 1, 2, 3, 2, 1)
        body = device.body(classes(1, 2, 3, 0))
        assert body.endswith(_hex("03 02 00 00 05  01 41 81 C1 81 41"))


class TestEventsWithAbsoluteTime:
    def test_a_change_of_state_is_a_g4v2_event_in_its_class(self):
        device = Device()
        device.move(0, 2)
        # Index 0 is class 1. Time 1001000 ms is 28 46 0F 00 00 00.
        assert device.body(classes(1)) == _hex("04 02 17 01  00  81  28 46 0F 00 00 00")

    def test_each_of_the_four_states_is_reported_as_it_is_reached(self):
        device = Device()
        device.move(0, 1)
        device.move(0, 2)
        device.move(0, 3)
        device.move(0, 0)
        assert device.body(classes(1)) == _hex(
            "04 02 17 04"
            "  00 41 28 46 0F 00 00 00"
            "  00 81 10 4A 0F 00 00 00"
            "  00 C1 F8 4D 0F 00 00 00"
            "  00 01 E0 51 0F 00 00 00"
        )

    def test_a_change_of_quality_alone_is_an_event(self):
        device = Device()
        device.move(1, 0, Quality.COMM_LOST)
        # State 0 and COMM_LOST (0x04) without ONLINE.
        assert device.body(classes(1)) == _hex("04 02 17 01  01  04  28 46 0F 00 00 00")

    def test_a_reading_that_has_not_changed_is_not_an_event(self):
        device = Device()
        device.outstation.poll()
        device.clock.advance(1.0)
        device.outstation.poll()
        assert device.master.read(classes(1, 2, 3)).fragment.is_null

    def test_each_event_waits_in_the_class_its_point_reports_in(self):
        device = Device()
        device.move(0, 2)
        device.move(2, 3)
        first = device.master.read(classes(1)).fragment
        second = device.master.read(classes(2)).fragment
        assert first.body == _hex("04 02 17 01  00  81  28 46 0F 00 00 00")
        assert second.body == _hex("04 02 17 01  02  C1  10 4A 0F 00 00 00")
        # The class 1 event is in the response, so only class 2 still has something waiting.
        assert first.iin1 & IIN1_CLASS_2 and not first.iin1 & IIN1_CLASS_1

    def test_a_point_with_no_event_class_reports_no_event(self):
        device = Device()
        device.move(4, 3)
        assert device.master.read(classes(1, 2, 3)).fragment.is_null

    def test_a_confirmed_event_is_not_sent_again(self):
        device = Device()
        device.move(0, 2)
        fragment = device.master.read(classes(1)).fragment
        assert fragment.con
        device.master.confirm(fragment)
        assert device.master.read(classes(1)).fragment.is_null

    def test_a_limited_quantity_stops_at_the_count(self):
        device = Device()
        device.move(0, 1)
        device.move(0, 2)
        assert device.body(header(4, 0, Q_COUNT_8, 1)) == _hex(
            "04 02 17 01  00  41  28 46 0F 00 00 00"
        )


class TestNamedVariations:
    def _moved(self) -> Device:
        device = Device()
        device.move(0, 1)
        device.move(1, 2)
        return device

    def test_g4v1_has_the_flag_octet_and_no_time(self):
        assert self._moved().body(header(4, 1)) == _hex("04 01 17 02  00 41  01 81")

    def test_g4v2_has_the_absolute_time(self):
        assert self._moved().body(header(4, 2)) == _hex(
            "04 02 17 02  00 41 28 46 0F 00 00 00  01 81 10 4A 0F 00 00 00"
        )

    def test_g4v3_follows_a_common_time_of_occurrence_and_counts_from_it(self):
        # Group 51 variation 1 is a synchronized time. The first event is 0 ms after it,
        # the second 1000 ms (0x03E8).
        assert self._moved().body(header(4, 3)) == _hex(
            "33 01 07 01  28 46 0F 00 00 00  04 03 17 02  00 41 00 00  01 81 E8 03"
        )

    def test_variation_zero_is_answered_with_the_absolute_time(self):
        assert self._moved().body(header(4, 0)) == _hex(
            "04 02 17 02  00 41 28 46 0F 00 00 00  01 81 10 4A 0F 00 00 00"
        )

    def test_a_variation_that_does_not_exist_is_an_unknown_object(self):
        fragment = self._moved().master.read(header(4, 4)).fragment
        assert fragment.iin2 & IIN2_OBJECT_UNKNOWN

    def test_a_read_by_name_with_nothing_buffered_is_a_null_response(self):
        assert Device().master.read(header(4, 0)).fragment.is_null


class TestEventsBeforeTheClockIsSet:
    def test_the_event_is_g4v3_behind_an_unsynchronized_common_time(self):
        device = Device(need_time=True)
        device.move(0, 2)
        # Group 51 variation 2 is a time from a clock that had not been set.
        assert device.body(classes(1)) == _hex(
            "33 02 07 01  28 46 0F 00 00 00  04 03 17 01  00 81 00 00"
        )


class TestBelowLevelFour:
    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_a_read_of_group_3_is_an_unknown_object(self, level):
        for variation in (0, 1, 2):
            fragment = Device(level=level).master.read(header(3, variation)).fragment
            assert not fragment.body and fragment.iin2 & IIN2_OBJECT_UNKNOWN

    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_a_read_of_group_4_is_an_unknown_object(self, level):
        for variation in (0, 1, 2, 3):
            fragment = Device(level=level).master.read(header(4, variation)).fragment
            assert not fragment.body and fragment.iin2 & IIN2_OBJECT_UNKNOWN

    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_class_0_leaves_them_out(self, level):
        device = Device(level=level)
        assert device.body(classes(0)) == _hex("01 02 00 00 00  01")

    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_a_change_buffers_no_event(self, level):
        device = Device(level=level)
        device.move(0, 2)
        assert device.master.read(classes(1, 2, 3)).fragment.is_null

    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_no_point_is_served(self, level):
        assert Device(level=level).outstation.served(Kind.DBI) == []

    def test_level_4_serves_every_point_of_the_map(self):
        points = Device(level=4).outstation.served(Kind.DBI)
        assert [point.index for point in points] == list(CLASSES)


class TestWithNoDoubleBitPoints:
    def test_a_level_4_outstation_with_none_refuses_both_groups(self):
        binding = Binding()
        binding.read(Kind.BI, 0, lambda: False)
        outstation = DerOutstation(
            load.resolve(document({"BI": [row("Alarm", 0, event_class=1)]}), Composition()),
            binding,
            strict=False,
            level=4,
        )
        master = TestMaster(outstation.session(need_time=False))
        for group in (3, 4):
            fragment = master.read(header(group, 0)).fragment
            assert not fragment.body and fragment.iin2 & IIN2_OBJECT_UNKNOWN


class TestThePointMap:
    def test_a_table_lists_double_bit_points_under_dbi(self):
        point_map = load.resolve(document({"DBI": [row("Valve", 7, event_class=2)]}), Composition())
        point = point_map.point(Kind.DBI, 7)
        assert (point.name, point.event_class) == ("Valve", 2)
        assert point.in_class_0 and not point.kind.is_output

    def test_a_reference_to_a_double_bit_point_resolves(self):
        tables = document(
            {
                "BI": [row("Valve closed", 0, event_class=1, associated="DBI3")],
                "DBI": [row("Valve", 3, event_class=1)],
            }
        )
        assert load.resolve(tables, Composition()).point(Kind.BI, 0).associated == (Kind.DBI, 3)

    def test_the_binding_may_not_name_a_point_the_map_lacks(self):
        binding = Binding()
        binding.read(Kind.DBI, 9, lambda: 0)
        with pytest.raises(Exception, match="DBI9"):
            DerOutstation(
                load.resolve(document({"DBI": [row("Valve", 0)]}), Composition()),
                binding,
                strict=False,
                level=4,
            )


class TestTheEventPolicy:
    def test_a_rule_for_the_kind_turns_every_double_bit_event_off(self):
        binding = Binding()
        binding.read(Kind.DBI, 0, lambda: 0)
        outstation = DerOutstation(
            load.resolve(document({"DBI": [row("Valve", 0, event_class=1)]}), Composition()),
            binding,
            strict=False,
            level=4,
            event_policy={"defaults": {"DBI": {"events": False}}},
        )
        assert outstation.event_class(Kind.DBI, 0) == 0

    def test_a_rule_for_the_point_moves_it_to_another_class(self):
        binding = Binding()
        binding.read(Kind.DBI, 0, lambda: 0)
        outstation = DerOutstation(
            load.resolve(document({"DBI": [row("Valve", 0, event_class=1)]}), Composition()),
            binding,
            strict=False,
            level=4,
            event_policy={"points": {"DBI0": {"class": 3}}},
        )
        assert outstation.event_class(Kind.DBI, 0) == 3


def _profile(level: int | None) -> ElementTree.Element:
    device = Device(level=level)
    return device_profile.build(device.outstation, device.session, today=datetime.date(2026, 1, 2))


class TestTheDeviceProfile:
    def test_a_level_4_outstation_declares_the_group_and_every_point(self):
        root = _profile(4)
        group = root.find("d:referenceDevice/d:database/d:doubleBitInputGroup", NS)
        assert group is not None
        points = root.findall(
            "d:referenceDevice/d:dataPointsList/d:doubleBitInputPoints/d:dataPoints"
            "/d:doubleBitInput",
            NS,
        )
        assert [int(p.find("d:index", NS).text) for p in points] == list(CLASSES)
        classes_listed = [p.find("d:changeEventClass", NS).text for p in points]
        assert classes_listed == ["one", "one", "two", "three", "none", "one"]

    def test_the_implementation_table_lists_both_groups(self):
        device = Device()
        table = device_profile.implementation(device.outstation, device.session.facts)
        listed = {(r.group, r.variation) for r in table.rows}
        assert {(3, 0), (3, 1), (3, 2), (4, 0), (4, 1), (4, 2), (4, 3)} <= listed

    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_below_level_4_neither_group_is_listed(self, level):
        device = Device(level=level)
        table = device_profile.implementation(device.outstation, device.session.facts)
        assert not {row_.group for row_ in table.rows} & {3, 4}
        root = _profile(level)
        assert root.find("d:referenceDevice/d:dataPointsList/d:doubleBitInputPoints", NS) is None
        assert root.find("d:referenceDevice/d:database/d:doubleBitInputGroup", NS) is None

    def test_every_request_the_table_lists_for_these_groups_is_answered(self):
        device = Device()
        device.move(0, 2)
        table = device_profile.implementation(device.outstation, device.session.facts)
        rows = [r for r in table.rows if r.group in (3, 4) and r.request]
        assert {(r.group, r.variation) for r in rows} >= {(3, 0), (3, 1), (3, 2), (4, 3)}
        for listed in rows:
            for qualifier in listed.request[1]:
                head = bytes([listed.group, listed.variation, qualifier])
                request = {
                    0x06: head,
                    0x00: head + bytes([0, 0]),
                    0x01: head + bytes([0, 0, 0, 0]),
                    0x07: head + bytes([1]),
                    0x08: head + bytes([1, 0]),
                    0x17: head + bytes([1, 0]),
                    0x28: head + bytes([1, 0, 0, 0]),
                }[qualifier]
                fragment = device.master.read(request).fragment
                assert not fragment.iin2 & (IIN2_OBJECT_UNKNOWN | IIN2_PARAMETER), (
                    listed,
                    qualifier,
                )
                device.master.confirm(fragment)

    @pytest.mark.parametrize("request_octets", ["03 03 06", "04 04 06"])
    def test_a_variation_the_table_does_not_list_is_an_unknown_object(self, request_octets):
        fragment = Device().master.read(_hex(request_octets)).fragment
        assert fragment.iin2 & IIN2_OBJECT_UNKNOWN

    def test_a_read_by_index_of_group_3_is_listed_for_flags_and_not_for_the_packed_form(self):
        device = Device()
        table = device_profile.implementation(device.outstation, device.session.facts)
        qualifiers = {
            (r.group, r.variation): r.request[1] for r in table.rows if r.group == 3 and r.request
        }
        assert Q_INDEX_8 in qualifiers[(3, 2)]
        assert Q_INDEX_8 not in qualifiers[(3, 1)]

    def test_the_master_reads_the_declared_points_with_their_classes(self):
        text = device_profile.render(_profile(4))
        declared = [d for d in read_device_profile(text) if d.type is PointType.DOUBLE_BIT_INPUT]
        assert [(d.index, d.name, d.event_class) for d in declared] == [
            (index, f"Valve {index}", cls) for index, cls in CLASSES.items()
        ]

    def test_the_console_view_lists_the_points_as_a_table(self):
        document = device_profile_view.read(device_profile.render(_profile(4)))
        points = table(document, "Data points list", "Double bit input points")
        assert column(points, "Index") == [str(index) for index in CLASSES]
        assert column(points, "Name") == [f"Valve {index}" for index in CLASSES]


SCHEMA = pathlib.Path(__file__).resolve().parent.parent / "schema" / device_profile.SCHEMA_FILE


@pytest.mark.skipif(not SCHEMA.is_file(), reason="the Users Group schema is obtained locally")
class TestAgainstTheSchema:
    def test_the_document_of_a_level_4_outstation_with_double_bit_inputs_validates(self):
        xmlschema = pytest.importorskip("xmlschema")
        document_ = device_profile.render(_profile(4))
        assert list(xmlschema.XMLSchema(str(SCHEMA)).iter_errors(document_)) == []
