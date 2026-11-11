"""Counter events, which a Level 3 or 4 outstation raises when a counter's flags change.

IEEE 1815-2012 11.9.5.2 has a device that supports counter events raise one whenever a
counter's flags change, and TB2016-003b Table 12-49 footnote o makes that reporting
mandatory where counter events are reported at all. A change in value raises none (D124).
The device under test of the IED harness has three counters, each counting 5, whose events
report in class 3. A counter event is group 22 variation 1: index, flags, then the count.
"""

from __future__ import annotations

import pytest
from ied_harness import (
    ENABLE_UNSOLICITED,
    IIN1_CLASS_3,
    Q_COUNT_8,
    Q_COUNT_16,
    UNSOLICITED_RESPONSE,
    Dut,
    classes,
    header,
)

from py1815.profile import device_profile
from py1815.profile.binding import Quality
from py1815.profile.model import Kind

ABOVE_LEVEL_2 = pytest.mark.parametrize("level", [3, 4])
BELOW_LEVEL_3 = pytest.mark.parametrize("level", [2, None], ids=["level_2", "default"])
#: Counter 0 with communication lost: index 0, flags 0x04, count 5.
LOST = "16 01 17 01 00 04 05 00 00 00"
#: Counter 0 lost and then restored: the second object has flags 0x01 (online).
LOST_AND_RESTORED = "16 01 17 02 00 04 05 00 00 00 00 01 05 00 00 00"


def _hex(octets: bytes) -> str:
    return octets.hex(" ").upper()


def _set_quality(dut: Dut, index: int, quality: Quality) -> int:
    """Set a counter's quality, poll the outstation, and return how many events it buffered."""
    dut.quality[(Kind.CTR, index)] = quality
    return dut.outstation.poll()


class TestAFlagChange:
    @ABOVE_LEVEL_2
    def test_is_reported_in_a_class_3_poll_and_retired_by_the_confirmation(self, level):
        dut = Dut(level=level)
        assert _set_quality(dut, 0, Quality.COMM_LOST) == 1
        assert dut.master.read(classes(1)).fragment.iin1 & IIN1_CLASS_3
        fragment = dut.master.read(classes(3)).fragment
        assert _hex(fragment.body) == LOST
        assert fragment.con
        after = dut.master.confirm(fragment).fragments
        assert not after
        empty = dut.master.read(classes(3)).fragment
        assert not empty.body and not empty.iin1 & IIN1_CLASS_3

    @ABOVE_LEVEL_2
    def test_back_to_normal_is_a_second_event(self, level):
        dut = Dut(level=level)
        _set_quality(dut, 0, Quality.COMM_LOST)
        _set_quality(dut, 0, Quality.GOOD)
        assert _hex(dut.master.read(classes(1, 2, 3)).fragment.body) == LOST_AND_RESTORED

    @ABOVE_LEVEL_2
    def test_is_not_reported_in_class_1_or_2(self, level):
        dut = Dut(level=level)
        _set_quality(dut, 0, Quality.COMM_LOST)
        assert not dut.master.read(classes(1, 2)).fragment.body

    @ABOVE_LEVEL_2
    def test_an_unchanged_quality_raises_nothing_more(self, level):
        dut = Dut(level=level)
        _set_quality(dut, 0, Quality.COMM_LOST)
        assert _set_quality(dut, 0, Quality.COMM_LOST) == 0

    @ABOVE_LEVEL_2
    def test_is_sent_unsolicited_when_class_3_is_enabled(self, level):
        dut = Dut(level=level, unsolicited=True)
        dut.master.confirm_unsolicited(dut.master.listen().fragment.sequence)
        dut.clear_restart()
        assert dut.master.request(ENABLE_UNSOLICITED, classes(3)).fragment.is_null
        _set_quality(dut, 0, Quality.COMM_LOST)
        fragment = dut.master.listen().fragment
        assert fragment.function == UNSOLICITED_RESPONSE
        assert _hex(fragment.body) == LOST


class TestAValueChange:
    @ABOVE_LEVEL_2
    def test_raises_no_counter_event(self, level):
        dut = Dut(level=level)
        dut.count(3)
        assert dut.outstation.poll() == 0
        assert not dut.master.read(classes(1, 2, 3)).fragment.body
        assert not dut.master.read(header(22, 0)).fragment.body

    @ABOVE_LEVEL_2
    def test_is_carried_by_the_next_flag_change(self, level):
        dut = Dut(level=level)
        dut.count(3)
        _set_quality(dut, 1, Quality.COMM_LOST)
        assert _hex(dut.master.read(header(22, 0)).fragment.body) == "16 01 17 01 01 04 08 00 00 00"


class TestReadingGroup22:
    # Table 12-23 lists group 22 variations 0, 1 and 2 with qualifiers 06, 07 and 08 at
    # Level 3. Every variation is answered in variation 1: the counters have 32 bits, and
    # IED procedure 8.25.2.3 step 9 takes variation 1 for a read of variation 2.
    @ABOVE_LEVEL_2
    @pytest.mark.parametrize("variation", [0, 1, 2])
    def test_every_variation_is_answered_in_variation_1(self, level, variation):
        dut = Dut(level=level)
        _set_quality(dut, 0, Quality.COMM_LOST)
        _set_quality(dut, 0, Quality.GOOD)
        fragment = dut.master.read(header(22, variation)).fragment
        assert _hex(fragment.body) == LOST_AND_RESTORED
        assert fragment.con

    @ABOVE_LEVEL_2
    @pytest.mark.parametrize("qualifier, count", [(Q_COUNT_8, "01"), (Q_COUNT_16, "01 00")])
    def test_a_count_returns_that_many_oldest_first(self, level, qualifier, count):
        dut = Dut(level=level)
        _set_quality(dut, 0, Quality.COMM_LOST)
        _set_quality(dut, 0, Quality.GOOD)
        request = f"16 00 {qualifier:02X} {count}"
        fragment = dut.master.read(bytes.fromhex(request)).fragment
        assert _hex(fragment.body) == LOST
        dut.master.confirm(fragment)
        rest = dut.master.read(header(22, 1)).fragment
        assert _hex(rest.body) == "16 01 17 01 00 01 05 00 00 00"

    @ABOVE_LEVEL_2
    def test_the_variations_with_time_are_refused(self, level):
        dut = Dut(level=level)
        _set_quality(dut, 0, Quality.COMM_LOST)
        assert dut.master.read(header(22, 5)).fragment.is_error


#: Every counter's value changes raise events (the event policy turns them on).
VALUE_CHANGES = {"defaults": {"CTR": {"value_changes": True}}}


class TestAValueChangeWhereThePolicyTurnsItOn:
    @ABOVE_LEVEL_2
    def test_every_change_of_count_is_an_event(self, level):
        dut = Dut(level=level, event_policy=VALUE_CHANGES)
        dut.count(3)
        assert dut.outstation.poll() == 3
        # Counters 0, 1 and 2, each ONLINE with a count of 8.
        assert _hex(dut.master.read(header(22, 0)).fragment.body) == (
            "16 01 17 03 00 01 08 00 00 00 01 01 08 00 00 00 02 01 08 00 00 00"
        )

    @ABOVE_LEVEL_2
    def test_a_change_within_the_deadband_is_not_an_event(self, level):
        policy = {"points": {"CTR0": {"value_changes": True, "deadband": 5}}}
        dut = Dut(level=level, event_policy=policy)
        dut.count(3)
        assert dut.outstation.poll() == 0, "3 counts from the first reading: inside 5"
        dut.count(3)
        assert dut.outstation.poll() == 1, "6 counts: past 5"
        dut.count(3)
        assert dut.outstation.poll() == 0, "measured from the count of the last event, 11"
        assert _hex(dut.master.read(header(22, 0)).fragment.body) == "16 01 17 01 00 01 0B 00 00 00"

    @ABOVE_LEVEL_2
    def test_a_flag_change_is_still_an_event(self, level):
        dut = Dut(level=level, event_policy=VALUE_CHANGES)
        assert _set_quality(dut, 0, Quality.COMM_LOST) == 1
        assert _hex(dut.master.read(header(22, 0)).fragment.body) == LOST

    @ABOVE_LEVEL_2
    def test_only_the_counters_the_policy_names_report_value_changes(self, level):
        dut = Dut(level=level, event_policy={"points": {"CTR1": {"value_changes": True}}})
        dut.count(3)
        assert dut.outstation.poll() == 1
        assert [dut.outstation.counter_deadband(i) for i in range(3)] == [None, 0.0, None]

    @BELOW_LEVEL_3
    def test_below_level_3_a_value_change_raises_no_event(self, level):
        dut = Dut(level=level, event_policy=VALUE_CHANGES)
        dut.count(3)
        assert dut.outstation.poll() == 0
        assert dut.master.read(header(22, 0)).fragment.is_null


class TestBelowLevel3:
    @BELOW_LEVEL_3
    def test_a_flag_change_raises_no_counter_event(self, level):
        dut = Dut(level=level)
        assert _set_quality(dut, 0, Quality.COMM_LOST) == 0
        assert dut.master.read(classes(1, 2, 3)).fragment.is_null
        for variation in (0, 1, 2):
            assert dut.master.read(header(22, variation)).fragment.is_null

    @BELOW_LEVEL_3
    def test_the_device_profile_lists_no_counter_event_responses(self, level):
        dut = Dut(level=level)
        rows = device_profile.implementation(dut.outstation, dut.session.facts).rows
        assert not [row for row in rows if row.group == 22 and row.response]
        assert dut.outstation.event_class(Kind.CTR, 0) == 3


class TestDeviceProfile:
    @ABOVE_LEVEL_2
    def test_lists_counter_events_in_variation_1(self, level):
        dut = Dut(level=level, unsolicited=True)
        rows = device_profile.implementation(dut.outstation, dut.session.facts).rows
        answered = {
            (row.variation, row.response[0]) for row in rows if row.group == 22 and row.response
        }
        assert answered == {(1, 0x81), (1, 0x82)}
        read = {row.variation for row in rows if row.group == 22 and row.request}
        assert read == {0, 1, 2}

    @pytest.mark.parametrize(
        ("level", "event_class", "settings"),
        [
            (3, "three", ["defaultCounterEventVariation", "counterEventReportingMode"]),
            (2, "none", []),
        ],
    )
    def test_states_flag_changes_and_no_value_changes_by_default(
        self, level, event_class, settings
    ):
        dut = Dut(level=level)
        root = device_profile.build(dut.outstation, dut.session)
        ns = {"d": device_profile.NAMESPACE}
        group = root.find("d:referenceDevice/d:database/d:counterGroup/d:configuration", ns)
        names = [child.tag.split("}")[1] for child in group]
        counter_events = {*settings, "reportValueChangeCounterEvents", "counterEventReportingMode"}
        assert [name for name in names if name in counter_events] == [
            *settings,
            "reportValueChangeCounterEvents",
        ]
        assert group.find("d:reportValueChangeCounterEvents/d:currentValue/d:no", ns) is not None
        if settings:
            assert group.find("d:defaultCounterEventVariation/d:currentValue/d:one", ns) is not None
        point = root.find(
            "d:referenceDevice/d:dataPointsList/d:counterPoints/d:dataPoints/d:counter", ns
        )
        assert point.find("d:counterEventClass", ns).text == event_class

    @pytest.mark.parametrize(
        ("policy", "current", "per_point"),
        [
            (VALUE_CHANGES, "yes", ["yes", "yes", "yes"]),
            (
                {"points": {"CTR1": {"value_changes": True}}},
                "basedOnPointIndex",
                ["no", "yes", "no"],
            ),
            (None, "no", ["no", "no", "no"]),
        ],
    )
    def test_states_value_changes_where_the_policy_turns_them_on(self, policy, current, per_point):
        dut = Dut(level=3, event_policy=policy)
        root = device_profile.build(dut.outstation, dut.session)
        ns = {"d": device_profile.NAMESPACE}
        group = root.find("d:referenceDevice/d:database/d:counterGroup/d:configuration", ns)
        setting = group.find("d:reportValueChangeCounterEvents", ns)
        assert setting.find(f"d:currentValue/d:{current}", ns) is not None
        offered = [child.tag.split("}")[1] for child in setting.find("d:capabilities", ns)]
        assert offered == ["no", "yes", "basedOnPointIndex"]
        points = root.findall(
            "d:referenceDevice/d:dataPointsList/d:counterPoints/d:dataPoints/d:counter", ns
        )
        reported = [
            child.tag.split("}")[1]
            for point in points
            for child in point.find("d:reportCounterValueChangeEvents", ns)
        ]
        assert reported == per_point
