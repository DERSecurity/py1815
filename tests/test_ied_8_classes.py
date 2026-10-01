"""IED certification procedures, section 8.5: class data.

The class procedures are written once per class and differ only in the class
number, so each is one test run three times.
"""

from __future__ import annotations

import pytest
from ied_harness import (
    ERROR_IIN,
    FLAG_ONLINE,
    IIN1_CLASS_1,
    IIN1_CLASS_2,
    IIN1_CLASS_3,
    Q_COUNT_8,
    Q_COUNT_16,
    Q_INDEX_8,
    Q_INDEX_16,
    Q_RANGE_8,
    Q_RANGE_16,
    Dut,
    classes,
)

#: Table 8-3: what a class 0 response may contain at subset level 2, and the
#: qualifiers it may use.
STATIC_OBJECTS = {
    (1, 1),
    (1, 2),
    (10, 2),
    (20, 1),
    (20, 2),
    (20, 5),
    (20, 6),
    (21, 1),
    (21, 2),
    (21, 9),
    (21, 10),
    (30, 1),
    (30, 2),
    (30, 3),
    (30, 4),
    (40, 2),
}
#: Table 8-4: what an event class response may contain at subset level 2.
EVENT_OBJECTS = {(2, 1), (2, 2), (2, 3), (22, 1), (22, 2), (32, 1), (32, 2), (51, 1), (51, 2)}

CLASS_BIT = {1: IIN1_CLASS_1, 2: IIN1_CLASS_2, 3: IIN1_CLASS_3}

#: A binary and an analog input in each class of the device under test.
BINARY_OF = {1: 0, 2: 2, 3: 3}
ANALOG_OF = {1: 0, 2: 1, 3: 2}

EACH_CLASS = pytest.mark.parametrize("cls", [1, 2, 3])


def _generate(dut: Dut, cls: int, count: int = 1) -> list[tuple[int, int]]:
    """Cause ``count`` events in a class, of both kinds. Returns (group, index) in order.

    One analog event and then binary ones: an analog point keeps only its
    latest event, so a second change of it would replace the first.
    """
    made = []
    for step in range(count):
        if step == 0:
            dut.step(ANALOG_OF[cls])
            made.append((32, ANALOG_OF[cls]))
        else:
            dut.toggle(BINARY_OF[cls])
            made.append((2, BINARY_OF[cls]))
    return made


def _check_events(fragment, expected: list[tuple[int, int]]) -> None:
    objects = fragment.objects
    assert [(o.group, o.index) for o in objects] == expected, "all of them, oldest first"
    assert {(o.group, o.variation) for o in objects} <= EVENT_OBJECTS
    assert {o.qualifier for o in objects} <= {Q_INDEX_8, Q_INDEX_16}
    assert all(o.flags & 0x7F == FLAG_ONLINE for o in objects), "online and nothing else"
    assert fragment.con, "a response carrying events asks to be confirmed"


class TestClass0:
    def test_8_5_1_2_class_0_reports_every_input_in_level_2_objects(self):
        dut = Dut()
        dut.master.request(7, bytes([20, 0, 0x06]))  # freeze, so frozen counters exist
        fragment = dut.master.read(classes(0)).fragment
        objects = fragment.objects
        assert {(o.group, o.variation) for o in objects} <= STATIC_OBJECTS
        assert {o.qualifier for o in objects} <= {Q_RANGE_8, Q_RANGE_16}
        assert {o.group for o in objects} == {1, 20, 21, 30}
        assert [o.index for o in fragment.of(1)] == [0, 1, 2, 3]
        assert [o.index for o in fragment.of(30)] == [0, 1, 2, 3]
        assert [o.index for o in fragment.of(20)] == [0, 1, 2]
        assert all(o.flags is None or o.flags & 0x7F == FLAG_ONLINE for o in objects)
        assert not fragment.con, "static data alone needs no confirmation"
        assert not fragment.iin2 & ERROR_IIN

    def test_8_5_1_2_class_0_reports_the_current_state(self):
        dut = Dut()
        dut.toggle(1)
        dut.set_analog(2, 4321)
        fragment = dut.master.read(classes(0)).fragment
        assert {o.index: o.state for o in fragment.of(1)}[1] is True
        assert {o.index: o.value for o in fragment.of(30)}[2] == 4321


class TestEventClasses:
    @EACH_CLASS
    def test_8_5_x_2_1_all_events_with_qualifier_06(self, cls):
        dut = Dut()
        assert dut.master.read(classes(cls)).fragment.is_null, "nothing has happened yet"
        made = _generate(dut, cls, 3)
        fragment = dut.master.read(classes(cls)).fragment
        _check_events(fragment, made)
        assert not fragment.iin1 & CLASS_BIT[cls], "nothing more is waiting in this class"
        dut.master.confirm(fragment)
        assert dut.master.read(classes(cls)).fragment.is_null

    @EACH_CLASS
    @pytest.mark.parametrize("qualifier", [Q_COUNT_8, Q_COUNT_16], ids=["07", "08"])
    def test_8_5_x_2_2_and_3_a_limited_quantity(self, cls, qualifier):
        dut = Dut()
        dut.master.empty_events()
        made = _generate(dut, cls, 4)
        some = dut.master.read(classes(cls, qualifier=qualifier, count=3)).fragment
        _check_events(some, made[:3])
        assert some.iin1 & CLASS_BIT[cls], "one is still waiting"
        dut.master.confirm(some)
        rest = dut.master.read(classes(cls, qualifier=qualifier, count=10)).fragment
        _check_events(rest, made[3:])
        dut.master.confirm(rest)
        assert dut.master.read(classes(cls)).fragment.is_null

    @EACH_CLASS
    def test_8_5_x_2_4_events_read_and_not_confirmed_are_reported_again(self, cls):
        dut = Dut()
        dut.master.empty_events()
        first = _generate(dut, cls, 2)
        fragment = dut.master.read(classes(cls)).fragment
        _check_events(fragment, first)
        # No confirmation, and time passes: nothing is sent unasked.
        dut.clock.advance(60.0)
        assert dut.master.raw(b"").silent
        dut.toggle(BINARY_OF[cls])
        again = dut.master.read(classes(cls)).fragment
        _check_events(again, [*first, (2, BINARY_OF[cls])])
        dut.master.confirm(again)
        assert dut.master.read(classes(cls)).fragment.is_null

    @EACH_CLASS
    def test_8_5_x_1_a_class_with_no_events_is_a_null_response(self, cls):
        dut = Dut()
        fragment = dut.master.read(classes(cls)).fragment
        assert fragment.is_null
        assert not fragment.con, "nothing to confirm"


class TestMultipleObjectRequest:
    def _events_in_every_class(self, dut: Dut) -> list[tuple[int, int]]:
        made = []
        # Interleaved, so that class order and time order differ.
        for cls in (3, 1, 2, 1, 3):
            dut.toggle(BINARY_OF[cls])
            made.append((2, BINARY_OF[cls]))
        return made

    def test_8_5_5_2_1_classes_1_2_and_3_in_one_request(self):
        dut = Dut()
        dut.master.empty_events()
        made = self._events_in_every_class(dut)
        fragment = dut.master.read(classes(1, 2, 3)).fragment
        _check_events(fragment, made)
        times = [o.time for o in fragment.objects]
        assert times == sorted(times), "oldest first, across the classes"
        dut.master.confirm(fragment)
        assert dut.master.read(classes(1, 2, 3)).fragment.is_null

    def test_8_5_5_2_2_classes_1_2_3_and_0_in_one_request(self):
        dut = Dut()
        dut.master.empty_events()
        made = self._events_in_every_class(dut)
        reply = dut.master.read(classes(1, 2, 3, 0), sequence=9)
        fragment = reply.fragment
        assert fragment.sequence == 9, "the request's own sequence number"
        objects = fragment.objects
        events = [o for o in objects if o.group in (2, 32)]
        static = [o for o in objects if o.group not in (2, 32)]
        assert objects == events + static, "every event before any static data"
        assert [(o.group, o.index) for o in events] == made
        assert {(o.group, o.variation) for o in events} <= EVENT_OBJECTS
        assert {(o.group, o.variation) for o in static} <= STATIC_OBJECTS
        assert {o.qualifier for o in static} <= {Q_RANGE_8, Q_RANGE_16}
        assert fragment.con
        dut.master.confirm(fragment)

    def test_8_5_5_1_several_events_of_one_analog_point_keep_their_order(self):
        dut = Dut(level2=True, capacity=50)
        # A session that keeps every analog change, to have several to order.
        dut.outstation.events._analog_latest_only = False
        dut.master.empty_events()
        for value in (200, 300, 400):
            dut.set_analog(0, value)
        fragment = dut.master.read(classes(1)).fragment
        assert [o.value for o in fragment.of(32)] == [200, 300, 400]


class TestClassAssignment:
    def test_8_5_6_2_each_class_returns_only_its_own_events(self):
        dut = Dut()
        dut.master.empty_events()
        made = {cls: _generate(dut, cls, 2) for cls in (1, 2, 3)}
        for cls in (1, 2, 3):
            fragment = dut.master.read(classes(cls)).fragment
            _check_events(fragment, made[cls])
            dut.master.confirm(fragment)
            assert dut.master.read(classes(cls)).fragment.is_null
        assert dut.master.read(classes(1, 2, 3)).fragment.is_null

    def test_8_5_6_2_the_indications_follow_what_is_left(self):
        dut = Dut()
        dut.master.empty_events()
        for cls in (1, 2, 3):
            _generate(dut, cls, 1)
        fragment = dut.master.read(classes(1)).fragment
        assert not fragment.iin1 & IIN1_CLASS_1
        assert fragment.iin1 & IIN1_CLASS_2 and fragment.iin1 & IIN1_CLASS_3
        dut.master.confirm(fragment)
        fragment = dut.master.read(classes(2)).fragment
        assert fragment.iin1 & (IIN1_CLASS_1 | IIN1_CLASS_2 | IIN1_CLASS_3) == IIN1_CLASS_3
