"""The curve store: curves behind one window, and the rules on editing them."""

from __future__ import annotations

import pytest

from py1815.control import CommandStatus
from py1815.profile import curves
from py1815.profile.binding import Binding
from py1815.profile.curves import Curve, CurveStore
from py1815.profile.model import Kind

SELECTOR, READBACK, REFERENCED, INDEX = 100, 500, 7, 50
VOLT_VAR, VOLT_WATT = 2, 5


class Bound:
    """A store bound to a binding, with one function that names a curve."""

    def __init__(self, count: int = 3) -> None:
        self.store = CurveStore(count)
        self.binding = Binding()
        self.enabled = False
        self.store.bind(self.binding, output=SELECTOR, readback=READBACK, referenced=REFERENCED)
        self.curve = self.store.reference(
            self.binding, INDEX, types=[VOLT_VAR], enabled=lambda: self.enabled
        )

    def write(self, index: int, value: float) -> CommandStatus:
        """What an operate on one analog output comes to: the check, then the write."""
        output = self.binding.outputs[(Kind.AO, index)]
        refused = output.check(value) if output.check is not None else None
        if refused is not None:
            return refused
        assert output.apply is not None
        return output.apply(value) or CommandStatus.SUCCESS

    def field(self, position: int, value: float) -> CommandStatus:
        return self.write(SELECTOR + 1 + position, value)

    def point(self, number: int, x: float, y: float) -> None:
        base = SELECTOR + 1 + curves.FIELDS + 2 * number
        assert self.write(base, x) is CommandStatus.SUCCESS
        assert self.write(base + 1, y) is CommandStatus.SUCCESS

    def read(self, kind: Kind, index: int) -> float | bool:
        return self.binding.readers[(kind, index)]()  # type: ignore[return-value]


class TestACurve:
    def _curve(self, *points: tuple[float, float]) -> Curve:
        curve = Curve(1)
        curve.fields[curves.POINT_COUNT] = len(points)
        for n, (x, y) in enumerate(points):
            curve.values[2 * n], curve.values[2 * n + 1] = x, y
        return curve

    def test_it_is_straight_between_its_points(self):
        curve = self._curve((900, 400), (1000, 0), (1100, -400))
        assert curve.at(950) == pytest.approx(200)
        assert curve.at(1000) == 0
        assert curve.at(1075) == pytest.approx(-300)

    def test_it_is_level_beyond_either_end(self):
        curve = self._curve((900, 400), (1100, -400))
        assert curve.at(0) == 400
        assert curve.at(5000) == -400

    def test_only_the_points_in_use_count(self):
        curve = self._curve((900, 400), (1100, -400))
        curve.values[4], curve.values[5] = 2000, 999
        assert curve.points == [(900, 400), (1100, -400)]
        assert curve.at(3000) == -400

    def test_a_curve_with_no_points_has_no_value(self):
        assert Curve(1).at(1000) is None

    def test_a_step_takes_the_value_before_it(self):
        """Two points at one X: the value there is the first one's."""
        curve = self._curve((1000, 100), (1000, 0), (1100, 0))
        assert curve.at(1000) == 100
        assert curve.at(1001) == 0

    def test_the_number_of_points_is_held_to_what_a_curve_can_carry(self):
        curve = Curve(1)
        curve.fields[curves.POINT_COUNT] = 500
        assert curve.count == curves.MAX_POINTS
        curve.fields[curves.POINT_COUNT] = -3
        assert curve.count == 0


class TestTheWindow:
    def test_a_store_holds_at_least_one_curve(self):
        with pytest.raises(ValueError):
            CurveStore(0)

    def test_it_binds_the_selector_the_fields_and_every_point(self):
        bound = Bound()
        outputs = [index for kind, index in bound.binding.outputs if kind is Kind.AO]
        block = 1 + curves.FIELDS + 2 * curves.MAX_POINTS
        assert sorted(outputs) == [INDEX, *range(SELECTOR, SELECTOR + block)]
        inputs = [index for kind, index in bound.binding.readers if kind is Kind.AI]
        assert sorted(inputs) == list(range(READBACK, READBACK + block))

    def test_writes_go_to_the_curve_that_is_selected(self):
        bound = Bound()
        bound.point(0, 950, 10)
        assert bound.write(SELECTOR, 2) is CommandStatus.SUCCESS
        assert bound.read(Kind.AI, READBACK) == 2
        assert bound.read(Kind.AI, READBACK + 1 + curves.FIELDS) == 0
        bound.point(0, 1050, 20)
        assert bound.store.curves[1].values[:2] == [950, 10]
        assert bound.store.curves[2].values[:2] == [1050, 20]

    @pytest.mark.parametrize("number", [0, 4, -1])
    def test_a_curve_that_does_not_exist_cannot_be_selected(self, number):
        bound = Bound(count=3)
        assert bound.write(SELECTOR, number) is CommandStatus.OUT_OF_RANGE
        assert bound.store.selected == 1

    def test_a_refusal_of_the_callers_comes_first(self):
        store, binding = CurveStore(2), Binding()
        store.bind(
            binding,
            output=SELECTOR,
            readback=READBACK,
            referenced=REFERENCED,
            check=lambda _value: CommandStatus.BLOCKED,
        )
        for index in (SELECTOR, SELECTOR + 1, SELECTOR + 1 + curves.FIELDS):
            check = binding.outputs[(Kind.AO, index)].check
            assert check is not None and check(99) is CommandStatus.BLOCKED


class TestReferences:
    def _defined(self, bound: Bound, number: int, kind: int = VOLT_VAR) -> None:
        assert bound.write(SELECTOR, number) is CommandStatus.SUCCESS
        assert bound.field(curves.TYPE, kind) is CommandStatus.SUCCESS
        bound.point(0, 900, 400)
        bound.point(1, 1100, -400)
        assert bound.field(curves.POINT_COUNT, 2) is CommandStatus.SUCCESS

    def test_a_function_names_no_curve_until_it_is_given_one(self):
        bound = Bound()
        assert bound.curve() is None
        assert not bound.read(Kind.BI, REFERENCED)

    def test_naming_a_curve_sets_the_indicator_for_that_curve_only(self):
        bound = Bound()
        self._defined(bound, 2)
        assert bound.write(INDEX, 2) is CommandStatus.SUCCESS
        assert bound.read(Kind.BI, REFERENCED)
        named = bound.curve()
        assert named is not None and named.number == 2
        bound.write(SELECTOR, 1)
        assert not bound.read(Kind.BI, REFERENCED)

    def test_zero_lets_the_curve_go(self):
        bound = Bound()
        self._defined(bound, 2)
        bound.write(INDEX, 2)
        assert bound.write(INDEX, 0) is CommandStatus.SUCCESS
        assert bound.curve() is None
        assert not bound.store.referenced(2)

    def test_a_curve_of_another_type_is_refused(self):
        bound = Bound()
        self._defined(bound, 2, VOLT_WATT)
        assert bound.write(INDEX, 2) is CommandStatus.NOT_SUPPORTED
        assert bound.curve() is None

    def test_a_curve_that_does_not_exist_is_refused(self):
        bound = Bound(count=3)
        assert bound.write(INDEX, 4) is CommandStatus.OUT_OF_RANGE

    def test_a_curve_is_locked_only_while_its_function_is_enabled(self):
        bound = Bound()
        self._defined(bound, 2)
        bound.write(INDEX, 2)
        assert not bound.store.locked(2)
        bound.point(0, 910, 390)
        bound.enabled = True
        assert bound.store.locked(2)
        first = SELECTOR + 1 + curves.FIELDS
        assert bound.write(first, 1) is CommandStatus.AUTOMATION_INHIBIT
        assert bound.field(curves.POINT_COUNT, 1) is CommandStatus.AUTOMATION_INHIBIT
        assert bound.store.curves[2].values[0] == 910
        assert bound.store.curves[2].count == 2

    def test_other_curves_stay_editable_while_one_is_locked(self):
        bound = Bound()
        self._defined(bound, 2)
        bound.write(INDEX, 2)
        bound.enabled = True
        assert bound.write(SELECTOR, 3) is CommandStatus.SUCCESS
        bound.point(0, 1, 2)

    def test_a_referenced_curve_cannot_become_a_type_its_function_does_not_follow(self):
        bound = Bound()
        self._defined(bound, 2)
        bound.write(INDEX, 2)
        assert bound.field(curves.TYPE, VOLT_WATT) is CommandStatus.NOT_SUPPORTED
        assert bound.store.curves[2].type == VOLT_VAR
        bound.write(INDEX, 0)
        assert bound.field(curves.TYPE, VOLT_WATT) is CommandStatus.SUCCESS

    def test_a_refusal_of_the_callers_comes_before_the_curve_number_is_looked_at(self):
        bound = Bound()
        bound.store.reference(
            bound.binding,
            INDEX + 1,
            types=[VOLT_VAR],
            enabled=lambda: False,
            check=lambda _value: CommandStatus.BLOCKED,
        )
        self._defined(bound, 1)
        assert bound.write(INDEX + 1, 1) is CommandStatus.BLOCKED
        assert bound.write(INDEX + 1, 0) is CommandStatus.BLOCKED
        assert not bound.store.referenced(1)

    def test_two_functions_may_name_one_curve_and_either_locks_it(self):
        bound = Bound()
        other_enabled = False
        bound.store.reference(
            bound.binding, INDEX + 1, types=[VOLT_VAR, VOLT_WATT], enabled=lambda: other_enabled
        )
        self._defined(bound, 1)
        bound.write(INDEX, 1)
        bound.write(INDEX + 1, 1)
        bound.write(INDEX, 0)
        assert bound.store.referenced(1), "the second function still names it"
        other_enabled = True
        assert bound.store.locked(1)
