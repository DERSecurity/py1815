"""The subset level an outstation is held to."""

from __future__ import annotations

import warnings

import pytest
from profile_fixtures import for_reference_der

from py1815.profile import der, load
from py1815.profile.model import Composition
from py1815.profile.outstation import DerOutstation
from py1815.subset import SubsetLevel


def _outstation(**options) -> DerOutstation:
    point_map = load.resolve(for_reference_der(), Composition())
    return DerOutstation(point_map, der.ReferenceDer().bind(point_map), **options)


@pytest.mark.parametrize("value", [2, 3, 4, SubsetLevel.LEVEL_3])
def test_parse_accepts_2_3_and_4(value):
    assert SubsetLevel.parse(value) == int(value)


@pytest.mark.parametrize("value", [0, 1, 5, -2, 2.0, "2", None, True, False])
def test_parse_refuses_anything_else_and_names_the_setting(value):
    with pytest.raises(ValueError, match=r"^lvl must be 2, 3 or 4, not "):
        SubsetLevel.parse(value, "lvl")


def test_levels_compare_as_integers():
    assert SubsetLevel.LEVEL_4 > SubsetLevel.LEVEL_3 >= 3


@pytest.mark.parametrize(
    "level, exact, analog_status_variation",
    [(None, False, 1), (2, True, 2), (3, False, 1), (4, False, 1)],
)
def test_each_level_answers_as_documented(level, exact, analog_status_variation):
    outstation = _outstation(level=level)
    assert outstation.level == (level or 2)
    assert outstation.level2 is exact
    assert outstation.default_variation(40) == analog_status_variation


def test_at_least_compares_the_claimed_level():
    outstation = _outstation(level=3)
    assert outstation.at_least(2) and outstation.at_least(SubsetLevel.LEVEL_3)
    assert not outstation.at_least(4)
    assert not _outstation().at_least(3)
    with pytest.raises(ValueError, match="level must be 2, 3 or 4"):
        outstation.at_least(5)


@pytest.mark.parametrize("value", [1, 5, "3", 3.0, True])
def test_outstation_refuses_a_level_outside_2_3_4(value):
    with pytest.raises(ValueError, match="level must be 2, 3 or 4"):
        _outstation(level=value)


def test_level2_true_is_a_deprecated_alias_for_level_2():
    with pytest.warns(DeprecationWarning, match="use level=2"):
        outstation = _outstation(level2=True)
    assert outstation.level == 2 and outstation.level2 is True
    with pytest.warns(DeprecationWarning):
        assert _outstation(level2=True, level=2).level == 2


def test_level2_true_with_another_level_is_refused():
    with pytest.warns(DeprecationWarning), pytest.raises(ValueError, match="conflicts"):
        _outstation(level2=True, level=3)


def test_level2_false_changes_nothing_and_does_not_warn():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        outstation = _outstation(level2=False, level=3)
    assert outstation.level == 3
