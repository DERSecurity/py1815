"""Loading the profile tables and resolving them for one DER."""

from __future__ import annotations

import copy
import json

import pytest
from profile_fixtures import REAL_TABLES, analog, document, row, small, units

from py1815.profile import load
from py1815.profile.model import Composition, Kind, MapError, Point, PointMap

AI, AO, BI, BO, CTR = Kind.AI, Kind.AO, Kind.BI, Kind.BO, Kind.CTR


class TestAbsolutePoints:
    def test_every_absolute_point_is_served_at_its_own_index(self):
        resolved = load.resolve(small(), units(0))
        assert resolved.point(AI, 1).name == "Power"
        assert resolved.point(BO, 1).name == "Unpaired switch"

    def test_scaling_and_range_come_from_the_tables(self):
        voltage = load.resolve(small(), units(0)).point(AI, 2)
        assert voltage.to_wire(240.0) == pytest.approx(2400)
        assert voltage.from_wire(2400) == pytest.approx(240.0)
        assert voltage.in_range(6000) and not voltage.in_range(6001)

    def test_a_point_with_no_multiplier_travels_as_it_is(self):
        point = Point(AI, 0, "raw")
        assert point.to_wire(7.0) == 7.0 and point.from_wire(7.0) == 7.0

    def test_a_value_the_tables_fix_is_carried_on_the_point(self):
        assert load.resolve(small(), units(0)).point(AI, 0).fixed_value == 2.5

    def test_a_missing_point_is_an_error_when_demanded_and_none_when_asked(self):
        resolved = load.resolve(small(), units(0))
        assert resolved.get(AI, 999) is None
        with pytest.raises(MapError):
            resolved.point(AI, 999)

    def test_points_of_a_kind_come_back_in_index_order(self):
        indices = [p.index for p in load.resolve(small(), units(2)).of(AI)]
        assert indices == sorted(indices)


class TestRepeatingBlocks:
    def test_no_units_means_the_block_is_not_served(self):
        resolved = load.resolve(small(), units(0))
        assert not [p for p in resolved.points.values() if p.block == "Unit"]

    def test_each_unit_is_a_block_length_further_on(self):
        resolved = load.resolve(small(), units(3))
        # The rows hold two analog inputs per unit where the key says one, and
        # a block has to hold every row it is given.
        assert [p.index for p in resolved.of(AI) if p.block == "Unit"] == [
            1000,
            1001,
            1002,
            1003,
            1004,
            1005,
        ]

    def test_a_units_points_are_named_for_it(self):
        resolved = load.resolve(small(), units(2))
        assert resolved.point(BI, 1001).name == "Unit #2 fault"
        assert resolved.point(BI, 1001).unit == 2

    def test_a_pairing_inside_a_block_stays_inside_that_unit(self):
        resolved = load.resolve(small(), units(2))
        assert resolved.point(AO, 1001).associated == (AI, 1003)
        assert resolved.point(AI, 1003).associated == (AO, 1001)

    def test_an_unknown_block_is_refused(self):
        tables = document({"AI": [analog("Orphan", block="Nowhere", offset=0)]})
        with pytest.raises(MapError, match="unknown block"):
            load.resolve(tables, Composition())

    def test_a_negative_count_is_refused(self):
        with pytest.raises(ValueError):
            Composition(inverters=-1)


class TestWhatALoadRefuses:
    def test_two_points_at_one_index(self):
        tables = document({"BI": [row("One", 4), row("Other", 4)]})
        with pytest.raises(MapError, match="claimed twice"):
            load.resolve(tables, Composition())

    def test_a_block_that_runs_past_the_index_space(self):
        tables = small()
        tables["key"]["equipment"]["meters"]["start"] = 65535
        with pytest.raises(MapError, match="outside"):
            load.resolve(tables, units(2))

    def test_the_same_index_in_two_kinds_is_two_points(self):
        """The control: an index is unique within a kind, not across them."""
        tables = document({"BI": [row("One", 4)], "BO": [row("Other", 4)]})
        assert len(load.resolve(tables, Composition())) == 2


class TestEventClasses:
    def test_a_stated_class_is_kept(self):
        resolved = load.resolve(small(), units(0))
        assert resolved.point(BI, 0).event_class == 1
        assert resolved.point(BI, 1).event_class == 0

    def test_a_blank_class_is_static_data_still_in_class_0(self):
        point = load.resolve(small(), units(0)).point(AI, 4)
        assert point.event_class == 0 and point.in_class_0

    def test_the_advertisement_block_is_in_no_class(self):
        point = load.resolve(small(), units(0)).point(AI, 65000)
        assert point.event_class is None and not point.in_class_0


class TestSupportsPairing:
    def test_a_supports_input_is_tied_to_its_functions_enable_output(self):
        assert load.resolve(small(), units(0)).point(BI, 1).enabled_by == (BO, 0)

    def test_other_inputs_of_the_function_are_not(self):
        assert load.resolve(small(), units(0)).point(BI, 2).enabled_by is None

    def test_two_candidate_outputs_leave_it_unpaired(self):
        """Ambiguity is left visible rather than resolved by guessing."""
        tables = small()
        tables["points"]["BO"].append(row("Enable Widget Mode Again", 7, purpose="Widget"))
        assert load.resolve(tables, units(0)).point(BI, 1).enabled_by is None


class TestTheAdvertisementBlock:
    def test_a_start_point_carries_its_blocks_starting_index(self):
        assert load.resolve(small(), units(0)).point(AI, 65000).fixed_value == 1000

    def test_a_count_point_carries_the_number_of_units(self):
        assert load.resolve(small(), units(4)).point(AI, 65001).fixed_value == 4

    def test_a_block_the_key_does_not_know_is_not_served(self):
        """Absent, rather than a zero that would read as "starts at index 0"."""
        assert load.resolve(small(), units(0)).get(AI, 65002) is None


class TestFindingTheTables:
    def test_the_environment_names_the_file(self, monkeypatch, tmp_path):
        monkeypatch.setenv(load.TABLES_VARIABLE, str(tmp_path / "elsewhere.json"))
        assert load.default_tables() == tmp_path / "elsewhere.json"

    def test_otherwise_it_is_under_the_home_directory(self, monkeypatch):
        monkeypatch.delenv(load.TABLES_VARIABLE, raising=False)
        assert load.default_tables().name == load.TABLES_NAME
        assert load.default_tables().parent.name == ".py1815"

    def test_a_missing_file_says_how_to_get_one(self, tmp_path):
        with pytest.raises(MapError, match="py1815-der tables"):
            load.load(tmp_path / "absent.json")

    @pytest.mark.parametrize("content", ["not json", "[]", '{"points": {}}'])
    def test_a_file_that_is_not_tables_is_refused(self, tmp_path, content):
        path = tmp_path / "tables.json"
        path.write_text(content, encoding="utf-8")
        with pytest.raises(MapError):
            load.load(path)

    def test_a_tables_file_loads(self, tmp_path):
        path = tmp_path / "tables.json"
        path.write_text(json.dumps(small()), encoding="utf-8")
        resolved = load.load(path, units(1))
        assert isinstance(resolved, PointMap)
        assert resolved.profile_version == "0.0"
        assert resolved.composition == units(1)


class TestTheMapIsImmutable:
    def test_points_cannot_be_added_after_the_fact(self):
        resolved = load.resolve(small(), units(0))
        with pytest.raises(TypeError):
            resolved.points[(AI, 500)] = Point(AI, 500, "late")  # type: ignore[index]

    def test_resolving_does_not_alter_the_document(self):
        tables = small()
        before = copy.deepcopy(tables)
        load.resolve(tables, units(2))
        assert tables == before


@pytest.mark.skipif(not REAL_TABLES.is_file(), reason="the IEEE tables are generated locally")
class TestTheRealTables:
    """What the loader makes of the profile itself, where a checkout has it."""

    def test_they_resolve_for_a_der_with_equipment(self):
        composition = Composition(meters=2, der_units=1, inverters=3, batteries=2)
        resolved = load.load(REAL_TABLES, composition)
        for kind in Kind:
            assert any(True for _ in resolved.of(kind)), f"no {kind.value} points"

    def test_every_supports_input_pairs_with_one_enable_output(self):
        resolved = load.load(REAL_TABLES)
        supports = [
            p for p in resolved.of(BI) if p.name.lower().startswith("supports") and p.unit is None
        ]
        assert supports
        assert all(p.enabled_by is not None for p in supports)
        assert len({p.enabled_by for p in supports}) == len(supports)

    def test_the_profile_version_point_carries_the_version(self):
        resolved = load.load(REAL_TABLES)
        assert resolved.point(AI, 0).fixed_value == float(resolved.profile_version)

    def test_the_advertised_starts_agree_with_where_the_blocks_resolve(self):
        resolved = load.load(REAL_TABLES, Composition(meters=1, inverters=1, batteries=1))
        advertised = {p.name: p.fixed_value for p in resolved.of(AI) if p.event_class is None}
        for block in ("Meter", "Inverter", "Battery"):
            first = min(p.index for p in resolved.of(AI) if p.block == block)
            name = next(n for n in advertised if f"({block}-AI)" in n)
            assert advertised[name] == first
