"""The object catalog, and the report of what the library does with each object.

``test_conformance.py`` holds the catalog to Annex A of the standard. These tests
hold the rest of the library to the catalog: the group constants, the variation
enums, the master's object layouts and the sizes the encoders use must all agree
with it, and the coverage report must follow the tables it reads.
"""

from __future__ import annotations

import json
import pathlib
from enum import IntEnum

import pytest

from py1815 import attributes, catalog, control, decode, object_coverage, objects, session
from py1815.application import CLASS_GROUP
from py1815.catalog import ALL, ObjectKind, SizeKind
from py1815.profile import xlsx

# ------------------------------------------------------------ the catalog itself


def test_a_known_variation_has_the_standards_number_name_and_size() -> None:
    # Group 30 variation 5 is the single-precision analog input: a flag octet and a
    # four-octet value.
    item = catalog.find(30, 5)
    assert item is not None
    assert item.name == "Analog input - single-precision, floating-point with flag"
    assert item.kind is ObjectKind.STATIC
    assert item.size == catalog.fixed(5)
    assert item.size.octets == 5
    assert item.size.bits is None


def test_a_packed_variation_gives_its_bits_and_no_octets() -> None:
    # Group 1 variation 1 is one bit per point; group 3 variation 1 is two.
    one, two = catalog.find(1, 1), catalog.find(3, 1)
    assert one is not None and two is not None
    assert (one.size.kind, one.size.bits, one.size.octets) == (SizeKind.PACKED, 1, None)
    assert (two.size.kind, two.size.bits) == (SizeKind.PACKED, 2)


def test_a_variable_size_object_has_no_fixed_size() -> None:
    # Group 110 is an octet string whose variation is its length.
    item = catalog.find(110, ALL)
    assert item is not None
    assert item.size == catalog.VARIABLE
    assert item.size.octets is None


def test_a_variation_the_standard_does_not_define_is_not_found() -> None:
    assert catalog.find(30, 7) is None
    assert catalog.find(30, 0) is None
    assert catalog.find(999, 1) is None


def test_no_two_variations_share_a_name_within_a_group() -> None:
    for group in catalog.GROUPS.values():
        names = [item.name for item in group.variations.values()]
        assert len(names) == len(set(names)), f"group {group.number} repeats a name"


# ------------------------------------------- the rest of the library against it

#: The group constants the library declares, with the name Annex A gives the group.
GROUP_CONSTANTS = {
    (attributes, "GROUP_DEVICE_ATTRIBUTES"): (0, "device attributes"),
    (decode, "GROUP_DEVICE_ATTRIBUTES"): (0, "device attributes"),
    (objects, "GROUP_BINARY_INPUT"): (1, "binary inputs"),
    (objects, "GROUP_BINARY_INPUT_EVENT"): (2, "binary input events"),
    (objects, "GROUP_DOUBLE_BIT_INPUT"): (3, "double-bit binary inputs"),
    (objects, "GROUP_DOUBLE_BIT_INPUT_EVENT"): (4, "double-bit binary input events"),
    (objects, "GROUP_COUNTER"): (20, "counters"),
    (objects, "GROUP_FROZEN_COUNTER"): (21, "frozen counters"),
    (objects, "GROUP_COUNTER_EVENT"): (22, "counter events"),
    (objects, "GROUP_FROZEN_COUNTER_EVENT"): (23, "frozen counter events"),
    (objects, "GROUP_ANALOG_INPUT"): (30, "analog inputs"),
    (objects, "GROUP_ANALOG_INPUT_EVENT"): (32, "analog input events"),
    (objects, "GROUP_ANALOG_DEADBAND"): (34, "analog input reporting deadbands"),
    (objects, "GROUP_COMMON_TIME"): (51, "time and date common time-of-occurrences"),
    (control, "GROUP_BINARY_OUTPUT_STATUS"): (10, "binary outputs"),
    (control, "GROUP_BINARY_OUTPUT_EVENT"): (11, "binary output events"),
    (control, "GROUP_BINARY_OUTPUT_COMMAND"): (12, "binary output commands"),
    (control, "GROUP_BINARY_OUTPUT_COMMAND_EVENT"): (13, "binary output command events"),
    (control, "GROUP_ANALOG_OUTPUT_STATUS"): (40, "analog output status"),
    (control, "GROUP_ANALOG_OUTPUT_COMMAND"): (41, "analog outputs"),
    (control, "GROUP_ANALOG_OUTPUT_EVENT"): (42, "analog output events"),
    (control, "GROUP_ANALOG_OUTPUT_COMMAND_EVENT"): (43, "analog output command events"),
    (decode, "GROUP_TIME"): (50, "time and date"),
    (decode, "GROUP_COMMON_TIME"): (51, "time and date common time-of-occurrences"),
    (decode, "GROUP_TIME_DELAY"): (52, "time delays"),
    (session, "TIME_GROUP"): (50, "time and date"),
    (session, "TIME_DELAY_GROUP"): (52, "time delays"),
    (session, "RESTART_GROUP"): (80, "internal indications"),
}


@pytest.mark.parametrize(("module", "name"), sorted(GROUP_CONSTANTS, key=str), ids=str)
def test_a_group_constant_is_the_number_annex_a_gives_that_group(module: object, name: str) -> None:
    number, title = GROUP_CONSTANTS[(module, name)]
    assert getattr(module, name) == number
    assert catalog.GROUPS[number].name == title


def test_the_class_group_is_the_class_objects_group() -> None:
    assert CLASS_GROUP == 60
    assert catalog.GROUPS[CLASS_GROUP].name == "class objects"


@pytest.mark.parametrize(
    ("module", "wanted"),
    [
        (objects, set(GROUP_CONSTANTS)),
        (control, set(GROUP_CONSTANTS)),
        (decode, set(GROUP_CONSTANTS)),
        (attributes, set(GROUP_CONSTANTS)),
    ],
    ids=["objects", "control", "decode", "attributes"],
)
def test_every_group_constant_in_a_module_is_checked_here(module: object, wanted: set) -> None:
    """A new ``GROUP_*`` constant fails until it is added to the table above."""
    declared = {
        (module, name)
        for name in vars(module)
        if name.startswith("GROUP_") and isinstance(getattr(module, name), int)
    }
    assert declared <= wanted, f"unchecked constants: {sorted(map(str, declared - wanted))}"


#: Each variation enum, the group it belongs to and the standard's kind for it.
VARIATION_ENUMS: list[tuple[type[IntEnum], int]] = [
    (objects.AnalogVariation, 30),
    (objects.BinaryVariation, 1),
    (objects.AnalogEventVariation, 32),
    (objects.BinaryEventVariation, 2),
    (objects.FrozenCounterVariation, 21),
    (objects.DoubleBitVariation, 3),
    (objects.DoubleBitEventVariation, 4),
]


@pytest.mark.parametrize(("enum", "group"), VARIATION_ENUMS, ids=lambda x: str(x))
def test_every_variation_enum_member_names_a_variation_in_the_catalog(
    enum: type[IntEnum], group: int
) -> None:
    for member in enum:
        assert catalog.find(group, int(member)) is not None, f"{enum.__name__}.{member.name}"


def test_the_analog_variation_names_describe_the_catalog_entries() -> None:
    """Pin the meaning of each analog member, which a rename or renumber would change."""
    expected = {
        objects.AnalogVariation.INT32_WITH_FLAG: (1, 5),
        objects.AnalogVariation.INT16_WITH_FLAG: (2, 3),
        objects.AnalogVariation.INT32: (3, 4),
        objects.AnalogVariation.INT16: (4, 2),
        objects.AnalogVariation.FLOAT32_WITH_FLAG: (5, 5),
    }
    for member, (variation, octets) in expected.items():
        item = catalog.find(30, int(member))
        assert item is not None
        assert int(member) == variation
        assert item.size.octets == octets


def test_the_event_sizes_the_encoders_use_are_the_catalog_sizes() -> None:
    for variation, size in objects.ANALOG_EVENT_SIZES.items():
        item = catalog.find(32, int(variation))
        assert item is not None and item.size.octets == size, variation
    for (group, variation), size in session._EVENT_SIZES.items():  # pylint: disable=protected-access
        item = catalog.find(group, variation)
        assert item is not None and item.size.octets == size, (group, variation)


def test_the_deadband_sizes_are_the_catalog_sizes() -> None:
    for variation, size in objects.DEADBAND_SIZES.items():
        item = catalog.find(objects.GROUP_ANALOG_DEADBAND, variation)
        assert item is not None and item.size.octets == size, variation


def test_a_widened_event_read_is_sized_by_the_variation_sent() -> None:
    """The event sizes are keyed by the variation sent, never by the one read."""
    widened = session._WIDENED_EVENT_VARIATIONS  # pylint: disable=protected-access
    sizes = session._EVENT_SIZES  # pylint: disable=protected-access
    assert widened == {22: {2: 1}, 23: {2: 1, 6: 5}}
    for group, answers in widened.items():
        for read, sent in answers.items():
            assert (group, sent) in sizes
            assert (group, read) not in sizes


def test_the_control_object_widths_are_the_catalog_sizes() -> None:
    crob = catalog.find(12, 1)
    assert crob is not None and crob.size.octets == control.CROB_SIZE
    for variation in range(1, 5):
        item = catalog.find(41, variation)
        assert item is not None
        assert control.object_size(41, variation) == item.size.octets


def test_every_object_layout_the_master_reads_has_the_catalog_size() -> None:
    for (group, variation), layout in decode.LAYOUTS.items():
        item = catalog.find(group, variation)
        assert item is not None, (group, variation)
        if layout.packed:
            # Two bits a point for a double-bit input (IEEE 1815-2012 A.4.1).
            bits = 2 if layout.double_bit else 1
            assert item.size == catalog.packed(bits), (group, variation)
        else:
            assert item.size.octets == layout.size, (group, variation)


# ------------------------------------------------------------ the coverage report


def _row(group: int, variation: int | None) -> object_coverage.Coverage:
    found = [r for r in object_coverage.coverage() if (r.group, r.variation) == (group, variation)]
    assert len(found) == 1
    return found[0]


def test_the_report_has_a_row_for_every_variation_in_the_catalog() -> None:
    rows = object_coverage.coverage()
    assert [(r.group, r.variation) for r in rows] == [
        (item.group, item.variation) for item in catalog.objects()
    ]


def test_every_object_a_table_mentions_is_in_the_catalog() -> None:
    """A group or variation in a table that the standard does not define is a typo."""
    known = {(item.group, item.variation) for item in catalog.objects()}
    for found in (
        object_coverage.served(),
        object_coverage.requested(),
        object_coverage.parsed(),
    ):
        assert found <= known, sorted(found - known)


def test_a_variation_served_requested_and_read_is_reported_as_all_three() -> None:
    # The 32-bit analog input with a flag is the profile's default.
    row = _row(30, 1)
    assert (row.served, row.requested, row.parsed) == (True, True, True)


def test_a_variation_only_the_master_reads_is_not_served() -> None:
    # The double-precision analog input is in the master's layouts and not in
    # the outstation's tables.
    row = _row(30, 6)
    assert (row.served, row.requested, row.parsed) == (False, False, True)


def test_a_variation_the_outstation_widens_is_accepted_and_not_served() -> None:
    # A request for the 16-bit counter is answered in the 32-bit variation.
    row = _row(20, 2)
    assert (row.served, row.requested) == (False, True)


def test_a_widened_event_variation_is_accepted_and_not_served() -> None:
    # Reads of the 16-bit counter and frozen counter events are answered in 32 bits.
    for group in (22, 23):
        assert (_row(group, 2).served, _row(group, 2).requested) == (False, True)
        assert (_row(group, 1).served, _row(group, 1).requested) == (True, True)


def test_a_read_only_level_3_accepts_is_reported() -> None:
    # Level 3 answers a packed binary input read with flags.
    assert (_row(1, 1).served, _row(1, 1).requested) == (False, True)


def test_the_time_and_the_indications_the_session_answers_are_served() -> None:
    for group in (50, 80):
        assert (_row(group, 1).served, _row(group, 1).requested) == (True, True)


def test_the_report_follows_the_session_event_tables(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _row(23, 2).requested
    monkeypatch.setattr(session, "_WIDENED_EVENT_VARIATIONS", {22: {2: 1}})
    assert not _row(23, 2).requested


def test_the_output_event_reads_are_accepted() -> None:
    # Group 11 and 42 events are reported; group 13 and 43 reads are answered
    # with nothing, because command events are not generated (D116).
    for group, variation in ((11, 1), (42, 5)):
        assert (_row(group, variation).served, _row(group, variation).requested) == (True, True)
    assert (_row(13, 1).served, _row(13, 1).requested) == (False, True)
    assert not _row(42, 6).requested


def test_a_class_object_is_accepted_in_a_request_and_never_served() -> None:
    row = _row(60, 2)
    assert (row.served, row.requested, row.parsed) == (False, True, False)


def test_a_write_the_session_honors_is_accepted() -> None:
    assert _row(50, 1).requested
    assert _row(80, 1).requested


def test_a_control_object_is_served_requested_and_read() -> None:
    row = _row(12, 1)
    assert (row.served, row.requested, row.parsed) == (True, True, True)


def test_an_object_in_no_table_is_supported_by_none() -> None:
    row = _row(120, 1)
    assert (row.served, row.requested, row.parsed) == (False, False, False)


def test_the_report_follows_the_master_layouts(monkeypatch: pytest.MonkeyPatch) -> None:
    """The report is read from the tables, not written down."""
    assert _row(30, 1).parsed
    monkeypatch.setattr(
        decode, "LAYOUTS", {k: v for k, v in decode.LAYOUTS.items() if k != (30, 1)}
    )
    assert not _row(30, 1).parsed


def test_the_report_follows_the_outstation_tables(monkeypatch: pytest.MonkeyPatch) -> None:
    assert (_row(30, 6).served, _row(30, 6).requested) == (False, False)
    served = object_coverage.outstation._SERVED_VARIATIONS  # pylint: disable=protected-access
    monkeypatch.setitem(served, 30, served[30] | {6})
    row = _row(30, 6)
    assert (row.served, row.requested) == (True, True)


def test_the_level_4_objects_are_reported() -> None:
    # Floating point, the deadbands and the time-stamped 16-bit frozen counters,
    # which are read and answered in 32 bits.
    for group, variation in ((30, 5), (40, 3), (32, 5), (32, 7), (34, 1), (34, 2), (34, 3)):
        row = _row(group, variation)
        assert (row.served, row.requested) == (True, True), (group, variation)
    for group in (21, 23):
        assert (_row(group, 6).served, _row(group, 6).requested) == (False, True)


def test_the_text_report_names_every_group_and_marks_each_column() -> None:
    text = object_coverage.format_report(object_coverage.coverage())
    for group in catalog.GROUPS.values():
        assert f"Group {group.number}: {group.name} (" in text
    assert "     2  yes  yes  yes  Binary input - with flags" in text
    assert "     1  -    yes  yes  Binary input - packed format" in text


# ---------------------------------------------------------- the subset-level column


def _subset_workbook() -> xlsx.Workbook:
    """A small workbook shaped like the subset tables, with invented levels."""

    def row(*cells: str) -> dict[int, str]:
        return {column: value for column, value in enumerate(cells, start=1) if value}

    rows = {
        1: row("Table 12-3: Outstation Subset Requirements - Request - Group 1 objects"),
        2: row("1", "0", "Any variation", "1 (READ)", "06", "", "2", "3", "4"),
        3: row("1", "2", "With flags", "1 (READ)", "06", "", "", "3", "4"),
        4: row("", "", "", "", "00, 01", "", "", "", "4"),
        5: row("Table 12-4: Master/Outstation Subset Requirements - Response"),
        6: row("1", "2", "With flags", "129", "00, 01", "1", "2", "3", "4"),
        7: row("1", "1", "Packed format", "129", "00, 01", "", "", "", "4"),
        8: row("Table 12-5: Request - Group 2 objects"),
        9: row("", "", "", "", "00, 01", "", "", "", "4"),
    }
    return xlsx.Workbook({"1-4": xlsx.Sheet(rows)})


def test_the_subset_level_is_the_lowest_level_marked_for_the_variation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(xlsx, "load_workbook", lambda path: _subset_workbook())
    levels = object_coverage.subset_levels(pathlib.Path("tables.xlsx"))
    # Level 3 in the request row, level 1 in the response row.
    assert levels[(1, 2)] == 1
    assert levels[(1, 1)] == 4
    # Variation 0 names no object, and a row under a table heading names no object either.
    assert (1, 0) not in levels
    assert set(levels) == {(1, 1), (1, 2)}


def test_the_level_column_is_left_blank_without_the_tables() -> None:
    assert all(row.level is None for row in object_coverage.coverage())
    assert "level" not in object_coverage.format_report(object_coverage.coverage())


def test_the_level_column_comes_from_the_tables_given(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = object_coverage.coverage({(1, 2): 1})
    assert {(r.group, r.variation): r.level for r in rows if r.group == 1} == {
        (1, 1): None,
        (1, 2): 1,
    }
    text = object_coverage.format_report(rows, with_levels=True)
    assert "L1  Binary input - with flags" in text


# --------------------------------------------------------------------- the command


def test_the_command_prints_the_report(capsys: pytest.CaptureFixture[str]) -> None:
    assert object_coverage.main([]) == 0
    assert "Group 30: analog inputs" in capsys.readouterr().out


def test_the_command_prints_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert object_coverage.main(["--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == len(list(catalog.objects()))
    assert {"group", "variation", "served", "requested", "parsed", "level"} <= set(rows[0])


def test_the_command_refuses_subset_tables_it_cannot_read(
    capsys: pytest.CaptureFixture[str], tmp_path: pathlib.Path
) -> None:
    assert object_coverage.main(["--subset-tables", str(tmp_path / "missing.xlsx")]) == 2
    assert "cannot read the subset tables" in capsys.readouterr().err
