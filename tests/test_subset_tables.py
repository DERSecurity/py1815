"""Every request the subset tables require a Level 2 outstation to parse is answered.

The DNP Users Group publishes the subset definitions as a workbook, updated
by TB2016-003: for each object and variation, which function codes and
qualifiers an outstation of each level shall accept. This test reads that
workbook, takes the rows marked for Level 2, sends each as a request, and
requires that none is refused as an unsupported function or unknown object.

The workbook is the Users Group's and is not in this repository, so the test
skips unless ``PY1815_SUBSET_TABLES`` names a copy. Nothing from it is written
down here: the requests are built from its rows at run time.
"""

from __future__ import annotations

import os
import pathlib
import re

import pytest
from ied_harness import (
    IIN2_BAD_FUNCTION,
    IIN2_OBJECT_UNKNOWN,
    Q_ALL,
    Q_COUNT_8,
    Q_COUNT_16,
    Q_INDEX_8,
    Q_INDEX_16,
    Q_RANGE_8,
    Q_RANGE_16,
    Dut,
    analog_output,
    crob,
    header,
)

from py1815.profile import xlsx

WORKBOOK = os.environ.get("PY1815_SUBSET_TABLES", "")

#: The sheets that describe objects a Level 2 outstation has: inputs, outputs,
#: counters, analogs, time, classes and the internal indications.
SHEETS = ("1-4", "10-13", "20-23", "30-34", "40-43", "50-52", "60", "80")

#: Functions that are never answered, whatever comes of them.
SILENT = {6, 8, 10}


def _required() -> list[tuple[int, int, int, int]]:
    """Every (group, variation, function, qualifier) marked for a Level 2 outstation."""
    book = xlsx.load_workbook(pathlib.Path(WORKBOOK))
    wanted: list[tuple[int, int, int, int]] = []
    for name in SHEETS:
        group = variation = function = None
        requests = False
        for row in book[name].iter_rows():
            cells = ["" if cell is None else str(cell).strip() for cell in row] + [""] * 12
            if cells[0].startswith("Table"):
                requests = "Outstation Subset Requirements - Request" in cells[0]
                group = variation = function = None
                continue
            if cells[0].isdigit():
                group = int(cells[0])
            if re.fullmatch(r"\d+", cells[1]):
                variation = int(cells[1])
            if cells[3][:1].isdigit():
                function = int(cells[3].split()[0])
            if not requests or cells[6] != "2" or None in (group, variation, function):
                continue
            for qualifier in re.findall(r"\b[0-9A-F]{2}\b", cells[4].split("(")[0]):
                wanted.append((group, variation, function, int(qualifier, 16)))
            for extra in re.findall(r"\)\s*((?:[0-9A-F]{2},?\s*)+)\(", cells[4]):
                for qualifier in re.findall(r"[0-9A-F]{2}", extra):
                    wanted.append((group, variation, function, int(qualifier, 16)))
    return sorted(set(wanted))


def _body(group: int, variation: int, qualifier: int) -> bytes:
    """A request body for one row: the header, with data where the function carries it."""
    if group == 12:
        return crob(0, qualifier=qualifier)
    if group == 41:
        return analog_output(0, 5, variation=variation, qualifier=qualifier)
    if group == 50:
        return header(group, variation, Q_COUNT_8, 1) + (1_800_000_000_000).to_bytes(6, "little")
    if group == 80:
        return header(group, variation, qualifier, 7, 7) + b"\x00"
    if qualifier == Q_ALL:
        return header(group, variation)
    if qualifier in (Q_COUNT_8, Q_COUNT_16):
        return header(group, variation, qualifier, 5)
    if qualifier in (Q_RANGE_8, Q_RANGE_16):
        return header(group, variation, qualifier, 0, 1)
    if qualifier in (Q_INDEX_8, Q_INDEX_16):
        # One object named by its index, with no data after it: what an
        # indexed request for anything but a control looks like.
        width = 1 if qualifier == Q_INDEX_8 else 2
        one, first = (1).to_bytes(width, "little"), (0).to_bytes(width, "little")
        return bytes([group, variation, qualifier]) + one + first
    raise AssertionError(f"no request is built for qualifier 0x{qualifier:02X}")


@pytest.mark.parametrize("group", [1, 12, 30, 41, 50, 80])
@pytest.mark.parametrize(
    "qualifier", [Q_ALL, Q_COUNT_8, Q_COUNT_16, Q_RANGE_8, Q_RANGE_16, Q_INDEX_8, Q_INDEX_16]
)
def test_a_request_is_built_for_every_qualifier_the_tables_use(group, qualifier):
    """No row is dropped for want of a body: the test below sends all of them.

    Runs without the workbook, so the guarantee does not depend on a copy
    being present.
    """
    assert _body(group, 1, qualifier)[:2] == bytes([group, 1])


def test_an_indexed_request_names_one_object_and_carries_no_data():
    assert _body(1, 2, Q_INDEX_8) == bytes([1, 2, Q_INDEX_8, 1, 0])
    assert _body(30, 1, Q_INDEX_16) == bytes([30, 1, Q_INDEX_16, 1, 0, 0, 0])


def test_a_qualifier_no_request_is_built_for_is_an_error_not_a_skip():
    with pytest.raises(AssertionError, match="no request is built"):
        _body(1, 2, 0x5B)


@pytest.mark.skipif(not WORKBOOK, reason="PY1815_SUBSET_TABLES does not name the subset workbook")
def test_tb2016_003_every_level_2_request_is_answered():
    required = _required()
    assert len(required) > 30, "the workbook's Level 2 rows were found"
    assert {group for group, *_ in required} >= {1, 2, 10, 12, 20, 21, 22, 30, 32, 40, 41, 50, 60}
    refused = []
    for group, variation, function, qualifier in required:
        dut = Dut(need_time=True)
        dut.toggle(0)
        dut.step(0)
        reply = dut.master.request(function, _body(group, variation, qualifier))
        if function in SILENT:
            if not reply.silent:
                refused.append((group, variation, function, hex(qualifier), "answered"))
            continue
        fragment = reply.fragment
        if fragment.iin2 & (IIN2_BAD_FUNCTION | IIN2_OBJECT_UNKNOWN):
            refused.append((group, variation, function, hex(qualifier), hex(fragment.iin2)))
    assert not refused
