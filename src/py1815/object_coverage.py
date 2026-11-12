"""Report which object groups and variations this library serves, accepts and reads.

For every variation :mod:`py1815.catalog` names, the report says three things:

``served``
    the outstation can put the object in a response;
``requested``
    the outstation accepts the object in a request, as the header of a read, the
    body of a write or a control, or a class object;
``parsed``
    the master reads the object out of a response.

The answers are read from the tables the code itself uses, so the report
changes when the code does and nothing here is counted by hand: the outstation's
variation tables, the session's event tables, the master's object layouts and
the control parser. A variation that no table mentions is reported as
supported by none.

The marks cover every subset level and setting the tables hold: an object that
only a Level 3 or Level 4 outstation serves or accepts is marked as served or
requested, so a mark says the library can do it, not that every configuration
does. A read that is answered in another variation marks the variation read as
requested and the variation sent as served.

The subset level at which a variation is required comes from the DNP Users
Group's subset tables, which this repository does not carry. Name a copy with
``--subset-tables`` or ``PY1815_SUBSET_TABLES`` and the report adds the column,
read at run time; without one the column is left out.

Run it as ``python -m py1815.object_coverage``.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

# The report reads the module-level tables that the outstation, the session and
# the master keep for themselves, which is the point of it.
# pylint: disable=protected-access

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass

from py1815 import catalog, control, decode, session
from py1815.application import CLASS_GROUP, CLASS_VARIATIONS
from py1815.objects import (
    COMMON_TIME_SYNCHRONIZED,
    COMMON_TIME_UNSYNCHRONIZED,
    GROUP_COMMON_TIME,
)
from py1815.profile import outstation, xlsx

Key = tuple[int, int | None]

#: The environment variable the subset-table tests also read.
SUBSET_TABLES_ENV = "PY1815_SUBSET_TABLES"


@dataclass(frozen=True)
class Coverage:
    """What this library does with one object variation."""

    group: int
    #: The variation number, or None for a group that gives none of its own.
    variation: int | None
    name: str
    served: bool
    requested: bool
    parsed: bool
    #: The lowest DNP3 subset level that requires the object, or None when the
    #: subset tables were not given or do not list it.
    level: int | None = None


def _widened() -> tuple[dict[int, dict[int, int]], ...]:
    """Return the outstation's tables of reads answered in another variation, at every level."""
    return (
        outstation._WIDENED_VARIATIONS,
        outstation._LEVEL_3_WIDENED,
        outstation._LEVEL_4_WIDENED,
    )


def _controls() -> set[Key]:
    """The control objects the outstation reads, and echoes in its answer."""
    return {
        (item.group, item.variation)
        for item in catalog.objects()
        if item.variation is not None
        and control.object_size(item.group, item.variation) is not None
    }


def served() -> set[Key]:
    """Every object the outstation can put in a response."""
    found: set[Key] = set()
    found.update(outstation._DEFAULT_VARIATIONS.items())
    found.update(outstation._LEVEL_2_VARIATIONS.items())
    for table in (outstation._SERVED_VARIATIONS, outstation._LEVEL_4_VARIATIONS):
        for group, variations in table.items():
            found.update((group, variation) for variation in variations)
    for widened in _widened():
        for group, answers in widened.items():
            found.update((group, variation) for variation in answers.values())
    found.update(session._EVENT_SIZES)
    for group, answers in session._WIDENED_EVENT_VARIATIONS.items():
        found.update((group, variation) for variation in answers.values())
    found.update(session._OWN_OBJECTS)
    found.add((session.TIME_DELAY_GROUP, session.TIME_DELAY_FINE_VARIATION))
    found.update(
        (GROUP_COMMON_TIME, variation)
        for variation in (COMMON_TIME_SYNCHRONIZED, COMMON_TIME_UNSYNCHRONIZED)
    )
    return found | _controls()


def requested() -> set[Key]:
    """Every object the outstation accepts in a request."""
    found: set[Key] = set()
    found.update(outstation._DEFAULT_VARIATIONS.items())
    found.update(outstation._LEVEL_2_VARIATIONS.items())
    for table in (outstation._SERVED_VARIATIONS, outstation._LEVEL_4_VARIATIONS):
        for group, variations in table.items():
            found.update((group, variation) for variation in variations)
    for widened in _widened():
        for group, answers in widened.items():
            found.update((group, variation) for variation in answers)
    for event_table in (session._EVENT_VARIATIONS, session._EXTENDED_EVENT_VARIATIONS):
        for group, named in event_table.items():
            found.update((group, variation) for variation in named if variation)
    for group, answers in session._WIDENED_EVENT_VARIATIONS.items():
        found.update((group, variation) for variation in answers)
    found.update(session._OWN_OBJECTS)
    found.update((CLASS_GROUP, variation) for variation in CLASS_VARIATIONS)
    # The writes a session honors: the clock, and the restart indication.
    found.add((session.TIME_GROUP, session.TIME_VARIATION))
    found.add((session.TIME_GROUP, session.LAST_RECORDED_TIME_VARIATION))
    found.add((session.RESTART_GROUP, session.RESTART_VARIATION))
    return found | _controls()


def parsed() -> set[Key]:
    """Every object the master reads out of a response."""
    return set(decode.LAYOUTS) | _controls()


def subset_levels(path: pathlib.Path) -> dict[Key, int]:
    """The lowest subset level at which each variation appears in the subset tables.

    Reads the workbook as the subset-table tests do. A row lists a function code
    and its qualifiers, and the levels that require them are marked in four
    columns; the object it belongs to is named by the nearest row above that
    gives a group and a variation. Variation 0, "any variation", names no object.
    """
    book = xlsx.load_workbook(path)
    levels: dict[Key, int] = {}
    for name in book.sheetnames:
        group: int | None = None
        variation: int | None = None
        for row in book[name].iter_rows():
            cells = ["" if cell is None else str(cell).strip() for cell in row] + [""] * 12
            if cells[0].startswith("Table"):
                group = variation = None
                continue
            if cells[0].isdigit():
                group = int(cells[0])
            if re.fullmatch(r"\d+", cells[1]):
                variation = int(cells[1])
            marks = [int(cell) for cell in cells[5:9] if cell in {"1", "2", "3", "4"}]
            if group is None or not variation or not marks:
                continue
            key = (group, variation)
            levels[key] = min(levels.get(key, 4), *marks)
    return levels


def coverage(levels: dict[Key, int] | None = None) -> list[Coverage]:
    """One entry for every variation of every group in the catalog."""
    can_serve, accepts, reads = served(), requested(), parsed()
    return [
        Coverage(
            item.group,
            item.variation,
            item.name,
            served=(item.group, item.variation) in can_serve,
            requested=(item.group, item.variation) in accepts,
            parsed=(item.group, item.variation) in reads,
            level=None if levels is None else levels.get((item.group, item.variation)),
        )
        for item in catalog.objects()
    ]


def format_report(rows: Sequence[Coverage], *, with_levels: bool = False) -> str:
    """The report as text: a heading for each group and a line for each variation."""
    lines: list[str] = []
    for group in catalog.GROUPS.values():
        mine = [row for row in rows if row.group == group.number]
        if not mine:
            continue
        counts = ", ".join(
            f"{label} {sum(getattr(row, label) for row in mine)} of {len(mine)}"
            for label in ("served", "requested", "parsed")
        )
        lines.append(f"Group {group.number}: {group.name} ({counts})")
        for row in mine:
            number = "all" if row.variation is None else str(row.variation)
            marks = "  ".join(
                f"{'yes' if getattr(row, label) else '-':3}"
                for label in ("served", "requested", "parsed")
            )
            level = ""
            if with_levels:
                level = f"  L{row.level}" if row.level is not None else "  -"
            lines.append(f"  {number:>4}  {marks}{level}  {row.name}")
        lines.append("")
    header = "served  requested  parsed" + ("  level" if with_levels else "")
    return f"Columns, left to right: {header}\n\n" + "\n".join(lines).rstrip() + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    """Print the report; return 0, or 2 when the subset tables cannot be read."""
    parser = argparse.ArgumentParser(
        prog="python -m py1815.object_coverage",
        description="Report which IEEE 1815-2012 objects this library serves, accepts and reads.",
    )
    parser.add_argument(
        "--subset-tables",
        type=pathlib.Path,
        default=os.environ.get(SUBSET_TABLES_ENV) or None,
        metavar="WORKBOOK",
        help=f"your copy of the DNP Users Group subset tables, to add the level column "
        f"(default: ${SUBSET_TABLES_ENV})",
    )
    parser.add_argument("--json", action="store_true", help="print the rows as JSON")
    args = parser.parse_args(argv)

    levels = None
    if args.subset_tables is not None:
        try:
            levels = subset_levels(args.subset_tables)
        except (OSError, xlsx.WorkbookError) as error:
            print(f"cannot read the subset tables: {error}", file=sys.stderr)
            return 2
    rows = coverage(levels)
    if args.json:
        print(json.dumps([asdict(row) for row in rows], indent=2))
    else:
        print(format_report(rows, with_levels=levels is not None), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
