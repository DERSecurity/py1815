"""Load the profile tables and resolve them into a map for one DER.

The tables are a JSON document `py1815.profile.extract` writes from the IEEE
1815.2 companion workbook. This library does not carry them (D36): they are
read from wherever the caller keeps its own copy, and :func:`default_tables`
says where that is unless told otherwise.

Resolution is the one place block arithmetic happens (D37). A point the tables
address relative to an equipment block is repeated once per unit of that
equipment, each at ``block start + unit * block length + offset``; everything
downstream sees absolute indices.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
from typing import Any

from py1815.profile.model import Address, Composition, Kind, MapError, Point, PointMap

#: The environment variable naming the tables file, when it is not in the
#: default place.
TABLES_VARIABLE = "PY1815_TABLES"

#: What the file is called wherever it is kept.
TABLES_NAME = "ieee-1815-2-2025.json"

#: The highest index a DNP3 point can have.
MAX_INDEX = 0xFFFF

_ABSOLUTE = re.compile(r"^(?P<kind>AI|AO|BI|BO|CTR)(?P<index>\d+)$")
_RELATIVE = re.compile(
    r"^(?P<block>[A-Za-z][A-Za-z0-9_]*?)_(?P<kind>AI|AO|BI|BO|CTR)\+(?P<offset>\d+)$"
)

#: An advertisement point names the block and kind whose start it carries in
#: parentheses: ``Functions (Fn-BO) starting index``.
_ADVERTISED_START = re.compile(r"\((?P<symbol>[A-Za-z0-9_]+)-(?P<kind>BO|BI|AO|AI)\)")
#: Or the equipment whose unit count it carries: ``Number of meters (Meter)``.
_ADVERTISED_COUNT = re.compile(r"^Number of .*\((?P<symbol>[A-Za-z_]+)\)\s*$")

#: The advertisement block's symbols for the fixed blocks, against the names
#: the Key sheet's rows are extracted under. The profile lists two schedule
#: blocks under one symbol, told apart by which is "backward compatible".
_FIXED_SYMBOLS = {
    "Base": "configuration",
    "Fn": "functions",
    "Crv": "curves",
    "Mtr": "system_meter",
    "Gap1": "gap_1",
}


def default_tables() -> pathlib.Path:
    """Where the tables are read from when no path is given.

    The environment variable if it is set, otherwise a file under the user's
    home directory. Never a path inside the installed package: the tables are
    the caller's copy of a document this library may not redistribute, and a
    location inside the package is one a packaging step could sweep up.
    """
    named = os.environ.get(TABLES_VARIABLE)
    if named:
        return pathlib.Path(named)
    return pathlib.Path.home() / ".py1815" / TABLES_NAME


def read_tables(path: str | pathlib.Path | None = None) -> dict[str, Any]:
    """The tables document at *path*, or at the default location."""
    where = pathlib.Path(path) if path is not None else default_tables()
    if not where.is_file():
        raise MapError(
            f"no profile tables at {where}. They are generated from the IEEE 1815.2 "
            "companion workbook, which this library does not carry: run "
            "`py1815-der tables fetch`, or `py1815-der tables build <workbook.xlsx>` "
            "with a copy you have downloaded."
        )
    try:
        document = json.loads(where.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise MapError(f"{where} is not a profile tables document: {exc}") from exc
    if not isinstance(document, dict) or "points" not in document or "key" not in document:
        raise MapError(f"{where} is not a profile tables document")
    return document


def load(
    path: str | pathlib.Path | None = None, composition: Composition | None = None
) -> PointMap:
    """Read the tables and resolve them for a DER of the given composition."""
    return resolve(read_tables(path), composition or Composition())


def _block_starts(key: dict[str, Any], composition: Composition) -> dict[str, dict[str, Any]]:
    """Each relative block's symbol, with its start, unit count and unit lengths."""
    blocks: dict[str, dict[str, Any]] = {}
    for component, entry in key.get("equipment", {}).items():
        stated = entry.get("per_unit", {})
        observed = entry.get("per_unit_observed", {})
        # The Key sheet's lengths and the rows disagree in places; a block has
        # to hold every row it is given, so the larger is the length.
        lengths = {
            kind.value: max(int(stated.get(kind.value, 0)), int(observed.get(kind.value, 0)))
            for kind in Kind
        }
        blocks[entry["symbol"]] = {
            "start": int(entry["start"]),
            "units": composition.count(component),
            "lengths": lengths,
            "component": component,
        }
    for name in ("experimental", "vendor"):
        entry = key.get(name)
        if entry:
            blocks[entry["symbol"]] = {
                "start": int(entry["start"]),
                "units": 1,
                "lengths": dict.fromkeys((kind.value for kind in Kind), 0),
                "component": None,
            }
    return blocks


def _reference(
    text: str | None, blocks: dict[str, dict[str, Any]], unit: int | None
) -> Address | None:
    """A paired-point reference as an address, for the unit that holds it."""
    if not text:
        return None
    absolute = _ABSOLUTE.match(text)
    if absolute:
        return (Kind(absolute.group("kind")), int(absolute.group("index")))
    relative = _RELATIVE.match(text)
    if relative and relative.group("block") in blocks:
        block = blocks[relative.group("block")]
        kind = Kind(relative.group("kind"))
        position = (unit or 1) - 1
        return (
            kind,
            block["start"]
            + position * block["lengths"][kind.value]
            + int(relative.group("offset")),
        )
    # A reference in a spelling nobody recognized is kept out of the map rather
    # than guessed at: an unpaired point is served without a mirror, which is
    # visible, where a wrong pairing would be a point reporting another's value.
    return None


def _advertised(row: dict[str, Any], key: dict[str, Any], composition: Composition) -> float | None:
    """What an advertisement point carries, or None where the Key has no answer."""
    name = row["name"]
    count = _ADVERTISED_COUNT.match(name)
    if count:
        for component, entry in key.get("equipment", {}).items():
            if entry["symbol"] == count.group("symbol"):
                return float(composition.count(component))
        return None
    start = _ADVERTISED_START.search(name)
    if not start:
        return None
    symbol, kind = start.group("symbol"), start.group("kind")
    fixed = key.get("fixed", {})
    if symbol == "Sch":
        which = "schedules_2" if "backward" in name.lower() else "schedules_4"
        value = fixed.get(which, {}).get(kind)
        return None if value is None else float(value)
    if symbol in _FIXED_SYMBOLS:
        value = fixed.get(_FIXED_SYMBOLS[symbol], {}).get(kind)
        return None if value is None else float(value)
    for entry in key.get("equipment", {}).values():
        if entry["symbol"] == symbol:
            lengths = entry.get("per_unit_observed", {}) or entry.get("per_unit", {})
            return float(entry["start"]) if lengths.get(kind) else None
    for name_ in ("experimental", "vendor"):
        entry = key.get(name_, {})
        # The advertisement block abbreviates the vendor block's symbol.
        if entry and symbol in (entry.get("symbol"), "Ven" if name_ == "vendor" else None):
            return float(entry["start"])
    return None


def _fixed_value(row: dict[str, Any]) -> float | None:
    """The value the tables fix for a point, where its Value column is a number."""
    text = row.get("value")
    if text is None:
        return None
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def _point(
    kind: Kind,
    index: int,
    row: dict[str, Any],
    *,
    blocks: dict[str, dict[str, Any]],
    unit: int | None,
    fixed_value: float | None,
    advertised: bool = False,
) -> Point:
    name = row["name"]
    if unit is not None:
        # The tables name every equipment point for unit #1 and say the rest
        # repeat it; the name follows the unit so two inverters do not share one.
        name = name.replace("#1", f"#{unit}")
    multiplier = row.get("multiplier")
    return Point(
        kind=kind,
        index=index,
        name=name,
        section=row.get("section"),
        purpose=row.get("purpose"),
        event_class=_event_class(row, advertised),
        mandatory=bool(row.get("mandatory_1815_2")),
        multiplier=None if multiplier is None else float(multiplier),
        offset=float(row.get("offset_value") or 0.0),
        minimum=row.get("minimum"),
        maximum=row.get("maximum"),
        units=row.get("units"),
        associated=_reference(row.get("associated"), blocks, unit),
        block=row.get("block"),
        unit=unit,
        fixed_value=fixed_value,
        frozen=bool(row.get("frozen")),
        frozen_event_class=row.get("frozen_event_class"),
    )


def _event_class(row: dict[str, Any], advertised: bool) -> int | None:
    """The class a point reports in, with a blank cell read as "static only".

    The profile leaves exactly one set of points out of class 0: the block
    advertisement. Everywhere else a blank class cell is a point with no
    event class -- a counter, which reports through its frozen twin, or a row
    the tables simply left empty -- and such a point is still part of an
    integrity poll.
    """
    if advertised:
        return None
    stated = row.get("event_class")
    return int(stated) if stated in (0, 1, 2, 3) else 0


def _pair_supports(points: dict[Address, Point]) -> None:
    """Tie each "supports" input to the output that enables its function.

    The tables pair the two by purpose: one binary input says whether a
    function is supported, and one binary output of the same purpose enables
    it. A supports input with no single such output is left unpaired, and is
    then served only if the caller binds it.
    """
    enables: dict[tuple[str | None, str | None, int | None], list[Address]] = {}
    for point in points.values():
        if point.kind is Kind.BO and point.name.lower().startswith("enable"):
            enables.setdefault((point.purpose, point.block, point.unit), []).append(point.address)
    for address, point in list(points.items()):
        if point.kind is not Kind.BI or not point.name.lower().startswith("supports"):
            continue
        candidates = enables.get((point.purpose, point.block, point.unit), [])
        if len(candidates) == 1:
            points[address] = _replace(point, enabled_by=candidates[0])


def _replace(point: Point, **changes: Any) -> Point:
    values = {name: getattr(point, name) for name in point.__dataclass_fields__}
    values.update(changes)
    return Point(**values)


def resolve(document: dict[str, Any], composition: Composition) -> PointMap:
    """The tables as a flat map of absolute indices for one composition."""
    key = document["key"]
    blocks = _block_starts(key, composition)
    advertisement = document.get("index_points") or {}
    first_advertised = int(advertisement.get("first", MAX_INDEX + 1))
    last_advertised = first_advertised + int(advertisement.get("count", 0)) - 1

    points: dict[Address, Point] = {}

    def add(point: Point, row: dict[str, Any]) -> None:
        if not 0 <= point.index <= MAX_INDEX:
            raise MapError(
                f"{point.kind.value} {row['name']!r} resolves to index {point.index}, "
                f"outside 0..{MAX_INDEX}"
            )
        if point.address in points:
            raise MapError(
                f"{point.kind.value}{point.index} is claimed twice: by "
                f"{points[point.address].name!r} and by {point.name!r}"
            )
        points[point.address] = point

    for kind in Kind:
        for row in document["points"].get(kind.value, []):
            if row.get("index") is not None:
                index = int(row["index"])
                advertised = kind is Kind.AI and first_advertised <= index <= last_advertised
                fixed = _advertised(row, key, composition) if advertised else _fixed_value(row)
                if advertised and fixed is None:
                    # Nothing to advertise for this block and kind, so the
                    # point is not served rather than served as a zero that
                    # would read as "starts at index 0".
                    continue
                add(
                    _point(
                        kind,
                        index,
                        row,
                        blocks=blocks,
                        unit=None,
                        fixed_value=fixed,
                        advertised=advertised,
                    ),
                    row,
                )
                continue
            block = blocks.get(row.get("block"))
            if block is None:
                raise MapError(f"{kind.value} {row['name']!r} names an unknown block")
            repeating = block["component"] is not None
            for position in range(block["units"]):
                index = (
                    block["start"] + position * block["lengths"][kind.value] + int(row["offset"])
                )
                add(
                    _point(
                        kind,
                        index,
                        row,
                        blocks=blocks,
                        unit=position + 1 if repeating else None,
                        fixed_value=None,
                    ),
                    row,
                )

    _pair_supports(points)
    return PointMap(
        points=points,
        composition=composition,
        edition=str(document.get("edition", "")),
        profile_version=(document.get("source") or {}).get("profile_version"),
    )
