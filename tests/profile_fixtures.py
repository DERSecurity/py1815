"""Synthetic profile tables for the tests.

The IEEE 1815.2 tables may not be redistributed, so the repository carries
none and CI has none. What the profile machinery needs to be tested against is
a document of the same shape, and that is all these are: points invented here,
at indices and with names chosen to be obviously nobody's, in the form
`py1815.profile.extract` writes.
"""

from __future__ import annotations

import pathlib
from typing import Any

from py1815.profile.binding import Binding
from py1815.profile.der import ReferenceDer
from py1815.profile.model import Composition, Kind, PointMap

#: Where a checkout that has regenerated the real tables keeps them. Tests
#: that need the real thing skip when it is absent, which is the expected
#: state everywhere but a machine that has downloaded the workbook.
REAL_TABLES = (
    pathlib.Path(__file__).resolve().parent.parent / "conformance" / "ieee-1815-2-2025.json"
)


def row(name: str, index: int | None = None, **fields: Any) -> dict[str, Any]:
    """One point row. Relative rows give ``block`` and ``offset`` instead of an index."""
    base: dict[str, Any] = {
        "index": index,
        "block": None,
        "offset": None,
        "name": name,
        "section": "Synthetic",
        "purpose": None,
        "mandatory_1815_2": False,
        "mandatory_1547": False,
    }
    base.update(fields)
    return base


def analog(name: str, index: int | None = None, **fields: Any) -> dict[str, Any]:
    """An analog row, with the scaling columns an analog sheet carries."""
    defaults = {"minimum": None, "maximum": None, "multiplier": 1, "offset_value": 0, "units": "x"}
    return row(name, index, **{**defaults, **fields})


def document(points: dict[str, list[dict[str, Any]]], **key: Any) -> dict[str, Any]:
    """A tables document around the given rows."""
    return {
        "edition": "synthetic",
        "generated_by": "tests",
        "source": {"profile_version": "0.0"},
        "key": {
            "fixed": key.get("fixed", {}),
            "equipment": key.get("equipment", {}),
            "experimental": key.get("experimental"),
            "vendor": key.get("vendor"),
            "maximum_index": 65535,
        },
        "index_points": key.get("index_points", {"first": 65000, "count": 0}),
        "points": {kind.value: points.get(kind.value, []) for kind in Kind},
    }


def small() -> dict[str, Any]:
    """A dozen points across every kind, with one repeating block and one function."""
    return document(
        {
            "BI": [
                row("Alarm", 0, event_class=1, mandatory_1815_2=True),
                row("Supports Widget Mode", 1, event_class=0, purpose="Widget"),
                row("Widget Enabled", 2, event_class=2, purpose="Widget", associated="BO0"),
                row("Lone flag", 9, event_class=2),
                row("Unit #1 fault", block="Unit", offset=0, event_class=1),
            ],
            "BO": [
                row("Enable Widget Mode", 0, purpose="Widget", associated="BI2"),
                row("Unpaired switch", 1),
            ],
            "AI": [
                analog("Version", 0, event_class=3, value="2.5", multiplier=0.1),
                analog("Power", 1, event_class=3, mandatory_1815_2=True, units="W"),
                analog("Voltage", 2, event_class=2, multiplier=0.1, minimum=0, maximum=6000),
                analog("Setpoint readback", 3, event_class=2, multiplier=0.1, associated="AO0"),
                analog("Blank class", 4),
                analog("Unit #1 power", block="Unit", offset=0, event_class=3),
                analog(
                    "Unit #1 limit", block="Unit", offset=1, event_class=2, associated="Unit_AO+0"
                ),
                analog("Gadgets (Unit-AI) starting index", 65000),
                analog("Number of gadgets (Unit)", 65001),
                analog("Nothing (Gap9-AI) starting index", 65002),
            ],
            "AO": [
                analog(
                    "Setpoint", 0, multiplier=0.1, minimum=-1000, maximum=1000, associated="AI3"
                ),
                analog("Unit #1 limit", block="Unit", offset=0, associated="Unit_AI+1"),
            ],
            "CTR": [
                row("Energy out", 0, frozen=True, frozen_event_class=3),
                row("Energy in", 1, frozen=True, frozen_event_class=3),
                row("Unfrozen tally", 5, frozen=False),
            ],
        },
        # The loader knows the equipment by the Key sheet's names for it, so the
        # synthetic block borrows one of those and keeps its own symbol.
        equipment={
            "meters": {
                "symbol": "Unit",
                "start": 1000,
                "per_unit": {"BI": 1, "AI": 1, "AO": 1},
                # One longer than the key says, as the real tables sometimes are.
                "per_unit_observed": {"BI": 1, "AI": 2, "AO": 1},
            }
        },
        index_points={"first": 65000, "count": 3},
    )


def units(count: int) -> Composition:
    """A composition with *count* of the synthetic tables' one repeating block."""
    return Composition(meters=count)


def for_reference_der() -> dict[str, Any]:
    """Tables holding exactly the points the reference DER binds, named by address.

    Built from the DER's own binding, so the simulation, the builder, the
    session and the listener can be exercised together where the real tables
    are not available. No name, unit or scaling here comes from the standard.
    """
    binding: Binding = ReferenceDer().bind(PointMap({}))
    points: dict[str, list[dict[str, Any]]] = {kind.value: [] for kind in Kind}
    for kind, index in sorted(
        {*binding.readers, *binding.outputs}, key=lambda a: (a[0].value, a[1])
    ):
        name = f"Synthetic {kind.value}{index}"
        if kind is Kind.CTR:
            points[kind.value].append(row(name, index, frozen=True, frozen_event_class=3))
        elif kind.is_analog:
            fields: dict[str, Any] = {"event_class": 2} if kind is Kind.AI else {}
            points[kind.value].append(analog(name, index, **fields))
        else:
            fields = {"event_class": 1} if kind is Kind.BI else {}
            points[kind.value].append(row(name, index, **fields))
    return document(points)
