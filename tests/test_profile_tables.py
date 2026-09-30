"""Pin the shape of the IEEE 1815.2 point tables a checkout has regenerated.

`scripts/extract_profile.py` reads the standard's companion workbook into
`conformance/ieee-1815-2-2025.json`; the workbook is not in the repository and
CI cannot re-run the extraction. What CI can do is hold the extracted file to
the properties the profile machinery will rely on, so a regeneration that
silently lost a sheet, duplicated an index or broke a cross-reference fails
here rather than in a loader.
"""

from __future__ import annotations

import collections
import json
import pathlib
import re

import pytest

TABLES = pathlib.Path(__file__).resolve().parent.parent / "conformance" / "ieee-1815-2-2025.json"

KINDS = ("BO", "BI", "AO", "AI", "CTR")

#: A paired-point reference as the extractor writes it: absolute (`AI29`) or
#: block-relative (`Exp_BI+1`). Anything else is a spelling it did not know.
_ABSOLUTE = re.compile(r"^(?P<kind>AI|AO|BI|BO|CTR)(?P<index>\d+)$")
_RELATIVE = re.compile(
    r"^(?P<block>[A-Za-z][A-Za-z0-9_]*?)_(?P<kind>AI|AO|BI|BO|CTR)\+(?P<offset>\d+)$"
)


#: The file is generated from a workbook whose download terms forbid
#: redistribution, so it is not in the repository and CI does not have it.
#: These tests run wherever someone has regenerated it and skip elsewhere;
#: a skip is the expected state on a clean checkout, not a failure.
pytestmark = pytest.mark.skipif(
    not TABLES.is_file(),
    reason="conformance/ieee-1815-2-2025.json is generated locally; see conformance/README.md",
)


@pytest.fixture(scope="module")
def tables() -> dict:
    return json.loads(TABLES.read_text(encoding="utf-8"))


def test_every_kind_is_present_and_populated(tables: dict) -> None:
    for kind in KINDS:
        assert tables["points"].get(kind), f"{kind} has no points"


def test_profile_version_is_the_one_the_version_point_carries(tables: dict) -> None:
    """AI0 is the profile version by definition (clause 1.5); the file says the same."""
    version_point = next(p for p in tables["points"]["AI"] if p["index"] == 0)
    assert version_point["value"] == tables["source"]["profile_version"]


@pytest.mark.parametrize("kind", KINDS)
def test_addresses_are_unique(tables: dict, kind: str) -> None:
    """No two points share an address, absolute or block-relative.

    A relative address is as visible to a loader as an absolute one: two
    points at `Meter_AI+3` resolve to the same index for every meter.
    """
    counts = collections.Counter(
        p["index"] if p["index"] is not None else (p["block"], p["offset"])
        for p in tables["points"][kind]
    )
    duplicated = sorted((str(a) for a, n in counts.items() if n > 1))
    assert not duplicated, f"{kind}: addresses assigned twice: {duplicated}"


@pytest.mark.parametrize("kind", KINDS)
def test_every_point_is_absolute_or_relative_never_both(tables: dict, kind: str) -> None:
    for point in tables["points"][kind]:
        absolute = point["index"] is not None
        relative = point["block"] is not None
        assert absolute != relative, f"{kind}: {point['name']!r} is neither or both"
        if relative:
            assert isinstance(point["offset"], int) and point["offset"] >= 0


def test_every_relative_block_is_in_the_key(tables: dict) -> None:
    """A relative index names a block the Key sheet gives a start for."""
    key = tables["key"]
    known = {entry["symbol"] for entry in key["equipment"].values()}
    known |= {key["experimental"]["symbol"], key["vendor"]["symbol"]}
    used = {p["block"] for kind in KINDS for p in tables["points"][kind] if p["block"]}
    assert used <= known, f"blocks with no start in the Key: {sorted(used - known)}"


def test_relative_offsets_fit_their_block(tables: dict) -> None:
    """An equipment point's offset stays inside the block length the rows imply."""
    for entry in tables["key"]["equipment"].values():
        for kind in KINDS:
            length = entry["per_unit_observed"].get(kind, 0)
            offsets = [p["offset"] for p in tables["points"][kind] if p["block"] == entry["symbol"]]
            assert all(offset < length for offset in offsets), (
                f"{entry['symbol']} {kind}: offsets {sorted(offsets)} against block length {length}"
            )


def test_the_key_never_claims_more_than_the_rows_hold(tables: dict) -> None:
    """The Key sheet's per-unit lengths are at most what the point rows imply.

    Three analog input blocks hold one more point than the Key says, which is
    the workbook's inconsistency rather than this file's, and is why the
    observed length is recorded beside the stated one. A Key length *larger*
    than the rows would mean a block the extractor lost part of.
    """
    for entry in tables["key"]["equipment"].values():
        for kind, stated in entry["per_unit"].items():
            observed = _block_length(tables, entry["symbol"], kind)
            assert stated <= observed, (
                f"{entry['symbol']} {kind}: the Key states {stated}, the rows hold {observed}"
            )


def test_recorded_block_lengths_are_the_rows(tables: dict) -> None:
    """`per_unit_observed` is derived from the rows and must still agree with them.

    It is stored so a loader need not walk the rows; this is what keeps the
    stored copy from drifting from the thing it summarizes.
    """
    for entry in tables["key"]["equipment"].values():
        for kind in KINDS:
            recorded = entry["per_unit_observed"].get(kind, 0)
            assert recorded == _block_length(tables, entry["symbol"], kind), (
                f"{entry['symbol']} {kind}: recorded {recorded}, rows say "
                f"{_block_length(tables, entry['symbol'], kind)}"
            )


def _block_length(tables: dict, symbol: str, kind: str) -> int:
    """The per-unit length the rows imply: the highest offset plus one."""
    offsets = [p["offset"] for p in tables["points"][kind] if p["block"] == symbol]
    return max(offsets) + 1 if offsets else 0


def test_index_points_start_where_clause_5_2_says(tables: dict) -> None:
    """The in-band block advertisement begins at analog input 65000."""
    assert tables["index_points"]["first"] == 65000
    assert tables["index_points"]["count"] > 0
    assert (
        tables["index_points"]["first"] + tables["index_points"]["count"]
        <= tables["key"]["maximum_index"]
    )


def test_no_point_sits_at_the_maximum_index(tables: dict) -> None:
    """The space's end marker is not a point."""
    top = tables["key"]["maximum_index"]
    for kind in KINDS:
        assert all(p["index"] != top for p in tables["points"][kind]), f"{kind} holds the sentinel"


def test_cross_references_name_points_that_exist(tables: dict) -> None:
    """A paired point ("Assoc. AI" and friends) resolves to a row in its sheet."""
    absolute = {
        kind: {p["index"] for p in tables["points"][kind] if p["index"] is not None}
        for kind in KINDS
    }
    relative = {
        kind: {(p["block"], p["offset"]) for p in tables["points"][kind] if p["block"]}
        for kind in KINDS
    }
    dangling = []
    for kind in KINDS:
        for point in tables["points"][kind]:
            target = point.get("associated")
            if not target:
                continue
            if match := _ABSOLUTE.match(target):
                found = int(match.group("index")) in absolute[match.group("kind")]
            elif match := _RELATIVE.match(target):
                found = (match.group("block"), int(match.group("offset"))) in relative[
                    match.group("kind")
                ]
            else:
                found = False
            if not found:
                dangling.append((kind, point["name"], target))
    assert not dangling, (
        f"{len(dangling)} cross-references to points that do not exist: {dangling[:8]}"
    )


def test_analog_ranges_are_ordered_where_given(tables: dict) -> None:
    """A stated range runs the right way.

    The workbook leaves the range blank for the curve pair points, whose units
    depend on the curve type, and for the auto-discovery count points, so a
    range is not required; a range that is stated must not be inverted.
    """
    for kind in ("AI", "AO"):
        for point in tables["points"][kind]:
            low, high = point["minimum"], point["maximum"]
            if low is not None and high is not None:
                assert low <= high, f"{kind}: {point['name']!r} range is inverted"
