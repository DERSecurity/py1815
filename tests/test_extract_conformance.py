"""Check how `scripts/extract_conformance.py` reads the object library of Annex A.

The extractor runs against the standard, which is not in this repository, so these
tests feed it synthetic text laid out the way `pdftotext -layout` prints Annex A:
the same headings, header boxes and typed fields, with invented wording. They check
how a size is read from a formal structure, that each named erratum corrects its
object, and that an erratum is refused once the text no longer needs it.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
from collections.abc import Iterator
from types import ModuleType

import pytest

_SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "extract_conformance.py"


@pytest.fixture(scope="module")
def extractor() -> Iterator[ModuleType]:
    spec = importlib.util.spec_from_file_location("extract_conformance", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        del sys.modules[spec.name]


def _object(
    clause: str, group: int, variation: int, kind: str, title: str, fields: list[str]
) -> str:
    """Return one object subclause: heading, header box and formal structure."""
    structure = "\n\n".join(f"           {field}: Value." for field in fields)
    return (
        f"{clause}      {title}\n\n"
        f"Group      DNP3 Object Library                       Group:          {group}\n"
        f"Name:                                                Variation:      {variation}\n"
        f"Variation        Synthetic Object\n"
        f"Name:            {title}                             Type:           {kind}\n\n"
        f"{clause}.1    Description\n\n"
        f"A synthetic object.\n\n"
        f"{clause}.2    Coding\n\n"
        f"{clause}.2.1  Pictorial\n\n"
        f"{clause}.2.2  Formal structure\n\n"
        f"{structure}\n\n"
        f"{clause}.2.3  Notes\n\n"
        f"None.\n\n"
    )


def _annex(groups: dict[int, list[tuple[int, str, list[str]]]]) -> str:
    """Return synthetic Annex A text: one subclause per group, one per variation."""
    parts = []
    for number, (group, variations) in enumerate(groups.items(), start=1):
        parts.append(f"A.{number}        Object group {group}: synthetic group {group}\n\n")
        for position, (variation, kind, fields) in enumerate(variations, start=1):
            parts.append(
                _object(
                    f"A.{number}.{position}",
                    group,
                    variation,
                    kind,
                    f"Synthetic variation {variation}",
                    fields,
                )
            )
    return "".join(parts)


def _library(
    extractor: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    groups: dict[int, list[tuple[int, str, list[str]]]],
) -> dict:
    """Run the Annex A reader over synthetic text holding exactly `groups`."""
    monkeypatch.setattr(extractor, "_GROUP_COUNT", len(groups))
    monkeypatch.setattr(extractor, "_VARIATION_COUNT", sum(len(v) for v in groups.values()))
    return extractor.object_library(_annex(groups))


# The objects the errata name, as the edition prints them.
_AS_PRINTED = {
    23: [(8, "Static", ["BSTR8", "UINT16", "DNP3TIME"])],
    32: [(8, "Event", ["BSTR8", "FLT32", "DNP3TIME"])],
    33: [(8, "Event", ["BSTR8", "FLT32", "DNP3TIME"])],
    86: [(2, "Info", ["BSTR4"])],
}


def test_sizes_are_summed_from_the_typed_fields(extractor, monkeypatch) -> None:
    library = _library(
        extractor,
        monkeypatch,
        {
            20: [
                (1, "Static", ["BSTR8", "UINT32"]),
                (2, "Static", ["BSTR8", "UINT16"]),
                (5, "Static", ["UINT32"]),
            ],
            50: [(1, "Info", ["DNP3TIME"])],
            110: [(1, "Static", ["OSTRn"])],
        },
    )
    sizes = {
        (group, variation): {k: v for k, v in row.items() if k in ("size", "octets", "bits")}
        for group, entry in library.items()
        for variation, row in entry["variations"].items()
    }
    assert sizes == {
        ("20", "1"): {"size": "fixed", "octets": 5},
        ("20", "2"): {"size": "fixed", "octets": 3},
        ("20", "5"): {"size": "fixed", "octets": 4},
        ("50", "1"): {"size": "fixed", "octets": 6},
        # A width given as a letter leaves the size to the sender.
        ("110", "1"): {"size": "variable"},
    }
    assert library["20"]["variations"]["1"]["type"] == "Static"
    assert library["20"]["name"] == "synthetic group 20"


def test_a_structure_of_part_octets_is_refused(extractor, monkeypatch) -> None:
    with pytest.raises(extractor.ExtractionError, match="not whole octets"):
        _library(extractor, monkeypatch, {1: [(1, "Static", ["BSTR4"])]})


def test_each_named_erratum_corrects_its_object(extractor, monkeypatch) -> None:
    library = _library(extractor, monkeypatch, _AS_PRINTED)
    # g23v8 is a frozen counter event, though its header box says Static.
    assert library["23"]["variations"]["8"]["type"] == "Event"
    assert library["23"]["variations"]["8"]["octets"] == 9
    # g32v8 and g33v8 carry a 64-bit value: 1 + 8 + 6 octets, not 1 + 4 + 6.
    assert library["32"]["variations"]["8"]["octets"] == 15
    assert library["33"]["variations"]["8"]["octets"] == 15
    # g86v2 is one octet, though its structure types the field as four bits.
    assert library["86"]["variations"]["2"]["octets"] == 1


@pytest.mark.parametrize(
    ("group", "fixed"),
    [
        (23, (8, "Event", ["BSTR8", "UINT16", "DNP3TIME"])),
        (32, (8, "Event", ["BSTR8", "FLT64", "DNP3TIME"])),
        (33, (8, "Event", ["BSTR8", "FLT64", "DNP3TIME"])),
        (86, (2, "Info", ["BSTR8"])),
    ],
)
def test_an_erratum_the_text_no_longer_needs_is_refused(
    extractor, monkeypatch, group: int, fixed: tuple[int, str, list[str]]
) -> None:
    corrected = dict(_AS_PRINTED)
    corrected[group] = [fixed]
    with pytest.raises(extractor.ExtractionError, match="no longer applies"):
        _library(extractor, monkeypatch, corrected)


def test_a_missing_subclause_is_refused(extractor, monkeypatch) -> None:
    monkeypatch.setattr(extractor, "_GROUP_COUNT", 1)
    monkeypatch.setattr(extractor, "_VARIATION_COUNT", 2)
    text = _annex({20: [(1, "Static", ["BSTR8", "UINT32"])]})
    with pytest.raises(extractor.ExtractionError, match="expected 2"):
        extractor.object_library(text)
