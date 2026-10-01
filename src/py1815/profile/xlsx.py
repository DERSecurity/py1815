"""Read cell values out of an .xlsx workbook, with the standard library alone.

The IEEE 1815.2 point tables are published as a spreadsheet, and reading them
is the only thing this package needs a spreadsheet for. A workbook is a zip of
XML parts, and the values of its cells -- which is all the extractor asks for
-- take a few dozen lines to read, so the reader lives here rather than
arriving as the one runtime dependency of a library whose design starts from
having none (D1).

Values only. No styles, no formulas (a formula cell yields the value the
spreadsheet program cached for it), no dates: a date cell yields its serial
number, and the tables this reads contain none.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import pathlib
import posixpath
import re
import zipfile
from collections.abc import Iterator
from typing import Any
from xml.etree import ElementTree

_MAIN = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_RELATIONSHIP = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
_PACKAGE = "{http://schemas.openxmlformats.org/package/2006/relationships}"

_REFERENCE = re.compile(r"^([A-Z]+)(\d+)$")

#: The largest part this reader will inflate. The tables are a few megabytes
#: of XML; a part claiming a thousand times that is not a spreadsheet anyone
#: meant to hand to a parser.
_MAX_PART = 256 * 1024 * 1024


class WorkbookError(ValueError):
    """The file is not a workbook this reader can make sense of."""


def _column(letters: str) -> int:
    """A column's letters as a one-based number: A is 1, AA is 27."""
    number = 0
    for letter in letters:
        number = number * 26 + (ord(letter) - ord("A") + 1)
    return number


def _number(text: str) -> int | float:
    """A numeric cell, as an integer where it was written as one."""
    if "." in text or "e" in text or "E" in text:
        return float(text)
    return int(text)


class Sheet:
    """One worksheet: its cells by row, values only."""

    def __init__(self, rows: dict[int, dict[int, Any]]) -> None:
        self._rows = rows
        self.max_row = max(rows, default=0)
        self.max_column = max((max(cells, default=0) for cells in rows.values()), default=0)

    def iter_rows(
        self,
        *,
        min_row: int = 1,
        max_row: int | None = None,
        min_col: int = 1,
        max_col: int | None = None,
    ) -> Iterator[tuple[Any, ...]]:
        """Each row as a tuple of values, ``None`` where a cell is empty.

        Every row in the range is yielded, including ones the file does not
        mention, so that a row's position in the result is its position in the
        sheet -- a caller that finds one row and reads the next is reading the
        one beneath it.
        """
        last_row = self.max_row if max_row is None else min(max_row, self.max_row)
        last_col = self.max_column if max_col is None else max_col
        for number in range(min_row, last_row + 1):
            cells = self._rows.get(number, {})
            yield tuple(cells.get(column) for column in range(min_col, last_col + 1))


class Workbook:
    """A workbook's sheets, by the names on their tabs."""

    def __init__(self, sheets: dict[str, Sheet]) -> None:
        self._sheets = sheets
        self.sheetnames = list(sheets)

    def __getitem__(self, name: str) -> Sheet:
        return self._sheets[name]

    def __contains__(self, name: object) -> bool:
        return name in self._sheets


def _part(archive: zipfile.ZipFile, name: str) -> ElementTree.Element:
    try:
        info = archive.getinfo(name)
    except KeyError:
        raise WorkbookError(f"the workbook has no part {name!r}") from None
    if info.file_size > _MAX_PART:
        raise WorkbookError(f"part {name!r} is {info.file_size} octets; refusing to read it")
    try:
        return ElementTree.fromstring(archive.read(info))
    except ElementTree.ParseError as exc:
        raise WorkbookError(f"part {name!r} is not well-formed XML: {exc}") from exc


def _shared_strings(archive: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in archive.namelist():
        return []
    strings = []
    for item in _part(archive, "xl/sharedStrings.xml").iter(f"{_MAIN}si"):
        strings.append(_string_item(item))
    return strings


def _string_item(item: ElementTree.Element) -> str:
    """The text of a string item: its own, or its rich-text runs joined.

    Phonetic runs are skipped. They are a reading aid stored beside the text
    in some locales, and joining them in would double the cell's content.
    """
    direct = item.find(f"{_MAIN}t")
    if direct is not None:
        return direct.text or ""
    return "".join(
        (text.text or "") for run in item.findall(f"{_MAIN}r") for text in run.findall(f"{_MAIN}t")
    )


def _sheet_paths(archive: zipfile.ZipFile) -> dict[str, str]:
    """Each sheet's tab name and the part that holds it."""
    targets = {
        relation.get("Id"): relation.get("Target", "")
        for relation in _part(archive, "xl/_rels/workbook.xml.rels").iter(f"{_PACKAGE}Relationship")
    }
    paths: dict[str, str] = {}
    for sheet in _part(archive, "xl/workbook.xml").iter(f"{_MAIN}sheet"):
        target = targets.get(sheet.get(f"{_RELATIONSHIP}id"))
        name = sheet.get("name")
        if not target or name is None:
            continue
        # A target is relative to the workbook part unless it is rooted.
        path = target.lstrip("/") if target.startswith("/") else posixpath.join("xl", target)
        paths[name] = posixpath.normpath(path)
    return paths


def _value(cell: ElementTree.Element, strings: list[str]) -> Any:
    kind = cell.get("t", "n")
    if kind == "inlineStr":
        inline = cell.find(f"{_MAIN}is")
        return _string_item(inline) if inline is not None else None
    raw = cell.find(f"{_MAIN}v")
    if raw is None or raw.text is None:
        return None
    if kind == "s":
        return strings[int(raw.text)]
    if kind == "b":
        return raw.text == "1"
    if kind in ("str", "e"):
        return raw.text
    try:
        return _number(raw.text)
    except ValueError:
        return raw.text


def _sheet(archive: zipfile.ZipFile, path: str, strings: list[str]) -> Sheet:
    rows: dict[int, dict[int, Any]] = {}
    for position, row in enumerate(_part(archive, path).iter(f"{_MAIN}row"), start=1):
        number = int(row.get("r", position))
        cells: dict[int, Any] = {}
        for offset, cell in enumerate(row.findall(f"{_MAIN}c"), start=1):
            match = _REFERENCE.match(cell.get("r", ""))
            column = _column(match.group(1)) if match else offset
            value = _value(cell, strings)
            if value is not None:
                cells[column] = value
        if cells:
            rows[number] = cells
    return Sheet(rows)


def load_workbook(path: str | pathlib.Path) -> Workbook:
    """Open a workbook and read every sheet's values."""
    try:
        with zipfile.ZipFile(path) as archive:
            strings = _shared_strings(archive)
            return Workbook(
                {
                    name: _sheet(archive, part, strings)
                    for name, part in _sheet_paths(archive).items()
                }
            )
    except zipfile.BadZipFile as exc:
        raise WorkbookError(f"{path} is not an .xlsx workbook: {exc}") from exc
