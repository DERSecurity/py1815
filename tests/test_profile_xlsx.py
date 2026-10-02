"""The workbook reader: cell values out of an .xlsx, with the standard library alone.

The workbooks here are written by hand, part by part, so the reader is checked
against the file format rather than against a library that also reads it.
"""

from __future__ import annotations

import pathlib
import zipfile

import pytest

from py1815.profile import xlsx

_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PKG = "http://schemas.openxmlformats.org/package/2006/relationships"


def _workbook(
    path: pathlib.Path,
    sheets: dict[str, str],
    *,
    strings: list[str] | None = None,
    rooted: bool = False,
) -> pathlib.Path:
    """Write a workbook whose sheets hold the given ``<sheetData>`` content."""
    with zipfile.ZipFile(path, "w") as archive:
        entries, relations = [], []
        for number, (name, data) in enumerate(sheets.items(), start=1):
            target = f"worksheets/sheet{number}.xml"
            entries.append(f'<sheet name="{name}" sheetId="{number}" r:id="rId{number}"/>')
            shown = f"/xl/{target}" if rooted else target
            relations.append(f'<Relationship Id="rId{number}" Target="{shown}"/>')
            archive.writestr(
                f"xl/{target}",
                f'<worksheet xmlns="{_MAIN}"><sheetData>{data}</sheetData></worksheet>',
            )
        archive.writestr(
            "xl/workbook.xml",
            f'<workbook xmlns="{_MAIN}" xmlns:r="{_REL}"><sheets>{"".join(entries)}</sheets>'
            "</workbook>",
        )
        archive.writestr(
            "xl/_rels/workbook.xml.rels",
            f'<Relationships xmlns="{_PKG}">{"".join(relations)}</Relationships>',
        )
        if strings is not None:
            items = "".join(strings)
            archive.writestr("xl/sharedStrings.xml", f'<sst xmlns="{_MAIN}">{items}</sst>')
    return path


def _rows(path: pathlib.Path, sheet: str = "S", **kwargs) -> list[tuple]:
    return list(xlsx.load_workbook(path)[sheet].iter_rows(**kwargs))


class TestCellValues:
    def test_numbers_keep_the_type_they_were_written_as(self, tmp_path):
        data = '<row r="1"><c r="A1"><v>5000</v></c><c r="B1"><v>0.1</v></c></row>'
        ((whole, fraction),) = _rows(_workbook(tmp_path / "w.xlsx", {"S": data}))
        assert (whole, type(whole)) == (5000, int)
        assert (fraction, type(fraction)) == (0.1, float)

    def test_a_shared_string_is_looked_up(self, tmp_path):
        data = '<row r="1"><c r="A1" t="s"><v>1</v></c></row>'
        path = _workbook(
            tmp_path / "w.xlsx",
            {"S": data},
            strings=["<si><t>zero</t></si>", "<si><t>one</t></si>"],
        )
        assert _rows(path) == [("one",)]

    @pytest.mark.parametrize("index", ["2", "-1", "1.5", "one"])
    def test_a_shared_string_that_is_not_there_is_a_workbook_error(self, tmp_path, index):
        """Past the end, before the start, and not a whole number at all."""
        data = f'<row r="1"><c r="A1" t="s"><v>{index}</v></c></row>'
        path = _workbook(
            tmp_path / "w.xlsx",
            {"S": data},
            strings=["<si><t>zero</t></si>", "<si><t>one</t></si>"],
        )
        with pytest.raises(xlsx.WorkbookError, match="shared string"):
            _rows(path)

    def test_rich_text_runs_are_joined_and_phonetic_runs_are_not(self, tmp_path):
        item = "<si><r><t>Volt</t></r><r><t>-Var</t></r><rPh><t>ignored</t></rPh></si>"
        data = '<row r="1"><c r="A1" t="s"><v>0</v></c></row>'
        assert _rows(_workbook(tmp_path / "w.xlsx", {"S": data}, strings=[item])) == [("Volt-Var",)]

    def test_inline_strings_booleans_and_formula_results(self, tmp_path):
        data = (
            '<row r="1">'
            '<c r="A1" t="inlineStr"><is><t>inline</t></is></c>'
            '<c r="B1" t="b"><v>1</v></c>'
            '<c r="C1" t="str"><f>A1</f><v>cached</v></c>'
            "</row>"
        )
        assert _rows(_workbook(tmp_path / "w.xlsx", {"S": data})) == [("inline", True, "cached")]

    def test_a_number_cell_that_is_not_a_number_is_kept_as_text(self, tmp_path):
        data = '<row r="1"><c r="A1"><v>n/a</v></c></row>'
        assert _rows(_workbook(tmp_path / "w.xlsx", {"S": data})) == [("n/a",)]


class TestTheGrid:
    SPARSE = (
        '<row r="1"><c r="A1"><v>1</v></c><c r="C1"><v>3</v></c></row>'
        '<row r="3"><c r="B3"><v>9</v></c></row>'
    )

    def test_empty_cells_are_none_and_missing_rows_are_empty_rows(self, tmp_path):
        """A row's position in the result is its position in the sheet."""
        rows = _rows(_workbook(tmp_path / "w.xlsx", {"S": self.SPARSE}))
        assert rows == [(1, None, 3), (None, None, None), (None, 9, None)]

    def test_a_window_can_be_cut_out_of_it(self, tmp_path):
        path = _workbook(tmp_path / "w.xlsx", {"S": self.SPARSE})
        assert _rows(path, min_row=3, min_col=2, max_col=4) == [(9, None, None)]
        assert _rows(path, max_row=1, max_col=2) == [(1, None)]

    def test_columns_past_z_are_counted(self, tmp_path):
        data = '<row r="1"><c r="AB1"><v>7</v></c></row>'
        ((*blank, last),) = _rows(_workbook(tmp_path / "w.xlsx", {"S": data}))
        assert last == 7 and len(blank) == 27

    def test_cells_without_references_fall_in_order(self, tmp_path):
        data = "<row><c><v>1</v></c><c><v>2</v></c></row>"
        assert _rows(_workbook(tmp_path / "w.xlsx", {"S": data})) == [(1, 2)]


class TestSheets:
    def test_sheets_are_found_by_the_names_on_their_tabs(self, tmp_path):
        one = '<row r="1"><c r="A1"><v>1</v></c></row>'
        two = '<row r="1"><c r="A1"><v>2</v></c></row>'
        workbook = xlsx.load_workbook(_workbook(tmp_path / "w.xlsx", {"Key": one, "AI": two}))
        assert workbook.sheetnames == ["Key", "AI"]
        assert "AI" in workbook and "BO" not in workbook
        assert list(workbook["AI"].iter_rows()) == [(2,)]

    def test_a_rooted_part_path_is_followed_too(self, tmp_path):
        data = '<row r="1"><c r="A1"><v>1</v></c></row>'
        assert _rows(_workbook(tmp_path / "w.xlsx", {"S": data}, rooted=True)) == [(1,)]

    def test_an_empty_sheet_has_no_rows(self, tmp_path):
        assert _rows(_workbook(tmp_path / "w.xlsx", {"S": ""})) == []


class TestWhatIsNotAWorkbook:
    def test_a_file_that_is_not_a_zip(self, tmp_path):
        path = tmp_path / "w.xlsx"
        path.write_text("not a workbook", encoding="utf-8")
        with pytest.raises(xlsx.WorkbookError):
            xlsx.load_workbook(path)

    def test_a_zip_with_no_workbook_part(self, tmp_path):
        path = tmp_path / "w.xlsx"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("readme.txt", "hello")
        with pytest.raises(xlsx.WorkbookError, match="no part"):
            xlsx.load_workbook(path)

    def test_a_part_that_is_not_xml(self, tmp_path):
        path = _workbook(tmp_path / "w.xlsx", {"S": "<row>"})
        with pytest.raises(xlsx.WorkbookError, match="well-formed"):
            xlsx.load_workbook(path)
