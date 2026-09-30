"""Read the normative tables out of IEEE Std 1815-2012 and write them as JSON.

The standard is a paid document and is not in this repository. Run this against
your own copy to regenerate `conformance/ieee-1815-2012.json`, which is what
`tests/test_conformance.py` checks the implementation against:

    python scripts/extract_conformance.py --pdf "IEEE 1815-2012.pdf" --write
    python scripts/extract_conformance.py --pdf "IEEE 1815-2012.pdf" --check

What the JSON holds is code assignments, names and field widths -- the wire
vocabulary a second implementation needs in order to interoperate, and which
this package's own source already declares. It deliberately holds none of the
standard's prose: no descriptions, no clause text. The `kind` fields are
one-word categories derived from the tables, not quotations of them.

Tables are found by their captions rather than by page number, so a differently
paginated PDF of the same edition still works. `pypdf` is not a dependency of
this package; install it just to run this script.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any

#: Where the checked-in tables live, relative to the repository root.
TABLES = pathlib.Path(__file__).resolve().parent.parent / "conformance" / "ieee-1815-2012.json"

EDITION = "IEEE Std 1815-2012"

#: Range specifier codes, in the order Table 4-5 lists them.
_RANGE_CODES = [f"{value:X}" for value in range(16)]

#: Object prefix codes, in the order Table 4-4 lists them.
_PREFIX_CODES = [str(value) for value in range(8)]


class ExtractionError(RuntimeError):
    """The standard did not yield a table this script expects to find."""


def _squash(text: str) -> str:
    """Drop every space, so a word the extractor split mid-way still matches."""
    return re.sub(r"\s+", "", text).lower()


class Standard:
    """The text of one PDF, addressable by table caption."""

    def __init__(self, path: pathlib.Path) -> None:
        try:
            import pypdf
        except ModuleNotFoundError:  # pragma: no cover - depends on the caller's venv
            raise SystemExit("this script needs pypdf: pip install pypdf") from None
        self._pages = pypdf.PdfReader(str(path)).pages
        self._cache: dict[int, str] = {}

    def __len__(self) -> int:
        return len(self._pages)

    def page(self, index: int) -> str:
        """One page, whitespace collapsed to single spaces."""
        if index not in self._cache:
            try:
                raw = self._pages[index].extract_text() or ""
            except Exception:  # pragma: no cover - a page pypdf cannot decode
                raw = ""
            self._cache[index] = " ".join(raw.split())
        return self._cache[index]

    def find(self, pattern: str) -> int:
        """The first page whose caption matches `pattern`, as a zero-based index.

        The table of contents lists every caption too, so a match trailed by dot
        leaders is that listing rather than the table itself.
        """
        rx = re.compile(pattern, re.IGNORECASE)
        for index in range(len(self)):
            text = self.page(index)
            for match in rx.finditer(text):
                if "..." not in text[match.end() : match.end() + 120]:
                    return index
        raise ExtractionError(f"no page matches {pattern!r}")

    def span(self, start: int, until: str, limit: int = 12) -> str:
        """Pages from `start` up to and including the one matching `until`."""
        rx = re.compile(until, re.IGNORECASE)
        parts = []
        for index in range(start, min(start + limit, len(self))):
            text = self.page(index)
            parts.append(text)
            if rx.search(text):
                return " ".join(parts)
        raise ExtractionError(f"no page within {limit} of {start + 1} matches {until!r}")


def _rows(segment: str, codes: list[str]) -> dict[str, str]:
    """Split a flattened table into one cell-run per leading code.

    A table row starts with its code and runs to the next code, so locating the
    codes in order gives the text between them without having to model columns.
    """
    bounds = []
    cursor = 0
    for code in codes:
        match = re.compile(rf"(?<![0-9A-Fa-fx]){re.escape(code)}\s").search(segment, cursor)
        if match is None:
            raise ExtractionError(f"row {code!r} not found")
        bounds.append((code, match.end()))
        cursor = match.end()
    out = {}
    for position, (code, start) in enumerate(bounds):
        if position + 1 < len(bounds):
            end = bounds[position + 1][1] - len(codes[position + 1]) - 1
        else:
            end = len(segment)
        out[code] = segment[start:end].strip()
    return out


def function_codes(std: Standard) -> dict[str, dict[str, Any]]:
    """Table 4-2, as decimal code to its name and whether it draws a response.

    Five rows state that the outstation shall not send a response. That is
    recorded as a flag rather than as the sentence stating it, because the flag
    is what an implementation has to get right.
    """
    start = std.find(r"Table 4-2.{0,3}Function code table")
    body = std.span(start, r"4\.2\.2\.6\s+Internal indications")
    rows = []
    for match in re.finditer(r"\b(\d{1,3})\s+0x([0-9A-Fa-f]{2})\s+([A-Z][A-Z0-9_]{2,})\b", body):
        decimal, hexadecimal, name = int(match.group(1)), int(match.group(2), 16), match.group(3)
        # Both columns spell the same code; a pair that disagrees is prose that
        # happened to look like a row.
        if decimal == hexadecimal:
            rows.append((decimal, name, match.start(), match.end()))
    # This edition assigns exactly this many codes (0 through 33 and 129
    # through 131; the rest are reserved). A guard on "roughly enough" would
    # let an omitted code be written out as authoritative, which is the very
    # gap the checked-in tables exist to close.
    assigned = {decimal for decimal, _, _, _ in rows}
    if len(assigned) != 37:
        raise ExtractionError(f"Table 4-2 yielded {len(assigned)} distinct codes, expected 37")

    found = {}
    for position, (decimal, name, _, body_start) in enumerate(rows):
        body_end = rows[position + 1][2] if position + 1 < len(rows) else len(body)
        silent = "shallnotsendaresponse" in _squash(body[body_start:body_end])
        found[str(decimal)] = {"name": name, "sends_response": not silent}
    silent_count = sum(1 for row in found.values() if not row["sends_response"])
    if silent_count != 5:
        raise ExtractionError(f"Table 4-2 yielded {silent_count} no-response codes, expected 5")
    return found


def iin_bits(std: Standard) -> dict[str, str]:
    """Table 4-3, as `<octet>.<bit>` to name."""
    start = std.find(r"Table 4-3.{0,3}IIN bits")
    body = std.span(start, r"4\.2\.2\.7\s+Object headers", limit=3)
    found = {
        f"{match.group(1)}.{match.group(2)}": match.group(3)
        for match in re.finditer(r"IIN([12])\.([0-7])\s+([A-Z][A-Z0-9_]{2,})\b", body)
    }
    expected = {f"{octet}.{bit}" for octet in (1, 2) for bit in range(8)}
    if set(found) != expected:
        raise ExtractionError(f"Table 4-3 yielded {sorted(found)}")
    return found


def _octets(cell: str) -> int | None:
    """The width a Table 4-4 cell states, or None where it states none."""
    match = re.search(r"([124])\s*-\s*octet", cell, re.IGNORECASE)
    return int(match.group(1)) if match else None


def object_prefix_codes(std: Standard) -> dict[str, dict[str, Any]]:
    """Table 4-4, as code to what it prefixes and how wide that prefix is."""
    start = std.find(r"Table 4-4.{0,3}Object prefix codes")
    segment = std.page(start).split("Table 4-4")[-1]
    out = {}
    for code, cell in _rows(segment, _PREFIX_CODES).items():
        squashed = _squash(cell)
        if "reservedforfutureuse" in squashed:
            kind: str | None = "reserved"
        elif "packedwithoutanindexprefix" in squashed:
            kind = "none"
        elif "prefixedwithanindex" in squashed:
            kind = "index"
        elif "prefixedwithanobjectsize" in squashed:
            kind = "size"
        else:
            raise ExtractionError(f"Table 4-4 row {code}: {cell[:60]!r}")
        out[code] = {"kind": kind, "octets": _octets(cell)}
    return out


def range_specifier_codes(std: Standard) -> dict[str, dict[str, Any]]:
    """Table 4-5, as code to what the range field holds and its width."""
    start = std.find(r"Table 4-5.{0,3}Range specifier codes")
    segment = std.page(start).split("Table 4-5")[-1]
    out = {}
    for code, cell in _rows(segment, _RANGE_CODES).items():
        squashed = _squash(cell)
        if "reservedforfutureuse" in squashed:
            kind = "reserved"
        elif "variableformatqualifier" in squashed:
            kind = "variable_count"
        elif "norangefieldisused" in squashed:
            kind = "all_objects"
        elif "startandstopindexes" in squashed:
            kind = "index_range"
        elif "startandstopvirtualaddresses" in squashed:
            kind = "address_range"
        elif "countofobjects" in squashed:
            kind = "count"
        else:
            raise ExtractionError(f"Table 4-5 row {code}: {cell[:60]!r}")
        # The width is the last bare integer in the row, the table's third
        # column; a reserved row states none.
        widths = re.findall(r"(?<![-\w])(\d)\s*$", cell)
        out[code] = {"kind": kind, "octets": int(widths[0]) if widths else None}
    return out


def valid_qualifier_codes(std: Standard) -> list[int]:
    """Table 4-6: every qualifier octet the standard permits."""
    start = std.find(r"Table 4-6.{0,3}Valid qualifier codes")
    segment = std.page(start).split("Object Prefix")[-1].split("4.2.2.7.3.5")[0]
    found = sorted({int(token, 16) for token in re.findall(r"\b([0-9A-F]{2})\b", segment)})
    # Exactly the permitted set: ten with no prefix, three each for one-,
    # two- and four-octet index prefixes, and one each for the three object
    # size prefixes.
    if len(found) != 22:
        raise ExtractionError(f"Table 4-6 yielded {len(found)} codes, expected 22")
    return found


def extract(path: pathlib.Path) -> dict[str, Any]:
    """Every table this script knows how to read, keyed by table number."""
    std = Standard(path)
    return {
        "edition": EDITION,
        "generated_by": "scripts/extract_conformance.py",
        "tables": {
            "4-2": {"title": "Function code table", "function_codes": function_codes(std)},
            "4-3": {"title": "IIN bits", "iin_bits": iin_bits(std)},
            "4-4": {"title": "Object prefix codes", "prefix_codes": object_prefix_codes(std)},
            "4-5": {"title": "Range specifier codes", "range_codes": range_specifier_codes(std)},
            "4-6": {"title": "Valid qualifier codes", "qualifiers": valid_qualifier_codes(std)},
        },
    }


def _serialize(tables: dict[str, Any]) -> str:
    return json.dumps(tables, indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pdf", required=True, type=pathlib.Path, help="your copy of the standard")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--write", action="store_true", help=f"overwrite {TABLES.name}")
    action.add_argument(
        "--check", action="store_true", help="fail if the PDF and the JSON disagree"
    )
    args = parser.parse_args(argv)

    if not args.pdf.is_file():
        print(f"no such file: {args.pdf}", file=sys.stderr)
        return 2
    try:
        tables = extract(args.pdf)
    except ExtractionError as error:
        print(f"extraction failed: {error}", file=sys.stderr)
        print("this reads a specific edition; check the PDF is IEEE 1815-2012.", file=sys.stderr)
        return 1

    if args.write:
        TABLES.parent.mkdir(parents=True, exist_ok=True)
        TABLES.write_text(_serialize(tables), encoding="utf-8")
        print(f"wrote {TABLES}")
        return 0

    if args.check:
        if not TABLES.is_file():
            print(f"{TABLES} does not exist; run with --write", file=sys.stderr)
            return 1
        if TABLES.read_text(encoding="utf-8") == _serialize(tables):
            print(f"{TABLES.name} matches {args.pdf.name}")
            return 0
        print(f"{TABLES.name} does not match {args.pdf.name}; run with --write", file=sys.stderr)
        return 1

    print(_serialize(tables), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
