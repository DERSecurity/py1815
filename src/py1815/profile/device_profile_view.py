"""Read a DNP3 Device Profile document and lay it out as a page a person can read.

A Device Profile is XML, and a person reads it as a document: what the device
is, how each setting may be configured and how it is configured now, the
implementation table, and the point lists. This module reads the XML of any
Device Profile, whichever edition of the schema it was written for and
whoever wrote it, into a plain model of facts, sections and tables, and
writes that model as one standalone HTML page that prints cleanly.

**The layout is this library's own.** The DNP Users Group publishes a
stylesheet that renders a Device Profile in the Users Group's layout. That
stylesheet and the schema are the Users Group's and are not carried here
(D98), so nothing in this module comes from either. A label is the element's
own name made readable (``maxReceivedFragmentSize`` becomes "Max received
fragment size"), which is not the wording the Users Group prints.

**What it does not know.** It does not know the schema: it cannot say whether
a document is valid, which elements an edition requires, or what an element
means. It recognizes a handful of element names that every edition shares,
such as the document header, the three parts of a setting and the point
lists, and lays out everything else by its shape. An element it does not
recognize is still shown, by its label and its text. It does not know the
namespace either, since each edition has its own: only local names are
compared. It states nothing the document does not: a value that is absent is
an empty cell.

**The document is untrusted input.** A document that is not XML, or is not a
Device Profile, is refused with a :class:`DeviceProfileError` that says what
is wrong. See :func:`read` for the limits it enforces.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import html
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any
from xml.parsers import expat

#: The most characters, or octets, of XML that :func:`read` takes. A profile
#: for a DER serving most of the IEEE 1815.2 points runs to a little over a
#: megabyte.
MAX_SIZE = 8 * 1024 * 1024
#: The most elements a document may hold, and how deep they may nest. A
#: profile of a few thousand points has tens of thousands of elements, nested
#: less than a dozen deep.
MAX_ELEMENTS = 500_000
MAX_DEPTH = 64

#: The most columns one table is laid out with, and the most cells the tables
#: of one document hold between them. A table has a column for each property
#: any of its records carries, so records that each carry a property of their
#: own would make a table as wide as it is long.
MAX_COLUMNS = 200
MAX_CELLS = 1_000_000

#: The root element of a Device Profile in every edition of the schema.
ROOT = "DNP3DeviceProfileDocument"

#: The line every page carries, saying whose layout it is.
NOTICE = (
    "Laid out by py1815 from the Device Profile XML. "
    "This is py1815's own layout, not the DNP Users Group's."
)

#: The title of a document that names neither itself nor its device.
DEFAULT_TITLE = "DNP3 Device Profile"

#: The three parts a setting is stated in.
_CAPABILITIES, _CURRENT, _METHODS = "capabilities", "currentValue", "methods"
_PARTS = (_CAPABILITIES, _CURRENT, _METHODS)

#: Elements whose children are a list of records, one to a row, however many
#: there are: the points of one type, the files, the implementation table.
_LISTS = frozenset({"dataPoints", "files", "table"})
#: An element that is a record wherever it appears, even when it appears once.
_RECORDS = frozenset({"revisionHistory"})
#: Elements that hold a sentence or a value and are shown as that text alone.
_BARE = frozenset({"value", "description", "explanation"})
#: The device's identification, shown with the header facts.
_IDENTITY = (
    "vendorName",
    "deviceName",
    "hardwareVersion",
    "softwareVersion",
    "documentVersionNumber",
)
#: Abbreviations the schema writes in lower case inside an element name.
_ABBREVIATIONS = frozenset(
    {"dnp", "iec", "iin", "ip", "lan", "tcp", "tls", "udp", "utc", "xml", "crob", "id"}
)

_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")

#: Column headings of a table of settings.
_ITEM, _STATED = "Item", "Stated"
_HEADINGS = {_CAPABILITIES: "Capabilities", _CURRENT: "Current value", _METHODS: "Methods"}


class DeviceProfileError(ValueError):
    """A document that cannot be read as a Device Profile, and why."""


@dataclass(frozen=True)
class Fact:
    """One fact of the document's header: what it is, and its value."""

    label: str
    value: str


@dataclass(frozen=True)
class Table:
    """A table: a title, column headings, and rows of text cells.

    Every row has a cell for every column. A cell that states several things
    separates them with a newline, and a cell the document says nothing for
    is empty.
    """

    title: str
    columns: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]


@dataclass(frozen=True)
class Section:
    """A part of the document: a title and the tables under it."""

    title: str
    tables: tuple[Table, ...]


@dataclass(frozen=True)
class Document:
    """A Device Profile as a person reads it: a title, header facts and sections."""

    title: str
    facts: tuple[Fact, ...]
    sections: tuple[Section, ...]
    #: Whose layout this is, in one line.
    notice: str = NOTICE

    def describe(self) -> dict[str, Any]:
        """Return the document as JSON-compatible data."""
        return {
            "title": self.title,
            "notice": self.notice,
            "facts": [{"label": fact.label, "value": fact.value} for fact in self.facts],
            "sections": [
                {
                    "title": section.title,
                    "tables": [
                        {
                            "title": table.title,
                            "columns": list(table.columns),
                            "rows": [list(row) for row in table.rows],
                        }
                        for table in section.tables
                    ],
                }
                for section in self.sections
            ],
        }


# ------------------------------------------------------------------- reading


@dataclass
class _Node:
    """One element: its local name, attributes, own text and child elements."""

    name: str
    #: Each attribute's local name and value, in the order written. Two
    #: attributes of different namespaces can share a local name, and both
    #: are kept.
    attributes: list[tuple[str, str]]
    children: list[_Node] = field(default_factory=list)
    text: str = ""
    parts: list[str] = field(default_factory=list)


def _local(name: str) -> str:
    """Return a name without the prefix that says which namespace it is in."""
    return name.rpartition(":")[2]


def _declares_namespace(name: str) -> bool:
    return name == "xmlns" or name.startswith("xmlns:")


def _megabytes(size: int) -> str:
    return f"{size // (1024 * 1024)} MiB"


def _parse(source: str | bytes) -> _Node:
    """Return the document's root element, or raise DeviceProfileError."""
    if len(source) > MAX_SIZE:
        raise DeviceProfileError(
            f"the Device Profile document is larger than {_megabytes(MAX_SIZE)}, "
            "the most that is read"
        )
    # What makes this safe for a document from anyone:
    # - A document type declaration is refused where it starts, before the
    #   parser reads what it declares. Entities are declared only there, so
    #   none can be defined to expand without bound and none can name a file
    #   or an address to fetch. What is left are the five entities XML
    #   predefines and character references, each of which is one character.
    # - The parser is given no handler for external entities and this module
    #   follows no reference: not a schema location, not a stylesheet
    #   instruction, not an inclusion.
    # - The element count and the nesting depth are checked as each element
    #   opens, so the tree built here is bounded whatever the text holds, and
    #   the functions below can walk it by recursion.
    #
    # The parser is not asked to resolve namespaces. Each edition of the
    # schema has its own, so a name is known by what follows its prefix, and a
    # namespace declaration is not an attribute of the document's.
    parser = expat.ParserCreate()
    parser.buffer_text = True
    stack: list[_Node] = []
    roots: list[_Node] = []
    count = 0

    def doctype(*_declaration: object) -> None:
        raise DeviceProfileError(
            "the document has a document type declaration, which a Device Profile "
            "does not need and this reader does not accept"
        )

    def start(name: str, attributes: dict[str, str]) -> None:
        nonlocal count
        count += 1
        if count > MAX_ELEMENTS:
            raise DeviceProfileError(
                f"the Device Profile document has more than {MAX_ELEMENTS} elements, "
                "the most that are read"
            )
        if len(stack) >= MAX_DEPTH:
            raise DeviceProfileError(
                f"the Device Profile document nests elements more than {MAX_DEPTH} deep"
            )
        stated = [
            (_local(key), value)
            for key, value in attributes.items()
            if not _declares_namespace(key)
        ]
        node = _Node(_local(name), stated)
        (stack[-1].children if stack else roots).append(node)
        stack.append(node)

    def end(_name: str) -> None:
        node = stack.pop()
        node.text = " ".join("".join(node.parts).split())
        node.parts = []

    def characters(data: str) -> None:
        if stack:
            stack[-1].parts.append(data)

    parser.StartDoctypeDeclHandler = doctype
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = characters
    try:
        parser.Parse(source, True)
    except (expat.ExpatError, UnicodeError, LookupError) as error:
        raise DeviceProfileError(f"the document is not XML: {error}") from None
    return roots[0]


# ------------------------------------------------------------------- wording


def _label(*names: str) -> str:
    """Return element names as a readable phrase: ``maxFrameSize`` -> "Max frame size".

    The words are the name's own, split where its capitals and digits split
    it. An abbreviation is kept in capitals with the digits that follow it
    ("IIN14", "DNP3"), every other word is in lower case, and the phrase
    starts with a capital.
    """
    words: list[str] = []
    abbreviated = False
    for name in names:
        for token in _WORD.findall(name):
            if token.isdigit():
                if abbreviated and words:
                    words[-1] += token
                else:
                    words.append(token)
                abbreviated = False
                continue
            abbreviated = (len(token) > 1 and token.isupper()) or token.lower() in _ABBREVIATIONS
            if token.lower() == "station" and words and words[-1].lower() == "out":
                # The schema writes "outStation", and the standard's word is "outstation".
                words[-1] += "station"
                continue
            words.append(token.upper() if abbreviated else token.lower())
    if not words:
        return " ".join(names)
    first = words[0]
    if first.islower():
        words[0] = first[0].upper() + first[1:]
    return " ".join(words)


def _attributes(node: _Node) -> list[str]:
    return [f"{_label(name)}: {value}" for name, value in node.attributes]


def _say(node: _Node) -> str:
    """Return an element and everything in it as one line of text.

    An empty element is its label, since that is how the schema writes a
    choice: ``<none/>`` is "None". An element with text is its label and the
    text, a range is "minimum to maximum", and an element with children is
    its label and what its children say.
    """
    stated = _attributes(node)
    if not node.children:
        if node.name in _BARE:
            return "; ".join([*stated, node.text] if node.text else stated)
        if node.text:
            stated.append(node.text)
        return f"{_label(node.name)}: {'; '.join(stated)}" if stated else _label(node.name)
    if (
        not stated
        and not node.text
        and [child.name for child in node.children] == ["minimum", "maximum"]
        and all(child.text and not child.children for child in node.children)
    ):
        span = f"{node.children[0].text} to {node.children[1].text}"
        return span if node.name == "range" else f"{_label(node.name)}: {span}"
    if node.text:
        stated.append(node.text)
    stated += [said for said in map(_say, node.children) if said]
    if not stated:
        return _label(node.name)
    if len(stated) == 1:
        return f"{_label(node.name)}: {stated[0]}"
    return f"{_label(node.name)} ({'; '.join(stated)})"


def _cell(nodes: Iterable[_Node]) -> str:
    """Return what the children of some elements say, one statement to a line."""
    lines: list[str] = []
    for node in nodes:
        lines += _attributes(node)
        if node.text:
            lines.append(node.text)
        lines += [said for said in map(_say, node.children) if said]
    return "\n".join(lines)


# -------------------------------------------------------------------- layout


@dataclass
class _Budget:
    """The cells the tables of one document may still be given."""

    cells: int

    def spend(self, cells: int) -> None:
        """Take cells from what is left, or refuse the document when there are too few."""
        self.cells -= cells
        if self.cells < 0:
            raise DeviceProfileError(
                f"the tables of the Device Profile document have more than {MAX_CELLS} "
                "cells, the most that are laid out"
            )


def _is_setting(node: _Node) -> bool:
    return any(child.name in _PARTS for child in node.children)


def _is_row(node: _Node) -> bool:
    """Whether an element is one row of a table of settings.

    A setting is, and so is an element with no children, and one whose
    children have none of their own: a choice and a note about it, say.
    """
    return _is_setting(node) or all(not child.children for child in node.children)


def _settings(title: str, rows: Sequence[tuple[str, _Node | str]]) -> Table:
    """Return a table of settings: one row for each, a column for each part stated."""
    cells: list[dict[str, str]] = []
    for label, node in rows:
        row = {_ITEM: label}
        if isinstance(node, str):
            row[_STATED] = node
        else:
            for part in _PARTS:
                found = [child for child in node.children if child.name == part]
                if found:
                    row[part] = _cell(found)
            # Whatever else the element holds is kept, in a column of its own.
            others = [child for child in node.children if child.name not in _PARTS]
            stated = [*_attributes(node), node.text, *map(_say, others)]
            row[_STATED] = "\n".join(line for line in stated if line)
        cells.append(row)
    keys: list[str] = [_ITEM]
    if any(part in row for row in cells for part in _PARTS):
        # The capabilities and the current value belong side by side even
        # where a document states only one of them. The methods are a column
        # only where some setting gives them.
        keys += [_CAPABILITIES, _CURRENT]
        if any(_METHODS in row for row in cells):
            keys.append(_METHODS)
    if len(keys) == 1 or any(row.get(_STATED) for row in cells):
        keys.append(_STATED)
    return Table(
        title,
        tuple(_HEADINGS.get(key, key) for key in keys),
        tuple(tuple(row.get(key, "") for key in keys) for row in cells),
    )


def _fields(record: _Node) -> list[tuple[str, str]]:
    """Return a record as columns and values, in the order the record gives them.

    A child with no children is a column. A child with children gives a
    column for each of them that has text, named for both ("Request function
    code"), and one column of its own for the rest.
    """
    found: list[tuple[str, str]] = [(_label(name), value) for name, value in record.attributes]
    if record.text:
        found.append((_label(record.name), record.text))
    for child in record.children:
        column = _label(child.name)
        if not child.children or child.text:
            found.append((column, child.text))
        found += [(_label(child.name, name), value) for name, value in child.attributes]
        for inner in child.children:
            if inner.text and not inner.children and not inner.attributes:
                found.append((_label(child.name, inner.name), inner.text))
            else:
                found.append((column, _say(inner)))
    return found


def _records(title: str, records: Sequence[_Node], budget: _Budget) -> Table:
    """Return a table with a row for each record and a column for each property."""
    columns: list[str] = []
    rows: list[dict[str, str]] = []
    for record in records:
        row: dict[str, str] = {}
        before: str | None = None
        for column, value in _fields(record):
            if column not in columns:
                if len(columns) >= MAX_COLUMNS:
                    raise DeviceProfileError(
                        f"a table of the Device Profile document has more than {MAX_COLUMNS} "
                        "columns, the most that are laid out"
                    )
                # Beside the column this record gives before it, so that a
                # property only some records carry lands where they have it.
                columns.insert(
                    columns.index(before) + 1 if before in columns else len(columns), column
                )
            # A property a record gives more than once is one cell.
            row[column] = ", ".join(part for part in (row.get(column, ""), value) if part)
            before = column
        rows.append(row)
    # Checked before the cells are made: every row is filled out to every column.
    budget.spend(len(columns) * len(rows))
    return Table(
        title,
        tuple(columns),
        tuple(tuple(row.get(column, "") for column in columns) for row in rows),
    )


def _title(path: Sequence[str]) -> str:
    return ": ".join(path)


def _tables(
    node: _Node, path: Sequence[str], budget: _Budget, *, leaves: bool = True
) -> list[Table]:
    """Return the tables that lay out an element's children.

    The children that are settings share one table. Children that are a list
    of records are a table each, and any other child is laid out the same way
    in turn, its label added to the titles of its tables.

    Args:
        node: The element whose children are laid out.
        path: The labels that title its tables.
        budget: The cells the document's tables may still be given.
        leaves: Whether a child with no children of its own is a row. The
            document header's are not: they are shown as facts instead.
    """
    groups: dict[str, list[_Node]] = {}
    for child in node.children:
        groups.setdefault(child.name, []).append(child)
    rows: list[tuple[str, _Node | str]] = [(_label(name), value) for name, value in node.attributes]
    if node.text:
        rows.append((_label(node.name), node.text))
    listed = node.name in _LISTS
    after: list[Table] = []
    for name, same in groups.items():
        first = same[0]
        if (
            listed
            or name in _RECORDS
            or (len(same) > 1 and first.children and not _is_setting(first))
        ):
            # A list names its table by where it is. Its own label is added
            # only when the list holds records of more than one kind.
            kind = [] if listed and len(groups) == 1 else [_label(name)]
            after.append(_records(_title([*path, *kind]) or _label(name), same, budget))
            continue
        for child in same:
            if _is_row(child):
                if leaves or child.children:
                    rows.append((_label(name), child))
            else:
                inner = path if name in _LISTS else [*path, _label(name)]
                after += _tables(child, inner, budget)
    return ([_settings(_title(path), rows)] if rows else []) + after


def _find(node: _Node, *names: str) -> _Node | None:
    """Return the element reached by following child names from a node, if there is one."""
    for name in names:
        found = next((child for child in node.children if child.name == name), None)
        if found is None:
            return None
        node = found
    return node


def _fact(node: _Node) -> Fact:
    """Return an element with no children as a fact: its label and its text."""
    return Fact(
        _label(node.name), "; ".join(line for line in (*_attributes(node), node.text) if line)
    )


def _own(part: _Node) -> list[Fact]:
    """Return what a part of the document states itself, beside its child elements.

    Its attributes and its own text are facts, so that neither is lost when
    the part's children are laid out as sections.
    """
    own = [Fact(_label(part.name, name), value) for name, value in part.attributes]
    if part.text:
        own.append(Fact(_label(part.name), part.text))
    return own


def _sections(part: _Node, budget: _Budget) -> list[Section]:
    """Return a section for each child of one of the document's parts.

    The device the document describes is the part every edition has, and its
    sections are titled by their own names. Any other part is laid out the
    same way, with its name before each title.
    """
    prefix = [] if part.name == "referenceDevice" else [_label(part.name)]
    sections: list[Section] = []
    for child in part.children:
        if _is_row(child):
            tables = [_settings("", [(_label(child.name), child)])]
        else:
            tables = _tables(child, [], budget)
        sections.append(Section(_title([*prefix, _label(child.name)]), tuple(tables)))
    return sections


def _layout(root: _Node) -> Document:
    """Return the document a Device Profile's root element lays out as."""
    if root.name != ROOT:
        raise DeviceProfileError(
            f"the document is not a Device Profile: its root element is {root.name}, not {ROOT}"
        )
    budget = _Budget(MAX_CELLS)
    facts = [Fact(_label(name), value) for name, value in root.attributes]
    if root.text:
        facts.append(Fact(_label(root.name), root.text))
    sections: list[Section] = []
    for part in root.children:
        if not part.children:
            facts.append(_fact(part))
        elif part.name == "documentHeader":
            # What the header states in a word or a sentence is a fact. The
            # rest of it, the revision history above all, is tables.
            facts += _own(part)
            facts += [_fact(child) for child in part.children if not child.children]
            tables = _tables(part, [], budget, leaves=False)
            if tables:
                sections.append(Section(_label(part.name), tuple(tables)))
        else:
            facts += _own(part)
            sections += _sections(part, budget)
    # The device's identification is repeated beside the header's facts, where
    # a reader looks for it. Its rows stay in the table they come from.
    identity = _find(root, "referenceDevice", "configuration", "deviceConfig")
    for name in _IDENTITY:
        current = None if identity is None else _find(identity, name, _CURRENT)
        if current is not None:
            facts.append(Fact(_label(name), _cell([current])))
    # The title is the name the header gives the document, or the device's
    # name, read from where every edition this was written against keeps
    # them. A fact that merely has the same label, a vendor's attribute on
    # the root for one, is a title only for a document that has neither.
    named = _find(root, "documentHeader", "documentName")
    device = None if identity is None else _find(identity, "deviceName", _CURRENT)
    labeled = {fact.label: fact.value for fact in reversed(facts)}
    title = (
        (named.text if named is not None else "")
        or (_cell([device]) if device is not None else "")
        or labeled.get(_label("documentName"))
        or labeled.get(_label("deviceName"))
        or DEFAULT_TITLE
    )
    return Document(title, tuple(facts), tuple(sections))


def read(source: str | bytes) -> Document:
    """Read the XML of a Device Profile document into a :class:`Document`.

    The text is read as it is given. Octets are decoded as the document's
    own declaration says, UTF-8 when it has none.

    The document is untrusted. One that declares a document type is
    refused, so no entity can be defined to expand or to fetch anything, and
    nothing the document refers to is followed. One of more than
    :data:`MAX_SIZE` characters or octets, more than :data:`MAX_ELEMENTS`
    elements, or elements nested more than :data:`MAX_DEPTH` deep is refused,
    and so is one whose tables would have more than :data:`MAX_COLUMNS`
    columns in one table or :data:`MAX_CELLS` cells between them.

    Raises:
        DeviceProfileError: The text is not XML, is not a Device Profile, or
            is past one of the limits. The message says which.
    """
    return _layout(_parse(source))


# ---------------------------------------------------------------------- page

_STYLE = """
:root { --ink: #1d1f21; --body: #33373a; --muted: #6b6f73; --rule: #d7d2c6; --band: #f3efe6; }
* { box-sizing: border-box; }
body { margin: 0 auto; padding: 28px 32px 48px; max-width: 1200px; color: var(--body);
  background: #fff; font: 14px/1.45 "Segoe UI", Helvetica, Arial, sans-serif; }
h1, h2, h3 { color: var(--ink); margin: 0; }
h1 { font-size: 26px; line-height: 1.2; }
h2 { font-size: 18px; margin: 34px 0 10px; padding-bottom: 5px; }
h2 { border-bottom: 2px solid var(--ink); }
h3 { font-size: 14px; margin: 20px 0 6px; }
.notice { color: var(--muted); font-size: 12.5px; margin: 6px 0 18px; }
.facts { display: grid; grid-template-columns: max-content 1fr; gap: 4px 22px; margin: 0; }
.facts dt { color: var(--muted); }
.facts dd { margin: 0; color: var(--ink); white-space: pre-line; overflow-wrap: anywhere; }
.contents { margin: 22px 0 0; font-size: 13px; }
.contents ol { margin: 4px 0 0; padding-left: 22px; columns: 2; }
.contents a { color: inherit; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: max-content; min-width: 100%; font-size: 13px; }
th, td { border: 1px solid var(--rule); padding: 4px 8px; text-align: left; vertical-align: top; }
th { background: var(--band); color: var(--ink); font-weight: 600; white-space: nowrap; }
td { white-space: pre-line; overflow-wrap: break-word; max-width: 46ch; }
td:first-child { color: var(--ink); }
table.wide { font-size: 12px; }
.empty { color: var(--muted); }
@page { margin: 14mm 12mm; }
@media print {
  body { max-width: none; padding: 0; font-size: 9.5pt; color: #000; }
  .contents { display: none; }
  .scroll { overflow: visible; }
  table { font-size: 8.5pt; width: 100%; min-width: 0; }
  th { white-space: normal; }
  td { max-width: none; }
  table.wide { font-size: 7.5pt; }
  thead { display: table-header-group; }
  tr, .facts { break-inside: avoid; page-break-inside: avoid; }
  h2, h3 { break-after: avoid; page-break-after: avoid; }
  th { background: #eee; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  a { color: inherit; text-decoration: none; }
}
"""

#: A table of more columns than this is set smaller, so that it fits a page.
_WIDE = 7


def _text(value: str) -> str:
    return html.escape(value, quote=True)


def _table(table: Table) -> list[str]:
    lines: list[str] = []
    if table.title:
        lines.append(f"<h3>{_text(table.title)}</h3>")
    wide = ' class="wide"' if len(table.columns) > _WIDE else ""
    lines.append(f'<div class="scroll"><table{wide}>')
    heads = "".join(f'<th scope="col">{_text(column)}</th>' for column in table.columns)
    lines.append(f"<thead><tr>{heads}</tr></thead>")
    lines.append("<tbody>")
    for row in table.rows:
        lines.append("<tr>" + "".join(f"<td>{_text(cell)}</td>" for cell in row) + "</tr>")
    lines.append("</tbody>")
    lines.append("</table></div>")
    return lines


def page(document: Document) -> str:
    """Return a Device Profile as one standalone HTML page.

    The page carries its own style, runs no script and refers to nothing
    outside itself, so it can be saved, mailed or opened from a disk. Every
    piece of text from the document is escaped. Printed, or saved as PDF from
    a browser, it repeats each table's headings on every page and keeps a row
    on one page.
    """
    lines = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_text(document.title)}</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        "<header>",
        f"<h1>{_text(document.title)}</h1>",
        f'<p class="notice">{_text(document.notice)}</p>',
    ]
    if document.facts:
        lines.append('<dl class="facts">')
        lines += [
            f"<dt>{_text(fact.label)}</dt><dd>{_text(fact.value)}</dd>" for fact in document.facts
        ]
        lines.append("</dl>")
    lines.append("</header>")
    if document.sections:
        lines.append('<nav class="contents" aria-label="Contents">')
        lines.append("<ol>")
        lines += [
            f'<li><a href="#section-{number}">{_text(section.title)}</a></li>'
            for number, section in enumerate(document.sections, start=1)
        ]
        lines.append("</ol>")
        lines.append("</nav>")
    lines.append("<main>")
    for number, section in enumerate(document.sections, start=1):
        lines.append(f'<section id="section-{number}">')
        lines.append(f"<h2>{_text(section.title)}</h2>")
        if not section.tables:
            lines.append('<p class="empty">Nothing is stated.</p>')
        for table in section.tables:
            lines += _table(table)
        lines.append("</section>")
    lines += ["</main>", "</body>", "</html>"]
    return "\n".join(lines) + "\n"


__all__ = [
    "DEFAULT_TITLE",
    "MAX_CELLS",
    "MAX_COLUMNS",
    "MAX_DEPTH",
    "MAX_ELEMENTS",
    "MAX_SIZE",
    "NOTICE",
    "DeviceProfileError",
    "Document",
    "Fact",
    "Section",
    "Table",
    "page",
    "read",
]
