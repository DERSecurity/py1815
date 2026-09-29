"""Assemble `changelog.d/` fragments into `CHANGELOG.md`.

Every changelog entry used to be written directly into `CHANGELOG.md`'s
`[Unreleased]` section, immediately under its `###` header. That is a shared
anchor: two concurrent pull requests both insert at the same line, so git
conflicts on every pair, even though the entries are independent and the
resolution is always "keep both".

A fragment is a file. Two pull requests adding entries create two different
files, so there is no shared hunk and no conflict to resolve. This module is the
other half: it turns the fragments back into a changelog section at release.

Fragment naming
---------------

``changelog.d/<reference>.<category>.md`` — for example ``113.fixed.md``.

* ``reference`` is the pull-request or issue number the entry points at.
* ``category`` is one of the Keep a Changelog headings, lowercased.
* Two entries on one pull request are ``113.fixed.md`` and ``113.changed.md``;
  two entries in the *same* category belong in one file, separated by a blank
  line — they render as one bullet with indented continuation paragraphs.

The body must cite its own reference (``#113``). The filename does not survive
the fold into ``CHANGELOG.md``, so a body that omits it would produce a released
entry with no pointer — which the changelog exists to carry.

Entry style
-----------

A fragment opens with a bolded summary — ``**...**`` closing in the same
paragraph, with at least one letter between the delimiters.

That is the one body rule checked here rather than left to review. A rule of
"1-3 lines per change" was tried first and does not survive contact: a line
depends on where the author happened to wrap, so the same entry passes or fails
on its formatting alone and a reviewer adjudicates it every time.

Length is deliberately not checked. A word cap was tried alongside the opener
rule and cost review rounds over a handful of words on entries that were doing
their job; an entry's size is the author's call. An entry carries the
consequence a consumer sees, any migration step, and the reasoning a later audit
cannot re-derive from the diff — the changelog is reconstructed from the
repository alone, so a pointer-only entry does not discharge that — and the pull
request the entry points at carries the rest.

The opener check bounds only *where* the close may be, so an opener whose close
falls late in the same paragraph is accepted. A summary legitimately wraps
across lines, and any length bound tight enough to reject a long bolded run
would reject those too.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import UTC
from datetime import datetime as _datetime

# Keep a Changelog's headings, in the order a rendered section presents them.
# A fragment naming anything else is rejected rather than silently filed under
# a heading nobody reads.
CATEGORIES = ("added", "changed", "deprecated", "removed", "fixed", "security")

_HEADING = {c: c.capitalize() for c in CATEGORIES}

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRAGMENT_DIR = os.path.join(_REPO_ROOT, "changelog.d")
CHANGELOG = os.path.join(_REPO_ROOT, "CHANGELOG.md")

_UNRELEASED = "## [Unreleased]"
# `113.fixed.md`. The reference is digits so a typo like `fixed.md` or
# `#113.fixed.md` fails loudly instead of sorting oddly.
_NAME = re.compile(r"^(?P<ref>\d+)\.(?P<category>[a-z]+)\.md$")
_SECTION = re.compile(r"^### (?P<heading>[A-Za-z][A-Za-z ]*?)\s*$", re.M)


class FragmentError(ValueError):
    """A fragment filename or body the assembler refuses to guess about."""


def parse_fragment_name(filename: str) -> tuple[int, str]:
    """Return ``(reference, category)`` for a fragment filename."""
    match = _NAME.match(filename)
    if match is None:
        raise FragmentError(
            f"{filename!r} is not a valid fragment name. "
            "Expected <reference>.<category>.md, e.g. 113.fixed.md"
        )
    category = match.group("category")
    if category not in CATEGORIES:
        raise FragmentError(
            f"{filename!r} names category {category!r}; expected one of {', '.join(CATEGORIES)}"
        )
    return int(match.group("ref")), category


def check_style(filename: str, body: str) -> None:
    """Raise unless ``body`` opens with a bolded summary.

    Separate from :func:`parse_fragment_name` because this is a body rule, and
    separate from the reference check only for readability — all three are
    what makes a fragment valid, and all three run on every scan. Length is
    deliberately not checked here.
    """
    # Markdown emphasis cannot cross a paragraph break, so the close has to be
    # in the first paragraph: a `**` belonging to a later entry in a
    # multi-entry file does not close this one. Scoped to the paragraph rather
    # than the first physical line, because a summary legitimately wraps: a
    # one-line summary is the exception, not the rule.
    first_paragraph = body.split("\n\n", 1)[0]
    closing = first_paragraph.find("**", 2)
    # The text between the delimiters, not merely the fact that two exist:
    # `**** #113` and `** ** #113` carry both delimiters and name nothing.
    # A summary with no letter in it — empty, whitespace, punctuation, or a
    # bare reference — is the same defect, so one test covers them all.
    summary = (
        first_paragraph[2:closing] if first_paragraph.startswith("**") and closing != -1 else ""
    )
    if not any(character.isalpha() for character in summary):
        raise FragmentError(
            f"{filename!r} does not open with a bolded summary. An entry starts "
            "with `**...**` naming what changed, so a reader scanning a released "
            "section takes the change from the first line without reading the rest. "
            "The close must be in the same paragraph, and something must sit "
            "between the delimiters: `****`, `** **`, a bare reference, or a "
            "`**` belonging to a later paragraph all name nothing."
        )


def read_fragments(fragment_dir: str = FRAGMENT_DIR) -> dict[str, list[tuple[int, str, str]]]:
    """Collect fragments as ``{category: [(reference, body, filename), ...]}``.

    The filename is carried through rather than rebuilt later: the reference is
    parsed to an ``int`` for ordering, which loses any zero-padding, so a name
    reconstructed from it would not match the file on disk.

    Ordered by reference within a category, so a rendered section is stable
    regardless of filesystem ordering and a re-run produces an identical diff.
    """
    if not os.path.isdir(fragment_dir):
        return {}
    collected: dict[str, list[tuple[int, str, str]]] = {}
    for filename in sorted(os.listdir(fragment_dir)):
        if filename == "README.md":
            continue
        # Every other entry goes through the name parser, including one that
        # is not `.md` at all. Skipping those silently is how `113.fixed.txt`
        # passes `--check` and is then never folded into a release: the
        # fragment is lost, and the only signal is its absence from a section
        # nobody is diffing.
        reference, category = parse_fragment_name(filename)
        with open(os.path.join(fragment_dir, filename), encoding="utf-8") as handle:
            body = handle.read().strip()
        if not body:
            raise FragmentError(f"{filename!r} is empty; a fragment must carry its entry text")
        if not re.search(rf"#{reference}(?!\d)", body):
            raise FragmentError(
                f"{filename!r} does not cite #{reference} in its body. The filename "
                "does not survive "
                "the fold into CHANGELOG.md, so the released entry would carry no reference. "
                "The match is on the whole number: #1134 does not satisfy #113, which would "
                "otherwise release an entry pointing somewhere else."
            )
        check_style(filename, body)
        collected.setdefault(category, []).append((reference, body, filename))
    for entries in collected.values():
        entries.sort()
    return collected


def render(fragments: dict[str, list[tuple[int, str, str]]]) -> str:
    """Render fragments as Keep a Changelog sections."""
    blocks: list[str] = []
    for category in CATEGORIES:
        entries = fragments.get(category)
        if not entries:
            continue
        lines = [f"### {_HEADING[category]}", ""]
        for _reference, body, _filename in entries:
            # Indent continuation lines so the bullet owns the whole entry;
            # without it a second paragraph escapes the list.
            first, *rest = body.split("\n")
            lines.append(f"- {first}")
            lines.extend(f"  {line}" if line.strip() else "" for line in rest)
            lines.append("")
        blocks.append("\n".join(lines))
    return "\n".join(blocks).rstrip() + "\n" if blocks else ""


def preview(fragment_dir: str = FRAGMENT_DIR) -> str:
    """What the pending fragments would render as."""
    rendered = render(read_fragments(fragment_dir))
    return rendered if rendered else "(no pending fragments)\n"


def _split_sections(body: str) -> dict[str, str]:
    """Split a changelog body into ``{category: entries}``.

    Text before the first ``###`` heading is filed under ``""`` and re-emitted
    ahead of the sections, so a hand-written preamble is not lost.
    """
    sections: dict[str, str] = {}
    matches = list(_SECTION.finditer(body))
    if not matches:
        return {"": body.strip()} if body.strip() else {}
    preamble = body[: matches[0].start()].strip()
    if preamble:
        sections[""] = preamble
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        category = match.group("heading").strip().lower()
        chunk = body[match.end() : end].strip()
        if not chunk:
            continue
        sections[category] = f"{sections[category]}\n\n{chunk}" if category in sections else chunk
    return sections


def merge_sections(existing: str, fragments: dict[str, list[tuple[int, str, str]]]) -> str:
    """Fold fragments into an existing body with one heading per category.

    Concatenating the two sides emits a second ``### Fixed`` whenever the
    existing body and a pending fragment share a category — two headings for one
    category inside a single released version.
    """
    sections = _split_sections(existing)
    rendered = _split_sections(render(fragments))

    out: list[str] = []
    if sections.get(""):
        out.append(sections[""])
    for category in CATEGORIES:
        parts = [part for part in (sections.get(category), rendered.get(category)) if part]
        if parts:
            out.append(f"### {_HEADING[category]}\n\n" + "\n\n".join(parts))
    # A heading outside the known set is carried through rather than dropped:
    # losing a released entry is worse than an unexpected heading.
    for category, chunk in sections.items():
        if category and category not in CATEGORIES:
            out.append(f"### {category.capitalize()}\n\n{chunk}")
    return "\n\n".join(out)


def release(
    version: str,
    when: str | None = None,
    *,
    changelog: str = CHANGELOG,
    fragment_dir: str = FRAGMENT_DIR,
) -> list[str]:
    """Fold pending fragments and the existing `[Unreleased]` body into a new
    ``## [version] - date`` section, and leave `[Unreleased]` empty.

    Returns the fragment paths consumed, so the caller can delete them in the
    same commit that records their content — the two must not drift.

    The existing `[Unreleased]` body is carried through rather than discarded:
    entries written before this mechanism existed are real unreleased content,
    and a release that dropped them would lose history to a tooling change.
    """
    # UTC, as `--date`'s help says. `date.today()` is the host's local date, so
    # a release cut near midnight from a non-UTC workstation stamps the day
    # before or after.
    when = when or _datetime.now(UTC).date().isoformat()
    with open(changelog, encoding="utf-8") as handle:
        text = handle.read()
    if _UNRELEASED not in text:
        raise FragmentError(f"{changelog} has no {_UNRELEASED} header to release from")

    start = text.index(_UNRELEASED)
    body_start = start + len(_UNRELEASED)
    next_section = text.find("\n## [", body_start)
    end = next_section if next_section != -1 else len(text)
    existing = text[body_start:end].strip()

    fragments = read_fragments(fragment_dir)
    section = merge_sections(existing, fragments).strip()

    new = f"{_UNRELEASED}\n\n## [{version}] - {when}\n\n{section}\n"
    with open(changelog, "w", encoding="utf-8") as handle:
        handle.write(text[:start] + new + text[end:])

    # The real filenames, never a name rebuilt from the parsed reference: the
    # reference is an int, so `0042.fixed.md` would rebuild as `42.fixed.md`
    # and the delete would raise — after CHANGELOG.md had already been
    # rewritten, leaving a half-applied release.
    return [
        os.path.join(fragment_dir, filename)
        for entries in fragments.values()
        for _reference, _body, filename in entries
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    parser.add_argument(
        "--preview", action="store_true", help="print the pending fragments as they would render"
    )
    parser.add_argument(
        "--check", action="store_true", help="validate fragment names and bodies, then exit"
    )
    parser.add_argument(
        "--release", metavar="X.Y.Z", help="fold fragments into a new version section"
    )
    parser.add_argument(
        "--date", metavar="YYYY-MM-DD", help="release date (UTC); defaults to today"
    )
    args = parser.parse_args(argv)

    try:
        if args.release:
            # Read the module constants at call time rather than relying on the
            # defaults, which bind at definition and cannot be redirected.
            consumed = release(
                args.release, args.date, changelog=CHANGELOG, fragment_dir=FRAGMENT_DIR
            )
            # CHANGELOG.md is already rewritten by this point, so a failure
            # deleting fragments leaves a half-applied release. Report which
            # half succeeded rather than surfacing a raw traceback: the
            # operator needs to know the fold landed and only the cleanup did
            # not, so they delete the remainder instead of re-running and
            # folding the same entries twice.
            undeleted: list[str] = []
            for path in consumed:
                try:
                    os.remove(path)
                except OSError:
                    undeleted.append(path)
            if undeleted:
                names = ", ".join(os.path.basename(p) for p in undeleted)
                print(
                    f"error: [{args.release}] was written to "
                    f"{os.path.basename(CHANGELOG)}, but these "
                    f"fragments could not be deleted and must be removed by hand: {names}",
                    file=sys.stderr,
                )
                return 1
            print(f"folded {len(consumed)} fragment(s) into [{args.release}]")
            return 0
        if args.check:
            read_fragments(FRAGMENT_DIR)
            print("fragments OK")
            return 0
        print(preview(FRAGMENT_DIR), end="")
        return 0
    except FragmentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
