# Changelog fragments

Pending changelog entries live here, one file per entry, until a release folds
them into [`CHANGELOG.md`](../CHANGELOG.md).

## Why

Entries used to be written straight into `CHANGELOG.md`'s `[Unreleased]`
section, immediately under the heading. That is a shared anchor: two concurrent
pull requests insert at the same line, so git conflicts on every pair, even
though the entries are independent and the resolution is always "keep both".

Two pull requests adding fragments create two different files. There is no
shared hunk, so there is nothing to conflict on. The conflict stops existing
rather than becoming easier to resolve.

## Adding an entry

Create `<reference>.<category>.md`:

```
changelog.d/42.added.md
```

- **`reference`** is the pull request or issue number the entry points at.
  Putting it in the filename means it cannot be forgotten.
- **`category`** is one of `added`, `changed`, `deprecated`, `removed`,
  `fixed`, `security` — Keep a Changelog's headings, lowercased.

The file holds the **entry body only**: no heading, no `-` bullet. The
assembler adds the bullet.

```markdown
**A feature key is validated against the registry rather than accepted as any
non-empty string (#42).** `id:htpp:server` used to validate cleanly and then
evaluate to `unknown` for the life of the rule, which is indistinguishable from
a device nobody polled.
```

Two things are checked, and only two:

- **The filename** parses as `<digits>.<category>.md` with a known category.
- **The body opens with a bolded summary** naming what changed, so a reader
  scanning a released section takes the change from the first line.

The body must also cite its own reference (`#42`). The filename does not
survive the fold into `CHANGELOG.md`, so a body that omits it would produce a
released entry with no pointer.

Length is deliberately not checked. Write the consequence a consumer sees, any
migration step, and the reasoning a later audit cannot re-derive from the diff.
What the entry does not need belongs in the pull request it already points at.

Two entries in different categories from one pull request are two files
(`42.added.md`, `42.changed.md`). Two entries in the *same* category belong in
one file, separated by a blank line.

## Checking your work

```bash
python scripts/build_changelog.py --check     # names, references, shape
python scripts/build_changelog.py --preview   # render as it will appear
```

`tests/test_changelog_fragments.py` runs the same validation over every
committed fragment, and CI runs the check, so a fragment that breaks a rule
fails there rather than surfacing at release.

## Releasing

```bash
python scripts/build_changelog.py --release X.Y.Z
```

That writes a `## [X.Y.Z] - YYYY-MM-DD` section containing the existing
`[Unreleased]` body **and** the rendered fragments, leaves `[Unreleased]`
holding only its "Nothing yet." placeholder, and prints the fragments it
consumed so they can be deleted in the same commit. The placeholder is not an
entry: it is dropped from what is folded and put back under the heading.
Commit that alongside the `version` bump in `pyproject.toml` — the deletion and
the content it became belong together, so the two cannot drift.

Entries written into `[Unreleased]` before this directory existed are carried
through rather than discarded. They predate the rules above and are not
retrofitted to them, so a long one is history rather than a model.
