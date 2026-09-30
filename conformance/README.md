# Conformance tables

`ieee-1815-2012.json` holds the normative tables this outstation is checked
against. `tests/test_conformance.py` diffs the implementation against it on
every test run, so a code the standard assigns and this package does not name
(or a field width that disagrees with the standard's) fails in CI rather than in
somebody else's master.

## What is in the file, and what is not

IEEE Std 1815-2012 is a paid document and is not in this repository. What is
checked in here is narrower than the tables it came from:

| In the file | Not in the file |
|---|---|
| Code assignments (function codes, indication bit positions, qualifier octets) | The standard's descriptions of them |
| Canonical names (`DIRECT_OPERATE`, `NEED_TIME`) | Any clause text or commentary |
| Field widths in octets | The tables' layout or shading |
| Whether a function code draws a response | The sentence that says so |

The code assignments and names are the wire vocabulary a second implementation
needs in order to interoperate, and this package's own public source already
declares nearly all of them. The `kind` fields are one-word categories derived
from the tables (`index_range`, `count`, `reserved`), not quotations of them.

Tables covered: 4-2 (function codes), 4-3 (IIN bits), 4-4 (object prefix codes),
4-5 (range specifier codes), 4-6 (valid qualifier codes).

## Regenerating it

You need your own copy of the standard and `pypdf`, which is not a dependency of
this package:

```bash
pip install pypdf
python scripts/extract_conformance.py --pdf "IEEE 1815-2012.pdf" --write
```

To confirm the checked-in file still matches the standard without rewriting it:

```bash
python scripts/extract_conformance.py --pdf "IEEE 1815-2012.pdf" --check
```

CI cannot run either of those, because it has no copy of the standard. What CI
runs is `tests/test_conformance.py`, which needs only this file. That split is
the point: extracting the tables is a step someone takes deliberately, with the
standard in front of them, and the result is reviewed as a diff like any other
change. Checking the implementation against the result happens on every commit.

The script finds each table by its caption rather than by page number, so a
differently paginated PDF of the same edition still works. It refuses to write a
file when a table comes out short, on the grounds that a partial table is worse
than none: it would pass the tests it no longer covers.

## Divergences

Where this package departs from a table on purpose, the departure is listed in
`tests/test_conformance.py` next to the test that would otherwise fail, with the
reason. There are three:

- Seven function codes whose names the standard abbreviates and this package
  writes out (`INITIALIZE_APPL` against `INITIALIZE_APPLICATION`, and so on).
  The wire value is what has to agree.
- Two indication-bit names, for the same reason.
- IIN2.6 and IIN2.7, which are reserved and always zero, so there is nothing to
  set and no name worth having.

Anything not on that list is a failure. An undocumented divergence cannot pass
quietly, which is the only property here that matters.
