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

## The IEEE 1815.2 point tables

`ieee-1815-2-2025.json` is the DER profile's point list: every binary and
analog input and output and every counter IEEE Std 1815.2-2025 defines, with
the columns an implementation needs. It is read from the standard's Profile
Companion Data Point Tables, a workbook the standard declares normative and
which IEEE distributes without charge alongside the standard:

    https://standards.ieee.org/wp-content/uploads/import/download/1815.2-2025_downloads.zip

**The file is generated, not committed.** IEEE's terms for that download are
explicit: a copy may be retrieved for personal use, and "you may not further
copy, prepare, and/or distribute copies of the Materials, nor significant
portions of the Materials, in any form, without prior written permission from
IEEE". A machine-readable form of the whole point list is a significant
portion in another form, and a public repository is distribution, so the
workbook and the file made from it are both in `.gitignore` and stay on the
machine that downloaded them. The standard's front matter adds that MESA and
the DNP Users Group retain the rights in the underlying content and license
it to IEEE, so permission, if sought, may involve more than one party.

What ships is the extractor and the tests. Anyone with the workbook
regenerates the file in one command (below), and every check in
`tests/test_profile_tables.py` then runs; on a checkout without the file those
tests skip, which is their expected state in CI.

For the predecessor profile, DNP3 Application Note AN2018-001, a different
route exists: EPRI, a co-author of the profile, publishes its complete point
map under a BSD-style license that permits redistribution with the copyright
notice retained and no use of EPRI's name for endorsement. That is a
legitimate source for a committed table of the predecessor profile, with the
notice, and it is the reason the profile machinery is designed to load either.

### What is kept and what is not

| In the file | Not in the file |
|---|---|
| Index, absolute or relative to a named block | The per-device "EUT capabilities" columns, a blank template for a device profile document |
| Name, section heading, purpose | The Key sheet's prose and the system diagrams |
| Default event class, range, multiplier, offset, units | |
| The IEC 61850 attribute each point originates from | |
| The paired point, mandatory flags for 1815.2 and 1547-2018 | |
| The Key sheet's block-start table, with per-unit block lengths | |

Relative indices are written as `<Block>_<KIND>+<offset>` in the index column
and are kept that way; the loader resolves them against the Key's starts for
a DER of known composition. Which points are relative is the workbook's
decision, not this file's.

### Where the workbook disagrees with itself

Three things in the workbook are inconsistent, and the file records the rows
rather than the summary in each case, because the rows are the profile:

- **The auto-discovery block.** Clause 5.2 says the block starting indices are
  published in band from analog input 65000, and the point rows agree. The Key
  sheet's own entry for that block says 60000. `index_points` records what the
  rows say; the Key's figure stays where the Key put it.
- **Three block lengths.** The Key sheet states each equipment block's per-unit
  length, and the DER unit, inverter and battery analog input blocks each hold
  one more point than it says. `per_unit_observed` is recorded beside the Key's
  `per_unit`; a loader sizing a block should use the larger.
- **Two spellings of a reference.** The paired-point columns write some
  equipment references kind-first (`AO+Meter+3`) where the index column would
  say `Meter_AO+3`, the counter sheet calls the meter block `HM` (the
  predecessor profile's symbol), and one reference calls the experimental block
  `EX`. All are normalized to the index column's spelling so a loader resolves
  one grammar.

The `AI65535 Maximum Points` row marks the end of the index space and is not a
point; it is left out.

One more thing the workbook does that the file does not repeat: each equipment
sheet states every per-unit block twice, once as unit #1 (`Meter_AI+3`) and
once as a generic unit #m (`Meter_AI+mhai(m)+3`) with `. . .` rows between.
The second is the first restated with an instance term. The extractor checks
that the two agree on every offset, keeps the unit #1 rows, and refuses the
sheet if they differ. They agree throughout, including on the three block
lengths the Key sheet gets wrong, which is a second witness that the rows are
right and the Key is not. An index cell that is neither a point, a restatement
nor a heading is an error, so a typo or a later edition's spelling cannot drop
a point without a trace.

### Regenerating it

```bash
pip install openpyxl
python scripts/extract_profile.py --cdpt "IEEE 1815.2-2025 Profile Companion Data Point Tables.xlsx" --check
python scripts/extract_profile.py --cdpt "IEEE 1815.2-2025 Profile Companion Data Point Tables.xlsx" --write
```

The extractor locates every column by its header text and refuses a sheet
whose headers have moved, so a later edition of the workbook fails loudly
rather than mapping a column to the wrong field. `tests/test_profile_tables.py`
holds the checked-in file to the properties a loader relies on -- unique
indices, resolvable blocks and references, block lengths consistent with the
Key -- and runs without the workbook.
