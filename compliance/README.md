# Conformance report

This directory holds the report that [dnp3c](https://github.com/stepfunc/dnp3c), Step
Function I/O's DNP3 conformance test harness, wrote when this repository ran it against
the py1815 outstation.

| | |
|---|---|
| Tool | dnp3c 0.2.0 |
| Procedures | DNP3 IED Certification Procedure, revision 3.1 rev 1 (13 September 2022) |
| Subset level | 2 |
| Connection | TCP |
| Device | A Subset Level 2 configuration of this library, served by [`interop/conformance_outstation.py`](../interop/conformance_outstation.py) and configured by [`interop/dnp3c/device.ini`](../interop/dnp3c/device.ini) |

Every procedure that runs passes. None passes with a warning, and none is excluded. The
rest are skipped because the outstation does not have the feature they test, because they
are the test for a device without a type the outstation has, or because they apply to
another subset level. [`docs/conformance.md`](../docs/conformance.md) lists each skip
and why.

This is not a certification. Certification is carried out by the DNP Users Group's
authorized test laboratories. The report is not a statement by Step Function I/O about
this library either. It is what their tool reported when this project ran it.

## Files

| File | What it is |
|---|---|
| `report.html` | dnp3c's report, linking to each procedure's log |
| `<procedure>/log.html` | Every step, frame and check of one procedure |
| `outcomes.json` | Each procedure's outcome, in the words of the program that drove the harness |

## Keeping it current

The report is copied from a run, never edited. `tests/test_conformance_record.py`
checks that its outcomes are the ones `interop/dnp3c/expected.json` has on record, and
that every log the report links to is here. To refresh it, run the procedures as
[`interop/dnp3c/README.md`](../interop/dnp3c/README.md) describes, confirm the run is
the one on record with `python interop/dnp3c/check_outcomes.py`, and copy the run's
`results/3.1r1/L2/report.html`, `outcomes.json` and each `<procedure>/log.html` here.

## License

The report and the logs are written by dnp3c, and carry its descriptions of each step.
dnp3c is licensed under the GNU General Public License v3.0 only, so this directory is
licensed the same way as [`interop/dnp3c`](../interop/dnp3c), under the GNU General
Public License, version 3 only. [`interop/dnp3c/LICENSE`](../interop/dnp3c/LICENSE) is its
text. Nothing here is part of the library, its wheel or its source distribution.
