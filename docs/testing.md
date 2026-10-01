# Testing

Three rules, all learned the hard way.

## Wire behavior is pinned to literal octets

A test that builds a frame with this library and parses it back agrees with
itself even when both halves are wrong. Swapped addresses, inverted endianness,
wrong length semantics, a misplaced block checksum: a round trip is happy with
all of them.

So the framing suite carries a published frame this implementation reproduces
octet for octet, a hand-derived populated frame, and the CRC catalogue check
value, which is the one assertion an implementation that is self-consistently
wrong cannot satisfy.

The transport and application layers assign FIR and FIN to opposite bits, which
is exactly the kind of detail a self-agreeing test will never catch, so both are
pinned to literal octets.

## Interoperability is tested against other implementations

A peer written from the same reading of the specification shares its
misreadings. So continuous integration reads this outstation with
implementations that have no relationship to it, chosen so that no two of them
are the same codebase wearing different clothes.

| Peer | What it answers |
|---|---|
| A C++ master, through its Python bindings | are the values right |
| A Rust master, by different authors | are the values *and the quality octet* right, and does a refused control arrive as a refusal |
| Wireshark's dissector | is what went on the wire well-formed DNP3, and does every checksum verify |
| Suricata's parser | the same question, from a second independent parser |

The masters answer "does it say the right thing". The dissectors answer "is what
it emitted really DNP3". Those are different questions and neither subsumes the
other.

### The function code sweep

A separate driver walks the function code space over a real connection and
checks each reply against a declared expectation: the link-layer functions, the
reads, the controls this outstation refuses, every function it does not
implement, and the ones that must draw no reply at all.

It also records the exchange, so covering more function codes is the same act as
capturing more of the wire format for the dissectors to read.

That sweep is what found the outstation answering four of the five function
codes the standard says must draw no response, which is the first thing the
interoperability work turned up in the library rather than in the harness.

### What the peers cannot check

The C++ master stores point values as bare scalars and discards the quality
octet, so the job driving it checks values and not flags. The fixture serves one
point offline specifically to exercise quality, and that point reads back as a
number like any other there.

Closing that gap needed a peer that exposes quality rather than a change to the
harness, which is what the Rust master is for. Quality is also pinned at the
object level by the unit suite.

## The standard is checked mechanically, not remembered

The function codes, indication bits and qualifier codes here were transcribed
from IEEE Std 1815-2012 by hand. Nothing checked that the transcription was
complete, and it was not: function code 31, `ACTIVATE_CONFIG`, was missing.

The sweep above could not have found that. Its cases are written out one per
function code, and nobody writes a case for a code they do not know exists. A
gap in a hand-written list of checks is invisible to the checks in the list.

So the tables are checked against the standard's own tables instead.
`conformance/ieee-1815-2012.json` holds the code assignments, names and field
widths read out of the document, and the suite diffs this package against them:

| Checked | Against |
|---|---|
| Every assigned function code is named, none invented, names agree | Table 4-2 |
| The codes that draw no response are exactly the five marked so | Table 4-2 |
| Every unimplemented request code is refused rather than dropped | Table 4-2 |
| Indication bits carry the mask for the position they are given | Table 4-3 |
| Index prefix widths | Table 4-4 |
| Range field widths, from both sides | Table 4-5 |
| Every accepted qualifier is one the standard permits | Table 4-6 |
| The sweep has a case for every assigned request code | Table 4-2 |

The last row is the one that closes the hole `ACTIVATE_CONFIG` fell through: the
sweep no longer has to notice its own gaps.

Two of these are worth separating from the rest, because they fail on wire
behavior rather than on a name. The no-response codes are checked behaviorally,
one case per code, by sending each one and asserting silence. The range field
widths are checked from both sides, because a parser that reads too few octets
does not raise; it leaves the remainder to be misread as the next object header.

Where this package departs from a table on purpose (seven names the standard
abbreviates, two indication-bit names, and the two reserved bits that are always
zero) the departure is listed beside the test with its reason. Anything not on
that list fails, which is the only property here that matters.

The standard is a paid document and is not in the repository, so regenerating
the tables is a step someone takes deliberately, with their own copy:

```bash
pip install pypdf
python scripts/extract_conformance.py --pdf "IEEE 1815-2012.pdf" --check
```

`conformance/README.md` covers what that file holds and what it deliberately
does not.

## The certification procedures are carried out section by section

The DNP Users Group's *DNP3 IED Certification Procedure* (version 3.1) is what a test
house follows to certify a Subset Level 2 outstation. The files `tests/test_ied_*.py`
carry it out: a test master built in `tests/ied_harness.py` sends each request as
octets, over the link layer and in one file over a real TCP listener, and the
assertions are the pass criteria of the section. A test is named for the section it
performs, so `test_8_2_1_2_4_...` is section 8.2.1.2.4.

The harness shares nothing with the library above the frame and object encoders, and
it parses responses itself, for the reason the first section of this page gives: a
master built from the session's own decoder would agree with the session's mistakes.

`tests/test_ied_coverage.py` is the catalog. Every section of the procedures appears
there once, either with the tests that carry it out or with the reason it does not
apply (the outstation never requests link confirmation, does not send unsolicited
responses, has no serial port, and so on). Two checks hold the catalog and the tests
together: a section listed as tested must have a test, and a test may not claim a
section the catalog has not accounted for. Adding a feature that makes a section
applicable means moving its entry and writing its test in the same change.

The procedures are the Users Group's and are not in the repository. The tests refer to
them by section number and describe what they check in their own words.

This is the project's own assessment. It is not a certification, and the device
profile the outstation generates does not claim one.

## Bulletins and application notes are checked one document at a time

The standard has been corrected and clarified since it was published, in the DNP Users
Group's technical bulletins and application notes: a replacement for the transport
reception table, rules for the special addresses, which error indication answers which
fault, how events stamped by an unset clock are reported, a checklist for validating
what arrives. `tests/test_technical_bulletins.py` holds one group of tests per
document, each test named for it (`test_tb2013_003_...`), and
`tests/test_bulletin_coverage.py` lists every bulletin and note as tested, or as asking
nothing of this outstation and why. Several are carried out by the certification
procedures and the catalog points there.

One check needs a file the repository does not hold. The Users Group publishes the
subset definitions as a workbook: for every object, which requests an outstation of
each level must accept. `tests/test_subset_tables.py` reads it, sends every request
marked for Level 2, and requires that none is refused as unsupported. It skips unless
the workbook is named:

```bash
PY1815_SUBSET_TABLES="Request-Response Subset Tables.xlsx" pytest tests/test_subset_tables.py
```

## The DER profile's test procedure runs against the simulated DER

EPRI's *Test Procedure for Validating DNP Application Note AN2018-001 in Distributed
Energy Resources* (report 3002016144) tests an outstation the way a controlling station
uses the profile: read a function's points, write its settings and read them back,
enable and disable it, and edit curves through the window all curves share.
`tests/test_epri_der_procedures.py` carries it out, with each test named for the
procedure's identifier (`test_mon_001_...` is MON-001) and the twenty-one mode
procedures as one parametrized test.

The procedures carry no point list of their own. Which input reads an output back,
which points make up a function and which input says it is supported are read from the
tables the outstation was built from, and a point counts as supported if the outstation
serves it. Each procedure therefore runs twice: against synthetic tables that give the
simulated DER's points invented pairings, which is what CI has, and against the IEEE
1815.2 tables on a machine that holds them, where it tests the published pairings.

For a function the simulated DER implements, the procedure is carried out in full,
including that its inputs are sent without the ONLINE flag while it is disabled. For
one it does not, the procedure checks that the function says so, cannot be enabled, and
serves none of its points.

`tests/test_epri_coverage.py` lists every procedure in the report as tested or not
applicable, and records where the suite departs from the report. The report predates
IEEE 1815.2; where they differ (the status for a write to a locked curve, which input a
command is read back at) the suite follows the standard.

## The DER profile is tested against tables invented for the purpose

The IEEE 1815.2 point tables may not be redistributed, so the repository has none and CI
has none. The profile machinery is therefore tested against synthetic tables of the same
shape, built in `tests/profile_fixtures.py`: a small one with every kind of point and one
repeating block, and one generated from the simulated DER's own binding so the simulation,
the builder, the session, the listener and the probe run together over TCP.

Tests that need the real tables are marked to skip when
`conformance/ieee-1815-2-2025.json` is absent, which is its state in CI and on a fresh
checkout. They run on any machine that has regenerated it (see
[`conformance/README.md`](https://github.com/DERSecurity/py1815/blob/main/conformance/README.md)),
and they are the ones that check the profile itself: that every mandatory point is served,
that only the implemented functions report as supported, and that the advertised block
starts agree with where the blocks resolve. A change to `py1815.profile` should be run
there before it is merged.

## Running them

```bash
pytest                      # the unit suite, no network
ruff check src tests interop scripts
ruff format --check src tests interop scripts
mypy src
```

The interoperability jobs need peers that are not installed by the dev extras,
so they run in continuous integration rather than locally. See
`.github/workflows/interop.yml`.
