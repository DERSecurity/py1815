# Testing

Three rules, all learned the hard way.

## Wire behavior is pinned to literal octets

A test that builds a frame with this library and parses it back agrees with
itself even when both halves are wrong. Swapped addresses, inverted endianness,
wrong length semantics, a misplaced block checksum: a round trip is happy with
all of them.

So the framing suite carries a published frame this implementation reproduces
octet for octet, a hand-derived populated frame, and the CRC catalog check
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
| [opendnp3](https://github.com/dnp3/opendnp3), a C++ master, through its [Python bindings](https://pypi.org/project/dnp3-python/) | are the values right |
| [`dnp3`](https://github.com/stepfunc/dnp3) by Step Function I/O, a Rust master by different authors | are the values *and the quality octet* right, and does a refused control arrive as a refusal |
| Wireshark's dissector | is what went on the wire well-formed DNP3, and does every checksum verify |
| Suricata's parser | the same question, from a second independent parser |

The masters answer "does it say the right thing". The dissectors answer "is what
it emitted really DNP3". Those are different questions and neither subsumes the
other.

### The master is tested the same way

The master is also tested against outstations this project did not write. Its
tests against this library's own outstation cannot show that it reads the
standard correctly, because the two share their protocol code and would agree
with each other through any mistake they share.

| Outstation | Built on |
|---|---|
| `interop/opendnp3_outstation.py` | [opendnp3](https://github.com/dnp3/opendnp3), C++, through its [Python bindings](https://pypi.org/project/dnp3-python/) |
| `interop/rust-outstation` | [`dnp3`](https://github.com/stepfunc/dnp3) by Step Function I/O, Rust |

Both serve the same fixed points and print every control and time write they
receive. `interop/master_check.py` connects this library's master to each one
and checks two things:

- What the master decodes matches the points served: values, quality flags,
  a response that spans several fragments, events, and unsolicited responses.
- What the outstation printed matches what the master sent: each control with
  its index, operation and value in every variation, and the time write. This
  comes from the outstation's log, so it does not depend on this library's own
  decoding.

It also runs the master's automatic tasks against both: the startup sequence,
clearing the restart indication, writing the time, enabling unsolicited
reporting, and polling when events are indicated.

The first run found a real fault. The master read named points with the
index-list qualifiers (0x17 and 0x28), which a Subset Level 2 outstation is not
required to accept, and opendnp3 rejected them. The master now reads named
points as start-stop ranges (D82).

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

The Python bindings to opendnp3 store point values as bare scalars and discard
the quality octet, so the job driving that master checks values and not flags. The fixture serves one
point offline specifically to exercise quality, and that point reads back as a
number like any other there.

Closing that gap needed a peer that exposes quality rather than a change to the
harness, which is what Step Function I/O's `dnp3` is for. Quality is also pinned
at the object level by the unit suite.

### Who the peers are, and on what terms

The masters are other people's work, and this page leans on them, so they are
credited here and not only in the directory that runs them.

**[`dnp3`](https://github.com/stepfunc/dnp3)** is published by [Step Function I/O](https://stepfunc.io).
It is used under their public [license](https://github.com/stepfunc/dnp3/blob/main/LICENSE.txt), which is not an open-source
license and is better read than summarized. Step Function I/O has said that
reading this outstation with the crate in this repository's public continuous
integration is in line with that license ([#48](https://github.com/DERSecurity/py1815/issues/48)). That is a statement
about this repository. Anyone running the job from a fork, or using the crate
for anything else, should read the license for their own use; commercial
licensing is at <https://stepfunc.io/contact>. Nothing the crate provides is linked into,
distributed with, or depended on by this library.

**[opendnp3](https://github.com/dnp3/opendnp3)** is under the Apache License 2.0 and is driven through
the [`dnp3-python`](https://pypi.org/project/dnp3-python/) bindings. Its upstream is archived, which rules
it out as a dependency and not as a witness: a frame it parses is a frame that
was correct when it was maintained, and the wire format has not moved. This
library also took two things from it directly. The ten-second default for how
long a select stays armed is opendnp3's. So is the name `TOO_MANY_OPS` for
control status 8: other spellings circulate, and the one that interoperates is
the one opendnp3 publishes.

## Silence is tested as an input

An outstation that relays commands has no opinion about what a device should
do when its master stops talking: the last value written stays in force until a
master writes another. That is easy to break without noticing, since the code
that would break it is a timer nobody is watching.

`tests/test_master_silence.py` commands an output and then lets time pass with
no request, through each thing that happens while a master is away: the
session's clock moving on, the caller's own loop still polling for events and
freezing counters, a select left to expire, and the listener closing a
connection it has heard nothing on. Afterwards the binding has been called
exactly once. Any timer added to the library has to leave those passing.

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
apply (the outstation never requests link confirmation, offers no UDP, has no
serial port, and so on). Two checks hold the catalog and the tests
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

## The suite also runs where an integer is 32 bits

The library is meant to run on small ARM controllers, and some of those are
32-bit. A `struct` format that used a native size, an integer assumed to be 64
bits wide, or a time that stops fitting in 2038 would pass on every 64-bit
machine and fail there. So the `test-arm32` job runs the whole unit suite on
Python 3.12 for `linux/arm/v7`, emulated with QEMU, and begins by checking that
the interpreter it was handed really is 32-bit, so that it cannot pass by
running somewhere else.

It runs the tests and nothing more. Ruff, mypy and the changelog check read the
source and answer the same on any machine, so they stay in the `test` job, and
this one installs the package, `pytest` and `pytest-asyncio`. Emulation makes it
the slowest job in the workflow, at several minutes, which is why it runs one
Python version: the question it asks is about the platform.

When it was first run the whole suite passed, and nothing in the library had to
change. The wire encoders name little-endian and an explicit width in every
`struct` format, and a DNP3 time is a Python integer of milliseconds that never
passes through a C `time_t`. The job is there so that stays true.

The same job then runs `scripts/measure_event_memory.py`, which puts the memory
a full event buffer costs on that platform in the log; see
[Memory on a small controller](der.md#memory-on-a-small-controller). A second
job, `image-arm`, builds the Docker image for `linux/arm64` and `linux/arm/v7`
and starts the command in each.

## The master, its API and the console

The master is tested the way the outstation is, and from the same argument.

- **From octets.** The decoder that reads a response's objects is tested from
  octets written out by hand, and the requests the master builds are pinned to
  theirs. It is not tested by encoding with this library and decoding again,
  which would agree with itself through any mistake the two shared.
- **The association against frames**, with no socket and an injected clock:
  sequence numbers, a response of several fragments, confirmations, silence,
  unsolicited responses, and who is speaking.
- **Against this library's outstation**, in one process and over a real
  socket. These show the two halves agree and that the master's bookkeeping is
  right. They are not evidence that either reads the standard correctly,
  since both stand on the same layers.
- **The API against its description.** `tests/test_master_openapi.py` fails
  when an operation exists that the OpenAPI document does not describe, when
  the document committed is not the one the description builds, and when what
  the service answers to each documented example does not fit what the
  document says it answers.
- **The console in a browser.** `tests/test_master_console.py` starts a
  simulated DER, the service and a headless browser, and checks the page: that
  it shows what the service reports, that its controls do what they say, that
  its tables hold still while values change, that a name is shown as text and
  never run, and that it asks the outside world for nothing. A machine with no
  Chrome, Chromium or Edge skips these, and says so. CI has one, and there a
  skip is a failure. Point `PY1815_BROWSER` at a browser to name one.

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

The 32-bit run needs Docker with QEMU's ARM emulation registered. With that in
place it is the command the `test-arm32` job runs:

```bash
docker run --rm --platform linux/arm/v7 -v "$PWD":/src:ro -w /src python:3.12-slim \
  sh -ec 'pip install -q . pytest pytest-asyncio && pytest -q -x -p no:cacheprovider'
```
