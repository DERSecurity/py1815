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
