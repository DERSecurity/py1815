# Testing

Two rules, both learned the hard way.

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

## Running them

```bash
pytest                      # the unit suite, no network
ruff check src tests interop
ruff format --check src tests interop
mypy src
```

The interoperability jobs need peers that are not installed by the dev extras,
so they run in continuous integration rather than locally. See
`.github/workflows/interop.yml`.
