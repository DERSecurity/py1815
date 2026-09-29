<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/DERSecurity/py1815/main/docs/assets/satori-dark.png">
    <img src="https://raw.githubusercontent.com/DERSecurity/py1815/main/docs/assets/satori.png" alt="Satori" height="88">
  </picture>
</p>

<p align="center">
  <a href="https://dersec.io/"><picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/DERSecurity/py1815/main/docs/assets/dersec-white.png">
    <img src="https://raw.githubusercontent.com/DERSecurity/py1815/main/docs/assets/dersec-dark.png" alt="DER Security" height="32">
  </picture></a>
</p>

# py1815

**The DNP3 (IEEE 1815) outstation of [Project Satori](https://open-satori.org)** —
an open-source project led by the SunSpec Alliance, DER Security,
and industry consortium members.

[![Tests](https://github.com/DERSecurity/py1815/actions/workflows/test.yml/badge.svg)](https://github.com/DERSecurity/py1815/actions/workflows/test.yml)
[![License](https://img.shields.io/github/license/DERSecurity/py1815)](https://github.com/DERSecurity/py1815/blob/main/LICENSE)
[![Project Satori](https://img.shields.io/badge/Project-Satori-b7410e)](https://open-satori.org)

A DNP3 (IEEE 1815) outstation in pure Python.

**Status: early development.** The protocol layers, the listener, controls and the event path are
implemented and tested: a master reads classes 1 to 3, confirms what it was sent, and is told
through the indication bits what is still waiting. An answer too large to send at once is a
conversation -- the master confirms each fragment and the next follows -- and a provider that says
where its own objects end has its point map split the same way. Not yet done are unsolicited
responses, which is outstation-initiated traffic, and the point-map loader. The first release is `0.1.0`, and the API is not
stable: while the major version is `0`, a minor bump may carry a breaking change.

## What it does

An outstation -- the side a SCADA master connects *to*. It reports measurements and accepts
commands. Subset Level 2 is the floor, over TCP and TLS; where the IEEE 1815.2 DER profile needs
more -- a 50 kW setpoint does not fit the 16-bit analog output Level 2 offers -- the extra
variations are served and named in the device profile.

| Layer | Module | Contents |
|---|---|---|
| Checksum | `crc` | CRC-16/DNP |
| Data link | `link` | FT3 framing, control byte, addresses, stream reader |
| Transport | `transport` | Segmentation and reassembly |
| Application | `application` | Control octet, function codes, internal indications, object headers |
| Objects | `objects` | Static binary and analog inputs with quality flags |
| Controls | `control` | Output commands and status, and the command status vocabulary |
| Events | `events` | Class 1 to 3 buffers, deadbands and confirmation |
| Session | `session` | One master association: octets in, octets out |

Each layer is testable without the ones above it. The session does no I/O at all -- it takes
the bytes that arrived and returns the bytes to send -- so protocol behavior is pinned against
literal frames rather than against a socket.

## Point maps

The library encodes and decodes the wire format. It does not embed a point map, and it does not
apply scaling: values arrive already in the representation they should take on the wire.

That separation is deliberate. The IEEE 1815.2 DER profile assigns specific indices to specific
measurements, and those tables are distributed to DNP Users Group members rather than published,
so a library that embedded them could not be shared. Instead the library defines the map format
and reads a table supplied by the caller.

## Documentation

The full documentation site, including an introduction to how DNP3 itself works
and an API reference generated from the source:

<https://dersecurity.github.io/py1815/>

```
pip install -e ".[docs]"
mkdocs serve                 # http://127.0.0.1:8000
```

## Development

```
pytest            # tests
ruff check .      # lint
ruff format --check .
mypy --strict src
mkdocs build --strict        # docs, warnings are errors
```

All five run in CI and all five must pass.

## Testing approach

Two rules, both learned the hard way:

- **Wire behavior is pinned to literal octets**, not to round trips. A test that builds a frame
  with this library and parses it back agrees with itself even when both halves are wrong --
  through swapped addresses, inverted endianness or a misplaced checksum. The framing tests
  carry published frames and hand-derived vectors, and the CRC is pinned to its catalogue check
  value.
- **Interoperability is tested against other implementations**, not against a peer written from
  the same understanding of the specification, which would share its misreadings. CI reads this
  outstation with a master built on a separately developed stack; see `interop/`.

## Project Satori

*Any certified DER. Any utility program.* Satori — “awakening” — is an
open-source initiative to make any certified DER a compliant participant in
utility DER programs: point it at a UL 1741 SB device — inverter, battery, or
EV — and it joins a program without a firmware rewrite.

A device joins a program by speaking whatever protocol the program is run on,
and that is not one protocol. IEEE 2030.5 is what most North American and
Australian utility programs specify. DNP3 is what a great deal of existing
distribution SCADA already speaks, and IEEE 1815.2 is the DER profile built on
it. A device that can only do one of them is a device that fits some programs
and not others, so Satori covers both:

| Project | Role |
|---|---|
| [PySunSpec2](https://github.com/sunspec/pysunspec2) | SunSpec Modbus reference library, used in more than 80% of inverter-based products shipped globally |
| [py20305](https://github.com/DERSecurity/py20305) | IEEE 2030.5 client stack with CSIP and CSIP-AUS support, and a SunSpec Modbus bridge |
| **py1815** (this repository) | DNP3 outstation stack, targeting the IEEE 1815.2 DER profile |
| Satori Scout | Phone app that finds DER on a network: a SunSpec Modbus sweep of the local subnet, and IEEE 2030.5 discovery over mDNS. A reference implementation rather than an open-source component |

Project website: <https://open-satori.org>

## License

Apache-2.0. See [LICENSE](https://github.com/DERSecurity/py1815/blob/main/LICENSE) and [NOTICE](https://github.com/DERSecurity/py1815/blob/main/NOTICE).
