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
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/DERSecurity/py1815/blob/main/LICENSE)
[![Project Satori](https://img.shields.io/badge/Project-Satori-b7410e)](https://open-satori.org)

A DNP3 (IEEE 1815) outstation in pure Python.

**Status: early development.** The protocol layers, the listener, controls and the event path are
implemented and tested: a master reads classes 1 to 3, confirms what it was sent, and is told
through the indication bits what is still waiting. An answer too large to send at once is a
conversation -- the master confirms each fragment and the next follows -- and a provider that says
where its own objects end has its point map split the same way. An IEEE 1815.2 DER outstation is
assembled from the profile's point tables and runs from one command, below. Not yet done are
unsolicited responses, which is outstation-initiated traffic. The first release
is `0.1.0`, and the API is not stable: while the major version is `0`, a minor bump may carry a
breaking change.

## Run an IEEE 1815.2 DER outstation

`py1815-der` serves a simulated DER as an IEEE 1815.2 outstation: the profile's own point map,
measurements that move, energy counters that freeze, and four DER functions a master can enable
and watch take effect.

Natively, with Python 3.11 or later:

```
git clone https://github.com/DERSecurity/py1815 && cd py1815
pip install .
py1815-der tables fetch     # once: downloads the profile's point tables from IEEE
py1815-der run              # listens on 127.0.0.1:20000
```

In Docker:

```
docker build -t py1815-der .
docker run --rm -v py1815-tables:/data py1815-der tables fetch
docker run --rm -p 20000:20000 -v py1815-tables:/data --name der py1815-der
```

Then, from a second terminal, ask it for everything once:

```
py1815-der poll                     # native
docker exec der py1815-der poll     # Docker
```

```
127.0.0.1:20000 answered in 2 fragment(s): 81 binary inputs, 4 counters, 4 frozen counters, 343 analog inputs
  16 event(s); indications 0x90 0x00
  AI536                60 Hz  System Meter Frequency
  AI537             36144 Watts  System Meter Active Power
  AI538             12048 Watts  System Meter Active Power A
  ...
```

Any DNP3 master can connect in place of `poll`. The outstation's link address is 1024 and it
expects master address 1 (`--outstation-address`, `--master-address`). The native command listens
on loopback only, because this entry point serves plaintext with no peer allow-list; pass
`--bind 0.0.0.0:20000` to reach it from another host. `py1815-der points` lists every point
served, and `py1815-der run --help` the rest of the options. The Docker command above publishes
the port on every interface of the host; write `-p 127.0.0.1:20000:20000` to keep it local.

**Why there is a download step.** IEEE 1815.2 specifies its points in a companion workbook that
IEEE distributes without charge and does not permit anyone else to redistribute. So neither this
repository nor the Docker image contains it: `tables fetch` downloads it from IEEE to the machine
it runs on (into `~/.py1815/`, or the `/data` volume) and reads it into the form the outstation
loads. If that machine cannot reach IEEE, download
[the archive](https://standards.ieee.org/wp-content/uploads/import/download/1815.2-2025_downloads.zip)
elsewhere and run `py1815-der tables build <workbook>.xlsx`. Keep both files out of anything you
publish.

**What it implements.** Assessed against the standard by this project's own tests, not by a
certification body:

| IEEE 1815.2 | Status |
|---|---|
| Implementation table (clause 5.4): binary inputs and events, output status, control relay output blocks, counters, frozen counters and their events, analog inputs and events, analog output status and commands, time write, delay measurement, class 0 to 3 reads, restart indication | Implemented |
| Point numbering and indexing (5.2), including equipment blocks resolved for a stated number of meters, DER units, inverters and batteries, and the block starting indices advertised from AI65000 | Implemented |
| Event classes, class 0 membership and reporting modes (5.3, 5.6) | Implemented as the profile selects them |
| Counter freezing (5.6.3): periodic from startup, period set by the master, never cleared, logged as timestamped events | Implemented |
| Every point the tables mark mandatory | Served by the simulated DER |
| DER functions (clause 6) | Active power limit, charge/discharge, constant vars and constant power factor act on the simulation. Every other function reports "not supported" through its supports point, as 6.1.1 requires of a function that is not implemented |
| Curves (6.1.3) | The multiplexed curve block stores and reads back ten curves; no curve-based function uses them yet |
| Schedules, equipment block measurements | Resolved in the map, not simulated |
| Unsolicited responses, floating-point variations, device attributes (all optional in the profile), secure authentication | Not implemented |

To put a real device behind the same outstation, bind its values to the profile's points instead
of the simulation's: see [Serving a DER](https://dersecurity.github.io/py1815/der/).

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
| Objects | `objects` | Binary inputs, analog inputs and counters, static and event, with quality flags |
| Controls | `control` | Output commands and status, and the command status vocabulary |
| Events | `events` | Class 1 to 3 buffers, deadbands and confirmation |
| Session | `session` | One master association: octets in, octets out |
| DER profile | `profile` | The IEEE 1815.2 point map, a builder that turns a map and a binding into an outstation, and a simulated DER |

Each layer is testable without the ones above it. The session does no I/O at all -- it takes
the bytes that arrived and returns the bytes to send -- so protocol behavior is pinned against
literal frames rather than against a socket.

## Point maps

The protocol layers encode and decode the wire format. They do not embed a point map, and they do
not apply scaling: values arrive already in the representation they should take on the wire.

That separation is deliberate. The IEEE 1815.2 DER profile assigns specific indices to specific
measurements, and the tables that say which are IEEE's: free to download, not free to
redistribute, so a library that embedded them could not be shared. Instead `py1815.profile`
defines the map format, reads the tables from the caller's own copy, and does the scaling they
call for, so a caller binds values in engineering units and never touches an encoder.

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
