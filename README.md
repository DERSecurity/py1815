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
assembled from the profile's point tables and runs from one command, below. Unsolicited
responses, which is outstation-initiated traffic, are there for a session built to send them,
and off otherwise. The first release
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
| DER functions (clause 6) | Active power limit, charge/discharge, constant vars, constant power factor, volt-var and volt-watt act on the simulation. Every other function reports "not supported" through its supports point, as 6.1.1 requires of a function that is not implemented. A disabled function's inputs are sent without the ONLINE flag |
| Curves (6.1.3) | Ten curves behind the multiplexed block, with the selector, referenced-indicator, locking and curve-type rules. Volt-var and volt-watt follow theirs; hysteresis is not followed |
| Schedules, equipment block measurements | Resolved in the map, not simulated |
| DNP3 Subset Level 2 conformance | The DNP Users Group's IED certification procedures (version 3.1) are carried out in CI, section by section, against a Level 2 configuration. Self-assessed, not certified |
| DER profile test procedure | EPRI's test procedure for the profile (report 3002016144) is carried out in CI against the simulated DER. The schedule procedure does not apply. Self-assessed |
| Technical bulletins and application notes | Each of the DNP Users Group's bulletins and notes is cataloged as acted on or not applicable. Acted on: the updated transport reception table, special addresses, error indications, relative time for events stamped before the clock is set, LAN time synchronization, validation of incoming data, disabling function codes, and the rules for unsolicited responses |
| Unsolicited responses (optional in the profile) | Implemented, off by default: `py1815-der run --unsolicited`, or `session(unsolicited=True)` |
| Floating-point variations, device attributes (both optional in the profile), secure authentication | Not implemented |

`py1815-der profile` writes the outstation's DNP3 Device Profile document (schema version
2.12.00), generated from the running configuration: its point lists, limits and
implementation table. See [Serving a DER](https://dersecurity.github.io/py1815/der/).

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
  carry published frames and hand-derived vectors, and the CRC is pinned to its catalog check
  value.
- **Interoperability is tested against other implementations**, not against a peer written from
  the same understanding of the specification, which would share its misreadings. CI reads this
  outstation with two masters built on separately developed stacks: [opendnp3](https://github.com/dnp3/opendnp3), in
  C++, through its Python bindings, and the [`dnp3`](https://github.com/stepfunc/dnp3) crate by
  [Step Function I/O](https://stepfunc.io), in Rust. Wireshark's and Suricata's dissectors read
  a capture of the same traffic. See `interop/` and [Acknowledgments](#acknowledgments).

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

## Acknowledgments

What this library can say about interoperating rests on implementations other people wrote.

- **[`dnp3`](https://github.com/stepfunc/dnp3) by Step Function I/O** is the Rust master in the interoperability suite.
  It is the peer that checks the quality flags and that a refused control arrives as a refusal,
  which the other master cannot do, so it carries a real share of the verification. It is used
  under Step Function I/O's public [license](https://github.com/stepfunc/dnp3/blob/main/LICENSE.txt), which is not an open-source license.
  Step Function I/O has said that reading this outstation with it in this repository's public CI
  is in line with that license ([#48](https://github.com/DERSecurity/py1815/issues/48)). That statement is about this repository: anyone
  running the job from a fork, or using the crate anywhere else, should read the license for
  their own use. Commercial licensing is at <https://stepfunc.io/contact>.
- **[opendnp3](https://github.com/dnp3/opendnp3)** is the C++ master in the suite, driven through the
  [`dnp3-python`](https://pypi.org/project/dnp3-python/) bindings. It is also where two of this library's choices come
  from: the ten-second default for how long a select stays armed, and the name `TOO_MANY_OPS`
  for control status 8, which is the spelling that interoperates.
- **Wireshark** and **Suricata** supply the two independent dissectors that read a capture of
  everything the suite puts on the wire.

## License

Apache-2.0. See [LICENSE](https://github.com/DERSecurity/py1815/blob/main/LICENSE) and [NOTICE](https://github.com/DERSecurity/py1815/blob/main/NOTICE).
