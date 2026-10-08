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
measurements that move, energy counters that freeze, and a few DER functions a master can enable
and watch take effect. The simulation is there to exercise the points. It is not a model of a
DER: how a DER carries out a function is out of scope for this package, and belongs to the
device or simulator bound behind the outstation.

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

## Quickstart: a master and a console on the simulated DER

`py1815-master` is a DNP3 master for testing outstations, with a web console. To see one
reading the simulated DER, with the point tables fetched as above:

```
py1815-master console --demo --open                   # reads
py1815-master console --demo --open --allow-control   # and can operate outputs
```

That starts a simulated IEEE 1815.2 DER, a master connected to it, and the console at
<http://127.0.0.1:8815/>, in one process.

To connect a master to a simulated DER that is already running, as you would to a real
outstation, use two terminals:

```
py1815-der run                      # terminal 1: the outstation, on 127.0.0.1:20000
```

```
py1815-master console --outstation der=127.0.0.1:20000 --profile \
    --integrity-interval 30 --event-interval 2 --open          # terminal 2
```

`--outstation` names the outstation and says where it listens. `--profile` says it is an
IEEE 1815.2 DER, so its points are shown by name and the console can list the profile's points
it has not reported. The two intervals repeat an integrity poll and an event poll. Without
them the master reads the outstation once when it connects, fetches events when a response
says some are waiting, and otherwise sends what you ask for from the Commands tab; with
`--manual` it sends only that. The link addresses default to the simulated DER's
(`--outstation-address 1024 --master-address 1`).

Every setting can also be kept in a JSON file. `py1815-master config` prints a complete one
to edit, and `--config FILE` loads it. See `docs/master-config.md`.

Or with Docker, which needs nothing installed but Docker:

```
git clone https://github.com/DERSecurity/py1815 && cd py1815
docker compose up
```

and open <http://localhost:8815/>. That fetches the point tables from IEEE into a volume the
first time, starts the simulated DER as an outstation in one container, and starts the master
with its API and console in another, connected to it. `compose.yaml` says what each part
does and how to reach the console from another machine. To run the master's image by itself
against an outstation of your own:

```
docker build --target master -t py1815-master .
docker run --rm -p 127.0.0.1:8815:8815 py1815-master \
    console --bind 0.0.0.0:8815 --new-token --outstation lab=192.0.2.10:20000
```

It prints the address to open, with a token made for that run.

In the console:

- **Overview** shows the connection and the internal indications of the last response.
- **Points** shows every point by type, with its value, flags and age.
- **Commands** sends a scan, a read or any other request, and shows what came back.
- **Events** lists changes as they are reported, and **Traffic** every frame, read layer by
  layer.

The same master answers a script. Over HTTP, while the console is running:

```
curl -s http://127.0.0.1:8815/api/scan -H 'Content-Type: application/json' \
     -d '{"outstation": "der", "kind": "integrity"}'
```

And from Python, with no console at all:

```python
import asyncio
from py1815.master import Master

async def main():
    async with Master() as master:
        der = await master.add("der", host="127.0.0.1", port=20000)
        poll = await der.integrity_poll()
        print(poll.outcome.value, len(poll.objects), "objects")
        print(der.store.analog_input(537))      # System Meter Active Power

asyncio.run(main())
```

This first version reads: it polls, reads named points and takes unsolicited responses, and
does not yet operate an output. See [The console](https://dersecurity.github.io/py1815/console/),
[The master's API](https://dersecurity.github.io/py1815/master-api/), whose routes are
described in an [OpenAPI document](src/py1815/master/console/openapi.json), and
[The master](https://dersecurity.github.io/py1815/master/) for the Python interface.

## More about the simulated DER

Any DNP3 master can connect in place of `poll`. The outstation's link address is 1024 and it
expects master address 1 (`--outstation-address`, `--master-address`), or serves whichever
master address speaks first with `--any-master`. The native command listens
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
| DER functions (clause 6) | Their points are served. Their behavior is out of scope: what a DER does when a function is enabled belongs to the device or simulator bound behind the outstation. What the profile says of the points themselves is implemented: a function with no enable output bound reports "not supported" through its supports point, as 6.1.1 requires, and a disabled function's inputs are sent without the ONLINE flag. The simulated DER answers to active power limit, charge/discharge, constant vars, constant power factor, volt-var and volt-watt, far enough to exercise those points and no further |
| Curves (6.1.3) | The curve block is implemented: ten curves behind the multiplexed block, with the selector, referenced-indicator, locking and curve-type rules. Following a curve is out of scope, and belongs to the DER behind the outstation. The simulated DER follows volt-var and volt-watt by straight lines between points; hysteresis is not followed |
| Schedules, equipment block measurements | Resolved in the map, not simulated |
| DNP3 Subset Level 2 conformance | The DNP Users Group's IED certification procedures (version 3.1) are carried out in CI, section by section, against a Level 2 configuration. Self-assessed, not certified |
| DER profile test procedure | EPRI's test procedure for the profile (report 3002016144) is carried out in CI against the simulated DER. The schedule procedure does not apply. Self-assessed |
| Technical bulletins and application notes | Each of the DNP Users Group's bulletins and notes is cataloged as acted on or not applicable. Acted on: the updated transport reception table, special addresses, error indications, relative time for events stamped before the clock is set, LAN time synchronization, validation of incoming data, disabling function codes, and the rules for unsolicited responses |
| Unsolicited responses (optional in the profile) | Implemented, off by default: `py1815-der run --unsolicited`, or `session(unsolicited=True)` |
| Floating-point variations, device attributes (both optional in the profile), secure authentication | Not implemented |

`py1815-der profile` writes the outstation's DNP3 Device Profile document (schema version
2.12.00), generated from the running configuration: its point lists, limits and
implementation table. See [Serving a DER](https://dersecurity.github.io/py1815/der/).

To put a real device or a DER simulator behind the same outstation, bind its values to the
profile's points instead of the simulation's: see
[Serving a DER](https://dersecurity.github.io/py1815/der/). That is also where DER functions,
curves and anything else a DER does come from.

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
| Master | `master`, `decode` | A master for exercising outstations: it polls, reads named points, takes unsolicited responses and keeps what it was told, and operates outputs by direct operate or by select and operate, from Python, a JSON service, or a web console (`py1815-master console`). The service commands only when started with `--allow-control`. A first version |

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
  a capture of the same traffic. The master is tested the other way round: CI reads and commands
  an opendnp3 outstation and a `dnp3` crate outstation with it, and checks each control against
  what the outstation says it received. See `interop/` and [Acknowledgments](#acknowledgments).

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

- **[`dnp3`](https://github.com/stepfunc/dnp3) by Step Function I/O** is the Rust master in the interoperability suite,
  and the Rust outstation that this library's master is read and commanded against.
  It is the peer that checks the quality flags and that a refused control arrives as a refusal,
  which the other master cannot do, so it carries a real share of the verification. It is used
  under Step Function I/O's public [license](https://github.com/stepfunc/dnp3/blob/main/LICENSE.txt), which is not an open-source license.
  Step Function I/O has said that using it for testing and interoperability of py1815 in this
  repository's public CI is in line with that license ([#48](https://github.com/DERSecurity/py1815/issues/48)). That statement is about this repository: anyone
  running the job from a fork, or using the crate anywhere else, should read the license for
  their own use. Commercial licensing is at <https://stepfunc.io/contact>.
- **[opendnp3](https://github.com/dnp3/opendnp3)** is the C++ master in the suite, and the C++ outstation the
  master is tested against. It found that the master read named points in a form a Level 2
  outstation need not accept. It is driven through the
  [`dnp3-python`](https://pypi.org/project/dnp3-python/) bindings. It is also where two of this library's choices come
  from: the ten-second default for how long a select stays armed, and the name `TOO_MANY_OPS`
  for control status 8, which is the spelling that interoperates.
- **Wireshark** and **Suricata** supply the two independent dissectors that read a capture of
  everything the suite puts on the wire.

## License

Apache-2.0. See [LICENSE](https://github.com/DERSecurity/py1815/blob/main/LICENSE) and [NOTICE](https://github.com/DERSecurity/py1815/blob/main/NOTICE).
