# py1815

A DNP3 (IEEE 1815) outstation in pure Python.

!!! warning "Early development"
    The protocol layers, the listener, controls and the event path are
    implemented and tested: a master reads classes 1 to 3, confirms what it was
    sent, and is told through the indication bits what is still waiting. Not yet
    done are unsolicited responses -- outstation-initiated traffic -- and the
    point-map loader; a response larger than one fragment is capped rather than
    split. Nothing is released yet and the API is not stable.

## Why it is pure Python

There is no maintained, importable DNP3 stack for current Python. The widely
used bindings wrap [opendnp3](https://github.com/dnp3/opendnp3), archived and
declared end-of-life in September 2022, and they publish wheels only up to
CPython 3.10. Everything else in the ecosystem is a compiled extension, which
means a prebuilt wheel per interpreter version and a cross-compiler for anything
unusual.

This library depends on nothing outside the standard library. That is the point
of it: it runs on embedded targets where no toolchain is available, and it
upgrades with the interpreter rather than waiting for someone to publish a
wheel.

## What it does

An outstation, the side a SCADA master connects *to*. Subset Level 2 is the
target, over TCP and TLS.

| Layer | Module | Contents |
|---|---|---|
| Checksum | `crc` | CRC-16/DNP |
| Data link | `link` | FT3 framing, control byte, addresses, stream reader |
| Transport | `transport` | Segmentation and reassembly |
| Application | `application` | Control octet, function codes, internal indications, object headers |
| Objects | `objects` | Binary and analog inputs, static and event, with quality flags |
| Events | `events` | Class buffers, deadbands, overflow |
| Session | `session` | One master association: octets in, octets out |
| Listener | `server` | TCP, TLS, and which connection is allowed to be the master |

Each layer is testable without the ones above it. The session does no I/O at
all, so protocol behavior is pinned against literal frames rather than against a
socket.

## Start here

- **[How DNP3 works](dnp3.md)** if the protocol is new to you, or if you need
  the shape of a frame in front of you.
- **[Serving an outstation](outstation.md)** to get one answering a master.
- **[Design decisions](DESIGN.md)** for why the library is shaped the way it
  is, numbered so they can be argued with.
- **[Testing](testing.md)** for how the wire behavior is held to, and what is
  checked by implementations that are not this one.

## Part of Project Satori

*Any certified DER. Any utility program.* Satori is an open-source initiative to
make any certified DER a compliant participant in utility DER programs.

A device joins a program by speaking whatever protocol that program is run on,
and that is not one protocol. IEEE 2030.5 is what most North American and
Australian utility programs specify. DNP3 is what a great deal of existing
distribution SCADA already speaks, and IEEE 1815.2 is the DER profile built on
it. This library is the DNP3 half.

Project website: <https://open-satori.org>

## License

Apache-2.0.
