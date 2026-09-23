# py1815

A DNP3 (IEEE 1815) outstation in pure Python.

**Status: early development.** The protocol layers below the point map are implemented and
tested; the listener, the event path and the point-map loader are not. Nothing is released yet,
and the API is not stable.

## Why this exists

There is no maintained, importable DNP3 stack for current Python. The widely used bindings wrap
[opendnp3](https://github.com/dnp3/opendnp3), which was archived and declared end-of-life in
September 2022, and they publish wheels only up to CPython 3.10. Everything else in the
ecosystem is a compiled extension, which means a prebuilt wheel per interpreter version and a
cross-compiler for anything unusual.

This library is pure Python and depends on nothing outside the standard library. That is the
point of it: it runs on embedded targets where no toolchain is available, and it upgrades with
the interpreter rather than waiting for someone to publish a wheel.

## What it does

An outstation -- the side a SCADA master connects *to*. Subset Level 2 is the target, over TCP
and TLS.

| Layer | Module | Contents |
|---|---|---|
| Checksum | `crc` | CRC-16/DNP |
| Data link | `link` | FT3 framing, control byte, addresses, stream reader |
| Transport | `transport` | Segmentation and reassembly |
| Application | `application` | Control octet, function codes, internal indications, object headers |
| Objects | `objects` | Static binary and analog inputs with quality flags |
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

## Development

```
pytest            # tests
ruff check .      # lint
ruff format --check .
mypy --strict src
```

All four run in CI and all four must pass.

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

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
