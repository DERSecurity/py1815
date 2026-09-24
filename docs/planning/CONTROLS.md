# Plan: control support

Making this a complete outstation rather than a monitoring one. Today a master
can read; it cannot command. `session.py` supports `CONFIRM`, `READ` and
`WRITE`, and `WRITE` honors exactly one object -- clearing the restart bit.
`SELECT`, `OPERATE` and `DIRECT_OPERATE` are refused with `FUNC_NOT_SUPPORTED`.

Scope agreed: the full Subset Level 2 control set, so conformance testing has
nothing left to add.

## What already exists

Worth stating first, because it changes the size of this considerably. The
application layer was written anticipating controls:

- `_PARSED_FUNCTIONS` (`application.py:111`) already contains `SELECT`,
  `OPERATE`, `DIRECT_OPERATE` and `DIRECT_OPERATE_NR`. A control request is
  already parsed rather than rejected.
- The qualifiers controls use are already accepted:
  `UINT8_COUNT_UINT8_INDEX` (`0x17`) and `UINT16_COUNT_UINT16_INDEX` (`0x28`).
- `parse_request` deliberately stops at the first header for a function
  carrying object data, leaving the rest in `Request.body`, because indices
  interleave with objects rather than forming a list. `ObjectHeader.indices`
  documents exactly this.
- `DIRECT_OPERATE_NR` is already dropped without a response, per **D9**. That
  behavior is correct as it stands and must survive this work.

So the parsing groundwork is laid. What is missing is walking the interleaved
body, the control objects themselves, the select state, and the response shape.

## Decisions

Continuing the numbering in [DESIGN.md](../DESIGN.md).

**D10 -- Controls reach the device through a synchronous `ControlProvider`,**
mirroring `ReadProvider`. The session stays synchronous, so it continues to do
no I/O and to be pinned against literal frames.

The consequence is honest and must be documented for callers: a status of
`SUCCESS` means the outstation accepted and dispatched the control, not that
hardware has moved. A provider that needs a device round-trip queues the work
and returns. Making the control path awaitable was considered and rejected --
it would turn `session.receive()` async, rewrite every existing test and the
server, and put a slow device inside a window a master is timing.

**D11 -- Select state lives in the session, not in the provider.** Selecting is
protocol bookkeeping: the provider is asked whether it *could* operate, and the
session remembers that it said yes. Two reasons. A provider implemented by a
caller should not have to reimplement matching and expiry to be conformant, and
under **D7** there is one association, so there is exactly one select to track
and its lifetime is the connection's.

**D12 -- A select is invalidated by anything that makes it ambiguous.** It
expires after a configurable timeout, it is consumed by the operate that
matches it, and it is discarded on `connection_reset`. A second select replaces
the first rather than accumulating.

**D13 -- The control point map belongs to the caller, as with reads.** Under
**D6** this library does not know that index 7 is a power setpoint, and it does
not scale. A control arrives at the provider as an index, a decoded object and
the function that carried it.

**D14 -- Every control is answered per object, echoed in request order.** The
response repeats the objects it was sent with each status field filled in. A
request naming four points where one is unsupported returns four objects with
three successes and one `NOT_SUPPORTED`, not a single refusal for the fragment.

## Work

### 1. Control objects -- `objects.py`

Currently inputs only: groups 1, 2, 30 and 32. Add:

| Group | Variation | Object | Direction |
|---|---|---|---|
| 12 | 1 | CROB | request and echo |
| 41 | 1-4 | Analog output (int32, int16, float32, double64) | request and echo |
| 10 | 2 | Binary output status | read back |
| 40 | 1-4 | Analog output status | read back |

CROB is 11 octets: control code, count, on-time, off-time, status. Analog
output is the value plus a status octet. The status objects carry a quality
flag octet like their input counterparts, so `analog_flags` and `binary_flags`
extend rather than being duplicated.

Both directions are needed: controls are **decoded** from a request and
**encoded** back into the response. Reads to this point have been encode-only,
so this is the first decoder in the module.

**Acceptance:** each object round-trips against literal octets from IEEE 1815,
in both directions, with the tests comparing hex rather than round-tripping.

### 2. Control status codes -- `objects.py` or a new `control.py`

The status enum the standard defines, at minimum `SUCCESS`, `TIMEOUT`,
`NO_SELECT`, `FORMAT_ERROR`, `NOT_SUPPORTED`, `ALREADY_ACTIVE`,
`HARDWARE_ERROR`, `LOCAL`, `TOO_MANY_OBJS`, `NOT_AUTHORIZED`,
`AUTOMATION_INHIBIT`, `PROCESSING_LIMITED` and `OUT_OF_RANGE`.

These are the vocabulary a provider answers in, so they are public API and
their docstrings should say when each is the right answer -- `NOT_SUPPORTED`
for a point that cannot be controlled at all, `OUT_OF_RANGE` for a value the
point cannot take, `PROCESSING_LIMITED` for a provider that accepted but cannot
confirm.

### 3. Interleaved body parsing -- `application.py`

Walk `Request.body` into `(index, object_bytes)` pairs, using the header's
qualifier to size the index and the group and variation to size the object.
Multiple headers per request, which the current single-header stop does not
handle.

The failure modes matter more than the happy path: a truncated body, an object
count that disagrees with the octets present, an index width that does not
match the qualifier. Each should produce `FORMAT_ERROR` against the objects
rather than an exception that escapes the session.

**Acceptance:** a malformed control request is answered, not raised. Fuzzing
the body length against a valid header produces a response every time.

### 4. Session dispatch and select state -- `session.py`

- Add `SELECT`, `OPERATE` and `DIRECT_OPERATE` to `_SUPPORTED_FUNCTIONS`.
  `DIRECT_OPERATE_NR` stays out, and stays silent (**D9**).
- `ControlProvider` Protocol alongside `ReadProvider`, with `select` and
  `operate` taking the decoded controls and returning one status each.
- Select state per **D11** and **D12**: what was selected, when, and the
  comparison an operate must satisfy.
- `_handle_control` building the echo per **D14**.

**Acceptance:** an operate with no prior select returns `NO_SELECT`; one after
the timeout returns `TIMEOUT`; one whose objects differ from the select
returns `NO_SELECT`; a matching pair returns the provider's statuses and
consumes the select. A `connection_reset` discards it.

### 5. Output status readback

A master that commands expects to read back. `ReadProvider` implementations
must be able to serve groups 10 and 40, which is a caller concern, but the
encoders and the class-0 participation are this library's.

Decide whether output status points participate in class 0 by default. They
conventionally do.

### 6. Interop -- and a test that must change

**The Rust master currently asserts controls are refused.**
`interop/rust-master/src/main.rs:187-198` sends a `LatchOn` CROB via
`DirectOperate` and requires `FUNC_NOT_SUPPORTED`, with a comment naming it as
the half of **D9** a sweep on our own socket cannot show. That assertion
encodes the present limitation and inverts the day controls land.

It should not simply be deleted. The property it protects -- that a refusal
reaches a master as a refusal rather than as a timeout -- is still worth
holding. Suggest retargeting it at an index the fixture deliberately does not
control, so the refusal path stays covered while a controllable index proves
the success path.

Also: `interop/outstation.py` serves groups 30 and 60 only, so it needs
controllable points; and `interop/sweep.py` walks the function code space and
will now see different answers for 3, 4 and 5.

### 7. Documentation

- **D10** through **D14** into `DESIGN.md`, and the roadmap updated -- controls
  are not currently on it.
- `SECURITY.md` scope gains a real attack surface: a control is the first
  request that changes state, so decoded control objects, the select state
  machine, and the provider boundary all belong in the list.
- `README.md` says the library reads; it will command.
- `CHANGELOG.md` under Unreleased.

## Sequencing

Objects and status codes first, then body parsing, then session dispatch, then
interop. Each is independently testable, and the first three land without
changing any answer the outstation currently gives -- so they can merge ahead
of the behavior change rather than in one reviewable-only-as-a-whole diff.

## Open

- **Select timeout default.** Needs a number. Common practice is 5 to 10
  seconds; the standard leaves it to the outstation.
- **`ALREADY_ACTIVE` semantics** under **D7**. With one association there is no
  competing master, so the case may not arise; worth confirming before
  implementing a status nothing can return.
- **Counter groups 20 and 21, and freeze.** Out of scope here, but `IMMED_FREEZE`
  sits in the same refused-function neighborhood, and "complete outstation" may
  be taken to include it.
