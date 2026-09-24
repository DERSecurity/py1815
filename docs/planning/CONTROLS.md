# Plan: control support

Making this a complete outstation rather than a monitoring one. Today a master
can read; it cannot command. `session.py` supports `CONFIRM`, `READ` and
`WRITE`, and `WRITE` honors exactly one object -- clearing the restart bit.
`SELECT`, `OPERATE` and `DIRECT_OPERATE` are refused with
`FUNC_NOT_SUPPORTED`.

## Scope

Subset Level 2 as the floor, plus the variations the IEEE 1815.2 DER profile
requires, each named in the device profile document as an agreed extension.

Not "the Level 2 control set", which is not a servable target here.
[DESIGN.md](../DESIGN.md) already says why: 32-bit analog outputs exceed Level
2, and a 50 kW real power value overflows a 16-bit point, so the profile cannot
be served inside Level 2 once controls are in scope. An implementation that
stopped at Level 2 would be conformant and useless for the thing this library
was built for.

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

This is conformant rather than a compromise, which is worth stating because it
reads like one. The standard defines status `SUCCESS` as *"command was
accepted, initiated, or queued"* -- queuing is explicitly one of the things
success means. A provider that hands the control to a device thread and returns
is answering correctly, not optimistically. What it must not do is block: a
device round-trip inside the window a master is timing is a protocol timeout
waiting to happen, which is the same reason `ReadProvider` is synchronous.

An awaitable control path was considered and rejected. It would turn
`session.receive()` async and rewrite every existing test and the server, to
buy a distinction the status vocabulary does not draw.

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

**D14 -- A complete control is answered per object, echoed in request order.** A
request naming four points where one is unsupported returns four objects with
three successes and one `NOT_SUPPORTED`, not a single refusal for the fragment.

**D15 -- A request that does not parse is refused at the fragment, not per
object.** These are different failures and they cannot share an answer. A
truncated body, a count that disagrees with the octets present, or an index
width that contradicts the qualifier may leave no complete object to echo --
there is nothing to attach a status to. Those produce a null response carrying
`PARAM_ERROR`. An object that parses completely and is then invalid -- a bad
control code, impossible timing values -- is echoed with `FORMAT_ERROR` under
**D14**.

**D16 -- A select arms the request it received, not the objects that
succeeded.** **D14** answers per object, so a four-point `SELECT` can return
three `SUCCESS` and one `NOT_SUPPORTED` -- which a master will meet on any map
with a read-only index. What that arms has to be defined, and the answer is the
whole request.

The following `OPERATE` must match what the master sent, because that is what
the master will send again; matching against a subset the master was never told
about would reject its own unchanged request. Each object is then answered on
its merits a second time, so an index that failed at select fails again at
operate. Nothing partially-selected is executed, and no subset bookkeeping is
invented to be got wrong.

## Work

### 1. Control objects -- `objects.py`

Currently inputs only: groups 1, 2, 30 and 32. Add:

| Group | Variation | Object | Direction |
|---|---|---|---|
| 12 | 1 | CROB | request and echo |
| 41 | 1-4 | Analog output (int32, int16, float32, double64) | request and echo |
| 10 | 2 | Binary output status | read back |
| 40 | 1-4 | Analog output status | read back |

Group 41 variation 1 and the floating-point variations are the above-Level-2
extensions the scope section names; the device profile document must list them.

CROB is 11 octets: control code, count, on-time, off-time, status. Analog
output is the value plus a status octet. The status objects carry a quality
flag octet like their input counterparts, so `analog_flags` and `binary_flags`
extend rather than being duplicated.

Both directions are needed: controls are **decoded** from a request and
**encoded** back into the response. Everything to this point has been
encode-only, so this is the module's first decoder.

**Acceptance:** each object round-trips against literal octets from IEEE 1815,
in both directions, with the tests comparing hex rather than round-tripping.

### 2. Control status codes -- `objects.py` or a new `control.py`

Define the full enumeration, not a useful subset. A decoder meets whatever a
master sends, and an unknown status arriving as an integer is worse than one
arriving with a name. The set runs to 18 plus two reserved values:

`SUCCESS` (0), `TIMEOUT`, `NO_SELECT`, `FORMAT_ERROR`, `NOT_SUPPORTED`,
`ALREADY_ACTIVE`, `HARDWARE_ERROR`, `LOCAL`, `TOO_MANY_OPS`, `NOT_AUTHORIZED`,
`AUTOMATION_INHIBIT`, `PROCESSING_LIMITED`, `OUT_OF_RANGE`, `DOWNSTREAM_LOCAL`,
`ALREADY_COMPLETE`, `BLOCKED`, `CANCELLED`, `BLOCKED_OTHER_MASTER`,
`DOWNSTREAM_FAIL` (18), `NON_PARTICIPATING` (126, deprecated), `UNDEFINED`
(127).

The name is `TOO_MANY_OPS` -- too many *operations*, throttling -- and not
`TOO_MANY_OBJS`. The ecosystem is inconsistent here and an earlier draft of
this plan had it wrong; the name that interoperates is the one opendnp3
publishes.

These are the vocabulary a provider answers in, so they are public API and
their docstrings should say when each is the right answer. Two are easy to get
backwards:

- **`PROCESSING_LIMITED`** means the outstation *could not* accept the
  operation, having no capacity for more activity than is already in progress.
  It is not "accepted but unconfirmed" -- that is `SUCCESS`, per **D10**.
- **`ALREADY_ACTIVE`** means the point is already in the requested state or the
  operation is already running. It is a provider answer, since only the
  provider knows the point's state.

### 3. Interleaved body parsing -- `application.py`

Walk `Request.body` into `(index, object_bytes)` pairs, using the header's
qualifier to size the index and the group and variation to size the object.
Multiple headers per request, which the current single-header stop does not
handle.

Bound the count, as a policy choice this library is making rather than one it
inherits. opendnp3 does not cap controls per request at all --
`maxControlsPerRequest` defaults to `4'294'967'295` in `OutstationParams.h` --
so a cap cannot be attributed to it, and an earlier draft of this plan claimed
a default of 16 that does not exist. Adopting that number on a false citation
would refuse a legitimate seventeen-point request with `TOO_MANY_OPS`.

The argument for a bound is availability, not precedent. Note that one already
exists implicitly: a fragment is 2048 octets and a CROB with a one-octet index
prefix is 12, so roughly 170 controls fit a fragment whatever this library
says. A lower cap is worth having only if some provider needs protecting from a
request that size, and it should be configurable with a default chosen and
justified here rather than borrowed.

**Acceptance:**

- A malformed body produces a fragment-level refusal per **D15**, never an
  exception escaping the session.
- Fuzzing the body length against a valid header produces a response every
  time -- for `SELECT`, `OPERATE` and `DIRECT_OPERATE` only.
- **Separately:** every body length under `DIRECT_OPERATE_NR`, malformed or
  not, produces silence. **D9** is not suspended by a parse failure, and an
  acceptance criterion demanding a response for all four functions would
  contradict it.

### 4. Session dispatch and select state -- `session.py`

- Add `SELECT`, `OPERATE` and `DIRECT_OPERATE` to `_SUPPORTED_FUNCTIONS`.
- **`DIRECT_OPERATE_NR` must begin executing**, while staying silent. Table 4-2
  defines it as "same as function code 5 but outstation shall not send a
  response" -- *same as function code 5*, so it operates and says nothing.
  Dropping it unexecuted is right for an outstation that cannot command and
  becomes the worst available behavior for one that can: silently ignoring
  commands a master believes it issued.

  There is a concrete interaction to handle rather than rediscover.
  `session.py:251` resolves `_NO_RESPONSE_FUNCTIONS` from the function code
  octet *before* `parse_request`, deliberately, so that a malformed member
  draws no reply. This function has to be carved out of that early branch while
  the other four stay in it -- and its silence must survive a body that does not
  parse, which is the very case that branch was written for.
- `ControlProvider` Protocol alongside `ReadProvider`, with `select` and
  `operate` taking the decoded controls and returning one status each.
- Select state per **D11** and **D12**: what was selected, when, and the
  comparison an operate must satisfy.
- `_handle_control` building the echo per **D14** and the fragment refusal per
  **D15**.

**Acceptance:** an operate with no prior select returns `NO_SELECT`; one after
the timeout returns `TIMEOUT`; one whose objects differ from the select returns
`NO_SELECT`; a matching pair returns the provider's statuses and consumes the
select. A `connection_reset` discards it.

### 5. Output status readback

A master that commands expects to read back, so groups 10 and 40 need
encoders here.

**Class-0 participation is the provider's, not this library's.** `Session`
forwards a class-0 header to `ReadProvider`, which chooses and encodes what
comes back; under **D6** the library holds no point map and so cannot know
which output points exist, let alone add them to a response. An earlier draft
of this plan assigned that ownership to the library, which the current API
cannot support. What belongs here is the encoders and the documentation telling
a caller that output status points conventionally participate in class 0.

### 6. Interop -- and a test that changes meaning

**The Rust master currently asserts controls are refused.**
`interop/rust-master/src/main.rs:187-198` sends a `LatchOn` CROB via
`DirectOperate` and requires `FUNC_NOT_SUPPORTED`, with a comment naming it as
the half of **D9** a sweep on our own socket cannot show.

Retargeting it at an uncontrollable index is *not* sufficient, and an earlier
draft of this plan said it was. The two assertions are about different layers:
an unsupported index yields an echoed object carrying `NOT_SUPPORTED` under
**D14**, while the existing test checks a fragment-level
`IIN2.FUNC_NOT_SUPPORTED`. Replacing one with the other silently drops the
coverage **D9** was given.

Both are needed:

- A per-object case: a controllable index succeeds, an uncontrollable one comes
  back `NOT_SUPPORTED`, in the same response.
- A function-level case that keeps **D9** covered, using a function that stays
  unsupported after this work -- `COLD_RESTART` or `IMMED_FREEZE` are
  candidates, subject to the master library being able to send one.

Also: `interop/outstation.py` serves groups 30 and 60 only, so it needs
controllable points; and `interop/sweep.py` walks the function code space and
will now see different answers for 3, 4 and 5.

### 7. Documentation

- **D10** through **D15** into `DESIGN.md`, and the roadmap updated -- controls
  are not currently on it.
- `SECURITY.md` -- create or extend depending on whether the policy branch has
  landed by then. A control is the first request that changes state, so decoded
  control objects, the select state machine and the provider boundary all
  belong in the scope list.
- `README.md` says the library reads; it will command.
- `CHANGELOG.md` under Unreleased.

## Sequencing

Objects and status codes first, then body parsing, then session dispatch, then
interop. Each is independently testable, and they can merge ahead of the
behavior change rather than arriving as one diff reviewable only as a whole.

One answer does change before 4 lands, and the claim that none does was wrong.
A control request with a malformed body is today parsed as far as its first
header and then refused at the function with `FUNC_NOT_SUPPORTED`. Once 3 walks
the body, that same request becomes a `PARAM_ERROR` under **D15** while the
function is still unsupported. Nothing currently sends one -- `interop/sweep.py`
sends bare control headers with no body, which parse -- so no test breaks, but
the change is real and 3 should carry it in its own notes.

## Open

- **Secure Authentication, group 120.** This is the change that lets the
  outstation alter physical state, and the only thing in front of it is **D8**'s
  TLS allow-list. IEEE 1815-2012 Table 7-7 lists `SELECT`, `OPERATE`,
  `DIRECT_OPERATE` and `DIRECT_OPERATE_NR` as MANDATORY critical requests, which
  is the standard naming these as the functions Secure Authentication exists
  for. Out of scope here is a defensible answer; leaving it unmentioned is not,
  and the `SECURITY.md` item under 7 documents the surface rather than deciding
  this.
- **Counter groups 20 and 21, and freeze.** Out of scope here, but
  `IMMED_FREEZE` sits in the same refused-function neighborhood, and "complete
  outstation" may be taken to include it. Deciding this needs the Level 2
  object requirement from the standard itself rather than from secondary
  sources.

## Settled by survey

- **Select timeout: 10 seconds, configurable.** opendnp3's `selectTimeout`
  default, and it is Apache 2.0 like this library and already one of the two
  masters in the interop suite. go-dnp3 uses 5 seconds when unset, so the
  range in the field is 5 to 10. The Rust `dnp3` crate is source-available
  rather than open source and is not the implementation to treat as reference.
- **`ALREADY_ACTIVE` does arise under D7.** It concerns the point's state, not
  competing masters. The status that genuinely cannot arise with one
  association is `BLOCKED_OTHER_MASTER` (17), which is defined as another
  master holding exclusive rights.
