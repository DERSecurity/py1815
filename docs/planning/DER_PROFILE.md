# Plan: generating an IEEE 1815.2 outstation

Making a DER profile outstation something a caller assembles from a point table
and a set of bindings, rather than something written by hand per deployment.
Today the library serves whatever objects a `ReadProvider` returns and commands
whatever a `ControlProvider` accepts; it knows nothing about which point is
the real power measurement, which binary input says a function is supported,
or where the second inverter's block begins. Every consumer would have to
rediscover that from the standard, and two consumers are waiting: a
DER simulator that reserves a port and a link address per simulated device for
an outstation it does not yet create, and a fleet aggregator whose own plan
already specifies the adapter and leaves the outstation to this library.

The two want different shapes of outstation from the same profile. The simulator wants
one outstation per simulated DER, which is the shape IEEE 1815.2 describes.
The aggregator wants one outstation presenting a fleet, with each device in a strided
block. A generator that serves both has to separate the profile's structure from
the deployment's layout, and that separation is most of this plan.

## Scope

An IEEE 1815.2-2025 outstation, with the predecessor profile (DNP3 Application
Note AN2018-001) as the table the work starts from, since 1815.2 keeps its
structure and largely relocates its indices. Read-only first, then functions
and controls, because that is the order both consumers need them in and
because the monitoring half exercises every mechanism the command half reuses.

Not in scope: a master, secure authentication, file transfer, datasets, and the
device attribute objects the profile marks optional. Counters are in scope
because the profile's fixed system block carries them, and the library has no
counter objects today.

Two things the library does not do yet are named here rather than assumed,
because a caller assembling an outstation from this will ask about both:

- **Unsolicited responses.** The profile's consumers expect outstation-initiated
  reporting, and this library still refuses `ENABLE_UNSOLICITED`. The generator
  does not assume it exists: an outstation built under these nine steps reports
  events when polled, and gains unsolicited reporting when the library does,
  through the same `EventBuffers` and with no change to the map or the binding.
  That work is its own roadmap entry in [DESIGN.md](../DESIGN.md), not a step
  here.
- **Floating-point analog events.** The library serves floating-point static
  analog inputs and integer analog events only; a point whose static form is a
  float has no float event form to report a change in. That asymmetry is not a
  decision anyone made, and a map that carries scaling and range per point is
  exactly where it surfaces. The builder therefore reports events for every
  analog point in the integer variation D39 makes the baseline, scaled by the
  table, until the event encoders gain the float variations, which is a small
  addition to `objects.py` that belongs with step 5.

## The licensing boundary, stated first

Everything else here is shaped by one fact: the profile's point list is
normative, and where it comes from decides what may ship. IEEE 1815.2
specifies its points in the Profile Companion Data Point Tables, a workbook the
standard declares normative because an implementation cannot be built without
it, and which IEEE distributes without charge alongside the standard. A
machine-readable form of it is checked in as `conformance/ieee-1815-2-2025.json`,
with its source named. AN2018-001's tables are DNP Users Group material and
cannot be committed. A map that is nearly right is worse than one that is
openly custom, because it will appear to interoperate, so nothing is derived
by guesswork from either.

The one exception is EPRI's reference outstation for AN2018-001, whose point
tables are published under a BSD-style license: index, name, range, event class,
and for each output the input that mirrors it. That license permits deriving a
table and carries a notice obligation with it. [DESIGN.md](../DESIGN.md) already
lists confirming that reading as an open item, and this plan does not resolve
it; it is written so that nothing waits on it.

So the library ships the machinery, and of the data only what its publisher
lets it: the map format, the loader that resolves it, the builder that turns
it into an outstation, the catalog of DER functions the profile defines, the
extractor that reads a source workbook into the map format, and the 1815.2
tables that extractor produced. What it does not ship is a map derived from
AN2018-001 or from the EPRI tables. The runtime treats both the same way, as
data a caller loads, which is [DESIGN.md](../DESIGN.md) **D6**; the difference
is only whether the repository can carry the file. This is the same split
`tests/test_conformance.py` and `scripts/extract_conformance.py` already make
for the base standard, and for the same reason.

## What already exists

Worth stating first, because the generator is mostly assembly of parts that are
already here or already in hand.

**In the library.** `Session` takes a `ReadProvider`, an optional
`ControlProvider`, and `EventBuffers`; `OutstationServer` serves one over TCP or
TLS. `BlockReadProvider` lets a provider say where its objects end, so a map
larger than a fragment reaches a master. `objects.py` encodes binary inputs and
events (groups 1 and 2), analog inputs and events (30 and 32), output status
(10 and 40) and time (50); `control.py` encodes and decodes control relay output
blocks (12) and analog outputs (41) and carries the command status vocabulary.
`events.py` holds per-class bounded buffers. Nothing in the library names a
point; that is the gap.

**In the standard.** IEEE 1815.2 clause 5.2 gives the indexing rule: SCADA and
configuration points have fixed absolute indices starting at zero, and every
function, curve, schedule, equipment and vendor point is relative to a block
starting index, which is either read from the companion tables or, if the
outstation supports it, published in band at analog inputs 65000 and above.
Clause 6.1.1 gives the support contract: a supported function sets its
"supports" binary input, which is reported in Class 0 only and never as an
event; a supported function implements every point the tables mark mandatory;
the controlling station enables it through a binary output. Clause 6.1.3 gives
curves and schedules as multiplexed edit buffers of up to one hundred points
each, so a function needing a curve does not need two hundred dedicated
indices. Clause 6 lists the functions themselves, clause 7 their priorities
when they conflict, and Table 7 the object variations and function codes an
implementation must support. Table 7 is extractable the same way the base
standard's tables were.

**In hand, and not committable.** AN2018-001 in a form the extractor can read,
with the semantic columns the EPRI tables lack: scaling, resolution, units, the
IEC 61850 logical node and attribute each point originates from, and the clause
that defines it. The EPRI tables themselves, with their license. EPRI's test
procedure for AN2018-001, which is the acceptance suite for the simulator.

**In hand, and committed.** The IEEE 1815.2 companion tables, read by
`scripts/extract_profile.py` into `conformance/ieee-1815-2-2025.json` and held
to shape by `tests/test_profile_tables.py`. The workbook disagrees with itself
in three places (the auto-discovery block's start, three per-unit block
lengths, and the spelling of some paired references); `conformance/README.md`
lists them, and the file records the rows rather than the summary each time.

**In the consumers.** The simulator allocates a DNP3 port and outstation address per
simulated device when the interface is enabled, then creates nothing: the slot
is shaped for exactly this and is empty. Its Modbus server binds each SunSpec
point to the simulator through a pair of read and write callables keyed by model
and point, and that idiom is the one the DNP3 binding should mirror, so an
operator who has configured one interface recognizes the other. A separate
DNP3 agent from an earlier test harness sits beside it, built on an end-of-life
stack through a subprocess and referenced by nothing in the simulator; this
plan retires it rather than wrapping it. The aggregator's own plan specifies its
adapter fully: an aggregate endpoint with strided per-device blocks, devices
ordered deterministically so a master's cached indices survive a restart, a
monitor role first with writable points omitted rather than refused, quality
mapped from its store's three-state health, and the index table held in that
repository. What it needs from here is a builder that accepts a map and a
binding, and a map transformation that produces the strided layout from the
single-device one.

## Decisions

Continuing the numbering in [DESIGN.md](../DESIGN.md).

**D36 -- The library ships the profile's machinery, and only the data its
publisher distributes openly.** Map format, loader, validator, builder, function
catalog and extractor are in the package, and so are the IEEE 1815.2 tables,
which IEEE publishes without charge. A table whose source is not open, which
today means AN2018-001 and anything derived from it, is read from the caller's
own copy by the extractor and is not committed. *Trade-off:* a deployment
wanting the predecessor profile runs the extractor once against a document it
must obtain, against a repository that carries only what it may.

**D37 -- Relative indices are resolved once, at load, into a flat map.** The
profile's block arithmetic (this component's block start, plus this instance
number times the block length, plus the offset) is evaluated when the map is
loaded for a DER of known composition, and the outstation serves absolute
indices from then on. The in-band block advertisement is derived from the same
resolution. *Trade-off:* changing a DER's composition means reloading the map,
against a request path that never does arithmetic and a validation that runs
once against the whole index space.

**D38 -- A point is bound by callables, in each direction, and the builder
does everything else.** A read binding returns a value, a source quality and a
source timestamp; a write binding receives a value and returns a command
status. The builder assembles Class 0, scales, sets flags, encodes, buffers
events and answers controls. The caller never touches an object encoder.
*Trade-off:* a caller with values already in wire form pays a conversion,
against an interface that is the same for a simulator and a store.

**D39 -- Integer variations are the baseline; floating point is offered by
map flag.** Table 7 lists floating-point inputs and outputs as recommended
rather than required, and the base standard requires that a device supporting
them support the integer variations too. Scaling and resolution come from the
table, so the conversion is a lookup rather than the per-value selection a
scale-factor protocol forces. *Trade-off:* both encodings implemented, against
a baseline the profile does not permit.

**D40 -- Support is derived from binding, never declared.** A function's
"supports" input is set when every point the catalog marks mandatory for that
function is bound, and clear otherwise; the builder refuses to construct an
outstation whose caller bound some mandatory points of a function and not the
rest. Enabling a function that is not supported is refused with a command
status rather than accepted and ignored. *Trade-off:* a caller cannot advertise
a function it half implements, which is the point.

**D41 -- Curves and schedules are objects to the binding, and multiplexed
points to the master.** The builder owns the edit buffer, the selected index
and the commit; a bound function receives a curve as an ordered list of pairs
with its units, and is never asked to interpret two hundred analog outputs.
*Trade-off:* a curve edit spanning several requests is state the builder holds
across them, against every consumer reimplementing the same protocol.

**D42 -- Layout is a map transformation, not a builder mode.** A strided fleet
map is produced from a single-device map by a function that offsets every index
by a block width times a device number and prepends the aggregate; the builder
does not know it happened. One outstation per DER and one outstation per fleet
are the same builder with different maps. *Trade-off:* the fleet layout's
policy (ordering, ceiling, what the aggregate serves) stays with the consumer,
where it already lives.

**D43 -- Unbound optional points are absent, not zero.** An optional point with
no binding is left out of the map the outstation serves, so a class 0 read does
not carry it and a read of its index answers `OBJECT_UNKNOWN`. A fabricated
value is indistinguishable from a real one on the wire. *Trade-off:* a
master's integrity poll of a partial implementation has gaps, which is the
honest shape of a partial implementation.

## How the interfaces are constructed

This is the logic the code will follow, written down before the code so it can
be argued with.

### The point model

A map is a list of points. Each carries:

- **Kind.** Binary input, binary output, analog input, analog output, counter.
- **Index**, either absolute or an expression over a named block: the block's
  symbol, an instance number, and an offset. The extractor produces the
  expression form for relative points; the loader resolves it.
- **Name** and the **block** it belongs to (system, schedule, a repeating
  component block such as meter, DER unit, inverter or battery, or in 1815.2 a
  function, curve, equipment or vendor block).
- **Role.** One of: measurement, nameplate, setting, mode enable, supports flag,
  alarm, curve point, schedule point, block advertisement. The role is what the
  builder dispatches on: a supports flag is served static and Class 0 only, a
  mode enable routes to the function catalog, a curve point to the edit
  buffer.
- **Event class** default, **range**, **scaling** and **resolution**, **units**,
  and whether the point is **mandatory** for the function it belongs to.
- **Function**, where the point belongs to one, by the catalog's identifier.
- **Mirror**, for outputs: the input that reports the output's status, where the
  profile pairs them.
- **Provenance.** Which document and clause the point came from, so a map
  reconciled between AN2018-001 and 1815.2 can say per point which it followed.

The loader takes a map and a **composition** (how many of each repeating
component the DER has), resolves every index, and validates what a map can be
checked for on its own: indices unique within a kind, every index within the
16-bit space with room for the advertisement block, every variation the map
asks for present in Table 7's implementation table, every function a point
names present in the catalog. The result is immutable and is what the builder
consumes. Whether a bound function's mandatory points are all bound is not a
property of the map, and the loader never sees a binding; that check belongs
to the builder, at the moment it receives one (D40).

### Binding

A binding is a mapping from point name to a callable pair. The read side
returns `(value, quality, source_timestamp)` where quality is one of good,
stale, comm-lost or never-read, chosen to line up with the three-state health
model the aggregator's store already uses plus the startup state DNP3 distinguishes.
The write side receives a value and returns a command status from
`control.CommandStatus`.

Outputs bind the write side and may bind a read side for status; a mirror
point with no read binding reports the last accepted write, which is what the
profile's paired points mean. Before any write has been accepted there is no
such value, and the mirror is not left undefined: the binding may supply an
initial value, in which case the mirror reports it as good; otherwise the
mirror reports never-read, with `ONLINE` clear and `RESTART` set, until the
first accepted write, exactly as an input that has never been read does. A
binding may also register a curve receiver and a schedule receiver per
function, which is how D41 delivers.

The simulator's binding keys are its state accessors, one per point, the
same way its Modbus server is built. The aggregator's binding keys are its store's
`(device, quantity)` pairs through the adapter's snapshot, which serves the
measurement points its store holds, declares nameplate points and reports them
offline until a retention plane exists, and omits points it has no source for.
Both are a few hundred lines that know both vocabularies and nothing else.

### Class 0 assembly

The builder implements `ReadProvider` and `BlockReadProvider`. For a class 0
read it walks the resolved map by kind, splits each kind into runs of
contiguous indices, and emits one object header per run with a start-stop
qualifier, choosing the variation D39 allows and the range demands: a point
whose scaled range overflows sixteen bits is served as thirty-two, which the
profile itself notes is unavoidable for real power in watts. A run is then cut
into blocks that fit the session's response budget, on object boundaries: the
session refuses any single block larger than a fragment however many fragments
follow (D31), so a long run served as one block would make a valid map
unreadable, and a block that split an object would corrupt it. A map larger
than a fragment therefore splits at index gaps and at the budget, and never
inside an object. Supports flags are served here and only here.
A read of a specific range or index is answered from the same walk restricted
to it, and an index the map does not hold answers `OBJECT_UNKNOWN` (D43).

### Scaling, quality and time

An integer variation carries `round(value * 10 ** scaling)`, with the table's
scaling column as the exponent and its resolution column as the event deadband
default. A floating variation carries the value as is. Quality maps onto the
flag octet: good is `ONLINE`; comm-lost clears `ONLINE` and sets `COMM_LOST`
with the last value; never-read clears `ONLINE` and sets `RESTART`; a value
outside the table's range sets `OVER_RANGE`.

Stale has no state of its own on the wire, and the plan does not pretend it
does. The static variations carry no timestamp, only the event variations do,
so a stale value served `ONLINE` in a class 0 read is indistinguishable from a
fresh one there, whatever timestamp the binding retained. The policy is
therefore two-valued at the wire: a value within the age the consumer declares
is good and served `ONLINE`; one beyond it is reported by the binding as
comm-lost, which does have a representation, and served that way. The window
is the consumer's to set, because only it knows what "too old" means for its
source; the builder never invents a third state. Timestamps are the source's,
never the time the frame was built, and reach the master on events.

### Functions

The catalog is a table keyed by function identifier, one row per function in
clause 6: the names of its supports flag and its enable output, the names of
its mandatory points, whether it uses a curve or a schedule and with what
units on each axis, and its priority class from clause 7. It carries names and
structure, not indices, which is what lets it ship (D36): the index of each
named point comes from the map.

At build time the catalog and the binding meet. For each function, D40
decides supported or not. A supported function's enable output is bound by the
builder to a handler that checks the function is supported, then calls the
consumer's enable callable with the function identifier and the state. The
timing parameters of clause 6.1.2 (when a newly enabled function takes effect,
and for how long) are the DER's to honor: the builder passes them through as
the values of their points and does not run timers, because it does not run
the DER.

Priorities are the same shape. Clause 7 says which function wins when two
command the same quantity; the builder can tell the consumer which functions
are enabled and at what priority, but the arbitration belongs to the thing
producing the power, so it is a callable the consumer implements and the
builder does not.

### Curves and schedules

A curve in the profile is an edit buffer: an output selects which curve index
is being edited, an output gives the number of points, and a hundred pairs of
outputs carry the X and Y values, with matching inputs for readback. The
builder holds one buffer per curve kind, accepts writes to its points, and on
commit (the profile defines which write commits) hands the consumer's receiver
a `Curve`: the index, the ordered pairs, and the axis units the catalog says
the receiving function uses. Reading the buffer's inputs reflects the buffer.
Schedules are the same mechanism with time-value pairs.

This is the one place the builder holds state across requests beyond what
`Session` already holds, and it is held per association like the rest.

### Controls

The builder implements `ControlProvider`. A control relay output block on a
binary output resolves to the point, which resolves to its role: a mode enable
goes through the function path above; anything else calls the point's write
binding. An analog output block resolves the same way, with the value unscaled
by the point's scaling and checked against its range before the binding sees
it; out of range is refused with the status the standard defines for it rather
than clamped. `select` runs every check but the binding; `operate` runs the
binding. Direct operate is both. A control on a point with no write binding is
`NOT_SUPPORTED` per point, which is the more informative answer the aggregator's plan
wanted and could not have until group 12 and 41 codecs existed; they exist.

### Events

Each bound input with an event class carries its resolution as a deadband. The
builder polls bindings on a cadence the consumer sets, or is told of changes
through a callable, whichever the consumer has; either way a change beyond the
deadband or any change of quality enqueues an event in `EventBuffers` with the
source timestamp. Supports flags never produce events. The mechanism is the
existing one; what is new is that the deadband and class come from the table
rather than from the caller.

### Layout

`stride(map, block_width, device_number)` offsets every resolved index of every
kind and returns a new map; `concatenate(maps)` checks the results do not
overlap and merges them. A fleet map is the aggregate's map followed by each
device's strided map, and the block advertisement is regenerated from the
result. The width is bounded below by the highest resolved index in the
single-device map plus one, and the loader reports the resulting device ceiling
so a consumer can refuse a fleet that exceeds it before serving part of one.
This is the whole of the library's contribution to aggregation; ordering,
ceiling policy and what the aggregate serves remain the consumer's.

## Work

### 1. The point model and loader -- `profile/model.py`, `profile/load.py`

The dataclasses above, a JSON form for them with a schema, and the loader that
resolves and validates. Block expressions are parsed from a small grammar
(`symbol`, `symbol + n`, `symbol + length * instance + n`) rather than
evaluated, so a malformed expression fails at load. The validator's variation
check reads Table 7 from the conformance tables, so extending
`scripts/extract_conformance.py` to read that table from IEEE 1815.2 is part of
this step.

### 2. The extractor -- `scripts/extract_profile.py`

Reads the IEEE 1815.2 companion tables into the map form; this half exists,
and produced the checked-in file. Reads a caller's copy of AN2018-001 into the
same form, with the semantic columns its tables carry. A `--reconcile` mode
diffs two maps by name and
reports moved, added, removed and changed points, which is the deliverable
the aggregator's first phase needs and which nobody should do by eye across a
thousand points. Like the conformance extractor it finds tables by their
headings and refuses to write a table that comes out short.

### 3. The function catalog -- `profile/functions.py`

One row per clause 6 function, with the fields under "Functions" above. Built
by hand from the clause text, because the catalog is structure rather than
data and the structure is small. A test asserts every function the map's points
reference is in the catalog and every catalog function's named points exist
in the synthetic example, so the two cannot drift.

### 4. Binding and the builder -- `profile/binding.py`, `profile/outstation.py`

The binding types, the builder, and the providers it produces. The builder is
the largest piece and is delivered in the order the sections above are written:
Class 0 and range reads, then quality and scaling, then events, then supports
and enables, then controls, then curves and schedules. Each lands with the
synthetic example map extended to exercise it.

### 5. Counters -- `objects.py`

Groups 20 and 21, static and frozen, in the variations Table 7 requires. New to
the library; small; needed because the system block has them.

### 6. Layout -- `profile/layout.py`

`stride` and `concatenate`, with the ceiling report.

### 7. Tests, and the synthetic example -- `tests/`, `conformance/example-map.json`

The example map is a dozen points across every kind and role, at indices
chosen to be obviously not the profile's, with one repeating block of two
instances and one curve. It is the fixture for every unit test and the map the
interoperability job serves: the existing masters read its measurements, the
Rust master reads its quality, and the sweep already covers the function codes.
A second interop case enables a function through its binary output and reads
the supports flag and the enable status back.

Negative controls as elsewhere: every validator rule has a test that breaks
the thing and confirms the loader refuses, and every builder behavior has a
test that binds the wrong thing and confirms the refusal reaches the wire.

### 8. Documentation

A page under `docs/` on assembling an outstation from a map, written for an
integrator who has the profile document and a device: obtain the source, run
the extractor, write the binding, build, serve. A template for the device
profile document the base standard requires, generated from a resolved map,
since the map knows exactly what is implemented. The roadmap entry in
[DESIGN.md](../DESIGN.md) becomes a link here.

### 9. Consumers

Each consumer's own repository carries its own step list. What this library
owes each is the contract above, and two things are worth recording here so
they are not lost.

The simulator gets one outstation per simulated device, on the port and link address
it already reserves, bound to its simulator through the same callable idiom
its Modbus server uses; the earlier subprocess agent is removed rather than
kept beside it. Its acceptance suite is EPRI's test procedure for AN2018-001,
which it already holds. Until this lands, its documentation lists the interface
as available, and that should be withdrawn rather than left standing.

The aggregator gets the builder plus `stride` and `concatenate`, and keeps its index
table, its ordering rule, its ceiling policy and its role model exactly as its
plan states them. Its first phase (build the map's semantic half, obtain the
companion tables, reconcile, record deltas) is what step 2 mechanizes.

## Sequencing

Steps 1 and 2 first, together, because the extractor is what turns the
in-hand AN2018-001 into a map the loader can validate, and that pair is useful
to the aggregator's first phase before anything serves a frame. Then 4 as far as
events, with 5 alongside, which is the monitoring outstation both consumers
need first. Then 3 with the rest of 4, which is functions, controls and curves.
Then 6, which is small and only the aggregator needs. 7 runs throughout; 8 closes.

The companion tables are in; the map format can be designed against the real
thing from the start, and reconciling AN2018-001 against it is a data change
through the extractor rather than a code change.

## Open

- **Redistributing the IEEE 1815.2 companion tables.** They are distributed
  without charge, which settled obtaining them; free to download is not the
  same as free to redistribute, and the checked-in copy rests on the reading
  that a machine-readable form of an openly published table, with its source
  named, is a reasonable use. That reading should be confirmed before a release
  carries the file.
- **The EPRI notice obligation**, already open in [DESIGN.md](../DESIGN.md).
  Resolving it decides whether a derived AN2018-001 map may ever be published
  from here. D36 assumes not, which is the safe side, and is easily relaxed.
- **How far 1815.2 moved.** The profile revision is described as relocating
  indices into subject-area blocks and adding points for several functions;
  until the tables are reconciled, the size of the delta is an estimate. It
  affects the aggregator's stride and nothing in the library.
- **Where clause 7 arbitration runs.** This plan puts it with the consumer, on
  the argument that the builder does not produce power. A simulator might
  prefer a reference arbitration it can borrow; if so it belongs in the
  catalog as data about priorities, not in the builder as behavior.
- **Time synchronization authority.** The profile expects the outstation to
  accept a time write and clear the need-time indication. A device whose clock
  is disciplined elsewhere should record the write without applying it, and
  the device profile document should say so; the aggregator's plan raises the same
  question and the answer should be one answer.
- **Operational states and role-based access.** IEEE 1815.2's informative
  annex on operational states (normal, local or maintenance, lockout) describes
  what a controlling station may do in each. It is informative and out of scope
  here, and it is the kind of thing a simulator built for security testing
  would want to model, so it is noted for whoever plans that.
- **Frozen counters and the historical blocks.** The profile's historical
  blocks lean on counters and freezes, and the library refuses freeze functions
  today. Step 5 adds the objects; whether the freeze function codes follow, or
  the historical blocks stay declared-offline, is decided when a consumer asks
  for them.

## References

- IEEE Std 1815.2-2025, clauses 5.2 (numbering and indexing), 5.4 (the
  implementation table), 6.1 (concepts for DER functions), 6.2 through 6.5
  (the functions), 7 (priorities); Annex C (operational states)
- DNP3 Application Note AN2018-001, sections 2.2 (points list and numbering),
  2.3 (modes and functions, multiplexed curves and schedules)
- IEEE Std 1815-2012, Table 4-6 and clause 4.2.2.7 for the qualifiers the
  builder emits
- [EPRI reference outstation for AN2018-001](https://github.com/epri-dev/der-dnp3-an2018),
  BSD-style license, point tables in its definition header
- [DESIGN.md](../DESIGN.md) D6 through D9 and D35, and the open item on the
  AN2018-001 attribution
- [CONTROLS.md](CONTROLS.md), [EVENTS.md](EVENTS.md) and
  [FRAGMENTATION.md](FRAGMENTATION.md), whose mechanisms the builder composes
- `scripts/extract_conformance.py` and `tests/test_conformance.py`, the pattern
  D36 follows
