# Serving a DER

An IEEE 1815.2 outstation is the profile's point map with a device behind it.
`py1815.profile` supplies the first half and a way to attach the second: it
loads the profile's tables, resolves them for your DER, and turns a set of
bindings into everything a [`Session`](reference/session.md) needs. You say
where each value comes from, in engineering units. Scaling, flags, class 0,
events, control echoes and counter freezes are done for you.

## Run the simulated one first

```
pip install .
py1815-der tables fetch
py1815-der run
```

and, from a second terminal, `py1815-der poll`. That is the profile's point
map served over a simulated DER: a three-phase, storage-coupled generator
with a system meter, four energy counters, and six functions a master can
enable (active power limit, charge/discharge, constant vars, constant power
factor, volt-var and volt-watt). The repository's `Dockerfile` runs the same thing in a container;
the README has the commands.

`py1815-der points` lists every point it serves. `py1815-der run --help` has
the link addresses, the bind address, and options for resolving equipment
blocks (`--inverters 2`, and so on). `py1815-der run --unsolicited` serves it
with unsolicited responses on, for a master that enables them.

## Where the tables come from

IEEE 1815.2 specifies its points in a companion workbook, which IEEE
distributes without charge and does not permit others to redistribute. This
library therefore carries none of it. `py1815-der tables fetch` downloads the
workbook from IEEE to the machine it runs on and reads it into the JSON
document the loader takes; `py1815-der tables build <workbook>.xlsx` does the
reading for a copy obtained some other way.

The document is looked for, in order, at the path given to the loader, at the
path in `PY1815_TABLES`, and at `~/.py1815/ieee-1815-2-2025.json`. It is never
looked for inside the installed package, and should not be put in anything
you publish: an image, a repository, a wheel.

## Bind your own device

Four steps: load the map, bind the points, build the outstation, serve it.

```python
import asyncio

from py1815 import OutstationServer
from py1815.control import CommandStatus
from py1815.profile import Binding, Composition, DerOutstation, Kind, Quality, Reading, load_map

point_map = load_map(composition=Composition(inverters=1))

binding = Binding()

# An input is bound to something that returns its value.
binding.read(Kind.AI, 537, lambda: meter.watts(), deadband=500)

# A source that can fail says so, and the master sees the quality.
def frequency() -> Reading:
    if not meter.reachable:
        return Reading(meter.last_hertz, Quality.COMM_LOST)
    return Reading(meter.hertz())

binding.read(Kind.AI, 536, frequency)

# An output is bound to what a command on it does.
def set_limit(percent: float) -> CommandStatus | None:
    return None if inverter.set_power_limit(percent) else CommandStatus.HARDWARE_ERROR

binding.output(Kind.AO, 87, set_limit, initial=100.0)
binding.output(Kind.BO, 17, lambda on: inverter.enable_power_limit(bool(on)), initial=False)

outstation = DerOutstation(point_map, binding)


async def main() -> None:
    server = OutstationServer(outstation.session(), bind="0.0.0.0:20000")
    await server.start()
    try:
        while True:
            await asyncio.sleep(1.0)
            outstation.poll()          # buffer events for whatever changed
    finally:
        await server.stop()


asyncio.run(main())
```

The indices above are the profile's; `py1815-der points` and the tables say
which is which. As written this raises, and that is the next section.

## Mandatory points

The profile marks some points mandatory for every outstation. `DerOutstation`
refuses to build one that leaves any of them unserved, and names them:

```
MapError: <n> point(s) the profile makes mandatory are not bound: AI1, AI2, ...
```

A point is served when you bind it, and also when the builder can answer it
without you:

- **An input paired with a bound output** reports what that output last
  accepted, which is what the profile's paired points mean. Bind the analog
  output for a setting and the analog input that reads it back comes with it.
  Before any write it reports the `initial` value you gave, or, given none,
  reports itself as never read rather than as zero.
- **A "supports" input** reports whether its function's enable output is
  bound. Support is derived, never declared: you cannot advertise a function
  you did not bind.
- **A point whose value the tables fix**, such as the profile version, and the
  block starting indices advertised from AI65000.

Everything else is yours to bind. An optional point you do not bind is absent
from the map: a class 0 read does not carry it and a read of its index is
refused. A zero would be indistinguishable from a real value.

`DerOutstation(point_map, binding, strict=False)` builds a partial map
anyway. That is useful while bringing a device up, and is not a conformant
outstation.

## How much of the profile is served

A partial map is expected to grow, and `coverage()` says where it stands:

```python
report = outstation.coverage()
print(report)
```

```
8 of 17 points served, 9 absent
  1 of 2 mandatory points served
  7 of 15 optional points served
  3 served point(s) offline when this was reported
not conformant; mandatory points not served: AI1

           mandatory  optional
bound              1         2
mirror             0         1
supports           0         1
fixed              0         3
absent             1         8

BO0        absent   -          Enable Widget Mode
BO1        absent   -          Unpaired switch
BI0      M bound    good       Alarm
BI1        supports good       Supports Widget Mode
BI2        absent   -          Widget Enabled
BI9        absent   -          Lone flag
AO0        bound    never-read Setpoint
AI0        fixed    good       Version
AI1      M absent   -          Power
AI2        bound    comm-lost  Voltage
AI3        mirror   never-read Setpoint readback
...
```

There is one line for every point of the map, served or not. The columns are
the point, `M` if the profile makes it mandatory, where its value comes from,
its quality, and its name.

- **Where the value comes from** is one of the cases under
  [Mandatory points](#mandatory-points): `bound` is a point you bound,
  `mirror` an input reading back a bound output, `supports` a function's
  supports input, and `fixed` a value the tables fix. `absent` is a point
  nothing serves. This column is settled when the outstation is built.
- **Quality** is what the point's source said when the report was made, in the
  words of [`Quality`](reference/profile.md#binding). Anything but `good` is a
  point that is served with its ONLINE flag clear, so a point bound to a source
  that has nothing behind it yet shows as bound and not good. This column is a
  snapshot: the report asks each source once.

The summary says how far the map is from one `strict` would accept, and names
the mandatory points still to serve. `report.conformant` is the same test.

The report is data. `report.entries` holds an `Entry` per point, and
`served`, `absent`, `offline` and `missing` select from it. To see what a new
binding changed, keep the earlier report:

```python
for entry in outstation.coverage().changed_since(earlier):
    print(entry.address, entry.source.value)
```

Binding one more point and rebuilding is the whole of the change: the point is
answered, and the [Device Profile document](#the-device-profile-document)
generated from the rebuilt outstation lists it. Binding an output may bring an
input with it, and the report shows both.

`py1815-der points --coverage` prints the report for the simulated DER.

A report is not part of what a master is answered with. Taking one buffers no
event and changes no output.

## What the builder does with a binding

| | |
|---|---|
| **Scaling** | A value goes on the wire as `(value - offset) / multiplier`, rounded, from the tables. A setpoint comes off it the other way. |
| **Range** | An input outside the tables' range is reported with `OVER_RANGE`. A setpoint outside it is refused with `OUT_OF_RANGE`, not clamped. |
| **Quality** | `GOOD` is `ONLINE`. `COMM_LOST` clears `ONLINE` and sets `COMM_LOST`. `NEVER_READ` sets `RESTART`. A reader that raises is reported as `COMM_LOST` and logged; the rest of the response is unaffected. |
| **Functions** | A function is supported when its enable output is bound. While it is disabled its inputs are sent with their values and without `ONLINE`, as clause 6.1.1 requires; the supports input and the input reporting whether it is enabled stay `ONLINE`. Whether it is enabled is what its enable output stands at: your `status=` reader when you give one, the last accepted write when you do not. `disabled_offline=False` turns this off. |
| **Class 0** | Binary inputs, counters, frozen counters and analog inputs. Output status is read by naming its group, and the advertisement block is left out, as the profile selects. |
| **Events** | `poll()` reads every input with an event class and buffers what changed, in the class the tables give it unless an [event policy](#setting-the-event-policy) says otherwise. Analog events keep only the latest per point and travel as 32-bit without time; binary events keep every change, with time. The time is the one the `Reading` gives, when it gives one and its quality is `GOOD`, moved onto the clock a master has set; otherwise it is when `poll()` recorded the event. The first `poll()` only notes where each point stands. |
| **Controls** | A select runs every check and executes nothing; an operate calls your binding. A binary output behaves as latched whichever operation commanded it. A point with no binding answers `NOT_SUPPORTED` for that point alone. |
| **Output status** | An output's status and the input that mirrors it report the same thing: your `status=` reader when you give one, the last accepted write when you do not. |
| **Counters** | Bind a counter to a running total. A freeze copies each one into its frozen twin and buffers a timestamped event. Counters are never cleared, including by freeze-and-clear. Call `freeze_all()` on the period the master sets. |
| **Time** | The session asks for the time until a master writes it, and event and freeze times follow what was written. |
| **Unsolicited responses** | Off unless the session is built with `outstation.session(unsolicited=True)`. Then the events `poll()` buffers are reported to a master that has enabled their class, without waiting to be polled; call `server.notify()` after `poll()` to send them at once. Nothing in the map or the binding changes. See [Serving an outstation](outstation.md#unsolicited-responses). |

A check that depends on state, not on the value, goes in `check=`: it runs on
select and again on operate, and returns the status to refuse with.

```python
binding.output(Kind.AO, 87, set_limit, check=lambda _value: (
    CommandStatus.LOCAL if inverter.in_local_mode else None
))
```

## When the device applies something else

A device may put a different value in force than the one a master wrote: it
clamps to a limit, ramps, or refuses part of the request. The master has to see
what was applied, not its own request echoed back. Bind the output's status to
the device, and both the output status and the mirroring input report it:

```python
binding.output(Kind.AO, 87, inverter.set_power_limit, status=lambda: inverter.power_limit)
```

`poll()` reads that input like any other, so when the device changes the value
with no command behind it, the master gets an event.

The same reader decides whether a function is enabled. Give an enable output a
`status=` reader and the function's inputs are marked as in effect when the
device says it is enabled: after the outstation restarts beside a device that
kept running, when another interface enabled it, and no longer once the device
has turned it off by itself. The reader is called for each of the function's
inputs that is read, so keep it as cheap as the others. If it raises, the
function is treated as disabled until it answers again.

## Reporting without commanding

An outstation can be one of several interfaces onto a device, with another of
them holding control. Build it read-only and it reports everything and
commands nothing:

```python
outstation = DerOutstation(point_map, binding, read_only=True)
```

Every control on a bound output is refused with `NOT_AUTHORIZED`, on select,
operate and direct operate, and your binding is never called. Pass
`read_only_status=CommandStatus.BLOCKED_OTHER_MASTER` if that says it better
for your device. Reads, freezes and the time write work as before.

It still reports what each output stands at, from the `status=` reader, since
that value was set by whichever interface does command. Give every output a
status reader on a read-only outstation: without one it can only report the
initial value you bound, or that it has nothing to report. That matters most
for an enable output, because without a reader the function it enables is
reported as disabled, and its inputs as not in effect, unless you bound it
with `initial=True`.

`outstation.read_only` may be changed while the outstation runs, for a device
whose control interface is reassigned. A change forgets the writes the
outstation had accepted: an output without a `status=` reader reports nothing
until it is written again. An operate that arrives after the outstation became
read-only is refused like any other control, with the same status, even when
its select was granted before the change. Giving control back withdraws any
select granted before the outstation was read-only, so the master has to select
again. A `Session` you build yourself instead of through `outstation.session()`
is not told; call its `abandon_select()` when you give control back.

## Setting the event policy

The tables give each point a default event class. Which points report, in which
class, and how far an analog input moves before it does, is the deployment's to
decide, and it is decided with data and not in the code that binds the points:

```python
policy = {
    "defaults": {
        "AI": {"class": 2},
        "BI": {"class": 1},
    },
    "points": {
        "AI537": {"class": 1, "deadband": 500},   # 500 W, in engineering units
        "AI536": {"deadband": 0.05},              # 0.05 Hz
        "BI12": {"events": False},                # static only
        "CTR0": {"class": 2},                     # the class its freezes are logged in
    },
}

outstation = DerOutstation(point_map, binding, event_policy=policy)
```

`defaults` holds a rule for a kind of point (`BI`, `AI` or `CTR`) and `points` a
rule for one point, named by kind and index. A rule may carry any of three keys:

| Key | Meaning |
|---|---|
| `class` | The class the point's events are reported in: 1, 2 or 3. |
| `events` | `false` turns events off. The point is still read and still answers class 0. `true` turns them back on for one point of a kind whose rule turned them off. |
| `deadband` | Analog inputs only. How far the value moves before the change is an event, in engineering units; the point's multiplier converts it. |

What is in force for a point is settled in this order:

| | First | Then | Then |
|---|---|---|---|
| **Class** | the point's own rule | the rule for its kind | the tables |
| **Deadband** | the point's own rule | `deadband=` given to `binding.read`, in transmitted units | the rule for its kind |

A rule for a kind moves the points that already report events and leaves the
others alone: a "supports" input, or a point the tables give no class, stays
static until it is named. A deadband for a whole kind is the same number of
engineering units for every analog input, watts and volts alike, so it suits a
map whose points share a scale and is best left out otherwise. With no deadband
from anywhere, every change of the transmitted value is an event. A change of
quality is always an event, whatever the deadband.

The policy is checked when the outstation is built, so a mistake stops startup:
a point the map does not hold, a class outside 1 to 3, a negative deadband, a
deadband on anything but an analog input, a rule for an output, or a key that
is not one of the three. A point the map holds and you have not bound yet is
accepted, so one policy can cover a binding that is still growing.

The library reads no policy file. The mapping above is what a JSON or YAML
document loads to, so keep the policy wherever your configuration lives and
hand over the result:

```python
import json

with open("event-policy.json", encoding="utf-8") as stream:
    outstation = DerOutstation(point_map, binding, event_policy=json.load(stream))
```

`EventPolicy` and `EventRule` are the same thing as dataclasses, for a policy
built in code, and `EventPolicy.from_mapping` turns the mapping into them.
`outstation.event_class(kind, index)` and `outstation.deadband(index)` say what
is in force, and the [Device Profile document](#the-device-profile-document)
lists both for every point.

## Curves

Functions that follow a curve share one block of points and a selector that says which
curve the block is showing. `CurveStore` is the state behind that block, with the rules
clause 6.1.3 attaches to it:

```python
from py1815.profile.curves import CurveStore

curves = CurveStore(count=10)
# The selector, and the fields and points that follow it; the inputs are laid out alike.
curves.bind(binding, output=244, readback=328, referenced=107)

# A function names its curve through one setting, and follows curves of some types.
volt_var = curves.reference(binding, 217, types=[2], enabled=lambda: inverter.volt_var_on)

curve = volt_var()            # None while the function names no curve
if curve is not None:
    target = curve.at(measured)   # in the units the curve's points were written in
```

A selector naming a curve that does not exist is refused. A curve named by an enabled
function cannot be edited until the function is disabled or pointed at another curve. A
function cannot be pointed at a curve of a type it does not follow. The points are kept
as the integers a master wrote, since their scaling depends on the units the curve
declares.

The simulated DER uses a store for volt-var and volt-watt.

## The Device Profile document

IEEE 1815 has every device publish a Device Profile: what it implements and
how it is configured, in an XML form the DNP Users Group maintains a schema
for. An outstation built here writes its own:

```
py1815-der profile --vendor "Example Co" --out device-profile.xml
```

or, for your own outstation and session:

```python
from py1815.profile import device_profile

session = outstation.session()
identity = device_profile.Identity(vendor="Example Co", device="EX-100", port=20000)
document = device_profile.render(device_profile.build(outstation, session, identity))
```

The document is schema version 2.12.00 and is read from the objects it
describes. The point lists are what the outstation serves, with each point's
class, class 0 membership, range, scaling and units. The class is the one in
force, so an event policy shows in it, and each analog input that reports
events lists its deadband in transmitted units. The addresses, fragment
sizes, select timeout and event buffer size are the session's. The
implementation table lists the objects, function codes and qualifiers that
session answers, so a monitor lists no controls and an outstation with no
counters lists no freezes. The test suite sends the session every request the
table lists, and a sample of what it leaves out, and checks they agree.

It leaves out what only a measurement or a test laboratory can supply: clock
drift, response time, timestamp error, and a conformance test result. The
schema makes those optional, and an absent element reads as "not stated".
Pass `statuses=` to `build` to list the command statuses your own bindings
can return; the ones the session and builder answer with are listed already.

The schema and its rendering stylesheet are the Users Group's, available to
members, and are not carried by this library. With your own copies beside the
file:

```
pip install xmlschema
py1815-der profile --out device-profile.xml --validate DNP3DeviceProfile021200.xsd
xsltproc DNP3DeviceProfile021200.xslt device-profile.xml > device-profile.html
```

A profile generated from the IEEE 1815.2 tables carries that standard's point
names. Publishing one for your own device is what the document is for;
the tables themselves stay where they were.

## Answering as Subset Level 2 only

IEEE 1815.2 asks for more than DNP3 Subset Level 2 in places: 32-bit setpoints,
frozen counter events, counters that a freeze never clears. A master that implements
the subset and no more can be served by building the outstation with `level2=True`:

```python
outstation = DerOutstation(profile, binding, level2=True)
```

A read that names no variation is then answered in the variations Level 2 requires a
master to parse, frozen counter events are not reported, and a freeze-and-clear
clears. An unflagged variation is replaced by its flagged one for any point whose
quality is not normal, so an offline point is never read as a plain number. This is
the configuration the conformance tests run against; see
[Testing](testing.md#the-certification-procedures-are-carried-out-section-by-section).

## Memory on a small controller

The library is pure Python with no runtime dependencies, so it runs wherever
CPython does, including 32-bit and 64-bit ARM Linux. CI runs the unit suite on
32-bit ARM as well as on the 64-bit machines the other jobs use; see
[Testing](testing.md#the-suite-also-runs-where-an-integer-is-32-bits).

The one part of an outstation whose size you choose is the event buffers.
`event_capacity` is how many events each of the three classes holds before its
oldest is dropped, and the default is 2000. The buffers are empty while a
master keeps polling and full when it has gone away, so the full figure is the
one to budget for.

Measured on CPython 3.12, 64-bit Linux, a binary or frozen counter event costs a
little under 300 bytes, and all three classes full of them at the default
capacity come to about 1.6 MiB. An analog event costs nearer 400 bytes, because
keeping only the latest one per point needs an index beside it, but there is at
most one per analog point, as below. To budget without counting points, size
against the analog figure: every slot holding an analog event comes to about
2.3 MiB at the default capacity, and no mix of events costs more. The figures
are approximate: they count what Python allocates for the events and not the
interpreter around them, and they move with the Python version. A 32-bit build
needs roughly half as much, because most of an event is pointers, and the
32-bit CI job prints its own figures on every run. To get the numbers for your
own interpreter and capacity:

```bash
python scripts/measure_event_memory.py --capacity 250
```

The [script](https://github.com/DERSecurity/py1815/blob/main/scripts/measure_event_memory.py)
is in the repository and not in the installed package.

To size the buffers down, pass a smaller `event_capacity`. The cost is linear
in it, and what you give up is history: how many changes the outstation can
hold for a master that is not reading them. A workable capacity is the number
of binary changes and counter freezes you expect between two polls of the
slowest master you serve, with room for the outage you want to ride through.
Analog inputs do not need counting, because the builder keeps only the latest
event per analog point, so they occupy at most one slot each however long the
master is away. When a class does fill, its oldest event is dropped and the
master is told, through the event buffer overflow indication, that it missed
something.

A session built without the profile takes its buffers from
`EventBuffers(capacity=...)`, which has its own default and the same cost per
event.

## What is not there yet

- **Schedules as objects.** The schedule blocks are ordinary points to the
  builder, and nothing runs a schedule. Curves have a store (see above);
  hysteresis, where a curve doubles back, is not followed.
- **Floating-point variations.** Inputs are served as integers, scaled by the
  tables, which is the profile's baseline. A floating-point setpoint is
  accepted and taken as engineering units.
- **Measured figures in the Device Profile.** Clock drift, response time and
  timestamp error are left unstated until someone measures them.

## Reference

See [DER profile](reference/profile.md).
