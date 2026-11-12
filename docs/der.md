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

The simulation exists to make the points mean something, so that a master, a
test or a demonstration has values that move and controls that answer. It is
not a model of a DER, and it will not become one: see
[What is out of scope](#what-is-out-of-scope).

`py1815-der points` lists every point it serves. `py1815-der run --unsolicited`
serves it with unsolicited responses on, for a master that enables them.

Every setting (addresses, the bind address, equipment counts, event policy,
timeouts) can be kept in a JSON file, and most also have a flag:

```bash
py1815-der config --out der.json     # print every setting with its default
py1815-der run --config der.json     # run with the edited file
```

[Configuring the outstation](der-config.md) lists them all.

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
| **Class 0** | Binary inputs, counters, frozen counters and analog inputs. Output status is read by naming its group, and the advertisement block is left out, as the profile selects. At Level 4, the output status of each output that has an event class, class 0 included, is carried too ([Output events](#output-events-at-level-4)). |
| **Events** | `poll()` reads every input with an event class and buffers what changed, in the class the tables give it unless an [event policy](#setting-the-event-policy) says otherwise. Analog events keep only the latest per point and travel as 32-bit without time; binary events keep every change, with time. The time is the one the `Reading` gives, when it gives one and its quality is `GOOD`, moved onto the clock a master has set; otherwise it is when `poll()` recorded the event. The first `poll()` only notes where each point stands. |
| **Controls** | A select runs every check and executes nothing; an operate calls your binding. A binary output behaves as latched whichever operation commanded it. A point with no binding answers `NOT_SUPPORTED` for that point alone, and so does a control relay output block with the clear bit or the obsolete queue bit set. |
| **Output status** | An output's status and the input that mirrors it report the same thing: your `status=` reader when you give one, the last accepted write when you do not. |
| **Counters** | Bind a counter to a running total. A freeze copies each one into its frozen twin and buffers a timestamped event. Counters are never cleared, including by freeze-and-clear, unless the outstation is given a subset level; then freeze-and-clear clears them, as the subset tables require. Call `freeze_all()` on the period the master sets. |
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

`defaults` holds a rule for a kind of point (`BI`, `DBI`, `AI` or `CTR`) and `points` a
rule for one point, named by kind and index. A rule may carry any of four keys:

| Key | Meaning |
|---|---|
| `class` | The class the point's events are reported in: 1, 2 or 3. |
| `events` | `false` turns events off. The point is still read and still answers class 0. `true` turns them back on for one point of a kind whose rule turned them off. |
| `deadband` | Analog inputs, and counters that report value changes. How far the value moves before the change is an event, in engineering units; the point's multiplier converts it. A counter measures from the count in its last event. |
| `value_changes` | Counters only, from Level 3. `true` has a change in the count raise a counter event, beside the event every change of the counter's flags raises. Off unless a rule turns it on, since energy counters change all the time. |

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

### Reading the document, and printing it

The XML is for a program. To read the document, or to hand it to someone,
write it as a page:

```
py1815-der profile --out device-profile.xml --html device-profile.html
```

`--html FILE` writes one HTML file beside the document. It carries its own
style, runs no script and refers to nothing outside itself, so it opens from
a disk and can be mailed. To make a PDF, open it in a browser, print it, and
choose **Save as PDF**: each table's headings are repeated on every page, and
a row is never split between two.

The same command lays out a Device Profile that already exists, such as one a
vendor sent you:

```
py1815-der profile --from vendor.xml --html vendor.html
```

`--from FILE` reads a document instead of building one. It takes a document
written for any edition of the schema, since it reads the element names and
not a schema, and it decodes the file as its XML declaration says. It builds
no outstation, so it needs no point tables, and the configuration file and the
flags that describe an outstation are not read. It is used with `--html`.
`--out` and `--validate` apply to a document the command builds, and are
refused with `--from`.

| Flag | Does |
|---|---|
| `--out FILE` | Writes the document's XML to the file. Without it, the XML goes to standard output |
| `--validate XSD` | Checks the document built against your copy of the schema |
| `--html FILE` | Also writes the document as an HTML page to read and to print |
| `--from FILE` | Lays out this Device Profile XML file instead of building one. Used with `--html` |

These flags say what the command does with a document. They are not settings
of the outstation, so they have no place in the
[configuration file](der-config.md).

The page opens with the document's name, what its header states and the
device's vendor, name and versions, and then has a section for each part of
the document: the revision history, the configuration, the database, the
implementation table and the point lists. A setting is a row with its
capabilities, its current value and, where the document gives them, the
methods by which it is configured. Each point type is a table with a row for
each point and a column for each property the points carry.

The layout is this library's own. It is not the layout the Users Group's
stylesheet produces, and the page says so. A heading or a label is the
element's own name made readable: `maxReceivedFragmentSize` is shown as "Max
received fragment size", and `applConfig` as "Appl config", which is not the
wording of the Users Group's template. Nothing is added to what the document
states. A value it does not state is an empty cell, and an element the layout
does not recognize is still shown, by its label and its text. For the Users
Group's own layout, use their stylesheet as above.

A document that is not XML, or is not a Device Profile, is refused with a
message that says which, and so is one that declares a document type or is
larger than 8 MiB. A table has a column for each property any of its records
carries, so a document whose tables would be wider or larger than any real
profile's is refused as well.

The console lays a document out the same way, on the **DER** tab: see
[The console](console.md#der). From Python:

```python
from py1815.profile import device_profile_view

document = device_profile_view.read(xml)   # text, or the octets of a file
html = device_profile_view.page(document)
```

A profile generated from the IEEE 1815.2 tables carries that standard's point
names. Publishing one for your own device is what the document is for;
the tables themselves stay where they were.

## Choosing a subset level

IEEE 1815.2 asks for more than DNP3 Subset Level 2 in places: 32-bit setpoints,
frozen counter events, counters that a freeze never clears. The outstation's `level`
is 2, 3 or 4, and the Device Profile claims the level chosen. A master that implements
the subset and no more is served with `level=2`:

```python
outstation = DerOutstation(profile, binding, level=2)
```

Without a level, the outstation claims Level 2 and serves the profile's additions.
Any other value is refused with an error. `level2=True` still works as `level=2`, with
a deprecation warning.

What each level answers, beyond what the level before it does:

| Level | Answers |
|---|---|
| 2 | A read that names no variation is answered in the variations Level 2 requires a master to parse. Frozen counter events are not reported, and a freeze-and-clear clears, as it does at Levels 3 and 4. Reads of the packed binary input variation, of 16-bit frozen counter events, of the current time and of the internal indications are refused as unknown objects. Counter events are not reported, and a read of group 22 is answered with nothing. |
| none | As Level 2, with the profile's additions: frozen counters with time, frozen counter events with time, and a freeze that never clears. The reads Level 2 refuses are refused here too. |
| 3 | Reads of the packed binary input variation, answered with flags as the standard allows. Reads of 16-bit frozen counter events, answered in 32 bits. A read of the current time (group 50 variation 1, one object) and of the internal indications (group 80 variation 1, by index 0 to 15). Frozen counter events are reported in class 3 polls, without time, and frozen counters are reported without time when a read names no variation. A change in a counter's flags, such as communication lost or restored, raises a counter event (group 22 variation 1) in the class of the counter's frozen counter events; a change in its value raises one only where the event policy turns `value_changes` on. Reads of group 22 variations 0, 1 and 2 return them, in variation 1. |
| 4 | Everything Level 3 answers, with the profile's own variations (frozen counters and frozen counter events with time) when a read names none. The floating-point analog variations, reads of 16-bit frozen counters and frozen counter events with time, answered in 32 bits, and the analog input deadbands, which a master reads and writes; see [Level 4](#level-4-floating-point-and-deadbands). Binary and analog output events, and reads of the command event groups, answered with nothing; see [Output events at Level 4](#output-events-at-level-4). Double-bit inputs; see [Double-bit inputs](#double-bit-inputs). Device attributes (group 0); see [Device attributes](#device-attributes). Below Level 4 a request that names one of these is refused as an unknown object. |

Every level reads each static group by range as well as for all points, and each event
group by count as well as for all events.

An unflagged variation is replaced by its flagged one for any point whose
quality is not normal, so an offline point is never read as a plain number. Level 2 is
the configuration the conformance tests run against; see
[Testing](testing.md#the-certification-procedures-are-carried-out-section-by-section).

From Level 3 a master may move points between event classes, or turn their events off,
with an assign-class request (function code 22). Levels 3 and 4 accept it for binary
inputs, counters, frozen counters and analog inputs, and Level 4 also for the outputs
and the [double-bit inputs](#double-bit-inputs).
A point assigned to class 0 raises no events but stays in a class 0 read; at Level 4 an
output assigned to class 0 is in a class 0 read too, as [Output events at
Level 4](#output-events-at-level-4) describes. A change made
after the request is reported in the new class; events already buffered stay in the class
they were recorded in. A restart returns every point to the class it started with: the
outstation does not keep assignments. Level 2 and the default refuse the request as an
unsupported function.

## Level 4: floating point and deadbands

With `level=4` the outstation serves, in addition to everything below Level 4:

| Object | What a master reads |
|---|---|
| Analog input, variation 5 (group 30) | Each served analog input as a single-precision float with a flag octet |
| Analog output status, variation 3 (group 40) | Each served output as a single-precision float with a flag octet |
| Analog input events, variations 5 and 7 (group 32) | A change as a float, without and with time |
| Frozen counters, variation 6 (group 21) | Answered as variation 5: 32 bits, with flag and time |
| Frozen counter events, variation 6 (group 23) | Answered as variation 5: 32 bits, with flag and time |
| Analog input reporting deadbands, variations 1 to 3 (group 34) | Read and written, as described below |

**Floating point is not scaled.** An integer variation carries the value after the
point's scaling from the tables. A floating-point variation carries the value as
the binding gave it, in engineering units, which is the number a setpoint of
variation 3 or 4 already carries. A power of 1500 W with a multiplier of 1 reads as
1500 in both forms; a voltage of 240.0 V with a multiplier of 0.1 reads as 2400 in
variation 1 and as 240.0 in variation 5. Variation 0 and class 0 stay integer, and the
flags are the same in every form. Whether a change is an event is still decided on
the integer form, so a change smaller than one count of the multiplier is not an
event; the event carries the value as it stands when the change is seen.

**Class polls.** A class 1, 2 or 3 read is answered in one analog event variation,
which `analog_event_variation` chooses. At Level 4 that may be
`AnalogEventVariation.FLOAT32` or `FLOAT32_WITH_TIME`; below Level 4 the session
refuses them with `ValueError`. Timed 16-bit and 32-bit integer events (variations 3
and 4) are answered at every level.

**A 16-bit frozen counter** is answered in 32 bits, as a 16-bit counter without time
already is: a counter that accumulates energy passes 65535 quickly, and a master
that implements Level 4 parses both the 16-bit and the 32-bit variation.

**Deadbands.** A master reads the deadband of every served analog input with a
range, all objects or an index for each, in variation 0 (answered in 32 bits) or in
variation 1, 2 or 3, and writes variation 1, 2 or 3 by range or by index. A write is
answered with a null response. A write that names an index that is not an analog
input, carries a value that is negative or not a number, or does not hold the objects
it declares, is answered with the parameter-error indication and changes nothing.
Deadbands are not part of a class 0 response.

A written deadband is the one that decides whether the input's next change is an
event. The deadband you configured, with the binding or the event policy, is the
starting value. Variations 1 and 2 are unsigned counts in the transmitted units,
the numbers the integer variations carry, so a deadband of 20 on a voltage with a
multiplier of 0.1 is 2.0 V. Variation 3 is in engineering units, like the other
floating-point objects, and is converted with the point's multiplier: a written 5.0 is
50 for that voltage. Variations 1 and 2 read back rounded to a whole count, and a
deadband at or past what the variation holds reads as the largest value it holds.
A deadband written for an input that reports no events, such as one assigned to class
0, is kept and is used if that input reports events later;
`outstation.deadband(index)` returns the one in force, in transmitted units.

Group 34 holds analog input deadbands only. The deadband of a counter that reports
value changes is set by the event policy and is not read or written over DNP3;
`outstation.counter_deadband(index)` returns it.

A written deadband is held in memory. It is lost when the outstation restarts, which
then uses the configured deadbands again, and the Device Profile says that no
settings are kept through a restart.

### Output events at Level 4

At Level 4, an output reports an event when its value or flags change: binary output
events (group 11) and analog output events (group 42). `poll()` reads the output's status
as a master would, which is your `status=` reader when you give one and the last accepted
write when you do not, so a control a master sends, a change the device makes itself and
a status that goes stale each produce an event. The first `poll()` only notes where each
output stands. When one request commands an output twice, the outstation polls between
the two controls, so a request that latches an output on and then off reports both changes.

An output starts in the class the tables give it. The tables give none, so the class is
that of the input paired with the output, which reports the same change: a master polling
that class hears of both together. An output whose paired input reports no events reports
none. An output with no paired input reports in class 3. The [event
policy](#setting-the-event-policy) does not apply to outputs.

A master moves an output's events to another class with an assign-class request that
names group 10 or group 40, and turns them off by assigning class 0, which keeps the
output in a class 0 read. Assigning the paired
input moves only the input. An assignment that names group 12 or group 41 is accepted and
changes nothing, because it assigns the command events, which are not generated. An
output given a class again reports only the changes after the request. A restart returns
each output to the class it started in. `outstation.event_class(Kind.BO, index)` returns the
class in force.

Every change is kept, and a full class drops its oldest event and sets the overflow
indication, as for the inputs. A class poll returns the events in the order they
happened, binary and analog outputs among the inputs, with time. A master can also read
them by group, as variation 0, or in variations 1 and 2 of group 11 and 1 to 5 and 7 of
group 42. A class poll and a variation 0 read return group 11 variation 2 and group 42
variation 3, a 32-bit integer with time; `analog_event_variation` chooses the variation of
analog input events only. Floating-point values are in engineering units, as in an analog
output command and the other floating-point objects; whether a value changed is decided on
the integer form, as for analog inputs.

The command event groups, 13 and 43, are read and answered with nothing: no outstation
is required to generate them, and this one does not. A read of a variation these groups
do not offer is answered as an unknown object.

An output that has a class is also carried by a class 0 read, in group 10 variation 2 and
group 40 variation 1, because a master learns the value an event changes from class 0.
That includes an output a master assigned to class 0, which reports no events. An output
with no class, one whose paired input reports no events and that no master has assigned,
is left out, as at the lower levels; a restart returns each output to how it started.
`outstation.in_class_0(Kind.BO, index)` says whether a class 0 read carries a point.

## Double-bit inputs

A double-bit binary input is one point with four states, for a device that has two
contacts to report, such as a switch that can be open, closed, moving or faulted. The
profile defines none, so a double-bit point is one a tables document lists under the key
`DBI`, in the rows the other kinds use, and it is served only by an outstation at Level 4.

```python
binding.read(Kind.DBI, 3, lambda: switch.state())   # 0, 1, 2 or 3
```

The reader returns the state as a whole number from 0 to 3, or a `Reading` that carries the
state and its quality:

| State | Name | Meaning |
|---|---|---|
| 0 | INTERMEDIATE | Moving between its end conditions |
| 1 | DETERMINED_OFF | The end condition that a single-bit input would report as 0 |
| 2 | DETERMINED_ON | The end condition that a single-bit input would report as 1 |
| 3 | INDETERMINATE | Abnormal, or a condition the device defines |

Which physical condition is OFF and which is ON is the device's to say; the standard leaves
it to the vendor to document. A value that is not one of the four is sent as INDETERMINATE
with the point marked as not reachable, and `coverage()` lists the point as offline.

At Level 4 a master reads the points as group 3, in the packed variation (two bits a point)
or with flags. A point in an exception condition, such as one that is not online, is always
sent with flags. The points answer class 0 and report events as group 4, which a master reads
by class or by naming the group, in the variations without time, with absolute time and with
relative time. A change of state, or of any quality flag, is an event. Below Level 4, groups 3
and 4 are unknown objects, no event is buffered, the Device Profile lists none of the points,
and `coverage()` reports each of them as absent.
An event policy's `defaults` may name the kind `DBI`, and a point's class is set in the same
way as for a binary input. A master moves a point to another class, or turns its events off,
with an assign-class request that names group 3; a point assigned to class 0 stays in a class
0 read.

## Device attributes

At Level 4 the outstation answers reads of object group 0, the attributes a master can
discover about it, and takes writes of four of them. Below Level 4 group 0 is an object
the outstation does not have.

A master reads one attribute at a time (group 0 with the variation, qualifier 0x00,
range 0 to 0), reads variation 254 with qualifier 0x06 for every attribute in one response, and
reads variation 255 for the list of variations and which of them it may write. Each
attribute is answered with its data type, its length and its value. Only attribute set 0, the
one the standard defines, exists.

| Variation | What it reports | Where the value comes from |
|---|---|---|
| 209 to 215 | Secure Authentication version, security statistics, data sets | Zero: none of them is implemented. Variation 211 reports no user-specific attribute sets |
| 216 | Most binary outputs in a control request | The response and request sizes |
| 217, 218 | Timing accuracy, and how long it holds | `timing_accuracy_us`, and zero |
| 219 to 239 | For each kind of point, whether it reports events, its highest index and its count | The points served and the event classes they can report in |
| 240, 241 | Largest fragment sent, and received | The session: `max_response`, and the request size it accepts |
| 242, 243, 248, 250, 252 | Software and hardware versions, serial number, product, manufacturer | The `identity` settings of the [configuration](der-config.md#identity) |
| 245, 246, 247 | Location name, ID, device name | The `identity` settings, and a master may rewrite them |
| 249 | The subset level claimed | The level, as `4:` |

A group the outstation does not serve reports no points and a highest index of zero.
"Supports events" is true for a kind of point (binary, double-bit and analog inputs,
counters, frozen counters, binary and analog outputs) when a served point of that kind
reports its events in a class, or may be given one by an assign-class request. An
assign-class request therefore does not change it. Frozen analog inputs are not served, so
that attribute is false. The optional attributes 196 to 208 and 244 are not offered.

A master may write variations 245, 246 and 247 with text of at most 128 visible ASCII
characters, and variation 240, the largest fragment the outstation sends. A write of 240
changes how the session fragments its responses from the next one: it may be any size from
the largest block a read can need plus a response header (1028 octets with the default block
size; with a small one, at least the 139 octets that a 128-character name needs) up to the
`max_response` the session was given. A session given a smaller `max_response` than that
floor is refused with `ValueError`. A request that holds one unacceptable value changes
nothing and is answered with the parameter error indication. A written value lasts until
the outstation restarts; it is not stored.

In Python, the attributes belong to the outstation and its sessions:

```python
from py1815.attributes import DeviceInformation

information = DeviceInformation(manufacturer="Example", product="Controller 9", serial_number="1234")
outstation = DerOutstation(profile, binding, level=4, information=information)
session = outstation.session()   # answers group 0
outstation.attributes.snapshot() # every attribute now, by variation
```

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

## What is out of scope

This package is the protocol and the profile's point map. It is not the DER.

- **DER functions (IEEE 1815.2 clause 6).** The points of every function are
  served, and what the profile says about the points is done here: support
  is derived from what you bind, and a disabled function's inputs go out
  without `ONLINE`. What a DER does once a function is enabled (limit its
  power, hold a power factor, ride through a disturbance, ramp, revert
  after a timeout) is the device's. You bind the function's outputs to
  whatever carries it out.
- **Curves (clause 6.1.3).** `CurveStore` holds the curves and enforces the
  rules on the curve block. Following a curve, with its units, reference,
  response time and hysteresis, is the device's.
- **Schedules.** The schedule blocks are ordinary points to the builder, and
  nothing here runs a schedule.

For DER behavior worth testing a master against, bind a DER simulator or the
device itself behind the outstation. The simulated DER in this package
answers to six functions and follows two curves by straight lines, which is
enough to show the points working and is the whole of what it will do.

## What is not there yet

- **Floating-point variations below Level 4.** Inputs are served as integers,
  scaled by the tables, which is the profile's baseline. Level 4 adds the
  floating-point variations.
- **Measured figures in the Device Profile.** Clock drift, response time and
  timestamp error are left unstated until someone measures them.

## Reference

See [DER profile](reference/profile.md).
