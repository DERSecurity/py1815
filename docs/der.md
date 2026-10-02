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
with a system meter, four energy counters, and four functions a master can
enable (active power limit, charge/discharge, constant vars, constant power
factor). The repository's `Dockerfile` runs the same thing in a container;
the README has the commands.

`py1815-der points` lists every point it serves. `py1815-der run --help` has
the link addresses, the bind address, and options for resolving equipment
blocks (`--inverters 2`, and so on).

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

## What the builder does with a binding

| | |
|---|---|
| **Scaling** | A value goes on the wire as `(value - offset) / multiplier`, rounded, from the tables. A setpoint comes off it the other way. |
| **Range** | An input outside the tables' range is reported with `OVER_RANGE`. A setpoint outside it is refused with `OUT_OF_RANGE`, not clamped. |
| **Quality** | `GOOD` is `ONLINE`. `COMM_LOST` clears `ONLINE` and sets `COMM_LOST`. `NEVER_READ` sets `RESTART`. A reader that raises is reported as `COMM_LOST` and logged; the rest of the response is unaffected. |
| **Class 0** | Binary inputs, counters, frozen counters and analog inputs. Output status is read by naming its group, and the advertisement block is left out, as the profile selects. |
| **Events** | `poll()` reads every input with an event class and buffers what changed, in the class the tables give it. Analog events keep only the latest per point and travel as 32-bit without time; binary events keep every change, with time. The first `poll()` only notes where each point stands. |
| **Controls** | A select runs every check and executes nothing; an operate calls your binding. A binary output behaves as latched whichever operation commanded it. A point with no binding answers `NOT_SUPPORTED` for that point alone. |
| **Counters** | Bind a counter to a running total. A freeze copies each one into its frozen twin and buffers a timestamped event. Counters are never cleared, including by freeze-and-clear. Call `freeze_all()` on the period the master sets. |
| **Time** | The session asks for the time until a master writes it, and event and freeze times follow what was written. |

A check that depends on state, not on the value, goes in `check=`: it runs on
select and again on operate, and returns the status to refuse with.

```python
binding.output(Kind.AO, 87, set_limit, check=lambda _value: (
    CommandStatus.LOCAL if inverter.in_local_mode else None
))
```

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
class, class 0 membership, range, scaling and units. The addresses, fragment
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

## What is not there yet

- **Curves and schedules as objects.** The multiplexed curve and schedule
  blocks are ordinary points to the builder. The simulated DER shows one way
  to hold a curve store behind them (`py1815.profile.der`); a builder-owned
  edit buffer that hands a function its curve as a list of pairs is planned.
- **Floating-point variations.** Inputs are served as integers, scaled by the
  tables, which is the profile's baseline. A floating-point setpoint is
  accepted and taken as engineering units.
- **Unsolicited responses.** Events are reported when polled.
- **Measured figures in the Device Profile.** Clock drift, response time and
  timestamp error are left unstated until someone measures them.

## Reference

See [DER profile](reference/profile.md).
