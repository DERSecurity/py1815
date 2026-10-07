# The console

A web page for a DNP3 master: what an outstation holds, what it reports, and
every frame that passes, in a browser. It is for watching a device at a bench
and for showing the software working.

```bash
py1815-master console --demo --open
```

That starts three things in one process and opens the page: a simulated
IEEE 1815.2 DER listening as an outstation, a master connected to it, and the
console at `http://127.0.0.1:8815/`.

!!! note
    The page reads. It polls, reads named points, takes unsolicited
    responses and shows the traffic. The service behind it can operate
    outputs when started with `--allow-control`, through
    [its API](master-api.md#commanding); the page has no control for one yet.

## Starting it

The demonstration needs the profile's point tables, which this library may not
carry. Fetch them once:

```bash
py1815-der tables fetch
```

To watch an outstation that is already running, name it:

```bash
py1815-master console --outstation lab=192.0.2.10:20000 \
    --integrity-interval 30 --event-interval 2
```

| Option | Does |
|---|---|
| `--demo` | Starts a simulated IEEE 1815.2 DER and connects to it |
| `--outstation NAME=HOST:PORT` | Adds an outstation and connects to it. May be given more than once |
| `--outstation-address`, `--master-address` | The link addresses, for the outstations named. 1024 and 1 unless given |
| `--integrity-interval SECONDS` | Repeats an integrity poll of each outstation named |
| `--event-interval SECONDS` | Repeats an event poll |
| `--output-interval SECONDS` | Repeats a read of output status. As often as the integrity poll unless given; 0 for never |
| `--profile` | The outstations named are IEEE 1815.2 DER: name their points from the profile, and let the console show the profile's points they have not reported |
| `--tables FILE` | The profile tables, for `--demo` and `--profile` |
| `--bind HOST:PORT` | Where the console listens. `127.0.0.1:8815` unless given |
| `--token TOKEN` | Required of every request to the service. Needed to listen on anything but this machine. Read from `PY1815_MASTER_TOKEN` when not given |
| `--new-token` | With no token given, makes one for this run and prints the address that carries it |
| `--no-token` | Listens beyond this machine with no token, for a container whose port is published to this machine only |
| `--connect-wait SECONDS` | Keeps trying, for this long, to connect to an outstation that is not there yet at startup |
| `--allow-control` | Lets the service behind the console command an outstation. Without it every such operation is refused |
| `--open` | Opens the console in a browser |

Outstations can also be added from the page, under **Add outstation**.

### In Docker

From a checkout, with nothing installed but Docker:

```bash
docker compose up
```

and open `http://localhost:8815/`. Three things run:

| Service | Does |
|---|---|
| `tables` | Fetches the profile's point tables from IEEE into a volume, the first time only. They may not be redistributed, so each machine gets its own copy |
| `der` | A simulated IEEE 1815.2 DER, listening as an outstation |
| `master` | The master, connected to `der`, serving its API and the console |

The master's image can also be run by itself, against any outstation:

```bash
docker build --target master -t py1815-master .
docker run --rm -p 127.0.0.1:8815:8815 py1815-master \
    console --bind 0.0.0.0:8815 --new-token --outstation lab=192.0.2.10:20000
```

Inside a container the console listens on every interface, and publishing the
port is what decides who can reach it. Listening that widely needs a token, so:

- `--new-token` makes one for the run and prints the address that carries it.
- `PY1815_MASTER_TOKEN` gives one that stays the same from run to run.
- `--no-token` does without, for a port published to this machine only, as
  `compose.yaml` publishes it. A request then still has to name this machine
  as its host.

For a profile's point names in the image, mount the volume the tables were
fetched into at `/data` and add `--profile`. `--connect-wait 60` keeps trying
for a minute to connect to an outstation that starts after the master does.

## What it shows

Outstations are listed on the left, each with a lamp for its connection. The
one selected has six tabs.

| Tab | Shows |
|---|---|
| **Overview** | Addresses, connection state, the scans being repeated, how the requests so far ended, how many points of each type have been reported, and every internal indication of the last response as a lamp |
| **Points** | A table for each point type |
| **Commands** | Scans, reads, unsolicited responses, any request by function code, and the result of each |
| **Events** | Events as they arrive, newest first, and whether each was polled or sent unasked |
| **Traffic** | Every frame, and the one selected read layer by layer |
| **Log** | What the console asked for, and what came of it |

### Points

One table for each of binary inputs, binary outputs, counters, frozen
counters, analog inputs and analog outputs.

| Column | Holds |
|---|---|
| Index | The point's index |
| Name | Its name, when the outstation has a profile |
| Value | `ON` or `OFF`, a count, or an analog value as transmitted |
| Flags | The flag bits that are set, by name. `no flags` for a variation that carries none, and `none set` when not even `ONLINE` is |
| Outstation time | The time the outstation gave the value, when it gave one |
| Object | The group and variation that carried it |
| Reported by | A static object, or an event |
| Age | How long since it was last reported |

The table holds still while it is read. Its columns keep their widths, a row
whose point has not changed is not redrawn, and a value is marked only when it
or its flags change, not when the same value is reported again.

- **Filter** narrows the table by index, name or flag.
- **Changed in the last 10 s** shows only the points whose value or flags
  changed lately.
- **Show points not reported** lists the points of the profile the outstation
  has not reported, set back and marked `NOT REPORTED`, beside the ones it
  has, and counts each type against the profile. A mandatory point among them
  is marked. It is offered when the outstation has a profile.

A point is not reported either because the outstation does not implement it or
because nobody has read it. A master cannot tell which from silence.

!!! note "Outputs"
    An integrity poll does not return what the outputs stand at. The
    IEEE 1815.2 profile leaves output status out of class 0, so it is read by
    its groups. The console reads it as often as the integrity poll for an
    outstation given one, and **Output status** on the Commands tab reads it
    once.

A point that is an enumeration is named without the values it can take, and
has a small **i** beside its name. Point at it, or reach it with the keyboard,
and the values are listed one to a line:

```
0: Curve is not defined
1: Not applicable / Unknown
2: Volt-Var
3: Frequency-Watt
```

### Commands

| Card | Does |
|---|---|
| **Scan** | An integrity poll, an event poll, one class, or output status. **Repeat** sets how often each is made unasked, and an empty field stops it |
| **Read points** | One point type, by a list of indices or `all` |
| **Unsolicited responses** | Asks the outstation to report the classes ticked without being polled, or to stop |
| **Request by function code** | Any request: a function, and the object headers after it in hexadecimal |

Each shows its result: the request, how it ended, how many fragments and
objects came back, the indications, how long it took, and the objects. An
outstation that does not answer is shown as a timeout, and one that refuses
shows the indication it refused with.

### Traffic

Each frame with its time, its direction and one line saying what it is:

```
→ READ seq 4: class 1, class 2, class 3
← RESPONSE seq 4 CON [NEED_TIME, DEVICE_RESTART]: g32v1 x7
→ CONFIRM seq 4
```

Select one and it is read beside its octets: the data link, the transport
header, and the application fragment on the frame that completed one. Point at
a layer and its octets are picked out; checksums are left unshaded. The view
can be narrowed to one direction or to frames that carry an application
fragment, paused, and cleared.

## Who can reach it

The console can read an outstation and, in time, will command one, so who can
reach it matters.

- It listens on this machine only. To reach it from another, give it a token:

  ```bash
  py1815-master console --bind 0.0.0.0:8815 --token "$(openssl rand -hex 16)"
  ```

  It prints an address that carries the token, and refuses any request to
  the service without it. The page's own files need none: they are the same
  for everyone and say nothing about any outstation. It speaks plain HTTP, so put it behind something that speaks TLS
  if the network between is not yours.

- It takes a request only from its own page. A browser will carry a request
  from any site to a port on your machine, so a request whose `Origin` is
  another site, or that names a host this machine is not, is refused.

- It loads nothing from the network: no font, script or style. It works on a
  lab network that reaches nothing, and tells nobody that it is running.

## What is behind it

The page holds no logic. It asks a service for things and shows what comes
back, and anything it does a script can do with the same requests. See
[The master's API](master-api.md).
