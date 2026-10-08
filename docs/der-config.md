# Configuring the outstation

Every setting of `py1815-der` can be kept in one JSON file. Most also have a
command-line flag, and a flag overrides the file. Three are set in the file
only: `disabled_offline`, `confirm_timeout` and `event_policy`. The Flag column
of the tables below shows which settings have one.

## Quick start

Print a complete configuration, edit it, and run with it:

```bash
py1815-der config --out der.json
# edit der.json
py1815-der run --config der.json
```

`py1815-der config` prints every setting with its default filled in, so the
file shows everything that can be changed. `run`, `points`, `profile` and
`config` all take `--config FILE`.

## The file

```json
{
  "bind": "127.0.0.1:20000",
  "tables": null,
  "outstation_address": 1024,
  "master_address": 1,
  "unsolicited": false,
  "read_only": false,
  "level2": false,
  "disabled_offline": true,
  "event_capacity": 2000,
  "max_response": 2048,
  "select_timeout": 10.0,
  "confirm_timeout": 10.0,
  "idle_timeout": 300.0,
  "event_policy": null,
  "composition": {
    "meters": 0,
    "der_units": 0,
    "inverters": 0,
    "batteries": 0
  },
  "simulation": {
    "seed": 0,
    "tick": 1.0
  },
  "identity": {
    "vendor": "Not stated",
    "device": "py1815 simulated DER outstation",
    "hardware_version": "Not applicable (software)",
    "software_version": "",
    "author": "py1815"
  }
}
```

Every setting is optional. A file that sets one thing is valid, and the rest
keep their defaults.

## Settings

| Setting | Default | Flag | Meaning |
|---|---|---|---|
| `bind` | `"127.0.0.1:20000"` | `--bind` | Address and port to listen on. The default accepts connections from this machine only. Use `0.0.0.0:20000` to accept them from other machines |
| `tables` | `null` | `--tables` | Path of the IEEE 1815.2 profile tables file. `null` uses the usual locations. See [Where the tables come from](der.md#where-the-tables-come-from) |
| `outstation_address` | `1024` | `--outstation-address` | This outstation's DNP3 link address |
| `master_address` | `1` | `--master-address`, `--any-master` | The master's DNP3 link address. `null` (or `--any-master`) serves whichever master speaks first on a connection |
| `unsolicited` | `false` | `--unsolicited` | Send unsolicited responses: announce a restart, and report the events of each class a master enables |
| `read_only` | `false` | `--read-only` | Refuse every control, so a master can read and cannot command. See [Reporting without commanding](der.md#reporting-without-commanding) |
| `level2` | `false` | `--level2` | Answer as a DNP3 Subset Level 2 outstation, without the profile's additions. See [Answering as Subset Level 2 only](der.md#answering-as-subset-level-2-only) |
| `disabled_offline` | `true` | | Clear the `ONLINE` flag on the inputs of a function that is disabled, as IEEE 1815.2 clause 6.1.1 requires |
| `event_capacity` | `2000` | `--event-capacity` | Events each class holds before the oldest is dropped |
| `max_response` | `2048` | `--max-response` | Largest response fragment to send, in octets |
| `select_timeout` | `10` | `--select-timeout` | Seconds a select stays valid |
| `confirm_timeout` | `10` | | Seconds to wait for a master to confirm a response. `null` waits without limit, and is not allowed when `unsolicited` is true |
| `idle_timeout` | `300` | `--idle-timeout` | Seconds of silence before a connection is closed |
| `event_policy` | `null` | | Which points report events, in which class and past what deadband. `null` uses the profile tables' choices. See [Setting the event policy](der.md#setting-the-event-policy) for the format |

### `composition`

How many of each repeating component the DER has. The profile's equipment
blocks are served once per unit.

| Setting | Default | Flag |
|---|---|---|
| `meters` | `0` | `--meters` |
| `der_units` | `0` | `--der-units` |
| `inverters` | `0` | `--inverters` |
| `batteries` | `0` | `--batteries` |

### `simulation`

| Setting | Default | Flag | Meaning |
|---|---|---|---|
| `seed` | `0` | `--seed` | Seed for the simulation's noise |
| `tick` | `1` | `--tick` | Seconds between simulation steps |

### `identity`

Used by `py1815-der profile` to fill in the DNP3 Device Profile document.

| Setting | Default | Flag |
|---|---|---|
| `vendor` | `"Not stated"` | `--vendor` |
| `device` | `"py1815 simulated DER outstation"` | `--device` |
| `hardware_version` | `"Not applicable (software)"` | `--hardware-version` |
| `software_version` | `""`, meaning this library's version | `--software-version` |
| `author` | `"py1815"` | `--author` |

## An example

A DER with one meter and two inverters that listens on every interface,
reports events unsolicited, and puts power readings in class 1:

```json
{
  "bind": "0.0.0.0:20000",
  "outstation_address": 10,
  "unsolicited": true,
  "composition": {"meters": 1, "inverters": 2},
  "event_policy": {
    "defaults": {"AI": {"class": 2, "deadband": 0.5}},
    "points": {"AI537": {"class": 1, "deadband": 500}}
  }
}
```

## Checking a file

Print the result of a file, or of a file plus flags:

```bash
py1815-der config --config der.json --read-only
```

A setting that does not exist, or a value of the wrong type, stops the command
before anything is served. The message says where the problem is:

```text
configuration.bnid is not a setting; expected one of bind, tables, ...
composition.meters must be a whole number from 0 to 1000
read_only must be true or false
```

## From Python

```python
from py1815.profile import der, load
from py1815.profile.config import DerConfig

config = DerConfig.load("der.json")
point_map = load.load(config.tables, config.composition)
simulation = der.build(point_map, seed=config.seed, **config.outstation_options())
session = simulation.outstation.session(**config.session_options())
```

The master has the same arrangement. See
[Configuring the master](master-config.md).
