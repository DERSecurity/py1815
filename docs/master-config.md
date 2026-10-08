# Configuring the master

Every setting of `py1815-master` can be kept in one JSON file. The most
common ones also have a command-line flag, and a flag overrides the file. The
rest are set in the file only; [Command-line flags](#command-line-flags) lists
which have a flag.

## Quick start

Print a complete configuration, edit it, and run with it:

```bash
py1815-master config --outstation lab=192.0.2.10:20000 --out master.json
# edit master.json
py1815-master console --config master.json
```

`py1815-master config` prints every setting with its default filled in, so the
file shows everything that can be changed. `console`, `serve` and `config` all
take `--config FILE`.

## The file

```json
{
  "allow_control": false,
  "bind": null,
  "tables": null,
  "connect_wait": 0.0,
  "capture": null,
  "defaults": {
    "port": 20000,
    "outstation_address": 1024,
    "master_address": 1,
    "response_timeout": 5.0,
    "connect_timeout": 5.0,
    "connect": true,
    "reconnect": 5.0,
    "confirm": true,
    "manual": false,
    "profile": false,
    "tasks": {
      "startup": true,
      "clear_restart": true,
      "write_time": true,
      "enable_unsolicited": [],
      "events_when_indicated": true,
      "integrity_on_overflow": true
    },
    "repeat": {
      "integrity": null,
      "events": null,
      "outputs": "with_integrity"
    }
  },
  "outstations": [
    {"name": "lab", "host": "192.0.2.10"},
    {"name": "bench", "host": "192.0.2.11", "port": 20001, "manual": true}
  ]
}
```

It has three parts:

- **Top-level settings** apply to the whole master.
- **`defaults`** holds the settings every outstation starts with.
- **`outstations`** lists the outstations. Each entry needs `name` and `host`.
  Any other setting in the entry overrides the default for that outstation.

Every setting is optional. A file that only lists outstations is valid.

## Top-level settings

| Setting | Default | Meaning |
|---|---|---|
| `allow_control` | `false` | Allow operations and tasks that write to an outstation: outputs, counters, clock and restart indication. See [Commanding](master-api.md#commanding) |
| `bind` | `null` | Address and port to listen on. `null` uses the command's default: `127.0.0.1:8815` for `console`, `127.0.0.1:8816` for `serve` |
| `tables` | `null` | Path of the IEEE 1815.2 profile tables file, for outstations with `profile` set. `null` uses the usual locations |
| `connect_wait` | `0` | Seconds to keep trying to reach an outstation that is not there at startup. `0` tries once |
| `capture` | `null` | Path of a pcap file to write every frame of every outstation to, as it is sent or received. The file is created, or emptied if it exists, when the master starts. `null` writes no file. See [Captures](master.md#captures) |

The console's token is not in the file, because it is a secret. Give it with
`--token` or the `PY1815_MASTER_TOKEN` environment variable.

## Outstation settings

These go in `defaults`, in an outstation's entry, or both.

| Setting | Default | Meaning |
|---|---|---|
| `name` | required | The name used in the console and the API. Not allowed in `defaults` |
| `host` | required | Host name or address. Not allowed in `defaults` |
| `port` | `20000` | TCP port |
| `outstation_address` | `1024` | The outstation's DNP3 link address |
| `master_address` | `1` | The master's DNP3 link address |
| `response_timeout` | `5` | Seconds to wait for a response, and for each further fragment |
| `connect_timeout` | `5` | Seconds to wait for the TCP connection |
| `connect` | `true` | Connect when the master starts |
| `reconnect` | `5` | Seconds between reconnection attempts after a lost connection. `null` disables reconnection |
| `confirm` | `true` | Confirm response fragments that ask for confirmation |
| `manual` | `false` | Send only what is asked for. Disables every task and confirmation, whatever `tasks` and `confirm` say |
| `profile` | `false` | The outstation is an IEEE 1815.2 DER: name its points from the profile tables |
| `tasks` | see below | The [automatic tasks](master.md#what-it-does-without-being-asked) |
| `repeat` | see below | Scans repeated on a schedule |

### `tasks`

| Setting | Default | Meaning |
|---|---|---|
| `startup` | `true` | On connect and after a reported restart: disable unsolicited reporting, then run an integrity poll |
| `clear_restart` | `true` | Clear the restart indication when a response sets it. Runs only when `allow_control` is on |
| `write_time` | `true` | Write the time when a response asks for it. Runs only when `allow_control` is on |
| `enable_unsolicited` | `[]` | Event classes (1, 2, 3) to enable unsolicited reporting for after startup |
| `events_when_indicated` | `true` | Poll for events when a response says some are waiting |
| `integrity_on_overflow` | `true` | Run an integrity poll when a response reports an event buffer overflow |

### `repeat`

| Setting | Default | Meaning |
|---|---|---|
| `integrity` | `null` | Seconds between integrity polls. `null` means not repeated |
| `events` | `null` | Seconds between event polls. `null` means not repeated |
| `outputs` | `"with_integrity"` | Seconds between reads of output status, `"with_integrity"` to read it as often as the integrity poll, or `null` for never. An integrity poll does not include output status |

`tasks` and `repeat` are merged with the defaults. An outstation entry that
sets `"tasks": {"startup": false}` changes that one task and keeps the rest.

## Command-line flags

A flag that is given overrides the file. The flags that describe an outstation
change `defaults`, so an outstation entry that sets the same thing keeps its
own value.

| Flag | Setting |
|---|---|
| `--allow-control` | `allow_control` |
| `--bind ADDRESS:PORT` | `bind` |
| `--tables FILE` | `tables` |
| `--connect-wait SECONDS` | `connect_wait` |
| `--capture FILE` | `capture` |
| `--outstation NAME=HOST:PORT` | Adds an entry to `outstations`. May be repeated |
| `--outstation-address N` | `defaults.outstation_address` |
| `--master-address N` | `defaults.master_address` |
| `--reconnect SECONDS` | `defaults.reconnect`. `0` means never |
| `--manual` | `defaults.manual` |
| `--profile` | `defaults.profile` |
| `--unsolicited 1,2,3` | `defaults.tasks.enable_unsolicited` |
| `--integrity-interval SECONDS` | `defaults.repeat.integrity` |
| `--event-interval SECONDS` | `defaults.repeat.events` |
| `--output-interval SECONDS` | `defaults.repeat.outputs`. `0` means never |

To check a file, or to see the result of a file plus flags, print it:

```bash
py1815-master config --config master.json --reconnect 1
```

## Errors

A setting that does not exist, or a value of the wrong type, stops the master
before it starts. The message says where the problem is:

```text
defaults.prot is not a setting; expected one of name, host, port, ...
outstations[1].port must be a whole number from 1 to 65535
outstations[2].name 'lab' is used more than once
```

The outstation has the same arrangement. See
[Configuring the outstation](der-config.md).

## From Python

```python
from py1815.master.config import MasterConfig

config = MasterConfig.load("master.json")
for outstation in config.outstations:
    print(outstation.name, outstation.host, outstation.reconnect)
print(config.render())
```
