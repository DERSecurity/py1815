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
  "capture_max_mb": 100.0,
  "capture_keep": 10,
  "log_file": null,
  "log_max_mb": 10.0,
  "log_keep": 5,
  "log_level": "info",
  "defaults": {
    "port": 20000,
    "outstation_address": 1024,
    "master_address": 1,
    "response_timeout": 5.0,
    "read_retries": 0,
    "connect_timeout": 5.0,
    "tls": null,
    "connect": true,
    "reconnect": 5.0,
    "confirm": true,
    "manual": false,
    "profile": false,
    "device_profile": null,
    "tasks": {
      "startup": true,
      "clear_restart": true,
      "write_time": true,
      "enable_unsolicited": [],
      "events_when_indicated": true,
      "integrity_on_overflow": true,
      "time_procedure": null,
      "event_follow_ups": 3
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
| `capture_max_mb` | `100` | Start a new capture file once the current one reaches this many megabytes. The full one is renamed `master.1.pcap` for a `capture` of `master.pcap` |
| `capture_keep` | `10` | Older capture files to keep. `0` keeps only the current one |
| `log_file` | `null` | Path of a file to write the log to, as well as the terminal. `null` logs to the terminal only. See [Running for days](master.md#running-for-days) |
| `log_max_mb` | `10` | Start a new log file once the current one reaches this many megabytes. The full one is renamed `master.log.1` |
| `log_keep` | `5` | Older log files to keep, at least 1 |
| `log_level` | `"info"` | The lowest level written to the log file: `debug`, `info` or `warning` |

The console's token is not in the file, because it is a secret. Give it with
`--token` or the `PY1815_MASTER_TOKEN` environment variable. The same goes for
the password of a TLS key: see [`tls`](#tls).

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
| `read_retries` | `0` | Times a read that times out with nothing received is sent again, under the same sequence number. Up to 10. No other request is ever sent again |
| `connect_timeout` | `5` | Seconds to wait for the TCP connection, and the TLS handshake |
| `tls` | `null` | Connect over TLS with these files, or `null` for plain TCP. See [`tls`](#tls) |
| `connect` | `true` | Connect when the master starts |
| `reconnect` | `5` | Seconds between reconnection attempts after a lost connection. `null` disables reconnection |
| `confirm` | `true` | Confirm response fragments that ask for confirmation |
| `manual` | `false` | Send only what is asked for. Disables every task and confirmation, whatever `tasks` and `confirm` say |
| `profile` | `false` | The outstation is an IEEE 1815.2 DER: name its points from the profile tables, and offer the [DER profile's operations](master-api.md#the-der-profile) |
| `device_profile` | `null` | Path of the outstation's DNP3 Device Profile document, which [`der.compare`](master-api.md#the-der-profile) compares what it serves with. Read when the master starts |
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
| `time_procedure` | `null` | How `write_time` sets the clock. `null` writes the master's time as it stands; `"lan"` and `"non_lan"` follow the procedures of IEEE 1815-2012 10.3.3, which correct for the time the request takes |
| `event_follow_ups` | `3` | Event polls made at once, one after another, while a poll's own response still says events are waiting. `0` leaves them for the next response that says so |

### `repeat`

| Setting | Default | Meaning |
|---|---|---|
| `integrity` | `null` | Seconds between integrity polls. `null` means not repeated |
| `events` | `null` | Seconds between event polls. `null` means not repeated |
| `outputs` | `"with_integrity"` | Seconds between reads of output status, `"with_integrity"` to read it as often as the integrity poll, or `null` for never. An integrity poll does not include output status |

### `tls`

| Setting | Default | Meaning |
|---|---|---|
| `ca` | `null` | A PEM file of the authorities the outstation's certificate is checked against. `null` uses the system's own |
| `certificate` | `null` | The master's certificate, in PEM, with its chain if it has one |
| `key` | `null` | The master's private key, in PEM, when it is not in the certificate's file |
| `server_name` | `null` | The name the outstation's certificate is checked against, when it is not `host` |

An outstation that listens with TLS usually requires a certificate of the
master, as this library's does, so give `certificate` and `key`. A key that is
encrypted is opened with the password in the `PY1815_MASTER_KEY_PASSWORD`
environment variable; the password is never a setting, so `py1815-master
config` never prints it.

```json
"defaults": {
  "tls": {"ca": "lab-ca.pem", "certificate": "master.pem", "key": "master.key"}
},
"outstations": [
  {"name": "lab", "host": "192.0.2.10", "tls": {"server_name": "inverter.lab"}},
  {"name": "bench", "host": "192.0.2.11", "tls": null}
]
```

`tasks`, `repeat` and `tls` are merged with the defaults. An outstation entry
that sets `"tasks": {"startup": false}` changes that one task and keeps the
rest, and one that sets `"tls": null` connects over plain TCP.

## Command-line flags

A flag that is given overrides the file. The flags that describe an outstation
change `defaults`, so an outstation entry that sets the same thing keeps its
own value.

| Flag | Setting |
|---|---|
| `--allow-control` | `allow_control` |
| `--bind ADDRESS:PORT` | `bind` |
| `--tables FILE` | `tables` |
| `--connect-wait SECONDS` | `connect_wait`: the service's `connect` keeps trying for this long, once a second |
| `--capture FILE` | `capture` |
| `--capture-max-mb MB` | `capture_max_mb` |
| `--capture-keep FILES` | `capture_keep` |
| `--log-file FILE` | `log_file` |
| `--log-max-mb MB` | `log_max_mb` |
| `--log-keep FILES` | `log_keep` |
| `--log-level LEVEL` | `log_level` |
| `--outstation NAME=HOST:PORT` | Adds an entry to `outstations`. May be repeated |
| `--outstation-address N` | `defaults.outstation_address` |
| `--master-address N` | `defaults.master_address` |
| `--read-retries N` | `defaults.read_retries` |
| `--tls-ca FILE` | `defaults.tls.ca` |
| `--tls-certificate FILE` | `defaults.tls.certificate` |
| `--tls-key FILE` | `defaults.tls.key` |
| `--tls-server-name NAME` | `defaults.tls.server_name` |
| `--reconnect SECONDS` | `defaults.reconnect`. `0` means never |
| `--manual` | `defaults.manual` |
| `--profile` | `defaults.profile` |
| `--device-profile FILE` | `defaults.device_profile` |
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
