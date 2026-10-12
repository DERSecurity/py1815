"""The master's configuration: every setting in one JSON document.

A configuration has its top-level settings, an ``evaluate`` object with the
settings of ``py1815-master evaluate``, a ``defaults`` object with the
settings shared by every outstation, and a list of ``outstations``. An
outstation entry needs a ``name`` and a ``host``; any other setting it gives
overrides the default.

.. code-block:: json

    {
      "allow_control": false,
      "defaults": {"reconnect": 5, "repeat": {"integrity": 30}},
      "outstations": [
        {"name": "lab", "host": "192.0.2.10"},
        {"name": "bench", "host": "192.0.2.11", "port": 20001, "manual": true}
      ]
    }

``py1815-master config`` prints the complete document, with every default
filled in, for editing. ``console``, ``serve`` and ``evaluate`` load one with
``--config FILE``.

Unknown settings and values of the wrong type are errors that name where they
are, so a typing mistake is reported instead of ignored.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import math
import pathlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields
from typing import Any

from py1815 import settings
from py1815.master import requests
from py1815.master.api import DEFAULT_CONNECT_TIMEOUT, DEFAULT_RECONNECT
from py1815.master.association import DEFAULT_READ_RETRIES, DEFAULT_RESPONSE_TIMEOUT
from py1815.master.bench import DEFAULT_SETTLE
from py1815.master.tasks import WRITING, Tasks
from py1815.master.tls import TlsSettings
from py1815.settings import ConfigError, read

#: ``repeat.outputs`` value that means "as often as the integrity poll".
WITH_INTEGRITY = "with_integrity"

#: The scans that can be repeated, in the order they are written.
REPEATED = ("integrity", "events", requests.OUTPUTS)

#: The most times a read may be sent again: enough for any link, and a bound
#: on how long one read can hold up every other request.
_MAX_READ_RETRIES = 10


@dataclass(frozen=True)
class OutstationConfig:
    """The settings of one outstation. ``name`` and ``host`` are required."""

    name: str = ""
    host: str = ""
    port: int = 20000
    outstation_address: int = 1024
    master_address: int = 1
    #: Seconds to wait for a response, and for each further fragment of one.
    response_timeout: float = DEFAULT_RESPONSE_TIMEOUT
    #: Times a read that times out is sent again. No other request is.
    read_retries: int = DEFAULT_READ_RETRIES
    #: Seconds to wait for the TCP connection.
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    #: Connect over TLS with these files, or None for plain TCP.
    tls: TlsSettings | None = None
    #: Connect when the master starts.
    connect: bool = True
    #: Seconds between reconnection attempts after a lost connection, or None
    #: for no reconnection.
    reconnect: float | None = DEFAULT_RECONNECT
    #: Confirm response fragments that ask for confirmation.
    confirm: bool = True
    #: Send only what is asked for. Disables every task and confirmation,
    #: whatever ``tasks`` and ``confirm`` say.
    manual: bool = False
    #: The outstation is an IEEE 1815.2 DER: name its points from the profile
    #: tables.
    profile: bool = False
    #: Path of the outstation's DNP3 Device Profile document, which
    #: ``der.compare`` compares what it serves with. None for none.
    device_profile: str | None = None
    #: The automatic tasks. The two that write (``clear_restart`` and
    #: ``write_time``) only run when ``allow_control`` is on.
    tasks: Tasks = field(default_factory=Tasks)
    #: Seconds between repeated scans, by kind. None means not repeated.
    #: ``outputs`` may be ``"with_integrity"``.
    repeat: Mapping[str, float | str | None] = field(
        default_factory=lambda: {"integrity": None, "events": None, "outputs": WITH_INTEGRITY}
    )

    #: Settings that take a number of seconds greater than zero.
    _SECONDS = ("response_timeout", "connect_timeout")
    _BOOLEANS = ("connect", "confirm", "manual", "profile")

    def changed(self, given: Mapping[str, Any], where: str) -> OutstationConfig:
        """Return a copy with the settings in ``given`` applied.

        ``tasks``, ``repeat`` and ``tls`` are merged: a setting they leave out
        keeps its current value. ``tls`` given as null is plain TCP.
        """
        allowed = [each.name for each in fields(self)]
        settings.section(given, where, allowed)
        values: dict[str, Any] = {each.name: getattr(self, each.name) for each in fields(self)}
        for key, value in given.items():
            at = f"{where}.{key}"
            if key in ("name", "host"):
                values[key] = settings.text(value, at)
            elif key == "port":
                values[key] = settings.integer(value, at, 1, 65535)
            elif key in ("outstation_address", "master_address"):
                values[key] = settings.integer(value, at, 0, settings.MAX_ADDRESS)
            elif key == "read_retries":
                values[key] = settings.integer(value, at, 0, _MAX_READ_RETRIES)
            elif key == "tls":
                values[key] = self._tls(value, at)
            elif key in self._SECONDS:
                values[key] = settings.seconds(value, at)
            elif key in self._BOOLEANS:
                values[key] = settings.boolean(value, at)
            elif key == "reconnect":
                values[key] = None if value is None else settings.seconds(value, at)
            elif key == "device_profile":
                values[key] = None if value is None else settings.text(value, at)
            elif key == "tasks":
                if not isinstance(value, Mapping):
                    raise ConfigError(f"{at} must be an object")
                try:
                    values[key] = self.tasks.changed(value)
                except ValueError as error:
                    raise ConfigError(f"{at}: {error}") from None
            else:
                values[key] = self._repeat(value, at)
        if values["outstation_address"] == values["master_address"]:
            raise ConfigError(f"{where}: outstation_address and master_address must be different")
        return OutstationConfig(**values)

    def _tls(self, given: Any, where: str) -> TlsSettings | None:
        """Return the TLS settings, merged with these as ``tasks`` and ``repeat`` are."""
        if given is None:
            return None
        if not isinstance(given, Mapping):
            raise ConfigError(f"{where} must be an object, or null for plain TCP")
        merged = {**(self.tls.describe() if self.tls is not None else {}), **given}
        try:
            return TlsSettings.from_mapping(merged)
        except ValueError as error:
            raise ConfigError(f"{where}: {error}") from None

    def _repeat(self, given: Any, where: str) -> dict[str, float | str | None]:
        merged = dict(self.repeat)
        for kind, value in settings.section(given, where, REPEATED).items():
            if value is None or (kind == requests.OUTPUTS and value == WITH_INTEGRITY):
                merged[kind] = value
            else:
                merged[kind] = settings.seconds(value, f"{where}.{kind}")
        return merged

    def output_interval(self) -> float | None:
        """Seconds between reads of output status, with ``with_integrity`` resolved."""
        outputs = self.repeat[requests.OUTPUTS]
        if outputs == WITH_INTEGRITY:
            outputs = self.repeat["integrity"]
        return None if outputs is None else float(outputs)

    def add_params(self, *, allow_control: bool) -> dict[str, Any]:
        """Return the parameters of the service's ``add`` operation for this outstation."""
        integrity, events = self.repeat["integrity"], self.repeat["events"]
        params: dict[str, Any] = {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "outstation_address": self.outstation_address,
            "master_address": self.master_address,
            "response_timeout": self.response_timeout,
            "read_retries": self.read_retries,
            "connect_timeout": self.connect_timeout,
            "tls": None if self.tls is None else self.tls.describe(),
            "connect": self.connect,
            "reconnect": self.reconnect,
            "integrity_interval": integrity,
            "event_interval": events,
            "output_interval": self.output_interval(),
        }
        if self.manual:
            params["manual"] = True
            return params
        tasks = self.tasks.describe()
        if not allow_control:
            # A read-only service refuses a request for a task that writes, so
            # leave those two to its default, which is off.
            for name in WRITING:
                del tasks[name]
        params["confirm"] = self.confirm
        params["tasks"] = tasks
        return params

    def describe(self) -> dict[str, Any]:
        """Return every setting as a JSON-compatible dict."""
        described: dict[str, Any] = {}
        for each in fields(self):
            value = getattr(self, each.name)
            if each.name in ("tasks", "tls") and value is not None:
                value = value.describe()
            elif each.name == "repeat":
                value = dict(value)
            described[each.name] = value
        return described


@dataclass(frozen=True)
class EvaluateConfig:
    """The settings of ``py1815-master evaluate``."""

    #: Seconds to wait for the outstation to reach a state it was commanded to.
    settle: float = DEFAULT_SETTLE
    #: How many curves the outstation stores, or None to find out by
    #: selecting each in turn.
    curves: int | None = None
    #: The checks to run, by identifier or set, or None for all of them.
    checks: tuple[str, ...] | None = None
    #: Path to write the report to as JSON, or None for no file.
    report: str | None = None

    @classmethod
    def from_mapping(cls, given: Any, where: str = "evaluate") -> EvaluateConfig:
        """Build the settings from a decoded JSON object."""
        allowed = [each.name for each in fields(cls)]
        values: dict[str, Any] = {}
        for key, value in settings.section(given, where, allowed).items():
            at = f"{where}.{key}"
            if key == "settle":
                values[key] = settings.seconds(value, at)
            elif key == "curves":
                values[key] = None if value is None else settings.integer(value, at, 1, 65535)
            elif key == "report":
                values[key] = None if value is None else settings.text(value, at)
            elif value is not None:
                if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Sequence):
                    raise ConfigError(f"{at} must be a list of check names, or null for all")
                values[key] = tuple(
                    settings.text(each, f"{at}[{position}]") for position, each in enumerate(value)
                )
        return cls(**values)

    def describe(self) -> dict[str, Any]:
        """Return every setting as a JSON-compatible dict."""
        return {
            "settle": self.settle,
            "curves": self.curves,
            "checks": None if self.checks is None else list(self.checks),
            "report": self.report,
        }


_TOP_LEVEL = (
    "allow_control",
    "bind",
    "tables",
    "connect_wait",
    "capture",
    "capture_max_mb",
    "capture_keep",
    "log_file",
    "log_max_mb",
    "log_keep",
    "log_level",
    "evaluate",
    "defaults",
    "outstations",
)

#: The log levels a configuration may name.
LOG_LEVELS = ("debug", "info", "warning")

#: Octets in one megabyte, as the size settings count them.
MEGABYTE = 1_000_000


@dataclass(frozen=True)
class MasterConfig:
    """The master's whole configuration."""

    #: Allow the operations and tasks that write to an outstation.
    allow_control: bool = False
    #: Address and port to listen on, or None for the command's default.
    bind: str | None = None
    #: Path of the profile tables file, or None for the usual locations.
    tables: str | None = None
    #: Seconds to keep trying to reach an outstation that is not there at
    #: startup. Zero tries once.
    connect_wait: float = 0.0
    #: Path of a pcap file to write every frame to as it is sent or received,
    #: or None for no file.
    capture: str | None = None
    #: Start a new capture file once the current one reaches this many
    #: megabytes, keeping ``capture_keep`` older files.
    capture_max_mb: float = 100.0
    capture_keep: int = 10
    #: Path of a log file, or None to log to the terminal only. The file is
    #: rotated at ``log_max_mb`` megabytes, keeping ``log_keep`` older files.
    log_file: str | None = None
    log_max_mb: float = 10.0
    log_keep: int = 5
    #: The lowest level written to the log file: debug, info or warning.
    log_level: str = "info"
    #: The settings of ``py1815-master evaluate``.
    evaluate: EvaluateConfig = field(default_factory=EvaluateConfig)
    #: The settings an outstation has unless its own entry says otherwise.
    defaults: OutstationConfig = field(default_factory=OutstationConfig)
    outstations: tuple[OutstationConfig, ...] = ()

    @classmethod
    def from_mapping(cls, given: Mapping[str, Any]) -> MasterConfig:
        """Build a configuration from a decoded JSON document.

        Raises :class:`ConfigError` for an unknown setting, a value of the
        wrong type, an outstation with no name or host, or a name used twice.
        """
        settings.section(given, "configuration", _TOP_LEVEL)
        values: dict[str, Any] = {}
        if "allow_control" in given:
            values["allow_control"] = settings.boolean(given["allow_control"], "allow_control")
        for key in ("bind", "tables", "capture", "log_file"):
            if given.get(key) is not None:
                values[key] = settings.text(given[key], key)
        for key in ("capture_max_mb", "log_max_mb"):
            if key in given:
                values[key] = settings.seconds(given[key], key, unit="megabytes")
        if "capture_keep" in given:
            values["capture_keep"] = settings.integer(
                given["capture_keep"], "capture_keep", 0, 1000
            )
        if "log_keep" in given:
            # At least 1: Python's rotating log handler does not rotate with 0,
            # and the file would then grow without limit.
            values["log_keep"] = settings.integer(given["log_keep"], "log_keep", 1, 1000)
        if "log_level" in given:
            level = given["log_level"]
            if level not in LOG_LEVELS:
                raise ConfigError(f"log_level must be one of {', '.join(LOG_LEVELS)}")
            values["log_level"] = level
        if "connect_wait" in given:
            wait = given["connect_wait"]
            if (
                isinstance(wait, bool)
                or not isinstance(wait, (int, float))
                or not math.isfinite(wait)
                or wait < 0
            ):
                raise ConfigError("connect_wait must be a number of seconds, zero or more")
            values["connect_wait"] = float(wait)
        if "evaluate" in given:
            values["evaluate"] = EvaluateConfig.from_mapping(given["evaluate"])

        shared = given.get("defaults", {})
        for required in ("name", "host"):
            if isinstance(shared, Mapping) and required in shared:
                raise ConfigError(f"defaults.{required} belongs in an outstation's own entry")
        defaults = OutstationConfig().changed(shared, "defaults")
        values["defaults"] = defaults

        entries = given.get("outstations", [])
        if isinstance(entries, (str, bytes, Mapping)) or not isinstance(entries, Sequence):
            raise ConfigError("outstations must be a list")
        outstations: list[OutstationConfig] = []
        for position, entry in enumerate(entries):
            where = f"outstations[{position}]"
            outstation = defaults.changed(entry, where)
            for required in ("name", "host"):
                if not getattr(outstation, required):
                    raise ConfigError(f"{where}.{required} is required")
            if any(outstation.name == other.name for other in outstations):
                raise ConfigError(f"{where}.name {outstation.name!r} is used more than once")
            outstations.append(outstation)
        values["outstations"] = tuple(outstations)
        return cls(**values)

    @classmethod
    def load(cls, path: str | pathlib.Path) -> MasterConfig:
        """Read a configuration from a JSON file."""
        return cls.from_mapping(read(path))

    def describe(self) -> dict[str, Any]:
        """Return the complete configuration as a JSON-compatible dict.

        ``defaults`` lists every outstation setting. Each outstation lists its
        name, its host and only the settings that differ from the defaults.
        """
        shared = self.defaults.describe()
        del shared["name"], shared["host"]
        outstations = []
        for outstation in self.outstations:
            own = outstation.describe()
            entry: dict[str, Any] = {"name": own.pop("name"), "host": own.pop("host")}
            for key, value in own.items():
                if value == shared[key]:
                    continue
                if isinstance(value, dict) and isinstance(shared[key], dict):
                    value = {k: v for k, v in value.items() if v != shared[key][k]}
                entry[key] = value
            outstations.append(entry)
        return {
            "allow_control": self.allow_control,
            "bind": self.bind,
            "tables": self.tables,
            "connect_wait": self.connect_wait,
            "capture": self.capture,
            "capture_max_mb": self.capture_max_mb,
            "capture_keep": self.capture_keep,
            "log_file": self.log_file,
            "log_max_mb": self.log_max_mb,
            "log_keep": self.log_keep,
            "log_level": self.log_level,
            "evaluate": self.evaluate.describe(),
            "defaults": shared,
            "outstations": outstations,
        }

    def render(self) -> str:
        """Return the complete configuration as formatted JSON."""
        return settings.render(self.describe())


__all__ = [
    "REPEATED",
    "WITH_INTEGRITY",
    "ConfigError",
    "EvaluateConfig",
    "MasterConfig",
    "OutstationConfig",
    "read",
]
