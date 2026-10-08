"""The master's configuration: every setting in one JSON document.

A configuration has four top-level settings, a ``defaults`` object with the
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
filled in, for editing. ``py1815-master console --config FILE`` and
``py1815-master serve --config FILE`` load one.

Unknown settings and values of the wrong type are errors that name where they
are, so a typing mistake is reported instead of ignored.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import json
import math
import pathlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields
from typing import Any

from py1815.master import requests
from py1815.master.api import DEFAULT_CONNECT_TIMEOUT, DEFAULT_RECONNECT
from py1815.master.association import DEFAULT_RESPONSE_TIMEOUT
from py1815.master.tasks import WRITING, Tasks

#: ``repeat.outputs`` value that means "as often as the integrity poll".
WITH_INTEGRITY = "with_integrity"

#: The scans that can be repeated, in the order they are written.
REPEATED = ("integrity", "events", requests.OUTPUTS)

_MAX_ADDRESS = 65519


class ConfigError(ValueError):
    """A configuration that cannot be used. The message says where and why."""


def _number(value: Any, where: str, *, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{where} must be a number of seconds")
    # JSON such as 1e309 decodes to infinity, which is not a usable interval.
    if not math.isfinite(value):
        raise ConfigError(f"{where} must be a finite number of seconds")
    if not value > minimum:
        raise ConfigError(f"{where} must be greater than {minimum:g}")
    return float(value)


def _integer(value: Any, where: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(f"{where} must be a whole number from {low} to {high}")
    return value


def _boolean(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{where} must be true or false")
    return value


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{where} must be a non-empty string")
    return value


def _object(value: Any, where: str, allowed: Sequence[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ConfigError(f"{where} must be an object")
    for key in value:
        if key not in allowed:
            raise ConfigError(
                f"{where}.{key} is not a setting; expected one of {', '.join(allowed)}"
            )
    return value


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
    #: Seconds to wait for the TCP connection.
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
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

        ``tasks`` and ``repeat`` are merged: a setting they leave out keeps its
        current value.
        """
        allowed = [each.name for each in fields(self)]
        _object(given, where, allowed)
        values: dict[str, Any] = {each.name: getattr(self, each.name) for each in fields(self)}
        for key, value in given.items():
            at = f"{where}.{key}"
            if key in ("name", "host"):
                values[key] = _text(value, at)
            elif key == "port":
                values[key] = _integer(value, at, 1, 65535)
            elif key in ("outstation_address", "master_address"):
                values[key] = _integer(value, at, 0, _MAX_ADDRESS)
            elif key in self._SECONDS:
                values[key] = _number(value, at)
            elif key in self._BOOLEANS:
                values[key] = _boolean(value, at)
            elif key == "reconnect":
                values[key] = None if value is None else _number(value, at)
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

    def _repeat(self, given: Any, where: str) -> dict[str, float | str | None]:
        merged = dict(self.repeat)
        for kind, value in _object(given, where, REPEATED).items():
            if value is None or (kind == requests.OUTPUTS and value == WITH_INTEGRITY):
                merged[kind] = value
            else:
                merged[kind] = _number(value, f"{where}.{kind}")
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
            "connect_timeout": self.connect_timeout,
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
            if each.name == "tasks":
                value = value.describe()
            elif each.name == "repeat":
                value = dict(value)
            described[each.name] = value
        return described


_TOP_LEVEL = ("allow_control", "bind", "tables", "connect_wait", "defaults", "outstations")


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
    #: The settings an outstation has unless its own entry says otherwise.
    defaults: OutstationConfig = field(default_factory=OutstationConfig)
    outstations: tuple[OutstationConfig, ...] = ()

    @classmethod
    def from_mapping(cls, given: Mapping[str, Any]) -> MasterConfig:
        """Build a configuration from a decoded JSON document.

        Raises :class:`ConfigError` for an unknown setting, a value of the
        wrong type, an outstation with no name or host, or a name used twice.
        """
        _object(given, "configuration", _TOP_LEVEL)
        values: dict[str, Any] = {}
        if "allow_control" in given:
            values["allow_control"] = _boolean(given["allow_control"], "allow_control")
        for key in ("bind", "tables"):
            if given.get(key) is not None:
                values[key] = _text(given[key], key)
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
                if isinstance(value, dict):
                    value = {k: v for k, v in value.items() if v != shared[key][k]}
                entry[key] = value
            outstations.append(entry)
        return {
            "allow_control": self.allow_control,
            "bind": self.bind,
            "tables": self.tables,
            "connect_wait": self.connect_wait,
            "defaults": shared,
            "outstations": outstations,
        }

    def render(self) -> str:
        """Return the complete configuration as formatted JSON."""
        return json.dumps(self.describe(), indent=2) + "\n"


def read(path: str | pathlib.Path) -> dict[str, Any]:
    """Read a JSON configuration file and return the decoded document."""
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8")
    except OSError as error:
        raise ConfigError(f"{path}: {error.strerror or error}") from None
    try:
        document = json.loads(text)
    except ValueError as error:
        raise ConfigError(f"{path} is not valid JSON: {error}") from None
    if not isinstance(document, dict):
        raise ConfigError(f"{path} must hold a JSON object")
    return document


__all__ = ["REPEATED", "WITH_INTEGRITY", "ConfigError", "MasterConfig", "OutstationConfig", "read"]
