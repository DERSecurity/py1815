"""The DER outstation's configuration: every setting in one JSON document.

.. code-block:: json

    {
      "bind": "0.0.0.0:20000",
      "outstation_address": 10,
      "unsolicited": true,
      "composition": {"meters": 1, "inverters": 2}
    }

``py1815-der config`` prints the complete document, with every default filled
in, for editing. ``py1815-der run --config FILE`` loads one, and so do
``points`` and ``profile``.

Unknown settings and values of the wrong type are errors that name where they
are, so a typing mistake is reported instead of ignored.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import pathlib
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from typing import Any

from py1815 import settings
from py1815.profile.model import Composition
from py1815.profile.policy import EventPolicy
from py1815.server import DEFAULT_PORT, IDLE_TIMEOUT
from py1815.session import DEFAULT_CONFIRM_TIMEOUT, DEFAULT_SELECT_TIMEOUT
from py1815.settings import ConfigError

_COMPOSITION = ("meters", "der_units", "inverters", "batteries")
_SIMULATION = ("seed", "tick")
_MAX_COUNT = 1000


@dataclass(frozen=True)
class Identity:
    """What the DNP3 Device Profile document says about the device."""

    vendor: str = "Not stated"
    device: str = "py1815 simulated DER outstation"
    hardware_version: str = "Not applicable (software)"
    #: Empty means this library's version.
    software_version: str = ""
    author: str = "py1815"


_IDENTITY = tuple(each.name for each in fields(Identity))


@dataclass(frozen=True)
class DerConfig:
    """The DER outstation's whole configuration."""

    #: Address and port to listen on. The default is this machine only.
    bind: str = f"127.0.0.1:{DEFAULT_PORT}"
    #: Path of the profile tables file, or None for the usual locations.
    tables: str | None = None
    #: This outstation's DNP3 link address.
    outstation_address: int = 1024
    #: The master's DNP3 link address, or None to serve whichever master
    #: speaks first on a connection.
    master_address: int | None = 1
    #: Send unsolicited responses for the event classes a master enables.
    unsolicited: bool = False
    #: Refuse every control, so a master can read and cannot command.
    read_only: bool = False
    #: Answer as a DNP3 Subset Level 2 outstation, without the profile's
    #: additions.
    level2: bool = False
    #: Clear the ONLINE flag on the inputs of a disabled function
    #: (IEEE 1815.2 clause 6.1.1).
    disabled_offline: bool = True
    #: Events each class holds before the oldest is dropped.
    event_capacity: int = 2000
    #: Largest response fragment to send, in octets.
    max_response: int = 2048
    #: Seconds a select stays valid.
    select_timeout: float = DEFAULT_SELECT_TIMEOUT
    #: Seconds to wait for a master to confirm a response, or None to wait
    #: without limit.
    confirm_timeout: float | None = DEFAULT_CONFIRM_TIMEOUT
    #: Seconds of silence before a connection is closed.
    idle_timeout: float = IDLE_TIMEOUT
    #: Which points report events, in which class and past what deadband, in
    #: the form :meth:`~py1815.profile.policy.EventPolicy.from_mapping` takes.
    #: None uses the profile tables' choices.
    event_policy: Mapping[str, Any] | None = None
    #: How many of each repeating component the DER has.
    composition: Composition = field(default_factory=Composition)
    #: Seed for the simulation's noise.
    seed: int = 0
    #: Seconds between simulation steps.
    tick: float = 1.0
    identity: Identity = field(default_factory=Identity)

    @classmethod
    def from_mapping(cls, given: Mapping[str, Any]) -> DerConfig:
        """Build a configuration from a decoded JSON document.

        Raises :class:`~py1815.settings.ConfigError` for an unknown setting or
        a value of the wrong type.
        """
        top_level = [each.name for each in fields(cls) if each.name not in ("seed", "tick")] + [
            "simulation"
        ]
        settings.section(given, "configuration", top_level)
        values: dict[str, Any] = {}
        for key, value in given.items():
            if key == "bind":
                values[key] = settings.text(value, key)
            elif key == "tables":
                values[key] = None if value is None else settings.text(value, key)
            elif key == "outstation_address":
                values[key] = settings.integer(value, key, 0, settings.MAX_ADDRESS)
            elif key == "master_address":
                values[key] = (
                    None if value is None else settings.integer(value, key, 0, settings.MAX_ADDRESS)
                )
            elif key in ("unsolicited", "read_only", "level2", "disabled_offline"):
                values[key] = settings.boolean(value, key)
            elif key == "event_capacity":
                values[key] = settings.integer(value, key, 1, 1_000_000)
            elif key == "max_response":
                values[key] = settings.integer(value, key, 249, 65535)
            elif key in ("select_timeout", "idle_timeout"):
                values[key] = settings.seconds(value, key)
            elif key == "confirm_timeout":
                values[key] = None if value is None else settings.seconds(value, key)
            elif key == "event_policy":
                values[key] = cls._event_policy(value)
            elif key == "composition":
                counts = settings.section(value, key, _COMPOSITION)
                values[key] = Composition(
                    **{
                        name: settings.integer(count, f"{key}.{name}", 0, _MAX_COUNT)
                        for name, count in counts.items()
                    }
                )
            elif key == "simulation":
                simulation = settings.section(value, key, _SIMULATION)
                if "seed" in simulation:
                    values["seed"] = settings.integer(
                        simulation["seed"], "simulation.seed", 0, 2**32 - 1
                    )
                if "tick" in simulation:
                    values["tick"] = settings.seconds(simulation["tick"], "simulation.tick")
            else:
                identity = settings.section(value, key, _IDENTITY)
                for name, entry in identity.items():
                    if not isinstance(entry, str):
                        raise ConfigError(f"{key}.{name} must be a string")
                values[key] = Identity(**identity)
        config = cls(**values)
        if config.master_address == config.outstation_address:
            raise ConfigError("outstation_address and master_address must be different")
        return config

    @staticmethod
    def _event_policy(value: Any) -> dict[str, Any] | None:
        if value is None:
            return None
        if not isinstance(value, Mapping):
            raise ConfigError("event_policy must be an object or null")
        try:
            EventPolicy.from_mapping(value)
        except (ValueError, TypeError, KeyError) as error:
            raise ConfigError(f"event_policy: {error}") from None
        return dict(value)

    @classmethod
    def load(cls, path: str | pathlib.Path) -> DerConfig:
        """Read a configuration from a JSON file."""
        return cls.from_mapping(settings.read(path))

    def outstation_options(self) -> dict[str, Any]:
        """Return the keyword arguments for :class:`~py1815.profile.outstation.DerOutstation`."""
        return {
            "event_capacity": self.event_capacity,
            "level2": self.level2,
            "disabled_offline": self.disabled_offline,
            "read_only": self.read_only,
            "event_policy": self.event_policy,
        }

    def session_options(self) -> dict[str, Any]:
        """Return the keyword arguments for the outstation's session."""
        return {
            "outstation_address": self.outstation_address,
            "master_address": self.master_address,
            "unsolicited": self.unsolicited,
            "max_response": self.max_response,
            "select_timeout": self.select_timeout,
            "confirm_timeout": self.confirm_timeout,
        }

    def describe(self) -> dict[str, Any]:
        """Return the complete configuration as a JSON-compatible dict."""
        described: dict[str, Any] = {}
        for each in fields(self):
            value = getattr(self, each.name)
            if each.name in ("seed", "tick"):
                continue
            if each.name == "composition":
                value = {name: getattr(value, name) for name in _COMPOSITION}
                described[each.name] = value
                described["simulation"] = {"seed": self.seed, "tick": self.tick}
                continue
            if each.name == "identity":
                value = {name: getattr(value, name) for name in _IDENTITY}
            elif each.name == "event_policy" and value is not None:
                value = dict(value)
            described[each.name] = value
        return described

    def render(self) -> str:
        """Return the complete configuration as formatted JSON."""
        return settings.render(self.describe())


__all__ = ["ConfigError", "DerConfig", "Identity"]
