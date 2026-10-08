"""Helpers for reading and validating JSON configuration files.

Shared by the master's configuration (:mod:`py1815.master.config`) and the DER
outstation's (:mod:`py1815.profile.config`). Each check takes the value and
its location in the document, and raises :class:`ConfigError` with a message
that names the location.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import json
import math
import pathlib
from collections.abc import Mapping, Sequence
from typing import Any

#: The highest DNP3 link address a device can have.
MAX_ADDRESS = 65519


class ConfigError(ValueError):
    """A configuration that cannot be used. The message says where and why."""


def seconds(value: Any, where: str, *, minimum: float = 0.0, unit: str = "seconds") -> float:
    """Return a number greater than ``minimum``, of seconds unless ``unit`` says otherwise."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{where} must be a number of {unit}")
    # JSON such as 1e309 decodes to infinity, which is not a usable value.
    if not math.isfinite(value):
        raise ConfigError(f"{where} must be a finite number of {unit}")
    if not value > minimum:
        raise ConfigError(f"{where} must be greater than {minimum:g}")
    return float(value)


def integer(value: Any, where: str, low: int, high: int) -> int:
    """Return a whole number from ``low`` to ``high``."""
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(f"{where} must be a whole number from {low} to {high}")
    return value


def boolean(value: Any, where: str) -> bool:
    """Return true or false."""
    if not isinstance(value, bool):
        raise ConfigError(f"{where} must be true or false")
    return value


def text(value: Any, where: str) -> str:
    """Return a non-empty string."""
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{where} must be a non-empty string")
    return value


def section(value: Any, where: str, allowed: Sequence[str]) -> Mapping[str, Any]:
    """Return a JSON object whose keys are all in ``allowed``."""
    if not isinstance(value, Mapping):
        raise ConfigError(f"{where} must be an object")
    for key in value:
        if key not in allowed:
            raise ConfigError(
                f"{where}.{key} is not a setting; expected one of {', '.join(allowed)}"
            )
    return value


def read(path: str | pathlib.Path) -> dict[str, Any]:
    """Read a JSON configuration file and return the decoded document."""
    try:
        content = pathlib.Path(path).read_text(encoding="utf-8")
    except OSError as error:
        raise ConfigError(f"{path}: {error.strerror or error}") from None
    try:
        document = json.loads(content)
    except ValueError as error:
        raise ConfigError(f"{path} is not valid JSON: {error}") from None
    if not isinstance(document, dict):
        raise ConfigError(f"{path} must hold a JSON object")
    return document


def render(document: Mapping[str, Any]) -> str:
    """Return a configuration as formatted JSON."""
    return json.dumps(document, indent=2) + "\n"
