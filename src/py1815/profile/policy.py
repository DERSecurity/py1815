"""Event policy: which points report events, in which class, past what deadband.

The tables give every point a default event class, and a default is all it
is. What a controlling station wants reported differs from one deployment to
the next, so the choice is taken as data: a rule for each kind of point, and
exceptions for the points named one at a time. A deployment edits that data
and not the code that binds its points.

The policy is a mapping, or the dataclasses a mapping becomes. This module
reads no file and defines no file format (D66): a caller that keeps its
policy in JSON or YAML loads it with whatever it already uses and hands over
the result.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from py1815.profile.model import Address, Kind

#: The keys a rule may carry in its mapping form.
_RULE_KEYS = ("class", "events", "deadband")
_POLICY_KEYS = ("defaults", "points")

_POINT_NAME = re.compile(r"([A-Za-z]+)(\d+)")


@dataclass(frozen=True)
class EventRule:
    """What one point, or every point of one kind, is told about its events.

    Each field left as None says nothing, and whatever stands behind the rule
    decides: behind a point's rule, the rule for its kind; behind that, the
    tables.
    """

    #: The class the events are reported in: 1, 2 or 3.
    event_class: int | None = None
    #: False turns events off, and the point is then static data only. It
    #: stays in a class 0 response exactly as before. True turns them back on
    #: for one point of a kind whose rule turned them off.
    events: bool | None = None
    #: How far an analog input has to move before the change is an event, in
    #: engineering units. The builder converts it with the point's scaling.
    deadband: float | None = None

    def __post_init__(self) -> None:
        chosen = self.event_class
        # An int and not a bool: ``1.0 == 1`` and ``True == 1``, and either in
        # force would hand back something that is not the class it claims.
        if chosen is not None and (
            not isinstance(chosen, int) or isinstance(chosen, bool) or chosen not in (1, 2, 3)
        ):
            raise ValueError(f"an event class is 1, 2 or 3, not {chosen!r}")
        if self.events is not None and not isinstance(self.events, bool):
            raise ValueError(f"events is true or false, not {self.events!r}")
        if self.events is False and chosen is not None:
            raise ValueError(f"events are turned off and given class {chosen} in one rule")
        deadband = self.deadband
        if deadband is None:
            return
        if isinstance(deadband, bool) or not isinstance(deadband, (int, float)):
            raise ValueError(f"a deadband is a number, not {deadband!r}")
        if not math.isfinite(deadband) or deadband < 0:
            raise ValueError(f"a deadband is zero or more, not {deadband!r}")

    @property
    def decides_reporting(self) -> bool:
        """Whether the rule says anything about a point reporting at all."""
        return self.event_class is not None or self.events is not None

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> EventRule:
        """A rule from its plain form: ``class``, ``events`` and ``deadband``."""
        if not isinstance(data, Mapping):
            raise ValueError(f"an event rule is a mapping, not {data!r}")
        stray = sorted(str(key) for key in data if key not in _RULE_KEYS)
        if stray:
            raise ValueError(
                f"an event rule holds {', '.join(_RULE_KEYS)}; it does not hold {', '.join(stray)}"
            )
        return cls(
            event_class=data.get("class"),
            events=data.get("events"),
            deadband=data.get("deadband"),
        )


@dataclass(frozen=True)
class EventPolicy:
    """A deployment's event reporting: a rule per kind, and exceptions per point.

    Three kinds report events and may be named: binary inputs, analog inputs,
    and counters, whose rule governs the event each freeze logs. A deadband
    belongs to an analog input and to nothing else.

    What can be checked without a map is checked here, so a policy that
    cannot be right is refused when it is made. Whether the points it names
    exist is the builder's to check, when it has the map beside it.
    """

    defaults: Mapping[Kind, EventRule] = field(default_factory=dict)
    points: Mapping[Address, EventRule] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for kind, rule in self.defaults.items():
            _check(kind, rule, f"the default for {getattr(kind, 'value', kind)!s}")
        for address, rule in self.points.items():
            if not isinstance(address, tuple) or len(address) != 2:
                raise ValueError(f"a point is named by its kind and index, not {address!r}")
            kind, index = address
            if isinstance(index, bool) or not isinstance(index, int) or index < 0:
                raise ValueError(f"a point's index is zero or more, not {index!r}")
            _check(kind, rule, f"{getattr(kind, 'value', kind)!s}{index}")
        object.__setattr__(self, "defaults", MappingProxyType(dict(self.defaults)))
        object.__setattr__(self, "points", MappingProxyType(dict(self.points)))

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> EventPolicy:
        """A policy from plain data, as a configuration file would hold it.

        ::

            {
                "defaults": {"AI": {"class": 2, "deadband": 0.5}},
                "points": {
                    "AI537": {"class": 1, "deadband": 500},
                    "BI12": {"events": False},
                },
            }

        ``defaults`` is keyed by kind (``BI``, ``AI`` or ``CTR``) and
        ``points`` by kind and index together. Either may be left out. A key
        this does not know is refused, since a misspelled one would otherwise
        be a rule that silently does nothing.
        """
        if not isinstance(data, Mapping):
            raise ValueError(f"an event policy is a mapping, not {data!r}")
        stray = sorted(str(key) for key in data if key not in _POLICY_KEYS)
        if stray:
            raise ValueError(
                f"an event policy holds {' and '.join(_POLICY_KEYS)}; "
                f"it does not hold {', '.join(stray)}"
            )
        defaults = _section(data, "defaults")
        points = _section(data, "points")
        return cls(
            defaults={_kind(key): EventRule.from_mapping(rule) for key, rule in defaults.items()},
            points={_address(key): EventRule.from_mapping(rule) for key, rule in points.items()},
        )


def _check(kind: object, rule: object, name: str) -> None:
    """Refuse a rule for a kind that cannot follow it."""
    if not isinstance(kind, Kind):
        raise ValueError(f"{name}: {kind!r} is not a kind of point")
    if not isinstance(rule, EventRule):
        raise ValueError(f"{name}: {rule!r} is not an event rule")
    if kind.is_output:
        raise ValueError(f"{name}: an output reports no events")
    if rule.deadband is not None and kind is not Kind.AI:
        raise ValueError(f"{name}: only an analog input has a deadband")


def _section(data: Mapping[str, Any], key: str) -> Mapping[Any, Any]:
    # A section left out is no rules. One that is present and empty-valued is
    # a mistake in the file, and treating it as left out would quietly drop
    # every rule the author meant it to hold.
    if key not in data:
        return {}
    section = data[key]
    if not isinstance(section, Mapping):
        raise ValueError(f"{key} is a mapping, not {section!r}")
    return section


def _kind(key: object) -> Kind:
    if isinstance(key, Kind):
        return key
    try:
        return Kind(str(key).upper())
    except ValueError:
        raise ValueError(f"{key!r} is not a kind of point") from None


def _address(key: object) -> Address:
    """A point's address from its name, ``AI537``, or from the pair itself."""
    if isinstance(key, tuple):
        if len(key) != 2:
            raise ValueError(f"a point is named by its kind and index, not {key!r}")
        return (_kind(key[0]), key[1])
    match = _POINT_NAME.fullmatch(str(key).strip())
    if match is None:
        raise ValueError(f"{key!r} does not name a point; a point is named like AI537")
    return (_kind(match.group(1)), int(match.group(2)))
