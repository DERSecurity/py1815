"""The point model: what a loaded profile table says about one point.

A map is a set of points with absolute indices. The tables state some indices
relative to a block (the second inverter's fourth analog input), and those are
resolved when the map is loaded for a DER of known composition (D37), so
nothing here or after it does index arithmetic.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType


class Kind(StrEnum):
    """The five kinds of point the profile defines, by the tables' own names."""

    BO = "BO"
    BI = "BI"
    AO = "AO"
    AI = "AI"
    CTR = "CTR"

    @property
    def is_output(self) -> bool:
        """Whether a master commands this kind, and does not merely read it."""
        return self in (Kind.BO, Kind.AO)

    @property
    def is_analog(self) -> bool:
        """Whether this kind carries a scaled number."""
        return self in (Kind.AO, Kind.AI)


#: A point's address: its kind and its index within that kind.
Address = tuple[Kind, int]


@dataclass(frozen=True)
class Composition:
    """How many of each repeating component a DER has.

    The equipment blocks of the tables are stated once per unit, and the
    number of units is the DER's. Zero of a component means its block is not
    served at all.
    """

    meters: int = 0
    der_units: int = 0
    inverters: int = 0
    batteries: int = 0

    def __post_init__(self) -> None:
        for name in ("meters", "der_units", "inverters", "batteries"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} is {getattr(self, name)}; a count cannot be negative")

    def count(self, component: str) -> int:
        """The number of units of a component, by the tables' key for it."""
        return int(getattr(self, component))


@dataclass(frozen=True)
class Point:
    """One point, at the index this DER serves it at."""

    kind: Kind
    index: int
    name: str
    #: The heading the tables list the point under.
    section: str | None = None
    #: What the tables say the point is for; functions share one purpose.
    purpose: str | None = None
    #: 1, 2 or 3 for a point that reports events, 0 for one read only as
    #: static data, and None for one that belongs to no class at all -- which
    #: is how the tables mark a point left out of a class 0 response.
    event_class: int | None = None
    #: Whether the profile requires every outstation to implement the point.
    mandatory: bool = False
    #: The transmitted value times this, plus ``offset``, is the engineering
    #: value. None where the tables state no scaling, and the value travels
    #: as it is.
    multiplier: float | None = None
    offset: float = 0.0
    #: The range of the *transmitted* value, where the tables give one.
    minimum: float | None = None
    maximum: float | None = None
    units: str | None = None
    #: The point this one is paired with: an output's status input, or an
    #: input's commanding output.
    associated: Address | None = None
    #: For a "supports" input, the output that enables the function it
    #: reports on. Support is derived from whether that output is bound (D40).
    enabled_by: Address | None = None
    #: The repeating block the point belongs to and which unit of it, one-based.
    block: str | None = None
    unit: int | None = None
    #: A value the tables themselves fix, in engineering units: the profile
    #: version, or a block's starting index in the advertisement block.
    fixed_value: float | None = None
    #: For a counter: whether a frozen counter exists beside it, and the class
    #: its freeze events report in.
    frozen: bool = False
    frozen_event_class: int | None = None

    @property
    def address(self) -> Address:
        """The kind and index together, which is what identifies a point."""
        return (self.kind, self.index)

    @property
    def in_class_0(self) -> bool:
        """Whether an integrity poll carries this point, by the tables alone."""
        return self.event_class is not None

    def to_wire(self, value: float) -> float:
        """An engineering value as the number that travels."""
        if self.multiplier is None:
            return value
        return (value - self.offset) / self.multiplier

    def from_wire(self, raw: float) -> float:
        """A transmitted number as the engineering value it stands for."""
        if self.multiplier is None:
            return raw
        return raw * self.multiplier + self.offset

    def in_range(self, raw: float) -> bool:
        """Whether a transmitted value is inside the range the tables give."""
        if self.minimum is not None and raw < self.minimum:
            return False
        return not (self.maximum is not None and raw > self.maximum)


class MapError(ValueError):
    """The tables, resolved for this composition, do not form a usable map."""


@dataclass(frozen=True)
class PointMap:
    """Every point of the profile, resolved for one DER."""

    points: Mapping[Address, Point]
    composition: Composition = field(default_factory=Composition)
    edition: str = ""
    profile_version: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "points", MappingProxyType(dict(self.points)))

    def __contains__(self, address: object) -> bool:
        return address in self.points

    def __len__(self) -> int:
        return len(self.points)

    def get(self, kind: Kind, index: int) -> Point | None:
        """The point at an address, or None if the map holds none there."""
        return self.points.get((kind, index))

    def point(self, kind: Kind, index: int) -> Point:
        """The point at an address, or the error that says the map has none."""
        found = self.points.get((kind, index))
        if found is None:
            raise MapError(f"the map holds no {kind.value}{index}")
        return found

    def of(self, kind: Kind) -> Iterator[Point]:
        """Every point of one kind, in index order."""
        return iter(sorted((p for p in self.points.values() if p.kind is kind), key=_by_index))


def _by_index(point: Point) -> int:
    return point.index
