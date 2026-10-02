"""The generic curves of IEEE 1815.2 clause 6.1.3, held behind one window.

A DER function that follows a curve does not get two hundred points of its
own. The profile gives every curve the same block of points and a selector
that says which curve the block is showing, and each function names the curve
it uses by number. This module is the store behind that block: the curves,
which one is selected, which functions refer to which, and the three rules
the standard attaches to them.

- A selector naming a curve that does not exist is refused.
- A curve referred to by an enabled function is locked: its type, its units
  and its points cannot be changed until the function is disabled or pointed
  at another curve.
- A function can only be pointed at a curve of a type it follows.

The standard recommends the status for the first two and leaves the third to
the implementation, which here answers that the operation is not supported
for that curve. Zero as a function's curve number means it uses none.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from itertools import pairwise

from py1815.control import CommandStatus
from py1815.profile.binding import Binding, Reader
from py1815.profile.model import Kind

#: The fields that precede a curve's points, in the order the block lays them
#: out after its selector.
TYPE, POINT_COUNT, X_UNITS, Y_UNITS = range(4)
FIELDS = 4

#: The most points one curve can hold.
MAX_POINTS = 100

#: The curve type that says a curve has not been defined.
UNDEFINED = 0

Check = Callable[[float], "CommandStatus | None"]


@dataclass
class Curve:
    """One curve, as the integers a controlling station wrote.

    The scaling of a point depends on the units the curve declares, so the
    values are kept as they travel and whoever follows the curve applies the
    scaling for the units it understands.
    """

    number: int
    fields: list[float] = field(default_factory=lambda: [0.0] * FIELDS)
    values: list[float] = field(default_factory=lambda: [0.0] * (2 * MAX_POINTS))

    @property
    def type(self) -> int:
        """What kind of curve this is; zero for one that is not defined."""
        return round(self.fields[TYPE])

    @property
    def count(self) -> int:
        """How many of its points are in use."""
        return max(0, min(MAX_POINTS, round(self.fields[POINT_COUNT])))

    @property
    def x_units(self) -> int:
        """The units of the independent values."""
        return round(self.fields[X_UNITS])

    @property
    def y_units(self) -> int:
        """The units of the dependent values."""
        return round(self.fields[Y_UNITS])

    @property
    def points(self) -> list[tuple[float, float]]:
        """The points in use, as written, lowest numbered first."""
        return [(self.values[2 * n], self.values[2 * n + 1]) for n in range(self.count)]

    def at(self, x: float) -> float | None:
        """The curve's value at *x*, in the units its points were written in.

        Straight lines between points, and level beyond either end. None for
        a curve with no points. The points are followed in the order of their
        independent values, so a curve that doubles back to describe
        hysteresis is not followed as one.
        """
        points = sorted(self.points, key=lambda point: point[0])
        if not points:
            return None
        if x <= points[0][0]:
            return points[0][1]
        for (x0, y0), (x1, y1) in pairwise(points):
            if x <= x1:
                return y0 if x1 == x0 else y0 + (y1 - y0) * (x - x0) / (x1 - x0)
        return points[-1][1]


@dataclass
class _Reference:
    """One function's use of a curve."""

    types: frozenset[int]
    enabled: Callable[[], bool]
    curve: int = 0


class CurveStore:
    """The curves a DER holds, and the window a controlling station edits them through."""

    def __init__(self, count: int = 10) -> None:
        """
        Args:
            count: How many curves there are, numbered from one. The profile
                leaves the number to the DER.
        """
        if count < 1:
            raise ValueError("a curve store holds at least one curve")
        self.curves: dict[int, Curve] = {n: Curve(n) for n in range(1, count + 1)}
        self.selected = 1
        self._references: list[_Reference] = []

    # ----------------------------------------------------------------- state

    @property
    def current(self) -> Curve:
        """The curve the window is showing."""
        return self.curves[self.selected]

    def referenced(self, number: int) -> bool:
        """Whether any function names this curve as the one it uses."""
        return any(reference.curve == number for reference in self._references)

    def locked(self, number: int) -> bool:
        """Whether a function that is enabled names this curve."""
        return any(
            reference.curve == number and reference.enabled() for reference in self._references
        )

    # --------------------------------------------------------------- binding

    def bind(
        self,
        binding: Binding,
        *,
        output: int,
        readback: int,
        referenced: int,
        check: Check | None = None,
    ) -> None:
        """Bind the curve block: its selector, the fields, the points and the indicator.

        Args:
            binding: Where the points are bound.
            output: The analog output index of the selector. The fields and
                then the points follow it.
            readback: The analog input index the selector reads back at; the
                inputs are laid out as the outputs are.
            referenced: The binary input saying whether the selected curve is
                named by a function.
            check: A refusal that applies to every write here, such as a
                lockout, consulted before this store's own.
        """

        def guarded(own: Check) -> Check:
            def consult(value: float) -> CommandStatus | None:
                if check is not None:
                    answer = check(value)
                    if answer is not None:
                        return answer
                return own(value)

            return consult

        def exists(value: float) -> CommandStatus | None:
            return None if round(value) in self.curves else CommandStatus.OUT_OF_RANGE

        def select(value: float) -> CommandStatus | None:
            self.selected = round(value)
            return None

        binding.output(Kind.AO, output, select, check=guarded(exists), status=lambda: self.selected)
        binding.read(Kind.AI, readback, lambda: self.selected)
        binding.read(Kind.BI, referenced, lambda: self.referenced(self.selected))

        def unlocked(position: int) -> Check:
            def consult(value: float) -> CommandStatus | None:
                if self.locked(self.selected):
                    return CommandStatus.AUTOMATION_INHIBIT
                if position == TYPE and not self._usable(self.selected, round(value)):
                    return CommandStatus.NOT_SUPPORTED
                return None

            return consult

        def cell(position: int) -> tuple[Callable[[float], None], Reader]:
            if position < FIELDS:

                def write_field(value: float) -> None:
                    self.current.fields[position] = float(value)

                return write_field, lambda: self.current.fields[position]

            def write_value(value: float) -> None:
                self.current.values[position - FIELDS] = float(value)

            return write_value, lambda: self.current.values[position - FIELDS]

        for position in range(FIELDS + 2 * MAX_POINTS):
            write, read = cell(position)
            binding.output(
                Kind.AO,
                output + 1 + position,
                write,
                check=guarded(unlocked(position)),
                status=read,
            )
            binding.read(Kind.AI, readback + 1 + position, read)

    def reference(
        self,
        binding: Binding,
        index: int,
        *,
        types: Iterable[int],
        enabled: Callable[[], bool],
        check: Check | None = None,
    ) -> Callable[[], Curve | None]:
        """Bind a function's curve number, and return how to get the curve it names.

        Args:
            binding: Where the output is bound.
            index: The analog output that holds the function's curve number.
            types: The curve types the function follows.
            enabled: Whether the function is enabled now, which is what locks
                the curve it names.
            check: A refusal consulted before this store's own.

        Returns:
            A callable giving the curve the function names, or None while it
            names none.
        """
        reference = _Reference(types=frozenset(types), enabled=enabled)
        self._references.append(reference)

        def consult(value: float) -> CommandStatus | None:
            if check is not None:
                answer = check(value)
                if answer is not None:
                    return answer
            number = round(value)
            if number == 0:
                return None
            if number not in self.curves:
                return CommandStatus.OUT_OF_RANGE
            if self.curves[number].type not in reference.types:
                return CommandStatus.NOT_SUPPORTED
            return None

        def assign(value: float) -> CommandStatus | None:
            reference.curve = round(value)
            return None

        binding.output(Kind.AO, index, assign, initial=0, check=consult)
        return lambda: self.curves.get(reference.curve)

    def _usable(self, number: int, kind: int) -> bool:
        """Whether every function naming curve *number* could follow one of type *kind*."""
        return all(
            kind in reference.types for reference in self._references if reference.curve == number
        )
