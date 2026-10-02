"""The IEEE 1815.2 DER profile: its point map, and an outstation built from it.

The protocol layers beneath this package know nothing about what a point
means. This package is where that knowledge lives, in three parts:

- **A map.** `load_map` reads the profile's point tables and resolves them for a
  DER of known composition into absolute indices (`model`, `load`).
- **A binding and a builder.** A caller says where each point's value comes
  from, in engineering units, and `DerOutstation` does the rest: scaling,
  flags, class 0, events, controls, freezes (`binding`, `outstation`).
- **A simulated DER**, bound through the same interface, so the outstation
  runs with nothing attached (`der`), and the `py1815-der` command (`cli`).

The tables themselves are IEEE's and are not carried here: `extract` reads
them from a workbook the caller downloads. See ``docs/DESIGN.md``, D36.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

from py1815.profile.binding import Binding, Output, Quality, Reading
from py1815.profile.load import default_tables, read_tables, resolve

# Not exported as `load`: that is the submodule's name, and a function of the
# same name here would replace it as the package's attribute.
from py1815.profile.load import load as load_map
from py1815.profile.model import Address, Composition, Kind, MapError, Point, PointMap
from py1815.profile.outstation import DerOutstation

__all__ = [
    "Address",
    "Binding",
    "Composition",
    "DerOutstation",
    "Kind",
    "MapError",
    "Output",
    "Point",
    "PointMap",
    "Quality",
    "Reading",
    "default_tables",
    "load_map",
    "read_tables",
    "resolve",
]
