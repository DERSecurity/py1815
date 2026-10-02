"""Measure what the event buffers cost in memory when they are full.

The buffers are the one part of an outstation whose size the caller chooses and
whose contents the master decides: a master that has gone away fills every
class to its capacity, and the events stay until it comes back. On a controller
with little memory that worst case is the figure to budget for, so this script
produces it rather than leaving it to be estimated.

For each kind of event it builds an `EventBuffers`, fills all three classes to
capacity, and reports what Python allocated for that, as bytes per event and as
a total. `tracemalloc` counts the allocations the interpreter made, which is
every object an event holds: the event, its point, its timestamp and its place
in the buffer. It does not count the interpreter itself or the allocator's own
overhead, so the process grows by somewhat more than the total printed.

The figure depends on the Python version and on the width of a pointer, so the
output names both, and a figure quoted anywhere should carry them with it.

    python scripts/measure_event_memory.py
    python scripts/measure_event_memory.py --capacity 250

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import inspect
import platform
import struct
import sys
import tracemalloc
from collections.abc import Callable
from pathlib import Path

# Run from a checkout without installing, the way the other scripts are.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from py1815.events import EventBuffers, EventClass
from py1815.objects import AnalogPoint, BinaryPoint, CounterPoint
from py1815.profile.outstation import DerOutstation

#: The capacity the profile outstation uses when a caller names none, read from
#: its signature so this script cannot drift from the default it reports on.
DEFAULT_CAPACITY: int = (
    inspect.signature(DerOutstation.__init__).parameters["event_capacity"].default
)

#: Points the events are spread over. A buffer fills because a few points keep
#: changing, not because thousands of points each change once.
POINTS = 16

#: Where the timestamps start, in milliseconds. Any recent time will do; what
#: matters is that it is the size of a real one, since a small integer is
#: shared by the interpreter and would cost nothing.
START_MS = 1_750_000_000_000

Fill = Callable[[EventBuffers, EventClass, int], None]


def _binary(buffers: EventBuffers, event_class: EventClass, number: int) -> None:
    # Each point alternates, so every reading is a change and so an event.
    recorded = buffers.record_binary(
        number % POINTS,
        BinaryPoint(state=(number // POINTS) % 2 == 0),
        event_class=event_class,
        timestamp_ms=START_MS + number,
    )
    assert recorded is not None


def _analog(buffers: EventBuffers, event_class: EventClass, number: int) -> None:
    recorded = buffers.record_analog(
        number % POINTS,
        AnalogPoint(value=number + 0.5),
        event_class=event_class,
        timestamp_ms=START_MS + number,
    )
    assert recorded is not None


def _frozen_counter(buffers: EventBuffers, event_class: EventClass, number: int) -> None:
    buffers.record_frozen_counter(
        number % POINTS,
        CounterPoint(value=100_000 + number),
        event_class=event_class,
        timestamp_ms=START_MS + number,
    )


KINDS: dict[str, Fill] = {
    "binary": _binary,
    "analog": _analog,
    "frozen counter": _frozen_counter,
}


def measure(fill: Fill, capacity: int) -> tuple[int, int]:
    """Bytes allocated to fill every class to capacity, and the events held."""
    tracemalloc.start()
    try:
        before, _ = tracemalloc.get_traced_memory()
        buffers = EventBuffers(capacity=capacity)
        number = 0
        for event_class in EventClass:
            for _ in range(capacity):
                fill(buffers, event_class, number)
                number += 1
        after, _ = tracemalloc.get_traced_memory()
        held = buffers.total
    finally:
        tracemalloc.stop()
    if held != capacity * len(EventClass):
        raise SystemExit(f"filled {held} events, expected {capacity * len(EventClass)}")
    return after - before, held


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument(
        "--capacity",
        type=int,
        default=DEFAULT_CAPACITY,
        help=f"events each class holds (default: {DEFAULT_CAPACITY}, the profile outstation's)",
    )
    args = parser.parse_args()
    if args.capacity < 1:
        parser.error("a buffer holds at least one event")

    print(
        f"{platform.python_implementation()} {platform.python_version()}, "
        f"{platform.system()} {platform.machine()}, "
        f"{struct.calcsize('P') * 8}-bit pointers"
    )
    print(
        f"{len(EventClass)} classes of {args.capacity} events, "
        "every class full of one kind of event:"
    )
    for name, fill in KINDS.items():
        allocated, held = measure(fill, args.capacity)
        print(
            f"  {name:<15} {allocated / held:6.0f} bytes per event, "
            f"{allocated / 1024:8.0f} KiB in all"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
