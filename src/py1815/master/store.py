"""What a master has been told: the last value of every point, and the events.

A store is filled from the objects of responses, in the order they arrived,
and is asked afterwards. It knows nothing of how the objects were obtained, so
a poll, a read and an unsolicited response all feed it the same way.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass

from py1815.decode import DecodedObject, PointType

#: Events kept before the oldest is dropped. A store is a record of a session
#: at a bench and not a historian.
DEFAULT_EVENT_CAPACITY = 10_000


@dataclass(frozen=True)
class PointValue:
    """The last thing an outstation said about one point."""

    value: bool | int | float | None
    #: The flag octet, or None when the variation that carried the value has
    #: none. None does not mean the point is healthy; it means nobody said.
    flags: int | None
    #: The time the outstation gave the value, in milliseconds since the
    #: epoch, or None when it gave none.
    time_ms: int | None
    #: Whether the value arrived as an event and not as a static object.
    from_event: bool
    group: int
    variation: int
    #: The clock when the value was received.
    received: float


class Store:
    """The last value of every point an outstation has reported."""

    def __init__(self, *, event_capacity: int = DEFAULT_EVENT_CAPACITY) -> None:
        self._points: dict[tuple[PointType, int], PointValue] = {}
        self._events: deque[DecodedObject] = deque(maxlen=event_capacity)
        #: Events received since the store was made, including those dropped
        #: for capacity and those cleared. Counts up and never goes back.
        self.events_received = 0

    def events_since(self, received: int) -> tuple[DecodedObject, ...]:
        """Return the events received after ``events_received`` stood at ``received``.

        Only those still held: an event dropped for capacity or cleared is
        not returned.
        """
        newer = self.events_received - received
        if newer <= 0:
            return ()
        return tuple(self._events)[-newer:]

    def apply(self, objects: Iterable[DecodedObject], *, now: float) -> None:
        """Take the objects of a response, in the order they were sent.

        The order matters and is the outstation's: an integrity poll asks for
        events before static data so that a present value is not overwritten
        by an older change, and applying objects in the order sent is what
        honors that.
        """
        for decoded in objects:
            if decoded.point is None or decoded.index is None:
                continue
            self._points[(decoded.point, decoded.index)] = PointValue(
                value=decoded.value,
                flags=decoded.flags,
                time_ms=decoded.time_ms,
                from_event=decoded.event,
                group=decoded.group,
                variation=decoded.variation,
                received=now,
            )
            if decoded.event:
                self._events.append(decoded)
                self.events_received += 1

    def get(self, point: PointType, index: int) -> PointValue | None:
        """One point's last value, or None if the outstation has never sent it."""
        return self._points.get((point, index))

    def points(self, point: PointType) -> dict[int, PointValue]:
        """Every point of one type that has been reported, by index, in order."""
        found = {index: value for (kind, index), value in self._points.items() if kind is point}
        return dict(sorted(found.items()))

    def binary_input(self, index: int) -> PointValue | None:
        return self.get(PointType.BINARY_INPUT, index)

    def binary_output(self, index: int) -> PointValue | None:
        return self.get(PointType.BINARY_OUTPUT, index)

    def counter(self, index: int) -> PointValue | None:
        return self.get(PointType.COUNTER, index)

    def frozen_counter(self, index: int) -> PointValue | None:
        return self.get(PointType.FROZEN_COUNTER, index)

    def analog_input(self, index: int) -> PointValue | None:
        return self.get(PointType.ANALOG_INPUT, index)

    def analog_output(self, index: int) -> PointValue | None:
        return self.get(PointType.ANALOG_OUTPUT, index)

    @property
    def events(self) -> tuple[DecodedObject, ...]:
        """The events received, oldest first, up to the capacity."""
        return tuple(self._events)

    def clear_events(self) -> None:
        self._events.clear()

    def __len__(self) -> int:
        return len(self._points)
