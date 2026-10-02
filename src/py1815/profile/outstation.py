"""The builder: a point map and a binding in, an IEEE 1815.2 outstation out.

:class:`DerOutstation` is everything a :class:`~py1815.session.Session` needs
from the device side. It answers reads from the map, in the variations and
class membership the profile selects; it accepts controls, scaled and range
checked by the tables; it records events with the class each point is given;
and it freezes the counters. The caller supplied values in engineering units
through a :class:`~py1815.profile.binding.Binding` and never sees an object.

What the profile fixes, and this module therefore does not ask about:

- Binary inputs, analog inputs, counters and frozen counters answer a class 0
  read. Output status does not: it is read by naming its group.
- The points that advertise block starting indices are served, and are left
  out of class 0.
- A "supports" input is static only. It never produces an event.
- A binary output behaves as latched whatever operation commanded it.
- A freeze does not clear the counters it freezes.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Callable, Iterable, Sequence
from typing import Any

from py1815.application import CLASS_GROUP, RESPONSE_HEADER_SIZE, ObjectHeader, QualifierCode
from py1815.application import object_header as range_header
from py1815.control import (
    GROUP_ANALOG_OUTPUT_COMMAND,
    GROUP_ANALOG_OUTPUT_STATUS,
    GROUP_BINARY_OUTPUT_COMMAND,
    GROUP_BINARY_OUTPUT_STATUS,
    AnalogOutput,
    CommandStatus,
    ControlRelayOutputBlock,
    OperationType,
    TripCloseCode,
    encode_analog_output_status,
    encode_binary_output_status,
)
from py1815.events import EventBuffers, EventClass
from py1815.events import now_ms as wall_clock_ms
from py1815.objects import (
    COUNTER_VARIATION,
    GROUP_ANALOG_INPUT,
    GROUP_BINARY_INPUT,
    GROUP_COUNTER,
    GROUP_FROZEN_COUNTER,
    AnalogEventVariation,
    AnalogPoint,
    AnalogQuality,
    AnalogVariation,
    BinaryPoint,
    BinaryVariation,
    CounterPoint,
    CounterQuality,
    FrozenCounterVariation,
    encode_analog,
    encode_binary,
    encode_counter,
    encode_frozen_counter,
    indexed_block,
)
from py1815.profile.binding import Binding, Output, Quality, Reader, Reading
from py1815.profile.model import Address, Kind, MapError, Point, PointMap
from py1815.session import Control, ParameterError, Session, UnknownObject

logger = logging.getLogger(__name__)

#: The variation each static group is reported in when a master asks for
#: variation 0 or for a class, which is the profile's choice for each.
_DEFAULT_VARIATIONS = {
    GROUP_BINARY_INPUT: int(BinaryVariation.WITH_FLAGS),
    GROUP_BINARY_OUTPUT_STATUS: 2,
    GROUP_COUNTER: COUNTER_VARIATION,
    GROUP_FROZEN_COUNTER: int(FrozenCounterVariation.INT32_WITH_FLAG_AND_TIME),
    GROUP_ANALOG_INPUT: int(AnalogVariation.INT32_WITH_FLAG),
    GROUP_ANALOG_OUTPUT_STATUS: 1,
}

#: What changes when the outstation is held to DNP3 Subset Level 2. The
#: profile's own choices for these two groups are not Level 2 objects: a
#: frozen counter with its time, and a 32-bit analog output status.
_LEVEL_2_VARIATIONS = {
    GROUP_FROZEN_COUNTER: int(FrozenCounterVariation.INT32_WITH_FLAG),
    GROUP_ANALOG_OUTPUT_STATUS: 2,
}

#: The variations a master may also name outright. Integers only: the
#: floating-point variations exceed DNP3 Level 2, and the profile makes them a
#: matter of agreement this builder does not yet offer (D39).
_SERVED_VARIATIONS = {
    GROUP_BINARY_INPUT: {2},
    GROUP_BINARY_OUTPUT_STATUS: {2},
    GROUP_COUNTER: {1},
    GROUP_FROZEN_COUNTER: {1, 5, 9},
    GROUP_ANALOG_INPUT: {1, 2, 3, 4},
    GROUP_ANALOG_OUTPUT_STATUS: {1, 2},
}

#: The analog input variation that carries the same value with its flags.
_FLAGGED_ANALOG = {
    int(AnalogVariation.INT32): int(AnalogVariation.INT32_WITH_FLAG),
    int(AnalogVariation.INT16): int(AnalogVariation.INT16_WITH_FLAG),
}

_GROUP_KINDS = {
    GROUP_BINARY_INPUT: Kind.BI,
    GROUP_BINARY_OUTPUT_STATUS: Kind.BO,
    GROUP_COUNTER: Kind.CTR,
    GROUP_FROZEN_COUNTER: Kind.CTR,
    GROUP_ANALOG_INPUT: Kind.AI,
    GROUP_ANALOG_OUTPUT_STATUS: Kind.AO,
}

#: The groups a class 0 read is answered with, in the order they are sent.
_CLASS_0_GROUPS = (GROUP_BINARY_INPUT, GROUP_COUNTER, GROUP_FROZEN_COUNTER, GROUP_ANALOG_INPUT)

_RANGES = (QualifierCode.UINT8_START_STOP, QualifierCode.UINT16_START_STOP)

#: The qualifiers that name points one at a time, and the octets each spends
#: on a count and on an index.
_INDEXED = {
    QualifierCode.UINT8_COUNT_UINT8_INDEX: 1,
    QualifierCode.UINT16_COUNT_UINT16_INDEX: 2,
}

#: The class frozen counter events report in where the tables do not say.
_DEFAULT_FROZEN_CLASS = EventClass.CLASS_3

_QUALITY_FLAGS = {
    Quality.GOOD: int(AnalogQuality.ONLINE),
    Quality.COMM_LOST: int(AnalogQuality.COMM_LOST),
    Quality.NEVER_READ: int(AnalogQuality.RESTART),
    Quality.OFFLINE: 0,
}


class DerOutstation:
    """An IEEE 1815.2 outstation's device side, built from a map and a binding.

    Implements the read, control and freeze providers a session takes, so one
    object is handed to :class:`~py1815.session.Session` three times, or
    :meth:`session` does it.
    """

    def __init__(
        self,
        point_map: PointMap,
        binding: Binding,
        *,
        strict: bool = True,
        event_capacity: int = 2000,
        block_octets: int = 1024,
        clock_ms: Callable[[], int] = wall_clock_ms,
        level2: bool = False,
        disabled_offline: bool = True,
        read_only: bool = False,
        read_only_status: CommandStatus = CommandStatus.NOT_AUTHORIZED,
    ) -> None:
        """
        Args:
            point_map: The profile's points, resolved for this DER.
            binding: Where each served point's value comes from.
            strict: Refuse to build an outstation that leaves a point the
                profile makes mandatory unserved. Turned off only to serve a
                deliberately partial map, which is then not a conformant one.
            event_capacity: Events each class holds before its oldest is lost.
            block_octets: The most octets one static block may occupy. A
                response is made of whole blocks, so this has to fit the
                fragment a master can receive.
            clock_ms: Wall-clock milliseconds, UTC. Event and freeze times are
                taken from it, corrected by whatever time a master has written.
            level2: Answer as a DNP3 Subset Level 2 outstation and nothing
                more. The DER profile is built on Level 2 and adds to it;
                IEEE 1815.2 has every such addition be one an outstation can
                turn off, and this turns them off. Frozen counters are
                reported without their time, analog output status in 16
                bits, a freeze buffers no event, and freeze-and-clear clears.
                A master may still name the fuller variations outright.
            disabled_offline: Report the inputs of a function that is
                disabled with the ONLINE flag clear, as IEEE 1815.2
                clause 6.1.1 requires: the value is still sent, marked
                as not in effect. Turn it off for a controlling station
                that discards any value not flagged ONLINE, and so
                could not check a setting before enabling its function.
            read_only: Report and do not command (D65). Every control on a
                bound output is refused with ``read_only_status`` and nothing
                reaches the binding. For an outstation that is one of several
                interfaces onto a device, when another of them holds control.
                Settable afterwards through :attr:`read_only`.
            read_only_status: What a refused control is answered with. The
                default says this master may not command here. A caller that
                knows another master holds the point may prefer
                ``BLOCKED_OTHER_MASTER``.
        """
        if block_octets < 32:
            raise ValueError(f"block_octets is {block_octets}; too small to hold an object range")
        if read_only_status is CommandStatus.SUCCESS:
            raise ValueError("read_only_status is SUCCESS, which refuses nothing")
        self._map = point_map
        self._binding = binding
        self.read_only = read_only
        self._read_only_status = read_only_status
        self._block_octets = block_octets
        self._clock_ms = clock_ms
        self._level2 = level2
        self._defaults = dict(_DEFAULT_VARIATIONS)
        if level2:
            self._defaults.update(_LEVEL_2_VARIATIONS)
        #: What each counter read when it was last cleared, so that a
        #: counter bound to a running total can be cleared without the
        #: source being asked to forget.
        self._cleared_at: dict[int, int] = {}
        #: What a master's time write moved this outstation's clock by.
        self._time_offset_ms = 0
        self.events = EventBuffers(capacity=event_capacity, analog_latest_only=True)

        unknown = sorted(
            f"{kind.value}{index}"
            for kind, index in (*binding.readers, *binding.outputs)
            if (kind, index) not in point_map
        )
        if unknown:
            raise MapError(f"the binding names points the map does not hold: {', '.join(unknown)}")

        #: The last value each output accepted, in engineering units.
        self._state: dict[Address, float | bool] = {
            address: output.initial
            for address, output in binding.outputs.items()
            if output.initial is not None
        }
        self._sources = self._resolve_sources()
        #: For each input of a function, the output that enables the function.
        self._gates: dict[Address, Address] = self._function_gates() if disabled_offline else {}
        self._served: dict[Kind, list[Point]] = {
            kind: [p for p in point_map.of(kind) if self._is_served(p)] for kind in Kind
        }
        self._by_index: dict[Kind, dict[int, Point]] = {
            kind: {p.index: p for p in points} for kind, points in self._served.items()
        }
        #: Each frozen counter's value and the moment it was frozen.
        self._frozen: dict[int, tuple[CounterPoint, int]] = {}
        self._primed = False

        if strict:
            missing = sorted(
                (p for p in point_map.points.values() if p.mandatory and not self._is_served(p)),
                key=lambda p: (p.kind.value, p.index),
            )
            if missing:
                listed = ", ".join(f"{p.kind.value}{p.index}" for p in missing[:20])
                more = f" and {len(missing) - 20} more" if len(missing) > 20 else ""
                raise MapError(
                    f"{len(missing)} point(s) the profile makes mandatory are not bound: "
                    f"{listed}{more}"
                )

    # ------------------------------------------------------------ assembly

    def _resolve_sources(self) -> dict[Address, Reader]:
        """Where each input's value comes from, the caller's word first.

        A bound reader wins. Failing that, an input paired with a bound output
        reports what that output last accepted; a "supports" input reports
        whether its function's enable output is bound (D40); and a point the
        tables fix the value of reports that value.
        """
        sources: dict[Address, Reader] = {}
        mirrors: dict[Address, Address] = {}
        for address in self._binding.outputs:
            point = self._map.point(*address)
            if point.associated is not None and not point.associated[0].is_output:
                mirrors[point.associated] = address
        for point in self._map.points.values():
            if point.kind.is_output or point.associated is None:
                continue
            if point.associated in self._binding.outputs:
                mirrors.setdefault(point.address, point.associated)

        for point in self._map.points.values():
            if point.kind.is_output:
                continue
            address = point.address
            if address in self._binding.readers:
                sources[address] = self._binding.readers[address]
            elif address in mirrors:
                sources[address] = self._mirror(mirrors[address])
            elif point.enabled_by is not None:
                sources[address] = _constant(point.enabled_by in self._binding.outputs)
            elif point.fixed_value is not None:
                sources[address] = _constant(point.fixed_value)
        return sources

    def _function_gates(self) -> dict[Address, Address]:
        """Which enable output each function input answers to.

        A function is the points the tables give one purpose, under one
        heading, around an enable output that a supports input is paired
        with. Two of its inputs are left out, because they say something
        about the function that is true whether or not it is enabled: the
        input that says it is supported, and the one that says whether it
        is enabled.
        """
        functions: dict[tuple[str, str | None], Point] = {}
        exempt: set[Address] = set()
        for point in self._map.points.values():
            if point.enabled_by is None or point.enabled_by not in self._binding.outputs:
                continue
            enable = self._map.point(*point.enabled_by)
            if not enable.purpose:
                continue
            functions[(enable.purpose.casefold(), enable.section)] = enable
            exempt.add(point.address)
            if enable.associated is not None:
                exempt.add(enable.associated)
        gates: dict[Address, Address] = {}
        for point in self._map.points.values():
            if point.kind.is_output or not point.purpose or point.address in exempt:
                continue
            gate = functions.get((point.purpose.casefold(), point.section))
            if gate is not None and point.address in self._sources:
                gates[point.address] = gate.address
        return gates

    def _mirror(self, output: Address) -> Reader:
        # The input paired with an output says what the output stands at,
        # which is the same question its status answers. Asking it the same
        # way is what keeps the two from disagreeing when the device applied
        # something other than what was written (D65).
        return lambda: self._standing(output)

    def _standing(self, address: Address) -> Reading:
        """What an output stands at: the value in force, and how far to trust it.

        The binding's status reader when it has one, since only the device
        knows what it applied. Without one, the last write this outstation
        accepted. A read-only outstation accepts none, and one that became
        read-only stops vouching for a write it took earlier, because another
        interface may have changed the value since: it reports the initial
        value the binding gave, or that it has nothing to report.
        """
        output = self._binding.outputs[address]
        if output.status is not None:
            try:
                result = output.status()
            except Exception:  # pylint: disable=broad-exception-caught
                logger.exception("profile: status of %s%d failed", address[0].value, address[1])
                return Reading(0, Quality.COMM_LOST)
            return result if isinstance(result, Reading) else Reading(result)
        value = output.initial if self.read_only else self._state.get(address)
        if value is None:
            # Nothing has been written and no initial value was given, so
            # there is no value to report: say so rather than report zero.
            return Reading(0, Quality.NEVER_READ)
        return Reading(value)

    def _is_served(self, point: Point) -> bool:
        if point.kind.is_output:
            return point.address in self._binding.outputs
        return point.address in self._sources

    @property
    def point_map(self) -> PointMap:
        """The map this outstation was built from."""
        return self._map

    @property
    def level2(self) -> bool:
        """Whether this outstation is held to Subset Level 2."""
        return self._level2

    def default_variation(self, group: int) -> int:
        """The variation a static group is reported in when none is named."""
        return self._defaults[group]

    def served(self, kind: Kind) -> list[Point]:
        """The points of one kind this outstation serves, in index order."""
        return list(self._served[kind])

    def value(self, kind: Kind, index: int) -> float | bool | None:
        """The last value an output accepted, or None if it has none yet."""
        return self._state.get((kind, index))

    # ---------------------------------------------------------------- time

    def now_ms(self) -> int:
        """The time, as this outstation's clock currently has it."""
        return self._clock_ms() + self._time_offset_ms

    def set_time(self, timestamp_ms: int) -> None:
        """Adopt the time a master wrote. Later events and freezes carry it."""
        self._time_offset_ms = int(timestamp_ms) - self._clock_ms()

    # ------------------------------------------------------------- readings

    def _reading(self, point: Point) -> Reading:
        try:
            result = self._sources[point.address]()
        except Exception:  # pylint: disable=broad-exception-caught
            # A source that raises is a source that could not be read. One bad
            # point must not take the whole response with it, and the master
            # is told this value cannot be trusted.
            logger.exception("profile: reading %s%d failed", point.kind.value, point.index)
            return Reading(0, Quality.COMM_LOST)
        reading = result if isinstance(result, Reading) else Reading(result)
        gate = self._gates.get(point.address)
        if gate is not None and reading.quality is Quality.GOOD and not self._state.get(gate):
            # The function this input belongs to is disabled. The value is
            # sent as it stands and marked as not in effect.
            return Reading(reading.value, Quality.OFFLINE, reading.timestamp_ms)
        return reading

    def _binary(self, point: Point) -> BinaryPoint:
        reading = self._reading(point)
        return BinaryPoint(bool(reading.value), _QUALITY_FLAGS[reading.quality])

    def _analog(self, point: Point) -> AnalogPoint:
        reading = self._reading(point)
        flags = _QUALITY_FLAGS[reading.quality]
        raw = point.to_wire(float(reading.value))
        if math.isfinite(raw):
            raw = float(round(raw))
            if not point.in_range(raw):
                flags |= AnalogQuality.OVER_RANGE
        return AnalogPoint(raw, flags)

    def _counter(self, point: Point) -> CounterPoint:
        reading = self._reading(point)
        flags = {
            Quality.GOOD: CounterQuality.ONLINE,
            Quality.COMM_LOST: CounterQuality.COMM_LOST,
            Quality.NEVER_READ: CounterQuality.RESTART,
            Quality.OFFLINE: 0,
        }[reading.quality]
        count = max(0, round(float(reading.value)))
        return CounterPoint(max(0, count - self._cleared_at.get(point.index, 0)), int(flags))

    # ---------------------------------------------------------------- reads

    def read(self, headers: Sequence[ObjectHeader]) -> bytes:
        """The objects a read names, as one body. See :meth:`read_blocks`."""
        return b"".join(self.read_blocks(headers))

    def read_blocks(self, headers: Sequence[ObjectHeader]) -> Sequence[bytes]:
        """The objects a read names, as the blocks a response may be split at."""
        blocks: list[bytes] = []
        for header in headers:
            if header.group == CLASS_GROUP and header.event_class == 0:
                for group in _CLASS_0_GROUPS:
                    points = [p for p in self._served[_GROUP_KINDS[group]] if p.in_class_0]
                    blocks += self._ranges(group, self._defaults[group], points)
                continue
            variation = self._variation(header)
            if header.qualifier in _INDEXED:
                blocks += self._indexed(
                    header.group, variation, self._named(header), header.qualifier
                )
            else:
                blocks += self._ranges(header.group, variation, self._selected(header))
        return blocks

    def _variation(self, header: ObjectHeader) -> int:
        served = _SERVED_VARIATIONS.get(header.group)
        if served is None:
            raise UnknownObject(f"group {header.group} is not served")
        if header.variation == 0:
            return self._defaults[header.group]
        if header.variation not in served:
            raise UnknownObject(f"group {header.group} variation {header.variation} is not offered")
        return header.variation

    def _named(self, header: ObjectHeader) -> list[Point]:
        """The served points a read names one index at a time, in the order named.

        Not required of an outstation at any subset level, and answered
        because a master picking a few scattered points has no better way to
        ask. Every index has to be a point this outstation serves. A range is
        allowed to cross a gap, since a master cannot know where the gaps
        are; an index is a statement that a point is there, and one that is
        not there is the master's error to hear about (D63).
        """
        points = self._served[_GROUP_KINDS[header.group]]
        if not points:
            raise UnknownObject(f"group {header.group} holds no points")
        if not header.indices:
            raise ParameterError(f"an indexed read of group {header.group} names no index")
        by_index = {point.index: point for point in points}
        absent = sorted({index for index in header.indices if index not in by_index})
        if absent:
            raise ParameterError(f"group {header.group} has no point at index {absent[0]}")
        return [by_index[index] for index in header.indices]

    def _selected(self, header: ObjectHeader) -> list[Point]:
        """The served points a static read header names."""
        points = self._served[_GROUP_KINDS[header.group]]
        if not points:
            # A kind this outstation has none of is, to a master, an object
            # it does not have. Answering with nothing and no indication
            # would read as a kind that exists and happens to be empty.
            raise UnknownObject(f"group {header.group} holds no points")
        if header.qualifier is QualifierCode.ALL_OBJECTS:
            return points
        if header.qualifier in _RANGES and header.start is not None and header.stop is not None:
            named = [p for p in points if header.start <= p.index <= header.stop]
            # A range that runs past the last point, or lands between
            # points, names something that is not there. The object is
            # one this outstation knows; it is the range that is wrong.
            if not named or header.stop > points[-1].index:
                raise ParameterError(
                    f"group {header.group} has no points across {header.start}..{header.stop}"
                )
            return named
        raise UnknownObject(
            f"qualifier 0x{int(header.qualifier):02X} does not select static group {header.group}"
        )

    def _encode(self, group: int, variation: int, point: Point) -> tuple[int, bytes] | None:
        """One point as one object and the variation it took, or None for nothing to report.

        The variation is the one asked for unless that one has no flag
        octet and the point has something to say in it. A variation
        without flags stands for a point that is online and nothing else;
        a point that is anything else is sent in the matching variation
        with flags, so that asking for the compact form never hides that
        a value is not to be trusted.
        """
        if group == GROUP_BINARY_INPUT:
            return variation, encode_binary(self._binary(point))
        if group == GROUP_ANALOG_INPUT:
            analog = self._analog(point)
            if analog.flags != AnalogQuality.ONLINE:
                variation = _FLAGGED_ANALOG.get(variation, variation)
            return variation, encode_analog(analog, AnalogVariation(variation))
        if group == GROUP_COUNTER:
            return variation, encode_counter(self._counter(point))
        if group == GROUP_FROZEN_COUNTER:
            frozen = self._frozen.get(point.index)
            if frozen is None:
                # Never frozen, so there is no frozen value; the counter is
                # absent from this group until its first freeze.
                return None
            if (
                variation == FrozenCounterVariation.INT32
                and frozen[0].flags != CounterQuality.ONLINE
            ):
                variation = int(FrozenCounterVariation.INT32_WITH_FLAG)
            timed = variation == FrozenCounterVariation.INT32_WITH_FLAG_AND_TIME
            return variation, encode_frozen_counter(
                frozen[0],
                variation=FrozenCounterVariation(variation),
                timestamp_ms=frozen[1] if timed else None,
            )
        value, flags = self._output_status(point)
        if group == GROUP_BINARY_OUTPUT_STATUS:
            return variation, encode_binary_output_status(state=bool(value), flags=flags)
        raw = point.to_wire(float(value or 0))
        return variation, encode_analog_output_status(float(round(raw)), variation, flags=flags)

    def _output_status(self, point: Point) -> tuple[float | bool | None, int]:
        """What an output currently stands at, and the flags that go with it."""
        reading = self._standing(point.address)
        if reading.quality is Quality.NEVER_READ:
            # Never written and given no initial value: nothing to report yet.
            return None, _QUALITY_FLAGS[Quality.NEVER_READ]
        return reading.value, _QUALITY_FLAGS[reading.quality]

    def _indexed(
        self, group: int, variation: int, points: Iterable[Point], qualifier: QualifierCode
    ) -> list[bytes]:
        """Points as index-prefixed objects, in the order given, split at the block budget.

        The counterpart of :meth:`_ranges` for a read that named indices. A
        block holds one variation, so a point that takes a different one from
        the point before it starts a new block, exactly as a range does.

        Where it differs is a point with nothing to report, which today is a
        frozen counter that has never been frozen. A range passes over it. A
        read that named it is refused, for the reason an index that is not a
        point is refused: leaving it out would answer with clean indications
        and fewer objects than were asked for (D63).
        """
        prefix = _INDEXED[qualifier]
        # Group, variation and qualifier, then a count as wide as an index.
        header = 3 + prefix
        blocks: list[bytes] = []
        current = variation
        items: list[tuple[int, bytes]] = []
        size = 0

        def flush() -> None:
            nonlocal items, size
            if items:
                blocks.append(indexed_block(group, current, items, qualifier=qualifier))
            items, size = [], 0

        for point in points:
            result = self._encode(group, variation, point)
            if result is None:
                raise ParameterError(f"group {group} has nothing to report at index {point.index}")
            taken, encoded = result
            cost = prefix + len(encoded)
            if items and (taken != current or size + cost + header > self._block_octets):
                flush()
            if not items:
                current = taken
            items.append((point.index, encoded))
            size += cost
        flush()
        return blocks

    def _ranges(self, group: int, variation: int, points: Iterable[Point]) -> list[bytes]:
        """Points as object ranges: split at index gaps and at the block budget.

        Never inside an object. A run of contiguous indices is one header and
        its objects until it would outgrow a block, and then it is two. A
        point that takes a different variation from its neighbors starts a
        run of its own, since a header names one variation.
        """
        blocks: list[bytes] = []
        start = previous = -1
        current = variation
        objects: list[bytes] = []
        size = 0

        def flush() -> None:
            nonlocal objects, size
            if objects:
                header = range_header(group, current, start=start, stop=previous)
                blocks.append(header + b"".join(objects))
            objects, size = [], 0

        for point in points:
            result = self._encode(group, variation, point)
            if result is None:
                continue
            taken, encoded = result
            # Seven octets is the widest range header: group, variation,
            # qualifier and two sixteen-bit indices.
            if objects and (
                point.index != previous + 1
                or taken != current
                or size + len(encoded) + 7 > self._block_octets
            ):
                flush()
            if not objects:
                start = point.index
                current = taken
            objects.append(encoded)
            size += len(encoded)
            previous = point.index
        flush()
        return blocks

    # --------------------------------------------------------------- events

    def poll(self) -> int:
        """Read every event-reporting input and buffer what changed.

        Called on whatever cadence the caller's sources move at, and again
        after a control is operated so the inputs that mirror it report the
        change at once. The first call only records where every point stands:
        a master learns initial values from its integrity poll, and a buffer
        of them would be a few hundred events saying nothing happened.

        Returns:
            How many events were buffered.
        """
        now = self.now_ms()
        buffered = 0
        for point in self._served[Kind.BI]:
            if point.event_class not in (1, 2, 3):
                continue
            binary = self._binary(point)
            if not self._primed:
                self.events.prime_binary(point.index, binary)
            elif self.events.record_binary(
                point.index,
                binary,
                event_class=EventClass(point.event_class),
                timestamp_ms=now,
            ):
                buffered += 1
        for point in self._served[Kind.AI]:
            if point.event_class not in (1, 2, 3):
                continue
            analog = self._analog(point)
            if not self._primed:
                self.events.prime_analog(point.index, analog)
            elif self.events.record_analog(
                point.index,
                analog,
                event_class=EventClass(point.event_class),
                deadband=self._binding.deadbands.get(point.index, 0.0),
                timestamp_ms=now,
            ):
                buffered += 1
        self._primed = True
        return buffered

    # -------------------------------------------------------------- freezes

    def freeze(self, headers: Sequence[ObjectHeader], *, clear: bool) -> None:
        """Freeze the counters a master named.

        Under the DER profile the counters are not cleared, whichever freeze
        was asked for: the profile has a controlling station compute an
        interval's energy by subtracting two frozen values, which a counter
        that restarted from zero would break. Held to Subset Level 2, a
        freeze-and-clear clears, as the base standard has it.
        """
        named: list[Point] = []
        for header in headers:
            if header.group != GROUP_COUNTER:
                raise UnknownObject(f"group {header.group} cannot be frozen")
            named += self._selected(header)
        if clear and self._level2:
            self._freeze(named, clear=True)
            return
        if clear:
            logger.info("profile: freeze-and-clear froze %d counter(s), clearing none", len(named))
        self._freeze(named)

    def freeze_all(self) -> int:
        """Freeze every counter at the same moment. Returns how many froze."""
        return self._freeze(self._served[Kind.CTR])

    def _freeze(self, points: Iterable[Point], *, clear: bool = False) -> int:
        now = self.now_ms()
        frozen = 0
        for point in points:
            if not point.frozen:
                continue
            value = self._counter(point)
            self._frozen[point.index] = (value, now)
            if clear:
                self._cleared_at[point.index] = self._cleared_at.get(point.index, 0) + value.value
            if self._level2:
                # Frozen counter events are not Level 2 objects.
                frozen += 1
                continue
            event_class = point.frozen_event_class
            self.events.record_frozen_counter(
                point.index,
                value,
                event_class=(
                    EventClass(event_class) if event_class in (1, 2, 3) else _DEFAULT_FROZEN_CLASS
                ),
                timestamp_ms=now,
            )
            frozen += 1
        return frozen

    # ------------------------------------------------------------- controls

    def select(self, controls: Sequence[Control]) -> Sequence[CommandStatus]:
        """Whether each control could be operated. Nothing is executed."""
        return [self._command(control, execute=False) for control in controls]

    def operate(self, controls: Sequence[Control]) -> Sequence[CommandStatus]:
        """Execute each control through its binding, and say how each went."""
        statuses = [self._command(control, execute=True) for control in controls]
        if self._primed and CommandStatus.SUCCESS in statuses:
            # So the inputs mirroring what just changed report it in the
            # indications of this very response, not on the next cadence.
            self.poll()
        return statuses

    def _command(self, control: Control, *, execute: bool) -> CommandStatus:
        if control.group == GROUP_BINARY_OUTPUT_COMMAND:
            kind = Kind.BO
        elif control.group == GROUP_ANALOG_OUTPUT_COMMAND:
            kind = Kind.AO
        else:
            return CommandStatus.NOT_SUPPORTED
        address = (kind, control.index)
        output = self._binding.outputs.get(address)
        point = self._map.get(kind, control.index)
        if output is None or point is None:
            # No such output here. Per point rather than for the request: the
            # controls beside it may be perfectly good.
            return CommandStatus.NOT_SUPPORTED
        if self.read_only:
            # Before the value is looked at and before the binding is asked
            # anything: a refusal that depended on what was requested would
            # tell a master more about a device it may not command than "no".
            return self._read_only_status

        value: float | bool
        if isinstance(control.command, ControlRelayOutputBlock):
            state = _latched(control.command)
            if state is None:
                return CommandStatus.NOT_SUPPORTED
            value = state
        else:
            status, value = _setpoint(control.command, point)
            if status is not CommandStatus.SUCCESS:
                return status
        return self._apply(address, output, value, execute=execute)

    def _apply(
        self, address: Address, output: Output, value: float | bool, *, execute: bool
    ) -> CommandStatus:
        if output.check is not None:
            refusal = output.check(value)
            if refusal is not None and refusal is not CommandStatus.SUCCESS:
                return refusal
        if not execute:
            return CommandStatus.SUCCESS
        answer: Any = output.apply(value) if output.apply is not None else None
        if answer is None or answer is CommandStatus.SUCCESS:
            self._state[address] = value
            return CommandStatus.SUCCESS
        return CommandStatus(answer)

    # -------------------------------------------------------------- session

    def session(self, *, max_response: int = 2048, **options: Any) -> Session:
        """A session wired to this outstation, with the profile's options set.

        Analog events travel in the 32-bit variation without time, which is
        the profile's selection and the one a Level 2 master is certain to
        parse; the time is asked for from the first response; and the freeze
        functions are served only when there are counters to freeze. The
        first two are defaults a caller may override by naming the option.
        """
        if self._block_octets + RESPONSE_HEADER_SIZE > max_response:
            raise ValueError(
                f"static blocks of up to {self._block_octets} octets do not fit a "
                f"{max_response}-octet response"
            )
        options.setdefault("need_time", True)
        options.setdefault("analog_event_variation", AnalogEventVariation.INT32)
        return Session(
            self,
            control_provider=self if self._binding.outputs else None,
            events=self.events,
            freeze_provider=self if self._served[Kind.CTR] else None,
            time_sink=self.set_time,
            max_response=max_response,
            **options,
        )


def _constant(value: float | bool) -> Reader:
    return lambda: Reading(value)


def _latched(command: ControlRelayOutputBlock) -> bool | None:
    """The state a control relay output block asks for, read as a latch.

    The profile permits every operation pair and has the outstation behave as
    if each point were latched, ignoring pulse times: close and the "on"
    operations set the point, trip and the "off" operations clear it.
    """
    if command.queued:
        return None
    if command.trip_close is TripCloseCode.CLOSE:
        return True
    if command.trip_close is TripCloseCode.TRIP:
        return False
    if command.trip_close is not TripCloseCode.NUL:
        return None
    if command.operation in (OperationType.LATCH_ON, OperationType.PULSE_ON):
        return True
    if command.operation in (OperationType.LATCH_OFF, OperationType.PULSE_OFF):
        return False
    return None


def _setpoint(command: AnalogOutput, point: Point) -> tuple[CommandStatus, float]:
    """An analog output command as an engineering value, checked against its range.

    An integer variation carries the transmitted value, which the tables'
    multiplier turns into engineering units. A floating-point variation
    carries engineering units already, by the profile's own rule that floats
    are not scaled. Out of range is refused rather than clamped: a setpoint
    quietly moved to the nearest limit is one the master did not send.
    """
    if not math.isfinite(command.value):
        return CommandStatus.OUT_OF_RANGE, 0.0
    if command.variation in (3, 4):
        value = float(command.value)
        raw = point.to_wire(value)
    else:
        raw = float(command.value)
        value = point.from_wire(raw)
    if not point.in_range(raw):
        return CommandStatus.OUT_OF_RANGE, 0.0
    return CommandStatus.SUCCESS, value
