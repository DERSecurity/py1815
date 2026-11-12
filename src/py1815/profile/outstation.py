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
- A freeze does not clear the counters it freezes, unless a subset level is
  claimed: the subset tables then have a freeze-and-clear clear them.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import logging
import math
import warnings
import weakref
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import replace
from typing import Any

from py1815.application import CLASS_GROUP, RESPONSE_HEADER_SIZE, ObjectHeader, QualifierCode
from py1815.application import object_header as range_header
from py1815.control import (
    GROUP_ANALOG_OUTPUT_COMMAND,
    GROUP_ANALOG_OUTPUT_COMMAND_EVENT,
    GROUP_ANALOG_OUTPUT_EVENT,
    GROUP_ANALOG_OUTPUT_STATUS,
    GROUP_BINARY_OUTPUT_COMMAND,
    GROUP_BINARY_OUTPUT_COMMAND_EVENT,
    GROUP_BINARY_OUTPUT_EVENT,
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
    GROUP_ANALOG_DEADBAND,
    GROUP_ANALOG_INPUT,
    GROUP_BINARY_INPUT,
    GROUP_COUNTER,
    GROUP_DOUBLE_BIT_INPUT,
    GROUP_FROZEN_COUNTER,
    AnalogEventVariation,
    AnalogPoint,
    AnalogQuality,
    AnalogVariation,
    BinaryPoint,
    BinaryQuality,
    BinaryVariation,
    CounterPoint,
    CounterQuality,
    DoubleBitPoint,
    DoubleBitState,
    DoubleBitVariation,
    FrozenCounterVariation,
    encode_analog,
    encode_binary,
    encode_counter,
    encode_deadband,
    encode_double_bit,
    encode_double_bit_packed,
    encode_frozen_counter,
    indexed_block,
)
from py1815.profile.binding import Binding, Output, Quality, Reader, Reading
from py1815.profile.coverage import Coverage, Entry, Source
from py1815.profile.model import Address, Kind, MapError, Point, PointMap
from py1815.profile.policy import EventPolicy, EventRule
from py1815.session import ClassAssignment, Control, ParameterError, Session, UnknownObject
from py1815.subset import SubsetLevel

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

#: The variations a master may also name outright, below Level 4. Integers
#: only: the floating-point variations are Level 4 objects (D112).
_SERVED_VARIATIONS = {
    GROUP_BINARY_INPUT: {2},
    GROUP_BINARY_OUTPUT_STATUS: {2},
    GROUP_COUNTER: {1},
    GROUP_FROZEN_COUNTER: {1, 5, 9},
    GROUP_ANALOG_INPUT: {1, 2, 3, 4},
    GROUP_ANALOG_OUTPUT_STATUS: {1, 2},
}

#: Counter reads a master may name that this outstation answers in another
#: variation. Counters are kept in 32 bits, so a request for a 16-bit or a
#: flagless variation is answered in the 32-bit one with flags. DNP3 IED
#: Certification Procedure 3.1 rev 1, 8.24.2, accepts a 32-bit answer from a
#: device that keeps only 32-bit values, and one with flags for one without.
_WIDENED_VARIATIONS = {
    GROUP_COUNTER: {2: COUNTER_VARIATION, 5: COUNTER_VARIATION, 6: COUNTER_VARIATION},
    GROUP_FROZEN_COUNTER: {
        2: int(FrozenCounterVariation.INT32_WITH_FLAG),
        10: int(FrozenCounterVariation.INT32),
    },
}

#: Reads a Level 3 outstation answers in another variation. A binary input
#: read in the packed variation is answered with flags, which Table 12-3
#: footnote a allows (D5).
_LEVEL_3_WIDENED = {GROUP_BINARY_INPUT: {1: int(BinaryVariation.WITH_FLAGS)}}

#: What a Level 4 outstation serves in addition: the double-bit inputs
#: (TB2016-003b Table 12-7), the floating-point static variations (D112) and the
#: analog input deadbands (D114).
_LEVEL_4_VARIATIONS = {
    GROUP_DOUBLE_BIT_INPUT: {int(DoubleBitVariation.PACKED), int(DoubleBitVariation.WITH_FLAGS)},
    GROUP_ANALOG_INPUT: {int(AnalogVariation.FLOAT32_WITH_FLAG)},
    GROUP_ANALOG_OUTPUT_STATUS: {3},
    GROUP_ANALOG_DEADBAND: {1, 2, 3},
}

#: What a Level 4 outstation also answers in a variation it keeps: a 16-bit
#: frozen counter with time is answered in the 32-bit one (D113).
_LEVEL_4_WIDENED = {
    GROUP_FROZEN_COUNTER: {6: int(FrozenCounterVariation.INT32_WITH_FLAG_AND_TIME)},
}

#: The variation a read of variation 0 or a class is answered in, for the groups
#: only a Level 4 outstation serves. A double-bit input is reported with its
#: flags, as a binary input is. The 32-bit deadband holds the most.
_LEVEL_4_DEFAULTS = {
    GROUP_DOUBLE_BIT_INPUT: int(DoubleBitVariation.WITH_FLAGS),
    GROUP_ANALOG_DEADBAND: 2,
}

#: The analog input variation that carries the same value with its flags.
_FLAGGED_ANALOG = {
    int(AnalogVariation.INT32): int(AnalogVariation.INT32_WITH_FLAG),
    int(AnalogVariation.INT16): int(AnalogVariation.INT16_WITH_FLAG),
}

_GROUP_KINDS = {
    GROUP_BINARY_INPUT: Kind.BI,
    GROUP_DOUBLE_BIT_INPUT: Kind.DBI,
    GROUP_BINARY_OUTPUT_STATUS: Kind.BO,
    GROUP_COUNTER: Kind.CTR,
    GROUP_FROZEN_COUNTER: Kind.CTR,
    GROUP_ANALOG_INPUT: Kind.AI,
    GROUP_ANALOG_OUTPUT_STATUS: Kind.AO,
    GROUP_ANALOG_DEADBAND: Kind.AI,
}

#: The groups an ASSIGN_CLASS request may name, each with the group whose points
#: it selects and the subset level that requires it. IEEE 1815-2012 Table 4-12
#: names the static group of the points whose events move, and TB2016-003b
#: ticks groups 1, 20, 21 and 30 for Level 3, and group 3 (Table 12-7) and the
#: output groups for Level 4. A command group selects the output it commands.
_ASSIGNABLE_GROUPS = {
    GROUP_BINARY_INPUT: (GROUP_BINARY_INPUT, SubsetLevel.LEVEL_3),
    GROUP_DOUBLE_BIT_INPUT: (GROUP_DOUBLE_BIT_INPUT, SubsetLevel.LEVEL_4),
    GROUP_COUNTER: (GROUP_COUNTER, SubsetLevel.LEVEL_3),
    GROUP_FROZEN_COUNTER: (GROUP_FROZEN_COUNTER, SubsetLevel.LEVEL_3),
    GROUP_ANALOG_INPUT: (GROUP_ANALOG_INPUT, SubsetLevel.LEVEL_3),
    GROUP_BINARY_OUTPUT_STATUS: (GROUP_BINARY_OUTPUT_STATUS, SubsetLevel.LEVEL_4),
    GROUP_BINARY_OUTPUT_COMMAND: (GROUP_BINARY_OUTPUT_STATUS, SubsetLevel.LEVEL_4),
    GROUP_ANALOG_OUTPUT_STATUS: (GROUP_ANALOG_OUTPUT_STATUS, SubsetLevel.LEVEL_4),
    GROUP_ANALOG_OUTPUT_COMMAND: (GROUP_ANALOG_OUTPUT_STATUS, SubsetLevel.LEVEL_4),
}

#: The command groups. An assignment through one of them sets the class of the
#: output's command events (IEEE 1815-2012 Table 4-12: group 12 for group 13,
#: group 41 for group 43), not of its output events. No command events are
#: generated (D116), so the points are checked and no class changes.
_COMMAND_EVENT_ASSIGNMENTS = frozenset({GROUP_BINARY_OUTPUT_COMMAND, GROUP_ANALOG_OUTPUT_COMMAND})

#: The groups a class 0 read is answered with, in the order they are sent.
_CLASS_0_GROUPS = (GROUP_BINARY_INPUT, GROUP_COUNTER, GROUP_FROZEN_COUNTER, GROUP_ANALOG_INPUT)

#: The same at Level 4, which adds the double-bit inputs (D117) and the output
#: status of the outputs that have a class, class 0 included: a master learns an
#: output's value from class 0 before the events that change it (IEEE 1815-2012,
#: A.7.1.1; TB2016-003b, Table 12-49 notes b and i).
_CLASS_0_GROUPS_L4 = (
    GROUP_BINARY_INPUT,
    GROUP_DOUBLE_BIT_INPUT,
    GROUP_BINARY_OUTPUT_STATUS,
    GROUP_COUNTER,
    GROUP_FROZEN_COUNTER,
    GROUP_ANALOG_INPUT,
    GROUP_ANALOG_OUTPUT_STATUS,
)

#: The class an output's events report in when neither the tables nor a paired
#: input give one, as for a frozen counter.
_DEFAULT_OUTPUT_CLASS = EventClass.CLASS_3

#: The output event groups each kind of output is read in at Level 4.
_OUTPUT_EVENT_GROUPS = {
    Kind.BO: (GROUP_BINARY_OUTPUT_EVENT, GROUP_BINARY_OUTPUT_COMMAND_EVENT),
    Kind.AO: (GROUP_ANALOG_OUTPUT_EVENT, GROUP_ANALOG_OUTPUT_COMMAND_EVENT),
}

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

#: The same table read the other way, for a report that has an output's flags
#: and wants the quality they stand for.
_FLAG_QUALITY = {flags: quality for quality, flags in _QUALITY_FLAGS.items()}


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
        level: SubsetLevel | int | None = None,
        level2: bool | None = None,
        disabled_offline: bool = True,
        event_policy: EventPolicy | Mapping[str, Any] | None = None,
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
            level: The DNP3 subset level to claim and answer at: 2, 3 or 4,
                as a :class:`~py1815.subset.SubsetLevel` or its integer.
                Anything else raises ``ValueError``. Level 2 answers as a
                Level 2 outstation and nothing more. The DER profile is
                built on Level 2 and adds to it; IEEE 1815.2 has every such
                addition be one an outstation can turn off, and Level 2
                turns them off. Frozen counters are reported without their
                time, analog output status in 16 bits, a freeze buffers no
                event, and freeze-and-clear clears. A master may still name
                the fuller variations outright. Levels 3 and 4 serve the
                profile's additions, as the default does, accept ASSIGN_CLASS
                (D110), and the Device Profile claims the level. Level 4 also
                serves the floating-point variations, which carry the value
                unscaled (D112), the time-stamped 16-bit frozen counters,
                answered in 32 bits (D113), and analog input deadbands that a
                master reads and writes (D114). At any level given,
                freeze-and-clear clears. None, the default, claims Level 2 and
                serves the profile's additions, which is what the DER profile
                asks for when no level is chosen, and its counters are never
                cleared.
            level2: Deprecated; use ``level=2``. True means ``level=2`` and
                warns. False changes nothing. True with a ``level`` other
                than 2 raises ``ValueError``.
            disabled_offline: Report the inputs of a function that is
                disabled with the ONLINE flag clear, as IEEE 1815.2
                clause 6.1.1 requires: the value is still sent, marked
                as not in effect. A function is enabled when its enable
                output stands at on, by the output's ``status`` reader if
                it has one and by the last accepted write if not. Turn it
                off for a controlling station
                that discards any value not flagged ONLINE, and so
                could not check a setting before enabling its function.
            event_policy: Which points report events, in which class, and
                past what deadband, where that is not to be the tables'
                choice: an :class:`~py1815.profile.policy.EventPolicy`, or
                the plain mapping one is made from. A policy that names a
                point the map does not hold, or asks of a point what it
                cannot do, is refused here. None leaves every class to the
                tables and every deadband to the binding.
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
        self._read_only = read_only
        self._read_only_status = read_only_status
        #: The sessions :meth:`session` wired to this outstation, so a change of
        #: role can withdraw the selects they granted under the old one.
        self._sessions: weakref.WeakSet[Session] = weakref.WeakSet()
        self._block_octets = block_octets
        self._clock_ms = clock_ms
        if level2:
            warnings.warn(
                "level2=True is deprecated; use level=2",
                DeprecationWarning,
                stacklevel=2,
            )
            if level is not None and SubsetLevel.parse(level) != SubsetLevel.LEVEL_2:
                raise ValueError(f"level2=True conflicts with level={level!r}")
            level = SubsetLevel.LEVEL_2
        #: The level claimed. An outstation given no level claims Level 2 and
        #: keeps the profile's additions.
        self._level = SubsetLevel.LEVEL_2 if level is None else SubsetLevel.parse(level)
        #: Held to Level 2 and nothing more, as opposed to answering with the
        #: profile's additions.
        self._level2 = level is not None and self._level == SubsetLevel.LEVEL_2
        self._defaults, self._served_variations, self._widened = self._variations_at_level()
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
        #: How each served point comes to be served. Kept for the coverage
        #: report; nothing that answers a master reads it.
        self._origins: dict[Address, Source] = dict.fromkeys(binding.outputs, Source.BOUND)
        self._sources = self._resolve_sources()
        #: For each input of a function, the output that enables the function.
        self._gates: dict[Address, Address] = self._function_gates() if disabled_offline else {}
        # Double-bit inputs are a Level 4 object (TB2016-003b Table 12-7): below it
        # a read of group 3 or 4 names an unknown object, and the points are in no
        # class 0 or class poll response.
        self._served: dict[Kind, list[Point]] = {
            kind: (
                [p for p in point_map.of(kind) if self._is_served(p)]
                if kind is not Kind.DBI or self.at_least(SubsetLevel.LEVEL_4)
                else []
            )
            for kind in Kind
        }
        self._by_index: dict[Kind, dict[int, Point]] = {
            kind: {p.index: p for p in points} for kind, points in self._served.items()
        }
        #: Each frozen counter's value and the moment it was frozen.
        self._frozen: dict[int, tuple[CounterPoint, int]] = {}
        self._primed = False
        if event_policy is None:
            event_policy = EventPolicy()
        elif not isinstance(event_policy, EventPolicy):
            event_policy = EventPolicy.from_mapping(event_policy)
        #: The event class each input reports in, and 0 for one that reports
        #: none. For a counter it is the class its freezes are logged in, and
        #: from Level 3 the class of its counter events as well. From Level 4
        #: it holds the class of each output that has one, class 0 included;
        #: an output with no class is absent (D115).
        self._classes: dict[Address, int] = {}
        #: Each event-reporting analog input's deadband, in transmitted units.
        #: One absent from here reports every change of its transmitted value.
        self._deadbands: dict[int, float] = {}
        #: Each counter whose value changes raise events, with how far its
        #: count has to move, in transmitted counts. One absent from here
        #: raises events on flag changes only (D124).
        self._counter_deadbands: dict[int, float] = {}
        self._event_policy = event_policy
        self._apply_policy(event_policy)
        #: The class each point had at startup, which a restart or a reset
        #: returns every assignment to.
        self._initial_classes = dict(self._classes)

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

    def _variations_at_level(
        self,
    ) -> tuple[dict[int, int], dict[int, set[int]], dict[int, dict[int, int]]]:
        """Return the variations at the claimed level, by group.

        Three tables: the variation a read of variation 0 is answered in, the
        variations a master may name, and those answered in another one. Level
        3 answers a packed binary input read with flags (D5). Level 4
        adds the double-bit inputs (D117), the floating-point variations, the
        deadbands and the time-stamped 16-bit frozen counter (D112, D113, D114).
        """
        defaults = {**_DEFAULT_VARIATIONS, **self._level_variations()}
        served = {group: set(each) for group, each in _SERVED_VARIATIONS.items()}
        widened = {group: dict(each) for group, each in _WIDENED_VARIATIONS.items()}
        if self.at_least(SubsetLevel.LEVEL_3):
            for group, extra_widened in _LEVEL_3_WIDENED.items():
                widened.setdefault(group, {}).update(extra_widened)
        if self.at_least(SubsetLevel.LEVEL_4):
            for group, extra in _LEVEL_4_VARIATIONS.items():
                served.setdefault(group, set()).update(extra)
            for group, extra_widened in _LEVEL_4_WIDENED.items():
                widened.setdefault(group, {}).update(extra_widened)
            defaults.update(_LEVEL_4_DEFAULTS)
        return defaults, served, widened

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
                self._origins[address] = Source.BOUND
            elif address in mirrors:
                sources[address] = self._mirror(mirrors[address])
                self._origins[address] = Source.MIRROR
            elif point.enabled_by is not None:
                sources[address] = _constant(point.enabled_by in self._binding.outputs)
                self._origins[address] = Source.SUPPORTS
            elif point.fixed_value is not None:
                sources[address] = _constant(point.fixed_value)
                self._origins[address] = Source.FIXED
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

    def _apply_policy(self, policy: EventPolicy) -> None:
        """Settle each input's event class and deadband, the policy's word first.

        For the class, a rule naming the point outranks the rule for its
        kind, which outranks the tables. A kind's rule moves the points that
        already report and leaves alone the ones the tables keep static: a
        "supports" input is not made to report by a rule for every binary
        input. Naming such a point is how it is given events.

        For the deadband, a rule naming the point outranks the deadband given
        when the point was bound, which outranks the rule for its kind. The
        two from the policy are in engineering units and are converted here;
        the binding's is in transmitted units already (D66).
        """
        unknown = sorted(_name(address) for address in policy.points if address not in self._map)
        if unknown:
            raise MapError(
                f"the event policy names points the map does not hold: {', '.join(unknown)}"
            )
        for point in self._map.points.values():
            if point.kind.is_output:
                continue
            default = policy.defaults.get(point.kind)
            own = policy.points.get(point.address)
            reported = _class_in_force(point, default, own)
            self._classes[point.address] = reported
            if point.kind is Kind.CTR:
                self._settle_counter(point, default, own, reported)
            if point.kind is not Kind.AI:
                continue
            if not reported:
                if own is not None and own.deadband is not None:
                    raise MapError(
                        f"the event policy gives {_name(point.address)} a deadband, "
                        "and the point reports no events"
                    )
                continue
            if own is not None and own.deadband is not None:
                self._deadbands[point.index] = _transmitted(point, own.deadband)
            elif point.index in self._binding.deadbands:
                self._deadbands[point.index] = self._binding.deadbands[point.index]
            elif default is not None and default.deadband is not None:
                self._deadbands[point.index] = _transmitted(point, default.deadband)
        if self.at_least(SubsetLevel.LEVEL_4):
            self._apply_output_classes()

    def _apply_output_classes(self) -> None:
        """Settle the class each served output reports its events in (D115).

        The class the tables give the output, if they give one. Otherwise the
        class of the input paired with it, since that input reports the same
        change and a master polling one class hears of both together; an output
        whose paired input reports no events reports none. An output with
        neither is given the class a frozen counter defaults to.

        This is only the starting class. From then on the output's class is its
        own: an ASSIGN_CLASS naming group 10 or 40 changes it, and one naming
        the paired input does not (IEEE 1815-2012 Table 4-12).
        """
        for kind in (Kind.BO, Kind.AO):
            for point in self._served[kind]:
                own = point.event_class
                if own in (1, 2, 3):
                    self._classes[point.address] = own
                    continue
                paired = None if point.associated is None else self._map.get(*point.associated)
                if paired is None:
                    self._classes[point.address] = int(_DEFAULT_OUTPUT_CLASS)
                elif self._classes.get(paired.address, 0):
                    self._classes[point.address] = self._classes[paired.address]
                # Otherwise the output has no class: it reports no events and is
                # out of the class 0 response until a master assigns it one.

    def _settle_counter(
        self, point: Point, default: EventRule | None, own: EventRule | None, reported: int
    ) -> None:
        """Note whether a counter's value changes raise events, and past what deadband.

        The point's rule outranks the rule for its kind. A deadband is how far
        the count has to move from the count in the counter's last event,
        which IEEE 1815-2012 11.9.5.2 gives as one way to decide that a count
        is significant; none reports every change.
        """
        chosen = own.value_changes if own is not None else None
        if chosen is None and default is not None:
            chosen = default.value_changes
        deadband = own.deadband if own is not None else None
        if deadband is None and default is not None:
            deadband = default.deadband
        if chosen and reported:
            self._counter_deadbands[point.index] = _transmitted(point, deadband or 0.0)
        elif own is not None and own.value_changes:
            raise MapError(
                f"the event policy has {_name(point.address)} report value changes, "
                "and the counter reports no events"
            )
        elif own is not None and own.deadband is not None:
            raise MapError(
                f"the event policy gives {_name(point.address)} a deadband, "
                "and its value changes raise no events"
            )

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
    def read_only(self) -> bool:
        """Whether this outstation reports and refuses every control (D65)."""
        return self._read_only

    @read_only.setter
    def read_only(self, value: bool) -> None:
        if bool(value) == self._read_only:
            return
        self._read_only = bool(value)
        # The writes this outstation accepted are no longer its to vouch for:
        # while it only reported, another interface may have changed every one
        # of them. Without a status reader, an output reports nothing until it
        # is written again under the new role.
        self._state.clear()
        if self._read_only:
            # A select granted while it commanded is left armed, so the operate
            # it was granted for reaches the refusal every other control gets
            # and is answered with the read-only status. Withdrawing it here
            # would answer NO_SELECT, which tells a master to select again when
            # the truth is that this interface may no longer command.
            return
        # Given control back. A select from before it only reported is not
        # permission now: another interface held the device in between.
        for session in list(self._sessions):
            session.abandon_select()

    @property
    def point_map(self) -> PointMap:
        """The map this outstation was built from."""
        return self._map

    @property
    def level(self) -> SubsetLevel:
        """The subset level this outstation claims."""
        return self._level

    def at_least(self, level: SubsetLevel | int) -> bool:
        """Return whether the claimed level is ``level`` or higher.

        A feature that Level 3 introduces asks ``at_least(SubsetLevel.LEVEL_3)``.
        """
        return self._level >= SubsetLevel.parse(level)

    @property
    def level2(self) -> bool:
        """Whether this outstation is held to Subset Level 2 and nothing more."""
        return self._level2

    def default_variation(self, group: int) -> int:
        """The variation a static group is reported in when none is named."""
        return self._defaults[group]

    def served(self, kind: Kind) -> list[Point]:
        """The points of one kind this outstation serves, in index order."""
        return list(self._served[kind])

    def event_class(self, kind: Kind, index: int) -> int:
        """The class a point's events are reported in: 1, 2 or 3, or 0 for none.

        What is in force, after the event policy and the tables have both had
        their say. For a counter it is the class its freezes are logged in,
        and from Level 3 the class of its counter events as well. For an
        output it is the class of its output events, which only Level 4 reports.
        """
        return self._classes.get(self._map.point(kind, index).address, 0)

    def counter_deadband(self, index: int) -> float | None:
        """How far a counter's count has to move to raise an event, in counts.

        None for a counter whose value changes raise no event, which is every
        counter an event policy does not turn them on for.
        """
        return self._counter_deadbands.get(self._map.point(Kind.CTR, index).index)

    def deadband(self, index: int) -> float:
        """An analog input's event deadband in force, in transmitted units.

        The configured one until a master writes another (D114). Zero reports
        every change of the transmitted value, and is also the answer for a
        point with no deadband.
        """
        return self._deadbands.get(self._map.point(Kind.AI, index).index, 0.0)

    def write_deadbands(self, deadbands: Sequence[tuple[int, int, float]]) -> None:
        """Take the deadbands a master wrote, all or none (D114).

        Each item is ``(variation, index, value)`` as group 34 carries it.
        Variations 1 and 2 are in transmitted units, the integers a point's
        integer variations carry. Variation 3 is in engineering units, as the
        floating-point variations of the analog input are (D112), and is
        converted with the point's scaling. A write for the same point twice
        leaves the later one. Raises ``ParameterError``, with nothing changed,
        for an index that is not a served analog input.
        """
        chosen: dict[int, float] = {}
        for variation, index, value in deadbands:
            point = self._by_index[Kind.AI].get(index)
            if point is None:
                raise ParameterError(f"analog input {index} is not served")
            chosen[index] = _transmitted(point, value) if variation == 3 else float(value)
        self._deadbands.update(chosen)

    def _deadband_in(self, point: Point, variation: int) -> float:
        """The deadband in force for a point, in the units a variation carries."""
        span = self._deadbands.get(point.index, 0.0)
        if variation == 3 and point.multiplier is not None:
            return span * abs(point.multiplier)
        return span

    def value(self, kind: Kind, index: int) -> float | bool | None:
        """The last value an output accepted, or None if it has none yet."""
        return self._state.get((kind, index))

    def frozen(self, index: int) -> int | None:
        """Return what counter *index* held at its last freeze, or None if never frozen."""
        held = self._frozen.get(index)
        return None if held is None else held[0].value

    def coverage(self) -> Coverage:
        """Every point of the map against what this outstation serves.

        For each point: whether it is bound, served without a binding (and
        how), or absent, and for a served point the quality it has at this
        moment. Where a point's value comes from was settled when the
        outstation was built and is the same in every report. The quality is
        read now, by asking each source once, so a report is a snapshot.

        A report, and no part of what a master is answered with: it buffers
        no event, changes no output and is read by nothing here (D67).
        """
        entries: list[Entry] = []
        for kind in Kind:
            for point in self._map.of(kind):
                source = self._origins.get(point.address, Source.ABSENT)
                if source is Source.ABSENT:
                    entries.append(Entry(point, source))
                    continue
                quality, online = self._standing_on_the_wire(point)
                entries.append(Entry(point, source, quality, online))
        return Coverage(tuple(entries))

    def _standing_on_the_wire(self, point: Point) -> tuple[Quality, bool]:
        """A served point's quality now, and whether it goes out with ONLINE set.

        One question to the source, answered both ways. They differ for a
        value with no number: the source calls it good, and the wire sends
        zero with ONLINE clear and a reference error, as it does for any NaN.
        """
        if point.kind.is_output:
            value, flags = self._output_status(point)
            quality = _FLAG_QUALITY[flags]
            online = quality is Quality.GOOD
            if online and point.kind is Kind.AO and value is not None:
                online = not math.isnan(point.to_wire(float(value)))
            return quality, online
        reading = self._reading(point)
        online = reading.quality is Quality.GOOD
        if online and point.kind is Kind.AI:
            online = not math.isnan(point.to_wire(float(reading.value)))
        return reading.quality, online

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
        if gate is not None and reading.quality is Quality.GOOD and not self._enabled(gate):
            # The function this input belongs to is disabled. The value is
            # sent as it stands and marked as not in effect.
            return Reading(reading.value, Quality.OFFLINE, reading.timestamp_ms)
        return reading

    def _enabled(self, gate: Address) -> bool:
        """Whether the function behind an enable output is enabled, as far as is known.

        What the enable output stands at, asked as its status and its mirror
        ask it, so the three cannot disagree (D65). A device that reports its
        own state is believed over the last write accepted here: it may have
        been enabled before this outstation started, or by another interface,
        or have turned the function off itself. A standing value that cannot
        be vouched for, because the reader failed or nothing has been written,
        is not taken as enabled: not knowing is not grounds to tell a master
        that a setting is in force.
        """
        standing = self._standing(gate)
        return standing.quality is Quality.GOOD and bool(standing.value)

    def _event_time(self, reading: Reading, now: int) -> int:
        """Return the timestamp for an event raised by this reading (D79).

        Use the reading's own timestamp when it has one and its quality is
        ``GOOD``, shifted by the offset a master's time write applied to this
        outstation's clock. Otherwise use ``now``. A reading that is not
        ``GOOD`` still holds the time of its last measurement, but the event
        is the quality change, and that is happening now.
        """
        if reading.timestamp_ms is None or reading.quality is not Quality.GOOD:
            return now
        return int(reading.timestamp_ms) + self._time_offset_ms

    def _binary(self, point: Point) -> BinaryPoint:
        return self._binary_of(self._reading(point))

    @staticmethod
    def _binary_of(reading: Reading) -> BinaryPoint:
        return BinaryPoint(bool(reading.value), _QUALITY_FLAGS[reading.quality])

    def _analog(self, point: Point) -> AnalogPoint:
        return self._analog_of(point, self._reading(point))

    @staticmethod
    def _analog_of(point: Point, reading: Reading) -> AnalogPoint:
        flags = _QUALITY_FLAGS[reading.quality]
        raw = point.to_wire(float(reading.value))
        if math.isfinite(raw):
            raw = float(round(raw))
            if not point.in_range(raw):
                flags |= AnalogQuality.OVER_RANGE
        return AnalogPoint(raw, flags)

    def _double_bit(self, point: Point) -> DoubleBitPoint:
        return self._double_bit_of(point, self._reading(point))

    @staticmethod
    def _double_bit_of(point: Point, reading: Reading) -> DoubleBitPoint:
        """Return a reading as a double-bit point.

        A value that is not a whole number from 0 to 3 is not a state. It is
        reported as INDETERMINATE with the source marked as not reachable, so a
        master is told the value cannot be trusted.
        """
        state = reading.value
        if isinstance(state, bool) or not 0 <= state <= 3 or state != int(state):
            logger.error(
                "profile: %s%d has the value %r, which is not a double-bit state",
                point.kind.value,
                point.index,
                state,
            )
            return DoubleBitPoint(
                int(DoubleBitState.INDETERMINATE), _QUALITY_FLAGS[Quality.COMM_LOST]
            )
        return DoubleBitPoint(int(state), _QUALITY_FLAGS[reading.quality])

    def _counter(self, point: Point) -> CounterPoint:
        return self._counter_of(point, self._reading(point))

    def _counter_of(self, point: Point, reading: Reading) -> CounterPoint:
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
                for group in self._class_0_groups:
                    points = [p for p in self._points(group) if self._in_class_0(p)]
                    blocks += self._ranges(group, self._defaults[group], points)
                continue
            variation = self._variation(header)
            if header.qualifier in _INDEXED:
                if (
                    header.group == GROUP_DOUBLE_BIT_INPUT
                    and variation == DoubleBitVariation.PACKED
                ):
                    # The packed variation has only a range form (TB2016-003b Table 12-8).
                    raise UnknownObject(
                        f"qualifier 0x{int(header.qualifier):02X} does not select "
                        f"group {header.group} variation {variation}"
                    )
                blocks += self._indexed(
                    header.group, variation, self._named(header), header.qualifier
                )
            else:
                blocks += self._ranges(header.group, variation, self._selected(header))
        return blocks

    @property
    def _class_0_groups(self) -> tuple[int, ...]:
        return _CLASS_0_GROUPS_L4 if self.at_least(SubsetLevel.LEVEL_4) else _CLASS_0_GROUPS

    def in_class_0(self, kind: Kind, index: int) -> bool:
        """Return whether a class 0 read carries a point.

        An output is carried when it has a class: one it reports events in, or
        class 0 by assignment, which stops its events and keeps it in class 0
        (TB2016-003b Table 12-49 note b). An output with no class is left out,
        as note i allows, so an outstation that reports no output events
        answers class 0 as it always has (D115).
        """
        return self._in_class_0(self._map.point(kind, index))

    def _in_class_0(self, point: Point) -> bool:
        if point.kind.is_output:
            # An output in the classes has a class, class 0 included.
            return point.address in self._classes
        return point.in_class_0

    def _variation(self, header: ObjectHeader) -> int:
        served = self._served_variations.get(header.group)
        if served is None:
            raise UnknownObject(f"group {header.group} is not served")
        if header.variation == 0:
            return self._defaults[header.group]
        widened = self._widened.get(header.group, {}).get(header.variation)
        if widened is not None:
            return widened
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
        points = self._points(header.group)
        if not points:
            raise UnknownObject(f"group {header.group} holds no points")
        if not header.indices:
            raise ParameterError(f"an indexed read of group {header.group} names no index")
        by_index = {point.index: point for point in points}
        absent = sorted({index for index in header.indices if index not in by_index})
        if absent:
            raise ParameterError(f"group {header.group} has no point at index {absent[0]}")
        return [by_index[index] for index in header.indices]

    def _points(self, group: int) -> list[Point]:
        """Return the served points a static group reports. Only counters that freeze are frozen."""
        points = self._served[_GROUP_KINDS[group]]
        if group == GROUP_FROZEN_COUNTER:
            return [p for p in points if p.frozen]
        return points

    def _selected(self, header: ObjectHeader) -> list[Point]:
        """The served points a static read header names."""
        points = self._points(header.group)
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
        if group == GROUP_ANALOG_DEADBAND:
            return variation, encode_deadband(self._deadband_in(point, variation), variation)
        if group == GROUP_DOUBLE_BIT_INPUT:
            double_bit = self._double_bit(point)
            if double_bit.flags != BinaryQuality.ONLINE:
                # The packed variation has no flags. A point in an exception
                # condition is reported with them (TB2016-003b Table 12-7, note a).
                variation = int(DoubleBitVariation.WITH_FLAGS)
            if variation == DoubleBitVariation.PACKED:
                # One state, packed with its neighbors by the range that holds it.
                return variation, bytes([double_bit.state])
            return variation, encode_double_bit(double_bit)
        if group == GROUP_ANALOG_INPUT:
            reading = self._reading(point)
            analog = self._analog_of(point, reading)
            if variation == AnalogVariation.FLOAT32_WITH_FLAG:
                # The value as the source gave it: a floating-point variation
                # is not scaled (D112). The flags are the integer form's.
                analog = AnalogPoint(float(reading.value), analog.flags)
            elif analog.flags != AnalogQuality.ONLINE:
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
        if variation == 3:
            return variation, encode_analog_output_status(float(value or 0), 3, flags=flags)
        raw = point.to_wire(float(value or 0))
        if math.isfinite(raw):
            # Rounded to the integer the variation carries. A value with no
            # number is passed as it is, and the encoder sends it flagged
            # instead of the read failing on it.
            raw = float(round(raw))
        return variation, encode_analog_output_status(raw, variation, flags=flags)

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
                if group == GROUP_DOUBLE_BIT_INPUT and current == DoubleBitVariation.PACKED:
                    blocks.append(header + encode_double_bit_packed([o[0] for o in objects]))
                else:
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
        # Only a Level 4 outstation has a floating-point event to report.
        floats = self.at_least(SubsetLevel.LEVEL_4)
        for point in self._served[Kind.BI]:
            reported = self._classes[point.address]
            if not reported:
                continue
            reading = self._reading(point)
            binary = self._binary_of(reading)
            if not self._primed:
                self.events.prime_binary(point.index, binary)
            elif self.events.record_binary(
                point.index,
                binary,
                event_class=EventClass(reported),
                timestamp_ms=self._event_time(reading, now),
            ):
                buffered += 1
        for point in self._served[Kind.DBI]:
            reported = self._classes[point.address]
            if not reported:
                continue
            reading = self._reading(point)
            double_bit = self._double_bit_of(point, reading)
            if not self._primed:
                self.events.prime_double_bit(point.index, double_bit)
            elif self.events.record_double_bit(
                point.index,
                double_bit,
                event_class=EventClass(reported),
                timestamp_ms=self._event_time(reading, now),
            ):
                buffered += 1
        for point in self._served[Kind.AI]:
            reported = self._classes[point.address]
            if not reported:
                continue
            reading = self._reading(point)
            analog = self._analog_of(point, reading)
            if not self._primed:
                self.events.prime_analog(point.index, analog)
            elif self.events.record_analog(
                point.index,
                analog,
                event_class=EventClass(reported),
                deadband=self._deadbands.get(point.index, 0.0),
                timestamp_ms=self._event_time(reading, now),
                unscaled=float(reading.value) if floats else None,
            ):
                buffered += 1
        if self.at_least(SubsetLevel.LEVEL_3):
            buffered += self._poll_counters(now)
        if self.at_least(SubsetLevel.LEVEL_4):
            buffered += self._poll_outputs(now)
        self._primed = True
        return buffered

    def _poll_counters(self, now: int) -> int:
        """Buffer a counter event for each counter whose flags changed (D124).

        A counter reports in the class its frozen counter events use. A
        change in value raises an event only for a counter whose event policy
        turns value changes on, once it moves past the deadband.
        """
        buffered = 0
        for point in self._served[Kind.CTR]:
            reported = self._classes[point.address]
            if not reported:
                continue
            reading = self._reading(point)
            counter = self._counter_of(point, reading)
            if not self._primed:
                self.events.prime_counter(point.index, counter)
            elif self.events.record_counter(
                point.index,
                counter,
                event_class=EventClass(reported),
                value_deadband=self._counter_deadbands.get(point.index),
                timestamp_ms=self._event_time(reading, now),
            ):
                buffered += 1
        return buffered

    def _poll_outputs(self, now: int) -> int:
        """Buffer the changes of the outputs that report events, from Level 4 up.

        An output's value or flags change when a control is carried out, when
        its status reader reports a change the device made, and when the
        reader stops answering. The first pass only records where each stands,
        as it does for the inputs.
        """
        buffered = 0
        for point in self._served[Kind.BO]:
            reported = self._classes.get(point.address, 0)
            if not reported:
                continue
            reading = self._standing(point.address)
            binary = self._binary_of(reading)
            if not self._primed:
                self.events.prime_binary_output(point.index, binary)
            elif self.events.record_binary_output(
                point.index,
                binary,
                event_class=EventClass(reported),
                timestamp_ms=self._event_time(reading, now),
            ):
                buffered += 1
        for point in self._served[Kind.AO]:
            reported = self._classes.get(point.address, 0)
            if not reported:
                continue
            reading = self._standing(point.address)
            analog = self._analog_of(point, reading)
            if not self._primed:
                self.events.prime_analog_output(point.index, analog)
            elif self.events.record_analog_output(
                point.index,
                analog,
                float(reading.value),
                event_class=EventClass(reported),
                timestamp_ms=self._event_time(reading, now),
            ):
                buffered += 1
        return buffered

    # ----------------------------------------------------- class assignment

    def assign_class(self, assignments: Sequence[ClassAssignment]) -> None:
        """Move points between event classes, or turn their events off (D110).

        Every set is checked before any is applied, so a request that names
        something unassignable changes nothing. A set applies to the points its
        headers select; where sets overlap, the later one wins. A point that
        cannot report events, such as a "supports" input, is left as it is by a
        set that gives it a class, so a range or an "all" header can be used
        without naming the points that never had events.

        Events already buffered keep the class they were recorded in and are
        reported there. Changes the sources made before the request are
        recorded first, under the classes they had. Only changes after the
        request use the new class (IEEE 1815-2012 4.4.14).

        Raises:
            UnknownObject: A header names a group this level does not assign.
            ParameterError: A header names a point that is not there.
        """
        chosen: dict[Address, int] = {}
        for assignment in assignments:
            for header in assignment.headers:
                points = self._assignable(header)
                if header.group in _COMMAND_EVENT_ASSIGNMENTS:
                    continue
                for point in points:
                    if assignment.event_class and not self._can_report(point):
                        continue
                    chosen[point.address] = assignment.event_class
        self._set_classes(chosen)

    def reset_classes(self) -> None:
        """Return every point to the class it had at startup."""
        self._set_classes(
            {address: self._initial_classes.get(address, 0) for address in self._classes}
        )
        # An output that started with no class has none again, and leaves the
        # class 0 response (D115).
        for address in self._classes.keys() - self._initial_classes.keys():
            del self._classes[address]

    def assignable_groups(self) -> list[int]:
        """The groups an ASSIGN_CLASS request may name at this level, in order."""
        return sorted(
            group
            for group, (selecting, level) in _ASSIGNABLE_GROUPS.items()
            if self.at_least(level) and self._points(selecting)
        )

    def _assignable(self, header: ObjectHeader) -> list[Point]:
        """The served points an ASSIGN_CLASS header names."""
        group, level = _ASSIGNABLE_GROUPS.get(header.group, (None, None))
        if group is None or level is None or not self.at_least(level):
            raise UnknownObject(f"group {header.group} cannot be assigned a class")
        selecting = replace(header, group=group)
        if header.qualifier in _INDEXED:
            return self._named(selecting)
        return self._selected(selecting)

    def _can_report(self, point: Point) -> bool:
        """Whether a point may be given a class that reports events."""
        if point.kind.is_output:
            return True
        if self._initial_classes.get(point.address, 0):
            return True
        if point.kind is Kind.CTR:
            return point.frozen and point.in_class_0
        return point.event_class in (1, 2, 3)

    def _set_classes(self, chosen: Mapping[Address, int]) -> None:
        """Apply new classes, giving a point that starts reporting a fresh baseline."""
        if self._primed:
            self.poll()
        for address, event_class in chosen.items():
            if self._classes.get(address) == event_class:
                continue
            self._classes[address] = event_class
            if event_class and self._primed:
                self._rebaseline(self._map.points[address])
        logger.info("profile: %d point(s) changed event class", len(chosen))

    def _rebaseline(self, point: Point) -> None:
        """Measure a point's next change from its value now, not from when it last reported."""
        if point.kind is Kind.BI:
            self.events.prime_binary(point.index, self._binary(point))
        elif point.kind is Kind.DBI:
            self.events.prime_double_bit(point.index, self._double_bit(point))
        elif point.kind is Kind.AI:
            self.events.prime_analog(point.index, self._analog(point))
            if point.index not in self._deadbands:
                default = self._event_policy.defaults.get(point.kind)
                if point.index in self._binding.deadbands:
                    self._deadbands[point.index] = self._binding.deadbands[point.index]
                elif default is not None and default.deadband is not None:
                    self._deadbands[point.index] = _transmitted(point, default.deadband)
        elif point.kind is Kind.CTR and self.at_least(SubsetLevel.LEVEL_3):
            self.events.prime_counter(point.index, self._counter(point))
        elif point.kind is Kind.BO:
            self.events.prime_binary_output(
                point.index, self._binary_of(self._standing(point.address))
            )
        elif point.kind is Kind.AO:
            self.events.prime_analog_output(
                point.index, self._analog_of(point, self._standing(point.address))
            )

    # -------------------------------------------------------------- freezes

    def freeze(self, headers: Sequence[ObjectHeader], *, clear: bool) -> None:
        """Freeze the counters a master named.

        Under the DER profile the counters are not cleared, whichever freeze
        was asked for: the profile has a controlling station compute an
        interval's energy by subtracting two frozen values, which a counter
        that restarted from zero would break. Held to a subset level, 2, 3 or
        4, a freeze-and-clear clears, as TB2016-003b Table 12-19 and IEEE
        1815-2012 11.9.5.2 have it (D107).
        """
        named: list[Point] = []
        for header in headers:
            if header.group != GROUP_COUNTER:
                raise UnknownObject(f"group {header.group} cannot be frozen")
            named += self._selected(header)
        if clear and (self._level2 or self._level > SubsetLevel.LEVEL_2):
            # A level was given, so the subset tables apply (D107).
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
            frozen += 1
            reported = self._classes[point.address]
            if self._level2 or not reported:
                # Frozen counter events are not Level 2 objects, and a policy
                # may turn a counter's off. The counter is frozen either way.
                continue
            self.events.record_frozen_counter(
                point.index, value, event_class=EventClass(reported), timestamp_ms=now
            )
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

    def _level_variations(self) -> dict[int, int]:
        """Return the variations the claimed level reports instead of the profile's own."""
        if self._level2:
            return _LEVEL_2_VARIATIONS
        if self._level == SubsetLevel.LEVEL_3:
            # Level 3 lists frozen counters in the Level 2 variations only
            # (Table 12-21); the variation with time is Level 4.
            return {GROUP_FROZEN_COUNTER: _LEVEL_2_VARIATIONS[GROUP_FROZEN_COUNTER]}
        return {}

    def _level_options(self) -> dict[str, Any]:
        """Return the session options the claimed level sets."""
        options: dict[str, Any] = {}
        if self.at_least(SubsetLevel.LEVEL_3):
            # Reads that Level 3 adds (Tables 12-25, 12-45 and 12-52).
            options["frozen_counter_event_16_bit"] = True
            options["time_source"] = self.now_ms
            options["indications_read"] = True
        if self._level == SubsetLevel.LEVEL_3:
            # Class polls carry frozen counter events without time (Table 12-49).
            options["frozen_counter_event_variation"] = 1
        if self.at_least(SubsetLevel.LEVEL_4):
            # Writes of analog input deadbands (D114), and reads of the
            # floating-point and 16-bit frozen counter events (D112, D113).
            options["deadband_provider"] = self
            options["extended_events"] = True
            # The output event groups of each kind of output served (D115,
            # D116). The others are objects this device lacks.
            options["output_events"] = [
                group
                for kind, groups in _OUTPUT_EVENT_GROUPS.items()
                if self._served[kind]
                for group in groups
            ]
        return options

    def session(self, *, max_response: int = 2048, **options: Any) -> Session:
        """A session wired to this outstation, with the profile's options set.

        Analog events travel in the 32-bit variation without time, which is
        the profile's selection and the one a Level 2 master is certain to
        parse; the time is asked for from the first response; and the freeze
        functions are served only when there are counters to freeze. The
        first two are defaults a caller may override by naming the option.

        Every other option of :class:`~py1815.session.Session` passes
        through. ``unsolicited=True`` is the one a profile's consumers ask
        about: the session then reports the events :meth:`poll` buffers to a
        master that has enabled their class, without waiting to be polled.
        It is off unless named, and nothing about the map or the binding
        changes with it.
        """
        if self._block_octets + RESPONSE_HEADER_SIZE > max_response:
            raise ValueError(
                f"static blocks of up to {self._block_octets} octets do not fit a "
                f"{max_response}-octet response"
            )
        options.setdefault("need_time", True)
        # Group 4 is read by name only where double-bit inputs are served, which
        # is Level 4.
        options.setdefault("double_bit_events", bool(self._served[Kind.DBI]))
        options.setdefault("analog_event_variation", AnalogEventVariation.INT32)
        for name, value in self._level_options().items():
            options.setdefault(name, value)
        session = Session(
            self,
            control_provider=self if self._binding.outputs else None,
            events=self.events,
            # A freeze is offered only where a counter freezes. One accepted by a device
            # whose counters do not would store nothing a read can return (D100).
            freeze_provider=self if any(p.frozen for p in self._served[Kind.CTR]) else None,
            # ASSIGN_CLASS is required from Level 3 (TB2016-003b Table 12-49) and refused below it.
            class_provider=self if self.at_least(SubsetLevel.LEVEL_3) else None,
            time_sink=self.set_time,
            max_response=max_response,
            **options,
        )
        self._sessions.add(session)
        return session


def _constant(value: float | bool) -> Reader:
    return lambda: Reading(value)


def _name(address: Address) -> str:
    return f"{address[0].value}{address[1]}"


def _class_in_force(point: Point, default: EventRule | None, own: EventRule | None) -> int:
    """The class one input reports in under a policy's rules, or 0 for no events."""
    tabled: int | None
    if point.kind is Kind.CTR:
        # A counter reports through its frozen twin, and only if it has one.
        tabled = point.frozen_event_class if point.frozen else 0
        if point.frozen and tabled not in (1, 2, 3):
            tabled = int(_DEFAULT_FROZEN_CLASS)
    else:
        tabled = point.event_class
    if own is not None and own.decides_reporting:
        if own.events is False:
            return 0
        if point.kind is Kind.CTR and not point.frozen:
            raise MapError(
                f"the event policy gives {_name(point.address)} events, "
                "and the counter has no frozen counter to log them"
            )
        if tabled is None or not point.in_class_0:
            # An event reports a change to a value the master first learned
            # from class 0, and this point is not in class 0. For a counter the
            # class comes from its frozen twin, so membership is asked directly.
            raise MapError(
                f"the event policy gives {_name(point.address)} events, "
                "and the point is left out of class 0"
            )
        chosen = own.event_class or (default.event_class if default is not None else None)
        chosen = chosen or tabled
        if chosen not in (1, 2, 3):
            raise MapError(
                f"the event policy turns events on for {_name(point.address)}, "
                "and nothing gives the point a class"
            )
        return chosen
    if tabled is None or tabled not in (1, 2, 3) or not point.in_class_0:
        return 0
    if default is None:
        return tabled
    if default.events is False:
        return 0
    return default.event_class or tabled


def _transmitted(point: Point, deadband: float) -> float:
    """A deadband in engineering units as the span of transmitted values it covers.

    A span and not a value, so the point's offset has no part in it, and
    neither has the sign of its multiplier.
    """
    if point.multiplier is None:
        return float(deadband)
    return abs(deadband / point.multiplier)


def _latched(command: ControlRelayOutputBlock) -> bool | None:
    """The state a control relay output block asks for, read as a latch.

    The profile permits every operation pair and has the outstation behave as
    if each point were latched, ignoring pulse times: close and the "on"
    operations set the point, trip and the "off" operations clear it.

    None, which is answered ``NOT_SUPPORTED``, for a block with the obsolete
    queue bit set, and for one with the clear bit set. This outstation does not
    support the clear bit, so it supports no combination that sets it (IEEE
    1815-2012, Annex A, group 12 variation 1). Carrying out the operation and
    ignoring the bit would skip the cancellation the master asked for (D101).
    """
    if command.queued or command.clear:
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
